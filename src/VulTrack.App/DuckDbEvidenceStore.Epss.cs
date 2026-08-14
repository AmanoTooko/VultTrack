using System.Diagnostics;
using DuckDB.NET.Data;

namespace VulTrack.App;

public sealed partial class DuckDbEvidenceStore
{
    // FIRST publishes one gzip CSV per day. Import it directly into DuckDB's
    // temporary columnar table, then only touch score rows whose values differ.
    public async Task<DuckDbFirstEpssApplyResult> ApplyFirstEpssSnapshotAsync(
        string gzipCsvPath,
        DateTimeOffset observedAt,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(gzipCsvPath))
            throw new ArgumentException("An EPSS gzip CSV path is required.", nameof(gzipCsvPath));
        var fullPath = Path.GetFullPath(gzipCsvPath);
        if (!File.Exists(fullPath))
            throw new FileNotFoundException("FIRST EPSS gzip CSV was not found.", fullPath);

        await InitializeAsync(ct);
        await _writeLock.WaitAsync(ct);
        var watch = Stopwatch.StartNew();
        try
        {
            using var connection = OpenConnection();
            Execute(connection, "begin transaction");
            try
            {
                Execute(connection, "drop table if exists temp_first_epss_input");
                Execute(connection, """
                    create temporary table temp_first_epss_input (
                      vulnerability_key varchar,
                      score double,
                      percentile double
                    )
                    """);
                Execute(connection, $$"""
                    insert into temp_first_epss_input
                    select upper(trim(cve)), epss, percentile
                    from read_csv(
                      {{SqlValue(fullPath)}},
                      header = true,
                      skip = 1,
                      delim = ',',
                      compression = 'gzip',
                      strict_mode = true,
                      columns = {'cve': 'VARCHAR', 'epss': 'DOUBLE', 'percentile': 'DOUBLE'})
                    """);

                var inputRows = ScalarLong(connection, "select count(*) from temp_first_epss_input");
                if (inputRows == 0)
                    throw new InvalidDataException("FIRST EPSS CSV contained no score rows.");
                var duplicateRows = ScalarLong(connection, """
                    select count(*)
                    from (
                      select vulnerability_key
                      from temp_first_epss_input
                      group by vulnerability_key
                      having count(*) > 1
                    )
                    """);
                if (duplicateRows > 0)
                    throw new InvalidDataException($"FIRST EPSS CSV contains {duplicateRows} duplicate CVE rows.");
                var invalidRows = ScalarLong(connection, """
                    select count(*)
                    from temp_first_epss_input
                    where not regexp_matches(vulnerability_key, '^CVE-[0-9]{4}-[0-9]{4,}$')
                       or score is null or percentile is null
                       or score < 0 or score > 1
                       or percentile < 0 or percentile > 1
                    """);
                if (invalidRows > 0)
                    throw new InvalidDataException($"FIRST EPSS CSV contains {invalidRows} invalid score rows.");

                var updatedRows = ScalarLong(connection, """
                    select count(*)
                    from threat_scores target
                    join temp_first_epss_input incoming
                      on target.vulnerability_key = incoming.vulnerability_key
                    where target.source_code = 'first-epss'
                      and target.score_type = 'epss'
                      and (target.score is distinct from incoming.score
                           or target.percentile is distinct from incoming.percentile)
                    """);
                var insertedRows = ScalarLong(connection, """
                    select count(*)
                    from temp_first_epss_input incoming
                    where not exists (
                      select 1
                      from threat_scores target
                      where target.source_code = 'first-epss'
                        and target.score_type = 'epss'
                        and target.vulnerability_key = incoming.vulnerability_key
                    )
                    """);
                var observed = SqlValue(observedAt.UtcDateTime.ToString("O"));
                Execute(connection, $"""
                    update threat_scores target
                    set score = incoming.score,
                        percentile = incoming.percentile,
                        observed_at = {observed}
                    from temp_first_epss_input incoming
                    where target.source_code = 'first-epss'
                      and target.score_type = 'epss'
                      and target.vulnerability_key = incoming.vulnerability_key
                      and (target.score is distinct from incoming.score
                           or target.percentile is distinct from incoming.percentile)
                    """);
                Execute(connection, $"""
                    insert into threat_scores (
                      source_code, raw_index_id, vulnerability_key, score_type, score, percentile, observed_at)
                    select 'first-epss', 'epss:' || vulnerability_key, vulnerability_key,
                           'epss', score, percentile, {observed}
                    from temp_first_epss_input incoming
                    where not exists (
                      select 1
                      from threat_scores target
                      where target.source_code = 'first-epss'
                        and target.score_type = 'epss'
                        and target.vulnerability_key = incoming.vulnerability_key
                    )
                    """);
                Execute(connection, "drop table temp_first_epss_input");
                ct.ThrowIfCancellationRequested();
                Execute(connection, "commit");
                watch.Stop();
                return new DuckDbFirstEpssApplyResult(
                    inputRows,
                    insertedRows,
                    updatedRows,
                    Math.Max(0, inputRows - insertedRows - updatedRows),
                    watch.ElapsedMilliseconds);
            }
            catch
            {
                try { Execute(connection, "rollback"); } catch { }
                throw;
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private static long ScalarLong(DuckDBConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(command.ExecuteScalar());
    }
}
