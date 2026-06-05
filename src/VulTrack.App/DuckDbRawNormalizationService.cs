using Npgsql;

namespace VulTrack.App;

public sealed class DuckDbRawNormalizationService(
    NpgsqlDataSource db,
    DuckDbEvidenceNormalizer normalizer,
    IConfiguration configuration,
    ILogger<DuckDbRawNormalizationService> logger) : IRawNormalizationService
{
    public async Task<IReadOnlyList<NormalizeBatchResult>> ProcessPendingAsync(int limitPerSource, CancellationToken ct)
    {
        var results = new List<NormalizeBatchResult>();
        await using var connection = await db.OpenConnectionAsync(ct);
        var enabledSources = await LoadEnabledAutomaticSourceCodesAsync(connection, ct);
        foreach (var sourceCode in enabledSources.Order(StringComparer.OrdinalIgnoreCase))
        {
            results.Add(await ProcessSourcePendingAsync(sourceCode, limitPerSource, ct));
        }

        return results;
    }

    public async Task<NormalizeBatchResult> ProcessSourcePendingAsync(string sourceCode, int limit, CancellationToken ct)
    {
        await using var connection = await db.OpenConnectionAsync(ct);
        if (!await TryAcquireSourceNormalizeLockAsync(connection, sourceCode, ct))
        {
            logger.LogInformation("DuckDB normalizer {SourceCode} is already running; skipping overlapping request.", sourceCode);
            return new NormalizeBatchResult(sourceCode, 0, 0);
        }

        try
        {
            await SupersedeOlderPendingRawAsync(connection, sourceCode, ct);
            var rawIndexIds = await LoadPendingRawIdsAsync(connection, sourceCode, limit, ct);
            if (rawIndexIds.Length == 0)
                return new NormalizeBatchResult(sourceCode, 0, 0);

            var request = new DuckDbEvidenceNormalizeRequest(
                sourceCode,
                Math.Min(DuckDbLimit(limit), rawIndexIds.Length),
                Reset: false,
                BatchSize: DuckDbBatchSize(),
                RawIndexIds: rawIndexIds);
            var result = await normalizer.NormalizeAsync(request, ct);
            var source = result.sources.FirstOrDefault(x => string.Equals(x.sourceCode, sourceCode, StringComparison.OrdinalIgnoreCase));
            if (source is null)
                return new NormalizeBatchResult(sourceCode, 0, 1);

            await MarkPendingSucceededAsync(connection, rawIndexIds, ct);
            return new NormalizeBatchResult(sourceCode, rawIndexIds.Length, 0);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "DuckDB normalizer {SourceCode} failed.", sourceCode);
            return new NormalizeBatchResult(sourceCode, 0, 1);
        }
        finally
        {
            await ReleaseSourceNormalizeLockAsync(connection, sourceCode, CancellationToken.None);
        }
    }

    private static async Task<Guid[]> LoadPendingRawIdsAsync(NpgsqlConnection connection, string sourceCode, int limit, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("""
            select r.id
            from source_raw_index r
            join sources s on s.id = r.source_id
            where s.code = $1
              and r.normalize_status in ('pending', 'failed')
            order by r.updated_at, r.id
            limit $2
            """, connection);
        cmd.CommandTimeout = 300;
        cmd.Parameters.AddWithValue(sourceCode);
        cmd.Parameters.AddWithValue(Math.Max(1, limit));

        var ids = new List<Guid>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            ids.Add(reader.GetGuid(0));
        return ids.ToArray();
    }

    private int DuckDbLimit(int schedulerLimit)
    {
        var configured = Environment.GetEnvironmentVariable("VULTRACK_DUCKDB_NORMALIZE_LIMIT")
            ?? configuration["VulTrack:DuckDb:NormalizeLimit"];
        return int.TryParse(configured, out var value) && value > 0
            ? Math.Min(value, 5_000_000)
            : Math.Max(schedulerLimit, 5_000_000);
    }

    private int DuckDbBatchSize()
    {
        var configured = Environment.GetEnvironmentVariable("VULTRACK_DUCKDB_NORMALIZE_BATCH_SIZE")
            ?? configuration["VulTrack:DuckDb:NormalizeBatchSize"];
        return int.TryParse(configured, out var value) && value > 0
            ? Math.Min(value, 100_000)
            : 10_000;
    }

    private static async Task<HashSet<string>> LoadEnabledAutomaticSourceCodesAsync(NpgsqlConnection connection, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("""
            select code
            from sources
            where enabled
              and coalesce(config_json->>'runMode', '') <> 'manual'
            """, connection);

        var codes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            codes.Add(reader.GetString(0));
        }

        return codes;
    }

    private static async Task<bool> TryAcquireSourceNormalizeLockAsync(NpgsqlConnection connection, string sourceCode, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("select pg_try_advisory_lock(hashtext($1), 0)", connection);
        cmd.Parameters.AddWithValue($"normalize:{sourceCode.ToLowerInvariant()}");
        return (bool)(await cmd.ExecuteScalarAsync(ct) ?? false);
    }

    private static async Task ReleaseSourceNormalizeLockAsync(NpgsqlConnection connection, string sourceCode, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("select pg_advisory_unlock(hashtext($1), 0)", connection);
        cmd.Parameters.AddWithValue($"normalize:{sourceCode.ToLowerInvariant()}");
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private async Task SupersedeOlderPendingRawAsync(NpgsqlConnection connection, string? sourceCode, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("""
            with ranked as (
              select r.id,
                     row_number() over (
                       partition by r.source_id, r.external_key
                       order by
                         case when r.status = 'priority' then 0 else 1 end,
                         r.source_modified_at desc nulls last,
                         r.updated_at desc,
                         r.created_at desc,
                         r.id desc
                     ) as rank
              from source_raw_index r
              join sources s on s.id = r.source_id
              where r.normalize_status in ('pending', 'failed')
                and ($1::text is null or s.code = $1)
            )
            update source_raw_index r
            set normalize_status = 'superseded',
                updated_at = now()
            from ranked
            where r.id = ranked.id
              and ranked.rank > 1
            """, connection);
        cmd.CommandTimeout = 300;
        cmd.Parameters.AddWithValue((object?)sourceCode ?? DBNull.Value);
        var superseded = await cmd.ExecuteNonQueryAsync(ct);
        if (superseded > 0)
            logger.LogInformation("Marked {Count} older raw snapshots as superseded for {SourceCode}.", superseded, sourceCode ?? "all sources");
    }

    private static async Task MarkPendingSucceededAsync(NpgsqlConnection connection, Guid[] rawIndexIds, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("""
            update source_raw_index
            set normalize_status = 'succeeded',
                updated_at = now()
            where id = any($1)
              and normalize_status in ('pending', 'failed')
            """, connection);
        cmd.CommandTimeout = 300;
        cmd.Parameters.AddWithValue(rawIndexIds);
        await cmd.ExecuteNonQueryAsync(ct);
    }
}
