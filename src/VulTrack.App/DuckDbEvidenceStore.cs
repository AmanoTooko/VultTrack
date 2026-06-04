using DuckDB.NET.Data;

namespace VulTrack.App;

public sealed record DuckDbAffectedFact(
    string FactType,
    string? Ecosystem,
    string? PackageName,
    string? Purl,
    string? Cpe23Uri,
    string? VersionRange,
    string? RangeType,
    bool Vulnerable);

public sealed record DuckDbSeverityScore(
    string ScoringSystem,
    string? ScoringVersion,
    string? ScoreType,
    string? VectorString,
    decimal? Score,
    string? SeverityLabel);

public sealed record DuckDbReference(
    string Url,
    string? RefType,
    string[] Tags);

public sealed record DuckDbWeakness(
    string WeaknessType,
    string? WeaknessId,
    string? Description);

public sealed record DuckDbEvidenceRecord(
    string SourceCode,
    Guid RawIndexId,
    string VulnerabilityKey,
    string SourceRecordId,
    IReadOnlyList<DuckDbAffectedFact> AffectedFacts,
    IReadOnlyList<DuckDbSeverityScore> SeverityScores,
    IReadOnlyList<DuckDbReference> References,
    IReadOnlyList<DuckDbWeakness> Weaknesses);

public sealed record DuckDbEvidenceStats(
    string path,
    long fileBytes,
    long affectedFacts,
    long severityScores,
    long references,
    long weaknesses);

public sealed class DuckDbEvidenceStore(IConfiguration configuration)
{
    public string DatabasePath { get; } = ResolvePath(configuration);

    public bool Enabled { get; } =
        string.Equals(Environment.GetEnvironmentVariable("VULTRACK_DUCKDB_ENABLED"), "true", StringComparison.OrdinalIgnoreCase)
        || string.Equals(configuration["VulTrack:DuckDb:Enabled"], "true", StringComparison.OrdinalIgnoreCase);

    public Task InitializeAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Directory.CreateDirectory(Path.GetDirectoryName(DatabasePath)!);
        using var connection = OpenConnection();
        foreach (var statement in SchemaStatements)
            Execute(connection, statement);
        return Task.CompletedTask;
    }

    public Task ResetAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        using var connection = OpenConnection();
        foreach (var statement in SchemaStatements)
            Execute(connection, statement);
        foreach (var table in EvidenceTables)
            Execute(connection, $"delete from {table}");
        return Task.CompletedTask;
    }

    public async Task ReplaceRecordsAsync(IReadOnlyList<DuckDbEvidenceRecord> records, CancellationToken ct)
    {
        if (records.Count == 0) return;
        await InitializeAsync(ct);

        using var connection = OpenConnection();
        Execute(connection, "begin transaction");
        try
        {
            var sourceCode = records[0].SourceCode;
            var rawIds = records.Select(x => x.RawIndexId.ToString("D")).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            foreach (var batch in rawIds.Chunk(1000))
            {
                var idList = string.Join(",", batch.Select(SqlValue));
                foreach (var table in EvidenceTables)
                    Execute(connection, $"delete from {table} where source_code = {SqlValue(sourceCode)} and raw_index_id in ({idList})");
            }

            await CopyAffectedFactsAsync(connection, records, ct);
            await CopySeverityScoresAsync(connection, records, ct);
            await CopyReferencesAsync(connection, records, ct);
            await CopyWeaknessesAsync(connection, records, ct);

            Execute(connection, "commit");
        }
        catch
        {
            Execute(connection, "rollback");
            throw;
        }
    }

    public Task<DuckDbEvidenceStats> StatsAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        using var connection = OpenConnection();
        foreach (var statement in SchemaStatements)
            Execute(connection, statement);

        var file = new FileInfo(DatabasePath);
        return Task.FromResult(new DuckDbEvidenceStats(
            DatabasePath,
            file.Exists ? file.Length : 0,
            Count(connection, "affected_facts"),
            Count(connection, "severity_scores"),
            Count(connection, "evidence_references"),
            Count(connection, "weaknesses")));
    }

    public async Task<IReadOnlyList<Dictionary<string, object?>>> QueryAffectedFactsAsync(string vulnerabilityKey, int limit = 200, CancellationToken ct = default)
    {
        if (!Enabled) return Array.Empty<Dictionary<string, object?>>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            select source_code, fact_type, ecosystem, package_name,
                   purl, cpe23_uri, version_range_raw, range_type, vulnerable
            from affected_facts
            where vulnerability_key = $1
            order by case when cpe23_uri is not null then 0 else 1 end,
                     case when purl is not null then 0 else 1 end,
                     source_code nulls last, package_name nulls last
            limit {limit}
            """;
        command.Parameters.Add(new DuckDBParameter(vulnerabilityKey));
        return await ReadRowsAsync(command, ct);
    }
}
}

    public async Task<IReadOnlyList<Dictionary<string, object?>>> QuerySeverityScoresAsync(string vulnerabilityKey, int limit = 40, CancellationToken ct = default)
    {
        if (!Enabled) return Array.Empty<Dictionary<string, object?>>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            select source_code, scoring_system, scoring_version, score_type,
                   vector_string, score, severity_label
            from severity_scores
            where vulnerability_key = $1
            order by score desc nulls last
            limit {limit}
            """;
        command.Parameters.Add(new DuckDBParameter(vulnerabilityKey));
        return await ReadRowsAsync(command, ct);
    }

    private static async Task<IReadOnlyList<Dictionary<string, object?>>> ReadRowsAsync(DuckDBCommand command, CancellationToken ct)
    {
        var rows = new List<Dictionary<string, object?>>();
        using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var dict = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            for (var i = 0; i < reader.FieldCount; i++)
                dict[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
            rows.Add(dict);
        }
        return rows;
    }

    private DuckDBConnection OpenConnection()
    {
        var connection = new DuckDBConnection($"Data Source={DatabasePath}");
        connection.Open();
        return connection;
    }

    private async Task CopyAffectedFactsAsync(DuckDBConnection connection, IReadOnlyList<DuckDbEvidenceRecord> records, CancellationToken ct)
    {
        var rows = records.SelectMany(record => record.AffectedFacts
            .GroupBy(fact => $"{fact.FactType}|{fact.Ecosystem}|{fact.PackageName}|{fact.Purl}|{fact.Cpe23Uri}|{fact.VersionRange}|{fact.RangeType}|{fact.Vulnerable}")
            .Select(group => group.First())
            .Select(fact => CsvRow(
                record.SourceCode,
                record.RawIndexId.ToString("D"),
                record.VulnerabilityKey,
                record.SourceRecordId,
                fact.FactType,
                fact.Ecosystem,
                fact.PackageName,
                fact.PackageName?.ToLowerInvariant(),
                fact.Purl,
                PurlWithoutVersion(fact.Purl),
                fact.Cpe23Uri,
                fact.VersionRange,
                fact.RangeType,
                fact.Vulnerable ? "true" : "false")));

        await CopyRowsAsync(connection, "affected_facts", """
            source_code, raw_index_id, vulnerability_key, source_record_id, fact_type, ecosystem,
            package_name, normalized_package_name, purl, purl_without_version, cpe23_uri,
            version_range_raw, range_type, vulnerable
            """, rows, ct);
    }

    private async Task CopySeverityScoresAsync(DuckDBConnection connection, IReadOnlyList<DuckDbEvidenceRecord> records, CancellationToken ct)
    {
        var rows = records.SelectMany(record => record.SeverityScores.Select(score => CsvRow(
            record.SourceCode,
            record.RawIndexId.ToString("D"),
            record.VulnerabilityKey,
            record.SourceRecordId,
            score.ScoringSystem,
            score.ScoringVersion,
            score.ScoreType,
            score.VectorString,
            score.Score?.ToString(System.Globalization.CultureInfo.InvariantCulture),
            score.SeverityLabel)));

        await CopyRowsAsync(connection, "severity_scores", """
            source_code, raw_index_id, vulnerability_key, source_record_id, scoring_system,
            scoring_version, score_type, vector_string, score, severity_label
            """, rows, ct);
    }

    private async Task CopyReferencesAsync(DuckDBConnection connection, IReadOnlyList<DuckDbEvidenceRecord> records, CancellationToken ct)
    {
        var rows = records.SelectMany(record => record.References
            .Where(reference => !string.IsNullOrWhiteSpace(reference.Url))
            .DistinctBy(reference => reference.Url)
            .Select(reference => CsvRow(
                record.SourceCode,
                record.RawIndexId.ToString("D"),
                record.VulnerabilityKey,
                record.SourceRecordId,
                reference.Url,
                reference.Url.ToLowerInvariant(),
                reference.RefType,
                System.Text.Json.JsonSerializer.Serialize(reference.Tags))));

        await CopyRowsAsync(connection, "evidence_references", """
            source_code, raw_index_id, vulnerability_key, source_record_id, url, normalized_url, ref_type, tags_json
            """, rows, ct);
    }

    private async Task CopyWeaknessesAsync(DuckDBConnection connection, IReadOnlyList<DuckDbEvidenceRecord> records, CancellationToken ct)
    {
        var rows = records.SelectMany(record => record.Weaknesses
            .Where(weakness => !string.IsNullOrWhiteSpace(weakness.WeaknessId) || !string.IsNullOrWhiteSpace(weakness.Description))
            .DistinctBy(weakness => $"{weakness.WeaknessType}|{weakness.WeaknessId}|{weakness.Description}")
            .Select(weakness => CsvRow(
                record.SourceCode,
                record.RawIndexId.ToString("D"),
                record.VulnerabilityKey,
                record.SourceRecordId,
                weakness.WeaknessType,
                weakness.WeaknessId,
                weakness.Description)));

        await CopyRowsAsync(connection, "weaknesses", """
            source_code, raw_index_id, vulnerability_key, source_record_id, weakness_type, weakness_id, description
            """, rows, ct);
    }

    private async Task CopyRowsAsync(DuckDBConnection connection, string tableName, string columns, IEnumerable<string> rows, CancellationToken ct)
    {
        var tempDir = Path.Combine(Path.GetDirectoryName(DatabasePath)!, "tmp");
        Directory.CreateDirectory(tempDir);
        var tempFile = Path.Combine(tempDir, $"{tableName}-{Guid.NewGuid():N}.csv");
        var count = 0;
        try
        {
            await using (var writer = new StreamWriter(tempFile))
            {
                foreach (var row in rows)
                {
                    ct.ThrowIfCancellationRequested();
                    await writer.WriteLineAsync(row);
                    count++;
                }
            }

            if (count == 0) return;
            Execute(connection, $"""
                copy {tableName} ({columns})
                from {SqlValue(tempFile)}
                (header false, delim ',', quote '"', escape '"', null '\N')
                """);
        }
        finally
        {
            try { File.Delete(tempFile); } catch { }
        }
    }

    private static long Count(DuckDBConnection connection, string tableName)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"select count(*) from {tableName}";
        return Convert.ToInt64(command.ExecuteScalar());
    }

    private static void Execute(DuckDBConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static string SqlValue(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? "null"
            : $"'{value.Replace("'", "''")}'";

    private static string CsvRow(params string?[] values) =>
        string.Join(",", values.Select(CsvValue));

    private static string CsvValue(string? value)
    {
        if (value is null) return "\\N";
        return $"\"{value.Replace("\"", "\"\"")}\"";
    }

    private static string? PurlWithoutVersion(string? purl)
    {
        if (string.IsNullOrWhiteSpace(purl)) return null;
        var at = purl.LastIndexOf('@');
        return at > "pkg:".Length ? purl[..at] : purl;
    }

    private static string ResolvePath(IConfiguration configuration)
    {
        var configured = Environment.GetEnvironmentVariable("VULTRACK_DUCKDB_PATH")
            ?? configuration["VulTrack:DuckDb:Path"];
        if (!string.IsNullOrWhiteSpace(configured)) return Path.GetFullPath(configured);

        var root = Environment.GetEnvironmentVariable("VULTRACK_REPO_ROOT")
            ?? Directory.GetCurrentDirectory();
        return Path.GetFullPath(Path.Combine(root, "data", "duckdb", "vultrack-evidence.duckdb"));
    }

    private static readonly string[] EvidenceTables =
    [
        "affected_facts",
        "severity_scores",
        "evidence_references",
        "weaknesses",
        "cpe_entries",
        "exploits",
        "threat_scores"
    ];

    private static readonly string[] SchemaStatements =
    [
        """
        create table if not exists affected_facts (
          source_code varchar,
          raw_index_id varchar,
          vulnerability_key varchar,
          source_record_id varchar,
          fact_type varchar,
          ecosystem varchar,
          package_name varchar,
          normalized_package_name varchar,
          purl varchar,
          purl_without_version varchar,
          cpe23_uri varchar,
          version_range_raw varchar,
          range_type varchar,
          vulnerable boolean
        )
        """,
        """
        create table if not exists severity_scores (
          source_code varchar,
          raw_index_id varchar,
          vulnerability_key varchar,
          source_record_id varchar,
          scoring_system varchar,
          scoring_version varchar,
          score_type varchar,
          vector_string varchar,
          score double,
          severity_label varchar
        )
        """,
        """
        create table if not exists evidence_references (
          source_code varchar,
          raw_index_id varchar,
          vulnerability_key varchar,
          source_record_id varchar,
          url varchar,
          normalized_url varchar,
          ref_type varchar,
          tags_json varchar
        )
        """,
        """
        create table if not exists weaknesses (
          source_code varchar,
          raw_index_id varchar,
          vulnerability_key varchar,
          source_record_id varchar,
          weakness_type varchar,
          weakness_id varchar,
          description varchar
        )
        """,
        """
        create table if not exists cpe_entries (
          source_code varchar,
          raw_index_id varchar,
          cpe23_uri varchar,
          vendor varchar,
          product varchar,
          version varchar,
          part varchar,
          target_sw varchar,
          deprecated boolean
        )
        """,
        """
        create table if not exists exploits (
          source_code varchar,
          raw_index_id varchar,
          source_key varchar,
          identifiers varchar,
          title varchar,
          source_url varchar,
          artifact_type varchar,
          exploit_type varchar,
          maturity varchar,
          verification_status varchar,
          published_at varchar,
          modified_at varchar
        )
        """,
        """
        create table if not exists threat_scores (
          source_code varchar,
          raw_index_id varchar,
          vulnerability_key varchar,
          score_type varchar,
          score double,
          percentile double,
          observed_at varchar
        )
        """
    ];

    public async Task<IReadOnlyList<Dictionary<string, object?>>> QueryCpeEntriesAsync(string vendor, string product, int limit = 50, CancellationToken ct = default)
    {
        if (!Enabled) return Array.Empty<Dictionary<string, object?>>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            select source_code, cpe23_uri, vendor, product, version, part, target_sw, deprecated
            from cpe_entries
            where vendor like '%' || $1 || '%' or product like '%' || $2 || '%'
            limit {limit}
            """;
        command.Parameters.Add(new DuckDBParameter(vendor ?? ""));
        command.Parameters.Add(new DuckDBParameter(product ?? ""));
        return await ReadRowsAsync(command, ct);
    }

    public async Task<IReadOnlyList<Dictionary<string, object?>>> QueryExploitsAsync(string vulnerabilityKey, int limit = 40, CancellationToken ct = default)
    {
        if (!Enabled) return Array.Empty<Dictionary<string, object?>>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            select source_code, source_key, title, source_url, artifact_type,
                   exploit_type, maturity, verification_status, published_at, modified_at
            from exploits
            where identifiers like '%' || $1 || '%'
            limit {limit}
            """;
        command.Parameters.Add(new DuckDBParameter(vulnerabilityKey));
        return await ReadRowsAsync(command, ct);
    }

    public async Task<IReadOnlyList<Dictionary<string, object?>>> QueryThreatScoresAsync(string vulnerabilityKey, int limit = 20, CancellationToken ct = default)
    {
        if (!Enabled) return Array.Empty<Dictionary<string, object?>>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            select source_code, score_type, score, percentile, observed_at
            from threat_scores
            where vulnerability_key = $1
            limit {limit}
            """;
        command.Parameters.Add(new DuckDBParameter(vulnerabilityKey));
        return await ReadRowsAsync(command, ct);
    }
