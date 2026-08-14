using DuckDB.NET.Data;

namespace VulTrack.App;

public sealed partial class DuckDbEvidenceStore
{
    public async Task<DuckDbSourceProjectionState> GetSourceProjectionStateAsync(string sourceCode, CancellationToken ct)
    {
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        var keys = new List<string>();
        using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                select distinct vulnerability_key
                from source_records
                where source_code = $1 and vulnerability_key is not null
                """;
            command.Parameters.Add(new DuckDBParameter(sourceCode));
            using var reader = await command.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
                keys.Add(reader.GetString(0));
        }
        using var affectedCommand = connection.CreateCommand();
        affectedCommand.CommandText = "select exists(select 1 from affected_facts where source_code = $1 limit 1)";
        affectedCommand.Parameters.Add(new DuckDBParameter(sourceCode));
        var hasAffectedFacts = Convert.ToBoolean(await affectedCommand.ExecuteScalarAsync(ct));
        return new DuckDbSourceProjectionState(keys, hasAffectedFacts);
    }

    public async Task<bool> HasSourceRecordsAsync(string sourceCode, CancellationToken ct)
    {
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        using var command = connection.CreateCommand();
        command.CommandText = "select exists(select 1 from source_records where source_code = $1 limit 1)";
        command.Parameters.Add(new DuckDBParameter(sourceCode));
        return Convert.ToBoolean(await command.ExecuteScalarAsync(ct));
    }

    public async Task<object> GetPrimaryStatusAsync(CancellationToken ct)
    {
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        var spoolRoot = Options.ResolveSpoolRoot();
        var incoming = Path.Combine(spoolRoot, "incoming");
        var readyFiles = Directory.Exists(incoming)
            ? Directory.EnumerateFiles(incoming, "*.ndjson.ready").ToArray()
            : [];
        var processingFiles = Directory.Exists(incoming)
            ? Directory.EnumerateFiles(incoming, "*.ndjson.processing").ToArray()
            : [];
        var schedulerSources = Options.Scheduler.SourceCodes();
        return new
        {
            storageBackend = "duckdb",
            database = new
            {
                path = DatabasePath,
                fileBytes = File.Exists(DatabasePath) ? new FileInfo(DatabasePath).Length : 0,
                sourceRecords = Count(connection, "source_records"),
                vulnerabilities = Count(connection, "vulnerabilities"),
                identifiers = Count(connection, "vulnerability_identifiers"),
                affectedFacts = Count(connection, "affected_facts"),
                affectedComponents = Count(connection, "affected_components"),
                severityScores = Count(connection, "severity_scores"),
                references = Count(connection, "evidence_references"),
                weaknesses = Count(connection, "weaknesses"),
                exploits = CountActiveExploits(connection),
                threatScores = Count(connection, "threat_scores"),
                aiAnalyses = Count(connection, "ai_vulnerability_analyses"),
                sboms = Count(connection, "sbom_uploads")
            },
            queue = new
            {
                readyFiles = readyFiles.Length,
                readyBytes = readyFiles.Sum(file => new FileInfo(file).Length),
                processingFiles = processingFiles.Length
            },
            scheduler = new
            {
                enabled = Options.Scheduler.Enabled,
                sources = schedulerSources,
                sourceStatus = schedulerSources.Select(source => ReadSpoolSourceStatus(spoolRoot, source)).ToArray()
            }
        };
    }

    private static object ReadSpoolSourceStatus(string spoolRoot, string sourceCode)
    {
        var path = Path.Combine(spoolRoot, "state", $"{sourceCode}.json");
        if (!File.Exists(path))
            return new { code = sourceCode, status = "never-run", stateUpdatedAt = (DateTimeOffset?)null };

        try
        {
            var state = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(path));
            var checkpoint = state?["checkpoint"];
            var lastRun = state?["lastRun"];
            var skipReason = checkpoint?["skipped"]?.ToString();
            return new
            {
                code = sourceCode,
                status = lastRun?["status"]?.GetValue<string>() ?? "unknown",
                trigger = lastRun?["trigger"]?.GetValue<string>(),
                startedAt = lastRun?["started_at"]?.GetValue<string>(),
                finishedAt = lastRun?["finished_at"]?.GetValue<string>(),
                lastFetched = checkpoint?["lastFetched"]?.GetValue<string>()
                    ?? checkpoint?["lastChecked"]?.GetValue<string>()
                    ?? lastRun?["finished_at"]?.GetValue<string>(),
                fetchedCount = lastRun?["fetched_count"]?.GetValue<int>() ?? 0,
                parsedCount = lastRun?["parsed_count"]?.GetValue<int>() ?? 0,
                errorCount = lastRun?["error_count"]?.GetValue<int>() ?? 0,
                skipped = !string.IsNullOrWhiteSpace(skipReason)
                    && !string.Equals(skipReason, "false", StringComparison.OrdinalIgnoreCase),
                skipReason,
                stateUpdatedAt = new DateTimeOffset(File.GetLastWriteTimeUtc(path))
            };
        }
        catch
        {
            return new
            {
                code = sourceCode,
                status = "invalid-state",
                stateUpdatedAt = (DateTimeOffset?)new DateTimeOffset(File.GetLastWriteTimeUtc(path))
            };
        }
    }

    public async Task<DuckDbEvidenceStats> StatsAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;

        var file = new FileInfo(DatabasePath);
        return new DuckDbEvidenceStats(
            DatabasePath,
            file.Exists ? file.Length : 0,
            Count(connection, "affected_facts"),
            Count(connection, "affected_components"),
            Count(connection, "severity_scores"),
            Count(connection, "evidence_references"),
            Count(connection, "weaknesses"));
    }

    public async Task<object> CoverageStatusAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;

        using var sourceCommand = connection.CreateCommand();
        sourceCommand.CommandText = """
            select source_code,
                   count(*) as records,
                   count(distinct vulnerability_key) as vulnerabilities,
                   max(nullif(modified_at, '')) as latest_modified_at
            from source_records
            group by source_code
            order by records desc, source_code
            """;
        var sources = await ReadRowsAsync(sourceCommand, ct);

        using var ecosystemCommand = connection.CreateCommand();
        ecosystemCommand.CommandText = """
            select coalesce(nullif(ecosystem_lower, ''), 'unknown') as ecosystem,
                   count(*) as components,
                   count(distinct vulnerability_id) as vulnerabilities,
                   count(*) filter (where normalized_range is not null and normalized_range <> '') as ranged_components,
                   count(*) filter (where purl_without_version is not null and purl_without_version <> '') as purl_components,
                   count(*) filter (where primary_cpe23_uri is not null and primary_cpe23_uri <> '') as cpe_components
            from affected_components
            group by coalesce(nullif(ecosystem_lower, ''), 'unknown')
            order by components desc, ecosystem
            """;
        var ecosystems = await ReadRowsAsync(ecosystemCommand, ct);

        return new
        {
            sources,
            ecosystems,
            generatedAt = DateTimeOffset.UtcNow
        };
    }
}
