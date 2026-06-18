using Npgsql;

namespace VulTrack.App;

public sealed class DuckDbRawNormalizationService(
    NpgsqlDataSource db,
    RawNormalizationService postgresNormalizer,
    DuckDbEvidenceNormalizer normalizer,
    StagingPayloadCompactor payloadCompactor,
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
        var rawIndexIds = await LoadPendingRawIdsAsync(connection, sourceCode, limit, ct);
        if (rawIndexIds.Length == 0)
            return new NormalizeBatchResult(sourceCode, 0, 0);

        var pgResult = await postgresNormalizer.ProcessSourcePendingAsync(sourceCode, limit, ct);
        if (pgResult.Processed <= 0)
            return pgResult;

        var inlineLimit = DuckDbInlineLimit();
        if (inlineLimit <= 0 || rawIndexIds.Length > inlineLimit)
        {
            logger.LogInformation("Skipping inline DuckDB evidence normalization for {SourceCode}: raw_ids={RawIds} exceeds inline_limit={InlineLimit}. Run source-level DuckDB rebuild after bulk PostgreSQL normalization.",
                sourceCode, rawIndexIds.Length, inlineLimit);
            return pgResult;
        }

        try
        {
            var request = new DuckDbEvidenceNormalizeRequest(
                sourceCode,
                Math.Min(DuckDbLimit(limit), rawIndexIds.Length),
                Reset: false,
                BatchSize: DuckDbBatchSize(),
                RawIndexIds: rawIndexIds);
            var result = await normalizer.NormalizeAsync(request, ct);
            var source = result.sources.FirstOrDefault(x => string.Equals(x.sourceCode, sourceCode, StringComparison.OrdinalIgnoreCase));
            if (source is not null)
            {
                await payloadCompactor.CompactAsync(rawIndexIds, ct);
            }
            return source is null
                ? new NormalizeBatchResult(sourceCode, pgResult.Processed, pgResult.Failed + 1)
                : new NormalizeBatchResult(sourceCode, pgResult.Processed, pgResult.Failed);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "DuckDB evidence projection failed after PostgreSQL normalization for {SourceCode}.", sourceCode);
            return new NormalizeBatchResult(sourceCode, pgResult.Processed, pgResult.Failed + 1);
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

    private int DuckDbInlineLimit()
    {
        var configured = Environment.GetEnvironmentVariable("VULTRACK_DUCKDB_INLINE_NORMALIZE_LIMIT")
            ?? configuration["VulTrack:DuckDb:InlineNormalizeLimit"];
        return int.TryParse(configured, out var value) && value >= 0
            ? Math.Min(value, 100_000)
            : 0;
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

}
