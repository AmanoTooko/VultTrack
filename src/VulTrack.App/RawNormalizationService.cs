using Npgsql;

namespace VulTrack.App;

public sealed class RawNormalizationService(
    NpgsqlDataSource db,
    IEnumerable<IRawNormalizer> normalizers,
    ILogger<RawNormalizationService> logger) : IRawNormalizationService
{
    public async Task<IReadOnlyList<NormalizeBatchResult>> ProcessPendingAsync(int limitPerSource, CancellationToken ct)
    {
        var results = new List<NormalizeBatchResult>();
        await using var connection = await db.OpenConnectionAsync(ct);
        await SupersedeOlderPendingRawAsync(connection, null, ct);

        foreach (var normalizer in normalizers)
        {
            try
            {
                var result = await normalizer.ProcessPendingAsync(connection, limitPerSource, ct);
                results.Add(result);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Normalizer {SourceCode} failed", normalizer.SourceCode);
                results.Add(new NormalizeBatchResult(normalizer.SourceCode, 0, 1));
            }
        }

        return results;
    }

    public async Task<NormalizeBatchResult> ProcessSourcePendingAsync(string sourceCode, int limit, CancellationToken ct)
    {
        await using var connection = await db.OpenConnectionAsync(ct);
        await SupersedeOlderPendingRawAsync(connection, sourceCode, ct);

        var scoped = normalizers.OfType<ISourceScopedRawNormalizer>().FirstOrDefault(x => x.SupportedSourceCodes.Contains(sourceCode));
        if (scoped is not null)
        {
            return await scoped.ProcessSourcePendingAsync(connection, sourceCode, limit, ct);
        }

        var normalizer = normalizers.FirstOrDefault(x => string.Equals(x.SourceCode, sourceCode, StringComparison.OrdinalIgnoreCase));
        if (normalizer is null)
        {
            return new NormalizeBatchResult(sourceCode, 0, 0);
        }

        try
        {
            var result = await normalizer.ProcessPendingAsync(connection, limit, ct);
            return result.SourceCode.Equals(sourceCode, StringComparison.OrdinalIgnoreCase)
                ? result
                : new NormalizeBatchResult(sourceCode, result.Processed, result.Failed);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Normalizer {SourceCode} failed for source-scoped request", sourceCode);
            return new NormalizeBatchResult(sourceCode, 0, 1);
        }
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
        {
            logger.LogInformation("Marked {Count} older raw snapshots as superseded for {SourceCode}.", superseded, sourceCode ?? "all sources");
        }
    }
}
