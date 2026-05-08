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
}
