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
}

