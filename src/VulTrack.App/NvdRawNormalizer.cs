using Npgsql;

namespace VulTrack.App;

public sealed class NvdRawNormalizer(NvdRawProcessor processor) : IRawNormalizer
{
    public string SourceCode => "nvd-cve";

    public async Task<NormalizeBatchResult> ProcessPendingAsync(NpgsqlConnection connection, int limit, CancellationToken ct)
    {
        var result = await processor.ProcessPendingAsync(limit, ct);
        return new NormalizeBatchResult(SourceCode, result.Processed, result.Failed);
    }
}

