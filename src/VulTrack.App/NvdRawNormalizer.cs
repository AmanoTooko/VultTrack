using Npgsql;

namespace VulTrack.App;

public sealed class NvdRawNormalizer(NvdRawProcessor processor) : ISourceScopedRawNormalizer
{
    public string SourceCode => "nvd-cve";
    public IReadOnlySet<string> SupportedSourceCodes { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "nvd-cve",
        "nvd-cve-init"
    };

    public async Task<NormalizeBatchResult> ProcessPendingAsync(NpgsqlConnection connection, int limit, CancellationToken ct)
        => await ProcessSourcePendingAsync(connection, SourceCode, limit, ct);

    public async Task<NormalizeBatchResult> ProcessSourcePendingAsync(NpgsqlConnection connection, string sourceCode, int limit, CancellationToken ct)
    {
        var result = await processor.ProcessPendingAsync(limit, sourceCode, ct);
        return new NormalizeBatchResult(sourceCode, result.Processed, result.Failed);
    }
}
