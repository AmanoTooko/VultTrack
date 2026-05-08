using Npgsql;

namespace VulTrack.App;

public interface IRawNormalizer
{
    string SourceCode { get; }
    Task<NormalizeBatchResult> ProcessPendingAsync(NpgsqlConnection connection, int limit, CancellationToken ct);
}

public interface IRawNormalizationService
{
    Task<IReadOnlyList<NormalizeBatchResult>> ProcessPendingAsync(int limitPerSource, CancellationToken ct);
}

public interface IAffectedComponentHook
{
    Task OnAffectedFactsAsync(NpgsqlConnection connection, Guid vulnerabilityId, Guid vulnerabilityRecordId, IReadOnlyList<AffectedFactDraft> facts, CancellationToken ct);
}

public interface IVulnerabilityCanonicalizer
{
    Task<Guid> UpsertCanonicalAsync(NpgsqlConnection connection, VulnerabilityCanonicalDraft draft, CancellationToken ct);
}

public sealed record NormalizeBatchResult(string SourceCode, int Processed, int Failed);

public sealed record VulnerabilityCanonicalDraft(
    string PreferredIdentifier,
    string? Title,
    string? Description,
    string? Status,
    DateTimeOffset? PublishedAt,
    DateTimeOffset? ModifiedAt,
    string[] Identifiers,
    Guid SourceId,
    Guid RawIndexId);

public sealed record AffectedFactDraft(
    string FactType,
    string? Ecosystem,
    string? PackageName,
    string? Purl,
    string? VersionRange,
    string? RangeType,
    string SourceSpecificJson);
