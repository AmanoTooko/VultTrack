using Npgsql;

namespace VulTrack.App;

public interface IRawNormalizer
{
    string SourceCode { get; }
    Task<NormalizeBatchResult> ProcessPendingAsync(NpgsqlConnection connection, int limit, CancellationToken ct);
}

public interface ISourceScopedRawNormalizer : IRawNormalizer
{
    IReadOnlySet<string> SupportedSourceCodes { get; }
    Task<NormalizeBatchResult> ProcessSourcePendingAsync(NpgsqlConnection connection, string sourceCode, int limit, CancellationToken ct);
}

public interface IRawNormalizationService
{
    Task<IReadOnlyList<NormalizeBatchResult>> ProcessPendingAsync(int limitPerSource, CancellationToken ct);
    Task<NormalizeBatchResult> ProcessSourcePendingAsync(string sourceCode, int limit, CancellationToken ct);
}

public interface IAffectedComponentHook
{
    Task OnAffectedFactsAsync(NpgsqlConnection connection, Guid vulnerabilityId, Guid vulnerabilityRecordId, IReadOnlyList<AffectedFactDraft> facts, CancellationToken ct);
    Task FlushProjectionsAsync(NpgsqlConnection connection, IReadOnlyList<Guid> vulnerabilityIds, CancellationToken ct);
}

public interface IVulnerabilityCanonicalizer
{
    Task<Guid> UpsertCanonicalAsync(NpgsqlConnection connection, VulnerabilityCanonicalDraft draft, CancellationToken ct);
    Task<Dictionary<string, Guid>> ResolveCanonicalIdsBatchAsync(NpgsqlConnection connection, IReadOnlyList<VulnerabilityCanonicalDraft> drafts, CancellationToken ct);
    Task<Guid> GetOrCreateCanonicalAsync(NpgsqlConnection connection, VulnerabilityCanonicalDraft draft, Dictionary<string, Guid>? cache, CancellationToken ct);
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

public sealed record DescriptionDraft(
    string? Lang,
    string DescriptionType,
    string Value,
    bool IsSelected = false);

public sealed record SeverityScoreDraft(
    string ScoringSystem,
    string? ScoringVersion,
    string? ScoreType,
    string? VectorString,
    decimal? Score,
    string? SeverityLabel,
    string MetricJson,
    bool IsSelected = false);

public sealed record ReferenceDraft(
    string Url,
    string? RefType,
    string[] Tags,
    string? SourceJsonPath = null);

public sealed record WeaknessDraft(
    string WeaknessType,
    string? WeaknessId,
    string? Description);
