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

public sealed record DuckDbExploit(
    string SourceCode,
    Guid RawIndexId,
    string SourceKey,
    string[] Identifiers,
    string? Title,
    string? SourceUrl,
    string? ArtifactType,
    string? ExploitType,
    string? Maturity,
    string? VerificationStatus,
    string? PublishedAt,
    string? ModifiedAt);

public sealed record DuckDbThreatScore(
    string SourceCode,
    Guid RawIndexId,
    string VulnerabilityKey,
    string ScoreType,
    double? Score,
    double? Percentile,
    string? ObservedAt);

public sealed record DuckDbEvidenceRecord(
    string SourceCode,
    Guid RawIndexId,
    string VulnerabilityKey,
    string SourceRecordId,
    IReadOnlyList<DuckDbAffectedFact> AffectedFacts,
    IReadOnlyList<DuckDbSeverityScore> SeverityScores,
    IReadOnlyList<DuckDbReference> References,
    IReadOnlyList<DuckDbWeakness> Weaknesses);

public sealed record DuckDbCatalogRecord(
    string SourceCode,
    string SourceRecordId,
    Guid VulnerabilityId,
    string VulnerabilityKey,
    string? Title,
    string? Description,
    string? Status,
    string? PublishedAt,
    string? ModifiedAt,
    string? SourceUrl,
    string RecordHash,
    IReadOnlyList<string> Identifiers,
    IReadOnlyList<string>? UpstreamIdentifiers = null,
    IReadOnlyList<string>? RelatedIdentifiers = null,
    string NormalizationVersion = "catalog-v1");

public sealed record DuckDbVulnerabilityRelations(
    string[] UpstreamIdentifiers,
    string[] RelatedIdentifiers);

public sealed record DuckDbCatalogStats(long SourceRecords, long Vulnerabilities, long Identifiers);
public sealed record DuckDbSourceProjectionState(IReadOnlyList<string> VulnerabilityKeys, bool HasAffectedFacts);
public sealed record DuckDbNucleiSnapshotStats(long ActiveRows, long ActiveDistinctRawIds);
public sealed record DuckDbFirstEpssApplyResult(
    long InputRows,
    long InsertedRows,
    long UpdatedRows,
    long UnchangedRows,
    long ElapsedMs);

public sealed record DuckDbCatalogVulnerability(
    Guid Id,
    string PrimaryIdentifier,
    string? Title,
    string? Description,
    string? Status,
    string? SeverityLabel,
    double? MaxCvssScore,
    long AffectedComponentCount,
    string[] AffectedComponentNames,
    string[] Identifiers,
    string? PublishedAt,
    string? ModifiedAt,
    long SourceCount);

public sealed record DuckDbCatalogListItem(
    Guid Id,
    string PrimaryIdentifier,
    string? Title,
    string? SeverityLabel,
    double? MaxCvssScore,
    long AffectedComponentCount,
    string[] AffectedComponentNames,
    string? PublishedAt,
    string? ModifiedAt);

public sealed record DuckDbCatalogSearchResult(
    IReadOnlyList<DuckDbCatalogListItem> Items,
    int Page,
    int PageSize,
    string Sort,
    bool HasMore);

public sealed record DuckDbComponentCatalogItem(
    Guid Id,
    string CanonicalName,
    string ComponentType,
    string? PrimaryPurl,
    string? PrimaryCpe23Uri,
    string[] Identities);

public sealed record DuckDbSbomUpload(
    Guid Id,
    string Name,
    string Format,
    int ComponentCount,
    int MatchedCount,
    DateTime UploadedAt);

public sealed record DuckDbSbomComponent(
    Guid Id,
    Guid SbomId,
    string? Purl,
    string? Name,
    string? Version,
    string? Ecosystem,
    string? GroupName,
    string? Vendor,
    string? Product,
    string? Cpe23Uri,
    string? SourcePackageName,
    string? SourcePackageVersion,
    string? ComponentType,
    string MetadataJson,
    int VulnCount);

public sealed record DuckDbSbomMatch(
    Guid ComponentId,
    Guid VulnerabilityId,
    string? Purl,
    string? DisplayName,
    string? Ecosystem,
    string? Range,
    bool? VersionMatched,
    string? Basis,
    string? MatchedVersion);

public sealed record DuckDbSbomFinding(
    Guid Id,
    Guid ComponentId,
    Guid VulnerabilityId,
    string PrimaryIdentifier,
    string? Title,
    string? SeverityLabel,
    double? CvssScore,
    string? ComponentName,
    string? Ecosystem,
    string? VersionRange,
    bool? VersionMatched,
    string? MatchBasis,
    string? MatchedVersion,
    string[] Identifiers,
    string[] Aliases);

public sealed record DuckDbAffectedComponentProjection(
    Guid Id,
    Guid VulnerabilityId,
    Guid? ComponentId,
    string? Ecosystem,
    string? PackageName,
    string DisplayName,
    string? PrimaryPurl,
    string? PrimaryCpe23Uri,
    string? NormalizedRange,
    string? RangeType,
    decimal Confidence,
    int EvidenceCount,
    string ResolutionStatus);

public sealed record DuckDbEvidenceStats(
    string path,
    long fileBytes,
    long affectedFacts,
    long affectedComponents,
    long severityScores,
    long references,
    long weaknesses);

public sealed record DuckDbSbomMatchComponent(
    Guid ComponentId,
    string? Purl,
    string? PurlDecoded,
    string? PurlWithoutVersion,
    string? Name,
    string? Version,
    string? Ecosystem,
    string? MappedEcosystem,
    string? Cpe23Uri,
    string? CpePrefix,
    string? CpeProduct,
    string? SourcePackageName,
    string? SourcePackageVersion);

public sealed record DuckDbSbomCandidateMatch(
    Guid ComponentId,
    string? Purl,
    string? ComponentVersion,
    string? ComponentCpe,
    string? SourcePackageVersion,
    Guid VulnerabilityId,
    string? DisplayName,
    string? Ecosystem,
    string? Range,
    string? MatchedCpe,
    string? Basis);

public sealed record DuckDbComponentVulnerabilityCandidate(
    Guid VulnerabilityId,
    string? Ecosystem,
    string? PackageName,
    string? Purl,
    string? VersionRange,
    string? RangeType);

public sealed record DuckDbAffectedEcosystemPackageSummary(
    string Ecosystem,
    string PackageName,
    long TotalCves,
    long FactCount);

public sealed record DuckDbAffectedMatchingQualitySummary(
    string Ecosystem,
    long Facts,
    long Vulnerabilities,
    long PurlFacts,
    long CpeFacts,
    long NoRange,
    long OpenLowerBound,
    long UnparseableRange);

public sealed record DuckDbAffectedComponentSummary(
    Guid VulnerabilityId,
    int Count,
    string[] Ecosystems,
    string[] Names);

public sealed record DuckDbVulnerabilityKeyMapping(
    Guid VulnerabilityId,
    string VulnerabilityKey);
