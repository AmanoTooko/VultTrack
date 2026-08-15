namespace VulTrack.App;

public sealed record VulnerabilitySearchRequest(
    string? Query = null,
    int Page = 1,
    int PageSize = 50,
    string? Sort = "modifiedDesc");

public sealed record AdminLoginRequest(string Username, string Password);

public sealed record DuckDbAiImportRequest(string Path, long? ExpectedRows = null);

public sealed record DuckDbSourceFetchRequest(
    string SourceCode,
    bool Force = false,
    int Limit = 0);

public sealed record AiSummaryRequest(
    Guid Id,
    bool Force = false);

public sealed record ComponentVulnerabilitySearchRequest(
    string? ComponentName = null,
    string? Name = null,
    string? Version = null,
    string? Vendor = null,
    string? Purl = null,
    string? Ecosystem = null,
    int PageSize = 50);

public sealed record ComponentSearchRequest(
    string? Query = null,
    string? Name = null,
    string? Vendor = null,
    string? Version = null,
    string? Purl = null,
    string? Ecosystem = null,
    int PageSize = 50);

public sealed record ComponentVulnerabilitySearchResult(
    string? ComponentName,
    string? Purl,
    string? PurlWithoutVersion,
    IReadOnlyList<ComponentVulnerabilityMatch> Items);

public sealed record ComponentVulnerabilityMatch(
    Guid VulnerabilityId,
    string PrimaryIdentifier,
    string? Title,
    string? SeverityLabel,
    decimal? CvssScore,
    string? Ecosystem,
    string? PackageName,
    string? Purl,
    string? VersionRange,
    string? RangeType,
    string[] Identifiers,
    string[] Aliases,
    bool? VersionMatched,
    string[] UpstreamIdentifiers,
    string[] RelatedIdentifiers);

public sealed record SbomMatchRequest(
    Guid SbomId);

public sealed record SbomDeleteRequest(
    Guid SbomId);
