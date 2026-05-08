namespace VulTrack.App;

public sealed record ProcessPendingRequest(int Limit = 100);

public sealed record ProcessPendingResult(int Processed, int Failed);

public sealed record VulnerabilitySearchRequest(string? Query = null, int Page = 1, int PageSize = 50);

public sealed record NormalizePendingRequest(int LimitPerSource = 100);

public sealed record ComponentVulnerabilitySearchRequest(
    string? ComponentName = null,
    string? Version = null,
    string? Vendor = null,
    string? Purl = null,
    string? Ecosystem = null,
    int PageSize = 50);

public sealed record ComponentSearchRequest(
    string? Query = null,
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
    bool? VersionMatched);
