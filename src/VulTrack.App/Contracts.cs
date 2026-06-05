namespace VulTrack.App;

public sealed record ProcessPendingRequest(int Limit = 100);

public sealed record ProcessPendingResult(int Processed, int Failed);

public sealed record VulnerabilitySearchRequest(
    string? Query = null,
    int Page = 1,
    int PageSize = 50,
    string? Sort = "modifiedDesc");

public sealed record NormalizePendingRequest(int LimitPerSource = 100);

public sealed record NormalizeSourceRequest(
    string SourceCode,
    int Limit = 100);

public sealed record AdminLoginRequest(string Username, string Password);

public sealed record AdminSourceUpdateRequest(
    string SourceCode,
    bool Enabled,
    string? ScheduleCron = null,
    string? RunMode = null);

public sealed record AdminSourceActionRequest(
    string SourceCode,
    bool Force = false,
    int Limit = 100);

public sealed record DetailSnapshotBuildRequest(
    string? Shard = null,
    int Limit = 100,
    string? Since = null,
    Guid[]? Ids = null,
    bool ConsumeQueue = false,
    int Concurrency = 4,
    int GzipLevel = 6);

public sealed record DuckDbAffectedComponentRebuildRequest(
    bool Reset = true,
    int BatchSize = 100000,
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
    bool? VersionMatched);

public sealed record SbomUploadRequest(
    string Name,
    string Content);

public sealed record SbomMatchRequest(
    Guid SbomId);

public sealed record SbomDeleteRequest(
    Guid SbomId);
