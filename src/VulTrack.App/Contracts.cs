namespace VulTrack.App;

public sealed record ProcessPendingRequest(int Limit = 100);

public sealed record ProcessPendingResult(int Processed, int Failed);

public sealed record VulnerabilitySearchRequest(string? Query = null, int Page = 1, int PageSize = 50);
