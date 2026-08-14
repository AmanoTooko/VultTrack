namespace VulTrack.App;

public static class ComponentEndpoints
{
    public static WebApplication MapComponentEndpoints(this WebApplication app)
    {
        app.MapPost("/api/v1/component.vulnerabilitySearch", async (ComponentVulnerabilitySearchService search, ComponentVulnerabilitySearchRequest request, CancellationToken ct) =>
        {
            var result = await search.SearchAsync(request, ct);
            return ApiResult.Ok(result);
        });

        app.MapPost("/api/v1/component.search", async (DuckDbEvidenceStore duckDb, ComponentSearchRequest request, CancellationToken ct) =>
        {
            var pageSize = request.PageSize <= 0 ? 50 : Math.Min(request.PageSize, 200);
            var lookup = ComponentQuery.Normalize(request.Name ?? request.Query, request.Vendor, request.Purl, request.Ecosystem);
            var queryText = request.Query?.Trim() ?? request.Name?.Trim() ?? "";
            var duckComponents = await duckDb.SearchComponentCatalogAsync(queryText, lookup, pageSize, ct);
            var componentItems = duckComponents.Select(item => new
            {
                id = item.Id,
                canonicalName = item.CanonicalName,
                componentType = item.ComponentType,
                primaryPurl = item.PrimaryPurl,
                primaryCpe23Uri = item.PrimaryCpe23Uri,
                primaryRepositoryUrl = (string?)null,
                identities = item.Identities
            });
            return ApiResult.Ok(new { components = componentItems, registryPackages = Array.Empty<object>(), source = "duckdb" });
        });

        return app;
    }
}
