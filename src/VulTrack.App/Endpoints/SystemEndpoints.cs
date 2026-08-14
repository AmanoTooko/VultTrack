namespace VulTrack.App;

public static class SystemEndpoints
{
    public static WebApplication MapSystemEndpoints(this WebApplication app)
    {
        app.MapGet("/api/v1/system.health", () => ApiResult.Ok(new
        {
            status = "healthy",
            service = "vultrack-app",
            dotnet = Environment.Version.ToString()
        }));

        app.MapGet("/api/v1/system.ready", async (DuckDbEvidenceStore duckDb, CancellationToken ct) =>
        {
            await duckDb.InitializeAsync(ct);
            return ApiResult.Ok(new { status = "ready", storageBackend = "duckdb", path = duckDb.DatabasePath });
        });

        app.MapGet("/api/v1/system.status", async (HttpContext context, AdminAuthService auth, DuckDbEvidenceStore duckDb, CancellationToken ct) =>
        {
            if (!auth.IsAuthenticated(context)) return ApiResult.Unauthorized();
            return ApiResult.Ok(await duckDb.GetPrimaryStatusAsync(ct));
        });

        return app;
    }
}
