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

        app.MapGet("/api/v1/system.ready", async (DuckDbEvidenceStore duckDb, ILoggerFactory loggerFactory, CancellationToken ct) =>
        {
            try
            {
                await duckDb.CheckReadyAsync(ct);
                return ApiResult.Ok(new { status = "ready", storageBackend = "duckdb", path = duckDb.DatabasePath });
            }
            catch (Exception ex)
            {
                loggerFactory.CreateLogger("Readiness").LogError(ex, "DuckDB readiness probe failed.");
                return ApiResult.Unavailable("DUCKDB_NOT_READY", "DuckDB is not ready for queries.");
            }
        });

        app.MapGet("/api/v1/system.status", async (HttpContext context, AdminAuthService auth, DuckDbEvidenceStore duckDb, CancellationToken ct) =>
        {
            if (!auth.IsAuthenticated(context)) return ApiResult.Unauthorized();
            return ApiResult.Ok(await duckDb.GetPrimaryStatusAsync(ct));
        });

        return app;
    }
}
