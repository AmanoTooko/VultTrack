using VulTrack.App;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<ComponentVulnerabilitySearchService>();
builder.Services.AddMemoryCache();
builder.Services.AddSingleton<AdminAuthService>();
builder.Services.AddSingleton<DuckDbEvidenceStore>();
builder.Services.AddSingleton<DuckDbEvidenceNormalizer>();
builder.Services.AddSingleton<DuckDbFirstScheduler>();
builder.Services.AddHostedService(serviceProvider => serviceProvider.GetRequiredService<DuckDbFirstScheduler>());
builder.Services.AddHttpClient<AiVulnerabilitySummaryService>();

var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/", () => Results.Redirect("/index.html"));

app.MapSystemEndpoints();
app.MapAuthEndpoints();
app.MapSourceEndpoints();
app.MapVulnerabilityEndpoints();
app.MapComponentEndpoints();
app.MapAdminEndpoints();
app.MapBenchmarkEndpoints();
SbomEndpoints.Map(app);

try
{
    await app.Services.GetRequiredService<DuckDbEvidenceStore>().SearchCatalogAsync(
        new VulnerabilitySearchRequest("", 1, 25, "modifiedDesc"),
        CancellationToken.None);
    app.Logger.LogInformation("DuckDB vulnerability list cache pages are warm.");
}
catch (Exception ex)
{
    app.Logger.LogWarning(ex, "DuckDB vulnerability list warm-up failed; requests will warm the cache on demand.");
}

app.Run();

public partial class Program;
