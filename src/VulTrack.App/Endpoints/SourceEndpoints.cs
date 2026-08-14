using System.Text.Json.Nodes;

namespace VulTrack.App;

public static class SourceEndpoints
{
    public static WebApplication MapSourceEndpoints(this WebApplication app)
    {
        app.MapGet("/api/v1/source.list", (VulTrackOptions options) => ApiResult.Ok(DuckDbConfiguredSources(options)));
        return app;
    }

    internal static object[] DuckDbConfiguredSources(VulTrackOptions options)
    {
        var spoolRoot = options.ResolveSpoolRoot();
        return options.Scheduler.SourceCodes()
            .Select(code =>
            {
                JsonNode? state = null;
                var statePath = Path.Combine(spoolRoot, "state", $"{code}.json");
                try { if (File.Exists(statePath)) state = JsonNode.Parse(File.ReadAllText(statePath)); }
                catch { }
                return (object)new
                {
                    code,
                    name = code,
                    kind = "vulnerability",
                    enabled = true,
                    pluginName = code,
                    scheduleCron = (string?)null,
                    runMode = "incremental",
                    storageBackend = "duckdb",
                    checkpoint = state?["checkpoint"],
                    latestRun = state?["lastRun"]
                };
            })
            .ToArray();
    }
}
