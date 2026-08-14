using System.Text.Json.Nodes;

namespace VulTrack.App;

public static class SourceEndpoints
{
    public static WebApplication MapSourceEndpoints(this WebApplication app)
    {
        app.MapGet("/api/v1/source.list", () => ApiResult.Ok(DuckDbConfiguredSources()));
        return app;
    }

    internal static object[] DuckDbConfiguredSources()
    {
        var spoolRoot = Environment.GetEnvironmentVariable("VULTRACK_SPOOL_PATH")
            ?? Path.Combine(Environment.GetEnvironmentVariable("VULTRACK_REPO_ROOT") ?? Directory.GetCurrentDirectory(), "data", "spool");
        return (Environment.GetEnvironmentVariable("DUCKDB_FETCH_SOURCES") ?? "nvd-cve,osv,cisa-kev,first-epss,exploitdb,nuclei-templates,metasploit,poc-in-github,cargo-advisory")
            .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase)
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
