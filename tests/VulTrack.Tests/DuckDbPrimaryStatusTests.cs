using System.Text.Json;
using Microsoft.Extensions.Configuration;
using VulTrack.App;

namespace VulTrack.Tests;

[Collection("DuckDbSpoolEnvironment")]
public sealed class DuckDbPrimaryStatusTests
{
    [Fact]
    public async Task StringSkipReason_RemainsAValidSuccessfulSourceStatus()
    {
        var root = Path.Combine(Path.GetTempPath(), "vultrack-primary-status-tests", Guid.NewGuid().ToString("N"));
        var spool = Path.Combine(root, "spool");
        var previousSpool = Environment.GetEnvironmentVariable("VULTRACK_SPOOL_PATH");
        var previousSources = Environment.GetEnvironmentVariable("DUCKDB_FETCH_SOURCES");
        Directory.CreateDirectory(Path.Combine(spool, "state"));
        Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", spool);
        Environment.SetEnvironmentVariable("DUCKDB_FETCH_SOURCES", "osv");
        try
        {
            await File.WriteAllTextAsync(
                Path.Combine(spool, "state", "osv.json"),
                """
                {
                  "checkpoint": {
                    "skipped": "not-modified",
                    "lastFetched": "2026-08-14T00:00:00Z"
                  },
                  "lastRun": {
                    "status": "succeeded",
                    "fetched_count": 0,
                    "parsed_count": 0,
                    "error_count": 0
                  }
                }
                """);
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["VulTrack:DuckDb:Path"] = Path.Combine(root, "status.duckdb"),
                    ["VulTrack:DuckDb:Enabled"] = "true"
                })
                .Build();
            using var store = new DuckDbEvidenceStore(configuration);

            var json = JsonSerializer.Serialize(await store.GetPrimaryStatusAsync(CancellationToken.None));

            Assert.Contains("\"status\":\"succeeded\"", json, StringComparison.Ordinal);
            Assert.Contains("\"skipped\":true", json, StringComparison.Ordinal);
            Assert.Contains("\"skipReason\":\"not-modified\"", json, StringComparison.Ordinal);
            Assert.DoesNotContain("invalid-state", json, StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", previousSpool);
            Environment.SetEnvironmentVariable("DUCKDB_FETCH_SOURCES", previousSources);
            Directory.Delete(root, recursive: true);
        }
    }
}
