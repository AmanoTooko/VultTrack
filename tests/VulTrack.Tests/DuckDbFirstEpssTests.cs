using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using VulTrack.App;

namespace VulTrack.Tests;

[Collection("DuckDbSpoolEnvironment")]
public sealed class DuckDbFirstEpssTests
{
    [Fact]
    public async Task NativeGzipPipeline_BaselineNoChangeSingleChangeAndFailureAreAtomic()
    {
        var root = Path.Combine(Path.GetTempPath(), "vultrack-epss-tests", Guid.NewGuid().ToString("N"));
        var previousSpoolPath = Environment.GetEnvironmentVariable("VULTRACK_SPOOL_PATH");
        Directory.CreateDirectory(root);
        Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", root);
        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["VulTrack:DuckDb:Path"] = Path.Combine(root, "epss.duckdb"),
                    ["VulTrack:DuckDb:Enabled"] = "true"
                })
                .Build();
            using var store = new DuckDbEvidenceStore(configuration);
            var normalizer = new DuckDbEvidenceNormalizer(
                new UnusedServiceProvider(), store, NullLogger<DuckDbEvidenceNormalizer>.Instance);

            var baseline = EpssCsv(
                "CVE-2026-0001,0.01,0.10",
                "CVE-2026-0002,0.02,0.20",
                "CVE-2026-0003,0.03,0.30");
            await WriteReadySnapshotAsync(root, "baseline", baseline, "2026-07-28T00:00:00Z");
            var first = await normalizer.IngestFirstEpssSnapshotsAsync(10, CancellationToken.None);
            var baselineFile = Assert.Single(first.Files);
            Assert.Equal(3, baselineFile.InputRows);
            Assert.Equal(3, baselineFile.InsertedRows);
            Assert.Equal(0, baselineFile.UpdatedRows);
            Assert.Equal(0.02, Score(await store.QueryThreatScoresAsync("CVE-2026-0002", ct: CancellationToken.None)), 6);
            Assert.Equal(0.20, Percentile(await store.QueryThreatScoresAsync("CVE-2026-0002", ct: CancellationToken.None)), 6);
            var baselineState = await ReadCheckpointAsync(root);

            await WriteReadySnapshotAsync(root, "unchanged", baseline, "2026-07-28T01:00:00Z");
            var unchanged = Assert.Single((await normalizer.IngestFirstEpssSnapshotsAsync(10, CancellationToken.None)).Files);
            Assert.Equal(0, unchanged.InsertedRows);
            Assert.Equal(0, unchanged.UpdatedRows);
            Assert.Equal(3, unchanged.UnchangedRows);
            Assert.Equal(0.02, Score(await store.QueryThreatScoresAsync("CVE-2026-0002", ct: CancellationToken.None)), 6);

            var changed = EpssCsv(
                "CVE-2026-0001,0.01,0.10",
                "CVE-2026-0002,0.025,0.25",
                "CVE-2026-0003,0.03,0.30");
            await WriteReadySnapshotAsync(root, "single-change", changed, "2026-07-28T02:00:00Z");
            var singleChange = Assert.Single((await normalizer.IngestFirstEpssSnapshotsAsync(10, CancellationToken.None)).Files);
            Assert.Equal(0, singleChange.InsertedRows);
            Assert.Equal(1, singleChange.UpdatedRows);
            Assert.Equal(2, singleChange.UnchangedRows);
            Assert.Equal(0.025, Score(await store.QueryThreatScoresAsync("CVE-2026-0002", ct: CancellationToken.None)), 6);
            Assert.Equal(0.25, Percentile(await store.QueryThreatScoresAsync("CVE-2026-0002", ct: CancellationToken.None)), 6);
            Assert.Equal(0.01, Score(await store.QueryThreatScoresAsync("CVE-2026-0001", ct: CancellationToken.None)), 6);

            var stateBeforeFailure = await ReadCheckpointAsync(root);
            Assert.NotEqual(baselineState["contentHash"]?.GetValue<string>(), stateBeforeFailure["contentHash"]?.GetValue<string>());
            await WriteReadySnapshotAsync(root, "invalid", EpssCsv("CVE-2026-0002,1.1,0.20"), "2026-07-28T03:00:00Z");
            await Assert.ThrowsAsync<InvalidDataException>(() => normalizer.IngestFirstEpssSnapshotsAsync(10, CancellationToken.None));
            Assert.Equal(0.025, Score(await store.QueryThreatScoresAsync("CVE-2026-0002", ct: CancellationToken.None)), 6);
            Assert.Equal(stateBeforeFailure["contentHash"]?.GetValue<string>(), (await ReadCheckpointAsync(root))["contentHash"]?.GetValue<string>());
            Assert.True(Directory.EnumerateFiles(Path.Combine(root, "incoming"), "first-epss-invalid.epss.*.ready").Any());
        }
        finally
        {
            Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", previousSpoolPath);
            Directory.Delete(root, recursive: true);
        }
    }

    private static async Task WriteReadySnapshotAsync(string root, string name, string csv, string observedAt)
    {
        var incoming = Path.Combine(root, "incoming");
        Directory.CreateDirectory(incoming);
        var gzip = Compress(csv);
        var hash = Convert.ToHexString(SHA256.HashData(gzip)).ToLowerInvariant();
        await File.WriteAllBytesAsync(Path.Combine(incoming, $"first-epss-{name}.epss.csv.gz.ready"), gzip);
        await File.WriteAllTextAsync(Path.Combine(incoming, $"first-epss-{name}.epss.json.ready"), JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            sourceCode = "first-epss",
            runId = name,
            observedAt,
            contentHash = hash,
            bytes = gzip.Length,
            sourceUrl = "https://www.first.org/epss/"
        }));
    }

    private static async Task<JsonObject> ReadCheckpointAsync(string root) =>
        JsonNode.Parse(await File.ReadAllTextAsync(Path.Combine(root, "state", "first-epss.json")))!["checkpoint"]!.AsObject();

    private static byte[] Compress(string value)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.SmallestSize, leaveOpen: true))
        using (var writer = new StreamWriter(gzip, Encoding.UTF8, 1024, leaveOpen: false))
            writer.Write(value);
        return output.ToArray();
    }

    private static string EpssCsv(params string[] rows) =>
        string.Join('\n', new[] { "#model_version:v2025.03.14,score_date:2026-07-28", "cve,epss,percentile" }.Concat(rows));

    private static double Score(IReadOnlyList<Dictionary<string, object?>> rows) => Convert.ToDouble(Assert.Single(rows)["score"]);
    private static double Percentile(IReadOnlyList<Dictionary<string, object?>> rows) => Convert.ToDouble(Assert.Single(rows)["percentile"]);

    private sealed class UnusedServiceProvider : IServiceProvider
    {
        public object? GetService(Type serviceType) => null;
    }
}
