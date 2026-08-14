using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using System.Text.Json;
using VulTrack.App;

namespace VulTrack.Tests;

[Collection("DuckDbSpoolEnvironment")]
public sealed class DuckDbNucleiSnapshotTests
{
    [Fact]
    public async Task CompleteRevision_ReplacesTheActiveSetWithoutDuplicateKeys()
    {
        var root = Path.Combine(Path.GetTempPath(), "vultrack-nuclei-tests", Guid.NewGuid().ToString("N"));
        var previousAllowLargeDrop = Environment.GetEnvironmentVariable("NUCLEI_ALLOW_LARGE_SNAPSHOT_DROP");
        Directory.CreateDirectory(root);
        Environment.SetEnvironmentVariable("NUCLEI_ALLOW_LARGE_SNAPSHOT_DROP", "false");
        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["VulTrack:DuckDb:Path"] = Path.Combine(root, "nuclei.duckdb"),
                    ["VulTrack:DuckDb:Enabled"] = "true"
                })
                .Build();
            using (var store = new DuckDbEvidenceStore(configuration))
            {

            var firstId = Guid.NewGuid();
            var removedId = Guid.NewGuid();
            var addedId = Guid.NewGuid();
            var thirdId = Guid.NewGuid();
            var first = await store.ApplyNucleiSnapshotAsync(
            [
                Exploit(firstId, "CVE-2024-0001", "revision-a title"),
                Exploit(removedId, "CVE-2024-0002", "removed in revision-b")
            ], "revision-a", CancellationToken.None);
            Assert.Equal(2, first.ActiveRows);
            Assert.Equal(2, first.ActiveDistinctRawIds);

            var second = await store.ApplyNucleiSnapshotAsync(
            [
                Exploit(firstId, "CVE-2024-0001", "revision-b updated title"),
                Exploit(addedId, "CVE-2024-0003", "new in revision-b"),
                Exploit(thirdId, "CVE-2024-0004", "another revision-b template"),
                Exploit(addedId, "CVE-2024-0003", "new in revision-b")
            ], "revision-b", CancellationToken.None);

            Assert.Equal(3, second.ActiveRows);
            Assert.Equal(3, second.ActiveDistinctRawIds);
            Assert.Single(await store.QueryExploitsAsync("CVE-2024-0001", 10, CancellationToken.None));
            Assert.Empty(await store.QueryExploitsAsync("CVE-2024-0002", 10, CancellationToken.None));
            Assert.Single(await store.QueryExploitsAsync("CVE-2024-0003", 10, CancellationToken.None));
            Assert.Single(await store.QueryExploitsAsync("CVE-2024-0004", 10, CancellationToken.None));
            Assert.Equal(second, await store.GetNucleiSnapshotStatsAsync(CancellationToken.None));

            await Assert.ThrowsAsync<InvalidDataException>(() =>
                store.ApplyNucleiSnapshotAsync(
                    [Exploit(firstId, "CVE-2024-0001", "unexpected small revision")],
                    "revision-c", CancellationToken.None));
            Assert.Equal(second, await store.GetNucleiSnapshotStatsAsync(CancellationToken.None));

            await Assert.ThrowsAsync<InvalidDataException>(() =>
                store.ApplyNucleiSnapshotAsync([], "revision-c", CancellationToken.None));
            Assert.Equal(second, await store.GetNucleiSnapshotStatsAsync(CancellationToken.None));
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable("NUCLEI_ALLOW_LARGE_SNAPSHOT_DROP", previousAllowLargeDrop);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task FailedOrOldSpool_IsRecoverableOnlyForTheCurrentCompletedRevision()
    {
        var root = Path.Combine(Path.GetTempPath(), "vultrack-nuclei-spool-tests", Guid.NewGuid().ToString("N"));
        var previousSpoolPath = Environment.GetEnvironmentVariable("VULTRACK_SPOOL_PATH");
        Directory.CreateDirectory(root);
        Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", root);
        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["VulTrack:DuckDb:Path"] = Path.Combine(root, "nuclei.duckdb"),
                    ["VulTrack:DuckDb:Enabled"] = "true"
                })
                .Build();
            using (var store = new DuckDbEvidenceStore(configuration))
            {
                var normalizer = new DuckDbEvidenceNormalizer(
                    new UnusedServiceProvider(), store, NullLogger<DuckDbEvidenceNormalizer>.Instance);
                await WriteCheckpointAsync(root, "revision-a");
                var failedName = "nuclei-templates-recovery-s0000.ndjson.ready";
                await WriteReadySpoolAsync(root, failedName, "revision-b", "CVE-2024-0100");

                await Assert.ThrowsAsync<InvalidDataException>(() => normalizer.IngestSpoolAsync(
                    new DuckDbSpoolIngestRequest(failedName, BatchSize: 100, DeleteOnSuccess: false), CancellationToken.None));
                var failedPath = Path.Combine(root, "incoming", failedName.Replace(".ready", ".failed", StringComparison.Ordinal));
                Assert.True(File.Exists(failedPath));
                Assert.Equal(new DuckDbNucleiSnapshotStats(0, 0), await store.GetNucleiSnapshotStatsAsync(CancellationToken.None));

                await WriteCheckpointAsync(root, "revision-b");
                var recoveredName = failedName.Replace(".failed", ".ready", StringComparison.Ordinal);
                File.Move(failedPath, Path.Combine(root, "incoming", recoveredName));
                await normalizer.IngestSpoolAsync(
                    new DuckDbSpoolIngestRequest(recoveredName, BatchSize: 100, DeleteOnSuccess: false), CancellationToken.None);
                Assert.Single(await store.QueryExploitsAsync("CVE-2024-0100", 10, CancellationToken.None));

                await WriteCheckpointAsync(root, "revision-c", recordCount: 2);
                var countMismatchName = "nuclei-templates-count-mismatch-s0000.ndjson.ready";
                await WriteReadySpoolAsync(root, countMismatchName, "revision-c", "CVE-2024-0102");
                await Assert.ThrowsAsync<InvalidDataException>(() => normalizer.IngestSpoolAsync(
                    new DuckDbSpoolIngestRequest(countMismatchName, BatchSize: 100, DeleteOnSuccess: false), CancellationToken.None));
                Assert.True(File.Exists(Path.Combine(root, "incoming", countMismatchName.Replace(".ready", ".failed", StringComparison.Ordinal))));
                Assert.Single(await store.QueryExploitsAsync("CVE-2024-0100", 10, CancellationToken.None));
                Assert.Empty(await store.QueryExploitsAsync("CVE-2024-0102", 10, CancellationToken.None));

                await WriteCheckpointAsync(root, "revision-b");

                var oldName = "nuclei-templates-old-revision-s0000.ndjson.ready";
                await WriteReadySpoolAsync(root, oldName, "revision-a", "CVE-2024-0101");
                await Assert.ThrowsAsync<InvalidDataException>(() => normalizer.IngestSpoolAsync(
                    new DuckDbSpoolIngestRequest(oldName, BatchSize: 100, DeleteOnSuccess: false), CancellationToken.None));
                Assert.True(File.Exists(Path.Combine(root, "incoming", oldName.Replace(".ready", ".failed", StringComparison.Ordinal))));
                Assert.Single(await store.QueryExploitsAsync("CVE-2024-0100", 10, CancellationToken.None));
                Assert.Empty(await store.QueryExploitsAsync("CVE-2024-0101", 10, CancellationToken.None));
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", previousSpoolPath);
            Directory.Delete(root, recursive: true);
        }
    }

    private static DuckDbExploit Exploit(Guid rawId, string cve, string title) => new(
        "nuclei-templates",
        rawId,
        rawId.ToString("N"),
        [cve],
        title,
        $"https://example.test/{rawId:N}",
        "nuclei_template",
        "scanner",
        "detection-template",
        "template_reviewed",
        null,
        "2026-07-28T00:00:00Z");

    private static async Task WriteCheckpointAsync(string root, string revision, int recordCount = 1)
    {
        var state = Path.Combine(root, "state");
        Directory.CreateDirectory(state);
        await File.WriteAllTextAsync(Path.Combine(state, "nuclei-templates.json"), JsonSerializer.Serialize(new
        {
            checkpoint = new
            {
                gitRevision = revision,
                completedGitRevision = revision,
                snapshotComplete = true,
                recordCount
            }
        }));
    }

    private static async Task WriteReadySpoolAsync(string root, string fileName, string revision, string cve)
    {
        var incoming = Path.Combine(root, "incoming");
        Directory.CreateDirectory(incoming);
        var line = JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            sourceCode = "nuclei-templates",
            sourceMode = (string?)null,
            runId = Guid.NewGuid().ToString("D"),
            snapshotId = revision,
            snapshotComplete = true,
            externalKey = $"templates/{cve}.yaml",
            externalId = cve,
            sourceUrl = $"https://example.test/{cve}",
            modifiedAt = "2026-07-28T00:00:00Z",
            recordHash = cve,
            identifiers = new[] { cve },
            payload = new
            {
                sourceKey = cve,
                identifiers = new[] { cve },
                title = cve,
                sourceUrl = $"https://example.test/{cve}",
                artifactType = "nuclei_template",
                exploitType = "scanner",
                maturity = "detection-template",
                verificationStatus = "template_reviewed",
                payload = new { gitRevision = revision }
            }
        });
        await File.WriteAllTextAsync(Path.Combine(incoming, fileName), line + Environment.NewLine);
    }

    private sealed class UnusedServiceProvider : IServiceProvider
    {
        public object? GetService(Type serviceType) => null;
    }
}
