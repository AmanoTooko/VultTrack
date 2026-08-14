using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using VulTrack.App;

namespace VulTrack.Tests;

[Collection("DuckDbSpoolEnvironment")]
public sealed class DuckDbOsvRelationTests
{
    [Fact]
    public async Task UpstreamAndRelatedIds_AreSearchableWithoutMergingAdvisoriesIntoCves()
    {
        var root = Path.Combine(Path.GetTempPath(), "vultrack-osv-relation-tests", Guid.NewGuid().ToString("N"));
        var previousSpoolPath = Environment.GetEnvironmentVariable("VULTRACK_SPOOL_PATH");
        Directory.CreateDirectory(Path.Combine(root, "incoming"));
        Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", root);
        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["VulTrack:DuckDb:Path"] = Path.Combine(root, "relations.duckdb"),
                    ["VulTrack:DuckDb:Enabled"] = "true"
                })
                .Build();
            using var store = new DuckDbEvidenceStore(configuration);
            var normalizer = new DuckDbEvidenceNormalizer(
                new UnusedServiceProvider(), store, NullLogger<DuckDbEvidenceNormalizer>.Instance);

            var staleId = Guid.NewGuid();
            await store.ReplaceCatalogRecordsAsync(
                [
                    new DuckDbCatalogRecord(
                        "osv",
                        "DEBIAN-CVE-2026-10001",
                        staleId,
                        "CVE-2026-10001",
                        "Stale merged advisory",
                        null,
                        "active",
                        null,
                        "2026-08-10T00:00:00Z",
                        "https://example.test/DEBIAN-CVE-2026-10001",
                        "relations-v1",
                        ["DEBIAN-CVE-2026-10001", "CVE-2026-10001"],
                        NormalizationVersion: "osv-relations-v1")
                ],
                CancellationToken.None);
            await store.RebuildCatalogAsync(CancellationToken.None);
            Assert.NotNull(await store.GetCatalogByIdAsync(staleId, CancellationToken.None));

            var fileName = "osv-relations-s0000.ndjson.ready";
            await File.WriteAllTextAsync(
                Path.Combine(root, "incoming", fileName),
                SpoolLine() + Environment.NewLine);
            await normalizer.IngestSpoolAsync(
                new DuckDbSpoolIngestRequest(fileName, BatchSize: 100, DeleteOnSuccess: true),
                CancellationToken.None);

            var advisory = await store.GetCatalogByIdentifierAsync("DEBIAN-CVE-2026-10001", CancellationToken.None);
            Assert.NotNull(advisory);
            Assert.Equal("DEBIAN-CVE-2026-10001", advisory.PrimaryIdentifier);
            Assert.Null(await store.GetCatalogByIdAsync(staleId, CancellationToken.None));
            Assert.Contains("GHSA-AAAA-BBBB-CCCC", advisory.Identifiers);
            Assert.DoesNotContain("CVE-2026-10001", advisory.Identifiers);
            Assert.DoesNotContain("CVE-2026-99999", advisory.Identifiers);

            var viaUpstream = await store.GetCatalogByIdentifierAsync("CVE-2026-10001", CancellationToken.None);
            Assert.NotNull(viaUpstream);
            Assert.Equal(advisory.Id, viaUpstream.Id);
            Assert.Null(await store.GetCatalogByIdentifierAsync("CVE-2026-99999", CancellationToken.None));

            var relations = await store.GetRelationsByVulnerabilityIdsAsync([advisory.Id], CancellationToken.None);
            var relation = Assert.Single(relations).Value;
            Assert.Equal(["CVE-2026-10001", "CVE-2026-10002"], relation.UpstreamIdentifiers);
            Assert.Equal(["OSV-2026-RELATED"], relation.RelatedIdentifiers);

            var detail = JsonSerializer.SerializeToNode(
                await store.GetCatalogDetailAsync(advisory.Id, CancellationToken.None))!.AsObject();
            Assert.Equal("CVE-2026-10001", detail["vulnerability"]!["upstreamIdentifiers"]![0]!.GetValue<string>());

            var component = ComponentQuery.Normalize(null, "2.2.0", "pkg:pypi/django@2.2.0", "pypi");
            var matches = await store.QueryComponentVulnerabilityCandidatesAsync(
                component,
                withRangeFilter: true,
                limit: 20,
                CancellationToken.None);
            Assert.Single(matches);
            Assert.Equal(advisory.Id, matches[0].VulnerabilityId);
        }
        finally
        {
            Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", previousSpoolPath);
            Directory.Delete(root, recursive: true);
        }
    }

    private static string SpoolLine() => JsonSerializer.Serialize(new
    {
        schemaVersion = 1,
        sourceCode = "osv",
        runId = "relations",
        externalKey = "DEBIAN-CVE-2026-10001",
        externalId = "DEBIAN-CVE-2026-10001",
        sourceUrl = "https://example.test/DEBIAN-CVE-2026-10001",
        modifiedAt = "2026-08-10T00:00:00Z",
        recordHash = "relations-v1",
        identifiers = new[] { "DSA-9999-1" },
        payload = new
        {
            id = "DEBIAN-CVE-2026-10001",
            aliases = new[] { "GHSA-AAAA-BBBB-CCCC" },
            upstream = new[] { "CVE-2026-10002", "CVE-2026-10001" },
            related = new[] { "OSV-2026-RELATED" },
            summary = "Django downstream advisory",
            database_specific = new
            {
                cve_ids = new[] { "CVE-2026-99999" }
            },
            affected = new[]
            {
                new
                {
                    package = new { ecosystem = "PyPI", name = "Django", purl = "pkg:pypi/django" },
                    ranges = new[]
                    {
                        new
                        {
                            type = "ECOSYSTEM",
                            events = new[]
                            {
                                new Dictionary<string, string> { ["introduced"] = "0" },
                                new Dictionary<string, string> { ["fixed"] = "2.2.1" }
                            }
                        }
                    },
                    database_specific = new
                    {
                        cves = new[] { "CVE-2026-99998" }
                    }
                }
            }
        }
    });

    private sealed class UnusedServiceProvider : IServiceProvider
    {
        public object? GetService(Type serviceType) => null;
    }
}
