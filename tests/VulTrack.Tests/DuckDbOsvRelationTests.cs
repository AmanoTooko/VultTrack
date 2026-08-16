using System.Text.Json;
using System.Text.Json.Nodes;
using DuckDB.NET.Data;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using VulTrack.App;

namespace VulTrack.Tests;

[Collection("DuckDbSpoolEnvironment")]
public sealed class DuckDbOsvRelationTests
{
    [Fact]
    public async Task DuplicateSourceRecordsInOneSpoolBatchKeepOnlyTheLastUpdate()
    {
        var root = Path.Combine(Path.GetTempPath(), "vultrack-osv-duplicate-batch-tests", Guid.NewGuid().ToString("N"));
        var previousSpoolPath = Environment.GetEnvironmentVariable("VULTRACK_SPOOL_PATH");
        Directory.CreateDirectory(Path.Combine(root, "incoming"));
        Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", root);
        try
        {
            var databasePath = Path.Combine(root, "duplicates.duckdb");
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["VulTrack:DuckDb:Path"] = databasePath,
                    ["VulTrack:DuckDb:Enabled"] = "true"
                })
                .Build();
            using var store = new DuckDbEvidenceStore(configuration);
            var normalizer = new DuckDbEvidenceNormalizer(
                new UnusedServiceProvider(), store, NullLogger<DuckDbEvidenceNormalizer>.Instance);

            var fileName = "osv-duplicate-batch.ndjson.ready";
            await File.WriteAllTextAsync(
                Path.Combine(root, "incoming", fileName),
                ProjectionSpoolLine(
                    "ECHO-DUPLICATE-0001",
                    upstream: ["CVE-2026-43001"],
                    summary: "Duplicate advisory v1",
                    fixedVersion: "1.0.0",
                    recordHash: "duplicate-v1") + Environment.NewLine +
                ProjectionSpoolLine(
                    "ECHO-DUPLICATE-0001",
                    upstream: ["CVE-2026-43002"],
                    summary: "Duplicate advisory v2",
                    fixedVersion: "2.0.0",
                    recordHash: "duplicate-v2") + Environment.NewLine);
            await normalizer.IngestSpoolAsync(
                new DuckDbSpoolIngestRequest(fileName, BatchSize: 100, DeleteOnSuccess: true),
                CancellationToken.None);

            using var connection = new DuckDBConnection($"Data Source={databasePath}");
            connection.Open();
            Assert.Equal(1L, CountRows(connection, "source_records"));
            Assert.Equal(1L, CountRows(connection, "source_record_relations"));
            Assert.Equal(1L, CountRows(connection, "affected_facts"));

            using var relation = connection.CreateCommand();
            relation.CommandText = "select related_identifier from source_record_relations";
            Assert.Equal("CVE-2026-43002", relation.ExecuteScalar()?.ToString());
            using var range = connection.CreateCommand();
            range.CommandText = "select version_range_raw from affected_facts";
            Assert.Equal(">= 0, < 2.0.0", range.ExecuteScalar()?.ToString());
        }
        finally
        {
            Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", previousSpoolPath);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task ForcedReplayReplacesAnUnchangedSourceHash()
    {
        var root = Path.Combine(Path.GetTempPath(), "vultrack-osv-forced-replay-tests", Guid.NewGuid().ToString("N"));
        var previousSpoolPath = Environment.GetEnvironmentVariable("VULTRACK_SPOOL_PATH");
        Directory.CreateDirectory(Path.Combine(root, "incoming"));
        Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", root);
        try
        {
            var databasePath = Path.Combine(root, "forced-replay.duckdb");
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["VulTrack:DuckDb:Path"] = databasePath,
                    ["VulTrack:DuckDb:Enabled"] = "true"
                })
                .Build();
            using var store = new DuckDbEvidenceStore(configuration);
            var normalizer = new DuckDbEvidenceNormalizer(
                new UnusedServiceProvider(), store, NullLogger<DuckDbEvidenceNormalizer>.Instance);

            var firstFile = "osv-forced-replay-first.ndjson.ready";
            await File.WriteAllTextAsync(
                Path.Combine(root, "incoming", firstFile),
                ProjectionSpoolLine(
                    "ECHO-FORCED-0001",
                    upstream: ["CVE-2026-44001"],
                    summary: "Forced replay advisory",
                    fixedVersion: "1.0.0",
                    recordHash: "unchanged-hash") + Environment.NewLine);
            await normalizer.IngestSpoolAsync(
                new DuckDbSpoolIngestRequest(firstFile, BatchSize: 100), CancellationToken.None);

            var replayFile = "osv-forced-replay-second.ndjson.ready";
            await File.WriteAllTextAsync(
                Path.Combine(root, "incoming", replayFile),
                ProjectionSpoolLine(
                    "ECHO-FORCED-0001",
                    upstream: ["CVE-2026-44002"],
                    summary: "Forced replay advisory",
                    fixedVersion: "2.0.0",
                    recordHash: "unchanged-hash",
                    forceNormalize: true) + Environment.NewLine);
            await normalizer.IngestSpoolAsync(
                new DuckDbSpoolIngestRequest(replayFile, BatchSize: 100), CancellationToken.None);

            using var connection = new DuckDBConnection($"Data Source={databasePath}");
            connection.Open();
            using var relation = connection.CreateCommand();
            relation.CommandText = "select related_identifier from source_record_relations";
            Assert.Equal("CVE-2026-44002", relation.ExecuteScalar()?.ToString());
            using var range = connection.CreateCommand();
            range.CommandText = "select version_range_raw from affected_facts";
            Assert.Equal(">= 0, < 2.0.0", range.ExecuteScalar()?.ToString());
        }
        finally
        {
            Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", previousSpoolPath);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task GhsaBulkRecordsUseOsvFactsAndKeepAmbiguousAdvisoriesIndependent()
    {
        var root = Path.Combine(Path.GetTempPath(), "vultrack-ghsa-bulk-tests", Guid.NewGuid().ToString("N"));
        var previousSpoolPath = Environment.GetEnvironmentVariable("VULTRACK_SPOOL_PATH");
        Directory.CreateDirectory(Path.Combine(root, "incoming"));
        Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", root);
        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["VulTrack:DuckDb:Path"] = Path.Combine(root, "ghsa-bulk.duckdb"),
                    ["VulTrack:DuckDb:Enabled"] = "true"
                })
                .Build();
            using var store = new DuckDbEvidenceStore(configuration);
            var normalizer = new DuckDbEvidenceNormalizer(
                new UnusedServiceProvider(), store, NullLogger<DuckDbEvidenceNormalizer>.Instance);

            var fileName = "ghsa-init-bulk-s0000.ndjson.ready";
            await File.WriteAllTextAsync(
                Path.Combine(root, "incoming", fileName),
                string.Join(
                    Environment.NewLine,
                    GhsaInitSpoolLine("GHSA-AAAA-BBBB-0001", []),
                    GhsaInitSpoolLine("GHSA-AAAA-BBBB-0002", ["CVE-2026-41002"]),
                    GhsaInitSpoolLine("GHSA-AAAA-BBBB-0003", ["CVE-2026-41003", "CVE-2026-41004"])) + Environment.NewLine);
            await normalizer.IngestSpoolAsync(
                new DuckDbSpoolIngestRequest(fileName, BatchSize: 100, DeleteOnSuccess: true),
                CancellationToken.None);

            var independent = await store.GetCatalogByIdentifierAsync("GHSA-AAAA-BBBB-0001", CancellationToken.None);
            Assert.NotNull(independent);
            Assert.Equal("GHSA-AAAA-BBBB-0001", independent.PrimaryIdentifier);
            var detail = JsonSerializer.SerializeToNode(
                await store.GetCatalogDetailAsync(independent.Id, CancellationToken.None))!.AsObject();
            Assert.Equal(9.8m, detail["vulnerability"]!["maxCvssScore"]!.GetValue<decimal>());
            Assert.Single(detail["affectedFacts"]!.AsArray());
            Assert.Equal(">= 0, < 2.0.0", detail["affectedFacts"]![0]!["version_range_raw"]!.GetValue<string>());
            Assert.Single(detail["references"]!.AsArray());
            Assert.Equal(
                "https://github.com/advisories/GHSA-AAAA-BBBB-0001",
                detail["references"]![0]!["url"]!.GetValue<string>());
            Assert.Equal("CVE-2026-41999", detail["vulnerability"]!["upstreamIdentifiers"]![0]!.GetValue<string>());
            Assert.Equal("OSV-2026-RELATED", detail["vulnerability"]!["relatedIdentifiers"]![0]!.GetValue<string>());

            var promoted = await store.GetCatalogByIdentifierAsync("GHSA-AAAA-BBBB-0002", CancellationToken.None);
            Assert.NotNull(promoted);
            Assert.Equal("CVE-2026-41002", promoted.PrimaryIdentifier);
            Assert.Contains("GHSA-AAAA-BBBB-0002", promoted.Identifiers);

            var ambiguous = await store.GetCatalogByIdentifierAsync("GHSA-AAAA-BBBB-0003", CancellationToken.None);
            Assert.NotNull(ambiguous);
            Assert.Equal("GHSA-AAAA-BBBB-0003", ambiguous.PrimaryIdentifier);
            Assert.DoesNotContain("CVE-2026-41003", ambiguous.Identifiers);
            Assert.DoesNotContain("CVE-2026-41004", ambiguous.Identifiers);
            var ambiguousRelations = await store.GetRelationsByVulnerabilityIdsAsync(
                [ambiguous.Id], CancellationToken.None);
            Assert.Equal(
                ["CVE-2026-41003", "CVE-2026-41004", "OSV-2026-RELATED"],
                Assert.Single(ambiguousRelations).Value.RelatedIdentifiers);
        }
        finally
        {
            Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", previousSpoolPath);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task DownstreamAdvisoryMergesIntoItsCve_ButPayloadCveMetadataNeverMerges()
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

            // DEBIAN-CVE-2026-10001 is a downstream view of exactly one CVE, so the CVE owns the
            // catalog entry and the Debian identifier survives as a searchable alias.
            var advisory = await store.GetCatalogByIdentifierAsync("DEBIAN-CVE-2026-10001", CancellationToken.None);
            Assert.NotNull(advisory);
            Assert.Equal("CVE-2026-10001", advisory.PrimaryIdentifier);
            Assert.Null(await store.GetCatalogByIdAsync(staleId, CancellationToken.None));
            Assert.Contains("GHSA-AAAA-BBBB-CCCC", advisory.Identifiers);
            Assert.Contains("DEBIAN-CVE-2026-10001", advisory.Identifiers);
            // Payload metadata (database_specific.cve_ids, per-package cves) names related CVEs,
            // not this record's identity. Merging on those collapsed unrelated advisories together.
            Assert.DoesNotContain("CVE-2026-99999", advisory.Identifiers);
            Assert.DoesNotContain("CVE-2026-99998", advisory.Identifiers);

            var viaUpstream = await store.GetCatalogByIdentifierAsync("CVE-2026-10001", CancellationToken.None);
            Assert.NotNull(viaUpstream);
            Assert.Equal(advisory.Id, viaUpstream.Id);
            Assert.Null(await store.GetCatalogByIdentifierAsync("CVE-2026-99999", CancellationToken.None));
            Assert.Null(await store.GetCatalogByIdentifierAsync("CVE-2026-99998", CancellationToken.None));

            var relations = await store.GetRelationsByVulnerabilityIdsAsync([advisory.Id], CancellationToken.None);
            var relation = Assert.Single(relations).Value;
            Assert.Equal(["CVE-2026-10002"], relation.UpstreamIdentifiers);
            Assert.Equal(["OSV-2026-RELATED"], relation.RelatedIdentifiers);

            var detail = JsonSerializer.SerializeToNode(
                await store.GetCatalogDetailAsync(advisory.Id, CancellationToken.None))!.AsObject();
            Assert.Equal("CVE-2026-10002", detail["vulnerability"]!["upstreamIdentifiers"]![0]!.GetValue<string>());

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

    [Fact]
    public async Task DeferredIngest_ReturnsChangedKeysWithoutRebuildingCatalog()
    {
        var root = Path.Combine(Path.GetTempPath(), "vultrack-osv-deferred-tests", Guid.NewGuid().ToString("N"));
        var previousSpoolPath = Environment.GetEnvironmentVariable("VULTRACK_SPOOL_PATH");
        Directory.CreateDirectory(Path.Combine(root, "incoming"));
        Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", root);
        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["VulTrack:DuckDb:Path"] = Path.Combine(root, "deferred.duckdb"),
                    ["VulTrack:DuckDb:Enabled"] = "true"
                })
                .Build();
            using var store = new DuckDbEvidenceStore(configuration);
            var normalizer = new DuckDbEvidenceNormalizer(
                new UnusedServiceProvider(), store, NullLogger<DuckDbEvidenceNormalizer>.Instance);

            var fileName = "osv-deferred-s0000.ndjson.ready";
            await File.WriteAllTextAsync(
                Path.Combine(root, "incoming", fileName),
                SpoolLine() + Environment.NewLine);
            var result = await normalizer.IngestSpoolAsync(
                new DuckDbSpoolIngestRequest(fileName, BatchSize: 100, DeleteOnSuccess: true, DeferCatalogRebuild: true),
                CancellationToken.None);

            Assert.True(result.ok);
            Assert.False(result.deferredFullCatalogRebuild);
            Assert.True(result.deferredAffectedRebuild);
            var changedKey = Assert.Single(result.deferredChangedKeys);
            Assert.Equal("CVE-2026-10001", changedKey);
            Assert.Null(await store.GetCatalogByIdentifierAsync("DEBIAN-CVE-2026-10001", CancellationToken.None));

            await store.RebuildCatalogForKeysAsync(result.deferredChangedKeys, CancellationToken.None);
            await store.RebuildAffectedComponentsForKeysAsync(result.deferredChangedKeys, CancellationToken.None);
            Assert.NotNull(await store.GetCatalogByIdentifierAsync("DEBIAN-CVE-2026-10001", CancellationToken.None));
        }
        finally
        {
            Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", previousSpoolPath);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task UpstreamRelationsNeverChangeAdvisoryIdentity()
    {
        var root = Path.Combine(Path.GetTempPath(), "vultrack-osv-multicve-tests", Guid.NewGuid().ToString("N"));
        var previousSpoolPath = Environment.GetEnvironmentVariable("VULTRACK_SPOOL_PATH");
        Directory.CreateDirectory(Path.Combine(root, "incoming"));
        Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", root);
        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["VulTrack:DuckDb:Path"] = Path.Combine(root, "multicve.duckdb"),
                    ["VulTrack:DuckDb:Enabled"] = "true"
                })
                .Build();
            using var store = new DuckDbEvidenceStore(configuration);
            var normalizer = new DuckDbEvidenceNormalizer(
                new UnusedServiceProvider(), store, NullLogger<DuckDbEvidenceNormalizer>.Instance);

            var fileName = "osv-multicve-s0000.ndjson.ready";
            await File.WriteAllTextAsync(
                Path.Combine(root, "incoming", fileName),
                string.Join(
                    Environment.NewLine,
                    UpstreamOnlySpoolLine("USN-7123-1", ["CVE-2026-20001", "CVE-2026-20002"]),
                    UpstreamOnlySpoolLine("USN-7124-1", ["CVE-2026-20003"])) + Environment.NewLine);
            await normalizer.IngestSpoolAsync(
                new DuckDbSpoolIngestRequest(fileName, BatchSize: 100, DeleteOnSuccess: true),
                CancellationToken.None);

            // Fixing two CVEs at once is ambiguous: filing it under one would drop its link to the
            // other, so the advisory keeps its own entry and both upstream links stay.
            var multi = await store.GetCatalogByIdentifierAsync("USN-7123-1", CancellationToken.None);
            Assert.NotNull(multi);
            Assert.Equal("USN-7123-1", multi.PrimaryIdentifier);
            var relations = await store.GetRelationsByVulnerabilityIdsAsync([multi.Id], CancellationToken.None);
            Assert.Equal(
                ["CVE-2026-20001", "CVE-2026-20002"],
                Assert.Single(relations).Value.UpstreamIdentifiers);

            // A single upstream CVE is still a relationship, not an identity assertion.
            var single = await store.GetCatalogByIdentifierAsync("USN-7124-1", CancellationToken.None);
            Assert.NotNull(single);
            Assert.Equal("USN-7124-1", single.PrimaryIdentifier);
            var singleRelations = await store.GetRelationsByVulnerabilityIdsAsync([single.Id], CancellationToken.None);
            Assert.Equal(
                ["CVE-2026-20003"],
                Assert.Single(singleRelations).Value.UpstreamIdentifiers);
            var viaRelation = await store.GetCatalogByIdentifierAsync("CVE-2026-20003", CancellationToken.None);
            Assert.NotNull(viaRelation);
            Assert.Equal(single.Id, viaRelation.Id);
            Assert.Equal("USN-7124-1", viaRelation.PrimaryIdentifier);
        }
        finally
        {
            Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", previousSpoolPath);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task MultiUpstreamAdvisoryIsVisibleFromEachDownstreamCve()
    {
        var root = Path.Combine(Path.GetTempPath(), "vultrack-osv-downstream-tests", Guid.NewGuid().ToString("N"));
        var previousSpoolPath = Environment.GetEnvironmentVariable("VULTRACK_SPOOL_PATH");
        Directory.CreateDirectory(Path.Combine(root, "incoming"));
        Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", root);
        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["VulTrack:DuckDb:Path"] = Path.Combine(root, "downstream.duckdb"),
                    ["VulTrack:DuckDb:Enabled"] = "true"
                })
                .Build();
            using var store = new DuckDbEvidenceStore(configuration);
            var normalizer = new DuckDbEvidenceNormalizer(
                new UnusedServiceProvider(), store, NullLogger<DuckDbEvidenceNormalizer>.Instance);

            await store.ReplaceCatalogRecordsAsync(
                [
                    CatalogFixture("nvd-cve", "CVE-2026-43001"),
                    CatalogFixture("nvd-cve", "CVE-2026-43002")
                ],
                CancellationToken.None);
            await store.RebuildCatalogAsync(CancellationToken.None);

            var fileName = "osv-clsa-relations-s0000.ndjson.ready";
            await File.WriteAllTextAsync(
                Path.Combine(root, "incoming", fileName),
                UpstreamOnlySpoolLine("CLSA-2026:1234", ["CVE-2026-43001", "CVE-2026-43002"])
                + Environment.NewLine);
            await normalizer.IngestSpoolAsync(
                new DuckDbSpoolIngestRequest(fileName, BatchSize: 100, DeleteOnSuccess: true),
                CancellationToken.None);

            var clsa = await store.GetCatalogByIdentifierAsync("CLSA-2026:1234", CancellationToken.None);
            Assert.NotNull(clsa);
            var clsaDetail = JsonSerializer.SerializeToNode(
                await store.GetCatalogDetailAsync(clsa.Id, CancellationToken.None))!.AsObject();
            Assert.Equal(
                ["CVE-2026-43001", "CVE-2026-43002"],
                clsaDetail["vulnerability"]!["upstreamIdentifiers"]!.AsArray()
                    .Select(value => value!.GetValue<string>()));

            foreach (var cve in new[] { "CVE-2026-43001", "CVE-2026-43002" })
            {
                var target = await store.GetCatalogByIdentifierAsync(cve, CancellationToken.None);
                Assert.NotNull(target);
                var targetDetail = JsonSerializer.SerializeToNode(
                    await store.GetCatalogDetailAsync(target.Id, CancellationToken.None))!.AsObject();
                Assert.Equal(
                    ["CLSA-2026:1234"],
                    targetDetail["vulnerability"]!["downstreamIdentifiers"]!.AsArray()
                        .Select(value => value!.GetValue<string>()));
                var downstream = Assert.Single(
                    targetDetail["vulnerability"]!["downstreamRelations"]!.AsArray());
                Assert.Equal("CLSA-2026:1234", downstream!["primaryIdentifier"]!.GetValue<string>());
                Assert.Equal("CLSA-2026:1234", downstream["sourceRecordId"]!.GetValue<string>());
                Assert.Equal("osv", downstream["sourceCode"]!.GetValue<string>());
                Assert.Equal("upstream", downstream["relationType"]!.GetValue<string>());

                var relationshipReference = Assert.Single(
                    targetDetail["vulnerability"]!["relationshipReferences"]!.AsArray());
                Assert.Equal("CLSA-2026:1234", relationshipReference!["identifier"]!.GetValue<string>());
                Assert.Equal("downstream", relationshipReference["direction"]!.GetValue<string>());
                Assert.Equal("upstream", relationshipReference["relationType"]!.GetValue<string>());
                Assert.Equal("https://osv.dev/vulnerability/CLSA-2026:1234",
                    relationshipReference["sourceUrl"]!.GetValue<string>());
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", previousSpoolPath);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task EvidenceOnlyDistributionProjectionsAttachToOneCveOrStayOutOfCatalog()
    {
        var root = Path.Combine(Path.GetTempPath(), "vultrack-osv-projection-tests", Guid.NewGuid().ToString("N"));
        var previousSpoolPath = Environment.GetEnvironmentVariable("VULTRACK_SPOOL_PATH");
        Directory.CreateDirectory(Path.Combine(root, "incoming"));
        Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", root);
        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["VulTrack:DuckDb:Path"] = Path.Combine(root, "projections.duckdb"),
                    ["VulTrack:DuckDb:Enabled"] = "true"
                })
                .Build();
            using var store = new DuckDbEvidenceStore(configuration);
            var normalizer = new DuckDbEvidenceNormalizer(
                new UnusedServiceProvider(), store, NullLogger<DuckDbEvidenceNormalizer>.Instance);

            var fileName = "osv-projections-s0000.ndjson.ready";
            await File.WriteAllTextAsync(
                Path.Combine(root, "incoming", fileName),
                string.Join(
                    Environment.NewLine,
                    ProjectionSpoolLine(
                        "MINI-AAAA-BBBB-0001",
                        upstream: ["CVE-2026-42001", "GHSA-AAAA-BBBB-0001"]),
                    ProjectionSpoolLine(
                        "CGA-AAAA-BBBB-0002",
                        related: ["CGA-AAAA-BBBB-0002", "CVE-2026-42002", "GHSA-AAAA-BBBB-0002"]),
                    ProjectionSpoolLine(
                        "MINI-AAAA-BBBB-0003",
                        upstream: ["GHSA-AAAA-BBBB-0003"]),
                    ProjectionSpoolLine(
                        "MINI-AAAA-BBBB-0004",
                        aliases: ["CVE-2026-42004"],
                        upstream: ["CVE-2026-99999"]),
                    ProjectionSpoolLine(
                        "MINI-AAAA-BBBB-0005",
                        aliases: ["CVE-2026-42005", "CVE-2026-42006"]),
                    ProjectionSpoolLine(
                        "CGA-AAAA-BBBB-0006",
                        aliases: ["GHSA-AAAA-BBBB-0006"]),
                    ProjectionSpoolLine(
                        "MINI-AAAA-BBBB-0007",
                        upstream: ["CVE-2026-42007"],
                        includeAffected: false),
                    ProjectionSpoolLine(
                        "CGA-AAAA-BBBB-0008",
                        includeAffected: false),
                    ProjectionSpoolLine(
                        "ECHO-AAAA-BBBB-0009",
                        upstream: ["CVE-2026-42009"]),
                    ProjectionSpoolLine(
                        "ECHO-AAAA-BBBB-0010",
                        includeAffected: false),
                    ProjectionSpoolLine(
                        "ECHO-AAAA-BBBB-0011",
                        upstream: ["CVE-2026-42011"],
                        summary: "Independent ECHO advisory")) + Environment.NewLine);
            await normalizer.IngestSpoolAsync(
                new DuckDbSpoolIngestRequest(fileName, BatchSize: 100, DeleteOnSuccess: true),
                CancellationToken.None);

            var mini = await store.GetCatalogByIdentifierAsync("MINI-AAAA-BBBB-0001", CancellationToken.None);
            Assert.NotNull(mini);
            Assert.Equal("CVE-2026-42001", mini.PrimaryIdentifier);
            Assert.Contains("MINI-AAAA-BBBB-0001", mini.Identifiers);
            var miniDetail = JsonSerializer.SerializeToNode(
                await store.GetCatalogDetailAsync(mini.Id, CancellationToken.None))!.AsObject();
            Assert.Single(miniDetail["affectedFacts"]!.AsArray());
            Assert.Equal(
                ["GHSA-AAAA-BBBB-0001"],
                miniDetail["vulnerability"]!["upstreamIdentifiers"]!.AsArray()
                    .Select(value => value!.GetValue<string>()));

            var cga = await store.GetCatalogByIdentifierAsync("CGA-AAAA-BBBB-0002", CancellationToken.None);
            Assert.NotNull(cga);
            Assert.Equal("CVE-2026-42002", cga.PrimaryIdentifier);
            var cgaDetail = JsonSerializer.SerializeToNode(
                await store.GetCatalogDetailAsync(cga.Id, CancellationToken.None))!.AsObject();
            Assert.Equal(
                ["GHSA-AAAA-BBBB-0002"],
                cgaDetail["vulnerability"]!["relatedIdentifiers"]!.AsArray()
                    .Select(value => value!.GetValue<string>()));

            Assert.Null(await store.GetCatalogByIdentifierAsync(
                "MINI-AAAA-BBBB-0003", CancellationToken.None));

            var directAlias = await store.GetCatalogByIdentifierAsync(
                "MINI-AAAA-BBBB-0004", CancellationToken.None);
            Assert.NotNull(directAlias);
            Assert.Equal("CVE-2026-42004", directAlias.PrimaryIdentifier);
            var directAliasDetail = JsonSerializer.SerializeToNode(
                await store.GetCatalogDetailAsync(directAlias.Id, CancellationToken.None))!.AsObject();
            Assert.Equal(
                ["CVE-2026-99999"],
                directAliasDetail["vulnerability"]!["upstreamIdentifiers"]!.AsArray()
                    .Select(value => value!.GetValue<string>()));

            Assert.Null(await store.GetCatalogByIdentifierAsync(
                "MINI-AAAA-BBBB-0005", CancellationToken.None));
            Assert.Null(await store.GetCatalogByIdentifierAsync(
                "CGA-AAAA-BBBB-0006", CancellationToken.None));

            var noAffected = await store.GetCatalogByIdentifierAsync(
                "MINI-AAAA-BBBB-0007", CancellationToken.None);
            Assert.NotNull(noAffected);
            Assert.Equal("CVE-2026-42007", noAffected.PrimaryIdentifier);
            Assert.Null(await store.GetCatalogByIdentifierAsync(
                "CGA-AAAA-BBBB-0008", CancellationToken.None));

            var echo = await store.GetCatalogByIdentifierAsync(
                "ECHO-AAAA-BBBB-0009", CancellationToken.None);
            Assert.NotNull(echo);
            Assert.Equal("CVE-2026-42009", echo.PrimaryIdentifier);
            Assert.Contains("ECHO-AAAA-BBBB-0009", echo.Identifiers);
            Assert.Null(await store.GetCatalogByIdentifierAsync(
                "ECHO-AAAA-BBBB-0010", CancellationToken.None));

            var contentfulEcho = await store.GetCatalogByIdentifierAsync(
                "ECHO-AAAA-BBBB-0011", CancellationToken.None);
            Assert.NotNull(contentfulEcho);
            Assert.Equal("ECHO-AAAA-BBBB-0011", contentfulEcho.PrimaryIdentifier);
            Assert.Equal("Independent ECHO advisory", contentfulEcho.Title);

            // Keyed rebuilds must keep the same suppression rule used by a full rebuild.
            await store.RebuildCatalogForKeysAsync(
                [
                    "MINI-AAAA-BBBB-0003",
                    "MINI-AAAA-BBBB-0005",
                    "CGA-AAAA-BBBB-0006",
                    "CGA-AAAA-BBBB-0008",
                    "ECHO-AAAA-BBBB-0010"
                ],
                CancellationToken.None);
            Assert.Null(await store.GetCatalogByIdentifierAsync(
                "MINI-AAAA-BBBB-0003", CancellationToken.None));
            Assert.Null(await store.GetCatalogByIdentifierAsync(
                "MINI-AAAA-BBBB-0005", CancellationToken.None));
            Assert.Null(await store.GetCatalogByIdentifierAsync(
                "CGA-AAAA-BBBB-0006", CancellationToken.None));
            Assert.Null(await store.GetCatalogByIdentifierAsync(
                "CGA-AAAA-BBBB-0008", CancellationToken.None));
            Assert.Null(await store.GetCatalogByIdentifierAsync(
                "ECHO-AAAA-BBBB-0010", CancellationToken.None));
        }
        finally
        {
            Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", previousSpoolPath);
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task MergedDistroAdvisoriesKeepTheirOwnAffectedRangesAsSeparateSourceFacts()
    {
        var root = Path.Combine(Path.GetTempPath(), "vultrack-osv-distro-tests", Guid.NewGuid().ToString("N"));
        var previousSpoolPath = Environment.GetEnvironmentVariable("VULTRACK_SPOOL_PATH");
        Directory.CreateDirectory(Path.Combine(root, "incoming"));
        Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", root);
        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["VulTrack:DuckDb:Path"] = Path.Combine(root, "distro.duckdb"),
                    ["VulTrack:DuckDb:Enabled"] = "true"
                })
                .Build();
            using var store = new DuckDbEvidenceStore(configuration);
            var normalizer = new DuckDbEvidenceNormalizer(
                new UnusedServiceProvider(), store, NullLogger<DuckDbEvidenceNormalizer>.Instance);

            var fileName = "osv-distro-s0000.ndjson.ready";
            await File.WriteAllTextAsync(
                Path.Combine(root, "incoming", fileName),
                string.Join(
                    Environment.NewLine,
                    DistroSpoolLine("UBUNTU-CVE-2026-30001", "1.11"),
                    DistroSpoolLine("DEBIAN-CVE-2026-30001", "1.12"),
                    DistroSpoolLine("ROOT-APP-MAVEN-CVE-2026-30001", "1.13"),
                    DistroSpoolLine("BELL-CVE-2026-30001", "1.14")) + Environment.NewLine);
            await normalizer.IngestSpoolAsync(
                new DuckDbSpoolIngestRequest(fileName, BatchSize: 100, DeleteOnSuccess: true),
                CancellationToken.None);

            var merged = await store.GetCatalogByIdentifierAsync("CVE-2026-30001", CancellationToken.None);
            Assert.NotNull(merged);
            Assert.Equal("CVE-2026-30001", merged.PrimaryIdentifier);
            foreach (var distroId in new[]
                     {
                         "UBUNTU-CVE-2026-30001", "DEBIAN-CVE-2026-30001",
                         "ROOT-APP-MAVEN-CVE-2026-30001", "BELL-CVE-2026-30001"
                     })
            {
                Assert.Contains(distroId, merged.Identifiers);
                var viaDistro = await store.GetCatalogByIdentifierAsync(distroId, CancellationToken.None);
                Assert.NotNull(viaDistro);
                Assert.Equal(merged.Id, viaDistro.Id);
            }

            // Conflicting per-distro ranges must stay visible as distinct source facts rather than
            // being collapsed into one range by the merge.
            var facts = await store.QueryAffectedFactsManyAsync(
                ["CVE-2026-30001"], ct: CancellationToken.None);
            var ranges = Assert.Single(facts).Value
                .Select(row => row["version_range_raw"]?.ToString())
                .OrderBy(value => value, StringComparer.Ordinal)
                .ToArray();
            Assert.Equal(4, ranges.Length);
            Assert.All(new[] { "1.11", "1.12", "1.13", "1.14" },
                expected => Assert.Contains(ranges, range => range is not null && range.Contains(expected)));
        }
        finally
        {
            Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", previousSpoolPath);
            Directory.Delete(root, recursive: true);
        }
    }

    private static string UpstreamOnlySpoolLine(string advisoryId, string[] upstream) =>
        JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            sourceCode = "osv",
            runId = "relations",
            externalKey = advisoryId,
            externalId = advisoryId,
            sourceUrl = $"https://osv.dev/vulnerability/{advisoryId}",
            modifiedAt = "2026-08-10T00:00:00Z",
            recordHash = $"{advisoryId}-v1",
            payload = new
            {
                id = advisoryId,
                upstream,
                summary = $"{advisoryId} advisory",
                references = new[]
                {
                    new { type = "ADVISORY", url = $"https://osv.dev/vulnerability/{advisoryId}" }
                }
            }
        });

    private static string DistroSpoolLine(string advisoryId, string fixedVersion) =>
        JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            sourceCode = "osv",
            runId = "distro",
            externalKey = advisoryId,
            externalId = advisoryId,
            modifiedAt = "2026-08-10T00:00:00Z",
            recordHash = $"{advisoryId}-v1",
            payload = new
            {
                id = advisoryId,
                summary = $"{advisoryId} advisory",
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
                                    new Dictionary<string, string> { ["fixed"] = fixedVersion }
                                }
                            }
                        }
                    }
                }
            }
        });

    private static string ProjectionSpoolLine(
        string advisoryId,
        string[]? aliases = null,
        string[]? upstream = null,
        string[]? related = null,
        bool includeAffected = true,
        string? summary = null,
        string fixedVersion = "2.0.0",
        string? recordHash = null,
        bool forceNormalize = false) =>
        JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            sourceCode = "osv",
            runId = "projections",
            externalKey = advisoryId,
            externalId = advisoryId,
            modifiedAt = "2026-08-10T00:00:00Z",
            recordHash = recordHash ?? $"{advisoryId}-v1",
            forceNormalize,
            payload = new
            {
                id = advisoryId,
                aliases,
                upstream,
                related,
                summary,
                affected = includeAffected
                    ? new object[]
                    {
                    new
                    {
                        package = new
                        {
                            ecosystem = "MinimOS",
                            name = "fixture-package",
                            purl = "pkg:apk/minimos/fixture-package"
                        },
                        ranges = new[]
                        {
                            new
                            {
                                type = "ECOSYSTEM",
                                events = new[]
                                {
                                    new Dictionary<string, string> { ["introduced"] = "0" },
                                    new Dictionary<string, string> { ["fixed"] = fixedVersion }
                                }
                            }
                        }
                    }
                    }
                    : Array.Empty<object>()
            }
        });

    private static long CountRows(DuckDBConnection connection, string table)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"select count(*) from {table}";
        return Convert.ToInt64(command.ExecuteScalar());
    }

    private static string GhsaInitSpoolLine(string advisoryId, string[] aliases) =>
        JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            sourceCode = "ghsa-init",
            runId = "ghsa-bulk",
            externalKey = advisoryId,
            externalId = advisoryId,
            sourceUrl = $"https://github.com/advisories/{advisoryId}",
            publishedAt = "2026-08-01T00:00:00Z",
            modifiedAt = "2026-08-10T00:00:00Z",
            recordHash = $"{advisoryId}-v1",
            identifiers = new[] { advisoryId }.Concat(aliases).ToArray(),
            payload = new
            {
                schema_version = "1.4.0",
                id = advisoryId,
                aliases,
                upstream = new[] { "CVE-2026-41999" },
                related = new[] { "CVE-2026-41999", "OSV-2026-RELATED" },
                summary = $"{advisoryId} summary",
                details = $"{advisoryId} details",
                severity = new[]
                {
                    new
                    {
                        type = "CVSS_V3",
                        score = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    }
                },
                references = new[]
                {
                    new { type = "ADVISORY", url = $"https://github.com/advisories/{advisoryId}" }
                },
                affected = new[]
                {
                    new
                    {
                        package = new { ecosystem = "npm", name = "fixture-package", purl = "pkg:npm/fixture-package" },
                        ranges = new[]
                        {
                            new
                            {
                                type = "SEMVER",
                                events = new[]
                                {
                                    new Dictionary<string, string> { ["introduced"] = "0" },
                                    new Dictionary<string, string> { ["fixed"] = "2.0.0" }
                                }
                            }
                        }
                    }
                }
            }
        });

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

    private static DuckDbCatalogRecord CatalogFixture(string sourceCode, string identifier) =>
        new(
            sourceCode,
            identifier,
            Guid.NewGuid(),
            identifier,
            $"{identifier} title",
            $"{identifier} description",
            "active",
            "2026-08-01T00:00:00Z",
            "2026-08-10T00:00:00Z",
            $"https://example.test/{identifier}",
            $"{identifier}-v1",
            [identifier]);

    private sealed class UnusedServiceProvider : IServiceProvider
    {
        public object? GetService(Type serviceType) => null;
    }
}
