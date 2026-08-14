using Microsoft.Extensions.Configuration;
using VulTrack.App;

namespace VulTrack.Tests;

public sealed class DuckDbCatalogSearchTests
{
    [Theory]
    [InlineData("pkg:deb/debian/openssl@3.0.11?distro=debian-12", "debian:12")]
    [InlineData("pkg:deb/ubuntu/openssl@3.0.11?distro=ubuntu-22.04", "ubuntu:22.04")]
    [InlineData("pkg:apk/alpine/openssl@3.1.4-r0?distro=alpine-3.19", "alpine:3.19")]
    [InlineData("pkg:rpm/redhat/openssl@3.0.7?distro=rhel-8.8", "red hat:enterprise_linux:8")]
    [InlineData("pkg:rpm/rocky/openssl@3.0.7?distro=rocky-9.3", "rocky linux:9")]
    [InlineData("pkg:rpm/almalinux/openssl@3.0.7?distro=almalinux-9.2", "almalinux:9")]
    public void Normalize_PreservesDistributionFromPurlQualifier(string purl, string expectedEcosystem)
    {
        var query = ComponentQuery.Normalize(null, null, purl, null);

        Assert.Equal(expectedEcosystem, query.Ecosystem);
    }

    [Fact]
    public async Task ExplicitPurl_WithDistroQualifier_DoesNotCrossDistributionReleases()
    {
        var root = Path.Combine(Path.GetTempPath(), "vultrack-purl-distro-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["VulTrack:DuckDb:Path"] = Path.Combine(root, "catalog.duckdb"),
                    ["VulTrack:DuckDb:Enabled"] = "true"
                })
                .Build();
            using var store = new DuckDbEvidenceStore(configuration);
            var debian12Id = Guid.NewGuid();
            var debian13Id = Guid.NewGuid();
            await store.ReplaceCatalogRecordsAsync(
                [
                    Catalog("CVE-TEST-12", debian12Id),
                    Catalog("CVE-TEST-13", debian13Id)
                ],
                CancellationToken.None);
            await store.ReplaceRecordsAsync(
                [
                    Evidence("CVE-TEST-12", debian12Id, "Debian:12"),
                    Evidence("CVE-TEST-13", debian13Id, "Debian:13")
                ],
                CancellationToken.None);
            await store.RebuildCatalogAsync(CancellationToken.None);
            await store.RebuildAffectedComponentsFromCatalogAsync(CancellationToken.None);

            var query = ComponentQuery.Normalize(
                null,
                null,
                "pkg:deb/debian/openssl@3.0.11-1~deb12u2?distro=debian-12",
                null);
            var matches = await store.QueryComponentVulnerabilityCandidatesAsync(
                query,
                withRangeFilter: true,
                limit: 20,
                CancellationToken.None);

            var match = Assert.Single(matches);
            Assert.Equal(debian12Id, match.VulnerabilityId);
            Assert.Equal("Debian:12", match.Ecosystem);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }

        static DuckDbCatalogRecord Catalog(string key, Guid id) => new(
            "osv",
            key,
            id,
            key,
            key,
            key,
            "active",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
            null,
            key,
            [key]);

        static DuckDbEvidenceRecord Evidence(string key, Guid id, string ecosystem) => new(
            "osv",
            id,
            key,
            key,
            [
                new DuckDbAffectedFact(
                    "affected",
                    ecosystem,
                    "openssl",
                    "pkg:deb/debian/openssl",
                    null,
                    ">=0,<4.0.0",
                    "ECOSYSTEM",
                    true)
            ],
            [],
            [],
            []);
    }

    [Fact]
    public async Task ListAndSearchPaths_ReturnOnlyMatchingRowsInStableOrder()
    {
        var root = Path.Combine(Path.GetTempPath(), "vultrack-catalog-search-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["VulTrack:DuckDb:Path"] = Path.Combine(root, "catalog.duckdb"),
                    ["VulTrack:DuckDb:Enabled"] = "true"
                })
                .Build();
            using var store = new DuckDbEvidenceStore(configuration);
            var records = Enumerable.Range(1, 80)
                .Select(index =>
                {
                    var year = index <= 40 ? 2021 : 2022;
                    var key = $"CVE-{year}-{index:D4}";
                    return new DuckDbCatalogRecord(
                        "test-source",
                        key,
                        Guid.NewGuid(),
                        key,
                        index == 17 ? "OpenSSL regression" : $"Test vulnerability {index}",
                        $"Description for {key}",
                        "active",
                        $"{year}-01-01T00:00:00Z",
                        $"{year}-01-{Math.Min(index, 28):D2}T00:00:00Z",
                        $"https://example.test/{key}",
                        $"hash-{index}",
                        index == 17 ? [key, "GHSA-OPEN-SSL-17"] : [key]);
                })
                .ToArray();

            await store.ReplaceCatalogRecordsAsync(records, CancellationToken.None);
            var unchanged = await store.FilterChangedCatalogRecordsAsync(records, CancellationToken.None);
            Assert.Empty(unchanged);

            var changedRecord = records[16] with
            {
                RecordHash = "hash-17-updated",
                Title = "OpenSSL regression updated"
            };
            var changed = await store.FilterChangedCatalogRecordsAsync(
                [records[0], changedRecord],
                CancellationToken.None);
            Assert.Single(changed);
            Assert.Equal(changedRecord.SourceRecordId, changed[0].SourceRecordId);

            await store.ReplaceRecordsAsync(
                [
                    new DuckDbEvidenceRecord(
                        "test-source",
                        records[16].VulnerabilityId,
                        records[16].VulnerabilityKey,
                        records[16].SourceRecordId,
                        [
                            new DuckDbAffectedFact(
                                "affected",
                                "crates.io",
                                "test-crate",
                                "pkg:cargo/test-crate@1.2.3",
                                null,
                                ">=0,<1.2.4",
                                "ECOSYSTEM",
                                true)
                        ],
                        [],
                        [],
                        [])
                ],
                CancellationToken.None);
            await store.RebuildCatalogAsync(CancellationToken.None);
            await store.RebuildAffectedComponentsForKeysAsync(
                [records[16].VulnerabilityKey],
                CancellationToken.None);

            var latest = await store.SearchCatalogAsync(
                new VulnerabilitySearchRequest("", 1, 25, "modifiedDesc"),
                CancellationToken.None);
            Assert.Equal(25, latest.Items.Count);
            Assert.True(string.CompareOrdinal(latest.Items[0].ModifiedAt, latest.Items[1].ModifiedAt) >= 0);

            var year = await store.SearchCatalogAsync(
                new VulnerabilitySearchRequest("CVE-2021", 1, 50, "identifierAsc"),
                CancellationToken.None);
            Assert.Equal(40, year.Items.Count);
            Assert.All(year.Items, item => Assert.StartsWith("CVE-2021-", item.PrimaryIdentifier));

            var text = await store.SearchCatalogAsync(
                new VulnerabilitySearchRequest("openssl", 1, 25, "modifiedDesc"),
                CancellationToken.None);
            Assert.Single(text.Items);
            Assert.Equal("CVE-2021-0017", text.Items[0].PrimaryIdentifier);

            var alias = await store.SearchCatalogAsync(
                new VulnerabilitySearchRequest("GHSA-OPEN-SSL-17", 1, 25, "modifiedDesc"),
                CancellationToken.None);
            Assert.Single(alias.Items);
            Assert.Equal("CVE-2021-0017", alias.Items[0].PrimaryIdentifier);

            var cargoLookup = ComponentQuery.Normalize(
                null,
                null,
                "pkg:cargo/test-crate@1.2.3",
                "cargo");
            var catalogComponents = await store.SearchComponentCatalogAsync(
                "",
                cargoLookup,
                10,
                CancellationToken.None);
            Assert.Single(catalogComponents);
            Assert.Equal("pkg:cargo/test-crate@1.2.3", catalogComponents[0].PrimaryPurl);

            var vulnerabilityCandidates = await store.QueryComponentVulnerabilityCandidatesAsync(
                cargoLookup,
                withRangeFilter: true,
                limit: 10,
                CancellationToken.None);
            Assert.Single(vulnerabilityCandidates);
            Assert.Equal("crates.io", vulnerabilityCandidates[0].Ecosystem);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
