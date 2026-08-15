using Microsoft.Extensions.Configuration;
using VulTrack.App;

namespace VulTrack.Tests;

public sealed class DuckDbCatalogSearchTests
{
    [Fact]
    public async Task CatalogIdentifierOwnerKeepsIdAndKeyPairedAcrossFullAndKeyedRebuilds()
    {
        var root = Path.Combine(Path.GetTempPath(), "vultrack-catalog-owner-tests", Guid.NewGuid().ToString("N"));
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
            var firstId = Guid.Parse("ffffffff-ffff-5fff-8fff-ffffffffffff");
            var secondId = Guid.Parse("00000000-0000-5000-8000-000000000000");
            var first = CatalogOwnerRecord("ASB-A-100", firstId, ["ASB-A-100", "A-SHARED"]);
            var second = CatalogOwnerRecord("ASB-A-200", secondId, ["ASB-A-200", "A-SHARED"]);

            await store.ReplaceCatalogRecordsAsync([first, second], CancellationToken.None);
            await store.RebuildCatalogAsync(CancellationToken.None);

            var fullOwner = await store.GetCatalogByIdentifierAsync("A-SHARED", CancellationToken.None);
            Assert.NotNull(fullOwner);
            Assert.Equal("ASB-A-100", fullOwner.PrimaryIdentifier);
            Assert.Equal(firstId, fullOwner.Id);

            await store.ReplaceCatalogRecordsAsync(
                [CatalogOwnerRecord("ASB-A-100", firstId, ["ASB-A-100"])],
                CancellationToken.None);
            await store.RebuildCatalogForKeysAsync(["ASB-A-100"], CancellationToken.None);

            var keyedOwner = await store.GetCatalogByIdentifierAsync("A-SHARED", CancellationToken.None);
            Assert.NotNull(keyedOwner);
            Assert.Equal("ASB-A-200", keyedOwner.PrimaryIdentifier);
            Assert.Equal(secondId, keyedOwner.Id);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

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

    private static DuckDbCatalogRecord CatalogOwnerRecord(
        string key,
        Guid id,
        IReadOnlyList<string> identifiers) =>
        new(
            "osv",
            key,
            id,
            key,
            key,
            key,
            "active",
            "2026-08-16T00:00:00Z",
            "2026-08-16T00:00:00Z",
            null,
            $"{key}-hash",
            identifiers);

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

    [Fact]
    public async Task TokenSearch_MatchesLikeResults_AndNarrowsWithAndSemantics()
    {
        var root = Path.Combine(Path.GetTempPath(), "vultrack-token-search-tests", Guid.NewGuid().ToString("N"));
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
            await store.ReplaceCatalogRecordsAsync(
                [
                    Catalog("CVE-2024-1001", "OpenSSL buffer overflow regression"),
                    Catalog("CVE-2024-1002", "OpenSSL certificate parsing flaw"),
                    Catalog("CVE-2024-1003", "Kernel scheduler regression"),
                    Catalog("CVE-2024-1004", "Unrelated vim issue")
                ],
                CancellationToken.None);
            await store.RebuildCatalogAsync(CancellationToken.None);

            var single = await store.SearchCatalogAsync(
                new VulnerabilitySearchRequest("openssl", 1, 25, "identifierAsc"),
                CancellationToken.None);
            Assert.Equal(
                ["CVE-2024-1001", "CVE-2024-1002"],
                single.Items.Select(item => item.PrimaryIdentifier).ToArray());

            var multi = await store.SearchCatalogAsync(
                new VulnerabilitySearchRequest("openssl regression", 1, 25, "identifierAsc"),
                CancellationToken.None);
            var narrowed = Assert.Single(multi.Items);
            Assert.Equal("CVE-2024-1001", narrowed.PrimaryIdentifier);

            var identifierTokens = await store.SearchCatalogAsync(
                new VulnerabilitySearchRequest("CVE 2024 1003", 1, 25, "identifierAsc"),
                CancellationToken.None);
            var identifierMatch = Assert.Single(identifierTokens.Items);
            Assert.Equal("CVE-2024-1003", identifierMatch.PrimaryIdentifier);

            var substringFallback = await store.SearchCatalogAsync(
                new VulnerabilitySearchRequest("openss", 1, 25, "identifierAsc"),
                CancellationToken.None);
            Assert.Equal(
                ["CVE-2024-1001", "CVE-2024-1002"],
                substringFallback.Items.Select(item => item.PrimaryIdentifier).ToArray());

            var noTokens = await store.SearchCatalogAsync(
                new VulnerabilitySearchRequest("++", 1, 25, "modifiedDesc"),
                CancellationToken.None);
            Assert.Empty(noTokens.Items);
            Assert.False(noTokens.HasMore);

            var deepPage = await store.SearchCatalogAsync(
                new VulnerabilitySearchRequest("openssl", 502, 200, "modifiedDesc"),
                CancellationToken.None);
            Assert.Empty(deepPage.Items);
            Assert.False(deepPage.HasMore);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }

        static DuckDbCatalogRecord Catalog(string key, string title) => new(
            "test-source",
            key,
            Guid.NewGuid(),
            key,
            title,
            $"Description for {key}",
            "active",
            "2024-01-01T00:00:00Z",
            "2024-01-02T00:00:00Z",
            $"https://example.test/{key}",
            $"hash-{key}",
            [key]);
    }

    [Fact]
    public async Task RebuildCatalogForKeys_RefreshesSearchTokens()
    {
        var root = Path.Combine(Path.GetTempPath(), "vultrack-token-refresh-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var id = Guid.NewGuid();
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
            await store.ReplaceCatalogRecordsAsync(
                [Catalog("Initial alpha weakness", "hash-1")],
                CancellationToken.None);
            await store.RebuildCatalogAsync(CancellationToken.None);

            var before = await store.SearchCatalogAsync(
                new VulnerabilitySearchRequest("alpha", 1, 25, "modifiedDesc"),
                CancellationToken.None);
            Assert.Single(before.Items);

            await store.ReplaceCatalogRecordsAsync(
                [Catalog("Patched beta fix", "hash-2")],
                CancellationToken.None);
            await store.RebuildCatalogForKeysAsync(["CVE-2024-2001"], CancellationToken.None);

            var added = await store.SearchCatalogAsync(
                new VulnerabilitySearchRequest("beta", 1, 25, "modifiedDesc"),
                CancellationToken.None);
            var addedMatch = Assert.Single(added.Items);
            Assert.Equal("CVE-2024-2001", addedMatch.PrimaryIdentifier);

            var removed = await store.SearchCatalogAsync(
                new VulnerabilitySearchRequest("alpha", 1, 25, "modifiedDesc"),
                CancellationToken.None);
            Assert.Empty(removed.Items);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }

        DuckDbCatalogRecord Catalog(string title, string hash) => new(
            "test-source",
            "CVE-2024-2001",
            id,
            "CVE-2024-2001",
            title,
            "Description",
            "active",
            "2024-02-01T00:00:00Z",
            "2024-02-02T00:00:00Z",
            "https://example.test/CVE-2024-2001",
            hash,
            ["CVE-2024-2001"]);
    }
}
