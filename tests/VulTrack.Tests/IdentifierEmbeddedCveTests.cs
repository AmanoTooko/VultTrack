using VulTrack.App;

namespace VulTrack.Tests;

public sealed class IdentifierEmbeddedCveTests
{
    [Theory]
    [InlineData("OSV-2026-0001", new[] { "OSV-2026-0001", "CVE-2026-10001" }, "CVE-2026-10001")]
    [InlineData("GHSA-AAAA-BBBB-CCCC", new[] { "GHSA-AAAA-BBBB-CCCC", "CVE-2026-10001" }, "CVE-2026-10001")]
    [InlineData("OSV-2026-0001", new[] { "OSV-2026-0001", "DEBIAN-CVE-2026-10001" }, "CVE-2026-10001")]
    [InlineData("GHSA-AAAA-BBBB-CCCC", new[] { "GHSA-AAAA-BBBB-CCCC" }, "GHSA-AAAA-BBBB-CCCC")]
    [InlineData("BDSA-2026-0001", new[] { "BDSA-2026-0001" }, "BDSA-2026-0001")]
    [InlineData("OSV-2026-0001", new[] { "OSV-2026-0001", "CVE-2026-10001", "CVE-2026-10002" }, "OSV-2026-0001")]
    [InlineData("GHSA-AAAA-BBBB-CCCC", new[] { "GHSA-AAAA-BBBB-CCCC", "CVE-2026-10001", "CVE-2026-10002" }, "GHSA-AAAA-BBBB-CCCC")]
    public void DirectAliasesResolveCanonicalIdentity(
        string ownIdentifier,
        string[] identifiers,
        string expected)
    {
        Assert.Equal(expected, Identifier.ResolveCanonicalIdentity(ownIdentifier, identifiers));
    }

    [Theory]
    [InlineData("UBUNTU-CVE-2026-23143", "CVE-2026-23143")]
    [InlineData("DEBIAN-CVE-2026-23143", "CVE-2026-23143")]
    [InlineData("BELL-CVE-2026-23143", "CVE-2026-23143")]
    [InlineData("ROOT-APP-MAVEN-CVE-2026-23143", "CVE-2026-23143")]
    [InlineData("ubuntu-cve-2026-23143", "CVE-2026-23143")]
    public void PrefixedIdentifier_ResolvesToItsCve(string identifier, string expected)
    {
        Assert.True(Identifier.TryGetEmbeddedCve(identifier, out var cve));
        Assert.Equal(expected, cve);
    }

    [Theory]
    // Already canonical: a CVE is not a downstream view of itself.
    [InlineData("CVE-2026-23143")]
    // Not end-anchored. The old implementation scraped these and merged unrelated advisories.
    [InlineData("CVE-2026-23143-EXTRA")]
    [InlineData("GHSA-CVE-2026-23143-XXXX")]
    // Not a CVE at all.
    [InlineData("GHSA-AAAA-BBBB-CCCC")]
    [InlineData("USN-7123-1")]
    [InlineData("RUSTSEC-2026-0001")]
    // Malformed CVEs.
    [InlineData("UBUNTU-CVE-2026-123")]
    [InlineData("UBUNTU-CVE-26-12345")]
    [InlineData("")]
    [InlineData(null)]
    public void EverythingElse_IsNotTreatedAsEmbeddingACve(string? identifier)
    {
        Assert.False(Identifier.TryGetEmbeddedCve(identifier, out var cve));
        Assert.Equal(string.Empty, cve);
    }
}
