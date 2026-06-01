using VulTrack.App;

namespace VulTrack.Tests;

public sealed class CanonicalIdentifierPolicyTests
{
    [Fact]
    public void ResolutionIdentifiers_UsesCveInsteadOfSharedAlias()
    {
        var draft = Draft("CVE-2026-31402", ["GHSA-SHARED", "CVE-2026-31402"]);

        Assert.Equal(["CVE-2026-31402"], CanonicalIdentifierPolicy.ResolutionIdentifiers(draft));
        Assert.Equal(["GHSA-SHARED", "CVE-2026-31402"], CanonicalIdentifierPolicy.EvidenceIdentifiers(draft));
    }

    [Fact]
    public void EvidenceIdentifiers_DropsAmbiguousMultiCveAliases()
    {
        var draft = Draft("CVE-2026-31402", ["POC-REPOSITORY", "CVE-2021-41864", "CVE-2026-31402"]);

        Assert.Equal(["CVE-2026-31402"], CanonicalIdentifierPolicy.ResolutionIdentifiers(draft));
        Assert.Equal(["CVE-2026-31402"], CanonicalIdentifierPolicy.EvidenceIdentifiers(draft));
    }

    [Fact]
    public void ResolutionIdentifiers_KeepsNonCveAdvisoriesSearchable()
    {
        var draft = Draft("GHSA-AAAA-BBBB-CCCC", ["GHSA-AAAA-BBBB-CCCC", "OSV-2026-1"]);

        Assert.Equal(["GHSA-AAAA-BBBB-CCCC", "OSV-2026-1"], CanonicalIdentifierPolicy.ResolutionIdentifiers(draft));
    }

    private static VulnerabilityCanonicalDraft Draft(string preferred, string[] identifiers) =>
        new(preferred, null, null, "active", null, null, identifiers, Guid.NewGuid(), Guid.NewGuid());
}
