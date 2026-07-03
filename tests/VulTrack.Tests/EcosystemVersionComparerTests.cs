using VulTrack.App;

namespace VulTrack.Tests;

public class EcosystemVersionComparerTests
{
    [Theory]
    [InlineData("3.11.2-6+deb12u6", "< 3.11.2-6+deb12u7", true)]
    [InlineData("3.11.2-6+deb12u7", "< 3.11.2-6+deb12u7", false)]
    [InlineData("1:2.6.1-1", "> 2.6.1-99", true)]
    [InlineData("1.0~rc1-1", "< 1.0-1", true)]
    public void DebianVersions_FollowDpkgOrdering(string version, string range, bool expected)
    {
        Assert.Equal(expected, EcosystemVersionComparer.Matches(version, range, "debian:12"));
    }

    [Theory]
    [InlineData("1.2.3-r0", "< 1.2.3-r1", true)]
    [InlineData("1.2.3_rc1-r0", "< 1.2.3-r0", true)]
    [InlineData("1.2.3-r2", "< 1.2.3-r1", false)]
    public void AlpineVersions_ComparePackageRevision(string version, string range, bool expected)
    {
        Assert.Equal(expected, EcosystemVersionComparer.Matches(version, range, "alpine:3.21"));
    }

    [Theory]
    [InlineData("1:2.0-1.el9", "> 2.99-99.el9", true)]
    [InlineData("2.0~rc1-1.el9", "< 2.0-1.el9", true)]
    public void RpmVersions_CompareEpochAndTilde(string version, string range, bool expected)
    {
        Assert.Equal(expected, EcosystemVersionComparer.Matches(version, range, "rpm"));
    }

    [Theory]
    [InlineData("1.2.3-rc.1", "< 1.2.3", true)]
    [InlineData("1.2.3+build.5", "= 1.2.3", true)]
    [InlineData("1.10.0", "> 1.9.9", true)]
    public void DefaultVersions_AreSemverLike(string version, string range, bool expected)
    {
        Assert.Equal(expected, EcosystemVersionComparer.Matches(version, range, "npm"));
    }

    [Theory]
    [InlineData("1.0.0", "< 2.0.0", true)]
    [InlineData("1.0.0", ">= 0, < 2.0.0", true)]
    [InlineData("2.0.0", ">= 0, < 2.0.0", false)]
    public void LowerBoundRanges_AreMatchedSemantically(string version, string range, bool expected)
    {
        Assert.Equal(expected, EcosystemVersionComparer.Matches(version, range, "npm"));
    }

    [Theory]
    [InlineData("a1b2c3d", "< 2.0.0")]
    [InlineData("git+https://example.test/repo@a1b2c3d", "< 2.0.0")]
    public void CommitLikeVersions_AreUnknownForSemanticRanges(string version, string range)
    {
        Assert.Null(EcosystemVersionComparer.Matches(version, range, "npm"));
    }

    [Fact]
    public void CommitLikeVersions_CanMatchExactHashConstraints()
    {
        Assert.True(EcosystemVersionComparer.Matches("a1b2c3d", "= a1b2c3d", "npm"));
        Assert.Null(EcosystemVersionComparer.Matches("a1b2c3d", "= deadbee", "npm"));
    }
}
