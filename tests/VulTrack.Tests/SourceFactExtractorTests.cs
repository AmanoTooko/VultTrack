using System.Linq;
using System.Text.Json.Nodes;
using VulTrack.App;

namespace VulTrack.Tests;

public class SourceFactExtractorTests
{
    [Fact]
    public void OsvSeverities_CalculatesCvss31ScoreFromVector()
    {
        var severity = JsonNode.Parse("""
        [
          { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }
        ]
        """);

        var rows = SourceFactExtractor.OsvSeverities(severity).ToList();

        Assert.Single(rows);
        Assert.Equal("cvss", rows[0].ScoringSystem);
        Assert.Equal("3.1", rows[0].ScoringVersion);
        Assert.StartsWith("CVSS:3.1", rows[0].VectorString);
        Assert.Equal(9.8m, rows[0].Score);
        Assert.Equal("CRITICAL", rows[0].SeverityLabel);
    }

    [Fact]
    public void CvssSeverities_WalksNestedGhsaShape()
    {
        var cvss = JsonNode.Parse("""
        {
          "cvss_v3": {
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "score": 9.8
          }
        }
        """);

        var rows = SourceFactExtractor.CvssSeverities(cvss).ToList();

        Assert.Contains(rows, x => x.ScoringVersion == "3.1" && x.Score == 9.8m && x.SeverityLabel == "CRITICAL");
    }

    [Fact]
    public void CvssSeverities_CalculatesLog4jScoreFromVector()
    {
        var cvss = JsonNode.Parse("""
        {
          "version": "3.1",
          "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        }
        """);

        var rows = SourceFactExtractor.CvssSeverities(cvss).ToList();

        Assert.Single(rows);
        Assert.Equal(10.0m, rows[0].Score);
        Assert.Equal("CRITICAL", rows[0].SeverityLabel);
    }

    [Fact]
    public void CvssScoreCalculator_CalculatesCvss30BaseVector()
    {
        var score = CvssScoreCalculator.CalculateBaseScore(
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

        Assert.Equal(9.8m, score);
    }

    [Fact]
    public void CvssScoreCalculator_UsesVersionSpecificChangedScopeFormula()
    {
        const string metrics = "/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H";

        Assert.Equal(9.9m, CvssScoreCalculator.CalculateBaseScore("CVSS:3.0" + metrics));
        Assert.Equal(10.0m, CvssScoreCalculator.CalculateBaseScore("CVSS:3.1" + metrics));
    }

    [Fact]
    public void CvssSeverities_CalculatesCvss20BareVector()
    {
        var cvss = JsonNode.Parse("""
        {
          "version": "2.0",
          "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C"
        }
        """);

        var rows = SourceFactExtractor.CvssSeverities(cvss).ToList();

        Assert.Single(rows);
        Assert.Equal(10.0m, rows[0].Score);
        Assert.Equal("HIGH", rows[0].SeverityLabel);
    }

    [Fact]
    public void References_HandlesObjectReferences()
    {
        var references = JsonNode.Parse("""
        [
          { "type": "WEB", "url": "https://example.test/advisory", "tags": ["Patch"] }
        ]
        """);

        var rows = SourceFactExtractor.References(references).ToList();

        Assert.Single(rows);
        Assert.Equal("https://example.test/advisory", rows[0].Url);
        Assert.Equal("WEB", rows[0].RefType);
        Assert.Equal("Patch", rows[0].Tags[0]);
    }
}
