using System.Linq;
using System.Text.Json.Nodes;
using VulTrack.App;

namespace VulTrack.Tests;

public class SourceFactExtractorTests
{
    [Fact]
    public void OsvSeverities_ExtractsCvssVectorVersion()
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
