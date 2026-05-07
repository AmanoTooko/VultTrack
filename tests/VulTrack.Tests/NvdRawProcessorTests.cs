using System.Linq;
using VulTrack.App;

namespace VulTrack.Tests;

public class NvdRawProcessorTests
{
    [Fact]
    public void ExtractCvss_ReturnsAllSupportedVersions()
    {
        const string metrics = """
        {
          "cvssMetricV40": [
            { "cvssData": { "version": "4.0", "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", "baseScore": 9.3, "baseSeverity": "CRITICAL" } }
          ],
          "cvssMetricV31": [
            { "cvssData": { "version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 9.8, "baseSeverity": "CRITICAL" } }
          ],
          "cvssMetricV2": [
            { "cvssData": { "version": "2.0", "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P", "baseScore": 7.5 }, "baseSeverity": "HIGH" }
          ]
        }
        """;

        var scores = NvdRawProcessor.ExtractCvss(metrics).ToList();

        Assert.Equal(3, scores.Count);
        Assert.Contains(scores, x => x.Version == "4.0" && x.Score == 9.3m);
        Assert.Contains(scores, x => x.Version == "3.1" && x.Score == 9.8m);
        Assert.Contains(scores, x => x.Version == "2.0" && x.Severity == "HIGH");
    }
}
