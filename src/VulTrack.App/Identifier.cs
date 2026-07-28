using System.Text.RegularExpressions;

namespace VulTrack.App;

public static partial class Identifier
{
    public static string Normalize(string value) => value.Trim().ToUpperInvariant();

    public static bool IsVulnerabilityId(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        var normalized = Normalize(value);
        if (normalized.Length is < 4 or > 160) return false;
        if (normalized.StartsWith("CVE-", StringComparison.Ordinal))
            return ExactCveRegex().IsMatch(normalized);
        return AdvisoryIdRegex().IsMatch(normalized);
    }

    public static string[] ExpandWithEmbeddedCves(string value)
    {
        var normalized = Normalize(value);
        var values = new List<string> { normalized };
        foreach (var match in CveRegex().Matches(normalized).Cast<Match>())
        {
            var cve = match.Value;
            if (!values.Contains(cve, StringComparer.OrdinalIgnoreCase))
                values.Add(cve);
        }
        return values.ToArray();
    }

    public static bool ContainsEmbeddedCve(string identifier, string cve)
    {
        var normalized = Normalize(identifier);
        var normalizedCve = Normalize(cve);
        return !string.Equals(normalized, normalizedCve, StringComparison.OrdinalIgnoreCase)
               && CveRegex().Matches(normalized).Cast<Match>()
                   .Any(match => string.Equals(match.Value, normalizedCve, StringComparison.OrdinalIgnoreCase));
    }

    public static string TypeOf(string value)
    {
        var normalized = Normalize(value);
        if (normalized.StartsWith("CVE-")) return "CVE";
        if (normalized.StartsWith("GHSA-")) return "GHSA";
        if (normalized.StartsWith("PYSEC-")) return "PYSEC";
        if (normalized.StartsWith("RUSTSEC-")) return "RUSTSEC";
        if (normalized.StartsWith("ASB-")) return "ASB";
        if (normalized.StartsWith("OSV-")) return "OSV";
        if (normalized.StartsWith("UBUNTU-")) return "UBUNTU";
        if (normalized.StartsWith("CNNVD-")) return "CNNVD";
        if (normalized.StartsWith("CNVD-")) return "CNVD";
        if (normalized.StartsWith("SSV-")) return "SSV";
        if (normalized.StartsWith("AVD-")) return "AVD";
        if (normalized.StartsWith("CT-")) return "CT";
        if (normalized.StartsWith("NSFOCUS-")) return "NSFOCUS";
        if (normalized.StartsWith("CERT360-")) return "CERT360";
        if (CweRegex().IsMatch(normalized)) return "CWE";
        return "OTHER";
    }

    [GeneratedRegex("^CWE-[0-9]+$")]
    private static partial Regex CweRegex();

    [GeneratedRegex("^CVE-[0-9]{4}-[0-9]{4,}$", RegexOptions.IgnoreCase)]
    private static partial Regex ExactCveRegex();

    [GeneratedRegex("^[A-Z][A-Z0-9_.]*-[A-Z0-9][A-Z0-9_.:-]*$", RegexOptions.IgnoreCase)]
    private static partial Regex AdvisoryIdRegex();

    [GeneratedRegex(@"\bCVE-\d{4}-\d{4,}\b", RegexOptions.IgnoreCase)]
    private static partial Regex CveRegex();
}
