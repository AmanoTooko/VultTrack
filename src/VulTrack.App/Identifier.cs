using System.Text.RegularExpressions;

namespace VulTrack.App;

public static partial class Identifier
{
    public static string Normalize(string value) => value.Trim().ToUpperInvariant();

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
        if (CweRegex().IsMatch(normalized)) return "CWE";
        return "OTHER";
    }

    [GeneratedRegex("^CWE-[0-9]+$")]
    private static partial Regex CweRegex();
}
