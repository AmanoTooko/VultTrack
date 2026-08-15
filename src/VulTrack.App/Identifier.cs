using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace VulTrack.App;

public static partial class Identifier
{
    private static readonly string[] CanonicalAdvisoryPrefixes = ["GHSA-", "BDSA-"];

    public static string Normalize(string value) => value.Trim().ToUpperInvariant();

    public static bool IsCve(string? value) =>
        !string.IsNullOrWhiteSpace(value) && ExactCveRegex().IsMatch(Normalize(value));

    public static bool IsVulnerabilityId(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        var normalized = Normalize(value);
        if (normalized.Length is < 4 or > 160) return false;
        if (normalized.StartsWith("CVE-", StringComparison.Ordinal))
            return ExactCveRegex().IsMatch(normalized);
        return AdvisoryIdRegex().IsMatch(normalized);
    }

    /// <summary>
    /// Extracts the CVE a prefixed identifier is a downstream view of, for example
    /// UBUNTU-CVE-2026-23143 or DEBIAN-CVE-2026-23143 -> CVE-2026-23143.
    /// </summary>
    /// <remarks>
    /// Deliberately end-anchored and single-match. An earlier implementation scraped every CVE
    /// found anywhere in a record (including payload metadata such as database_specific.cve_ids),
    /// which merged unrelated advisories together. Only an identifier that *ends* with the CVE is
    /// treated as naming that CVE.
    /// </remarks>
    public static bool TryGetEmbeddedCve(string? value, out string cve)
    {
        cve = string.Empty;
        if (string.IsNullOrWhiteSpace(value)) return false;
        var normalized = Normalize(value);
        // A bare CVE is already canonical, not a downstream view of one.
        if (ExactCveRegex().IsMatch(normalized)) return false;
        var match = EmbeddedCveSuffixRegex().Match(normalized);
        if (!match.Success) return false;
        cve = match.Groups[1].Value;
        return true;
    }

    /// <summary>
    /// Selects the canonical identity from direct aliases. Relationship fields such as OSV
    /// upstream/related are intentionally excluded by the caller because they do not assert
    /// that two advisories are the same vulnerability record.
    /// </summary>
    public static string ResolveCanonicalIdentity(string ownIdentifier, IEnumerable<string> identifiers)
    {
        var own = Normalize(ownIdentifier);
        var values = identifiers
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(Normalize)
            .Where(IsVulnerabilityId)
            .Append(own)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        // A suffix identifier explicitly names one CVE even when its payload contains other
        // related CVEs: DEBIAN-CVE-2026-1234 is a downstream view of CVE-2026-1234.
        if (TryGetEmbeddedCve(own, out var embeddedCve)) return embeddedCve;
        if (IsCve(own)) return own;

        var cves = values
            .Select(value =>
            {
                if (IsCve(value)) return value;
                return TryGetEmbeddedCve(value, out var candidate) ? candidate : null;
            })
            .Where(value => value is not null)
            .Select(value => value!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (cves.Length == 1) return cves[0];
        if (cves.Length > 1) return own;

        // A GHSA/BDSA with no CVE, or with several CVEs, remains an independent advisory.
        // The prefixes are deliberately a small authoritative allow-list; arbitrary advisory
        // IDs do not gain ownership merely because they happen to be aliases.
        foreach (var prefix in CanonicalAdvisoryPrefixes)
        {
            if (own.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && IsVulnerabilityId(own))
                return own;
            var advisories = values
                .Where(value => value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                .ToArray();
            if (advisories.Length == 1) return advisories[0];
        }

        return own;
    }

    public static Guid DeterministicVulnerabilityId(string canonicalIdentifier)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes($"vulnerability:{Normalize(canonicalIdentifier)}"));
        Span<byte> bytes = stackalloc byte[16];
        hash.AsSpan(0, 16).CopyTo(bytes);
        bytes[6] = (byte)((bytes[6] & 0x0f) | 0x50);
        bytes[8] = (byte)((bytes[8] & 0x3f) | 0x80);
        return new Guid(bytes);
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

    // The prefix may itself contain hyphens (ROOT-APP-MAVEN-CVE-2026-1234); the trailing CVE is
    // pinned to the end of the string so a CVE mentioned mid-identifier never becomes the key.
    [GeneratedRegex(@"^[A-Z][A-Z0-9_.-]*-(CVE-[0-9]{4}-[0-9]{4,})$", RegexOptions.IgnoreCase)]
    private static partial Regex EmbeddedCveSuffixRegex();
}
