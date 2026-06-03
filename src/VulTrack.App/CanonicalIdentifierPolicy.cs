namespace VulTrack.App;

public static class CanonicalIdentifierPolicy
{
    public static string[] EvidenceIdentifiers(VulnerabilityCanonicalDraft draft)
    {
        var identifiers = Normalize(draft.Identifiers.Length == 0 ? [draft.PreferredIdentifier] : draft.Identifiers);
        var cves = identifiers.Where(IsCve).ToArray();
        if (cves.Length <= 1) return identifiers;

        return [PreferredCve(draft, cves)];
    }

    public static string[] ResolutionIdentifiers(VulnerabilityCanonicalDraft draft)
    {
        var identifiers = EvidenceIdentifiers(draft);
        var cves = identifiers.Where(IsCve).ToArray();
        if (cves.Length == 0) return identifiers;
        var preferred = PreferredCve(draft, cves);
        return identifiers
            .Where(identifier => IsCve(identifier) || Identifier.ContainsEmbeddedCve(identifier, preferred))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static string[] Normalize(IEnumerable<string> identifiers) =>
        identifiers
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(Identifier.Normalize)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static bool IsCve(string identifier) => Identifier.TypeOf(identifier) == "CVE";

    private static string PreferredCve(VulnerabilityCanonicalDraft draft, string[] cves)
    {
        var preferred = Identifier.Normalize(draft.PreferredIdentifier);
        return cves.Contains(preferred, StringComparer.OrdinalIgnoreCase) ? preferred : cves[0];
    }
}
