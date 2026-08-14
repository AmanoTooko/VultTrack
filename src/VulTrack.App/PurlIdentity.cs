namespace VulTrack.App;

public static class PurlIdentity
{
    public static string? WithoutVersionAndQualifiers(string? purl)
    {
        if (string.IsNullOrWhiteSpace(purl)) return null;

        var value = purl.Trim();
        var fragment = value.IndexOf('#');
        if (fragment >= 0) value = value[..fragment];
        var query = value.IndexOf('?');
        if (query >= 0) value = value[..query];

        var slash = value.LastIndexOf('/');
        var at = value.LastIndexOf('@');
        return at > slash && at > "pkg:".Length ? value[..at] : value;
    }

    public static string? EcosystemFromPurl(string? purl)
    {
        if (string.IsNullOrWhiteSpace(purl) || !purl.StartsWith("pkg:", StringComparison.OrdinalIgnoreCase))
            return null;

        var slash = purl.IndexOf('/');
        if (slash < 0) return null;
        var type = purl["pkg:".Length..slash].ToLowerInvariant();
        var path = purl[(slash + 1)..].Split(['/', '@', '?', '#'], 2)[0];
        var distribution = Qualifier(purl, "distro")?.ToLowerInvariant();
        return type switch
        {
            "deb" => DistroEcosystem(
                path.Equals("ubuntu", StringComparison.OrdinalIgnoreCase) ? "ubuntu" : "debian",
                distribution),
            "apk" => DistroEcosystem("alpine", distribution),
            "rpm" => RpmEcosystem(path, distribution),
            "golang" => "go",
            "gem" => "rubygems",
            "composer" => "packagist",
            _ => type
        };
    }

    public static string? Qualifier(string? purl, string key)
    {
        if (string.IsNullOrWhiteSpace(purl)) return null;
        var queryStart = purl.IndexOf('?');
        if (queryStart < 0) return null;
        var fragmentStart = purl.IndexOf('#', queryStart + 1);
        var query = fragmentStart < 0
            ? purl[(queryStart + 1)..]
            : purl[(queryStart + 1)..fragmentStart];
        foreach (var pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = pair.Split('=', 2);
            if (parts.Length == 2 && string.Equals(parts[0], key, StringComparison.OrdinalIgnoreCase))
                return Uri.UnescapeDataString(parts[1]);
        }
        return null;
    }

    private static string DistroEcosystem(string fallback, string? distro)
    {
        if (string.IsNullOrWhiteSpace(distro)) return fallback;
        var match = System.Text.RegularExpressions.Regex.Match(
            distro,
            @"^(debian|ubuntu|alpine)[-_](\d+(?:\.\d+)?)",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        return match.Success
            ? $"{match.Groups[1].Value.ToLowerInvariant()}:{match.Groups[2].Value}"
            : fallback;
    }

    private static string RpmEcosystem(string distributionNamespace, string? distro)
    {
        var product = distributionNamespace.ToLowerInvariant() switch
        {
            "redhat" or "rhel" => "red hat:enterprise_linux",
            "rocky" or "rockylinux" => "rocky linux",
            "alma" or "almalinux" => "almalinux",
            "opensuse" => "opensuse",
            "suse" => "suse",
            _ => "rpm"
        };
        if (string.IsNullOrWhiteSpace(distro) || product is "rpm" or "opensuse" or "suse")
            return product;
        var version = System.Text.RegularExpressions.Regex.Match(distro, @"(?:^|[-_])(\d+)(?:[._-]|$)");
        return version.Success ? $"{product}:{version.Groups[1].Value}" : product;
    }
}
