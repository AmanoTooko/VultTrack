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
}
