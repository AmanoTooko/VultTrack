using System.Collections.Concurrent;
using System.Text.RegularExpressions;

namespace VulTrack.App;

public static class EcosystemVersionComparer
{
    private static readonly ConcurrentDictionary<string, bool?> Cache = new();
    private static readonly Regex ConstraintPattern = new(@"(<=|>=|==|=|<|>)\s*([^\s,]+)", RegexOptions.Compiled);

    public static bool? Matches(string version, string? range, string? ecosystem = null)
    {
        if (string.IsNullOrWhiteSpace(version) || string.IsNullOrWhiteSpace(range)) return null;
        var cacheKey = $"{ecosystem}|{version}|{range}";
        if (Cache.TryGetValue(cacheKey, out var cached)) return cached;

        var constraints = ConstraintPattern.Matches(range)
            .Select(match => (Op: match.Groups[1].Value, Version: match.Groups[2].Value))
            .ToArray();
        if (constraints.Length == 0) return null;

        foreach (var constraint in constraints)
        {
            var compared = Compare(version, constraint.Version, ecosystem);
            var matched = constraint.Op switch
            {
                "<" => compared < 0,
                "<=" => compared <= 0,
                ">" => compared > 0,
                ">=" => compared >= 0,
                "=" or "==" => compared == 0,
                _ => false
            };
            if (!matched)
            {
                Cache.TryAdd(cacheKey, false);
                return false;
            }
        }

        Cache.TryAdd(cacheKey, true);
        return true;
    }

    public static int Compare(string left, string right, string? ecosystem = null)
    {
        var normalized = ecosystem?.ToLowerInvariant() ?? "";
        if (normalized.StartsWith("debian") || normalized.StartsWith("ubuntu") || normalized == "deb")
            return CompareDebian(left, right);
        if (normalized.StartsWith("rpm") || normalized.StartsWith("redhat") || normalized.StartsWith("rocky") || normalized.StartsWith("alma"))
            return CompareRpm(left, right);
        if (normalized.StartsWith("alpine") || normalized == "apk")
            return CompareApk(left, right);
        return CompareSemverLike(left, right);
    }

    private static int CompareDebian(string left, string right)
    {
        var l = DebianParts(left);
        var r = DebianParts(right);
        var result = l.Epoch.CompareTo(r.Epoch);
        if (result != 0) return result;
        result = CompareDebianPart(l.Upstream, r.Upstream);
        return result != 0 ? result : CompareDebianPart(l.Revision, r.Revision);
    }

    private static (long Epoch, string Upstream, string Revision) DebianParts(string value)
    {
        var epoch = 0L;
        var rest = value;
        var colon = value.IndexOf(':');
        if (colon >= 0 && long.TryParse(value[..colon], out var parsedEpoch))
        {
            epoch = parsedEpoch;
            rest = value[(colon + 1)..];
        }

        var dash = rest.LastIndexOf('-');
        return dash < 0
            ? (epoch, rest, "0")
            : (epoch, rest[..dash], rest[(dash + 1)..]);
    }

    private static int CompareDebianPart(string left, string right)
    {
        var li = 0;
        var ri = 0;
        while (li < left.Length || ri < right.Length)
        {
            while ((li < left.Length && !char.IsDigit(left[li])) || (ri < right.Length && !char.IsDigit(right[ri])))
            {
                var compared = DebianCharOrder(li < left.Length ? left[li] : '\0')
                    .CompareTo(DebianCharOrder(ri < right.Length ? right[ri] : '\0'));
                if (compared != 0) return compared;
                if (li < left.Length) li++;
                if (ri < right.Length) ri++;
            }

            while (li < left.Length && left[li] == '0') li++;
            while (ri < right.Length && right[ri] == '0') ri++;
            var lstart = li;
            var rstart = ri;
            while (li < left.Length && char.IsDigit(left[li])) li++;
            while (ri < right.Length && char.IsDigit(right[ri])) ri++;
            var llen = li - lstart;
            var rlen = ri - rstart;
            if (llen != rlen) return llen.CompareTo(rlen);
            for (var i = 0; i < llen; i++)
            {
                if (left[lstart + i] != right[rstart + i])
                    return left[lstart + i].CompareTo(right[rstart + i]);
            }
        }
        return 0;
    }

    private static int DebianCharOrder(char value) =>
        value switch
        {
            '~' => -1,
            '\0' => 0,
            _ when char.IsLetter(value) => value,
            _ => value + 256
        };

    private static int CompareRpm(string left, string right)
    {
        var l = RpmParts(left);
        var r = RpmParts(right);
        var result = l.Epoch.CompareTo(r.Epoch);
        return result != 0 ? result : CompareTokenized(l.Value, r.Value, rpmMode: true);
    }

    private static (long Epoch, string Value) RpmParts(string value)
    {
        var colon = value.IndexOf(':');
        return colon >= 0 && long.TryParse(value[..colon], out var epoch)
            ? (epoch, value[(colon + 1)..])
            : (0, value);
    }

    private static int CompareApk(string left, string right)
    {
        var l = ApkParts(left);
        var r = ApkParts(right);
        var result = CompareTokenized(l.Version, r.Version);
        return result != 0 ? result : l.Revision.CompareTo(r.Revision);
    }

    private static (string Version, int Revision) ApkParts(string value)
    {
        var match = Regex.Match(value, @"^(.*?)-r(\d+)$", RegexOptions.IgnoreCase);
        return match.Success ? (match.Groups[1].Value, int.Parse(match.Groups[2].Value)) : (value, 0);
    }

    private static int CompareSemverLike(string left, string right) =>
        CompareTokenized(left.TrimStart('v', 'V').Split('+', 2)[0], right.TrimStart('v', 'V').Split('+', 2)[0]);

    private static int CompareTokenized(string left, string right, bool rpmMode = false)
    {
        var l = Tokens(left, rpmMode);
        var r = Tokens(right, rpmMode);
        for (var i = 0; i < Math.Max(l.Count, r.Count); i++)
        {
            if (i >= l.Count) return r[i].Kind == TokenKind.PreRelease ? 1 : -1;
            if (i >= r.Count) return l[i].Kind is TokenKind.PreRelease or TokenKind.Tilde ? -1 : 1;
            var compared = CompareToken(l[i], r[i]);
            if (compared != 0) return compared;
        }
        return 0;
    }

    private static int CompareToken(Token left, Token right)
    {
        if (left.Kind != right.Kind)
        {
            if (left.Kind == TokenKind.Tilde || right.Kind == TokenKind.Tilde)
                return left.Kind == TokenKind.Tilde ? -1 : 1;
            if (left.Kind == TokenKind.Number || right.Kind == TokenKind.Number)
                return left.Kind == TokenKind.Number ? 1 : -1;
        }
        if (left.Kind == TokenKind.Number)
        {
            var l = left.Value.TrimStart('0');
            var r = right.Value.TrimStart('0');
            if (l.Length != r.Length) return l.Length.CompareTo(r.Length);
            return string.CompareOrdinal(l, r);
        }
        return string.Compare(left.Value, right.Value, StringComparison.OrdinalIgnoreCase);
    }

    private static List<Token> Tokens(string value, bool rpmMode)
    {
        var tokens = new List<Token>();
        for (var i = 0; i < value.Length;)
        {
            var ch = value[i];
            if (ch == '~')
            {
                tokens.Add(new Token(TokenKind.Tilde, "~"));
                i++;
                continue;
            }
            if (!char.IsLetterOrDigit(ch))
            {
                i++;
                continue;
            }
            var numeric = char.IsDigit(ch);
            var start = i++;
            while (i < value.Length && char.IsLetterOrDigit(value[i]) && char.IsDigit(value[i]) == numeric) i++;
            var raw = value[start..i];
            var prerelease = !rpmMode && !numeric && IsPreRelease(raw);
            tokens.Add(new Token(prerelease ? TokenKind.PreRelease : numeric ? TokenKind.Number : TokenKind.Text, raw));
        }
        return tokens;
    }

    private static bool IsPreRelease(string value) =>
        value.Equals("alpha", StringComparison.OrdinalIgnoreCase)
        || value.Equals("beta", StringComparison.OrdinalIgnoreCase)
        || value.Equals("pre", StringComparison.OrdinalIgnoreCase)
        || value.Equals("preview", StringComparison.OrdinalIgnoreCase)
        || value.Equals("rc", StringComparison.OrdinalIgnoreCase);

    private enum TokenKind { Tilde, PreRelease, Text, Number }
    private sealed record Token(TokenKind Kind, string Value);
}
