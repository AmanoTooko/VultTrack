namespace VulTrack.App;

public static class CvssScoreCalculator
{
    private static readonly IReadOnlyDictionary<string, decimal> V3Weights =
        new Dictionary<string, decimal>(StringComparer.OrdinalIgnoreCase)
        {
            ["AV:N"] = 0.85m,
            ["AV:A"] = 0.62m,
            ["AV:L"] = 0.55m,
            ["AV:P"] = 0.20m,
            ["AC:L"] = 0.77m,
            ["AC:H"] = 0.44m,
            ["UI:N"] = 0.85m,
            ["UI:R"] = 0.62m,
            ["C:N"] = 0.00m,
            ["C:L"] = 0.22m,
            ["C:H"] = 0.56m,
            ["I:N"] = 0.00m,
            ["I:L"] = 0.22m,
            ["I:H"] = 0.56m,
            ["A:N"] = 0.00m,
            ["A:L"] = 0.22m,
            ["A:H"] = 0.56m
        };

    private static readonly IReadOnlyDictionary<string, decimal> V3PrivilegesRequiredUnchanged =
        new Dictionary<string, decimal>(StringComparer.OrdinalIgnoreCase)
        {
            ["PR:N"] = 0.85m,
            ["PR:L"] = 0.62m,
            ["PR:H"] = 0.27m
        };

    private static readonly IReadOnlyDictionary<string, decimal> V3PrivilegesRequiredChanged =
        new Dictionary<string, decimal>(StringComparer.OrdinalIgnoreCase)
        {
            ["PR:N"] = 0.85m,
            ["PR:L"] = 0.68m,
            ["PR:H"] = 0.50m
        };

    private static readonly IReadOnlyDictionary<string, decimal> V2Weights =
        new Dictionary<string, decimal>(StringComparer.OrdinalIgnoreCase)
        {
            ["AV:L"] = 0.395m,
            ["AV:A"] = 0.646m,
            ["AV:N"] = 1.000m,
            ["AC:H"] = 0.350m,
            ["AC:M"] = 0.610m,
            ["AC:L"] = 0.710m,
            ["AU:M"] = 0.450m,
            ["AU:S"] = 0.560m,
            ["AU:N"] = 0.704m,
            ["C:N"] = 0.000m,
            ["C:P"] = 0.275m,
            ["C:C"] = 0.660m,
            ["I:N"] = 0.000m,
            ["I:P"] = 0.275m,
            ["I:C"] = 0.660m,
            ["A:N"] = 0.000m,
            ["A:P"] = 0.275m,
            ["A:C"] = 0.660m
        };

    public static decimal? CalculateBaseScore(string? vector, string? versionHint = null)
    {
        var parsed = Parse(vector, versionHint);
        return parsed?.Version switch
        {
            "3.0" or "3.1" => CalculateV3(parsed.Version, parsed.Metrics),
            "2.0" => CalculateV2(parsed.Metrics),
            _ => null
        };
    }

    private static decimal? CalculateV3(string version, IReadOnlyDictionary<string, string> metrics)
    {
        if (!metrics.TryGetValue("S", out var scope) ||
            !string.Equals(scope, "U", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(scope, "C", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var attackVector = Weight(metrics, "AV", V3Weights);
        var attackComplexity = Weight(metrics, "AC", V3Weights);
        var privilegesRequired = Weight(
            metrics,
            "PR",
            string.Equals(scope, "C", StringComparison.OrdinalIgnoreCase)
                ? V3PrivilegesRequiredChanged
                : V3PrivilegesRequiredUnchanged);
        var userInteraction = Weight(metrics, "UI", V3Weights);
        var confidentiality = Weight(metrics, "C", V3Weights);
        var integrity = Weight(metrics, "I", V3Weights);
        var availability = Weight(metrics, "A", V3Weights);

        if (attackVector is null ||
            attackComplexity is null ||
            privilegesRequired is null ||
            userInteraction is null ||
            confidentiality is null ||
            integrity is null ||
            availability is null)
        {
            return null;
        }

        var impactSubScore = 1m - ((1m - confidentiality.Value) * (1m - integrity.Value) * (1m - availability.Value));
        var impact = string.Equals(scope, "U", StringComparison.OrdinalIgnoreCase)
            ? 6.42m * impactSubScore
            : version == "3.0"
                ? (7.52m * (impactSubScore - 0.029m)) - (3.25m * Pow(impactSubScore - 0.02m, 15))
                : (7.52m * (impactSubScore - 0.029m)) - (3.25m * Pow((impactSubScore * 0.9731m) - 0.02m, 13));

        if (impact <= 0m) return 0m;

        var exploitability = 8.22m * attackVector.Value * attackComplexity.Value * privilegesRequired.Value * userInteraction.Value;
        var baseScore = string.Equals(scope, "U", StringComparison.OrdinalIgnoreCase)
            ? Math.Min(impact + exploitability, 10m)
            : Math.Min(1.08m * (impact + exploitability), 10m);

        return RoundUpToOneDecimal(baseScore);
    }

    private static decimal? CalculateV2(IReadOnlyDictionary<string, string> metrics)
    {
        var attackVector = Weight(metrics, "AV", V2Weights);
        var attackComplexity = Weight(metrics, "AC", V2Weights);
        var authentication = Weight(metrics, "AU", V2Weights);
        var confidentiality = Weight(metrics, "C", V2Weights);
        var integrity = Weight(metrics, "I", V2Weights);
        var availability = Weight(metrics, "A", V2Weights);

        if (attackVector is null ||
            attackComplexity is null ||
            authentication is null ||
            confidentiality is null ||
            integrity is null ||
            availability is null)
        {
            return null;
        }

        var impact = 10.41m * (1m - ((1m - confidentiality.Value) * (1m - integrity.Value) * (1m - availability.Value)));
        var exploitability = 20m * attackVector.Value * attackComplexity.Value * authentication.Value;
        var impactFactor = impact == 0m ? 0m : 1.176m;
        var baseScore = (((0.6m * impact) + (0.4m * exploitability) - 1.5m) * impactFactor);

        return decimal.Round(baseScore, 1, MidpointRounding.AwayFromZero);
    }

    private static ParsedVector? Parse(string? vector, string? versionHint)
    {
        if (string.IsNullOrWhiteSpace(vector)) return null;

        var parts = vector.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length == 0) return null;

        var offset = 0;
        string? vectorVersion = null;
        if (parts[0].StartsWith("CVSS:", StringComparison.OrdinalIgnoreCase))
        {
            vectorVersion = parts[0]["CVSS:".Length..];
            offset = 1;
        }

        var metrics = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var index = offset; index < parts.Length; index++)
        {
            var separator = parts[index].IndexOf(':');
            if (separator <= 0 || separator == parts[index].Length - 1) return null;

            var name = parts[index][..separator];
            var value = parts[index][(separator + 1)..];
            if (!metrics.TryAdd(name, value)) return null;
        }

        var version = vectorVersion is null
            ? NormalizeVersion(versionHint)
            : NormalizeVersion(vectorVersion);
        if (version is null && metrics.ContainsKey("AU")) version = "2.0";

        return version is null ? null : new ParsedVector(version, metrics);
    }

    private static string? NormalizeVersion(string? version) =>
        version?.Trim().ToUpperInvariant() switch
        {
            "2" or "2.0" or "CVSS:2.0" or "CVSS_V2" or "CVSS_V2_0" => "2.0",
            "3.0" or "CVSS:3.0" or "CVSS_V3_0" => "3.0",
            "3" or "3.1" or "CVSS:3.1" or "CVSS_V3" or "CVSS_V3_1" => "3.1",
            _ => null
        };

    private static decimal? Weight(
        IReadOnlyDictionary<string, string> metrics,
        string metric,
        IReadOnlyDictionary<string, decimal> weights)
    {
        return metrics.TryGetValue(metric, out var value) &&
               weights.TryGetValue($"{metric}:{value}", out var weight)
            ? weight
            : null;
    }

    private static decimal Pow(decimal value, int exponent)
    {
        var result = 1m;
        for (var index = 0; index < exponent; index++) result *= value;
        return result;
    }

    private static decimal RoundUpToOneDecimal(decimal value) => Math.Ceiling(value * 10m) / 10m;

    private sealed record ParsedVector(string Version, IReadOnlyDictionary<string, string> Metrics);
}
