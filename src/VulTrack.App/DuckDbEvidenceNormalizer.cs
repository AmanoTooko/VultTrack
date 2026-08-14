using System.Text.Json.Nodes;

namespace VulTrack.App;

public sealed partial class DuckDbEvidenceNormalizer(
    IServiceProvider services,
    DuckDbEvidenceStore store,
    ILogger<DuckDbEvidenceNormalizer> logger)
{
    private static string CanonicalEvidenceSourceCode(string sourceCode) => sourceCode.ToLowerInvariant() switch
    {
        "nvd-cve-init" => "nvd-cve",
        "osv-init" => "osv",
        "android-osv-init" => "android-osv",
        "google-osv-init" => "google-osv",
        "maven-osv-init" => "maven-osv",
        _ => sourceCode.ToLowerInvariant()
    };

    private static IEnumerable<DuckDbAffectedFact> ExtractDebianFacts(JsonNode? packages)
    {
        if (packages is not JsonObject obj) yield break;
        foreach (var (packageName, advisory) in obj)
        {
            if (string.IsNullOrWhiteSpace(packageName)) continue;
            foreach (var fact in ExtractDebianFacts(packageName, advisory))
                yield return fact;
        }
    }

    private static IEnumerable<DuckDbAffectedFact> ExtractDebianFacts(string packageName, JsonNode? advisory)
    {
        if (advisory?["releases"] is not JsonObject releases) yield break;
        foreach (var (release, item) in releases)
        {
            var status = item?["status"]?.GetValue<string>()?.ToLowerInvariant();
            var fixedVersion = item?["fixed_version"]?.GetValue<string>();
            var range = status switch
            {
                "open" => ">= 0",
                "resolved" when !string.IsNullOrWhiteSpace(fixedVersion) && fixedVersion != "0" => $"< {fixedVersion}",
                _ => null
            };
            if (range is null) continue;
            yield return new DuckDbAffectedFact(
                "package",
                DebianEcosystem(release),
                packageName,
                $"pkg:deb/debian/{Uri.EscapeDataString(packageName)}",
                null,
                range,
                $"security-tracker:{status}",
                true);
        }
    }

    private static IEnumerable<DuckDbAffectedFact> ExtractOsvFacts(JsonNode? affected)
    {
        foreach (var item in ArrayItems(affected))
        {
            var package = item?["package"];
            var ecosystem = package?["ecosystem"]?.GetValue<string>();
            var name = package?["name"]?.GetValue<string>();
            var purl = package?["purl"]?.GetValue<string>() ?? ToPurl(ecosystem, name);
            var emitted = false;
            foreach (var range in ArrayItems(item?["ranges"]))
            {
                var rangeType = range?["type"]?.GetValue<string>();
                foreach (var expression in OsvRanges(range))
                {
                    emitted = true;
                    yield return new DuckDbAffectedFact("package", ecosystem, name, purl, null, expression, rangeType, true);
                }
            }

            if (!emitted)
            {
                foreach (var version in ArrayItems(item?["versions"])
                    .Select(node => node?.GetValue<string>())
                    .Where(value => !string.IsNullOrWhiteSpace(value)))
                {
                    emitted = true;
                    yield return new DuckDbAffectedFact("package", ecosystem, name, purl, null, $"= {version}", "versions", true);
                }
            }

            if (!emitted && !string.IsNullOrWhiteSpace(name))
                yield return new DuckDbAffectedFact("package", ecosystem, name, purl, null, null, null, true);
        }
    }

    private static IEnumerable<DuckDbAffectedFact> ExtractNvdFacts(JsonNode? configurations)
    {
        foreach (var cpeMatch in WalkCpeMatches(configurations))
        {
            var criteria = cpeMatch?["criteria"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(criteria)) continue;
            var range = CpeRange(cpeMatch);
            yield return new DuckDbAffectedFact(
                "cpe",
                "cpe",
                ParseCpeProduct(criteria),
                null,
                criteria,
                range,
                range is null ? "cpe_match_no_range" : "cpe_match",
                cpeMatch?["vulnerable"]?.GetValue<bool>() ?? true);
        }
    }

    private static IEnumerable<DuckDbAffectedFact> ExtractCveListFacts(JsonNode? cna)
    {
        foreach (var affected in ArrayItems(cna?["affected"]))
        {
            var vendor = affected?["vendor"]?.GetValue<string>();
            var product = affected?["product"]?.GetValue<string>();
            var name = string.Join(':', new[] { vendor, product }.Where(x => !string.IsNullOrWhiteSpace(x)));
            if (string.IsNullOrWhiteSpace(name)) continue;
            foreach (var version in ArrayItems(affected?["versions"]))
            {
                var status = version?["status"]?.GetValue<string>();
                if (!string.Equals(status, "affected", StringComparison.OrdinalIgnoreCase)) continue;
                var lessThan = version?["lessThan"]?.GetValue<string>();
                var lessThanOrEqual = version?["lessThanOrEqual"]?.GetValue<string>();
                var exactVersion = version?["version"]?.GetValue<string>();
                string? rawRange;
                if (exactVersion is not null && lessThan is not null)
                    rawRange = $">= {exactVersion}, < {lessThan}";
                else if (exactVersion is not null && lessThanOrEqual is not null)
                    rawRange = $">= {exactVersion}, <= {lessThanOrEqual}";
                else if (lessThan is not null)
                    rawRange = $"< {lessThan}";
                else if (lessThanOrEqual is not null)
                    rawRange = $"<= {lessThanOrEqual}";
                else if (exactVersion is not null)
                    rawRange = $"= {exactVersion}";
                else
                    rawRange = version?.ToJsonString();
                yield return new DuckDbAffectedFact("package", null, name, null, null, rawRange, "cve-list", true);
            }
        }
    }

    private static IEnumerable<DuckDbReference> ExtractCveListReferences(JsonNode? references)
    {
        foreach (var reference in ArrayItems(references))
        {
            var url = reference?["url"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(url)) continue;
            var tags = ArrayItems(reference?["tags"])
                .Select(x => x?.GetValue<string>())
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(x => x!)
                .ToArray();
            yield return new DuckDbReference(url, null, tags);
        }
    }

    private static IEnumerable<DuckDbSeverityScore> ExtractOsvSeverity(JsonNode? severity)
    {
        foreach (var item in ArrayItems(severity))
        {
            var type = item?["type"]?.GetValue<string>() ?? "vendor";
            var scoreText = item?["score"]?.GetValue<string>();
            var versionFromType = CvssVersionFromType(type);
            var calculatedScore = CvssScoreCalculator.CalculateBaseScore(scoreText, versionFromType);
            var vector = scoreText?.StartsWith("CVSS:", StringComparison.OrdinalIgnoreCase) == true || calculatedScore is not null
                ? scoreText
                : null;
            var numeric = DecimalValue(item?["score"]);
            var score = numeric ?? calculatedScore;
            var version = CvssVersion(vector) ?? versionFromType;
            yield return new DuckDbSeverityScore(
                type.StartsWith("CVSS", StringComparison.OrdinalIgnoreCase) ? "cvss" : type.ToLowerInvariant(),
                version,
                "base",
                vector,
                score,
                score is null ? null : SeverityFromScore(score.Value, version));
        }
    }

    private static IEnumerable<DuckDbSeverityScore> ExtractGhsaSeverity(JsonNode? cvss)
    {
        var vector = cvss?["vector_string"]?.GetValue<string>() ?? cvss?["vector"]?.GetValue<string>();
        var score = DecimalValue(cvss?["score"]);
        var version = vector?.StartsWith("CVSS:4.", StringComparison.OrdinalIgnoreCase) == true ? "4.0"
            : vector?.StartsWith("CVSS:3.1", StringComparison.OrdinalIgnoreCase) == true ? "3.1"
            : vector?.StartsWith("CVSS:3.0", StringComparison.OrdinalIgnoreCase) == true ? "3.0"
            : null;
        if (vector is not null || score is not null)
            yield return new DuckDbSeverityScore("cvss", version, "base", vector, score, score is null ? null : SeverityFromScore(score.Value, version));
    }

    private static IEnumerable<DuckDbSeverityScore> ExtractNvdSeverity(JsonNode? metrics)
    {
        if (metrics is not JsonObject obj) yield break;
        foreach (var (metricName, metricArray) in obj)
        {
            foreach (var item in ArrayItems(metricArray))
            {
                var data = item?["cvssData"];
                var version = data?["version"]?.GetValue<string>();
                var vector = data?["vectorString"]?.GetValue<string>();
                var score = DecimalValue(data?["baseScore"]);
                var label = data?["baseSeverity"]?.GetValue<string>() ?? item?["baseSeverity"]?.GetValue<string>();
                if (version is null && vector is null && score is null && label is null) continue;
                yield return new DuckDbSeverityScore("cvss", version, "base", vector, score, label);
            }
        }
    }

    private static IEnumerable<DuckDbReference> ExtractReferences(JsonNode? references)
    {
        foreach (var item in ArrayItems(references))
        {
            var url = item switch
            {
                JsonValue value => value.TryGetValue<string>(out var text) ? text : null,
                JsonObject obj => obj["url"]?.GetValue<string>() ?? obj["href"]?.GetValue<string>(),
                _ => null
            };
            if (string.IsNullOrWhiteSpace(url)) continue;
            var tags = item is JsonObject objWithTags
                ? ArrayItems(objWithTags["tags"]).Select(x => x?.GetValue<string>()).Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x!).ToArray()
                : [];
            var refType = item is JsonObject objWithType
                ? objWithType["type"]?.GetValue<string>() ?? objWithType["refsource"]?.GetValue<string>()
                : null;
            yield return new DuckDbReference(url, refType, tags);
        }
    }

    private static IEnumerable<DuckDbWeakness> ExtractNvdWeaknesses(JsonNode? weaknesses)
    {
        foreach (var item in ArrayItems(weaknesses))
        {
            foreach (var description in ArrayItems(item?["description"]))
            {
                var value = description?["value"]?.GetValue<string>();
                if (!string.IsNullOrWhiteSpace(value))
                    yield return new DuckDbWeakness("CWE", value, null);
            }
        }
    }

    private static IEnumerable<JsonNode?> WalkCpeMatches(JsonNode? node)
    {
        if (node is null) yield break;
        if (node is JsonArray arr)
        {
            foreach (var item in arr)
            {
                foreach (var nested in WalkCpeMatches(item))
                    yield return nested;
            }
            yield break;
        }

        if (node is not JsonObject obj) yield break;

        if (obj["criteria"] is not null)
            yield return node;
        foreach (var child in ArrayItems(obj["nodes"]))
        {
            foreach (var nested in WalkCpeMatches(child))
                yield return nested;
        }
        foreach (var match in ArrayItems(obj["cpeMatch"]))
            yield return match;
    }

    private static IEnumerable<string> OsvRanges(JsonNode? range)
    {
        string? introduced = null;
        var emitted = false;
        foreach (var item in ArrayItems(range?["events"]))
        {
            var nextIntroduced = item?["introduced"]?.GetValue<string>();
            if (!string.IsNullOrWhiteSpace(nextIntroduced))
            {
                introduced = nextIntroduced;
                continue;
            }

            var fixedVersion = item?["fixed"]?.GetValue<string>();
            var lastAffected = item?["last_affected"]?.GetValue<string>();
            var limit = item?["limit"]?.GetValue<string>();
            var upper = fixedVersion ?? limit ?? lastAffected;
            if (string.IsNullOrWhiteSpace(upper)) continue;

            var upperOperator = lastAffected is null ? "<" : "<=";
            emitted = true;
            yield return string.IsNullOrWhiteSpace(introduced)
                ? $"{upperOperator} {upper}"
                : $">= {introduced}, {upperOperator} {upper}";
            introduced = null;
        }

        if (!string.IsNullOrWhiteSpace(introduced))
        {
            emitted = true;
            yield return $">= {introduced}";
        }
        if (!emitted && range is not null)
            yield return range.ToJsonString();
    }

    private static string? CpeRange(JsonNode? cpeMatch)
    {
        var parts = new List<string>();
        AddCpeRangePart(parts, ">=", cpeMatch?["versionStartIncluding"]?.GetValue<string>());
        AddCpeRangePart(parts, ">", cpeMatch?["versionStartExcluding"]?.GetValue<string>());
        AddCpeRangePart(parts, "<=", cpeMatch?["versionEndIncluding"]?.GetValue<string>());
        AddCpeRangePart(parts, "<", cpeMatch?["versionEndExcluding"]?.GetValue<string>());
        return parts.Count == 0 ? null : string.Join(", ", parts);
    }

    private static void AddCpeRangePart(List<string> parts, string op, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value)) parts.Add($"{op} {value}");
    }

    private static IEnumerable<JsonNode?> ArrayItems(JsonNode? node)
    {
        if (node is not JsonArray array) yield break;
        foreach (var item in array) yield return item;
    }

    private static decimal? DecimalValue(JsonNode? node)
    {
        if (node is null) return null;
        try { return node.GetValue<decimal>(); }
        catch { return null; }
    }

    private static string? CvssVersion(string? vector)
    {
        if (string.IsNullOrWhiteSpace(vector) || !vector.StartsWith("CVSS:", StringComparison.OrdinalIgnoreCase)) return null;
        var slash = vector.IndexOf('/');
        return slash > "CVSS:".Length ? vector["CVSS:".Length..slash] : null;
    }

    private static string? CvssVersionFromType(string? type) =>
        type?.ToUpperInvariant() switch
        {
            "CVSS_V4" or "CVSS_V4_0" => "4.0",
            "CVSS_V3" or "CVSS_V3_1" => "3.1",
            "CVSS_V3_0" => "3.0",
            "CVSS_V2" => "2.0",
            _ => null
        };

    private static string SeverityFromScore(decimal score, string? version = null) =>
        version?.StartsWith("2", StringComparison.Ordinal) == true
            ? score switch
            {
                >= 7.0m => "HIGH",
                >= 4.0m => "MEDIUM",
                _ => "LOW"
            }
            : score switch
            {
                >= 9.0m => "CRITICAL",
                >= 7.0m => "HIGH",
                >= 4.0m => "MEDIUM",
                > 0m => "LOW",
                _ => "NONE"
            };

    private static string DebianEcosystem(string release) => release.ToLowerInvariant() switch
    {
        "etch" => "debian:4",
        "lenny" => "debian:5",
        "squeeze" => "debian:6",
        "wheezy" => "debian:7",
        "jessie" => "debian:8",
        "stretch" => "debian:9",
        "buster" => "debian:10",
        "bullseye" => "debian:11",
        "bookworm" => "debian:12",
        "trixie" => "debian:13",
        "forky" => "debian:14",
        var value => $"debian:{value}"
    };

    private static string? ToPurl(string? ecosystem, string? packageName)
    {
        if (string.IsNullOrWhiteSpace(ecosystem) || string.IsNullOrWhiteSpace(packageName)) return null;
        return ecosystem.ToLowerInvariant() switch
        {
            "npm" => $"pkg:npm/{Uri.EscapeDataString(packageName)}",
            "pip" or "pypi" => $"pkg:pypi/{Uri.EscapeDataString(packageName.ToLowerInvariant())}",
            "maven" when packageName.Contains(':') => $"pkg:maven/{Uri.EscapeDataString(packageName.Split(':')[0])}/{Uri.EscapeDataString(packageName.Split(':')[1])}",
            "nuget" => $"pkg:nuget/{Uri.EscapeDataString(packageName)}",
            "go" => $"pkg:golang/{packageName}",
            "alpine" => $"pkg:apk/alpine/{Uri.EscapeDataString(packageName)}",
            _ => null
        };
    }

    private static string? ParseCpeProduct(string cpe23Uri)
    {
        var parts = cpe23Uri.Split(':');
        return parts.Length > 4 ? parts[4].Replace("\\:", ":") : null;
    }

    private static DuckDbEvidenceRecord EmptyRecord(string sourceCode, Guid rawIndexId, string vulnerabilityKey, string sourceRecordId) =>
        new(sourceCode, rawIndexId, vulnerabilityKey, sourceRecordId, [], [], [], []);

    private static string? StringValue(JsonNode? node)
    {
        if (node is null || node.GetValueKind() == System.Text.Json.JsonValueKind.Null) return null;
        return node.GetValueKind() == System.Text.Json.JsonValueKind.String ? node.GetValue<string>() : node.ToJsonString();
    }
}
