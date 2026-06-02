using System.Text.Json.Nodes;

namespace VulTrack.App;

public static class SourceFactExtractor
{
    public static IReadOnlyList<DescriptionDraft> Descriptions(string? summary, string? details)
    {
        var rows = new List<DescriptionDraft>();
        if (!string.IsNullOrWhiteSpace(summary))
        {
            rows.Add(new DescriptionDraft("en", "summary", summary, true));
        }

        if (!string.IsNullOrWhiteSpace(details) && !string.Equals(summary, details, StringComparison.Ordinal))
        {
            rows.Add(new DescriptionDraft("en", "detail", details, rows.Count == 0));
        }

        return rows;
    }

    public static IReadOnlyList<ReferenceDraft> References(JsonNode? references)
    {
        var rows = new List<ReferenceDraft>();
        foreach (var item in references?.AsArray() ?? [])
        {
            var url = item switch
            {
                JsonValue value => value.TryGetValue<string>(out var text) ? text : null,
                _ => item?["url"]?.GetValue<string>() ?? item?["href"]?.GetValue<string>()
            };
            if (string.IsNullOrWhiteSpace(url)) continue;

            var obj = item as JsonObject;
            var type = obj?["type"]?.GetValue<string>() ?? obj?["refsource"]?.GetValue<string>();
            var tags = obj?["tags"]?.AsArray().Select(x => x?.GetValue<string>() ?? "").Where(x => !string.IsNullOrWhiteSpace(x)).ToArray()
                ?? [];
            rows.Add(new ReferenceDraft(url, type, tags));
        }

        return rows;
    }

    public static IReadOnlyList<SeverityScoreDraft> OsvSeverities(JsonNode? severities)
    {
        var rows = new List<SeverityScoreDraft>();
        foreach (var item in severities?.AsArray() ?? [])
        {
            var type = item?["type"]?.GetValue<string>() ?? "vendor";
            var scoreText = item?["score"]?.GetValue<string>();
            var versionFromType = VersionFromType(type);
            var calculatedScore = CvssScoreCalculator.CalculateBaseScore(scoreText, versionFromType);
            var vector = scoreText?.StartsWith("CVSS:", StringComparison.OrdinalIgnoreCase) == true || calculatedScore is not null
                ? scoreText
                : null;
            var numeric = DecimalValue(item?["score"]);
            var score = numeric ?? calculatedScore;
            var version = CvssVersion(vector) ?? versionFromType;
            rows.Add(new SeverityScoreDraft(
                type.StartsWith("CVSS", StringComparison.OrdinalIgnoreCase) ? "cvss" : type.ToLowerInvariant(),
                version,
                "base",
                vector,
                score,
                score is null ? null : SeverityFromScore(score.Value, version),
                item?.ToJsonString() ?? "{}"));
        }

        return rows;
    }

    public static IReadOnlyList<SeverityScoreDraft> CvssSeverities(JsonNode? cvss)
    {
        var rows = new List<SeverityScoreDraft>();
        foreach (var item in WalkObjects(cvss))
        {
            var vector = StringValue(item["vectorString"]) ?? StringValue(item["vector_string"]);
            var version = CvssVersion(vector) ?? StringValue(item["version"]);
            var score = DecimalValue(item["score"]) ??
                DecimalValue(item["baseScore"]) ??
                DecimalValue(item["base_score"]) ??
                CvssScoreCalculator.CalculateBaseScore(vector, version);
            var label = StringValue(item["severity"]) ??
                StringValue(item["baseSeverity"]) ??
                (score is null ? null : SeverityFromScore(score.Value, version));

            if (vector is null && score is null && label is null) continue;

            rows.Add(new SeverityScoreDraft(
                "cvss",
                version,
                "base",
                vector,
                score,
                label,
                item.ToJsonString()));
        }

        return rows;
    }

    public static IReadOnlyList<SeverityScoreDraft> LabelSeverity(string? label, string payloadJson)
    {
        if (string.IsNullOrWhiteSpace(label)) return [];
        return
        [
            new SeverityScoreDraft(
                "vendor",
                null,
                "advisory",
                null,
                null,
                label,
                payloadJson)
        ];
    }

    public static IReadOnlyList<WeaknessDraft> Weaknesses(JsonNode? cwes)
    {
        var rows = new List<WeaknessDraft>();
        foreach (var item in cwes?.AsArray() ?? [])
        {
            if (item is JsonValue value && value.TryGetValue<string>(out var text))
            {
                rows.Add(new WeaknessDraft("CWE", text, text));
                continue;
            }

            var id = item?["cwe_id"]?.GetValue<string>() ?? item?["id"]?.GetValue<string>() ?? item?["value"]?.GetValue<string>();
            var name = item?["name"]?.GetValue<string>() ?? item?["description"]?.GetValue<string>();
            rows.Add(new WeaknessDraft("CWE", id, name ?? id));
        }

        return rows;
    }

    private static IEnumerable<JsonObject> WalkObjects(JsonNode? node)
    {
        if (node is JsonObject obj)
        {
            yield return obj;
            foreach (var child in obj.Select(x => x.Value))
            {
                foreach (var nested in WalkObjects(child)) yield return nested;
            }
        }
        else if (node is JsonArray array)
        {
            foreach (var child in array)
            {
                foreach (var nested in WalkObjects(child)) yield return nested;
            }
        }
    }

    private static string? StringValue(JsonNode? node)
    {
        if (node is null || node.GetValueKind() == System.Text.Json.JsonValueKind.Null) return null;
        return node.GetValueKind() == System.Text.Json.JsonValueKind.String ? node.GetValue<string>() : node.ToJsonString();
    }

    private static decimal? DecimalValue(JsonNode? node)
    {
        if (node is null) return null;
        if (node.GetValueKind() == System.Text.Json.JsonValueKind.Null) return null;
        if (node.GetValueKind() == System.Text.Json.JsonValueKind.Number && node.AsValue().TryGetValue<decimal>(out var number)) return number;
        return decimal.TryParse(node.GetValue<string>(), out var parsed) ? parsed : null;
    }

    private static string? CvssVersion(string? vector)
    {
        if (string.IsNullOrWhiteSpace(vector) || !vector.StartsWith("CVSS:", StringComparison.OrdinalIgnoreCase)) return null;
        var slash = vector.IndexOf('/');
        return slash > "CVSS:".Length ? vector["CVSS:".Length..slash] : null;
    }

    private static string? VersionFromType(string? type) =>
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
}
