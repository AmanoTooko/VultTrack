using System.Text.Json.Nodes;

namespace VulTrack.App;

internal static class OsvIdentifierExtractor
{
    public static string[] Extract(string osvId, IEnumerable<string?> aliases, JsonNode? payload)
    {
        var values = new List<string?>();
        values.Add(osvId);
        values.AddRange(aliases);

        if (payload is not null)
        {
            CollectSemanticIdentifiers(payload, selected: false, values);
        }

        return values
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .SelectMany(value => Identifier.ExpandWithEmbeddedCves(value!))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static string Preferred(string osvId, IEnumerable<string?> aliases, JsonNode? payload)
    {
        var identifiers = Extract(osvId, aliases, payload);
        return identifiers.FirstOrDefault(value => value.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase))
            ?? identifiers.FirstOrDefault()
            ?? osvId;
    }

    private static void CollectSemanticIdentifiers(JsonNode node, bool selected, List<string?> values)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (var (name, value) in obj)
                {
                    if (value is null) continue;
                    var childSelected = selected || IsIdentifierProperty(name);
                    CollectSemanticIdentifiers(value, childSelected, values);
                }
                break;
            case JsonArray array:
                foreach (var item in array)
                {
                    if (item is not null)
                        CollectSemanticIdentifiers(item, selected, values);
                }
                break;
            case JsonValue value when selected && value.TryGetValue<string>(out var text):
                values.Add(text);
                break;
        }
    }

    private static bool IsIdentifierProperty(string name)
    {
        var lower = name.ToLowerInvariant();
        return lower.Contains("alias", StringComparison.Ordinal)
            || lower.Contains("upstream", StringComparison.Ordinal)
            || lower.Contains("related", StringComparison.Ordinal)
            || lower.Contains("cve", StringComparison.Ordinal);
    }
}
