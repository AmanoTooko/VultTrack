using System.Text.Json.Nodes;

namespace VulTrack.App;

internal static class OsvIdentifierExtractor
{
    public static string[] Extract(string osvId, IEnumerable<string?> aliases, JsonNode? payload)
    {
        _ = payload;
        return Normalize(aliases.Prepend(osvId));
    }

    public static string[] ExtractUpstream(JsonNode? payload)
    {
        if (payload is not JsonObject obj) return [];

        var values = new List<string?>();
        CollectStringValues(Property(obj, "upstream"), values);
        if (Property(obj, "database_specific") is JsonObject databaseSpecific)
        {
            CollectStringValues(Property(databaseSpecific, "upstream"), values);
            CollectStringValues(Property(databaseSpecific, "upstream_ids"), values);
        }
        return Normalize(values);
    }

    public static string[] ExtractRelated(JsonNode? payload)
    {
        if (payload is not JsonObject obj) return [];
        var values = new List<string?>();
        CollectStringValues(Property(obj, "related"), values);
        return Normalize(values);
    }

    private static string[] Normalize(IEnumerable<string?> values) => values
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => Identifier.Normalize(value!))
            .Where(Identifier.IsVulnerabilityId)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    public static string Preferred(string osvId, IEnumerable<string?> aliases, JsonNode? payload)
    {
        var identifiers = Extract(osvId, aliases, payload);
        return identifiers.FirstOrDefault(value => value.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase))
            ?? identifiers.FirstOrDefault()
            ?? osvId;
    }

    private static void CollectStringValues(JsonNode? node, List<string?> values)
    {
        switch (node)
        {
            case JsonArray array:
                foreach (var item in array)
                    CollectStringValues(item, values);
                break;
            case JsonValue value when value.TryGetValue<string>(out var text):
                values.Add(text);
                break;
            case JsonObject obj:
                foreach (var name in new[] { "id", "value" })
                    CollectStringValues(Property(obj, name), values);
                break;
        }
    }

    private static JsonNode? Property(JsonObject obj, string name) =>
        obj.FirstOrDefault(pair => pair.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;
}
