using System.Text.Json.Nodes;
using Npgsql;

namespace VulTrack.App;

public sealed class GhsaRawNormalizer(IEnumerable<IAffectedComponentHook> affectedHooks, IVulnerabilityCanonicalizer canonicalizer)
    : NormalizerBase(affectedHooks, canonicalizer), IRawNormalizer
{
    public string SourceCode => "ghsa-family";

    private static readonly (string Table, string SourceCode)[] Tables =
    [
        ("stg_ghsa_advisories", "ghsa"),
        ("stg_npm_advisories", "npm-advisory"),
        ("stg_npm_advisories", "npm-audit")
    ];

    public async Task<NormalizeBatchResult> ProcessPendingAsync(NpgsqlConnection connection, int limit, CancellationToken ct)
    {
        var processed = 0;
        var failed = 0;

        foreach (var (table, sourceCode) in Tables)
        {
            await using var select = new NpgsqlCommand($"""
                select s.raw_index_id, s.ghsa_id, s.cve_id, s.summary, s.description,
                       s.ecosystem, s.package_name, s.vulnerable_ranges, s.payload, r.source_id
                from {table} s
                join source_raw_index r on r.id = s.raw_index_id
                join sources src on src.id = r.source_id
                where r.normalize_status <> 'succeeded' and src.code = $1
                order by r.updated_at
                limit $2
                """, connection);
            select.Parameters.AddWithValue(sourceCode);
            select.Parameters.AddWithValue(Math.Max(1, limit - processed));

            var rows = new List<Row>();
            await using (var reader = await select.ExecuteReaderAsync(ct))
            {
                while (await reader.ReadAsync(ct))
                {
                    rows.Add(new Row(
                        reader.GetGuid(0),
                        reader.GetString(1),
                        reader.IsDBNull(2) ? null : reader.GetString(2),
                        reader.IsDBNull(3) ? null : reader.GetString(3),
                        reader.IsDBNull(4) ? null : reader.GetString(4),
                        reader.IsDBNull(5) ? null : reader.GetString(5),
                        reader.IsDBNull(6) ? null : reader.GetString(6),
                        reader.GetString(7),
                        reader.GetString(8),
                        reader.GetGuid(9)));
                }
            }

            foreach (var row in rows)
            {
                try
                {
                    var identifiers = IdentifiersFrom([row.GhsaId, row.CveId]);
                    var primary = row.CveId ?? row.GhsaId;
                    var vulnerabilityId = await UpsertVulnerabilityAsync(connection, row.SourceId, row.RawIndexId, primary, row.Summary, row.Description ?? row.Summary, "active", DateValue(JsonNode.Parse(row.Payload), "published_at"), DateValue(JsonNode.Parse(row.Payload), "updated_at"), identifiers, ct);
                    var recordId = await UpsertRecordAsync(connection, vulnerabilityId, row.SourceId, row.RawIndexId, row.GhsaId, row.Summary, row.Description, "active", row.Payload, ct);
                    await UpsertIdentifiersAsync(connection, vulnerabilityId, row.SourceId, row.RawIndexId, identifiers, ct);
                    var facts = ExtractAffectedFacts(row).ToList();
                    await InsertAffectedFactsAsync(connection, vulnerabilityId, recordId, row.SourceId, row.RawIndexId, facts, ct);
                    await MarkNormalizedAsync(connection, row.RawIndexId, ct);
                    processed++;
                }
                catch
                {
                    failed++;
                }
            }

            if (processed >= limit) break;
        }

        return new NormalizeBatchResult(SourceCode, processed, failed);
    }

    private static IEnumerable<AffectedFactDraft> ExtractAffectedFacts(Row row)
    {
        var ranges = JsonNode.Parse(row.VulnerableRanges)?.AsArray().Select(x => x?.GetValue<string>()).Where(x => !string.IsNullOrWhiteSpace(x)).ToArray() ?? [];
        if (string.IsNullOrWhiteSpace(row.PackageName))
        {
            yield break;
        }

        var purl = ToPurl(row.Ecosystem, row.PackageName);
        if (ranges.Length == 0)
        {
            yield return new AffectedFactDraft("package", row.Ecosystem, row.PackageName, purl, null, "vendor", row.Payload);
            yield break;
        }

        foreach (var range in ranges)
        {
            yield return new AffectedFactDraft("package", row.Ecosystem, row.PackageName, purl, range, "vendor", row.Payload);
        }
    }

    private static string? ToPurl(string? ecosystem, string? packageName)
    {
        if (string.IsNullOrWhiteSpace(ecosystem) || string.IsNullOrWhiteSpace(packageName)) return null;
        return ecosystem.ToLowerInvariant() switch
        {
            "npm" => $"pkg:npm/{Uri.EscapeDataString(packageName)}",
            "pip" or "pypi" => $"pkg:pypi/{Uri.EscapeDataString(packageName.ToLowerInvariant())}",
            "maven" when packageName.Contains(':') => $"pkg:maven/{Uri.EscapeDataString(packageName.Split(':')[0])}/{Uri.EscapeDataString(packageName.Split(':')[1])}",
            "nuget" => $"pkg:nuget/{Uri.EscapeDataString(packageName)}",
            _ => null
        };
    }

    private sealed record Row(Guid RawIndexId, string GhsaId, string? CveId, string? Summary, string? Description, string? Ecosystem, string? PackageName, string VulnerableRanges, string Payload, Guid SourceId);
}
