using System.Text.Json.Nodes;
using Npgsql;

namespace VulTrack.App;

public sealed class CveListRawNormalizer(IEnumerable<IAffectedComponentHook> affectedHooks, IVulnerabilityCanonicalizer canonicalizer)
    : NormalizerBase(affectedHooks, canonicalizer), IRawNormalizer
{
    public string SourceCode => "cve-list-v5";

    public async Task<NormalizeBatchResult> ProcessPendingAsync(NpgsqlConnection connection, int limit, CancellationToken ct)
    {
        await using var select = new NpgsqlCommand("""
            select s.raw_index_id, s.cve_id, s.cve_metadata, s.containers_cna, s.containers_adp,
                   s.state, s.published_at, s.updated_at, s.payload, r.source_id
            from stg_cve_list_records s
            join source_raw_index r on r.id = s.raw_index_id
            join sources src on src.id = r.source_id
            where r.normalize_status <> 'succeeded' and src.code = 'cve-list-v5'
            order by s.updated_at nulls last, s.cve_id
            limit $1
            """, connection);
        select.Parameters.AddWithValue(Math.Max(1, limit));

        var rows = new List<Row>();
        await using (var reader = await select.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            {
                rows.Add(new Row(
                    reader.GetGuid(0),
                    reader.GetString(1),
                    reader.GetString(2),
                    reader.GetString(3),
                    reader.GetString(4),
                    reader.IsDBNull(5) ? null : reader.GetString(5),
                    reader.IsDBNull(6) ? null : reader.GetFieldValue<DateTimeOffset>(6),
                    reader.IsDBNull(7) ? null : reader.GetFieldValue<DateTimeOffset>(7),
                    reader.GetString(8),
                    reader.GetGuid(9)));
            }
        }

        var processed = 0;
        var failed = 0;
        foreach (var row in rows)
        {
            try
            {
                var cna = JsonNode.Parse(row.ContainersCna);
                var identifiers = IdentifiersFrom([row.CveId]);
                var title = EnglishDescription(cna?["descriptions"]) ?? row.CveId;
                var status = string.Equals(row.State, "REJECTED", StringComparison.OrdinalIgnoreCase) ? "rejected" : "active";
                var vulnerabilityId = await UpsertVulnerabilityAsync(connection, row.SourceId, row.RawIndexId, row.CveId, title, title, status, row.PublishedAt, row.UpdatedAt, identifiers, ct);
                var recordId = await UpsertRecordAsync(connection, vulnerabilityId, row.SourceId, row.RawIndexId, row.CveId, title, title, status, row.Payload, ct);
                await UpsertDescriptionsAsync(connection, vulnerabilityId, recordId, row.SourceId, cna?["descriptions"], ct);
                await UpsertReferencesAsync(connection, vulnerabilityId, recordId, row.SourceId, cna?["references"], ct);
                var facts = ExtractAffectedFacts(cna).ToList();
                await InsertAffectedFactsAsync(connection, vulnerabilityId, recordId, row.SourceId, row.RawIndexId, facts, ct);
                await MarkNormalizedAsync(connection, row.RawIndexId, ct);
                processed++;
            }
            catch
            {
                failed++;
            }
        }

        return new NormalizeBatchResult(SourceCode, processed, failed);
    }

    private static string? EnglishDescription(JsonNode? descriptions) =>
        descriptions?.AsArray().FirstOrDefault(x => string.Equals(x?["lang"]?.GetValue<string>(), "en", StringComparison.OrdinalIgnoreCase))?["value"]?.GetValue<string>()
        ?? descriptions?.AsArray().FirstOrDefault()?["value"]?.GetValue<string>();

    private static async Task UpsertDescriptionsAsync(NpgsqlConnection connection, Guid vulnerabilityId, Guid recordId, Guid sourceId, JsonNode? descriptions, CancellationToken ct)
    {
        foreach (var desc in descriptions?.AsArray() ?? [])
        {
            var value = desc?["value"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(value)) continue;
            await using var cmd = new NpgsqlCommand("""
                insert into vulnerability_descriptions
                  (vulnerability_id, vulnerability_record_id, source_id, lang, description_type, value, is_selected)
                values ($1,$2,$3,$4,'detail',$5,$6)
                """, connection);
            cmd.Parameters.AddWithValue(vulnerabilityId);
            cmd.Parameters.AddWithValue(recordId);
            cmd.Parameters.AddWithValue(sourceId);
            cmd.Parameters.AddWithValue(desc?["lang"]?.GetValue<string>() ?? "und");
            cmd.Parameters.AddWithValue(value);
            cmd.Parameters.AddWithValue(string.Equals(desc?["lang"]?.GetValue<string>(), "en", StringComparison.OrdinalIgnoreCase));
            await cmd.ExecuteNonQueryAsync(ct);
        }
    }

    private static async Task UpsertReferencesAsync(NpgsqlConnection connection, Guid vulnerabilityId, Guid recordId, Guid sourceId, JsonNode? references, CancellationToken ct)
    {
        foreach (var reference in references?.AsArray() ?? [])
        {
            var url = reference?["url"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(url)) continue;
            await using var cmd = new NpgsqlCommand("""
                insert into vulnerability_references
                  (vulnerability_id, vulnerability_record_id, source_id, url, normalized_url, tags)
                values ($1,$2,$3,$4,lower($4),$5)
                """, connection);
            cmd.Parameters.AddWithValue(vulnerabilityId);
            cmd.Parameters.AddWithValue(recordId);
            cmd.Parameters.AddWithValue(sourceId);
            cmd.Parameters.AddWithValue(url);
            cmd.Parameters.AddWithValue(reference?["tags"]?.AsArray().Select(x => x?.GetValue<string>()).Where(x => !string.IsNullOrWhiteSpace(x)).ToArray() ?? []);
            await cmd.ExecuteNonQueryAsync(ct);
        }
    }

    private static IEnumerable<AffectedFactDraft> ExtractAffectedFacts(JsonNode? cna)
    {
        foreach (var affected in cna?["affected"]?.AsArray() ?? [])
        {
            var vendor = affected?["vendor"]?.GetValue<string>();
            var product = affected?["product"]?.GetValue<string>();
            var name = string.Join(':', new[] { vendor, product }.Where(x => !string.IsNullOrWhiteSpace(x)));
            if (string.IsNullOrWhiteSpace(name)) continue;
            foreach (var version in affected?["versions"]?.AsArray() ?? [])
            {
                var status = version?["status"]?.GetValue<string>();
                var vulnerable = string.Equals(status, "affected", StringComparison.OrdinalIgnoreCase);
                if (!vulnerable) continue;
                var rawRange = version?["lessThan"]?.GetValue<string>() is { } lessThan
                    ? $"< {lessThan}"
                    : version?["version"]?.GetValue<string>();
                yield return new AffectedFactDraft("package", null, name, null, rawRange, "cve-list", version?.ToJsonString() ?? "{}");
            }
        }
    }

    private sealed record Row(Guid RawIndexId, string CveId, string CveMetadata, string ContainersCna, string ContainersAdp, string? State, DateTimeOffset? PublishedAt, DateTimeOffset? UpdatedAt, string Payload, Guid SourceId);
}
