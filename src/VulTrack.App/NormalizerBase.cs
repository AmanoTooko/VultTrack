using System.Text.Json.Nodes;
using Npgsql;

namespace VulTrack.App;

public abstract class NormalizerBase(
    IEnumerable<IAffectedComponentHook> affectedHooks,
    IVulnerabilityCanonicalizer canonicalizer)
{
    protected Task<Guid> UpsertVulnerabilityAsync(NpgsqlConnection connection, Guid sourceId, Guid rawIndexId, string primaryIdentifier, string? title, string? description, string? status, DateTimeOffset? publishedAt, DateTimeOffset? modifiedAt, string[] identifiers, CancellationToken ct) =>
        canonicalizer.UpsertCanonicalAsync(
            connection,
            new VulnerabilityCanonicalDraft(primaryIdentifier, title, description, status, publishedAt, modifiedAt, identifiers, sourceId, rawIndexId),
            ct);

    protected async Task<Guid> UpsertRecordAsync(NpgsqlConnection connection, Guid vulnerabilityId, Guid sourceId, Guid rawIndexId, string sourceRecordId, string? title, string? description, string? status, string payloadJson, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("""
            insert into vulnerability_records
              (vulnerability_id, source_id, raw_index_id, source_record_id, title, description, status, source_specific)
            values ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)
            on conflict (source_id, source_record_id, raw_index_id) do update set
              vulnerability_id = excluded.vulnerability_id,
              title = excluded.title,
              description = excluded.description,
              status = excluded.status,
              source_specific = excluded.source_specific,
              updated_at = now()
            returning id
            """, connection);
        cmd.Parameters.AddWithValue(vulnerabilityId);
        cmd.Parameters.AddWithValue(sourceId);
        cmd.Parameters.AddWithValue(rawIndexId);
        cmd.Parameters.AddWithValue(sourceRecordId);
        cmd.Parameters.AddWithValue((object?)title ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)description ?? DBNull.Value);
        cmd.Parameters.AddWithValue(status ?? "active");
        cmd.Parameters.AddWithValue(payloadJson);
        return (Guid)(await cmd.ExecuteScalarAsync(ct))!;
    }

    protected static Task UpsertIdentifiersAsync(NpgsqlConnection connection, Guid vulnerabilityId, Guid sourceId, Guid rawIndexId, IEnumerable<string> identifiers, CancellationToken ct) =>
        Task.CompletedTask;

    protected async Task InsertAffectedFactsAsync(NpgsqlConnection connection, Guid vulnerabilityId, Guid recordId, Guid sourceId, Guid rawIndexId, IReadOnlyList<AffectedFactDraft> facts, CancellationToken ct)
    {
        foreach (var fact in facts)
        {
            await using var cmd = new NpgsqlCommand("""
                insert into vulnerability_affected_facts
                  (vulnerability_id, vulnerability_record_id, source_id, raw_index_id, fact_type, ecosystem,
                   package_name, normalized_package_name, purl, purl_without_version, version_range_raw,
                   range_type, vulnerable, source_specific)
                values ($1,$2,$3,$4,$5,$6,$7,lower($7),$8,$9,$10,$11,true,$12::jsonb)
                """, connection);
            cmd.Parameters.AddWithValue(vulnerabilityId);
            cmd.Parameters.AddWithValue(recordId);
            cmd.Parameters.AddWithValue(sourceId);
            cmd.Parameters.AddWithValue(rawIndexId);
            cmd.Parameters.AddWithValue(fact.FactType);
            cmd.Parameters.AddWithValue((object?)fact.Ecosystem ?? DBNull.Value);
            cmd.Parameters.AddWithValue((object?)fact.PackageName ?? DBNull.Value);
            cmd.Parameters.AddWithValue((object?)fact.Purl ?? DBNull.Value);
            cmd.Parameters.AddWithValue((object?)PurlWithoutVersion(fact.Purl) ?? DBNull.Value);
            cmd.Parameters.AddWithValue((object?)fact.VersionRange ?? DBNull.Value);
            cmd.Parameters.AddWithValue((object?)fact.RangeType ?? DBNull.Value);
            cmd.Parameters.AddWithValue(fact.SourceSpecificJson);
            await cmd.ExecuteNonQueryAsync(ct);
        }

        foreach (var hook in affectedHooks)
        {
            await hook.OnAffectedFactsAsync(connection, vulnerabilityId, recordId, facts, ct);
        }
    }

    protected static async Task MarkNormalizedAsync(NpgsqlConnection connection, Guid rawIndexId, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("update source_raw_index set normalize_status = 'succeeded', updated_at = now() where id = $1", connection);
        cmd.Parameters.AddWithValue(rawIndexId);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    protected static string[] IdentifiersFrom(params IEnumerable<string?>[] groups) =>
        groups.SelectMany(x => x).Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x!).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

    protected static DateTimeOffset? DateValue(JsonNode? node, string name)
    {
        var value = node?[name]?.GetValue<string>();
        return DateTimeOffset.TryParse(value, out var parsed) ? parsed : null;
    }

    private static string? PurlWithoutVersion(string? purl)
    {
        if (string.IsNullOrWhiteSpace(purl)) return null;
        var at = purl.LastIndexOf('@');
        return at > "pkg:".Length ? purl[..at] : purl;
    }
}
