using System.Text.Json.Nodes;
using Npgsql;

namespace VulTrack.App;

public sealed class EcosystemAdvisoryNormalizer(IEnumerable<IAffectedComponentHook> affectedHooks, IVulnerabilityCanonicalizer canonicalizer)
    : NormalizerBase(affectedHooks, canonicalizer), ISourceScopedRawNormalizer
{
    public string SourceCode => "ecosystem-advisories";
    public IReadOnlySet<string> SupportedSourceCodes { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "maven-advisory",
        "nuget-advisory",
        "redhat-csaf",
        "suse-csaf"
    };

    public async Task<NormalizeBatchResult> ProcessPendingAsync(NpgsqlConnection connection, int limit, CancellationToken ct)
        => await ProcessSourcePendingCoreAsync(connection, null, limit, ct);

    public async Task<NormalizeBatchResult> ProcessSourcePendingAsync(NpgsqlConnection connection, string sourceCode, int limit, CancellationToken ct)
        => await ProcessSourcePendingCoreAsync(connection, sourceCode, limit, ct);

    private async Task<NormalizeBatchResult> ProcessSourcePendingCoreAsync(NpgsqlConnection connection, string? sourceCode, int limit, CancellationToken ct)
    {
        await using var select = new NpgsqlCommand("""
            select s.raw_index_id, s.provider, s.ecosystem, s.advisory_id, s.identifiers,
                   s.package_name, s.purl, s.vulnerable_ranges, s.severity_label, s.published_at,
                   s.modified_at, s.references_json, s.payload, r.source_id
            from stg_ecosystem_advisories s
            join source_raw_index r on r.id = s.raw_index_id
            join sources src on src.id = r.source_id
            where r.normalize_status <> 'succeeded'
              and ($1::text is null or src.code = $1)
            order by r.updated_at
            limit $2
            """, connection);
        select.Parameters.AddWithValue((object?)sourceCode ?? DBNull.Value);
        select.Parameters.AddWithValue(limit);

        var rows = new List<Row>();
        await using (var reader = await select.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            {
                rows.Add(new Row(
                    reader.GetGuid(0),
                    reader.GetString(1),
                    reader.IsDBNull(2) ? null : reader.GetString(2),
                    reader.GetString(3),
                    reader.GetFieldValue<string[]>(4),
                    reader.IsDBNull(5) ? null : reader.GetString(5),
                    reader.IsDBNull(6) ? null : reader.GetString(6),
                    reader.GetString(7),
                    reader.IsDBNull(8) ? null : reader.GetString(8),
                    reader.IsDBNull(9) ? null : reader.GetFieldValue<DateTimeOffset>(9),
                    reader.IsDBNull(10) ? null : reader.GetFieldValue<DateTimeOffset>(10),
                    reader.GetString(11),
                    reader.GetString(12),
                    reader.GetGuid(13)));
            }
        }

        var processed = 0;
        var failed = 0;
        foreach (var row in rows)
        {
            try
            {
                var identifiers = IdentifiersFrom([row.AdvisoryId], row.Identifiers);
                var primary = identifiers.FirstOrDefault(x => x.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)) ?? row.AdvisoryId;
                var payload = JsonNode.Parse(row.Payload);
                var title = payload?["vulnerability"]?["summary"]?.GetValue<string>() ?? row.AdvisoryId;
                var vulnerabilityId = await UpsertVulnerabilityAsync(connection, row.SourceId, row.RawIndexId, primary, title, title, "active", row.PublishedAt, row.ModifiedAt, identifiers, ct);
                var recordId = await UpsertRecordAsync(connection, vulnerabilityId, row.SourceId, row.RawIndexId, row.AdvisoryId, title, title, "active", row.Payload, ct);
                await UpsertIdentifiersAsync(connection, vulnerabilityId, row.SourceId, row.RawIndexId, identifiers, ct);
                await InsertDescriptionsAsync(connection, vulnerabilityId, recordId, row.SourceId, SourceFactExtractor.Descriptions(title, payload?["vulnerability"]?["details"]?.GetValue<string>()), ct);
                var severities = SourceFactExtractor.CvssSeverities(payload?["cvss"]).Concat(SourceFactExtractor.LabelSeverity(row.SeverityLabel, row.Payload)).ToList();
                await InsertSeverityScoresAsync(connection, vulnerabilityId, recordId, row.SourceId, row.RawIndexId, severities, ct);
                await InsertReferencesAsync(connection, vulnerabilityId, recordId, row.SourceId, SourceFactExtractor.References(JsonNode.Parse(row.ReferencesJson)), ct);
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

        return new NormalizeBatchResult(sourceCode ?? SourceCode, processed, failed);
    }

    private static IEnumerable<AffectedFactDraft> ExtractAffectedFacts(Row row)
    {
        if (string.IsNullOrWhiteSpace(row.PackageName) && string.IsNullOrWhiteSpace(row.Purl)) yield break;
        var ranges = JsonNode.Parse(row.VulnerableRanges)?.AsArray().Select(x => x?.GetValue<string>()).Where(x => !string.IsNullOrWhiteSpace(x)).ToArray() ?? [];
        if (ranges.Length == 0)
        {
            yield return new AffectedFactDraft("package", row.Ecosystem, row.PackageName, row.Purl, null, "vendor", row.Payload);
            yield break;
        }
        foreach (var range in ranges)
        {
            yield return new AffectedFactDraft("package", row.Ecosystem, row.PackageName, row.Purl, range, "vendor", row.Payload);
        }
    }

    private sealed record Row(Guid RawIndexId, string Provider, string? Ecosystem, string AdvisoryId, string[] Identifiers, string? PackageName, string? Purl, string VulnerableRanges, string? SeverityLabel, DateTimeOffset? PublishedAt, DateTimeOffset? ModifiedAt, string ReferencesJson, string Payload, Guid SourceId);
}
