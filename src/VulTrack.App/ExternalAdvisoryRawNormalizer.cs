using System.Text.Json.Nodes;
using Npgsql;

namespace VulTrack.App;

public sealed class ExternalAdvisoryRawNormalizer(
    IEnumerable<IAffectedComponentHook> affectedHooks,
    IVulnerabilityCanonicalizer canonicalizer,
    ILogger<ExternalAdvisoryRawNormalizer> logger)
    : NormalizerBase(affectedHooks, canonicalizer), ISourceScopedRawNormalizer
{
    public string SourceCode => "china-advisory";
    public IReadOnlySet<string> SupportedSourceCodes { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "cnnvd",
        "cnvd",
        "seebug",
        "aliyun-avd",
        "nsfocus-vulndb",
        "chaitin-vuldb",
        "cert-360"
    };

    public async Task<NormalizeBatchResult> ProcessPendingAsync(NpgsqlConnection connection, int limit, CancellationToken ct)
        => await ProcessSourcePendingCoreAsync(connection, null, limit, ct);

    public async Task<NormalizeBatchResult> ProcessSourcePendingAsync(NpgsqlConnection connection, string sourceCode, int limit, CancellationToken ct)
        => await ProcessSourcePendingCoreAsync(connection, sourceCode, limit, ct);

    private async Task<NormalizeBatchResult> ProcessSourcePendingCoreAsync(NpgsqlConnection connection, string? sourceCode, int limit, CancellationToken ct)
    {
        await using var select = new NpgsqlCommand("""
            select a.raw_index_id, a.provider, a.advisory_id, a.identifiers, a.title, a.summary,
                   a.description, a.severity_label, a.references_json, a.affected_products,
                   a.affected_vendors, a.poc_available, a.detail_available, a.published_at,
                   a.modified_at, a.payload, r.source_id
            from stg_external_advisories a
            join source_raw_index r on r.id = a.raw_index_id
            join sources src on src.id = r.source_id
            where r.normalize_status in ('pending', 'failed')
              and ($1::text is null or src.code = $1)
            order by r.updated_at
            limit $2
            """, connection);
        select.Parameters.AddWithValue((object?)sourceCode ?? DBNull.Value);
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
                    reader.GetFieldValue<string[]>(3),
                    reader.IsDBNull(4) ? null : reader.GetString(4),
                    reader.IsDBNull(5) ? null : reader.GetString(5),
                    reader.IsDBNull(6) ? null : reader.GetString(6),
                    reader.IsDBNull(7) ? null : reader.GetString(7),
                    reader.GetString(8),
                    reader.GetString(9),
                    reader.GetString(10),
                    reader.IsDBNull(11) ? null : reader.GetBoolean(11),
                    reader.IsDBNull(12) ? null : reader.GetBoolean(12),
                    reader.IsDBNull(13) ? null : reader.GetFieldValue<DateTimeOffset>(13),
                    reader.IsDBNull(14) ? null : reader.GetFieldValue<DateTimeOffset>(14),
                    reader.GetString(15),
                    reader.GetGuid(16)));
            }
        }

        var drafts = rows.Select(row =>
        {
            var identifiers = IdentifiersFrom([row.AdvisoryId], row.Identifiers);
            var primary = identifiers.FirstOrDefault(x => x.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)) ?? row.AdvisoryId;
            return (Row: row, Draft: new VulnerabilityCanonicalDraft(primary, row.Title, row.Description ?? row.Summary, "active", row.PublishedAt, row.ModifiedAt, identifiers, row.SourceId, row.RawIndexId));
        }).ToList();
        var cache = await Canonicalizer.ResolveCanonicalIdsBatchAsync(connection, drafts.Select(x => x.Draft).ToList(), ct);

        var processed = 0;
        var failed = 0;
        var succeededIds = new List<Guid>();
        var affectedVulnIds = new List<Guid>();
        foreach (var (row, draft) in drafts)
        {
            try
            {
                var vulnerabilityId = await Canonicalizer.GetOrCreateCanonicalAsync(connection, draft, cache, ct);
                await AppendIdentifiersAsync(connection, vulnerabilityId, draft.Identifiers, ct);
                var recordId = await UpsertRecordAsync(connection, vulnerabilityId, row.SourceId, row.RawIndexId, row.AdvisoryId, row.Title, row.Description ?? row.Summary, "active", ct);
                await InsertDescriptionsAsync(connection, vulnerabilityId, recordId, row.SourceId, Descriptions(row), ct);
                await InsertSeverityScoresAsync(connection, vulnerabilityId, recordId, row.SourceId, row.RawIndexId, SourceFactExtractor.LabelSeverity(row.SeverityLabel, row.Payload), ct);
                await UpdateSeverityLabelAsync(connection, vulnerabilityId, row, ct);
                await InsertReferencesAsync(connection, vulnerabilityId, recordId, row.SourceId, SourceFactExtractor.References(JsonNode.Parse(row.ReferencesJson)), ct);
                var facts = AffectedFacts(row).ToList();
                await InsertAffectedFactsAsync(connection, vulnerabilityId, recordId, row.SourceId, row.RawIndexId, facts, ct);
                if (facts.Count > 0) affectedVulnIds.Add(vulnerabilityId);
                if (row.PocAvailable == true) await UpsertPocSignalAsync(connection, vulnerabilityId, row, ct);
                succeededIds.Add(row.RawIndexId);
                processed++;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to normalize external advisory {Provider}:{AdvisoryId} from raw {RawIndexId}", row.Provider, row.AdvisoryId, row.RawIndexId);
                failed++;
            }
        }

        await FlushAffectedProjectionsAsync(connection, affectedVulnIds, ct);
        await MarkNormalizedBatchAsync(connection, succeededIds, ct);
        return new NormalizeBatchResult(sourceCode ?? SourceCode, processed, failed);
    }

    private static IReadOnlyList<DescriptionDraft> Descriptions(Row row)
    {
        var rows = new List<DescriptionDraft>();
        if (!string.IsNullOrWhiteSpace(row.Summary))
            rows.Add(new DescriptionDraft("zh-CN", "summary", row.Summary, true));
        if (!string.IsNullOrWhiteSpace(row.Description) && !string.Equals(row.Summary, row.Description, StringComparison.Ordinal))
            rows.Add(new DescriptionDraft("zh-CN", "detail", row.Description, rows.Count == 0));
        return rows;
    }

    private static IEnumerable<AffectedFactDraft> AffectedFacts(Row row)
    {
        foreach (var product in JsonNode.Parse(row.AffectedProducts)?.AsArray() ?? [])
        {
            var name = product?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(name)) continue;
            yield return new AffectedFactDraft("product", "product", name, null, null, "vendor-product", row.Payload);
        }
    }

    private static async Task UpsertPocSignalAsync(NpgsqlConnection connection, Guid vulnerabilityId, Row row, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("""
            insert into vulnerability_exploits
              (vulnerability_id, source_id, raw_index_id, source_key, source_url, title,
               artifact_type, maturity, verification_status, published_at, modified_at, tags, source_specific)
            values
              ($1,$2,$3,$4,$5,$6,'source_poc_signal','poc','source_reported',$7,$8,array['poc-signal'],$9::jsonb)
            on conflict (source_id, source_key, vulnerability_id) do update set
              raw_index_id = excluded.raw_index_id,
              source_url = excluded.source_url,
              title = excluded.title,
              modified_at = excluded.modified_at,
              source_specific = excluded.source_specific,
              updated_at = now()
            """, connection);
        cmd.Parameters.AddWithValue(vulnerabilityId);
        cmd.Parameters.AddWithValue(row.SourceId);
        cmd.Parameters.AddWithValue(row.RawIndexId);
        cmd.Parameters.AddWithValue($"{row.AdvisoryId}:poc");
        cmd.Parameters.AddWithValue((object?)FirstReference(row.ReferencesJson) ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)row.Title ?? row.AdvisoryId);
        cmd.Parameters.AddWithValue((object?)row.PublishedAt ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)row.ModifiedAt ?? DBNull.Value);
        cmd.Parameters.AddWithValue(row.Payload);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static async Task UpdateSeverityLabelAsync(NpgsqlConnection connection, Guid vulnerabilityId, Row row, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(row.SeverityLabel)) return;
        await using var cmd = new NpgsqlCommand("""
            update vulnerabilities
            set severity_label = coalesce(severity_label, $2),
                severity_source = coalesce(severity_source, $3),
                updated_at = now()
            where id = $1
            """, connection);
        cmd.Parameters.AddWithValue(vulnerabilityId);
        cmd.Parameters.AddWithValue(row.SeverityLabel);
        cmd.Parameters.AddWithValue(row.Provider);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static async Task AppendIdentifiersAsync(NpgsqlConnection connection, Guid vulnerabilityId, string[] identifiers, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("""
            update vulnerabilities
            set identifiers = (select array(select distinct unnest(vulnerabilities.identifiers || $2::text[]))),
                aliases = (select array(
                    select distinct identifier
                    from unnest(vulnerabilities.aliases || $2::text[]) identifier
                    where identifier <> vulnerabilities.primary_identifier
                )),
                updated_at = now()
            where id = $1
            """, connection);
        cmd.Parameters.AddWithValue(vulnerabilityId);
        cmd.Parameters.AddWithValue(identifiers);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static string? FirstReference(string json)
    {
        foreach (var item in JsonNode.Parse(json)?.AsArray() ?? [])
        {
            if (item is JsonValue value && value.TryGetValue<string>(out var text)) return text;
            var url = item?["url"]?.GetValue<string>();
            if (!string.IsNullOrWhiteSpace(url)) return url;
        }
        return null;
    }

    private sealed record Row(
        Guid RawIndexId,
        string Provider,
        string AdvisoryId,
        string[] Identifiers,
        string? Title,
        string? Summary,
        string? Description,
        string? SeverityLabel,
        string ReferencesJson,
        string AffectedProducts,
        string AffectedVendors,
        bool? PocAvailable,
        bool? DetailAvailable,
        DateTimeOffset? PublishedAt,
        DateTimeOffset? ModifiedAt,
        string Payload,
        Guid SourceId);
}
