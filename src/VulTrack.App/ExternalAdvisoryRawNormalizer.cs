using System.Diagnostics;
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

        var drafts = new List<ExternalNormalizationDraft>();
        var failedRawIds = new HashSet<Guid>();
        foreach (var row in rows)
        {
            try
            {
                var identifiers = IdentifiersFrom([row.AdvisoryId], row.Identifiers);
                var primary = identifiers.FirstOrDefault(x => x.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)) ?? row.AdvisoryId;
                drafts.Add(new ExternalNormalizationDraft(
                    row.RawIndexId,
                    row.AdvisoryId,
                    row.SourceId,
                    row,
                    new VulnerabilityCanonicalDraft(primary, row.Title, row.Description ?? row.Summary, "active", row.PublishedAt, row.ModifiedAt, identifiers, row.SourceId, row.RawIndexId),
                    Descriptions(row),
                    SourceFactExtractor.LabelSeverity(row.SeverityLabel, row.Payload).ToList(),
                    SourceFactExtractor.References(JsonNode.Parse(row.ReferencesJson)),
                    AffectedFacts(row).ToList()));
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to parse external advisory {Provider}:{AdvisoryId} from raw {RawIndexId}", row.Provider, row.AdvisoryId, row.RawIndexId);
                failedRawIds.Add(row.RawIndexId);
            }
        }

        var result = await ProcessExternalDraftsAsync(connection, sourceCode ?? SourceCode, drafts, failedRawIds, ct);
        await MarkNormalizedBatchAsync(connection, result.SucceededRawIndexIds, ct);
        return new NormalizeBatchResult(sourceCode ?? SourceCode, result.Processed, result.Failed);
    }

    private async Task<(int Processed, int Failed, IReadOnlyList<Guid> SucceededRawIndexIds)> ProcessExternalDraftsAsync(
        NpgsqlConnection connection,
        string sourceCode,
        IReadOnlyList<ExternalNormalizationDraft> drafts,
        HashSet<Guid> failedRawIds,
        CancellationToken ct)
    {
        var canonicalized = new List<ExternalCanonicalizedDraft>();
        if (drafts.Count > 0)
        {
            var resolveWatch = Stopwatch.StartNew();
            var cache = await Canonicalizer.ResolveCanonicalIdsBatchAsync(connection, drafts.Select(x => x.CanonicalDraft).ToList(), ct);
            resolveWatch.Stop();
            var canonicalWatch = Stopwatch.StartNew();
            foreach (var draft in drafts)
            {
                try
                {
                    var vulnerabilityId = await Canonicalizer.GetOrCreateCanonicalAsync(connection, draft.CanonicalDraft, cache, ct);
                    canonicalized.Add(new ExternalCanonicalizedDraft(draft, vulnerabilityId));
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "Failed to canonicalize external advisory {Provider}:{AdvisoryId} from raw {RawIndexId}", draft.Row.Provider, draft.Row.AdvisoryId, draft.RawIndexId);
                    failedRawIds.Add(draft.RawIndexId);
                }
            }
            canonicalWatch.Stop();

            var remapWatch = Stopwatch.StartNew();
            var currentCanonicalIds = await Canonicalizer.ResolveCanonicalIdsBatchAsync(connection, canonicalized.Select(x => x.Draft.CanonicalDraft).ToList(), ct);
            var remapped = 0;
            canonicalized = canonicalized
                .Select(item =>
                {
                    var currentId = ResolveCanonicalIdFromCache(item.Draft.CanonicalDraft, currentCanonicalIds, item.VulnerabilityId);
                    if (currentId != item.VulnerabilityId) remapped++;
                    return item with { VulnerabilityId = currentId };
                })
                .ToList();
            remapWatch.Stop();

            logger.LogInformation("External advisory normalize {SourceCode}: parsed={Parsed}, canonicalized={Canonicalized}, resolve_ms={ResolveMs}, canonical_ms={CanonicalMs}.",
                sourceCode, drafts.Count, canonicalized.Count, resolveWatch.ElapsedMilliseconds, canonicalWatch.ElapsedMilliseconds);
            if (remapped > 0)
            {
                logger.LogInformation("External advisory normalize {SourceCode}: remapped {Remapped} in-batch canonical ids after merges in {RemapMs} ms.",
                    sourceCode, remapped, remapWatch.ElapsedMilliseconds);
            }
        }

        var writeResult = await ProcessExternalCanonicalizedBatchAsync(connection, sourceCode, canonicalized, ct);
        foreach (var rawId in writeResult.FailedRawIndexIds) failedRawIds.Add(rawId);

        var succeededRawIds = writeResult.SucceededRawIndexIds
            .Where(rawId => !failedRawIds.Contains(rawId))
            .Distinct()
            .ToArray();
        var attemptedRawIds = drafts.Select(x => x.RawIndexId).Concat(failedRawIds).Distinct().ToArray();
        var failedCount = attemptedRawIds.Count(rawId => !succeededRawIds.Contains(rawId));
        return (succeededRawIds.Length, failedCount, succeededRawIds);
    }

    private async Task<(IReadOnlyList<Guid> SucceededRawIndexIds, IReadOnlyList<Guid> FailedRawIndexIds)> ProcessExternalCanonicalizedBatchAsync(
        NpgsqlConnection connection,
        string sourceCode,
        IReadOnlyList<ExternalCanonicalizedDraft> canonicalized,
        CancellationToken ct)
    {
        if (canonicalized.Count == 0) return ([], []);

        for (var attempt = 1; attempt <= 2; attempt++)
        {
            try
            {
                var recordInputs = canonicalized
                    .Select(item => new VulnerabilityRecordBatchItem(
                        item.VulnerabilityId,
                        item.Draft.SourceId,
                        item.Draft.RawIndexId,
                        item.Draft.SourceRecordId,
                        item.Draft.Row.Title,
                        item.Draft.Row.Description ?? item.Draft.Row.Summary,
                        "active"))
                    .ToList();

                var watch = Stopwatch.StartNew();
                var recordIds = await UpsertRecordsBatchAsync(connection, recordInputs, ct);
                var recordsMs = watch.ElapsedMilliseconds;
                var descriptionItems = new List<DescriptionBatchItem>();
                var severityItems = new List<SeverityScoreBatchItem>();
                var referenceItems = new List<ReferenceBatchItem>();
                var affectedItems = new List<AffectedFactBatchItem>();
                var affectedVulnIds = new List<Guid>();
                var succeededRawIds = new List<Guid>();

                foreach (var item in canonicalized)
                {
                    var key = (item.Draft.SourceId, item.Draft.SourceRecordId, item.Draft.RawIndexId);
                    if (!recordIds.TryGetValue(key, out var recordId))
                        throw new InvalidOperationException($"Missing vulnerability record id for external advisory raw {item.Draft.RawIndexId}");

                    descriptionItems.Add(new DescriptionBatchItem(item.VulnerabilityId, recordId, item.Draft.SourceId, item.Draft.Descriptions));
                    severityItems.Add(new SeverityScoreBatchItem(item.VulnerabilityId, recordId, item.Draft.SourceId, item.Draft.RawIndexId, item.Draft.Severities));
                    referenceItems.Add(new ReferenceBatchItem(item.VulnerabilityId, recordId, item.Draft.SourceId, item.Draft.References));
                    affectedItems.Add(new AffectedFactBatchItem(item.VulnerabilityId, recordId, item.Draft.SourceId, item.Draft.RawIndexId, item.Draft.AffectedFacts));
                    if (item.Draft.AffectedFacts.Count > 0) affectedVulnIds.Add(item.VulnerabilityId);
                    succeededRawIds.Add(item.Draft.RawIndexId);
                }

                watch.Restart();
                await AppendIdentifiersBatchAsync(connection, canonicalized, ct);
                var identifiersMs = watch.ElapsedMilliseconds;
                watch.Restart();
                await InsertDescriptionsBatchAsync(connection, descriptionItems, ct);
                var descriptionsMs = watch.ElapsedMilliseconds;
                watch.Restart();
                await InsertSeverityScoresBatchAsync(connection, severityItems, ct);
                var severitiesMs = watch.ElapsedMilliseconds;
                watch.Restart();
                await UpdateSeverityLabelBatchAsync(connection, canonicalized, ct);
                var severityLabelsMs = watch.ElapsedMilliseconds;
                watch.Restart();
                await InsertReferencesBatchAsync(connection, referenceItems, ct);
                var referencesMs = watch.ElapsedMilliseconds;
                watch.Restart();
                await InsertAffectedFactsBatchAsync(connection, affectedItems, ct);
                var affectedMs = watch.ElapsedMilliseconds;
                watch.Restart();
                await UpsertPocSignalsBatchAsync(connection, canonicalized, ct);
                var pocMs = watch.ElapsedMilliseconds;
                watch.Restart();
                await FlushAffectedProjectionsAsync(connection, affectedVulnIds, ct);
                var flushMs = watch.ElapsedMilliseconds;

                logger.LogInformation("External advisory batch write {SourceCode} count={Count}: records_ms={RecordsMs}, identifiers_ms={IdentifiersMs}, descriptions_ms={DescriptionsMs}, severities_ms={SeveritiesMs}, severity_labels_ms={SeverityLabelsMs}, references_ms={ReferencesMs}, affected_ms={AffectedMs}, poc_ms={PocMs}, flush_ms={FlushMs}.",
                    sourceCode, canonicalized.Count, recordsMs, identifiersMs, descriptionsMs, severitiesMs, severityLabelsMs, referencesMs, affectedMs, pocMs, flushMs);
                return (succeededRawIds, []);
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.DeadlockDetected && attempt == 1)
            {
                logger.LogWarning(ex, "External advisory batch normalize {SourceCode} deadlocked for {Count} records; retrying batch once.", sourceCode, canonicalized.Count);
                await Task.Delay(500, ct);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "External advisory batch normalize {SourceCode} failed for {Count} records; falling back to per-record writes.", sourceCode, canonicalized.Count);
                return await ProcessExternalCanonicalizedIndividuallyAsync(connection, canonicalized, ct);
            }
        }

        return await ProcessExternalCanonicalizedIndividuallyAsync(connection, canonicalized, ct);
    }

    private async Task<(IReadOnlyList<Guid> SucceededRawIndexIds, IReadOnlyList<Guid> FailedRawIndexIds)> ProcessExternalCanonicalizedIndividuallyAsync(
        NpgsqlConnection connection,
        IReadOnlyList<ExternalCanonicalizedDraft> canonicalized,
        CancellationToken ct)
    {
        var succeededRawIds = new List<Guid>();
        var failedRawIds = new List<Guid>();
        var affectedVulnIds = new List<Guid>();

        foreach (var item in canonicalized)
        {
            var row = item.Draft.Row;
            try
            {
                await AppendIdentifiersAsync(connection, item.VulnerabilityId, item.Draft.CanonicalDraft.Identifiers, ct);
                var recordId = await UpsertRecordAsync(connection, item.VulnerabilityId, row.SourceId, row.RawIndexId, row.AdvisoryId, row.Title, row.Description ?? row.Summary, "active", ct);
                await InsertDescriptionsAsync(connection, item.VulnerabilityId, recordId, row.SourceId, item.Draft.Descriptions, ct);
                await InsertSeverityScoresAsync(connection, item.VulnerabilityId, recordId, row.SourceId, row.RawIndexId, item.Draft.Severities, ct);
                await UpdateSeverityLabelAsync(connection, item.VulnerabilityId, row, ct);
                await InsertReferencesAsync(connection, item.VulnerabilityId, recordId, row.SourceId, item.Draft.References, ct);
                await InsertAffectedFactsAsync(connection, item.VulnerabilityId, recordId, row.SourceId, row.RawIndexId, item.Draft.AffectedFacts, ct);
                if (item.Draft.AffectedFacts.Count > 0) affectedVulnIds.Add(item.VulnerabilityId);
                if (row.PocAvailable == true) await UpsertPocSignalAsync(connection, item.VulnerabilityId, row, ct);
                succeededRawIds.Add(row.RawIndexId);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to write external advisory {Provider}:{AdvisoryId} from raw {RawIndexId}", row.Provider, row.AdvisoryId, row.RawIndexId);
                failedRawIds.Add(row.RawIndexId);
            }
        }

        await FlushAffectedProjectionsAsync(connection, affectedVulnIds, ct);
        return (succeededRawIds, failedRawIds);
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

    private static async Task UpsertPocSignalsBatchAsync(NpgsqlConnection connection, IReadOnlyList<ExternalCanonicalizedDraft> items, CancellationToken ct)
    {
        var rows = items
            .Where(item => item.Draft.Row.PocAvailable == true)
            .GroupBy(item => new { item.Draft.SourceId, item.Draft.Row.AdvisoryId, item.VulnerabilityId })
            .Select(group => group.First())
            .ToList();
        if (rows.Count == 0) return;

        foreach (var batch in rows.Chunk(1000))
        {
            var values = new List<string>();
            var parameters = new List<object>();
            var parameterIndex = 1;
            foreach (var item in batch)
            {
                var row = item.Draft.Row;
                values.Add($"(${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},'source_poc_signal','poc','source_reported',${parameterIndex++},${parameterIndex++},array['poc-signal'],${parameterIndex++}::jsonb)");
                parameters.Add(item.VulnerabilityId);
                parameters.Add(row.SourceId);
                parameters.Add(row.RawIndexId);
                parameters.Add($"{row.AdvisoryId}:poc");
                parameters.Add((object?)FirstReference(row.ReferencesJson) ?? DBNull.Value);
                parameters.Add((object?)row.Title ?? row.AdvisoryId);
                parameters.Add((object?)row.PublishedAt ?? DBNull.Value);
                parameters.Add((object?)row.ModifiedAt ?? DBNull.Value);
                parameters.Add(row.Payload);
            }

            await using var cmd = new NpgsqlCommand($"""
                insert into vulnerability_exploits
                  (vulnerability_id, source_id, raw_index_id, source_key, source_url, title,
                   artifact_type, maturity, verification_status, published_at, modified_at, tags, source_specific)
                values {string.Join(",", values)}
                on conflict (source_id, source_key, vulnerability_id) do update set
                  raw_index_id = excluded.raw_index_id,
                  source_url = excluded.source_url,
                  title = excluded.title,
                  modified_at = excluded.modified_at,
                  source_specific = excluded.source_specific,
                  updated_at = now()
                """, connection);
            cmd.CommandTimeout = 300;
            foreach (var parameter in parameters) cmd.Parameters.AddWithValue(parameter);
            await cmd.ExecuteNonQueryAsync(ct);
        }
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

    private static async Task UpdateSeverityLabelBatchAsync(NpgsqlConnection connection, IReadOnlyList<ExternalCanonicalizedDraft> items, CancellationToken ct)
    {
        var rows = items
            .Where(item => !string.IsNullOrWhiteSpace(item.Draft.Row.SeverityLabel))
            .GroupBy(item => item.VulnerabilityId)
            .Select(group => group.First())
            .ToList();
        if (rows.Count == 0) return;

        foreach (var batch in rows.Chunk(1000))
        {
            var values = new List<string>();
            var parameters = new List<object>();
            var parameterIndex = 1;
            foreach (var item in batch)
            {
                values.Add($"(${parameterIndex++}::uuid,${parameterIndex++},${parameterIndex++})");
                parameters.Add(item.VulnerabilityId);
                parameters.Add(item.Draft.Row.SeverityLabel!);
                parameters.Add(item.Draft.Row.Provider);
            }

            await using var cmd = new NpgsqlCommand($"""
                update vulnerabilities v
                set severity_label = coalesce(v.severity_label, incoming.label),
                    severity_source = coalesce(v.severity_source, incoming.provider),
                    updated_at = now()
                from (values {string.Join(",", values)}) as incoming(id, label, provider)
                where v.id = incoming.id
                """, connection);
            cmd.CommandTimeout = 300;
            foreach (var parameter in parameters) cmd.Parameters.AddWithValue(parameter);
            await cmd.ExecuteNonQueryAsync(ct);
        }
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

    private static async Task AppendIdentifiersBatchAsync(NpgsqlConnection connection, IReadOnlyList<ExternalCanonicalizedDraft> items, CancellationToken ct)
    {
        var rows = items
            .GroupBy(item => item.VulnerabilityId)
            .Select(group => new
            {
                VulnerabilityId = group.Key,
                Identifiers = group
                    .SelectMany(item => item.Draft.CanonicalDraft.Identifiers)
                    .Where(identifier => !string.IsNullOrWhiteSpace(identifier))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray()
            })
            .Where(row => row.Identifiers.Length > 0)
            .ToList();
        if (rows.Count == 0) return;

        foreach (var batch in rows.Chunk(1000))
        {
            var values = new List<string>();
            var parameters = new List<object>();
            var parameterIndex = 1;
            foreach (var row in batch)
            {
                values.Add($"(${parameterIndex++}::uuid,${parameterIndex++}::text[])");
                parameters.Add(row.VulnerabilityId);
                parameters.Add(row.Identifiers);
            }

            await using var cmd = new NpgsqlCommand($"""
                update vulnerabilities v
                set identifiers = (select array(select distinct unnest(v.identifiers || incoming.identifiers))),
                    aliases = (select array(
                        select distinct identifier
                        from unnest(v.aliases || incoming.identifiers) identifier
                        where identifier <> v.primary_identifier
                    )),
                    updated_at = now()
                from (values {string.Join(",", values)}) as incoming(id, identifiers)
                where v.id = incoming.id
                """, connection);
            cmd.CommandTimeout = 300;
            foreach (var parameter in parameters) cmd.Parameters.AddWithValue(parameter);
            await cmd.ExecuteNonQueryAsync(ct);
        }
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

    private sealed record ExternalNormalizationDraft(
        Guid RawIndexId,
        string SourceRecordId,
        Guid SourceId,
        Row Row,
        VulnerabilityCanonicalDraft CanonicalDraft,
        IReadOnlyList<DescriptionDraft> Descriptions,
        IReadOnlyList<SeverityScoreDraft> Severities,
        IReadOnlyList<ReferenceDraft> References,
        IReadOnlyList<AffectedFactDraft> AffectedFacts);

    private sealed record ExternalCanonicalizedDraft(ExternalNormalizationDraft Draft, Guid VulnerabilityId);

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
