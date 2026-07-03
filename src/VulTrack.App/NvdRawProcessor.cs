using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;

namespace VulTrack.App;

public sealed class NvdRawProcessor(
    NpgsqlDataSource db,
    IVulnerabilityCanonicalizer canonicalizer,
    IEnumerable<IAffectedComponentHook> affectedHooks,
    ILogger<NvdRawProcessor> logger)
    : NormalizerBase(affectedHooks, canonicalizer)
{
    public Task<ProcessPendingResult> ProcessPendingAsync(int limit, CancellationToken ct) =>
        ProcessPendingAsync(limit, "nvd-cve", ct);

    public async Task<ProcessPendingResult> ProcessPendingAsync(int limit, string sourceCode, CancellationToken ct)
    {
        var records = await SelectPendingRecordsAsync(limit, sourceCode, priorityOnly: true, ct);
        if (records.Count == 0)
        {
            records = await SelectPendingRecordsAsync(limit, sourceCode, priorityOnly: false, ct);
        }

        try
        {
            return await ProcessBatchAsync(records, sourceCode, ct);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "NVD batch normalize failed for {Count} records from {SourceCode}; falling back to savepoint-per-record mode.", records.Count, sourceCode);
            return await ProcessIndividuallyAsync(records, ct);
        }
    }

    private async Task<ProcessPendingResult> ProcessBatchAsync(IReadOnlyList<NvdStagingRecord> records, string sourceCode, CancellationToken ct)
    {
        var totalWatch = Stopwatch.StartNew();
        var (drafts, parseFailed) = BuildDrafts(records);

        await using var connection = await db.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);

        var resolveWatch = Stopwatch.StartNew();
        var cache = await Canonicalizer.ResolveCanonicalIdsBatchAsync(connection, drafts.Select(x => x.CanonicalDraft).ToList(), ct);
        resolveWatch.Stop();

        var canonicalized = new List<NvdCanonicalizedDraft>();
        var canonicalFailed = 0;
        var canonicalWatch = Stopwatch.StartNew();
        foreach (var draft in drafts)
        {
            try
            {
                var vulnerabilityId = await Canonicalizer.GetOrCreateCanonicalAsync(connection, draft.CanonicalDraft, cache, ct);
                canonicalized.Add(new NvdCanonicalizedDraft(draft, vulnerabilityId));
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to canonicalize NVD CVE {CveId}", draft.Record.CveId);
                canonicalFailed++;
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

        var writeResult = await ProcessCanonicalizedBatchAsync(connection, canonicalized, ct);
        await MarkNormalizedAsync(connection, writeResult.SucceededRawIndexIds, ct);
        await transaction.CommitAsync(ct);

        totalWatch.Stop();
        var failed = parseFailed + canonicalFailed + writeResult.Failed;
        logger.LogInformation(
            "NVD batch normalize {SourceCode}: selected={Selected}, parsed={Parsed}, canonicalized={Canonicalized}, processed={Processed}, failed={Failed}, remapped={Remapped}, resolve_ms={ResolveMs}, canonical_ms={CanonicalMs}, remap_ms={RemapMs}, total_ms={TotalMs}.",
            sourceCode, records.Count, drafts.Count, canonicalized.Count, writeResult.Processed, failed,
            remapped, resolveWatch.ElapsedMilliseconds, canonicalWatch.ElapsedMilliseconds, remapWatch.ElapsedMilliseconds, totalWatch.ElapsedMilliseconds);
        return new ProcessPendingResult(writeResult.Processed, failed);
    }

    private async Task<ProcessPendingResult> ProcessIndividuallyAsync(IReadOnlyList<NvdStagingRecord> records, CancellationToken ct)
    {
        var processed = 0;
        var failed = 0;
        var succeededRawIndexIds = new List<Guid>();
        var affectedVulnerabilityIds = new HashSet<Guid>();

        await using var connection = await db.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        foreach (var record in records)
        {
            var savepointName = $"record_{processed + failed}";
            await transaction.SaveAsync(savepointName, ct);
            try
            {
                var vulnerabilityId = await UpsertVulnerabilityAsync(connection, record, ct);
                var vulnerabilityRecordId = await UpsertRecordAsync(connection, vulnerabilityId, record, ct);
                await UpsertIdentifierAsync(connection, vulnerabilityId, record, ct);
                await UpsertDescriptionsAsync(connection, vulnerabilityId, vulnerabilityRecordId, record, ct);
                await UpsertSeveritiesAsync(connection, vulnerabilityId, vulnerabilityRecordId, record, ct);
                await UpsertWeaknessesAsync(connection, vulnerabilityId, vulnerabilityRecordId, record, ct);
                await UpsertReferencesAsync(connection, vulnerabilityId, vulnerabilityRecordId, record, ct);
                var affectedFacts = await UpsertAffectedFactsAsync(connection, vulnerabilityId, vulnerabilityRecordId, record, ct);
                if (affectedFacts.Count > 0) affectedVulnerabilityIds.Add(vulnerabilityId);
                await DispatchAffectedHooksAsync(connection, vulnerabilityId, vulnerabilityRecordId, affectedFacts, ct);
                succeededRawIndexIds.Add(record.RawIndexId);
                await transaction.ReleaseAsync(savepointName, ct);
                processed++;
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync(savepointName, ct);
                logger.LogError(ex, "Failed to normalize NVD CVE {CveId}", record.CveId);
                failed++;
            }
        }

        await FlushAffectedProjectionsAsync(connection, affectedVulnerabilityIds, ct);
        await MarkNormalizedAsync(connection, succeededRawIndexIds, ct);
        await transaction.CommitAsync(ct);
        return new ProcessPendingResult(processed, failed);
    }

    private static (List<NvdNormalizationDraft> Drafts, int Failed) BuildDrafts(IReadOnlyList<NvdStagingRecord> records)
    {
        var drafts = new List<NvdNormalizationDraft>(records.Count);
        var failed = 0;

        foreach (var record in records)
        {
            try
            {
                var descriptions = ExtractDescriptionDrafts(record.Descriptions).ToList();
                var title = descriptions.FirstOrDefault(x => string.Equals(x.Lang, "en", StringComparison.OrdinalIgnoreCase))?.Value
                    ?? descriptions.FirstOrDefault()?.Value;
                var severities = ExtractSeverityDrafts(record.Metrics).ToList();
                var weaknesses = ExtractWeaknessDrafts(record.Weaknesses).ToList();
                var references = ExtractReferenceDrafts(record.References).ToList();
                var affectedFacts = ExtractNvdAffectedFacts(record.Configurations).ToList();
                var vulnerableFacts = affectedFacts
                    .Where(x => x.Vulnerable)
                    .Select(x => new AffectedFactDraft("cpe", "cpe", x.Product, null, x.VersionRange, x.RangeType, x.SourceSpecificJson, x.Criteria))
                    .DistinctBy(x => $"{x.Cpe23Uri}|{x.PackageName}|{x.VersionRange}|{x.RangeType}", StringComparer.OrdinalIgnoreCase)
                    .ToList();

                var canonicalDraft = new VulnerabilityCanonicalDraft(
                    record.CveId,
                    title,
                    title,
                    record.Status ?? "active",
                    record.PublishedAt,
                    record.ModifiedAt,
                    [record.CveId],
                    record.SourceId,
                    record.RawIndexId);

                drafts.Add(new NvdNormalizationDraft(
                    record,
                    canonicalDraft,
                    descriptions,
                    severities,
                    weaknesses,
                    references,
                    affectedFacts,
                    vulnerableFacts));
            }
            catch
            {
                failed++;
            }
        }

        return (drafts, failed);
    }

    private async Task<(int Processed, int Failed, IReadOnlyList<Guid> SucceededRawIndexIds)> ProcessCanonicalizedBatchAsync(
        NpgsqlConnection connection,
        IReadOnlyList<NvdCanonicalizedDraft> canonicalized,
        CancellationToken ct)
    {
        if (canonicalized.Count == 0) return (0, 0, []);

        var recordInputs = canonicalized
            .Select(item => new VulnerabilityRecordBatchItem(
                item.VulnerabilityId,
                item.Draft.Record.SourceId,
                item.Draft.Record.RawIndexId,
                item.Draft.Record.CveId,
                item.Draft.CanonicalDraft.Title,
                item.Draft.CanonicalDraft.Description,
                item.Draft.Record.Status ?? "active"))
            .ToList();

        var watch = Stopwatch.StartNew();
        var recordIds = await UpsertRecordsBatchAsync(connection, recordInputs, ct);
        var recordsMs = watch.ElapsedMilliseconds;

        var descriptionItems = new List<DescriptionBatchItem>(canonicalized.Count);
        var severityItems = new List<SeverityScoreBatchItem>(canonicalized.Count);
        var weaknessItems = new List<WeaknessBatchItem>(canonicalized.Count);
        var referenceItems = new List<ReferenceBatchItem>(canonicalized.Count);
        var affectedItems = new List<AffectedFactBatchItem>(canonicalized.Count);
        var affectedRows = new List<NvdAffectedFactRow>();
        var severitySelections = new List<NvdSeveritySelection>();
        var affectedVulnerabilityIds = new List<Guid>();
        var succeededIds = new List<Guid>(canonicalized.Count);

        foreach (var item in canonicalized)
        {
            var draft = item.Draft;
            var key = (draft.Record.SourceId, draft.Record.CveId, draft.Record.RawIndexId);
            if (!recordIds.TryGetValue(key, out var recordId))
                throw new InvalidOperationException($"Missing vulnerability record id for NVD raw {draft.Record.RawIndexId}");

            descriptionItems.Add(new DescriptionBatchItem(item.VulnerabilityId, recordId, draft.Record.SourceId, draft.Descriptions));
            severityItems.Add(new SeverityScoreBatchItem(item.VulnerabilityId, recordId, draft.Record.SourceId, draft.Record.RawIndexId, draft.Severities));
            weaknessItems.Add(new WeaknessBatchItem(item.VulnerabilityId, recordId, draft.Record.SourceId, draft.Weaknesses));
            referenceItems.Add(new ReferenceBatchItem(item.VulnerabilityId, recordId, draft.Record.SourceId, draft.References));
            affectedItems.Add(new AffectedFactBatchItem(item.VulnerabilityId, recordId, draft.Record.SourceId, draft.Record.RawIndexId, draft.VulnerableAffectedFacts));

            var selectedSeverity = draft.Severities.FirstOrDefault(x => x.IsSelected);
            if (selectedSeverity is not null)
            {
                severitySelections.Add(new NvdSeveritySelection(
                    item.VulnerabilityId,
                    draft.Record.SourceId,
                    selectedSeverity.Score,
                    selectedSeverity.ScoringVersion,
                    selectedSeverity.VectorString,
                    selectedSeverity.SeverityLabel));
            }

            foreach (var fact in draft.AffectedFacts)
            {
                affectedRows.Add(new NvdAffectedFactRow(
                    item.VulnerabilityId,
                    recordId,
                    draft.Record.SourceId,
                    draft.Record.RawIndexId,
                    fact));
            }

            if (draft.VulnerableAffectedFacts.Count > 0) affectedVulnerabilityIds.Add(item.VulnerabilityId);
            succeededIds.Add(draft.Record.RawIndexId);
        }

        watch.Restart();
        await InsertDescriptionsBatchAsync(connection, descriptionItems, ct);
        var descriptionsMs = watch.ElapsedMilliseconds;
        watch.Restart();
        await InsertSeverityScoresBatchAsync(connection, severityItems, ct);
        await UpdateNvdSeverityMetadataBatchAsync(connection, severitySelections, ct);
        var severitiesMs = watch.ElapsedMilliseconds;
        watch.Restart();
        await InsertWeaknessesBatchAsync(connection, weaknessItems, ct);
        var weaknessesMs = watch.ElapsedMilliseconds;
        watch.Restart();
        await InsertReferencesBatchAsync(connection, referenceItems, ct);
        var referencesMs = watch.ElapsedMilliseconds;
        watch.Restart();
        await InsertNvdAffectedFactsBatchAsync(connection, affectedItems.Select(x => x.VulnerabilityRecordId).ToList(), affectedRows, ct);
        await DispatchAffectedHooksBatchAsync(connection, affectedItems, ct);
        var affectedMs = watch.ElapsedMilliseconds;
        watch.Restart();
        await FlushAffectedProjectionsAsync(connection, affectedVulnerabilityIds, ct);
        var flushMs = watch.ElapsedMilliseconds;

        logger.LogInformation(
            "NVD batch write count={Count}: records_ms={RecordsMs}, descriptions_ms={DescriptionsMs}, severities_ms={SeveritiesMs}, weaknesses_ms={WeaknessesMs}, references_ms={ReferencesMs}, affected_ms={AffectedMs}, flush_ms={FlushMs}.",
            canonicalized.Count, recordsMs, descriptionsMs, severitiesMs, weaknessesMs, referencesMs, affectedMs, flushMs);

        return (canonicalized.Count, 0, succeededIds);
    }

    private static async Task UpdateNvdSeverityMetadataBatchAsync(NpgsqlConnection connection, IReadOnlyList<NvdSeveritySelection> selections, CancellationToken ct)
    {
        if (selections.Count == 0) return;

        foreach (var batch in selections.Chunk(1000))
        {
            var values = new List<string>();
            var parameters = new List<object>();
            var parameterIndex = 1;
            foreach (var row in batch)
            {
                values.Add($"(${parameterIndex++}::uuid,${parameterIndex++}::uuid,${parameterIndex++}::numeric,${parameterIndex++},${parameterIndex++},${parameterIndex++})");
                parameters.Add(row.VulnerabilityId);
                parameters.Add(row.SourceId);
                parameters.Add((object?)row.Score ?? DBNull.Value);
                parameters.Add((object?)row.Version ?? DBNull.Value);
                parameters.Add((object?)row.Vector ?? DBNull.Value);
                parameters.Add((object?)row.Label ?? DBNull.Value);
            }

            await using var cmd = new NpgsqlCommand($"""
                update vulnerabilities v
                set max_cvss_score = coalesce(incoming.score, v.max_cvss_score),
                    max_cvss_version = coalesce(incoming.version, v.max_cvss_version),
                    max_cvss_vector = coalesce(incoming.vector, v.max_cvss_vector),
                    max_cvss_source_id = incoming.source_id,
                    severity_label = coalesce(incoming.label, v.severity_label),
                    severity_source = 'nvd-cve',
                    severity_confidence = 1.0,
                    updated_at = now()
                from (values {string.Join(",", values)}) as incoming(id, source_id, score, version, vector, label)
                where v.id = incoming.id
                """, connection);
            cmd.CommandTimeout = 300;
            foreach (var parameter in parameters) cmd.Parameters.AddWithValue(parameter);
            await cmd.ExecuteNonQueryAsync(ct);
        }
    }

    private static async Task InsertNvdAffectedFactsBatchAsync(
        NpgsqlConnection connection,
        IReadOnlyList<Guid> recordIds,
        IReadOnlyList<NvdAffectedFactRow> rows,
        CancellationToken ct)
    {
        await DeleteRecordRowsBatchAsync(connection, "vulnerability_affected_facts", recordIds, ct);

        var deduped = rows
            .GroupBy(x => $"{x.VulnerabilityRecordId}|{x.Fact.Criteria}|{x.Fact.Product}|{x.Fact.VersionRange}|{x.Fact.RangeType}|{x.Fact.Vulnerable}", StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .ToList();
        if (deduped.Count == 0) return;

        foreach (var batch in deduped.Chunk(1000))
        {
            var values = new List<string>();
            var parameters = new List<object>();
            var parameterIndex = 1;
            foreach (var row in batch)
            {
                values.Add($"(${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},'cpe','cpe',${parameterIndex++},${parameterIndex++},lower(${parameterIndex - 1}),${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++}::jsonb)");
                parameters.Add(row.VulnerabilityId);
                parameters.Add(row.VulnerabilityRecordId);
                parameters.Add(row.SourceId);
                parameters.Add(row.RawIndexId);
                parameters.Add(row.Fact.Criteria);
                parameters.Add(row.Fact.Product);
                parameters.Add((object?)row.Fact.VersionRange ?? DBNull.Value);
                parameters.Add(row.Fact.RangeType);
                parameters.Add(row.Fact.Vulnerable);
                parameters.Add(row.Fact.SourceSpecificJson);
            }

            await using var cmd = new NpgsqlCommand($"""
                insert into vulnerability_affected_facts
                  (vulnerability_id, vulnerability_record_id, source_id, raw_index_id, fact_type, ecosystem,
                   cpe23_uri, package_name, normalized_package_name, version_range_raw, range_type, vulnerable,
                   source_specific)
                values {string.Join(",", values)}
                """, connection);
            cmd.CommandTimeout = 300;
            foreach (var parameter in parameters) cmd.Parameters.AddWithValue(parameter);
            await cmd.ExecuteNonQueryAsync(ct);
        }
    }

    private static IEnumerable<DescriptionDraft> ExtractDescriptionDrafts(string descriptionsJson)
    {
        foreach (var item in JsonNode.Parse(descriptionsJson)?.AsArray() ?? [])
        {
            var value = item?["value"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(value)) continue;
            var lang = item?["lang"]?.GetValue<string>() ?? "und";
            yield return new DescriptionDraft(lang, "detail", value, string.Equals(lang, "en", StringComparison.OrdinalIgnoreCase));
        }
    }

    private static IEnumerable<SeverityScoreDraft> ExtractSeverityDrafts(string metricsJson)
    {
        var scores = ExtractCvss(metricsJson).ToList();
        var selected = scores
            .Where(x => x.Score is not null)
            .OrderByDescending(x => x.Score)
            .FirstOrDefault();

        foreach (var score in scores)
        {
            yield return new SeverityScoreDraft(
                "cvss",
                score.Version,
                "base",
                score.Vector,
                score.Score,
                score.Severity,
                score.RawJson,
                selected is not null && score.RawJson == selected.RawJson);
        }
    }

    private static IEnumerable<WeaknessDraft> ExtractWeaknessDrafts(string weaknessesJson)
    {
        foreach (var weakness in JsonNode.Parse(weaknessesJson)?.AsArray() ?? [])
        {
            foreach (var desc in weakness?["description"]?.AsArray() ?? [])
            {
                var value = desc?["value"]?.GetValue<string>();
                if (string.IsNullOrWhiteSpace(value)) continue;
                yield return new WeaknessDraft("CWE", value, value);
            }
        }
    }

    private static IEnumerable<ReferenceDraft> ExtractReferenceDrafts(string referencesJson)
    {
        foreach (var reference in JsonNode.Parse(referencesJson)?.AsArray() ?? [])
        {
            var url = reference?["url"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(url)) continue;
            var tags = reference?["tags"]?.AsArray()
                .Select(x => x?.GetValue<string>() ?? "")
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .ToArray() ?? [];
            yield return new ReferenceDraft(url, null, tags);
        }
    }

    private static IEnumerable<NvdAffectedFactDraft> ExtractNvdAffectedFacts(string configurationsJson)
    {
        foreach (var cpeMatch in WalkCpeMatches(JsonNode.Parse(configurationsJson)))
        {
            var criteria = cpeMatch?["criteria"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(criteria)) continue;
            var product = ParseProduct(criteria);
            var versionRange = ExtractCpeVersionRange(cpeMatch);
            var rangeType = versionRange is not null ? "cpe_match" : "cpe_match_no_range";
            var vulnerable = cpeMatch?["vulnerable"]?.GetValue<bool>() ?? true;
            yield return new NvdAffectedFactDraft(
                criteria,
                product,
                versionRange,
                rangeType,
                vulnerable,
                cpeMatch?.ToJsonString() ?? "{}");
        }
    }

    private async Task<List<NvdStagingRecord>> SelectPendingRecordsAsync(int limit, string sourceCode, bool priorityOnly, CancellationToken ct)
    {
        await using var select = db.CreateCommand(priorityOnly ? """
            select s.raw_index_id, s.cve_id, s.vuln_status, s.descriptions, s.metrics,
                   s.weaknesses, s.configurations, s.references_json, s.published_at, s.modified_at,
                   s.payload, r.source_id
            from stg_nvd_cves s
            join source_raw_index r on r.id = s.raw_index_id
            join sources src on src.id = r.source_id
            where r.normalize_status in ('pending', 'failed')
              and r.status = 'priority'
              and src.code = $2
            order by s.modified_at nulls last, s.cve_id
            limit $1
            """ : """
            select s.raw_index_id, s.cve_id, s.vuln_status, s.descriptions, s.metrics,
                   s.weaknesses, s.configurations, s.references_json, s.published_at, s.modified_at,
                   s.payload, r.source_id
            from stg_nvd_cves s
            join source_raw_index r on r.id = s.raw_index_id
            join sources src on src.id = r.source_id
            where r.normalize_status in ('pending', 'failed')
              and src.code = $2
            order by s.modified_at nulls last, s.cve_id
            limit $1
            """);
        select.Parameters.AddWithValue(limit);
        select.Parameters.AddWithValue(sourceCode);

        var records = new List<NvdStagingRecord>();
        await using (var reader = await select.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            {
                records.Add(new NvdStagingRecord(
                    reader.GetGuid(0),
                    reader.GetString(1),
                    reader.IsDBNull(2) ? null : reader.GetString(2),
                    reader.GetString(3),
                    reader.GetString(4),
                    reader.GetString(5),
                    reader.GetString(6),
                    reader.GetString(7),
                    reader.IsDBNull(8) ? null : reader.GetFieldValue<DateTimeOffset>(8),
                    reader.IsDBNull(9) ? null : reader.GetFieldValue<DateTimeOffset>(9),
                    reader.GetString(10),
                    reader.GetGuid(11)));
            }
        }

        return records;
    }

    private async Task<Guid> UpsertVulnerabilityAsync(NpgsqlConnection conn, NvdStagingRecord record, CancellationToken ct)
    {
        var descriptions = JsonNode.Parse(record.Descriptions)?.AsArray();
        var title = descriptions?.FirstOrDefault(x => x?["lang"]?.GetValue<string>() == "en")?["value"]?.GetValue<string>();
        var selectedSeverity = ExtractCvss(record.Metrics).OrderByDescending(x => x.Score).FirstOrDefault();
        var vulnerabilityId = await Canonicalizer.UpsertCanonicalAsync(
            conn,
            new VulnerabilityCanonicalDraft(
                record.CveId,
                title,
                title,
                record.Status ?? "active",
                record.PublishedAt,
                record.ModifiedAt,
                [record.CveId],
                record.SourceId,
                record.RawIndexId),
            ct);

        await using var cmd = new NpgsqlCommand("""
            update vulnerabilities
            set max_cvss_score = coalesce($2, max_cvss_score),
                max_cvss_version = coalesce($3, max_cvss_version),
                max_cvss_vector = coalesce($4, max_cvss_vector),
                severity_label = coalesce($5, severity_label),
                severity_source = 'nvd-cve',
                severity_confidence = 1.0,
                updated_at = now()
            where id = $1
            """, conn);
        cmd.Parameters.AddWithValue(vulnerabilityId);
        cmd.Parameters.AddWithValue((object?)selectedSeverity?.Score ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)selectedSeverity?.Version ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)selectedSeverity?.Vector ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)selectedSeverity?.Severity ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
        return vulnerabilityId;
    }

    private static async Task<Guid> UpsertRecordAsync(NpgsqlConnection conn, Guid vulnerabilityId, NvdStagingRecord record, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("""
            insert into vulnerability_records
              (vulnerability_id, source_id, raw_index_id, source_record_id, title, description, status)
            values ($1,$2,$3,$4,$5,$6,$7)
            on conflict (source_id, source_record_id, raw_index_id) do update set
              vulnerability_id = excluded.vulnerability_id,
              updated_at = now()
            returning id
            """, conn);
        var title = JsonNode.Parse(record.Descriptions)?.AsArray()
            .FirstOrDefault(x => x?["lang"]?.GetValue<string>() == "en")?["value"]?.GetValue<string>();
        cmd.Parameters.AddWithValue(vulnerabilityId);
        cmd.Parameters.AddWithValue(record.SourceId);
        cmd.Parameters.AddWithValue(record.RawIndexId);
        cmd.Parameters.AddWithValue(record.CveId);
        cmd.Parameters.AddWithValue((object?)title ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)title ?? DBNull.Value);
        cmd.Parameters.AddWithValue(record.Status ?? "active");
        return (Guid)(await cmd.ExecuteScalarAsync(ct))!;
    }

    private static Task UpsertIdentifierAsync(NpgsqlConnection conn, Guid vulnerabilityId, NvdStagingRecord record, CancellationToken ct) => Task.CompletedTask;

    private static async Task UpsertDescriptionsAsync(NpgsqlConnection conn, Guid vulnerabilityId, Guid recordId, NvdStagingRecord record, CancellationToken ct)
    {
        foreach (var item in JsonNode.Parse(record.Descriptions)?.AsArray() ?? [])
        {
            await using var cmd = new NpgsqlCommand("""
                insert into vulnerability_descriptions
                  (vulnerability_id, vulnerability_record_id, source_id, lang, description_type, value, is_selected)
                values ($1,$2,$3,$4,'detail',$5,$6)
                on conflict (vulnerability_id, source_id, lang, description_type)
                do update set value = excluded.value, is_selected = excluded.is_selected
                """, conn);
            cmd.Parameters.AddWithValue(vulnerabilityId);
            cmd.Parameters.AddWithValue(recordId);
            cmd.Parameters.AddWithValue(record.SourceId);
            cmd.Parameters.AddWithValue(item?["lang"]?.GetValue<string>() ?? "und");
            cmd.Parameters.AddWithValue(item?["value"]?.GetValue<string>() ?? "");
            cmd.Parameters.AddWithValue(item?["lang"]?.GetValue<string>() == "en");
            await cmd.ExecuteNonQueryAsync(ct);
        }
    }

    private static async Task UpsertSeveritiesAsync(NpgsqlConnection conn, Guid vulnerabilityId, Guid recordId, NvdStagingRecord record, CancellationToken ct)
    {
        await DeleteRecordRowsAsync(conn, "vulnerability_severity_scores", recordId, ct);

        var scores = ExtractCvss(record.Metrics).ToList();
        var max = scores.OrderByDescending(x => x.Score).FirstOrDefault();
        foreach (var score in scores)
        {
            await using var cmd = new NpgsqlCommand("""
                insert into vulnerability_severity_scores
                  (vulnerability_id, vulnerability_record_id, source_id, raw_index_id, scoring_system, scoring_version,
                   score_type, vector_string, score, severity_label, normalized_severity, source_severity_label,
                   metric_json, is_selected)
                values ($1,$2,$3,$4,'cvss',$5,'base',$6,$7,$8,$8,$8,$9::jsonb,$10)
                """, conn);
            cmd.Parameters.AddWithValue(vulnerabilityId);
            cmd.Parameters.AddWithValue(recordId);
            cmd.Parameters.AddWithValue(record.SourceId);
            cmd.Parameters.AddWithValue(record.RawIndexId);
            cmd.Parameters.AddWithValue(score.Version);
            cmd.Parameters.AddWithValue((object?)score.Vector ?? DBNull.Value);
            cmd.Parameters.AddWithValue((object?)score.Score ?? DBNull.Value);
            cmd.Parameters.AddWithValue((object?)score.Severity ?? DBNull.Value);
            cmd.Parameters.AddWithValue(score.RawJson);
            cmd.Parameters.AddWithValue(max is not null && score.RawJson == max.RawJson);
            await cmd.ExecuteNonQueryAsync(ct);
        }
    }

    private static async Task UpsertWeaknessesAsync(NpgsqlConnection conn, Guid vulnerabilityId, Guid recordId, NvdStagingRecord record, CancellationToken ct)
    {
        foreach (var weakness in JsonNode.Parse(record.Weaknesses)?.AsArray() ?? [])
        {
            foreach (var desc in weakness?["description"]?.AsArray() ?? [])
            {
                var value = desc?["value"]?.GetValue<string>();
                await using var cmd = new NpgsqlCommand("""
                    insert into vulnerability_weaknesses
                      (vulnerability_id, vulnerability_record_id, source_id, weakness_type, weakness_id, description)
                    values ($1,$2,$3,'CWE',$4,$5)
                    on conflict (vulnerability_id, source_id, coalesce(weakness_id,'')) do nothing
                    """, conn);
                cmd.Parameters.AddWithValue(vulnerabilityId);
                cmd.Parameters.AddWithValue(recordId);
                cmd.Parameters.AddWithValue(record.SourceId);
                cmd.Parameters.AddWithValue((object?)value ?? DBNull.Value);
                cmd.Parameters.AddWithValue((object?)value ?? DBNull.Value);
                await cmd.ExecuteNonQueryAsync(ct);
            }
        }
    }

    private static async Task UpsertReferencesAsync(NpgsqlConnection conn, Guid vulnerabilityId, Guid recordId, NvdStagingRecord record, CancellationToken ct)
    {
        await DeleteRecordRowsAsync(conn, "vulnerability_references", recordId, ct);

        var references = (JsonNode.Parse(record.References)?.AsArray() ?? [])
            .Select(reference => new
            {
                Url = reference?["url"]?.GetValue<string>(),
                Tags = reference?["tags"]?.AsArray().Select(x => x?.GetValue<string>() ?? "").ToArray() ?? []
            })
            .Where(reference => !string.IsNullOrWhiteSpace(reference.Url))
            .DistinctBy(reference => reference.Url, StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (var reference in references)
        {
            await using var cmd = new NpgsqlCommand("""
                insert into vulnerability_references
                  (vulnerability_id, vulnerability_record_id, source_id, url, normalized_url, tags)
                values ($1,$2,$3,$4,$4,$5)
                """, conn);
            cmd.Parameters.AddWithValue(vulnerabilityId);
            cmd.Parameters.AddWithValue(recordId);
            cmd.Parameters.AddWithValue(record.SourceId);
            cmd.Parameters.AddWithValue(reference.Url!);
            cmd.Parameters.AddWithValue(reference.Tags);
            await cmd.ExecuteNonQueryAsync(ct);
        }
    }

    private static async Task<IReadOnlyList<AffectedFactDraft>> UpsertAffectedFactsAsync(NpgsqlConnection conn, Guid vulnerabilityId, Guid recordId, NvdStagingRecord record, CancellationToken ct)
    {
        await DeleteRecordRowsAsync(conn, "vulnerability_affected_facts", recordId, ct);

        var facts = new List<AffectedFactDraft>();
        var extracted = new List<NvdCpeFact>();
        foreach (var cpeMatch in WalkCpeMatches(JsonNode.Parse(record.Configurations)))
        {
            var criteria = cpeMatch?["criteria"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(criteria)) continue;
            var product = ParseProduct(criteria);
            var versionRange = ExtractCpeVersionRange(cpeMatch);
            var rangeType = versionRange is not null ? "cpe_match" : "cpe_match_no_range";
            var vulnerable = cpeMatch?["vulnerable"]?.GetValue<bool>() ?? true;
            var sourceSpecificJson = cpeMatch?.ToJsonString() ?? "{}";
            extracted.Add(new NvdCpeFact(criteria, product, versionRange, rangeType, vulnerable, sourceSpecificJson));
            if (vulnerable)
            {
                facts.Add(new AffectedFactDraft("cpe", "cpe", product, null, versionRange, rangeType, sourceSpecificJson, criteria));
            }
        }

        foreach (var batch in extracted.Chunk(1000))
        {
            var values = new List<string>();
            var parameters = new List<object>();
            var parameterIndex = 1;
            foreach (var fact in batch)
            {
                values.Add($"(${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},'cpe','cpe',${parameterIndex++},${parameterIndex++},lower(${parameterIndex - 1}),${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++}::jsonb)");
                parameters.Add(vulnerabilityId);
                parameters.Add(recordId);
                parameters.Add(record.SourceId);
                parameters.Add(record.RawIndexId);
                parameters.Add(fact.Criteria);
                parameters.Add(fact.Product);
                parameters.Add((object?)fact.VersionRange ?? DBNull.Value);
                parameters.Add(fact.RangeType);
                parameters.Add(fact.Vulnerable);
                parameters.Add(fact.SourceSpecificJson);
            }

            await using var cmd = new NpgsqlCommand($"""
                insert into vulnerability_affected_facts
                  (vulnerability_id, vulnerability_record_id, source_id, raw_index_id, fact_type, ecosystem,
                   cpe23_uri, package_name, normalized_package_name, version_range_raw, range_type, vulnerable,
                   source_specific)
                values {string.Join(",", values)}
                """, conn);
            foreach (var parameter in parameters) cmd.Parameters.AddWithValue(parameter);
            await cmd.ExecuteNonQueryAsync(ct);
        }

        return facts;
    }

    private static async Task DeleteRecordRowsAsync(NpgsqlConnection conn, string tableName, Guid recordId, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand($"delete from {tableName} where vulnerability_record_id = $1", conn);
        cmd.Parameters.AddWithValue(recordId);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static string? ExtractCpeVersionRange(JsonNode? cpeMatch)
    {
        if (cpeMatch is null) return null;
        var parts = new List<string>();
        var startInc = cpeMatch["versionStartIncluding"]?.GetValue<string>();
        var startExc = cpeMatch["versionStartExcluding"]?.GetValue<string>();
        var endInc = cpeMatch["versionEndIncluding"]?.GetValue<string>();
        var endExc = cpeMatch["versionEndExcluding"]?.GetValue<string>();

        if (!string.IsNullOrWhiteSpace(startInc)) parts.Add($">= {startInc}");
        if (!string.IsNullOrWhiteSpace(startExc)) parts.Add($"> {startExc}");
        if (!string.IsNullOrWhiteSpace(endInc)) parts.Add($"<= {endInc}");
        if (!string.IsNullOrWhiteSpace(endExc)) parts.Add($"< {endExc}");

        return parts.Count > 0 ? string.Join(", ", parts) : null;
    }

    private static async Task MarkNormalizedAsync(NpgsqlConnection conn, IReadOnlyList<Guid> rawIndexIds, CancellationToken ct)
    {
        if (rawIndexIds.Count == 0) return;
        await using var cmd = new NpgsqlCommand("""
            update source_raw_index
            set normalize_status = 'succeeded',
                status = case when status = 'priority' then 'normalized' else status end,
                updated_at = now()
            where id = any($1)
            """, conn);
        cmd.Parameters.AddWithValue(rawIndexIds.ToArray());
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public static IEnumerable<CvssScore> ExtractCvss(string metricsJson)
    {
        var metrics = JsonNode.Parse(metricsJson);
        if (metrics is null) yield break;
        foreach (var (property, version) in new[] {
            ("cvssMetricV40", "4.0"),
            ("cvssMetricV31", "3.1"),
            ("cvssMetricV30", "3.0"),
            ("cvssMetricV2", "2.0")
        })
        {
            foreach (var metric in metrics[property]?.AsArray() ?? [])
            {
                var data = metric?["cvssData"];
                yield return new CvssScore(
                    version,
                    data?["vectorString"]?.GetValue<string>(),
                    data?["baseScore"]?.GetValue<decimal?>(),
                    data?["baseSeverity"]?.GetValue<string>() ?? metric?["baseSeverity"]?.GetValue<string>(),
                    metric?.ToJsonString() ?? "{}");
            }
        }
    }

    private static IEnumerable<JsonNode?> WalkCpeMatches(JsonNode? configurations)
    {
        if (configurations is null) yield break;
        foreach (var config in configurations.AsArray())
        {
            foreach (var node in config?["nodes"]?.AsArray() ?? [])
            {
                foreach (var match in WalkNode(node)) yield return match;
            }
        }
    }

    private static IEnumerable<JsonNode?> WalkNode(JsonNode? node)
    {
        foreach (var match in node?["cpeMatch"]?.AsArray() ?? []) yield return match;
        foreach (var child in node?["children"]?.AsArray() ?? [])
        {
            foreach (var match in WalkNode(child)) yield return match;
        }
    }

    private static string ParseProduct(string cpe)
    {
        var parts = cpe.Split(':');
        return parts.Length > 4 ? parts[4].Replace("\\", "") : cpe;
    }

    private sealed record NvdNormalizationDraft(
        NvdStagingRecord Record,
        VulnerabilityCanonicalDraft CanonicalDraft,
        IReadOnlyList<DescriptionDraft> Descriptions,
        IReadOnlyList<SeverityScoreDraft> Severities,
        IReadOnlyList<WeaknessDraft> Weaknesses,
        IReadOnlyList<ReferenceDraft> References,
        IReadOnlyList<NvdAffectedFactDraft> AffectedFacts,
        IReadOnlyList<AffectedFactDraft> VulnerableAffectedFacts);

    private sealed record NvdCanonicalizedDraft(NvdNormalizationDraft Draft, Guid VulnerabilityId);

    private sealed record NvdAffectedFactDraft(
        string Criteria,
        string Product,
        string? VersionRange,
        string RangeType,
        bool Vulnerable,
        string SourceSpecificJson);

    private sealed record NvdAffectedFactRow(
        Guid VulnerabilityId,
        Guid VulnerabilityRecordId,
        Guid SourceId,
        Guid RawIndexId,
        NvdAffectedFactDraft Fact);

    private sealed record NvdSeveritySelection(
        Guid VulnerabilityId,
        Guid SourceId,
        decimal? Score,
        string? Version,
        string? Vector,
        string? Label);
}

public sealed record NvdStagingRecord(
    Guid RawIndexId,
    string CveId,
    string? Status,
    string Descriptions,
    string Metrics,
    string Weaknesses,
    string Configurations,
    string References,
    DateTimeOffset? PublishedAt,
    DateTimeOffset? ModifiedAt,
    string Payload,
    Guid SourceId);

public sealed record CvssScore(string Version, string? Vector, decimal? Score, string? Severity, string RawJson);

public sealed record NvdCpeFact(
    string Criteria,
    string Product,
    string? VersionRange,
    string RangeType,
    bool Vulnerable,
    string SourceSpecificJson);
