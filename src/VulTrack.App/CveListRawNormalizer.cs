using System.Text.Json.Nodes;
using System.Diagnostics;
using Npgsql;

namespace VulTrack.App;

public sealed class CveListRawNormalizer(
    IEnumerable<IAffectedComponentHook> affectedHooks,
    IVulnerabilityCanonicalizer canonicalizer,
    ILogger<CveListRawNormalizer> logger)
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
            where r.normalize_status in ('pending', 'failed') and src.code = 'cve-list-v5'
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
        var drafts = new List<CveListNormalizationDraft>();
        foreach (var row in rows)
        {
            try
            {
                var cna = JsonNode.Parse(row.ContainersCna);
                var identifiers = IdentifiersFrom([row.CveId]);
                var title = EnglishDescription(cna?["descriptions"]) ?? row.CveId;
                var status = string.Equals(row.State, "REJECTED", StringComparison.OrdinalIgnoreCase) ? "rejected" : "active";
                drafts.Add(new CveListNormalizationDraft(
                    row.RawIndexId,
                    row.CveId,
                    row.SourceId,
                    new VulnerabilityCanonicalDraft(row.CveId, title, title, status, row.PublishedAt, row.UpdatedAt, identifiers, row.SourceId, row.RawIndexId),
                    DescriptionDrafts(cna?["descriptions"]),
                    ReferenceDrafts(cna?["references"]),
                    ExtractAffectedFacts(cna).ToList()));
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to parse CVE List record {CveId} from raw {RawIndexId}", row.CveId, row.RawIndexId);
                failed++;
            }
        }

        if (drafts.Count > 0)
        {
            var resolveWatch = Stopwatch.StartNew();
            var cache = await Canonicalizer.ResolveCanonicalIdsBatchAsync(connection, drafts.Select(x => x.CanonicalDraft).ToList(), ct);
            resolveWatch.Stop();

            var canonicalized = new List<CveListCanonicalizedDraft>();
            var canonicalWatch = Stopwatch.StartNew();
            foreach (var draft in drafts)
            {
                try
                {
                    var vulnerabilityId = await Canonicalizer.GetOrCreateCanonicalAsync(connection, draft.CanonicalDraft, cache, ct);
                    canonicalized.Add(new CveListCanonicalizedDraft(draft, vulnerabilityId));
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "Failed to canonicalize CVE List record {CveId} from raw {RawIndexId}", draft.SourceRecordId, draft.RawIndexId);
                    failed++;
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

            logger.LogInformation("CVE List normalize: parsed={Parsed}, canonicalized={Canonicalized}, resolve_ms={ResolveMs}, canonical_ms={CanonicalMs}.",
                drafts.Count, canonicalized.Count, resolveWatch.ElapsedMilliseconds, canonicalWatch.ElapsedMilliseconds);
            if (remapped > 0)
            {
                logger.LogInformation("CVE List normalize: remapped {Remapped} in-batch canonical ids after merges in {RemapMs} ms.",
                    remapped, remapWatch.ElapsedMilliseconds);
            }

            var batchResult = await ProcessCanonicalizedBatchAsync(connection, canonicalized, ct);
            processed += batchResult.Processed;
            failed += batchResult.Failed;
            await MarkNormalizedBatchAsync(connection, batchResult.SucceededRawIndexIds, ct);
        }

        return new NormalizeBatchResult(SourceCode, processed, failed);
    }

    private static string? EnglishDescription(JsonNode? descriptions) =>
        descriptions?.AsArray().FirstOrDefault(x => string.Equals(x?["lang"]?.GetValue<string>(), "en", StringComparison.OrdinalIgnoreCase))?["value"]?.GetValue<string>()
        ?? descriptions?.AsArray().FirstOrDefault()?["value"]?.GetValue<string>();

    private async Task<(int Processed, int Failed, IReadOnlyList<Guid> SucceededRawIndexIds)> ProcessCanonicalizedBatchAsync(
        NpgsqlConnection connection,
        IReadOnlyList<CveListCanonicalizedDraft> canonicalized,
        CancellationToken ct)
    {
        if (canonicalized.Count == 0) return (0, 0, []);

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
                        item.Draft.CanonicalDraft.Title,
                        item.Draft.CanonicalDraft.Description,
                        item.Draft.CanonicalDraft.Status))
                    .ToList();

                var watch = Stopwatch.StartNew();
                var recordIds = await UpsertRecordsBatchAsync(connection, recordInputs, ct);
                var recordsMs = watch.ElapsedMilliseconds;
                var descriptionItems = new List<DescriptionBatchItem>();
                var referenceItems = new List<ReferenceBatchItem>();
                var affectedItems = new List<AffectedFactBatchItem>();
                var affectedVulnIds = new List<Guid>();
                var succeededIds = new List<Guid>();

                foreach (var item in canonicalized)
                {
                    var key = (item.Draft.SourceId, item.Draft.SourceRecordId, item.Draft.RawIndexId);
                    if (!recordIds.TryGetValue(key, out var recordId))
                        throw new InvalidOperationException($"Missing vulnerability record id for CVE List raw {item.Draft.RawIndexId}");

                    descriptionItems.Add(new DescriptionBatchItem(item.VulnerabilityId, recordId, item.Draft.SourceId, item.Draft.Descriptions));
                    referenceItems.Add(new ReferenceBatchItem(item.VulnerabilityId, recordId, item.Draft.SourceId, item.Draft.References));
                    affectedItems.Add(new AffectedFactBatchItem(item.VulnerabilityId, recordId, item.Draft.SourceId, item.Draft.RawIndexId, item.Draft.AffectedFacts));
                    if (item.Draft.AffectedFacts.Count > 0) affectedVulnIds.Add(item.VulnerabilityId);
                    succeededIds.Add(item.Draft.RawIndexId);
                }

                watch.Restart();
                await InsertDescriptionsBatchAsync(connection, descriptionItems, ct);
                var descriptionsMs = watch.ElapsedMilliseconds;
                watch.Restart();
                await InsertReferencesBatchAsync(connection, referenceItems, ct);
                var referencesMs = watch.ElapsedMilliseconds;
                watch.Restart();
                await InsertAffectedFactsBatchAsync(connection, affectedItems, ct);
                var affectedMs = watch.ElapsedMilliseconds;
                watch.Restart();
                await FlushAffectedProjectionsAsync(connection, affectedVulnIds, ct);
                var flushMs = watch.ElapsedMilliseconds;
                logger.LogInformation("CVE List batch write count={Count}: records_ms={RecordsMs}, descriptions_ms={DescriptionsMs}, references_ms={ReferencesMs}, affected_ms={AffectedMs}, flush_ms={FlushMs}.",
                    canonicalized.Count, recordsMs, descriptionsMs, referencesMs, affectedMs, flushMs);

                return (canonicalized.Count, 0, succeededIds);
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.DeadlockDetected && attempt == 1)
            {
                logger.LogWarning(ex, "CVE List batch normalize deadlocked for {Count} records; retrying batch once.", canonicalized.Count);
                await Task.Delay(500, ct);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "CVE List batch normalize failed for {Count} records; falling back to per-record writes.", canonicalized.Count);
                return await ProcessCanonicalizedIndividuallyAsync(connection, canonicalized, ct);
            }
        }

        return await ProcessCanonicalizedIndividuallyAsync(connection, canonicalized, ct);
    }

    private async Task<(int Processed, int Failed, IReadOnlyList<Guid> SucceededRawIndexIds)> ProcessCanonicalizedIndividuallyAsync(
        NpgsqlConnection connection,
        IReadOnlyList<CveListCanonicalizedDraft> canonicalized,
        CancellationToken ct)
    {
        var processed = 0;
        var failed = 0;
        var succeededIds = new List<Guid>();
        var affectedVulnIds = new List<Guid>();

        foreach (var item in canonicalized)
        {
            try
            {
                var draft = item.Draft;
                var recordId = await UpsertRecordAsync(connection, item.VulnerabilityId, draft.SourceId, draft.RawIndexId, draft.SourceRecordId, draft.CanonicalDraft.Title, draft.CanonicalDraft.Description, draft.CanonicalDraft.Status, ct);
                await InsertDescriptionsAsync(connection, item.VulnerabilityId, recordId, draft.SourceId, draft.Descriptions, ct);
                await InsertReferencesAsync(connection, item.VulnerabilityId, recordId, draft.SourceId, draft.References, ct);
                await InsertAffectedFactsAsync(connection, item.VulnerabilityId, recordId, draft.SourceId, draft.RawIndexId, draft.AffectedFacts, ct);
                if (draft.AffectedFacts.Count > 0) affectedVulnIds.Add(item.VulnerabilityId);
                succeededIds.Add(draft.RawIndexId);
                processed++;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to write CVE List record {CveId} from raw {RawIndexId}", item.Draft.SourceRecordId, item.Draft.RawIndexId);
                failed++;
            }
        }

        await FlushAffectedProjectionsAsync(connection, affectedVulnIds, ct);
        return (processed, failed, succeededIds);
    }

    private static IReadOnlyList<DescriptionDraft> DescriptionDrafts(JsonNode? descriptions)
    {
        var rows = new List<DescriptionDraft>();
        foreach (var desc in descriptions?.AsArray() ?? [])
        {
            var value = desc?["value"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(value)) continue;
            var lang = desc?["lang"]?.GetValue<string>() ?? "und";
            rows.Add(new DescriptionDraft(
                lang,
                "detail",
                value,
                string.Equals(lang, "en", StringComparison.OrdinalIgnoreCase)));
        }

        return rows;
    }

    private static IReadOnlyList<ReferenceDraft> ReferenceDrafts(JsonNode? references)
    {
        var rows = new List<ReferenceDraft>();
        foreach (var reference in references?.AsArray() ?? [])
        {
            var url = reference?["url"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(url)) continue;
            rows.Add(new ReferenceDraft(
                url,
                null,
                reference?["tags"]?.AsArray()
                    .Select(x => x?.GetValue<string>())
                    .Where(x => !string.IsNullOrWhiteSpace(x))
                    .Select(x => x!)
                    .ToArray() ?? []));
        }

        return rows;
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
                var lessThan = version?["lessThan"]?.GetValue<string>();
                var lessThanOrEqual = version?["lessThanOrEqual"]?.GetValue<string>();
                var exactVersion = version?["version"]?.GetValue<string>();
                string? rawRange;
                if (exactVersion is not null && lessThan is not null)
                    rawRange = $">= {exactVersion}, < {lessThan}";
                else if (exactVersion is not null && lessThanOrEqual is not null)
                    rawRange = $">= {exactVersion}, <= {lessThanOrEqual}";
                else if (lessThan is not null)
                    rawRange = $"< {lessThan}";
                else if (lessThanOrEqual is not null)
                    rawRange = $"<= {lessThanOrEqual}";
                else if (exactVersion is not null)
                    rawRange = $"= {exactVersion}";
                else
                    rawRange = version?.ToJsonString();
                yield return new AffectedFactDraft("package", null, name, null, rawRange, "cve-list", version?.ToJsonString() ?? "{}");
            }
        }
    }

    private sealed record CveListNormalizationDraft(
        Guid RawIndexId,
        string SourceRecordId,
        Guid SourceId,
        VulnerabilityCanonicalDraft CanonicalDraft,
        IReadOnlyList<DescriptionDraft> Descriptions,
        IReadOnlyList<ReferenceDraft> References,
        IReadOnlyList<AffectedFactDraft> AffectedFacts);

    private sealed record CveListCanonicalizedDraft(CveListNormalizationDraft Draft, Guid VulnerabilityId);

    private sealed record Row(Guid RawIndexId, string CveId, string CveMetadata, string ContainersCna, string ContainersAdp, string? State, DateTimeOffset? PublishedAt, DateTimeOffset? UpdatedAt, string Payload, Guid SourceId);
}
