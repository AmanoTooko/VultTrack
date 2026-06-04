using System.Text.Json.Nodes;
using System.Diagnostics;
using Npgsql;

namespace VulTrack.App;

public sealed class PypiRawNormalizer(
    IEnumerable<IAffectedComponentHook> affectedHooks,
    IVulnerabilityCanonicalizer canonicalizer,
    ILogger<PypiRawNormalizer> logger)
    : NormalizerBase(affectedHooks, canonicalizer), ISourceScopedRawNormalizer
{
    public string SourceCode => "pypi-advisory";
    public IReadOnlySet<string> SupportedSourceCodes { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "pypi-advisory" };

    public async Task<NormalizeBatchResult> ProcessPendingAsync(NpgsqlConnection connection, int limit, CancellationToken ct)
        => await ProcessSourcePendingAsync(connection, SourceCode, limit, ct);

    public async Task<NormalizeBatchResult> ProcessSourcePendingAsync(NpgsqlConnection connection, string sourceCode, int limit, CancellationToken ct)
    {
        await using var select = new NpgsqlCommand("""
            select s.raw_index_id, s.pysec_id, s.aliases, s.package_name, s.summary, s.details,
                   s.affected, s.published_at, s.modified_at, s.payload, r.source_id
            from stg_pypi_advisories s
            join source_raw_index r on r.id = s.raw_index_id
            join sources src on src.id = r.source_id
            where r.normalize_status in ('pending', 'failed') and src.code = $1
            order by r.updated_at
            limit $2
            """, connection);
        select.Parameters.AddWithValue(sourceCode);
        select.Parameters.AddWithValue(Math.Max(1, limit));

        var rows = new List<Row>();
        await using (var reader = await select.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            {
                rows.Add(new Row(
                    reader.GetGuid(0),
                    reader.GetString(1),
                    reader.GetFieldValue<string[]>(2),
                    reader.IsDBNull(3) ? null : reader.GetString(3),
                    reader.IsDBNull(4) ? null : reader.GetString(4),
                    reader.IsDBNull(5) ? null : reader.GetString(5),
                    reader.GetString(6),
                    reader.IsDBNull(7) ? null : reader.GetFieldValue<DateTimeOffset>(7),
                    reader.IsDBNull(8) ? null : reader.GetFieldValue<DateTimeOffset>(8),
                    reader.GetString(9),
                    reader.GetGuid(10)));
            }
        }

        var processed = 0;
        var failed = 0;
        var drafts = new List<PypiNormalizationDraft>();
        foreach (var row in rows)
        {
            try
            {
                var identifiers = IdentifiersFrom([row.PysecId], row.Aliases);
                var primary = identifiers.FirstOrDefault(x => x.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)) ?? row.PysecId;
                var title = row.Summary ?? row.PysecId;
                var payload = JsonNode.Parse(row.Payload);
                drafts.Add(new PypiNormalizationDraft(
                    row.RawIndexId,
                    row.PysecId,
                    row.SourceId,
                    new VulnerabilityCanonicalDraft(primary, title, row.Details ?? title, "active", row.PublishedAt, row.ModifiedAt, identifiers, row.SourceId, row.RawIndexId),
                    SourceFactExtractor.Descriptions(row.Summary, row.Details),
                    SourceFactExtractor.OsvSeverities(payload?["severity"]),
                    SourceFactExtractor.References(payload?["references"]),
                    ExtractAffectedFacts(row).ToList()));
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to parse PyPI advisory {PysecId} from raw {RawIndexId}", row.PysecId, row.RawIndexId);
                failed++;
            }
        }

        if (drafts.Count > 0)
        {
            var resolveWatch = Stopwatch.StartNew();
            var cache = await Canonicalizer.ResolveCanonicalIdsBatchAsync(connection, drafts.Select(x => x.CanonicalDraft).ToList(), ct);
            resolveWatch.Stop();

            var canonicalized = new List<PypiCanonicalizedDraft>();
            var canonicalWatch = Stopwatch.StartNew();
            foreach (var draft in drafts)
            {
                try
                {
                    var vulnerabilityId = await Canonicalizer.GetOrCreateCanonicalAsync(connection, draft.CanonicalDraft, cache, ct);
                    canonicalized.Add(new PypiCanonicalizedDraft(draft, vulnerabilityId));
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "Failed to canonicalize PyPI advisory {PysecId} from raw {RawIndexId}", draft.SourceRecordId, draft.RawIndexId);
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

            logger.LogInformation("PyPI normalize: parsed={Parsed}, canonicalized={Canonicalized}, resolve_ms={ResolveMs}, canonical_ms={CanonicalMs}.",
                drafts.Count, canonicalized.Count, resolveWatch.ElapsedMilliseconds, canonicalWatch.ElapsedMilliseconds);
            if (remapped > 0)
            {
                logger.LogInformation("PyPI normalize: remapped {Remapped} in-batch canonical ids after merges in {RemapMs} ms.",
                    remapped, remapWatch.ElapsedMilliseconds);
            }

            var batchResult = await ProcessCanonicalizedBatchAsync(connection, canonicalized, ct);
            processed += batchResult.Processed;
            failed += batchResult.Failed;
            await MarkNormalizedBatchAsync(connection, batchResult.SucceededRawIndexIds, ct);
        }

        return new NormalizeBatchResult(SourceCode, processed, failed);
    }

    private async Task<(int Processed, int Failed, IReadOnlyList<Guid> SucceededRawIndexIds)> ProcessCanonicalizedBatchAsync(
        NpgsqlConnection connection,
        IReadOnlyList<PypiCanonicalizedDraft> canonicalized,
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
                var succeededIds = new List<Guid>();

                foreach (var item in canonicalized)
                {
                    var key = (item.Draft.SourceId, item.Draft.SourceRecordId, item.Draft.RawIndexId);
                    if (!recordIds.TryGetValue(key, out var recordId))
                        throw new InvalidOperationException($"Missing vulnerability record id for PyPI raw {item.Draft.RawIndexId}");

                    descriptionItems.Add(new DescriptionBatchItem(item.VulnerabilityId, recordId, item.Draft.SourceId, item.Draft.Descriptions));
                    severityItems.Add(new SeverityScoreBatchItem(item.VulnerabilityId, recordId, item.Draft.SourceId, item.Draft.RawIndexId, item.Draft.Severities));
                    referenceItems.Add(new ReferenceBatchItem(item.VulnerabilityId, recordId, item.Draft.SourceId, item.Draft.References));
                    affectedItems.Add(new AffectedFactBatchItem(item.VulnerabilityId, recordId, item.Draft.SourceId, item.Draft.RawIndexId, item.Draft.AffectedFacts));
                    if (item.Draft.AffectedFacts.Count > 0) affectedVulnIds.Add(item.VulnerabilityId);
                    succeededIds.Add(item.Draft.RawIndexId);
                }

                watch.Restart();
                await InsertDescriptionsBatchAsync(connection, descriptionItems, ct);
                var descriptionsMs = watch.ElapsedMilliseconds;
                watch.Restart();
                await InsertSeverityScoresBatchAsync(connection, severityItems, ct);
                var severitiesMs = watch.ElapsedMilliseconds;
                watch.Restart();
                await InsertReferencesBatchAsync(connection, referenceItems, ct);
                var referencesMs = watch.ElapsedMilliseconds;
                watch.Restart();
                await InsertAffectedFactsBatchAsync(connection, affectedItems, ct);
                var affectedMs = watch.ElapsedMilliseconds;
                watch.Restart();
                await FlushAffectedProjectionsAsync(connection, affectedVulnIds, ct);
                var flushMs = watch.ElapsedMilliseconds;
                logger.LogInformation("PyPI batch write count={Count}: records_ms={RecordsMs}, descriptions_ms={DescriptionsMs}, severities_ms={SeveritiesMs}, references_ms={ReferencesMs}, affected_ms={AffectedMs}, flush_ms={FlushMs}.",
                    canonicalized.Count, recordsMs, descriptionsMs, severitiesMs, referencesMs, affectedMs, flushMs);

                return (canonicalized.Count, 0, succeededIds);
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.DeadlockDetected && attempt == 1)
            {
                logger.LogWarning(ex, "PyPI batch normalize deadlocked for {Count} records; retrying batch once.", canonicalized.Count);
                await Task.Delay(500, ct);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "PyPI batch normalize failed for {Count} records; falling back to per-record writes.", canonicalized.Count);
                return await ProcessCanonicalizedIndividuallyAsync(connection, canonicalized, ct);
            }
        }

        return await ProcessCanonicalizedIndividuallyAsync(connection, canonicalized, ct);
    }

    private async Task<(int Processed, int Failed, IReadOnlyList<Guid> SucceededRawIndexIds)> ProcessCanonicalizedIndividuallyAsync(
        NpgsqlConnection connection,
        IReadOnlyList<PypiCanonicalizedDraft> canonicalized,
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
                var recordId = await UpsertRecordAsync(connection, item.VulnerabilityId, draft.SourceId, draft.RawIndexId, draft.SourceRecordId, draft.CanonicalDraft.Title, draft.CanonicalDraft.Description, "active", ct);
                await UpsertIdentifiersAsync(connection, item.VulnerabilityId, draft.SourceId, draft.RawIndexId, draft.CanonicalDraft.Identifiers, ct);
                await InsertDescriptionsAsync(connection, item.VulnerabilityId, recordId, draft.SourceId, draft.Descriptions, ct);
                await InsertSeverityScoresAsync(connection, item.VulnerabilityId, recordId, draft.SourceId, draft.RawIndexId, draft.Severities, ct);
                await InsertReferencesAsync(connection, item.VulnerabilityId, recordId, draft.SourceId, draft.References, ct);
                await InsertAffectedFactsAsync(connection, item.VulnerabilityId, recordId, draft.SourceId, draft.RawIndexId, draft.AffectedFacts, ct);
                if (draft.AffectedFacts.Count > 0) affectedVulnIds.Add(item.VulnerabilityId);
                succeededIds.Add(draft.RawIndexId);
                processed++;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to write PyPI advisory {PysecId} from raw {RawIndexId}", item.Draft.SourceRecordId, item.Draft.RawIndexId);
                failed++;
            }
        }

        await FlushAffectedProjectionsAsync(connection, affectedVulnIds, ct);
        return (processed, failed, succeededIds);
    }

    private static IEnumerable<AffectedFactDraft> ExtractAffectedFacts(Row row)
    {
        var affected = JsonNode.Parse(row.Affected)?.AsArray() ?? [];
        foreach (var item in affected)
        {
            var name = item?["package"]?["name"]?.GetValue<string>() ?? row.PackageName;
            if (string.IsNullOrWhiteSpace(name)) continue;
            var purl = $"pkg:pypi/{Uri.EscapeDataString(name.ToLowerInvariant())}";
            foreach (var range in item?["ranges"]?.AsArray() ?? [])
            {
                var events = range?["events"]?.AsArray();
                var introduced = events?.FirstOrDefault(x => x?["introduced"] is not null)?["introduced"]?.GetValue<string>();
                var fixedVersion = events?.FirstOrDefault(x => x?["fixed"] is not null)?["fixed"]?.GetValue<string>();
                string? rawRange;
                if (introduced is not null && fixedVersion is not null)
                    rawRange = $">= {introduced}, < {fixedVersion}";
                else if (fixedVersion is not null)
                    rawRange = $"< {fixedVersion}";
                else if (introduced is not null)
                    rawRange = $">= {introduced}";
                else
                    rawRange = range?.ToJsonString();
                yield return new AffectedFactDraft("package", "PyPI", name, purl, rawRange, range?["type"]?.GetValue<string>(), item?.ToJsonString() ?? "{}");
            }
        }

        if (affected.Count == 0 && !string.IsNullOrWhiteSpace(row.PackageName))
        {
            yield return new AffectedFactDraft("package", "PyPI", row.PackageName, $"pkg:pypi/{Uri.EscapeDataString(row.PackageName.ToLowerInvariant())}", null, null, row.Payload);
        }
    }

    private sealed record PypiNormalizationDraft(
        Guid RawIndexId,
        string SourceRecordId,
        Guid SourceId,
        VulnerabilityCanonicalDraft CanonicalDraft,
        IReadOnlyList<DescriptionDraft> Descriptions,
        IReadOnlyList<SeverityScoreDraft> Severities,
        IReadOnlyList<ReferenceDraft> References,
        IReadOnlyList<AffectedFactDraft> AffectedFacts);

    private sealed record PypiCanonicalizedDraft(PypiNormalizationDraft Draft, Guid VulnerabilityId);

    private sealed record Row(Guid RawIndexId, string PysecId, string[] Aliases, string? PackageName, string? Summary, string? Details, string Affected, DateTimeOffset? PublishedAt, DateTimeOffset? ModifiedAt, string Payload, Guid SourceId);
}
