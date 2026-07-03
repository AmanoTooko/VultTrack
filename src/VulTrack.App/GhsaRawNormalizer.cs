using System.Text.Json.Nodes;
using System.Diagnostics;
using Npgsql;

namespace VulTrack.App;

public sealed class GhsaRawNormalizer(
    IEnumerable<IAffectedComponentHook> affectedHooks,
    IVulnerabilityCanonicalizer canonicalizer,
    ILogger<GhsaRawNormalizer> logger)
    : NormalizerBase(affectedHooks, canonicalizer), ISourceScopedRawNormalizer
{
    public string SourceCode => "ghsa-family";
    public IReadOnlySet<string> SupportedSourceCodes { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "ghsa",
        "npm-advisory",
        "npm-audit"
    };

    private static readonly (string Table, string SourceCode)[] Tables =
    [
        ("stg_ghsa_advisories", "ghsa"),
        ("stg_npm_advisories", "npm-advisory"),
        ("stg_npm_advisories", "npm-audit")
    ];

    public async Task<NormalizeBatchResult> ProcessPendingAsync(NpgsqlConnection connection, int limit, CancellationToken ct)
        => await ProcessTablesAsync(connection, limit, null, ct);

    public Task<NormalizeBatchResult> ProcessSourcePendingAsync(NpgsqlConnection connection, string sourceCode, int limit, CancellationToken ct)
        => ProcessTablesAsync(connection, limit, sourceCode, ct);

    private async Task<NormalizeBatchResult> ProcessTablesAsync(NpgsqlConnection connection, int limit, string? requestedSourceCode, CancellationToken ct)
    {
        var processed = 0;
        var failed = 0;

        foreach (var (table, tableSourceCode) in Tables)
        {
            if (requestedSourceCode is not null && !string.Equals(tableSourceCode, requestedSourceCode, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            await using var select = new NpgsqlCommand($"""
                select s.raw_index_id, s.ghsa_id, s.cve_id, s.summary, s.description,
                       s.ecosystem, s.package_name, s.vulnerable_ranges, s.cvss, s.cwes,
                       s.references_json, s.payload, r.source_id
                from {table} s
                join source_raw_index r on r.id = s.raw_index_id
                join sources src on src.id = r.source_id
                where r.normalize_status in ('pending', 'failed') and src.code = $1
                order by r.updated_at
                limit $2
                """, connection);
            select.Parameters.AddWithValue(tableSourceCode);
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
                        reader.GetString(9),
                        reader.GetString(10),
                        reader.GetString(11),
                        reader.GetGuid(12)));
                }
            }

            var drafts = new List<GhsaNormalizationDraft>();
            foreach (var row in rows)
            {
                try
                {
                    var identifiers = IdentifiersFrom([row.GhsaId, row.CveId]);
                    var primary = row.CveId ?? row.GhsaId;
                    var payload = JsonNode.Parse(row.Payload);
                    drafts.Add(new GhsaNormalizationDraft(
                        row.RawIndexId,
                        row.GhsaId,
                        row.SourceId,
                        new VulnerabilityCanonicalDraft(primary, row.Summary, row.Description ?? row.Summary, "active", DateValue(payload, "published_at"), DateValue(payload, "updated_at"), identifiers, row.SourceId, row.RawIndexId),
                        SourceFactExtractor.Descriptions(row.Summary, row.Description),
                        SourceFactExtractor.CvssSeverities(JsonNode.Parse(row.Cvss)).ToList(),
                        SourceFactExtractor.References(JsonNode.Parse(row.References)),
                        SourceFactExtractor.Weaknesses(JsonNode.Parse(row.Cwes)),
                        ExtractAffectedFacts(row).ToList()));
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Failed to normalize GHSA record {GhsaId} from raw {RawIndexId}", row.GhsaId, row.RawIndexId);
                    failed++;
                }
            }

            if (drafts.Count > 0)
            {
                var resolveWatch = Stopwatch.StartNew();
                var cache = await Canonicalizer.ResolveCanonicalIdsBatchAsync(connection, drafts.Select(x => x.CanonicalDraft).ToList(), ct);
                resolveWatch.Stop();

                var canonicalized = new List<GhsaCanonicalizedDraft>();
                var canonicalWatch = Stopwatch.StartNew();
                foreach (var draft in drafts)
                {
                    try
                    {
                        var vulnerabilityId = await Canonicalizer.GetOrCreateCanonicalAsync(connection, draft.CanonicalDraft, cache, ct);
                        canonicalized.Add(new GhsaCanonicalizedDraft(draft, vulnerabilityId));
                    }
                    catch (Exception ex)
                    {
                        logger.LogWarning(ex, "Failed to canonicalize GHSA record {GhsaId} from raw {RawIndexId}", draft.SourceRecordId, draft.RawIndexId);
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

                logger.LogInformation("GHSA normalize {SourceCode}: parsed={Parsed}, canonicalized={Canonicalized}, resolve_ms={ResolveMs}, canonical_ms={CanonicalMs}.",
                    tableSourceCode, drafts.Count, canonicalized.Count, resolveWatch.ElapsedMilliseconds, canonicalWatch.ElapsedMilliseconds);
                if (remapped > 0)
                {
                    logger.LogInformation("GHSA normalize {SourceCode}: remapped {Remapped} in-batch canonical ids after merges in {RemapMs} ms.",
                        tableSourceCode, remapped, remapWatch.ElapsedMilliseconds);
                }

                var batchResult = await ProcessCanonicalizedBatchAsync(connection, canonicalized, ct);
                processed += batchResult.Processed;
                failed += batchResult.Failed;
                await MarkNormalizedBatchAsync(connection, batchResult.SucceededRawIndexIds, ct);
            }

            if (processed >= limit) break;
        }

        return new NormalizeBatchResult(SourceCode, processed, failed);
    }

    private async Task<(int Processed, int Failed, IReadOnlyList<Guid> SucceededRawIndexIds)> ProcessCanonicalizedBatchAsync(
        NpgsqlConnection connection,
        IReadOnlyList<GhsaCanonicalizedDraft> canonicalized,
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
                var weaknessItems = new List<WeaknessBatchItem>();
                var affectedItems = new List<AffectedFactBatchItem>();
                var affectedVulnIds = new List<Guid>();
                var succeededIds = new List<Guid>();

                foreach (var item in canonicalized)
                {
                    var key = (item.Draft.SourceId, item.Draft.SourceRecordId, item.Draft.RawIndexId);
                    if (!recordIds.TryGetValue(key, out var recordId))
                        throw new InvalidOperationException($"Missing vulnerability record id for GHSA raw {item.Draft.RawIndexId}");

                    descriptionItems.Add(new DescriptionBatchItem(item.VulnerabilityId, recordId, item.Draft.SourceId, item.Draft.Descriptions));
                    severityItems.Add(new SeverityScoreBatchItem(item.VulnerabilityId, recordId, item.Draft.SourceId, item.Draft.RawIndexId, item.Draft.Severities));
                    referenceItems.Add(new ReferenceBatchItem(item.VulnerabilityId, recordId, item.Draft.SourceId, item.Draft.References));
                    weaknessItems.Add(new WeaknessBatchItem(item.VulnerabilityId, recordId, item.Draft.SourceId, item.Draft.Weaknesses));
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
                await InsertWeaknessesBatchAsync(connection, weaknessItems, ct);
                var weaknessesMs = watch.ElapsedMilliseconds;
                watch.Restart();
                await InsertAffectedFactsBatchAsync(connection, affectedItems, ct);
                var affectedMs = watch.ElapsedMilliseconds;
                watch.Restart();
                await FlushAffectedProjectionsAsync(connection, affectedVulnIds, ct);
                var flushMs = watch.ElapsedMilliseconds;
                logger.LogInformation("GHSA batch write count={Count}: records_ms={RecordsMs}, descriptions_ms={DescriptionsMs}, severities_ms={SeveritiesMs}, references_ms={ReferencesMs}, weaknesses_ms={WeaknessesMs}, affected_ms={AffectedMs}, flush_ms={FlushMs}.",
                    canonicalized.Count, recordsMs, descriptionsMs, severitiesMs, referencesMs, weaknessesMs, affectedMs, flushMs);

                return (canonicalized.Count, 0, succeededIds);
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.DeadlockDetected && attempt == 1)
            {
                logger.LogWarning(ex, "GHSA batch normalize deadlocked for {Count} records; retrying batch once.", canonicalized.Count);
                await Task.Delay(500, ct);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "GHSA batch normalize failed for {Count} records; falling back to per-record writes.", canonicalized.Count);
                return await ProcessCanonicalizedIndividuallyAsync(connection, canonicalized, ct);
            }
        }

        return await ProcessCanonicalizedIndividuallyAsync(connection, canonicalized, ct);
    }

    private async Task<(int Processed, int Failed, IReadOnlyList<Guid> SucceededRawIndexIds)> ProcessCanonicalizedIndividuallyAsync(
        NpgsqlConnection connection,
        IReadOnlyList<GhsaCanonicalizedDraft> canonicalized,
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
                await InsertWeaknessesAsync(connection, item.VulnerabilityId, recordId, draft.SourceId, draft.Weaknesses, ct);
                await InsertAffectedFactsAsync(connection, item.VulnerabilityId, recordId, draft.SourceId, draft.RawIndexId, draft.AffectedFacts, ct);
                if (draft.AffectedFacts.Count > 0) affectedVulnIds.Add(item.VulnerabilityId);
                succeededIds.Add(draft.RawIndexId);
                processed++;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to write GHSA record {GhsaId} from raw {RawIndexId}", item.Draft.SourceRecordId, item.Draft.RawIndexId);
                failed++;
            }
        }

        await FlushAffectedProjectionsAsync(connection, affectedVulnIds, ct);
        return (processed, failed, succeededIds);
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

    private sealed record GhsaNormalizationDraft(
        Guid RawIndexId,
        string SourceRecordId,
        Guid SourceId,
        VulnerabilityCanonicalDraft CanonicalDraft,
        IReadOnlyList<DescriptionDraft> Descriptions,
        IReadOnlyList<SeverityScoreDraft> Severities,
        IReadOnlyList<ReferenceDraft> References,
        IReadOnlyList<WeaknessDraft> Weaknesses,
        IReadOnlyList<AffectedFactDraft> AffectedFacts);

    private sealed record GhsaCanonicalizedDraft(GhsaNormalizationDraft Draft, Guid VulnerabilityId);

    private sealed record Row(Guid RawIndexId, string GhsaId, string? CveId, string? Summary, string? Description, string? Ecosystem, string? PackageName, string VulnerableRanges, string Cvss, string Cwes, string References, string Payload, Guid SourceId);
}
