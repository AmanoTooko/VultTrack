using System.Text.Json.Nodes;
using System.Diagnostics;
using Npgsql;

namespace VulTrack.App;

public sealed class EcosystemAdvisoryNormalizer(IEnumerable<IAffectedComponentHook> affectedHooks, IVulnerabilityCanonicalizer canonicalizer, ILogger<EcosystemAdvisoryNormalizer> logger)
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
            where r.normalize_status in ('pending', 'failed')
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

        var drafts = new List<EcosystemNormalizationDraft>();
        foreach (var row in rows)
        {
            try
            {
                var identifiers = IdentifiersFrom([row.AdvisoryId], row.Identifiers);
                var isCsaf = row.Provider is "suse-csaf" or "redhat-csaf";
                var cves = identifiers.Where(x => x.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)).ToArray();
                var payload = JsonNode.Parse(row.Payload);
                IEnumerable<string[]> identifierSets = isCsaf && cves.Length > 0 ? cves.Select(x => new[] { x }) : [identifiers];
                foreach (var identifierSet in identifierSets)
                {
                    var primary = identifierSet.FirstOrDefault(x => x.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)) ?? row.AdvisoryId;
                    var title = ExtractTitle(payload, isCsaf, row.AdvisoryId);
                    var description = ExtractDescription(payload, isCsaf, title);
                    var fullDraft = new VulnerabilityCanonicalDraft(primary, title, description, "active", row.PublishedAt, row.ModifiedAt, identifierSet, row.SourceId, row.RawIndexId);
                    var sourceRecordId = isCsaf ? $"{row.AdvisoryId}:{primary}" : row.AdvisoryId;
                    drafts.Add(new EcosystemNormalizationDraft(
                        row.RawIndexId,
                        sourceRecordId,
                        row.SourceId,
                        fullDraft,
                        SourceFactExtractor.Descriptions(title, description),
                        ExtractSeverities(payload, isCsaf, row.SeverityLabel, row.Payload, primary).ToList(),
                        SourceFactExtractor.References(JsonNode.Parse(row.ReferencesJson)),
                        ExtractAffectedFacts(row, payload, isCsaf, primary).ToList()));
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to parse ecosystem advisory {AdvisoryId} from raw {RawIndexId}", row.AdvisoryId, row.RawIndexId);
                failed++;
            }
        }

        if (drafts.Count > 0)
        {
            var resolveWatch = Stopwatch.StartNew();
            var cache = await Canonicalizer.ResolveCanonicalIdsBatchAsync(connection, drafts.Select(d => d.CanonicalDraft).ToList(), ct);
            resolveWatch.Stop();

            var canonicalized = new List<EcosystemCanonicalizedDraft>();
            var canonicalWatch = Stopwatch.StartNew();
            foreach (var draft in drafts)
            {
                try
                {
                    var vulnerabilityId = await Canonicalizer.GetOrCreateCanonicalAsync(connection, draft.CanonicalDraft, cache, ct);
                    canonicalized.Add(new EcosystemCanonicalizedDraft(draft, vulnerabilityId));
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "Failed to canonicalize ecosystem advisory {SourceRecordId} from raw {RawIndexId}", draft.SourceRecordId, draft.RawIndexId);
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

            logger.LogInformation("Ecosystem advisory normalize {SourceCode}: parsed={Parsed}, canonicalized={Canonicalized}, resolve_ms={ResolveMs}, canonical_ms={CanonicalMs}.",
                sourceCode ?? SourceCode, drafts.Count, canonicalized.Count, resolveWatch.ElapsedMilliseconds, canonicalWatch.ElapsedMilliseconds);
            if (remapped > 0)
            {
                logger.LogInformation("Ecosystem advisory normalize {SourceCode}: remapped {Remapped} in-batch canonical ids after merges in {RemapMs} ms.",
                    sourceCode ?? SourceCode, remapped, remapWatch.ElapsedMilliseconds);
            }

            var batchResult = await ProcessCanonicalizedBatchAsync(connection, canonicalized, ct);
            processed += batchResult.Processed;
            failed += batchResult.Failed;
            await MarkNormalizedBatchAsync(connection, batchResult.SucceededRawIndexIds, ct);
        }

        return new NormalizeBatchResult(sourceCode ?? SourceCode, processed, failed);
    }

    private async Task<(int Processed, int Failed, IReadOnlyList<Guid> SucceededRawIndexIds)> ProcessCanonicalizedBatchAsync(
        NpgsqlConnection connection,
        IReadOnlyList<EcosystemCanonicalizedDraft> canonicalized,
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
                        throw new InvalidOperationException($"Missing vulnerability record id for ecosystem advisory raw {item.Draft.RawIndexId}");

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
                logger.LogInformation("Ecosystem advisory batch write count={Count}: records_ms={RecordsMs}, descriptions_ms={DescriptionsMs}, severities_ms={SeveritiesMs}, references_ms={ReferencesMs}, affected_ms={AffectedMs}, flush_ms={FlushMs}.",
                    canonicalized.Count, recordsMs, descriptionsMs, severitiesMs, referencesMs, affectedMs, flushMs);

                return (canonicalized.Count, 0, succeededIds);
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.DeadlockDetected && attempt == 1)
            {
                logger.LogWarning(ex, "Ecosystem advisory batch normalize deadlocked for {Count} records; retrying batch once.", canonicalized.Count);
                await Task.Delay(500, ct);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Ecosystem advisory batch normalize failed for {Count} records; falling back to per-record writes.", canonicalized.Count);
                return await ProcessCanonicalizedIndividuallyAsync(connection, canonicalized, ct);
            }
        }

        return await ProcessCanonicalizedIndividuallyAsync(connection, canonicalized, ct);
    }

    private async Task<(int Processed, int Failed, IReadOnlyList<Guid> SucceededRawIndexIds)> ProcessCanonicalizedIndividuallyAsync(
        NpgsqlConnection connection,
        IReadOnlyList<EcosystemCanonicalizedDraft> canonicalized,
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
                logger.LogWarning(ex, "Failed to write ecosystem advisory {SourceRecordId} from raw {RawIndexId}", item.Draft.SourceRecordId, item.Draft.RawIndexId);
                failed++;
            }
        }

        await FlushAffectedProjectionsAsync(connection, affectedVulnIds, ct);
        return (processed, failed, succeededIds);
    }

    private static string ExtractTitle(JsonNode? payload, bool isCsaf, string fallback)
    {
        if (!isCsaf) return payload?["vulnerability"]?["summary"]?.GetValue<string>() ?? fallback;
        return payload?["document"]?["title"]?.GetValue<string>() ?? fallback;
    }

    private static string? ExtractDescription(JsonNode? payload, bool isCsaf, string title)
    {
        if (!isCsaf) return payload?["vulnerability"]?["details"]?.GetValue<string>() ?? title;
        var notes = payload?["document"]?["notes"]?.AsArray();
        if (notes is not null)
        {
            foreach (var note in notes)
            {
                var category = note?["category"]?.GetValue<string>();
                if (category is "description" or "summary" or "general")
                    return note?["text"]?.GetValue<string>() ?? title;
            }
        }
        return title;
    }

    private static IEnumerable<SeverityScoreDraft> ExtractSeverities(JsonNode? payload, bool isCsaf, string? severityLabel, string payloadJson, string? identifier = null)
    {
        if (!isCsaf)
        {
            foreach (var s in SourceFactExtractor.CvssSeverities(payload?["cvss"])) yield return s;
            foreach (var s in SourceFactExtractor.LabelSeverity(severityLabel, payloadJson)) yield return s;
            yield break;
        }

        var seen = false;
        foreach (var vuln in payload?["vulnerabilities"]?.AsArray() ?? [])
        {
            if (!string.IsNullOrWhiteSpace(identifier)
                && !string.Equals(vuln?["cve"]?.GetValue<string>(), identifier, StringComparison.OrdinalIgnoreCase))
                continue;
            foreach (var scoreEntry in vuln?["scores"]?.AsArray() ?? [])
            {
                var cvss = scoreEntry?["cvss_v3"] ?? scoreEntry?["cvss_v3_1"] ?? scoreEntry?["cvss_v3_0"] ?? scoreEntry?["cvss_v2"];
                if (cvss is null) continue;
                var vector = cvss["vectorString"]?.GetValue<string>();
                var score = cvss["baseScore"]?.GetValue<decimal?>();
                var label = cvss["baseSeverity"]?.GetValue<string>();
                if (vector is null && score is null && label is null) continue;
                seen = true;
                var version = vector?.StartsWith("CVSS:", StringComparison.OrdinalIgnoreCase) == true
                    ? vector["CVSS:".Length..vector.IndexOf('/')]
                    : cvss["version"]?.GetValue<string>();
                yield return new SeverityScoreDraft("cvss", version, "base", vector, score, label, cvss.ToJsonString());
            }
        }

        if (!seen && !string.IsNullOrWhiteSpace(severityLabel))
        {
            foreach (var s in SourceFactExtractor.LabelSeverity(severityLabel, payloadJson)) yield return s;
        }
    }

    private static IEnumerable<AffectedFactDraft> ExtractAffectedFacts(Row row, JsonNode? payload, bool isCsaf, string? identifier = null)
    {
        if (isCsaf)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var productSeen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var vuln in payload?["vulnerabilities"]?.AsArray() ?? [])
            {
                var cve = vuln?["cve"]?.GetValue<string>();
                if (!string.IsNullOrWhiteSpace(identifier)
                    && !string.Equals(cve, identifier, StringComparison.OrdinalIgnoreCase))
                    continue;
                var productStatus = vuln?["product_status"];
                var products = productStatus?["known_affected"]?.AsArray()
                    ?? productStatus?["recommended"]?.AsArray()
                    ?? productStatus?["first_fixed"]?.AsArray()
                    ?? [];
                foreach (var product in products)
                {
                    var productStr = product?.GetValue<string>();
                    if (string.IsNullOrWhiteSpace(productStr)) continue;
                    var productName = ParseSuseProductName(productStr);
                    if (string.IsNullOrWhiteSpace(productName)) continue;
                    var dedupeKey = productName;
                    if (!productSeen.Add(dedupeKey)) continue;
                    var ecosystem = DetectSuseEcosystem(productStr);
                    yield return new AffectedFactDraft("package", ecosystem, productName, null, productStr, "csaf-product", $"{{\"product\":{System.Text.Json.JsonSerializer.Serialize(productStr)}}}");
                }
            }
            yield break;
        }

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

    private static string ParseSuseProductName(string product)
    {
        if (string.IsNullOrWhiteSpace(product)) return product;
        var colonIdx = product.IndexOf(':');
        var name = colonIdx > 0 && colonIdx < product.Length - 1 ? product[(colonIdx + 1)..] : product;
        var parts = name.Split('-', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length <= 1) return name;
        var result = new List<string>();
        foreach (var part in parts)
        {
            if (char.IsDigit(part[0]) && part.Contains('.'))
                break;
            result.Add(part);
        }
        return result.Count > 0 ? string.Join("-", result) : name;
    }

    private static string DetectSuseEcosystem(string product)
    {
        var lower = product.ToLowerInvariant();
        if (lower.Contains("suse") || lower.Contains("opensuse") || lower.Contains("sles")) return "rpm";
        return "rpm";
    }

    private sealed record EcosystemNormalizationDraft(
        Guid RawIndexId,
        string SourceRecordId,
        Guid SourceId,
        VulnerabilityCanonicalDraft CanonicalDraft,
        IReadOnlyList<DescriptionDraft> Descriptions,
        IReadOnlyList<SeverityScoreDraft> Severities,
        IReadOnlyList<ReferenceDraft> References,
        IReadOnlyList<AffectedFactDraft> AffectedFacts);

    private sealed record EcosystemCanonicalizedDraft(EcosystemNormalizationDraft Draft, Guid VulnerabilityId);

    private sealed record Row(Guid RawIndexId, string Provider, string? Ecosystem, string AdvisoryId, string[] Identifiers, string? PackageName, string? Purl, string VulnerableRanges, string? SeverityLabel, DateTimeOffset? PublishedAt, DateTimeOffset? ModifiedAt, string ReferencesJson, string Payload, Guid SourceId);
}
