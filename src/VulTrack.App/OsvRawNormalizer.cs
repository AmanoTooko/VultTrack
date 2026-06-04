using System.Text.Json.Nodes;
using System.Diagnostics;
using Npgsql;

namespace VulTrack.App;

public sealed class OsvRawNormalizer(IEnumerable<IAffectedComponentHook> affectedHooks, IVulnerabilityCanonicalizer canonicalizer, ILogger<OsvRawNormalizer> logger)
    : NormalizerBase(affectedHooks, canonicalizer), ISourceScopedRawNormalizer
{
    public string SourceCode => "osv-family";
    public IReadOnlySet<string> SupportedSourceCodes { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "ubuntu-osv",
        "android-osv",
        "android-osv-init",
        "google-osv",
        "google-osv-init",
        "go-advisory",
        "cargo-advisory",
        "maven-osv",
        "maven-osv-init",
        "osv",
        "osv-init"
    };

    private static readonly (string Table, string SourceCode)[] Tables =
    [
        ("stg_ubuntu_osv", "ubuntu-osv"),
        ("stg_android_osv", "android-osv"),
        ("stg_android_osv", "android-osv-init"),
        ("stg_android_osv", "google-osv"),
        ("stg_osv_vulnerabilities", "google-osv"),
        ("stg_osv_vulnerabilities", "google-osv-init"),
        ("stg_osv_vulnerabilities", "go-advisory"),
        ("stg_osv_vulnerabilities", "cargo-advisory"),
        ("stg_osv_vulnerabilities", "maven-osv"),
        ("stg_osv_vulnerabilities", "maven-osv-init"),
        ("stg_osv_vulnerabilities", "osv"),
        ("stg_osv_vulnerabilities", "osv-init")
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
                with pending_raw as materialized (
                    select id, source_id
                    from (
                        select r.id, r.source_id, r.updated_at
                        from source_raw_index r
                        where r.normalize_status = 'pending'
                          and r.source_id = (select id from sources where code = $1)
                        order by r.updated_at, r.id
                        limit $2
                    ) pending
                    union all
                    select id, source_id
                    from (
                        select r.id, r.source_id, r.updated_at
                        from source_raw_index r
                        where r.normalize_status = 'failed'
                          and r.source_id = (select id from sources where code = $1)
                        order by r.updated_at, r.id
                        limit $2
                    ) failed
                    limit $2
                )
                select s.raw_index_id, s.osv_id, s.aliases, s.payload, r.source_id
                from pending_raw r
                join {table} s on s.raw_index_id = r.id
                order by s.raw_index_id
                """, connection);
            select.Parameters.AddWithValue(tableSourceCode);
            select.Parameters.AddWithValue(Math.Max(1, limit - processed));

            var rows = new List<(Guid RawIndexId, string OsvId, string[] Aliases, string Payload, Guid SourceId)>();
            await using (var reader = await select.ExecuteReaderAsync(ct))
            {
                while (await reader.ReadAsync(ct))
                {
                    rows.Add((
                        reader.GetGuid(0),
                        reader.GetString(1),
                        reader.GetFieldValue<string[]>(2),
                        reader.GetString(3),
                        reader.GetGuid(4)));
                }
            }

            var drafts = new List<OsvNormalizationDraft>();
            foreach (var row in rows)
            {
                try
                {
                    var payload = JsonNode.Parse(row.Payload);
                    var identifiers = IdentifiersFrom([row.OsvId], row.Aliases);
                    var primary = identifiers.FirstOrDefault(x => x.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)) ?? row.OsvId;
                    var title = payload?["summary"]?.GetValue<string>();
                    var description = payload?["details"]?.GetValue<string>() ?? title;
                    var draft = new VulnerabilityCanonicalDraft(primary, title, description, "active", DateValue(payload, "published"), DateValue(payload, "modified"), identifiers, row.SourceId, row.RawIndexId);
                    drafts.Add(new OsvNormalizationDraft(
                        row.RawIndexId,
                        row.OsvId,
                        row.SourceId,
                        row.Payload,
                        draft,
                        SourceFactExtractor.Descriptions(title, description),
                        SourceFactExtractor.OsvSeverities(payload?["severity"]),
                        SourceFactExtractor.References(payload?["references"]),
                        ExtractAffectedFacts(payload).ToList()));
                }
                catch
                {
                    failed++;
                }
            }

            if (drafts.Count > 0)
            {
                var resolveWatch = Stopwatch.StartNew();
                var cache = await Canonicalizer.ResolveCanonicalIdsBatchAsync(connection, drafts.Select(x => x.CanonicalDraft).ToList(), ct);
                resolveWatch.Stop();
                var canonicalized = new List<OsvCanonicalizedDraft>();
                var canonicalWatch = Stopwatch.StartNew();
                foreach (var draft in drafts)
                {
                    try
                    {
                        var vulnerabilityId = await Canonicalizer.GetOrCreateCanonicalAsync(connection, draft.CanonicalDraft, cache, ct);
                        canonicalized.Add(new OsvCanonicalizedDraft(draft, vulnerabilityId));
                    }
                    catch
                    {
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
                logger.LogInformation("OSV normalize {SourceCode}: parsed={Parsed}, canonicalized={Canonicalized}, resolve_ms={ResolveMs}, canonical_ms={CanonicalMs}.",
                    tableSourceCode, drafts.Count, canonicalized.Count, resolveWatch.ElapsedMilliseconds, canonicalWatch.ElapsedMilliseconds);
                if (remapped > 0)
                {
                    logger.LogInformation("OSV normalize {SourceCode}: remapped {Remapped} in-batch canonical ids after merges in {RemapMs} ms.",
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

    private async Task<(int Processed, int Failed, IReadOnlyList<Guid> SucceededRawIndexIds)> ProcessCanonicalizedBatchAsync(NpgsqlConnection connection, IReadOnlyList<OsvCanonicalizedDraft> canonicalized, CancellationToken ct)
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
                    throw new InvalidOperationException($"Missing vulnerability record id for OSV raw {item.Draft.RawIndexId}");

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
            logger.LogInformation("OSV batch write count={Count}: records_ms={RecordsMs}, descriptions_ms={DescriptionsMs}, severities_ms={SeveritiesMs}, references_ms={ReferencesMs}, affected_ms={AffectedMs}, flush_ms={FlushMs}.",
                canonicalized.Count, recordsMs, descriptionsMs, severitiesMs, referencesMs, affectedMs, flushMs);
            return (canonicalized.Count, 0, succeededIds);
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.DeadlockDetected && attempt == 1)
        {
            logger.LogWarning(ex, "OSV batch normalize deadlocked for {Count} records; retrying batch once.", canonicalized.Count);
            await Task.Delay(500, ct);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "OSV batch normalize failed for {Count} records; falling back to per-record writes.", canonicalized.Count);
            return await ProcessCanonicalizedIndividuallyAsync(connection, canonicalized, ct);
        }
        }

        return await ProcessCanonicalizedIndividuallyAsync(connection, canonicalized, ct);
    }

    private async Task<(int Processed, int Failed, IReadOnlyList<Guid> SucceededRawIndexIds)> ProcessCanonicalizedIndividuallyAsync(NpgsqlConnection connection, IReadOnlyList<OsvCanonicalizedDraft> canonicalized, CancellationToken ct)
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
            catch
            {
                failed++;
            }
        }

        await FlushAffectedProjectionsAsync(connection, affectedVulnIds, ct);
        return (processed, failed, succeededIds);
    }

    private static IEnumerable<AffectedFactDraft> ExtractAffectedFacts(JsonNode? payload)
    {
        foreach (var affected in payload?["affected"]?.AsArray() ?? [])
        {
            var package = affected?["package"];
            var ecosystem = package?["ecosystem"]?.GetValue<string>();
            var name = package?["name"]?.GetValue<string>();
            var purl = package?["purl"]?.GetValue<string>() ?? ToPurl(ecosystem, name);
            foreach (var range in affected?["ranges"]?.AsArray() ?? [])
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
                yield return new AffectedFactDraft("package", ecosystem, name, purl, rawRange, range?["type"]?.GetValue<string>(), affected?.ToJsonString() ?? "{}");
            }
            if (affected?["ranges"] is null && !string.IsNullOrWhiteSpace(name))
            {
                yield return new AffectedFactDraft("package", ecosystem, name, purl, null, null, affected?.ToJsonString() ?? "{}");
            }
        }
    }

    private static string? ToPurl(string? ecosystem, string? name)
    {
        if (string.IsNullOrWhiteSpace(ecosystem) || string.IsNullOrWhiteSpace(name)) return null;
        return ecosystem.ToLowerInvariant() switch
        {
            "npm" => $"pkg:npm/{Uri.EscapeDataString(name)}",
            "pypi" => $"pkg:pypi/{Uri.EscapeDataString(name.ToLowerInvariant())}",
            "maven" when name.Contains(':') => $"pkg:maven/{Uri.EscapeDataString(name.Split(':')[0])}/{Uri.EscapeDataString(name.Split(':')[1])}",
            "nuget" => $"pkg:nuget/{Uri.EscapeDataString(name)}",
            "go" => $"pkg:golang/{name}",
            _ => null
        };
    }

    private sealed record OsvNormalizationDraft(
        Guid RawIndexId,
        string SourceRecordId,
        Guid SourceId,
        string Payload,
        VulnerabilityCanonicalDraft CanonicalDraft,
        IReadOnlyList<DescriptionDraft> Descriptions,
        IReadOnlyList<SeverityScoreDraft> Severities,
        IReadOnlyList<ReferenceDraft> References,
        IReadOnlyList<AffectedFactDraft> AffectedFacts);

    private sealed record OsvCanonicalizedDraft(OsvNormalizationDraft Draft, Guid VulnerabilityId);
}
