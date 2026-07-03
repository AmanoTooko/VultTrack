using System.Text.Json.Nodes;
using System.Diagnostics;
using Npgsql;

namespace VulTrack.App;

public sealed class DistroRawNormalizer(IEnumerable<IAffectedComponentHook> affectedHooks, IVulnerabilityCanonicalizer canonicalizer, ILogger<DistroRawNormalizer> logger)
    : NormalizerBase(affectedHooks, canonicalizer), ISourceScopedRawNormalizer
{
    public string SourceCode => "distro";
    public IReadOnlySet<string> SupportedSourceCodes { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "alpine-secdb",
        "debian-security-tracker"
    };

    public async Task<NormalizeBatchResult> ProcessPendingAsync(NpgsqlConnection connection, int limit, CancellationToken ct)
    {
        var alpine = await ProcessSourcePendingAsync(connection, "alpine-secdb", limit, ct);
        var debian = alpine.Processed >= limit ? new NormalizeBatchResult("debian-security-tracker", 0, 0) : await ProcessSourcePendingAsync(connection, "debian-security-tracker", limit - alpine.Processed, ct);
        return new NormalizeBatchResult(SourceCode, alpine.Processed + debian.Processed, alpine.Failed + debian.Failed);
    }

    public Task<NormalizeBatchResult> ProcessSourcePendingAsync(NpgsqlConnection connection, string sourceCode, int limit, CancellationToken ct)
        => string.Equals(sourceCode, "alpine-secdb", StringComparison.OrdinalIgnoreCase)
            ? ProcessAlpineAsync(connection, limit, ct)
            : string.Equals(sourceCode, "debian-security-tracker", StringComparison.OrdinalIgnoreCase)
                ? ProcessDebianAsync(connection, limit, ct)
                : Task.FromResult(new NormalizeBatchResult(sourceCode, 0, 0));

    private async Task<NormalizeBatchResult> ProcessAlpineAsync(NpgsqlConnection connection, int limit, CancellationToken ct)
    {
        await using var select = new NpgsqlCommand("""
            select s.raw_index_id, s.distro_release, s.package_name, s.identifiers, s.secfixes, r.source_id
            from stg_alpine_secdb s
            join source_raw_index r on r.id = s.raw_index_id
            join sources src on src.id = r.source_id
            where r.normalize_status in ('pending', 'failed') and src.code = 'alpine-secdb'
            order by s.distro_release, s.package_name
            limit $1
            """, connection);
        select.Parameters.AddWithValue(Math.Max(1, limit));

        var rows = new List<AlpineRow>();
        await using (var reader = await select.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            {
                rows.Add(new AlpineRow(reader.GetGuid(0), reader.GetString(1), reader.GetString(2), reader.GetFieldValue<string[]>(3), reader.GetString(4), reader.GetGuid(5)));
            }
        }

        var drafts = new List<DistroNormalizationDraft>();
        var noDraftRawIds = new HashSet<Guid>();
        var failedRawIds = new HashSet<Guid>();
        foreach (var row in rows)
        {
            try
            {
                var rawDraftCount = 0;
                foreach (var identifier in row.Identifiers.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    var ids = ExtractAllIdentifiers(identifier);
                    var title = $"{identifier} affects Alpine package {row.PackageName}";
                    drafts.Add(new DistroNormalizationDraft(
                        row.RawIndexId,
                        $"{identifier}:{row.DistroRelease}:{row.PackageName}",
                        row.SourceId,
                        new VulnerabilityCanonicalDraft(identifier, title, title, "active", null, null, ids, row.SourceId, row.RawIndexId),
                        ExtractAlpineFacts(row, identifier).ToList()));
                    rawDraftCount++;
                }

                if (rawDraftCount == 0) noDraftRawIds.Add(row.RawIndexId);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to normalize Alpine {Package}", row.PackageName);
                failedRawIds.Add(row.RawIndexId);
            }
        }

        var result = await ProcessDistroDraftsAsync(connection, "alpine-secdb", drafts, noDraftRawIds, failedRawIds, ct);
        await MarkNormalizedBatchAsync(connection, result.SucceededRawIndexIds, ct);
        return new NormalizeBatchResult("alpine-secdb", result.Processed, result.Failed);
    }

    private async Task<NormalizeBatchResult> ProcessDebianAsync(NpgsqlConnection connection, int limit, CancellationToken ct)
    {
        await using var select = new NpgsqlCommand("""
            select s.raw_index_id, s.cve_id, s.packages, r.source_id
            from stg_debian_security_tracker s
            join source_raw_index r on r.id = s.raw_index_id
            join sources src on src.id = r.source_id
            where r.normalize_status in ('pending', 'failed') and src.code = 'debian-security-tracker'
            order by s.cve_id
            limit $1
            """, connection);
        // Debian records near the end of the tracker can contain very large
        // package maps. Keep each materialized batch bounded even when the
        // scheduler uses a larger global normalization limit.
        select.Parameters.AddWithValue(Math.Clamp(limit, 1, 1000));

        var rows = new List<DebianRow>();
        await using (var reader = await select.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            {
                rows.Add(new DebianRow(reader.GetGuid(0), reader.GetString(1), reader.GetString(2), reader.GetGuid(3)));
            }
        }

        var drafts = new List<DistroNormalizationDraft>();
        var noDraftRawIds = new HashSet<Guid>();
        var failedRawIds = new HashSet<Guid>();
        foreach (var row in rows)
        {
            try
            {
                var rowDrafts = BuildDebianDrafts(row).ToList();
                if (rowDrafts.Count == 0)
                {
                    noDraftRawIds.Add(row.RawIndexId);
                    continue;
                }

                drafts.AddRange(rowDrafts);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to normalize Debian {CveId}", row.CveId);
                failedRawIds.Add(row.RawIndexId);
            }
        }

        var result = await ProcessDistroDraftsAsync(connection, "debian-security-tracker", drafts, noDraftRawIds, failedRawIds, ct);
        await MarkNormalizedBatchAsync(connection, result.SucceededRawIndexIds, ct);
        return new NormalizeBatchResult("debian-security-tracker", result.Processed, result.Failed);
    }

    private static IEnumerable<DistroNormalizationDraft> BuildDebianDrafts(DebianRow row)
    {
        if (IsDebianVulnerabilityIdentifier(row.CveId))
        {
            var identifiers = ExtractAllIdentifiers(row.CveId);
            yield return new DistroNormalizationDraft(
                row.RawIndexId,
                row.CveId,
                row.SourceId,
                new VulnerabilityCanonicalDraft(row.CveId, null, null, "active", null, null, identifiers, row.SourceId, row.RawIndexId),
                ExtractDebianFacts(row).ToList());
            yield break;
        }

        var packages = JsonNode.Parse(row.Packages)?.AsObject();
        if (packages is null) yield break;

        // Older Debian staging rows were keyed by source package (for example
        // "linux") and stored CVE objects below it. Convert those rows back
        // into one vulnerability draft per CVE, with the original key as the
        // affected package name.
        var packageName = row.CveId;
        foreach (var (identifier, advisory) in packages)
        {
            if (!IsDebianVulnerabilityIdentifier(identifier)) continue;
            var facts = ExtractDebianFacts(packageName, advisory).ToList();
            if (facts.Count == 0) continue;
            var identifiers = ExtractAllIdentifiers(identifier);
            yield return new DistroNormalizationDraft(
                row.RawIndexId,
                identifier,
                row.SourceId,
                new VulnerabilityCanonicalDraft(identifier, null, null, "active", null, null, identifiers, row.SourceId, row.RawIndexId),
                facts);
        }
    }

    private async Task<(int Processed, int Failed, IReadOnlyList<Guid> SucceededRawIndexIds)> ProcessDistroDraftsAsync(
        NpgsqlConnection connection,
        string sourceCode,
        IReadOnlyList<DistroNormalizationDraft> drafts,
        IReadOnlySet<Guid> noDraftRawIds,
        HashSet<Guid> failedRawIds,
        CancellationToken ct)
    {
        var rawDraftCounts = drafts
            .GroupBy(x => x.RawIndexId)
            .ToDictionary(group => group.Key, group => group.Count());
        var canonicalized = new List<DistroCanonicalizedDraft>();

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
                    canonicalized.Add(new DistroCanonicalizedDraft(draft, vulnerabilityId));
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "Failed to canonicalize distro record {SourceRecordId} from raw {RawIndexId}", draft.SourceRecordId, draft.RawIndexId);
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

            logger.LogInformation("Distro normalize {SourceCode}: parsed={Parsed}, canonicalized={Canonicalized}, resolve_ms={ResolveMs}, canonical_ms={CanonicalMs}.",
                sourceCode, drafts.Count, canonicalized.Count, resolveWatch.ElapsedMilliseconds, canonicalWatch.ElapsedMilliseconds);
            if (remapped > 0)
            {
                logger.LogInformation("Distro normalize {SourceCode}: remapped {Remapped} in-batch canonical ids after merges in {RemapMs} ms.",
                    sourceCode, remapped, remapWatch.ElapsedMilliseconds);
            }
        }

        var writeResult = await ProcessDistroCanonicalizedBatchAsync(connection, sourceCode, canonicalized, ct);
        foreach (var rawId in writeResult.FailedRawIndexIds) failedRawIds.Add(rawId);

        var succeededDraftCounts = writeResult.SucceededRawIndexIds
            .Where(rawId => !failedRawIds.Contains(rawId))
            .GroupBy(rawId => rawId)
            .ToDictionary(group => group.Key, group => group.Count());

        var succeededRawIds = new HashSet<Guid>(noDraftRawIds.Where(rawId => !failedRawIds.Contains(rawId)));
        foreach (var (rawId, expectedCount) in rawDraftCounts)
        {
            if (!failedRawIds.Contains(rawId) &&
                succeededDraftCounts.TryGetValue(rawId, out var succeededCount) &&
                succeededCount == expectedCount)
            {
                succeededRawIds.Add(rawId);
            }
        }

        var attemptedRawIds = rawDraftCounts.Keys.Concat(noDraftRawIds).Concat(failedRawIds).Distinct().ToArray();
        var failedCount = attemptedRawIds.Count(rawId => !succeededRawIds.Contains(rawId));
        return (succeededRawIds.Count, failedCount, succeededRawIds.ToArray());
    }

    private async Task<(IReadOnlyList<Guid> SucceededRawIndexIds, IReadOnlyList<Guid> FailedRawIndexIds)> ProcessDistroCanonicalizedBatchAsync(
        NpgsqlConnection connection,
        string sourceCode,
        IReadOnlyList<DistroCanonicalizedDraft> canonicalized,
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
                        item.Draft.CanonicalDraft.Title,
                        item.Draft.CanonicalDraft.Description,
                        "active"))
                    .ToList();

                var watch = Stopwatch.StartNew();
                var recordIds = await UpsertRecordsBatchAsync(connection, recordInputs, ct);
                var recordsMs = watch.ElapsedMilliseconds;
                var affectedItems = new List<AffectedFactBatchItem>();
                var affectedVulnIds = new List<Guid>();
                var succeededRawIds = new List<Guid>();

                foreach (var item in canonicalized)
                {
                    var key = (item.Draft.SourceId, item.Draft.SourceRecordId, item.Draft.RawIndexId);
                    if (!recordIds.TryGetValue(key, out var recordId))
                        throw new InvalidOperationException($"Missing vulnerability record id for distro raw {item.Draft.RawIndexId}");

                    affectedItems.Add(new AffectedFactBatchItem(item.VulnerabilityId, recordId, item.Draft.SourceId, item.Draft.RawIndexId, item.Draft.AffectedFacts));
                    if (item.Draft.AffectedFacts.Count > 0) affectedVulnIds.Add(item.VulnerabilityId);
                    succeededRawIds.Add(item.Draft.RawIndexId);
                }

                watch.Restart();
                await InsertAffectedFactsBatchAsync(connection, affectedItems, ct);
                var affectedMs = watch.ElapsedMilliseconds;
                watch.Restart();
                await FlushAffectedProjectionsAsync(connection, affectedVulnIds, ct);
                var flushMs = watch.ElapsedMilliseconds;
                logger.LogInformation("Distro batch write {SourceCode} count={Count}: records_ms={RecordsMs}, affected_ms={AffectedMs}, flush_ms={FlushMs}.",
                    sourceCode, canonicalized.Count, recordsMs, affectedMs, flushMs);
                return (succeededRawIds, []);
            }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.DeadlockDetected && attempt == 1)
            {
                logger.LogWarning(ex, "Distro batch normalize {SourceCode} deadlocked for {Count} records; retrying batch once.", sourceCode, canonicalized.Count);
                await Task.Delay(500, ct);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Distro batch normalize {SourceCode} failed for {Count} records; falling back to per-record writes.", sourceCode, canonicalized.Count);
                return await ProcessDistroCanonicalizedIndividuallyAsync(connection, canonicalized, ct);
            }
        }

        return await ProcessDistroCanonicalizedIndividuallyAsync(connection, canonicalized, ct);
    }

    private async Task<(IReadOnlyList<Guid> SucceededRawIndexIds, IReadOnlyList<Guid> FailedRawIndexIds)> ProcessDistroCanonicalizedIndividuallyAsync(
        NpgsqlConnection connection,
        IReadOnlyList<DistroCanonicalizedDraft> canonicalized,
        CancellationToken ct)
    {
        var succeededRawIds = new List<Guid>();
        var failedRawIds = new List<Guid>();
        var affectedVulnIds = new List<Guid>();

        foreach (var item in canonicalized)
        {
            try
            {
                var draft = item.Draft;
                var recordId = await UpsertRecordAsync(connection, item.VulnerabilityId, draft.SourceId, draft.RawIndexId, draft.SourceRecordId, draft.CanonicalDraft.Title, draft.CanonicalDraft.Description, "active", ct);
                await InsertAffectedFactsAsync(connection, item.VulnerabilityId, recordId, draft.SourceId, draft.RawIndexId, draft.AffectedFacts, ct);
                if (draft.AffectedFacts.Count > 0) affectedVulnIds.Add(item.VulnerabilityId);
                succeededRawIds.Add(draft.RawIndexId);
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Failed to write distro record {SourceRecordId} from raw {RawIndexId}", item.Draft.SourceRecordId, item.Draft.RawIndexId);
                failedRawIds.Add(item.Draft.RawIndexId);
            }
        }

        await FlushAffectedProjectionsAsync(connection, affectedVulnIds, ct);
        return (succeededRawIds, failedRawIds);
    }

    private static IEnumerable<AffectedFactDraft> ExtractDebianFacts(DebianRow row)
    {
        var packages = JsonNode.Parse(row.Packages)?.AsObject();
        if (packages is null) yield break;
        foreach (var (name, value) in packages)
        {
            if (string.IsNullOrWhiteSpace(name)) continue;
            foreach (var fact in ExtractDebianFacts(name, value))
                yield return fact;
        }
    }

    private static IEnumerable<AffectedFactDraft> ExtractDebianFacts(string packageName, JsonNode? value)
    {
        var releases = value?["releases"]?.AsObject();
        if (releases is null) yield break;
        foreach (var (release, advisory) in releases)
        {
            var status = advisory?["status"]?.GetValue<string>()?.ToLowerInvariant();
            var fixedVersion = advisory?["fixed_version"]?.GetValue<string>();
            var range = status switch
            {
                "open" => ">= 0",
                "resolved" when !string.IsNullOrWhiteSpace(fixedVersion) && fixedVersion != "0" => $"< {fixedVersion}",
                _ => null
            };
            if (range is null) continue;
            yield return new AffectedFactDraft(
                "package",
                DebianEcosystem(release),
                packageName,
                $"pkg:deb/debian/{Uri.EscapeDataString(packageName)}",
                range,
                $"security-tracker:{status}",
                advisory?.ToJsonString() ?? "{}");
        }
    }

    private static IEnumerable<AffectedFactDraft> ExtractAlpineFacts(AlpineRow row, string identifier)
    {
        var secfixes = JsonNode.Parse(row.Secfixes)?.AsObject();
        if (secfixes is null) yield break;
        foreach (var (fixedVersion, ids) in secfixes)
        {
            var matched = ids?.AsArray()
                .Any(x => string.Equals(x?.GetValue<string>(), identifier, StringComparison.OrdinalIgnoreCase)) ?? false;
            if (!matched || string.IsNullOrWhiteSpace(fixedVersion)) continue;
            var release = row.DistroRelease.Split('/', 2)[0].TrimStart('v', 'V');
            yield return new AffectedFactDraft(
                "package",
                $"alpine:{release}",
                row.PackageName,
                $"pkg:apk/alpine/{Uri.EscapeDataString(row.PackageName)}",
                $"< {fixedVersion}",
                "secfixes",
                "{}");
        }
    }

    private static string DebianEcosystem(string release) => release.ToLowerInvariant() switch
    {
        "etch" => "debian:4",
        "lenny" => "debian:5",
        "squeeze" => "debian:6",
        "wheezy" => "debian:7",
        "jessie" => "debian:8",
        "stretch" => "debian:9",
        "buster" => "debian:10",
        "bullseye" => "debian:11",
        "bookworm" => "debian:12",
        "trixie" => "debian:13",
        "forky" => "debian:14",
        var value => $"debian:{value}"
    };

    private static string[] ExtractAllIdentifiers(string rawId)
    {
        var ids = new List<string> { rawId };
        // Extract CVE from DEBIAN-CVE-XXXX, UBUNTU-CVE-XXXX, ALPINE-CVE-XXXX etc
        var match = System.Text.RegularExpressions.Regex.Match(rawId, @"\b(CVE-\d{4}-\d{4,})\b", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        if (match.Success && !ids.Contains(match.Groups[1].Value, StringComparer.OrdinalIgnoreCase))
            ids.Add(match.Groups[1].Value);
        return IdentifiersFrom(ids);
    }

    private static bool IsDebianVulnerabilityIdentifier(string value) =>
        value.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)
        || value.StartsWith("TEMP-", StringComparison.OrdinalIgnoreCase);

    private sealed record DistroNormalizationDraft(
        Guid RawIndexId,
        string SourceRecordId,
        Guid SourceId,
        VulnerabilityCanonicalDraft CanonicalDraft,
        IReadOnlyList<AffectedFactDraft> AffectedFacts);

    private sealed record DistroCanonicalizedDraft(DistroNormalizationDraft Draft, Guid VulnerabilityId);

    private sealed record AlpineRow(Guid RawIndexId, string DistroRelease, string PackageName, string[] Identifiers, string Secfixes, Guid SourceId);
    private sealed record DebianRow(Guid RawIndexId, string CveId, string Packages, Guid SourceId);
}
