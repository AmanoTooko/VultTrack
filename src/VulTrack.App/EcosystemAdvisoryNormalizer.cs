using System.Text.Json.Nodes;
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
        var succeededIds = new List<Guid>();
        var affectedVulnIds = new List<Guid>();

        var drafts = new List<(Row Row, VulnerabilityCanonicalDraft Draft)>();
        foreach (var row in rows)
        {
            var identifiers = IdentifiersFrom([row.AdvisoryId], row.Identifiers);
            var isCsaf = row.Provider is "suse-csaf" or "redhat-csaf";
            var cves = identifiers.Where(x => x.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)).ToArray();
            IEnumerable<string[]> identifierSets = isCsaf && cves.Length > 0 ? cves.Select(x => new[] { x }) : [identifiers];
            foreach (var identifierSet in identifierSets)
            {
                var primary = identifierSet.FirstOrDefault(x => x.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)) ?? row.AdvisoryId;
                drafts.Add((row, new VulnerabilityCanonicalDraft(primary, null, null, "active", row.PublishedAt, row.ModifiedAt, identifierSet, row.SourceId, row.RawIndexId)));
            }
        }

        var cache = await Canonicalizer.ResolveCanonicalIdsBatchAsync(connection, drafts.Select(d => d.Draft).ToList(), ct);

        foreach (var (row, draft) in drafts)
        {
            try
            {
                var identifiers = draft.Identifiers;
                var primary = draft.PreferredIdentifier;
                var payload = JsonNode.Parse(row.Payload);
                var isCsaf = row.Provider is "suse-csaf" or "redhat-csaf";
                var title = ExtractTitle(payload, isCsaf, row.AdvisoryId);
                var description = ExtractDescription(payload, isCsaf, title);
                var fullDraft = new VulnerabilityCanonicalDraft(primary, title, description, "active", row.PublishedAt, row.ModifiedAt, identifiers, row.SourceId, row.RawIndexId);
                var vulnerabilityId = await Canonicalizer.GetOrCreateCanonicalAsync(connection, fullDraft, cache, ct);
                var sourceRecordId = isCsaf ? $"{row.AdvisoryId}:{primary}" : row.AdvisoryId;
                var recordId = await UpsertRecordAsync(connection, vulnerabilityId, row.SourceId, row.RawIndexId, sourceRecordId, title, description, "active", ct);
                await UpsertIdentifiersAsync(connection, vulnerabilityId, row.SourceId, row.RawIndexId, identifiers, ct);
                await InsertDescriptionsAsync(connection, vulnerabilityId, recordId, row.SourceId, SourceFactExtractor.Descriptions(title, description), ct);
                var severities = ExtractSeverities(payload, isCsaf, row.SeverityLabel, row.Payload, primary).ToList();
                await InsertSeverityScoresAsync(connection, vulnerabilityId, recordId, row.SourceId, row.RawIndexId, severities, ct);
                await InsertReferencesAsync(connection, vulnerabilityId, recordId, row.SourceId, SourceFactExtractor.References(JsonNode.Parse(row.ReferencesJson)), ct);
                var facts = ExtractAffectedFacts(row, payload, isCsaf, primary).ToList();
                await InsertAffectedFactsAsync(connection, vulnerabilityId, recordId, row.SourceId, row.RawIndexId, facts, ct);
                if (facts.Count > 0) affectedVulnIds.Add(vulnerabilityId);
                succeededIds.Add(row.RawIndexId);
                processed++;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to normalize ecosystem advisory {AdvisoryId} from raw {RawIndexId}", row.AdvisoryId, row.RawIndexId);
                failed++;
            }
        }

        await FlushAffectedProjectionsAsync(connection, affectedVulnIds, ct);
        await MarkNormalizedBatchAsync(connection, succeededIds, ct);

        return new NormalizeBatchResult(sourceCode ?? SourceCode, processed, failed);
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

    private sealed record Row(Guid RawIndexId, string Provider, string? Ecosystem, string AdvisoryId, string[] Identifiers, string? PackageName, string? Purl, string VulnerableRanges, string? SeverityLabel, DateTimeOffset? PublishedAt, DateTimeOffset? ModifiedAt, string ReferencesJson, string Payload, Guid SourceId);
}
