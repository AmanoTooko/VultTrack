using System.Text.Json.Nodes;
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
            where r.normalize_status <> 'succeeded' and src.code = 'alpine-secdb'
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

        var processed = 0;
        var failed = 0;
        var succeededIds = new List<Guid>();
        var affectedVulnIds = new List<Guid>();
        foreach (var row in rows)
        {
            try
            {
                foreach (var identifier in row.Identifiers.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    var ids = ExtractAllIdentifiers(identifier);
                    var title = $"{identifier} affects Alpine package {row.PackageName}";
                    var vulnerabilityId = await UpsertVulnerabilityAsync(connection, row.SourceId, row.RawIndexId, identifier, title, title, "active", null, null, ids, ct);
                    var recordId = await UpsertRecordAsync(connection, vulnerabilityId, row.SourceId, row.RawIndexId, $"{identifier}:{row.DistroRelease}:{row.PackageName}", title, title, "active", ct);
                    var facts = ExtractAlpineFacts(row, identifier).ToList();
                    await InsertAffectedFactsAsync(connection, vulnerabilityId, recordId, row.SourceId, row.RawIndexId, facts, ct);
                    if (facts.Count > 0) affectedVulnIds.Add(vulnerabilityId);
                }

                succeededIds.Add(row.RawIndexId);
                processed++;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to normalize Alpine {Package}", row.PackageName);
                failed++;
            }
        }

        await FlushAffectedProjectionsAsync(connection, affectedVulnIds, ct);
        await MarkNormalizedBatchAsync(connection, succeededIds, ct);

        return new NormalizeBatchResult("alpine-secdb", processed, failed);
    }

    private async Task<NormalizeBatchResult> ProcessDebianAsync(NpgsqlConnection connection, int limit, CancellationToken ct)
    {
        await using var select = new NpgsqlCommand("""
            select s.raw_index_id, s.cve_id, s.packages, r.source_id
            from stg_debian_security_tracker s
            join source_raw_index r on r.id = s.raw_index_id
            join sources src on src.id = r.source_id
            where r.normalize_status <> 'succeeded' and src.code = 'debian-security-tracker'
            order by s.cve_id
            limit $1
            """, connection);
        select.Parameters.AddWithValue(Math.Max(1, limit));

        var rows = new List<DebianRow>();
        await using (var reader = await select.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            {
                rows.Add(new DebianRow(reader.GetGuid(0), reader.GetString(1), reader.GetString(2), reader.GetGuid(3)));
            }
        }

        var processed = 0;
        var failed = 0;
        var succeededIds = new List<Guid>();
        var affectedVulnIds = new List<Guid>();
        foreach (var row in rows)
        {
            try
            {
                var title = $"{row.CveId} Debian security tracker";
                var identifiers = ExtractAllIdentifiers(row.CveId);
                var vulnerabilityId = await UpsertVulnerabilityAsync(connection, row.SourceId, row.RawIndexId, row.CveId, title, title, "active", null, null, identifiers, ct);
                var recordId = await UpsertRecordAsync(connection, vulnerabilityId, row.SourceId, row.RawIndexId, row.CveId, title, title, "active", ct);
                var facts = ExtractDebianFacts(row).ToList();
                await InsertAffectedFactsAsync(connection, vulnerabilityId, recordId, row.SourceId, row.RawIndexId, facts, ct);
                if (facts.Count > 0) affectedVulnIds.Add(vulnerabilityId);
                succeededIds.Add(row.RawIndexId);
                processed++;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to normalize Debian {CveId}", row.CveId);
                failed++;
            }
        }

        await FlushAffectedProjectionsAsync(connection, affectedVulnIds, ct);
        await MarkNormalizedBatchAsync(connection, succeededIds, ct);

        return new NormalizeBatchResult("debian-security-tracker", processed, failed);
    }

    private static IEnumerable<AffectedFactDraft> ExtractDebianFacts(DebianRow row)
    {
        var packages = JsonNode.Parse(row.Packages)?.AsObject();
        if (packages is null) yield break;
        foreach (var (name, value) in packages)
        {
            if (string.IsNullOrWhiteSpace(name)) continue;
            var releases = value?["releases"]?.AsObject();
            if (releases is null) continue;
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
                    name,
                    $"pkg:deb/debian/{Uri.EscapeDataString(name)}",
                    range,
                    $"security-tracker:{status}",
                    advisory?.ToJsonString() ?? "{}");
            }
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

    private sealed record AlpineRow(Guid RawIndexId, string DistroRelease, string PackageName, string[] Identifiers, string Secfixes, Guid SourceId);
    private sealed record DebianRow(Guid RawIndexId, string CveId, string Packages, Guid SourceId);
}
