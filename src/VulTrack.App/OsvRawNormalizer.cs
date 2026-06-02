using System.Text.Json.Nodes;
using Npgsql;

namespace VulTrack.App;

public sealed class OsvRawNormalizer(IEnumerable<IAffectedComponentHook> affectedHooks, IVulnerabilityCanonicalizer canonicalizer)
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
                select s.raw_index_id, s.osv_id, s.aliases, s.payload, r.source_id
                from {table} s
                join source_raw_index r on r.id = s.raw_index_id
                join sources src on src.id = r.source_id
                where r.normalize_status <> 'succeeded' and src.code = $1
                order by r.updated_at
                limit $2
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

            var succeededIds = new List<Guid>();
            var affectedVulnIds = new List<Guid>();
            foreach (var row in rows)
            {
                try
                {
                    var payload = JsonNode.Parse(row.Payload);
                    var identifiers = IdentifiersFrom([row.OsvId], row.Aliases);
                    var primary = identifiers.FirstOrDefault(x => x.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)) ?? row.OsvId;
                    var title = payload?["summary"]?.GetValue<string>();
                    var description = payload?["details"]?.GetValue<string>() ?? title;
                    var vulnerabilityId = await UpsertVulnerabilityAsync(connection, row.SourceId, row.RawIndexId, primary, title, description, "active", DateValue(payload, "published"), DateValue(payload, "modified"), identifiers, ct);
                    var recordId = await UpsertRecordAsync(connection, vulnerabilityId, row.SourceId, row.RawIndexId, row.OsvId, title, description, "active", ct);
                    await UpsertIdentifiersAsync(connection, vulnerabilityId, row.SourceId, row.RawIndexId, identifiers, ct);
                    await InsertDescriptionsAsync(connection, vulnerabilityId, recordId, row.SourceId, SourceFactExtractor.Descriptions(title, description), ct);
                    await InsertSeverityScoresAsync(connection, vulnerabilityId, recordId, row.SourceId, row.RawIndexId, SourceFactExtractor.OsvSeverities(payload?["severity"]), ct);
                    await InsertReferencesAsync(connection, vulnerabilityId, recordId, row.SourceId, SourceFactExtractor.References(payload?["references"]), ct);
                    var facts = ExtractAffectedFacts(payload).ToList();
                    await InsertAffectedFactsAsync(connection, vulnerabilityId, recordId, row.SourceId, row.RawIndexId, facts, ct);
                    if (facts.Count > 0) affectedVulnIds.Add(vulnerabilityId);
                    succeededIds.Add(row.RawIndexId);
                    processed++;
                }
                catch
                {
                    failed++;
                }
            }

            await FlushAffectedProjectionsAsync(connection, affectedVulnIds, ct);
            await MarkNormalizedBatchAsync(connection, succeededIds, ct);

            if (processed >= limit) break;
        }

        return new NormalizeBatchResult(SourceCode, processed, failed);
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
}
