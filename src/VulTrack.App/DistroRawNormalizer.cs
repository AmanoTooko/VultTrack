using System.Text.Json.Nodes;
using Npgsql;

namespace VulTrack.App;

public sealed class DistroRawNormalizer(IEnumerable<IAffectedComponentHook> affectedHooks, IVulnerabilityCanonicalizer canonicalizer)
    : NormalizerBase(affectedHooks, canonicalizer), IRawNormalizer
{
    public string SourceCode => "distro";

    public async Task<NormalizeBatchResult> ProcessPendingAsync(NpgsqlConnection connection, int limit, CancellationToken ct)
    {
        var alpine = await ProcessAlpineAsync(connection, limit, ct);
        var debian = alpine.Processed >= limit ? new NormalizeBatchResult("debian-security-tracker", 0, 0) : await ProcessDebianAsync(connection, limit - alpine.Processed, ct);
        return new NormalizeBatchResult(SourceCode, alpine.Processed + debian.Processed, alpine.Failed + debian.Failed);
    }

    private async Task<NormalizeBatchResult> ProcessAlpineAsync(NpgsqlConnection connection, int limit, CancellationToken ct)
    {
        await using var select = new NpgsqlCommand("""
            select s.raw_index_id, s.distro_release, s.package_name, s.identifiers, s.secfixes, s.payload, r.source_id
            from stg_alpine_secdb s
            join source_raw_index r on r.id = s.raw_index_id
            where r.normalize_status <> 'succeeded'
            order by s.distro_release, s.package_name
            limit $1
            """, connection);
        select.Parameters.AddWithValue(Math.Max(1, limit));

        var rows = new List<AlpineRow>();
        await using (var reader = await select.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            {
                rows.Add(new AlpineRow(reader.GetGuid(0), reader.GetString(1), reader.GetString(2), reader.GetFieldValue<string[]>(3), reader.GetString(4), reader.GetString(5), reader.GetGuid(6)));
            }
        }

        var processed = 0;
        var failed = 0;
        foreach (var row in rows)
        {
            try
            {
                foreach (var identifier in row.Identifiers.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    var ids = IdentifiersFrom([identifier]);
                    var title = $"{identifier} affects Alpine package {row.PackageName}";
                    var vulnerabilityId = await UpsertVulnerabilityAsync(connection, row.SourceId, row.RawIndexId, identifier, title, title, "active", null, null, ids, ct);
                    var recordId = await UpsertRecordAsync(connection, vulnerabilityId, row.SourceId, row.RawIndexId, $"{identifier}:{row.DistroRelease}:{row.PackageName}", title, title, "active", row.Payload, ct);
                    var facts = new[] { new AffectedFactDraft("package", "alpine", row.PackageName, null, null, "secfixes", row.Payload) };
                    await InsertAffectedFactsAsync(connection, vulnerabilityId, recordId, row.SourceId, row.RawIndexId, facts, ct);
                }

                await MarkNormalizedAsync(connection, row.RawIndexId, ct);
                processed++;
            }
            catch
            {
                failed++;
            }
        }

        return new NormalizeBatchResult("alpine-secdb", processed, failed);
    }

    private async Task<NormalizeBatchResult> ProcessDebianAsync(NpgsqlConnection connection, int limit, CancellationToken ct)
    {
        await using var select = new NpgsqlCommand("""
            select s.raw_index_id, s.cve_id, s.packages, s.payload, r.source_id
            from stg_debian_security_tracker s
            join source_raw_index r on r.id = s.raw_index_id
            where r.normalize_status <> 'succeeded'
            order by s.cve_id
            limit $1
            """, connection);
        select.Parameters.AddWithValue(Math.Max(1, limit));

        var rows = new List<DebianRow>();
        await using (var reader = await select.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            {
                rows.Add(new DebianRow(reader.GetGuid(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetGuid(4)));
            }
        }

        var processed = 0;
        var failed = 0;
        foreach (var row in rows)
        {
            try
            {
                var title = $"{row.CveId} Debian security tracker";
                var vulnerabilityId = await UpsertVulnerabilityAsync(connection, row.SourceId, row.RawIndexId, row.CveId, title, title, "active", null, null, [row.CveId], ct);
                var recordId = await UpsertRecordAsync(connection, vulnerabilityId, row.SourceId, row.RawIndexId, row.CveId, title, title, "active", row.Payload, ct);
                var facts = ExtractDebianFacts(row).ToList();
                await InsertAffectedFactsAsync(connection, vulnerabilityId, recordId, row.SourceId, row.RawIndexId, facts, ct);
                await MarkNormalizedAsync(connection, row.RawIndexId, ct);
                processed++;
            }
            catch
            {
                failed++;
            }
        }

        return new NormalizeBatchResult("debian-security-tracker", processed, failed);
    }

    private static IEnumerable<AffectedFactDraft> ExtractDebianFacts(DebianRow row)
    {
        var packages = JsonNode.Parse(row.Packages)?.AsObject();
        if (packages is null) yield break;
        foreach (var (name, value) in packages)
        {
            if (string.IsNullOrWhiteSpace(name)) continue;
            yield return new AffectedFactDraft("package", "debian", name, null, null, "security-tracker", value?.ToJsonString() ?? "{}");
        }
    }

    private sealed record AlpineRow(Guid RawIndexId, string DistroRelease, string PackageName, string[] Identifiers, string Secfixes, string Payload, Guid SourceId);
    private sealed record DebianRow(Guid RawIndexId, string CveId, string Packages, string Payload, Guid SourceId);
}
