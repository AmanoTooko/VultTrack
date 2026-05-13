using System.Text.Json.Nodes;
using Npgsql;

namespace VulTrack.App;

public sealed class PypiRawNormalizer(IEnumerable<IAffectedComponentHook> affectedHooks, IVulnerabilityCanonicalizer canonicalizer)
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
            where r.normalize_status <> 'succeeded' and src.code = $1
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
        var succeededIds = new List<Guid>();
        foreach (var row in rows)
        {
            try
            {
                var identifiers = IdentifiersFrom([row.PysecId], row.Aliases);
                var primary = identifiers.FirstOrDefault(x => x.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)) ?? row.PysecId;
                var title = row.Summary ?? row.PysecId;
                var vulnerabilityId = await UpsertVulnerabilityAsync(connection, row.SourceId, row.RawIndexId, primary, title, row.Details ?? title, "active", row.PublishedAt, row.ModifiedAt, identifiers, ct);
                var recordId = await UpsertRecordAsync(connection, vulnerabilityId, row.SourceId, row.RawIndexId, row.PysecId, title, row.Details, "active", row.Payload, ct);
                await UpsertIdentifiersAsync(connection, vulnerabilityId, row.SourceId, row.RawIndexId, identifiers, ct);
                var payload = JsonNode.Parse(row.Payload);
                await InsertDescriptionsAsync(connection, vulnerabilityId, recordId, row.SourceId, SourceFactExtractor.Descriptions(row.Summary, row.Details), ct);
                await InsertSeverityScoresAsync(connection, vulnerabilityId, recordId, row.SourceId, row.RawIndexId, SourceFactExtractor.OsvSeverities(payload?["severity"]), ct);
                await InsertReferencesAsync(connection, vulnerabilityId, recordId, row.SourceId, SourceFactExtractor.References(payload?["references"]), ct);
                var facts = ExtractAffectedFacts(row).ToList();
                await InsertAffectedFactsAsync(connection, vulnerabilityId, recordId, row.SourceId, row.RawIndexId, facts, ct);
                succeededIds.Add(row.RawIndexId);
                processed++;
            }
            catch
            {
                failed++;
            }
        }

        await MarkNormalizedBatchAsync(connection, succeededIds, ct);

        return new NormalizeBatchResult(SourceCode, processed, failed);
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

    private sealed record Row(Guid RawIndexId, string PysecId, string[] Aliases, string? PackageName, string? Summary, string? Details, string Affected, DateTimeOffset? PublishedAt, DateTimeOffset? ModifiedAt, string Payload, Guid SourceId);
}
