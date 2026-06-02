using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;

namespace VulTrack.App;

public sealed class NvdRawProcessor(
    NpgsqlDataSource db,
    IVulnerabilityCanonicalizer canonicalizer,
    IEnumerable<IAffectedComponentHook> affectedHooks,
    ILogger<NvdRawProcessor> logger)
{
    public async Task<ProcessPendingResult> ProcessPendingAsync(int limit, CancellationToken ct)
    {
        var processed = 0;
        var failed = 0;

        await using var select = db.CreateCommand("""
            select s.raw_index_id, s.cve_id, s.vuln_status, s.descriptions, s.metrics,
                   s.weaknesses, s.configurations, s.references_json, s.published_at, s.modified_at,
                   s.payload, r.source_id
            from stg_nvd_cves s
            join source_raw_index r on r.id = s.raw_index_id
            where r.normalize_status <> 'succeeded'
            order by s.modified_at nulls last, s.cve_id
            limit $1
            """);
        select.Parameters.AddWithValue(limit);

        var records = new List<NvdStagingRecord>();
        await using (var reader = await select.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            {
                records.Add(new NvdStagingRecord(
                    reader.GetGuid(0),
                    reader.GetString(1),
                    reader.IsDBNull(2) ? null : reader.GetString(2),
                    reader.GetString(3),
                    reader.GetString(4),
                    reader.GetString(5),
                    reader.GetString(6),
                    reader.GetString(7),
                    reader.IsDBNull(8) ? null : reader.GetFieldValue<DateTimeOffset>(8),
                    reader.IsDBNull(9) ? null : reader.GetFieldValue<DateTimeOffset>(9),
                    reader.GetString(10),
                    reader.GetGuid(11)));
            }
        }

        var succeededRawIndexIds = new List<Guid>();
        var affectedVulnerabilityIds = new HashSet<Guid>();
        await using var connection = await db.OpenConnectionAsync(ct);
        await using var transaction = await connection.BeginTransactionAsync(ct);
        foreach (var record in records)
        {
            var savepointName = $"record_{processed + failed}";
            await transaction.SaveAsync(savepointName, ct);
            try
            {
                var vulnerabilityId = await UpsertVulnerabilityAsync(connection, record, ct);
                var vulnerabilityRecordId = await UpsertRecordAsync(connection, vulnerabilityId, record, ct);
                await UpsertIdentifierAsync(connection, vulnerabilityId, record, ct);
                await UpsertDescriptionsAsync(connection, vulnerabilityId, vulnerabilityRecordId, record, ct);
                await UpsertSeveritiesAsync(connection, vulnerabilityId, vulnerabilityRecordId, record, ct);
                await UpsertWeaknessesAsync(connection, vulnerabilityId, vulnerabilityRecordId, record, ct);
                await UpsertReferencesAsync(connection, vulnerabilityId, vulnerabilityRecordId, record, ct);
                var affectedFacts = await UpsertAffectedFactsAsync(connection, vulnerabilityId, vulnerabilityRecordId, record, ct);
                if (affectedFacts.Count > 0) affectedVulnerabilityIds.Add(vulnerabilityId);
                foreach (var hook in affectedHooks)
                {
                    await hook.OnAffectedFactsAsync(connection, vulnerabilityId, vulnerabilityRecordId, affectedFacts, ct);
                }
                succeededRawIndexIds.Add(record.RawIndexId);
                await transaction.ReleaseAsync(savepointName, ct);
                processed++;
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync(savepointName, ct);
                logger.LogError(ex, "Failed to normalize NVD CVE {CveId}", record.CveId);
                failed++;
            }
        }

        foreach (var hook in affectedHooks)
        {
            await hook.FlushProjectionsAsync(connection, affectedVulnerabilityIds.ToList(), ct);
        }
        await MarkNormalizedAsync(connection, succeededRawIndexIds, ct);
        await transaction.CommitAsync(ct);
        return new ProcessPendingResult(processed, failed);
    }

    private async Task<Guid> UpsertVulnerabilityAsync(NpgsqlConnection conn, NvdStagingRecord record, CancellationToken ct)
    {
        var descriptions = JsonNode.Parse(record.Descriptions)?.AsArray();
        var title = descriptions?.FirstOrDefault(x => x?["lang"]?.GetValue<string>() == "en")?["value"]?.GetValue<string>();
        var selectedSeverity = ExtractCvss(record.Metrics).OrderByDescending(x => x.Score).FirstOrDefault();
        var vulnerabilityId = await canonicalizer.UpsertCanonicalAsync(
            conn,
            new VulnerabilityCanonicalDraft(
                record.CveId,
                title,
                title,
                record.Status ?? "active",
                record.PublishedAt,
                record.ModifiedAt,
                [record.CveId],
                record.SourceId,
                record.RawIndexId),
            ct);

        await using var cmd = new NpgsqlCommand("""
            update vulnerabilities
            set max_cvss_score = coalesce($2, max_cvss_score),
                max_cvss_version = coalesce($3, max_cvss_version),
                max_cvss_vector = coalesce($4, max_cvss_vector),
                severity_label = coalesce($5, severity_label),
                severity_source = 'nvd-cve',
                severity_confidence = 1.0,
                updated_at = now()
            where id = $1
            """, conn);
        cmd.Parameters.AddWithValue(vulnerabilityId);
        cmd.Parameters.AddWithValue((object?)selectedSeverity?.Score ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)selectedSeverity?.Version ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)selectedSeverity?.Vector ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)selectedSeverity?.Severity ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
        return vulnerabilityId;
    }

    private static async Task<Guid> UpsertRecordAsync(NpgsqlConnection conn, Guid vulnerabilityId, NvdStagingRecord record, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("""
            insert into vulnerability_records
              (vulnerability_id, source_id, raw_index_id, source_record_id, title, description, status)
            values ($1,$2,$3,$4,$5,$6,$7)
            on conflict (source_id, source_record_id, raw_index_id) do update set
              vulnerability_id = excluded.vulnerability_id,
              updated_at = now()
            returning id
            """, conn);
        var title = JsonNode.Parse(record.Descriptions)?.AsArray()
            .FirstOrDefault(x => x?["lang"]?.GetValue<string>() == "en")?["value"]?.GetValue<string>();
        cmd.Parameters.AddWithValue(vulnerabilityId);
        cmd.Parameters.AddWithValue(record.SourceId);
        cmd.Parameters.AddWithValue(record.RawIndexId);
        cmd.Parameters.AddWithValue(record.CveId);
        cmd.Parameters.AddWithValue((object?)title ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)title ?? DBNull.Value);
        cmd.Parameters.AddWithValue(record.Status ?? "active");
        return (Guid)(await cmd.ExecuteScalarAsync(ct))!;
    }

    private static Task UpsertIdentifierAsync(NpgsqlConnection conn, Guid vulnerabilityId, NvdStagingRecord record, CancellationToken ct) => Task.CompletedTask;

    private static async Task UpsertDescriptionsAsync(NpgsqlConnection conn, Guid vulnerabilityId, Guid recordId, NvdStagingRecord record, CancellationToken ct)
    {
        foreach (var item in JsonNode.Parse(record.Descriptions)?.AsArray() ?? [])
        {
            await using var cmd = new NpgsqlCommand("""
                insert into vulnerability_descriptions
                  (vulnerability_id, vulnerability_record_id, source_id, lang, description_type, value, is_selected)
                values ($1,$2,$3,$4,'detail',$5,$6)
                on conflict (vulnerability_id, source_id, lang, description_type)
                do update set value = excluded.value, is_selected = excluded.is_selected
                """, conn);
            cmd.Parameters.AddWithValue(vulnerabilityId);
            cmd.Parameters.AddWithValue(recordId);
            cmd.Parameters.AddWithValue(record.SourceId);
            cmd.Parameters.AddWithValue(item?["lang"]?.GetValue<string>() ?? "und");
            cmd.Parameters.AddWithValue(item?["value"]?.GetValue<string>() ?? "");
            cmd.Parameters.AddWithValue(item?["lang"]?.GetValue<string>() == "en");
            await cmd.ExecuteNonQueryAsync(ct);
        }
    }

    private static async Task UpsertSeveritiesAsync(NpgsqlConnection conn, Guid vulnerabilityId, Guid recordId, NvdStagingRecord record, CancellationToken ct)
    {
        var scores = ExtractCvss(record.Metrics).ToList();
        var max = scores.OrderByDescending(x => x.Score).FirstOrDefault();
        foreach (var score in scores)
        {
            await using var cmd = new NpgsqlCommand("""
                insert into vulnerability_severity_scores
                  (vulnerability_id, vulnerability_record_id, source_id, raw_index_id, scoring_system, scoring_version,
                   score_type, vector_string, score, severity_label, normalized_severity, source_severity_label,
                   metric_json, is_selected)
                values ($1,$2,$3,$4,'cvss',$5,'base',$6,$7,$8,$8,$8,$9::jsonb,$10)
                """, conn);
            cmd.Parameters.AddWithValue(vulnerabilityId);
            cmd.Parameters.AddWithValue(recordId);
            cmd.Parameters.AddWithValue(record.SourceId);
            cmd.Parameters.AddWithValue(record.RawIndexId);
            cmd.Parameters.AddWithValue(score.Version);
            cmd.Parameters.AddWithValue((object?)score.Vector ?? DBNull.Value);
            cmd.Parameters.AddWithValue((object?)score.Score ?? DBNull.Value);
            cmd.Parameters.AddWithValue((object?)score.Severity ?? DBNull.Value);
            cmd.Parameters.AddWithValue(score.RawJson);
            cmd.Parameters.AddWithValue(max is not null && score.RawJson == max.RawJson);
            await cmd.ExecuteNonQueryAsync(ct);
        }
    }

    private static async Task UpsertWeaknessesAsync(NpgsqlConnection conn, Guid vulnerabilityId, Guid recordId, NvdStagingRecord record, CancellationToken ct)
    {
        foreach (var weakness in JsonNode.Parse(record.Weaknesses)?.AsArray() ?? [])
        {
            foreach (var desc in weakness?["description"]?.AsArray() ?? [])
            {
                var value = desc?["value"]?.GetValue<string>();
                await using var cmd = new NpgsqlCommand("""
                    insert into vulnerability_weaknesses
                      (vulnerability_id, vulnerability_record_id, source_id, weakness_type, weakness_id, description)
                    values ($1,$2,$3,'CWE',$4,$5)
                    on conflict (vulnerability_id, source_id, coalesce(weakness_id,'')) do nothing
                    """, conn);
                cmd.Parameters.AddWithValue(vulnerabilityId);
                cmd.Parameters.AddWithValue(recordId);
                cmd.Parameters.AddWithValue(record.SourceId);
                cmd.Parameters.AddWithValue((object?)value ?? DBNull.Value);
                cmd.Parameters.AddWithValue((object?)value ?? DBNull.Value);
                await cmd.ExecuteNonQueryAsync(ct);
            }
        }
    }

    private static async Task UpsertReferencesAsync(NpgsqlConnection conn, Guid vulnerabilityId, Guid recordId, NvdStagingRecord record, CancellationToken ct)
    {
        foreach (var reference in JsonNode.Parse(record.References)?.AsArray() ?? [])
        {
            await using var cmd = new NpgsqlCommand("""
                insert into vulnerability_references
                  (vulnerability_id, vulnerability_record_id, source_id, url, normalized_url, tags)
                values ($1,$2,$3,$4,$4,$5)
                """, conn);
            cmd.Parameters.AddWithValue(vulnerabilityId);
            cmd.Parameters.AddWithValue(recordId);
            cmd.Parameters.AddWithValue(record.SourceId);
            cmd.Parameters.AddWithValue(reference?["url"]?.GetValue<string>() ?? "");
            cmd.Parameters.AddWithValue(reference?["tags"]?.AsArray().Select(x => x?.GetValue<string>() ?? "").ToArray() ?? []);
            await cmd.ExecuteNonQueryAsync(ct);
        }
    }

    private static async Task<IReadOnlyList<AffectedFactDraft>> UpsertAffectedFactsAsync(NpgsqlConnection conn, Guid vulnerabilityId, Guid recordId, NvdStagingRecord record, CancellationToken ct)
    {
        var facts = new List<AffectedFactDraft>();
        foreach (var cpeMatch in WalkCpeMatches(JsonNode.Parse(record.Configurations)))
        {
            var criteria = cpeMatch?["criteria"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(criteria)) continue;
            var product = ParseProduct(criteria);
            var versionRange = ExtractCpeVersionRange(cpeMatch);
            var rangeType = versionRange is not null ? "cpe_match" : "cpe_match_no_range";
            await using var cmd = new NpgsqlCommand("""
                insert into vulnerability_affected_facts
                  (vulnerability_id, vulnerability_record_id, source_id, raw_index_id, fact_type, ecosystem,
                   cpe23_uri, package_name, normalized_package_name, version_range_raw, range_type, vulnerable,
                   source_specific)
                values ($1,$2,$3,$4,'cpe','cpe',$5,$6,lower($6),$7,$8,$9,'{}'::jsonb)
                """, conn);
            cmd.Parameters.AddWithValue(vulnerabilityId);
            cmd.Parameters.AddWithValue(recordId);
            cmd.Parameters.AddWithValue(record.SourceId);
            cmd.Parameters.AddWithValue(record.RawIndexId);
            cmd.Parameters.AddWithValue(criteria);
            cmd.Parameters.AddWithValue(product);
            cmd.Parameters.AddWithValue((object?)versionRange ?? DBNull.Value);
            cmd.Parameters.AddWithValue(rangeType);
            cmd.Parameters.AddWithValue(cpeMatch?["vulnerable"]?.GetValue<bool>() ?? true);
            await cmd.ExecuteNonQueryAsync(ct);
            facts.Add(new AffectedFactDraft("cpe", "cpe", product, null, versionRange, rangeType, cpeMatch?.ToJsonString() ?? "{}", criteria));
        }

        return facts;
    }

    private static string? ExtractCpeVersionRange(JsonNode? cpeMatch)
    {
        if (cpeMatch is null) return null;
        var parts = new List<string>();
        var startInc = cpeMatch["versionStartIncluding"]?.GetValue<string>();
        var startExc = cpeMatch["versionStartExcluding"]?.GetValue<string>();
        var endInc = cpeMatch["versionEndIncluding"]?.GetValue<string>();
        var endExc = cpeMatch["versionEndExcluding"]?.GetValue<string>();

        if (!string.IsNullOrWhiteSpace(startInc)) parts.Add($">= {startInc}");
        if (!string.IsNullOrWhiteSpace(startExc)) parts.Add($"> {startExc}");
        if (!string.IsNullOrWhiteSpace(endInc)) parts.Add($"<= {endInc}");
        if (!string.IsNullOrWhiteSpace(endExc)) parts.Add($"< {endExc}");

        return parts.Count > 0 ? string.Join(", ", parts) : null;
    }

    private static async Task MarkNormalizedAsync(NpgsqlConnection conn, IReadOnlyList<Guid> rawIndexIds, CancellationToken ct)
    {
        if (rawIndexIds.Count == 0) return;
        await using var cmd = new NpgsqlCommand("update source_raw_index set normalize_status = 'succeeded', updated_at = now() where id = any($1)", conn);
        cmd.Parameters.AddWithValue(rawIndexIds.ToArray());
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public static IEnumerable<CvssScore> ExtractCvss(string metricsJson)
    {
        var metrics = JsonNode.Parse(metricsJson);
        if (metrics is null) yield break;
        foreach (var (property, version) in new[] {
            ("cvssMetricV40", "4.0"),
            ("cvssMetricV31", "3.1"),
            ("cvssMetricV30", "3.0"),
            ("cvssMetricV2", "2.0")
        })
        {
            foreach (var metric in metrics[property]?.AsArray() ?? [])
            {
                var data = metric?["cvssData"];
                yield return new CvssScore(
                    version,
                    data?["vectorString"]?.GetValue<string>(),
                    data?["baseScore"]?.GetValue<decimal?>(),
                    data?["baseSeverity"]?.GetValue<string>() ?? metric?["baseSeverity"]?.GetValue<string>(),
                    metric?.ToJsonString() ?? "{}");
            }
        }
    }

    private static IEnumerable<JsonNode?> WalkCpeMatches(JsonNode? configurations)
    {
        if (configurations is null) yield break;
        foreach (var config in configurations.AsArray())
        {
            foreach (var node in config?["nodes"]?.AsArray() ?? [])
            {
                foreach (var match in WalkNode(node)) yield return match;
            }
        }
    }

    private static IEnumerable<JsonNode?> WalkNode(JsonNode? node)
    {
        foreach (var match in node?["cpeMatch"]?.AsArray() ?? []) yield return match;
        foreach (var child in node?["children"]?.AsArray() ?? [])
        {
            foreach (var match in WalkNode(child)) yield return match;
        }
    }

    private static string ParseProduct(string cpe)
    {
        var parts = cpe.Split(':');
        return parts.Length > 4 ? parts[4].Replace("\\", "") : cpe;
    }
}

public sealed record NvdStagingRecord(
    Guid RawIndexId,
    string CveId,
    string? Status,
    string Descriptions,
    string Metrics,
    string Weaknesses,
    string Configurations,
    string References,
    DateTimeOffset? PublishedAt,
    DateTimeOffset? ModifiedAt,
    string Payload,
    Guid SourceId);

public sealed record CvssScore(string Version, string? Vector, decimal? Score, string? Severity, string RawJson);
