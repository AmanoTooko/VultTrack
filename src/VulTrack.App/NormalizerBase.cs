using System.Text.Json.Nodes;
using Npgsql;

namespace VulTrack.App;

public abstract class NormalizerBase(
    IEnumerable<IAffectedComponentHook> affectedHooks,
    IVulnerabilityCanonicalizer canonicalizer)
{
    protected IVulnerabilityCanonicalizer Canonicalizer { get; } = canonicalizer;

    protected Task<Guid> UpsertVulnerabilityAsync(NpgsqlConnection connection, Guid sourceId, Guid rawIndexId, string primaryIdentifier, string? title, string? description, string? status, DateTimeOffset? publishedAt, DateTimeOffset? modifiedAt, string[] identifiers, CancellationToken ct) =>
        Canonicalizer.UpsertCanonicalAsync(
            connection,
            new VulnerabilityCanonicalDraft(primaryIdentifier, title, description, status, publishedAt, modifiedAt, identifiers, sourceId, rawIndexId),
            ct);

    protected async Task<Guid> UpsertRecordAsync(NpgsqlConnection connection, Guid vulnerabilityId, Guid sourceId, Guid rawIndexId, string sourceRecordId, string? title, string? description, string? status, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("""
            insert into vulnerability_records
              (vulnerability_id, source_id, raw_index_id, source_record_id, title, description, status)
            values ($1,$2,$3,$4,$5,$6,$7)
            on conflict (source_id, source_record_id, raw_index_id) do update set
              vulnerability_id = excluded.vulnerability_id,
              title = excluded.title,
              description = excluded.description,
              status = excluded.status,
              updated_at = now()
            returning id
            """, connection);
        cmd.Parameters.AddWithValue(vulnerabilityId);
        cmd.Parameters.AddWithValue(sourceId);
        cmd.Parameters.AddWithValue(rawIndexId);
        cmd.Parameters.AddWithValue(sourceRecordId);
        cmd.Parameters.AddWithValue((object?)title ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)description ?? DBNull.Value);
        cmd.Parameters.AddWithValue(status ?? "active");
        return (Guid)(await cmd.ExecuteScalarAsync(ct))!;
    }

    protected static Task UpsertIdentifiersAsync(NpgsqlConnection connection, Guid vulnerabilityId, Guid sourceId, Guid rawIndexId, IEnumerable<string> identifiers, CancellationToken ct) =>
        Task.CompletedTask;

    protected async Task InsertAffectedFactsAsync(NpgsqlConnection connection, Guid vulnerabilityId, Guid recordId, Guid sourceId, Guid rawIndexId, IReadOnlyList<AffectedFactDraft> facts, CancellationToken ct)
    {
        if (facts.Count == 0)
        {
            foreach (var hook in affectedHooks)
                await hook.OnAffectedFactsAsync(connection, vulnerabilityId, recordId, facts, ct);
            return;
        }

        var dedupedFacts = facts
            .GroupBy(f => $"{f.FactType}|{f.PackageName ?? ""}|{f.VersionRange ?? ""}|{f.RangeType ?? ""}|{f.Purl ?? ""}|{f.Cpe23Uri ?? ""}|{f.Ecosystem ?? ""}")
            .Select(g => g.First())
            .ToList();

        if (dedupedFacts.Count == 1)
        {
            var fact = dedupedFacts[0];
            await using var cmd = new NpgsqlCommand("""
                insert into vulnerability_affected_facts
                  (vulnerability_id, vulnerability_record_id, source_id, raw_index_id, fact_type, ecosystem,
                   package_name, normalized_package_name, purl, purl_without_version, cpe23_uri,
                   version_range_raw, range_type, vulnerable)
                values ($1,$2,$3,$4,$5,$6,$7,lower($7),$8,$9,$10,$11,$12,true)
                """, connection);
            cmd.Parameters.AddWithValue(vulnerabilityId);
            cmd.Parameters.AddWithValue(recordId);
            cmd.Parameters.AddWithValue(sourceId);
            cmd.Parameters.AddWithValue(rawIndexId);
            cmd.Parameters.AddWithValue(fact.FactType);
            cmd.Parameters.AddWithValue((object?)fact.Ecosystem ?? DBNull.Value);
            cmd.Parameters.AddWithValue((object?)fact.PackageName ?? DBNull.Value);
            cmd.Parameters.AddWithValue((object?)fact.Purl ?? DBNull.Value);
            cmd.Parameters.AddWithValue((object?)PurlWithoutVersion(fact.Purl) ?? DBNull.Value);
            cmd.Parameters.AddWithValue((object?)fact.Cpe23Uri ?? DBNull.Value);
            cmd.Parameters.AddWithValue((object?)fact.VersionRange ?? DBNull.Value);
            cmd.Parameters.AddWithValue((object?)fact.RangeType ?? DBNull.Value);
            await cmd.ExecuteNonQueryAsync(ct);
        }
        else
        {
            foreach (var batch in dedupedFacts.Chunk(4000))
            {
                var values = new List<string>();
                var paramIdx = 1;
                var cmdParams = new List<object>();
                foreach (var fact in batch)
                {
                    values.Add($"(${paramIdx++},${paramIdx++},${paramIdx++},${paramIdx++},${paramIdx++},${paramIdx++},${paramIdx++},lower(${paramIdx - 1}),${paramIdx++},${paramIdx++},${paramIdx++},${paramIdx++},${paramIdx++},true)");
                    cmdParams.Add(vulnerabilityId);
                    cmdParams.Add(recordId);
                    cmdParams.Add(sourceId);
                    cmdParams.Add(rawIndexId);
                    cmdParams.Add(fact.FactType);
                    cmdParams.Add((object?)fact.Ecosystem ?? DBNull.Value);
                    cmdParams.Add((object?)fact.PackageName ?? DBNull.Value);
                    cmdParams.Add((object?)fact.Purl ?? DBNull.Value);
                    cmdParams.Add((object?)PurlWithoutVersion(fact.Purl) ?? DBNull.Value);
                    cmdParams.Add((object?)fact.Cpe23Uri ?? DBNull.Value);
                    cmdParams.Add((object?)fact.VersionRange ?? DBNull.Value);
                    cmdParams.Add((object?)fact.RangeType ?? DBNull.Value);
                }

                await using var batchCmd = new NpgsqlCommand(
                    $"insert into vulnerability_affected_facts (vulnerability_id, vulnerability_record_id, source_id, raw_index_id, fact_type, ecosystem, package_name, normalized_package_name, purl, purl_without_version, cpe23_uri, version_range_raw, range_type, vulnerable) values {string.Join(",", values)}",
                    connection);
                for (var i = 0; i < cmdParams.Count; i++) batchCmd.Parameters.AddWithValue(cmdParams[i]);
                await batchCmd.ExecuteNonQueryAsync(ct);
            }
        }

        foreach (var hook in affectedHooks)
        {
            await hook.OnAffectedFactsAsync(connection, vulnerabilityId, recordId, facts, ct);
        }
    }

    protected static async Task InsertDescriptionsAsync(NpgsqlConnection connection, Guid vulnerabilityId, Guid recordId, Guid sourceId, IReadOnlyList<DescriptionDraft> descriptions, CancellationToken ct)
    {
        var valid = descriptions
            .Where(x => !string.IsNullOrWhiteSpace(x.Value))
            .GroupBy(x => new { x.Lang, x.DescriptionType })
            .Select(g => g.First())
            .ToList();
        if (valid.Count == 0) return;

        if (valid.Count == 1)
        {
            var d = valid[0];
            await using var cmd = new NpgsqlCommand("""
                insert into vulnerability_descriptions
                  (vulnerability_id, vulnerability_record_id, source_id, lang, description_type, value, is_selected)
                values ($1,$2,$3,$4,$5,$6,$7)
                on conflict (vulnerability_id, source_id, lang, description_type)
                do update set value = excluded.value, is_selected = excluded.is_selected
                """, connection);
            cmd.Parameters.AddWithValue(vulnerabilityId);
            cmd.Parameters.AddWithValue(recordId);
            cmd.Parameters.AddWithValue(sourceId);
            cmd.Parameters.AddWithValue((object?)d.Lang ?? DBNull.Value);
            cmd.Parameters.AddWithValue(d.DescriptionType);
            cmd.Parameters.AddWithValue(d.Value);
            cmd.Parameters.AddWithValue(d.IsSelected);
            await cmd.ExecuteNonQueryAsync(ct);
            return;
        }

        var values = new List<string>();
        var paramIdx = 1;
        var cmdParams = new List<object>();
        foreach (var d in valid)
        {
            values.Add($"(${paramIdx++},${paramIdx++},${paramIdx++},${paramIdx++},${paramIdx++},${paramIdx++},${paramIdx++})");
            cmdParams.Add(vulnerabilityId);
            cmdParams.Add(recordId);
            cmdParams.Add(sourceId);
            cmdParams.Add((object?)d.Lang ?? DBNull.Value);
            cmdParams.Add(d.DescriptionType);
            cmdParams.Add(d.Value);
            cmdParams.Add(d.IsSelected);
        }

        await using var batchCmd = new NpgsqlCommand(
            $"insert into vulnerability_descriptions (vulnerability_id, vulnerability_record_id, source_id, lang, description_type, value, is_selected) values {string.Join(",", values)} on conflict (vulnerability_id, source_id, lang, description_type) do update set value = excluded.value, is_selected = excluded.is_selected",
            connection);
        for (var i = 0; i < cmdParams.Count; i++) batchCmd.Parameters.AddWithValue(cmdParams[i]);
        await batchCmd.ExecuteNonQueryAsync(ct);
    }

    protected static async Task InsertSeverityScoresAsync(NpgsqlConnection connection, Guid vulnerabilityId, Guid recordId, Guid sourceId, Guid rawIndexId, IReadOnlyList<SeverityScoreDraft> scores, CancellationToken ct)
    {
        var selected = scores
            .Where(x => x.Score is not null)
            .OrderByDescending(x => x.Score)
            .FirstOrDefault();

        foreach (var score in scores)
        {
            await using var cmd = new NpgsqlCommand("""
                insert into vulnerability_severity_scores
                  (vulnerability_id, vulnerability_record_id, source_id, raw_index_id, scoring_system, scoring_version,
                   score_type, vector_string, score, severity_label, normalized_severity, source_severity_label,
                   metric_json, is_selected)
                values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10,$10,$11::jsonb,$12)
                """, connection);
            cmd.Parameters.AddWithValue(vulnerabilityId);
            cmd.Parameters.AddWithValue(recordId);
            cmd.Parameters.AddWithValue(sourceId);
            cmd.Parameters.AddWithValue(rawIndexId);
            cmd.Parameters.AddWithValue(score.ScoringSystem);
            cmd.Parameters.AddWithValue((object?)score.ScoringVersion ?? DBNull.Value);
            cmd.Parameters.AddWithValue((object?)score.ScoreType ?? DBNull.Value);
            cmd.Parameters.AddWithValue((object?)score.VectorString ?? DBNull.Value);
            cmd.Parameters.AddWithValue((object?)score.Score ?? DBNull.Value);
            cmd.Parameters.AddWithValue((object?)score.SeverityLabel ?? DBNull.Value);
            cmd.Parameters.AddWithValue(score.MetricJson);
            cmd.Parameters.AddWithValue(score.IsSelected || (selected is not null && score == selected));
            await cmd.ExecuteNonQueryAsync(ct);
        }

        if (selected is not null)
        {
            var selectedScore = selected.Score.GetValueOrDefault();
            await using var update = new NpgsqlCommand("""
                update vulnerabilities
                set max_cvss_score = case when max_cvss_score is null or max_cvss_score < $2 then $2 else max_cvss_score end,
                    max_cvss_version = case when max_cvss_score is null or max_cvss_score < $2 then $3 else max_cvss_version end,
                    max_cvss_vector = case when max_cvss_score is null or max_cvss_score < $2 then $4 else max_cvss_vector end,
                    severity_label = coalesce(severity_label, $5),
                    updated_at = now()
                where id = $1
                """, connection);
            update.Parameters.AddWithValue(vulnerabilityId);
            update.Parameters.AddWithValue(selectedScore);
            update.Parameters.AddWithValue((object?)selected.ScoringVersion ?? DBNull.Value);
            update.Parameters.AddWithValue((object?)selected.VectorString ?? DBNull.Value);
            update.Parameters.AddWithValue((object?)selected.SeverityLabel ?? DBNull.Value);
            await update.ExecuteNonQueryAsync(ct);
        }
    }

    protected static async Task InsertReferencesAsync(NpgsqlConnection connection, Guid vulnerabilityId, Guid recordId, Guid sourceId, IReadOnlyList<ReferenceDraft> references, CancellationToken ct)
    {
        var valid = references.Where(x => !string.IsNullOrWhiteSpace(x.Url)).DistinctBy(x => x.Url).ToList();
        if (valid.Count == 0) return;

        if (valid.Count == 1)
        {
            var r = valid[0];
            await using var cmd = new NpgsqlCommand("""
                insert into vulnerability_references
                  (vulnerability_id, vulnerability_record_id, source_id, url, normalized_url, ref_type, tags, source_json_path)
                values ($1,$2,$3,$4,lower($4),$5,$6,$7)
                """, connection);
            cmd.Parameters.AddWithValue(vulnerabilityId);
            cmd.Parameters.AddWithValue(recordId);
            cmd.Parameters.AddWithValue(sourceId);
            cmd.Parameters.AddWithValue(r.Url);
            cmd.Parameters.AddWithValue((object?)r.RefType ?? DBNull.Value);
            cmd.Parameters.AddWithValue(r.Tags);
            cmd.Parameters.AddWithValue((object?)r.SourceJsonPath ?? DBNull.Value);
            await cmd.ExecuteNonQueryAsync(ct);
            return;
        }

        var values = new List<string>();
        var paramIdx = 1;
        var cmdParams = new List<object>();
        foreach (var r in valid)
        {
            values.Add($"(${paramIdx++},${paramIdx++},${paramIdx++},${paramIdx++},lower(${paramIdx - 1}),${paramIdx++},${paramIdx++},${paramIdx++})");
            cmdParams.Add(vulnerabilityId);
            cmdParams.Add(recordId);
            cmdParams.Add(sourceId);
            cmdParams.Add(r.Url);
            cmdParams.Add((object?)r.RefType ?? DBNull.Value);
            cmdParams.Add(r.Tags);
            cmdParams.Add((object?)r.SourceJsonPath ?? DBNull.Value);
        }

        await using var batchCmd = new NpgsqlCommand(
            $"insert into vulnerability_references (vulnerability_id, vulnerability_record_id, source_id, url, normalized_url, ref_type, tags, source_json_path) values {string.Join(",", values)}",
            connection);
        for (var i = 0; i < cmdParams.Count; i++) batchCmd.Parameters.AddWithValue(cmdParams[i]);
        await batchCmd.ExecuteNonQueryAsync(ct);
    }

    protected static async Task InsertWeaknessesAsync(NpgsqlConnection connection, Guid vulnerabilityId, Guid recordId, Guid sourceId, IReadOnlyList<WeaknessDraft> weaknesses, CancellationToken ct)
    {
        var valid = weaknesses
            .Where(x => !string.IsNullOrWhiteSpace(x.WeaknessId) || !string.IsNullOrWhiteSpace(x.Description))
            .GroupBy(x => string.IsNullOrWhiteSpace(x.WeaknessId) ? "" : x.WeaknessId.Trim(), StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();
        if (valid.Count == 0) return;

        if (valid.Count == 1)
        {
            var w = valid[0];
            await using var cmd = new NpgsqlCommand("""
                insert into vulnerability_weaknesses
                  (vulnerability_id, vulnerability_record_id, source_id, weakness_type, weakness_id, description)
                values ($1,$2,$3,$4,$5,$6) on conflict (vulnerability_id, source_id, coalesce(weakness_id,'')) do nothing
                """, connection);
            cmd.Parameters.AddWithValue(vulnerabilityId);
            cmd.Parameters.AddWithValue(recordId);
            cmd.Parameters.AddWithValue(sourceId);
            cmd.Parameters.AddWithValue(w.WeaknessType);
            cmd.Parameters.AddWithValue((object?)w.WeaknessId ?? DBNull.Value);
            cmd.Parameters.AddWithValue((object?)w.Description ?? DBNull.Value);
            await cmd.ExecuteNonQueryAsync(ct);
            return;
        }

        var values = new List<string>();
        var paramIdx = 1;
        var cmdParams = new List<object>();
        foreach (var w in valid)
        {
            values.Add($"(${paramIdx++},${paramIdx++},${paramIdx++},${paramIdx++},${paramIdx++},${paramIdx++})");
            cmdParams.Add(vulnerabilityId);
            cmdParams.Add(recordId);
            cmdParams.Add(sourceId);
            cmdParams.Add(w.WeaknessType);
            cmdParams.Add((object?)w.WeaknessId ?? DBNull.Value);
            cmdParams.Add((object?)w.Description ?? DBNull.Value);
        }

        await using var batchCmd = new NpgsqlCommand(
            $"insert into vulnerability_weaknesses (vulnerability_id, vulnerability_record_id, source_id, weakness_type, weakness_id, description) values {string.Join(",", values)} on conflict (vulnerability_id, source_id, coalesce(weakness_id,'')) do nothing",
            connection);
        for (var i = 0; i < cmdParams.Count; i++) batchCmd.Parameters.AddWithValue(cmdParams[i]);
        await batchCmd.ExecuteNonQueryAsync(ct);
    }

    protected async Task FlushAffectedProjectionsAsync(NpgsqlConnection connection, IReadOnlyCollection<Guid> vulnerabilityIds, CancellationToken ct)
    {
        if (vulnerabilityIds.Count == 0) return;
        foreach (var hook in affectedHooks)
        {
            await hook.FlushProjectionsAsync(connection, vulnerabilityIds.ToList(), ct);
        }
    }

    protected static async Task MarkNormalizedAsync(NpgsqlConnection connection, Guid rawIndexId, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("update source_raw_index set normalize_status = 'succeeded', updated_at = now() where id = $1", connection);
        cmd.Parameters.AddWithValue(rawIndexId);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    protected static async Task MarkNormalizedBatchAsync(NpgsqlConnection connection, IReadOnlyList<Guid> rawIndexIds, CancellationToken ct)
    {
        if (rawIndexIds.Count == 0) return;
        await using var cmd = new NpgsqlCommand("update source_raw_index set normalize_status = 'succeeded', updated_at = now() where id = any($1)", connection);
        cmd.Parameters.AddWithValue(rawIndexIds.ToArray());
        await cmd.ExecuteNonQueryAsync(ct);
    }

    protected static string[] IdentifiersFrom(params IEnumerable<string?>[] groups) =>
        groups.SelectMany(x => x).Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x!).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

    protected static DateTimeOffset? DateValue(JsonNode? node, string name)
    {
        var value = node?[name]?.GetValue<string>();
        return DateTimeOffset.TryParse(value, out var parsed) ? parsed : null;
    }

    private static string? PurlWithoutVersion(string? purl)
    {
        if (string.IsNullOrWhiteSpace(purl)) return null;
        var at = purl.LastIndexOf('@');
        return at > "pkg:".Length ? purl[..at] : purl;
    }
}
