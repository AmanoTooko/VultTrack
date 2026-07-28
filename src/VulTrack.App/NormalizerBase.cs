using System.Text.Json.Nodes;
using Npgsql;
using NpgsqlTypes;

namespace VulTrack.App;

public abstract class NormalizerBase(
    IEnumerable<IAffectedComponentHook> affectedHooks,
    IVulnerabilityCanonicalizer canonicalizer)
{
    protected IVulnerabilityCanonicalizer Canonicalizer { get; } = canonicalizer;

    // DuckDB owns high-cardinality evidence; PostgreSQL retains only canonical metadata.
    protected static bool DuckDbEvidenceOnly =>
        string.Equals(Environment.GetEnvironmentVariable("VULTRACK_DUCKDB_EVIDENCE_ONLY"), "true", StringComparison.OrdinalIgnoreCase);

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

    protected static async Task<Dictionary<(Guid SourceId, string SourceRecordId, Guid RawIndexId), Guid>> UpsertRecordsBatchAsync(NpgsqlConnection connection, IReadOnlyList<VulnerabilityRecordBatchItem> items, CancellationToken ct)
    {
        var result = new Dictionary<(Guid SourceId, string SourceRecordId, Guid RawIndexId), Guid>();
        if (items.Count == 0) return result;

        foreach (var batch in items.Chunk(1000))
        {
            var values = new List<string>();
            var parameters = new List<object>();
            var parameterIndex = 1;
            foreach (var item in batch)
            {
                values.Add($"(${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++})");
                parameters.Add(item.VulnerabilityId);
                parameters.Add(item.SourceId);
                parameters.Add(item.RawIndexId);
                parameters.Add(item.SourceRecordId);
                parameters.Add((object?)item.Title ?? DBNull.Value);
                parameters.Add((object?)item.Description ?? DBNull.Value);
                parameters.Add(item.Status ?? "active");
            }

            await using var cmd = new NpgsqlCommand($"""
                insert into vulnerability_records
                  (vulnerability_id, source_id, raw_index_id, source_record_id, title, description, status)
                values {string.Join(",", values)}
                on conflict (source_id, source_record_id, raw_index_id) do update set
                  vulnerability_id = excluded.vulnerability_id,
                  title = excluded.title,
                  description = excluded.description,
                  status = excluded.status,
                  updated_at = now()
                returning source_id, source_record_id, raw_index_id, id
                """, connection);
            cmd.CommandTimeout = 300;
            foreach (var parameter in parameters) cmd.Parameters.AddWithValue(parameter);
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                result[(reader.GetGuid(0), reader.GetString(1), reader.GetGuid(2))] = reader.GetGuid(3);
            }
        }

        return result;
    }

    protected static Task UpsertIdentifiersAsync(NpgsqlConnection connection, Guid vulnerabilityId, Guid sourceId, Guid rawIndexId, IEnumerable<string> identifiers, CancellationToken ct) =>
        Task.CompletedTask;

    protected async Task InsertAffectedFactsAsync(NpgsqlConnection connection, Guid vulnerabilityId, Guid recordId, Guid sourceId, Guid rawIndexId, IReadOnlyList<AffectedFactDraft> facts, CancellationToken ct)
    {
        if (DuckDbEvidenceOnly) return;
        if (facts.Count == 0)
        {
            await DispatchAffectedHooksAsync(connection, vulnerabilityId, recordId, facts, ct);
            return;
        }

        var dedupedFacts = facts
            .GroupBy(f => $"{f.FactType}|{f.PackageName ?? ""}|{f.VersionRange ?? ""}|{f.RangeType ?? ""}|{f.Purl ?? ""}|{f.Cpe23Uri ?? ""}|{f.Ecosystem ?? ""}")
            .Select(g => g.First())
            .ToList();

        // Delete existing facts for this record to avoid duplicates on re-normalize
        await using (var delCmd = new NpgsqlCommand(
            "delete from vulnerability_affected_facts where vulnerability_record_id = $1", connection))
        {
            delCmd.Parameters.AddWithValue(recordId);
            await delCmd.ExecuteNonQueryAsync(ct);
        }

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

        await DispatchAffectedHooksAsync(connection, vulnerabilityId, recordId, facts, ct);
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

    protected static async Task InsertDescriptionsBatchAsync(NpgsqlConnection connection, IReadOnlyList<DescriptionBatchItem> items, CancellationToken ct)
    {
        var rows = items
            .SelectMany(item => item.Descriptions
                .Where(x => !string.IsNullOrWhiteSpace(x.Value))
                .GroupBy(x => new { x.Lang, x.DescriptionType })
                .Select(group => group.First())
                .Select(description => new { item.VulnerabilityId, item.VulnerabilityRecordId, item.SourceId, Description = description }))
            .GroupBy(x => new { x.VulnerabilityId, x.SourceId, x.Description.Lang, x.Description.DescriptionType })
            .Select(group => group
                .OrderByDescending(x => x.Description.IsSelected)
                .ThenByDescending(x => x.Description.Value.Length)
                .First())
            .ToList();
        if (rows.Count == 0) return;

        foreach (var batch in rows.Chunk(1000))
        {
            var values = new List<string>();
            var parameters = new List<object>();
            var parameterIndex = 1;
            foreach (var row in batch)
            {
                values.Add($"(${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++})");
                parameters.Add(row.VulnerabilityId);
                parameters.Add(row.VulnerabilityRecordId);
                parameters.Add(row.SourceId);
                parameters.Add((object?)row.Description.Lang ?? DBNull.Value);
                parameters.Add(row.Description.DescriptionType);
                parameters.Add(row.Description.Value);
                parameters.Add(row.Description.IsSelected);
            }

            await using var cmd = new NpgsqlCommand($"""
                insert into vulnerability_descriptions
                  (vulnerability_id, vulnerability_record_id, source_id, lang, description_type, value, is_selected)
                values {string.Join(",", values)}
                on conflict (vulnerability_id, source_id, lang, description_type)
                do update set value = excluded.value, is_selected = excluded.is_selected
                """, connection);
            cmd.CommandTimeout = 300;
            foreach (var parameter in parameters) cmd.Parameters.AddWithValue(parameter);
            await cmd.ExecuteNonQueryAsync(ct);
        }
    }

    protected static async Task InsertSeverityScoresAsync(NpgsqlConnection connection, Guid vulnerabilityId, Guid recordId, Guid sourceId, Guid rawIndexId, IReadOnlyList<SeverityScoreDraft> scores, CancellationToken ct)
    {
        if (DuckDbEvidenceOnly)
        {
            var summary = scores
                .Where(x => x.Score is not null)
                .OrderByDescending(x => x.Score)
                .FirstOrDefault();
            if (summary is not null)
                await UpdateSeveritySummaryAsync(connection, vulnerabilityId, summary, ct);
            return;
        }

        // Delete existing scores for this record to avoid duplicates on re-normalize
        await using (var delCmd = new NpgsqlCommand(
            "delete from vulnerability_severity_scores where vulnerability_record_id = $1", connection))
        {
            delCmd.Parameters.AddWithValue(recordId);
            await delCmd.ExecuteNonQueryAsync(ct);
        }

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
                  and (max_cvss_score is null or max_cvss_score < $2 or (severity_label is null and $5 is not null))
                """, connection);
            update.Parameters.AddWithValue(vulnerabilityId);
            update.Parameters.AddWithValue(selectedScore);
            update.Parameters.AddWithValue((object?)selected.ScoringVersion ?? DBNull.Value);
            update.Parameters.AddWithValue((object?)selected.VectorString ?? DBNull.Value);
            update.Parameters.AddWithValue((object?)selected.SeverityLabel ?? DBNull.Value);
            await update.ExecuteNonQueryAsync(ct);
        }
    }

    protected static async Task InsertSeverityScoresBatchAsync(NpgsqlConnection connection, IReadOnlyList<SeverityScoreBatchItem> items, CancellationToken ct)
    {
        if (items.Count == 0) return;
        if (DuckDbEvidenceOnly)
        {
            var summaries = items
                .SelectMany(item => item.Scores
                    .Where(score => score.Score is not null)
                    .Select(score => new { item.VulnerabilityId, Score = score }))
                .GroupBy(x => x.VulnerabilityId)
                .Select(group => group.OrderByDescending(x => x.Score.Score).First())
                .ToList();
            await UpdateSeveritySummariesBatchAsync(connection, summaries.Select(x => (x.VulnerabilityId, x.Score)).ToList(), ct);
            return;
        }

        await DeleteRecordRowsBatchAsync(connection, "vulnerability_severity_scores", items.Select(x => x.VulnerabilityRecordId).ToArray(), ct);

        var rows = items.SelectMany(item =>
        {
            var selected = item.Scores
                .Where(x => x.Score is not null)
                .OrderByDescending(x => x.Score)
                .FirstOrDefault();
            return item.Scores.Select(score => new
            {
                item.VulnerabilityId,
                item.VulnerabilityRecordId,
                item.SourceId,
                item.RawIndexId,
                Score = score,
                IsSelected = score.IsSelected || (selected is not null && score == selected)
            });
        }).ToList();

        foreach (var batch in rows.Chunk(1000))
        {
            var values = new List<string>();
            var parameters = new List<object>();
            var parameterIndex = 1;
            foreach (var row in batch)
            {
                values.Add($"(${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++}::jsonb,${parameterIndex++})");
                parameters.Add(row.VulnerabilityId);
                parameters.Add(row.VulnerabilityRecordId);
                parameters.Add(row.SourceId);
                parameters.Add(row.RawIndexId);
                parameters.Add(row.Score.ScoringSystem);
                parameters.Add((object?)row.Score.ScoringVersion ?? DBNull.Value);
                parameters.Add((object?)row.Score.ScoreType ?? DBNull.Value);
                parameters.Add((object?)row.Score.VectorString ?? DBNull.Value);
                parameters.Add((object?)row.Score.Score ?? DBNull.Value);
                parameters.Add((object?)row.Score.SeverityLabel ?? DBNull.Value);
                parameters.Add((object?)row.Score.SeverityLabel ?? DBNull.Value);
                parameters.Add((object?)row.Score.SeverityLabel ?? DBNull.Value);
                parameters.Add(row.Score.MetricJson);
                parameters.Add(row.IsSelected);
            }

            await using var cmd = new NpgsqlCommand($"""
                insert into vulnerability_severity_scores
                  (vulnerability_id, vulnerability_record_id, source_id, raw_index_id, scoring_system, scoring_version,
                   score_type, vector_string, score, severity_label, normalized_severity, source_severity_label,
                   metric_json, is_selected)
                values {string.Join(",", values)}
                """, connection);
            cmd.CommandTimeout = 300;
            foreach (var parameter in parameters) cmd.Parameters.AddWithValue(parameter);
            await cmd.ExecuteNonQueryAsync(ct);
        }

        var bestScores = rows
            .Where(x => x.Score.Score is not null)
            .GroupBy(x => x.VulnerabilityId)
            .Select(group => group.OrderByDescending(x => x.Score.Score).First())
            .ToList();
        foreach (var batch in bestScores.Chunk(1000))
        {
            var values = new List<string>();
            var parameters = new List<object>();
            var parameterIndex = 1;
            foreach (var row in batch)
            {
                values.Add($"(${parameterIndex++}::uuid,${parameterIndex++}::numeric,${parameterIndex++},${parameterIndex++},${parameterIndex++})");
                parameters.Add(row.VulnerabilityId);
                parameters.Add(row.Score.Score!.Value);
                parameters.Add((object?)row.Score.ScoringVersion ?? DBNull.Value);
                parameters.Add((object?)row.Score.VectorString ?? DBNull.Value);
                parameters.Add((object?)row.Score.SeverityLabel ?? DBNull.Value);
            }

            await using var update = new NpgsqlCommand($"""
                update vulnerabilities v
                set max_cvss_score = case when v.max_cvss_score is null or v.max_cvss_score < incoming.score then incoming.score else v.max_cvss_score end,
                    max_cvss_version = case when v.max_cvss_score is null or v.max_cvss_score < incoming.score then incoming.version else v.max_cvss_version end,
                    max_cvss_vector = case when v.max_cvss_score is null or v.max_cvss_score < incoming.score then incoming.vector else v.max_cvss_vector end,
                    severity_label = coalesce(v.severity_label, incoming.label),
                    updated_at = now()
                from (values {string.Join(",", values)}) as incoming(id, score, version, vector, label)
                where v.id = incoming.id
                  and (v.max_cvss_score is null or v.max_cvss_score < incoming.score
                       or (v.severity_label is null and incoming.label is not null))
                """, connection);
            update.CommandTimeout = 300;
            foreach (var parameter in parameters) update.Parameters.AddWithValue(parameter);
            await update.ExecuteNonQueryAsync(ct);
        }
    }

    private static async Task UpdateSeveritySummaryAsync(
        NpgsqlConnection connection,
        Guid vulnerabilityId,
        SeverityScoreDraft score,
        CancellationToken ct)
    {
        await using var update = new NpgsqlCommand("""
            update vulnerabilities
            set max_cvss_score = case when max_cvss_score is null or max_cvss_score < $2 then $2 else max_cvss_score end,
                max_cvss_version = case when max_cvss_score is null or max_cvss_score < $2 then $3 else max_cvss_version end,
                max_cvss_vector = case when max_cvss_score is null or max_cvss_score < $2 then $4 else max_cvss_vector end,
                severity_label = coalesce(severity_label, $5),
                updated_at = now()
            where id = $1
              and (max_cvss_score is null or max_cvss_score < $2 or (severity_label is null and $5 is not null))
            """, connection);
        update.Parameters.AddWithValue(vulnerabilityId);
        update.Parameters.AddWithValue(score.Score!.Value);
        update.Parameters.AddWithValue((object?)score.ScoringVersion ?? DBNull.Value);
        update.Parameters.AddWithValue((object?)score.VectorString ?? DBNull.Value);
        update.Parameters.AddWithValue((object?)score.SeverityLabel ?? DBNull.Value);
        await update.ExecuteNonQueryAsync(ct);
    }

    private static async Task UpdateSeveritySummariesBatchAsync(
        NpgsqlConnection connection,
        IReadOnlyList<(Guid VulnerabilityId, SeverityScoreDraft Score)> summaries,
        CancellationToken ct)
    {
        foreach (var batch in summaries.Chunk(1000))
        {
            var values = new List<string>();
            var parameters = new List<object>();
            var parameterIndex = 1;
            foreach (var row in batch)
            {
                values.Add($"(${parameterIndex++}::uuid,${parameterIndex++}::numeric,${parameterIndex++},${parameterIndex++},${parameterIndex++})");
                parameters.Add(row.VulnerabilityId);
                parameters.Add(row.Score.Score!.Value);
                parameters.Add((object?)row.Score.ScoringVersion ?? DBNull.Value);
                parameters.Add((object?)row.Score.VectorString ?? DBNull.Value);
                parameters.Add((object?)row.Score.SeverityLabel ?? DBNull.Value);
            }

            await using var update = new NpgsqlCommand($"""
                update vulnerabilities v
                set max_cvss_score = case when v.max_cvss_score is null or v.max_cvss_score < incoming.score then incoming.score else v.max_cvss_score end,
                    max_cvss_version = case when v.max_cvss_score is null or v.max_cvss_score < incoming.score then incoming.version else v.max_cvss_version end,
                    max_cvss_vector = case when v.max_cvss_score is null or v.max_cvss_score < incoming.score then incoming.vector else v.max_cvss_vector end,
                    severity_label = coalesce(v.severity_label, incoming.label),
                    updated_at = now()
                from (values {string.Join(",", values)}) as incoming(id, score, version, vector, label)
                where v.id = incoming.id
                  and (v.max_cvss_score is null or v.max_cvss_score < incoming.score
                       or (v.severity_label is null and incoming.label is not null))
                """, connection);
            update.CommandTimeout = 300;
            foreach (var parameter in parameters) update.Parameters.AddWithValue(parameter);
            await update.ExecuteNonQueryAsync(ct);
        }
    }

    protected static async Task InsertReferencesAsync(NpgsqlConnection connection, Guid vulnerabilityId, Guid recordId, Guid sourceId, IReadOnlyList<ReferenceDraft> references, CancellationToken ct)
    {
        if (DuckDbEvidenceOnly) return;
        var valid = references.Where(x => !string.IsNullOrWhiteSpace(x.Url)).DistinctBy(x => x.Url).ToList();
        if (valid.Count == 0) return;

        // Delete existing references for this record to avoid duplicates on re-normalize
        await using (var delCmd = new NpgsqlCommand(
            "delete from vulnerability_references where vulnerability_record_id = $1", connection))
        {
            delCmd.Parameters.AddWithValue(recordId);
            await delCmd.ExecuteNonQueryAsync(ct);
        }

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

    protected static async Task InsertReferencesBatchAsync(NpgsqlConnection connection, IReadOnlyList<ReferenceBatchItem> items, CancellationToken ct)
    {
        if (DuckDbEvidenceOnly) return;
        if (items.Count == 0) return;
        await DeleteRecordRowsBatchAsync(connection, "vulnerability_references", items.Select(x => x.VulnerabilityRecordId).ToArray(), ct);

        var rows = items
            .SelectMany(item => item.References
                .Where(x => !string.IsNullOrWhiteSpace(x.Url))
                .DistinctBy(x => x.Url)
                .Select(reference => new { item.VulnerabilityId, item.VulnerabilityRecordId, item.SourceId, Reference = reference }))
            .ToList();
        if (rows.Count == 0) return;

        foreach (var batch in rows.Chunk(1000))
        {
            var values = new List<string>();
            var parameters = new List<object>();
            var parameterIndex = 1;
            foreach (var row in batch)
            {
                values.Add($"(${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},lower(${parameterIndex - 1}),${parameterIndex++},${parameterIndex++},${parameterIndex++})");
                parameters.Add(row.VulnerabilityId);
                parameters.Add(row.VulnerabilityRecordId);
                parameters.Add(row.SourceId);
                parameters.Add(row.Reference.Url);
                parameters.Add((object?)row.Reference.RefType ?? DBNull.Value);
                parameters.Add(row.Reference.Tags);
                parameters.Add((object?)row.Reference.SourceJsonPath ?? DBNull.Value);
            }

            await using var cmd = new NpgsqlCommand($"""
                insert into vulnerability_references
                  (vulnerability_id, vulnerability_record_id, source_id, url, normalized_url, ref_type, tags, source_json_path)
                values {string.Join(",", values)}
                """, connection);
            cmd.CommandTimeout = 300;
            foreach (var parameter in parameters) cmd.Parameters.AddWithValue(parameter);
            await cmd.ExecuteNonQueryAsync(ct);
        }
    }

    protected async Task InsertAffectedFactsBatchAsync(NpgsqlConnection connection, IReadOnlyList<AffectedFactBatchItem> items, CancellationToken ct)
    {
        if (items.Count == 0) return;
        if (DuckDbEvidenceOnly) return;
        await DeleteRecordRowsBatchAsync(connection, "vulnerability_affected_facts", items.Select(x => x.VulnerabilityRecordId).ToArray(), ct);

        var rows = items
            .SelectMany(item => item.Facts
                .GroupBy(f => $"{f.FactType}|{f.PackageName ?? ""}|{f.VersionRange ?? ""}|{f.RangeType ?? ""}|{f.Purl ?? ""}|{f.Cpe23Uri ?? ""}|{f.Ecosystem ?? ""}")
                .Select(group => group.First())
                .Select(fact => new AffectedFactCopyRow(item.VulnerabilityId, item.VulnerabilityRecordId, item.SourceId, item.RawIndexId, fact)))
            .ToList();

        if (rows.Count > 0)
            await CopyAffectedFactsAsync(connection, rows, ct);

        await DispatchAffectedHooksBatchAsync(connection, items, ct);
    }

    protected static async Task InsertWeaknessesAsync(NpgsqlConnection connection, Guid vulnerabilityId, Guid recordId, Guid sourceId, IReadOnlyList<WeaknessDraft> weaknesses, CancellationToken ct)
    {
        if (DuckDbEvidenceOnly) return;
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

    protected static async Task InsertWeaknessesBatchAsync(NpgsqlConnection connection, IReadOnlyList<WeaknessBatchItem> items, CancellationToken ct)
    {
        if (DuckDbEvidenceOnly) return;
        var rows = items
            .SelectMany(item => item.Weaknesses
                .Where(x => !string.IsNullOrWhiteSpace(x.WeaknessId) || !string.IsNullOrWhiteSpace(x.Description))
                .GroupBy(x => string.IsNullOrWhiteSpace(x.WeaknessId) ? "" : x.WeaknessId.Trim(), StringComparer.OrdinalIgnoreCase)
                .Select(group => group.First())
                .Select(weakness => new { item.VulnerabilityId, item.VulnerabilityRecordId, item.SourceId, Weakness = weakness }))
            .GroupBy(x => new
            {
                x.VulnerabilityId,
                x.SourceId,
                WeaknessId = string.IsNullOrWhiteSpace(x.Weakness.WeaknessId) ? "" : x.Weakness.WeaknessId.Trim()
            })
            .Select(group => group.First())
            .ToList();
        if (rows.Count == 0) return;

        foreach (var batch in rows.Chunk(1000))
        {
            var values = new List<string>();
            var parameters = new List<object>();
            var parameterIndex = 1;
            foreach (var row in batch)
            {
                values.Add($"(${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++})");
                parameters.Add(row.VulnerabilityId);
                parameters.Add(row.VulnerabilityRecordId);
                parameters.Add(row.SourceId);
                parameters.Add(row.Weakness.WeaknessType);
                parameters.Add((object?)row.Weakness.WeaknessId ?? DBNull.Value);
                parameters.Add((object?)row.Weakness.Description ?? DBNull.Value);
            }

            await using var cmd = new NpgsqlCommand($"""
                insert into vulnerability_weaknesses
                  (vulnerability_id, vulnerability_record_id, source_id, weakness_type, weakness_id, description)
                values {string.Join(",", values)}
                on conflict (vulnerability_id, source_id, coalesce(weakness_id,'')) do nothing
                """, connection);
            cmd.CommandTimeout = 300;
            foreach (var parameter in parameters) cmd.Parameters.AddWithValue(parameter);
            await cmd.ExecuteNonQueryAsync(ct);
        }
    }

    protected async Task FlushAffectedProjectionsAsync(NpgsqlConnection connection, IReadOnlyCollection<Guid> vulnerabilityIds, CancellationToken ct)
    {
        if (vulnerabilityIds.Count == 0) return;
        var distinctVulnerabilityIds = vulnerabilityIds.Distinct().ToList();
        foreach (var hook in affectedHooks)
        {
            await hook.FlushProjectionsAsync(connection, distinctVulnerabilityIds, ct);
        }
    }

    protected async Task DispatchAffectedHooksAsync(NpgsqlConnection connection, Guid vulnerabilityId, Guid vulnerabilityRecordId, IReadOnlyList<AffectedFactDraft> facts, CancellationToken ct)
    {
        foreach (var hook in affectedHooks)
        {
            await hook.OnAffectedFactsAsync(connection, vulnerabilityId, vulnerabilityRecordId, facts, ct);
        }
    }

    protected async Task DispatchAffectedHooksBatchAsync(NpgsqlConnection connection, IReadOnlyList<AffectedFactBatchItem> items, CancellationToken ct)
    {
        foreach (var hook in affectedHooks)
        {
            if (hook is IBatchAffectedComponentHook batchHook)
            {
                await batchHook.OnAffectedFactsBatchAsync(connection, items, ct);
            }
            else
            {
                foreach (var item in items)
                    await hook.OnAffectedFactsAsync(connection, item.VulnerabilityId, item.VulnerabilityRecordId, item.Facts, ct);
            }
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

    protected static async Task DeleteRecordRowsBatchAsync(NpgsqlConnection connection, string tableName, IReadOnlyList<Guid> recordIds, CancellationToken ct)
    {
        if (recordIds.Count == 0) return;
        foreach (var batch in recordIds.Distinct().Chunk(4000))
        {
            await using var cmd = new NpgsqlCommand($"delete from {tableName} where vulnerability_record_id = any($1)", connection);
            cmd.CommandTimeout = 300;
            cmd.Parameters.AddWithValue(batch.ToArray());
            await cmd.ExecuteNonQueryAsync(ct);
        }
    }

    private static async Task CopyAffectedFactsAsync(
        NpgsqlConnection connection,
        IReadOnlyList<AffectedFactCopyRow> rows,
        CancellationToken ct)
    {
        await using var writer = await connection.BeginBinaryImportAsync("""
            copy vulnerability_affected_facts
              (vulnerability_id, vulnerability_record_id, source_id, raw_index_id, fact_type, ecosystem,
               package_name, normalized_package_name, purl, purl_without_version, cpe23_uri,
               version_range_raw, range_type, vulnerable)
            from stdin (format binary)
            """, ct);
        writer.Timeout = TimeSpan.FromMinutes(5);

        foreach (var row in rows)
        {
            var fact = row.Fact;
            string? packageName = fact.PackageName;
            await writer.StartRowAsync(ct);
            await writer.WriteAsync(row.VulnerabilityId, NpgsqlDbType.Uuid, ct);
            await writer.WriteAsync(row.VulnerabilityRecordId, NpgsqlDbType.Uuid, ct);
            await writer.WriteAsync(row.SourceId, NpgsqlDbType.Uuid, ct);
            await writer.WriteAsync(row.RawIndexId, NpgsqlDbType.Uuid, ct);
            await writer.WriteAsync(fact.FactType, NpgsqlDbType.Text, ct);
            await WriteNullableTextAsync(writer, fact.Ecosystem, ct);
            await WriteNullableTextAsync(writer, packageName, ct);
            await WriteNullableTextAsync(writer, packageName?.ToLowerInvariant(), ct);
            await WriteNullableTextAsync(writer, fact.Purl, ct);
            await WriteNullableTextAsync(writer, PurlWithoutVersion(fact.Purl), ct);
            await WriteNullableTextAsync(writer, fact.Cpe23Uri, ct);
            await WriteNullableTextAsync(writer, fact.VersionRange, ct);
            await WriteNullableTextAsync(writer, fact.RangeType, ct);
            await writer.WriteAsync(true, NpgsqlDbType.Boolean, ct);
        }

        await writer.CompleteAsync(ct);
    }

    private static Task WriteNullableTextAsync(NpgsqlBinaryImporter writer, string? value, CancellationToken ct) =>
        string.IsNullOrWhiteSpace(value)
            ? writer.WriteNullAsync(ct)
            : writer.WriteAsync(value, NpgsqlDbType.Text, ct);

    private sealed record AffectedFactCopyRow(
        Guid VulnerabilityId,
        Guid VulnerabilityRecordId,
        Guid SourceId,
        Guid RawIndexId,
        AffectedFactDraft Fact);

    protected static string[] IdentifiersFrom(params IEnumerable<string?>[] groups) =>
        groups
            .SelectMany(x => x)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .SelectMany(x => Identifier.ExpandWithEmbeddedCves(x!))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    protected static Guid ResolveCanonicalIdFromCache(VulnerabilityCanonicalDraft draft, IReadOnlyDictionary<string, Guid> cache, Guid fallback)
    {
        foreach (var identifier in CanonicalIdentifierPolicy.ResolutionIdentifiers(draft))
        {
            if (cache.TryGetValue(identifier, out var canonicalId) && canonicalId != default)
                return canonicalId;
        }

        return fallback;
    }

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
