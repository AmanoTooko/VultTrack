using Npgsql;

namespace VulTrack.App;

public sealed class DefaultAffectedComponentHook : IAffectedComponentHook
{
    public async Task OnAffectedFactsAsync(NpgsqlConnection connection, Guid vulnerabilityId, Guid vulnerabilityRecordId, IReadOnlyList<AffectedFactDraft> facts, CancellationToken ct)
    {
        var projections = facts
            .Select(fact => new
            {
                Fact = fact,
                DisplayName = fact.PackageName ?? fact.Purl ?? fact.Cpe23Uri
            })
            .Where(x => !string.IsNullOrWhiteSpace(x.DisplayName))
            .GroupBy(x => new
            {
                x.Fact.Ecosystem,
                x.DisplayName,
                x.Fact.Purl,
                x.Fact.Cpe23Uri,
                x.Fact.VersionRange,
                x.Fact.RangeType
            })
            .Select(group => group.First())
            .ToList();

        foreach (var batch in projections.Chunk(4000))
        {
            var values = new List<string>();
            var parameters = new List<object>();
            var parameterIndex = 1;

            foreach (var projection in batch)
            {
                values.Add($"(${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},${parameterIndex++},1,'source facts','default-source-fact-hook')");
                parameters.Add(vulnerabilityId);
                parameters.Add((object?)projection.Fact.Ecosystem ?? DBNull.Value);
                parameters.Add((object?)projection.Fact.PackageName ?? DBNull.Value);
                parameters.Add(projection.DisplayName!);
                parameters.Add((object?)projection.Fact.Purl ?? DBNull.Value);
                parameters.Add((object?)projection.Fact.Cpe23Uri ?? DBNull.Value);
                parameters.Add((object?)projection.Fact.VersionRange ?? DBNull.Value);
                parameters.Add((object?)projection.Fact.RangeType ?? DBNull.Value);
            }

            await using var cmd = new NpgsqlCommand($"""
                insert into vulnerability_affected_components
                  (vulnerability_id, ecosystem, package_name, display_name, primary_purl,
                   primary_cpe23_uri, normalized_range, range_type, evidence_count, evidence_summary, selected_by_rule)
                values {string.Join(",", values)}
                on conflict (
                  vulnerability_id,
                  (coalesce(ecosystem, '')),
                  (coalesce(display_name, '')),
                  (coalesce(primary_purl, '')),
                  (coalesce(primary_cpe23_uri, '')),
                  (coalesce(normalized_range, '')),
                  (coalesce(range_type, ''))
                ) do update set
                  evidence_count = vulnerability_affected_components.evidence_count + 1,
                  updated_at = now()
                """, connection);
            cmd.CommandTimeout = 300;
            foreach (var parameter in parameters) cmd.Parameters.AddWithValue(parameter);
            await cmd.ExecuteNonQueryAsync(ct);
        }
    }

    public async Task FlushProjectionsAsync(NpgsqlConnection connection, IReadOnlyList<Guid> vulnerabilityIds, CancellationToken ct)
    {
        if (vulnerabilityIds.Count == 0) return;
        foreach (var batch in vulnerabilityIds.Distinct().Chunk(500))
        {
            await using var cmd = new NpgsqlCommand("""
                update vulnerabilities
                set affected_component_count = coalesce(t.cnt, 0),
                    affected_ecosystems = coalesce(t.ecos, '{}'),
                    affected_component_names = coalesce(t.names, '{}'),
                    search_text = to_tsvector('simple',
                        coalesce(primary_identifier,'') || ' ' ||
                        coalesce(title,'') || ' ' ||
                        coalesce(description,'') || ' ' ||
                        coalesce(replace(array_to_string(coalesce(t.names, '{}'), ' '), '/', ' '), '')),
                    updated_at = now()
                from (
                    select c.vulnerability_id,
                           count(*)::int as cnt,
                           array_agg(distinct c.ecosystem) filter (where c.ecosystem is not null) as ecos,
                           array_agg(distinct c.display_name) as names
                    from vulnerability_affected_components c
                    where c.vulnerability_id = any($1)
                    group by c.vulnerability_id
                ) t
                where vulnerabilities.id = t.vulnerability_id
                """, connection);
            cmd.CommandTimeout = 300;
            cmd.Parameters.AddWithValue(batch);
            await cmd.ExecuteNonQueryAsync(ct);
        }
    }
}
