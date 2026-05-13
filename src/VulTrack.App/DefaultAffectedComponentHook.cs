using Npgsql;

namespace VulTrack.App;

public sealed class DefaultAffectedComponentHook : IAffectedComponentHook
{
    public async Task OnAffectedFactsAsync(NpgsqlConnection connection, Guid vulnerabilityId, Guid vulnerabilityRecordId, IReadOnlyList<AffectedFactDraft> facts, CancellationToken ct)
    {
        foreach (var fact in facts)
        {
            var displayName = fact.PackageName ?? fact.Purl;
            if (string.IsNullOrWhiteSpace(displayName)) continue;

            await using var cmd = new NpgsqlCommand("""
                with existing as (
                    select id from vulnerability_affected_components
                    where vulnerability_id = $1
                      and coalesce(ecosystem, '') = coalesce($2, '')
                      and coalesce(display_name, '') = coalesce($4, '')
                      and coalesce(primary_purl, '') = coalesce($5, '')
                      and coalesce(normalized_range, '') = coalesce($6, '')
                      and coalesce(range_type, '') = coalesce($7, '')
                    limit 1
                ), inserted as (
                    insert into vulnerability_affected_components
                      (vulnerability_id, ecosystem, package_name, display_name, primary_purl,
                       normalized_range, range_type, evidence_count, evidence_summary, selected_by_rule)
                    select $1,$2,$3,$4,$5,$6,$7,1,'source facts','default-source-fact-hook'
                    where not exists (select 1 from existing)
                    returning id
                )
                update vulnerability_affected_components
                set evidence_count = evidence_count + 1, updated_at = now()
                where id = (select id from existing union all select id from inserted limit 1)
                """, connection);
            cmd.Parameters.AddWithValue(vulnerabilityId);
            cmd.Parameters.AddWithValue((object?)fact.Ecosystem ?? DBNull.Value);
            cmd.Parameters.AddWithValue((object?)fact.PackageName ?? DBNull.Value);
            cmd.Parameters.AddWithValue(displayName);
            cmd.Parameters.AddWithValue((object?)fact.Purl ?? DBNull.Value);
            cmd.Parameters.AddWithValue((object?)fact.VersionRange ?? DBNull.Value);
            cmd.Parameters.AddWithValue((object?)fact.RangeType ?? DBNull.Value);
            await cmd.ExecuteNonQueryAsync(ct);
        }
    }

    public async Task FlushProjectionsAsync(NpgsqlConnection connection, IReadOnlyList<Guid> vulnerabilityIds, CancellationToken ct)
    {
        if (vulnerabilityIds.Count == 0) return;
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
        cmd.Parameters.AddWithValue(vulnerabilityIds.ToArray());
        await cmd.ExecuteNonQueryAsync(ct);
    }
}
