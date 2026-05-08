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
                    select id
                    from vulnerability_affected_components
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
                    select $1,$2,$3,$4,$5,$6,$7,0,'source facts','default-source-fact-hook'
                    where not exists (select 1 from existing)
                    returning id
                )
                update vulnerability_affected_components
                set evidence_count = evidence_count + 1,
                    updated_at = now()
                where id in (select id from existing union select id from inserted)
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

        await using var projection = new NpgsqlCommand("""
            update vulnerabilities
            set affected_component_count = coalesce((
                    select count(*)::int from vulnerability_affected_components c where c.vulnerability_id = $1
                ), 0),
                affected_ecosystems = coalesce((
                    select array_agg(distinct c.ecosystem) filter (where c.ecosystem is not null)
                    from vulnerability_affected_components c where c.vulnerability_id = $1
                ), '{}'),
                affected_component_names = coalesce((
                    select array_agg(distinct c.display_name)
                    from vulnerability_affected_components c where c.vulnerability_id = $1
                ), '{}'),
                updated_at = now()
            where id = $1
            """, connection);
        projection.Parameters.AddWithValue(vulnerabilityId);
        await projection.ExecuteNonQueryAsync(ct);
    }
}
