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
                insert into vulnerability_affected_components
                  (vulnerability_id, ecosystem, package_name, display_name, primary_purl,
                   normalized_range, range_type, evidence_count, evidence_summary, selected_by_rule)
                values ($1,$2,$3,$4,$5,$6,$7,1,'source fact','default-source-fact-hook')
                on conflict do nothing
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
}

