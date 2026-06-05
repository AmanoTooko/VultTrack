using Npgsql;
using NpgsqlTypes;

namespace VulTrack.App;

public sealed class DefaultAffectedComponentHook(DuckDbEvidenceStore duckDb) : IBatchAffectedComponentHook
{
    public Task OnAffectedFactsAsync(NpgsqlConnection connection, Guid vulnerabilityId, Guid vulnerabilityRecordId, IReadOnlyList<AffectedFactDraft> facts, CancellationToken ct) =>
        OnAffectedFactsBatchAsync(connection, [new AffectedFactBatchItem(vulnerabilityId, vulnerabilityRecordId, Guid.Empty, Guid.Empty, facts)], ct);

    public async Task OnAffectedFactsBatchAsync(NpgsqlConnection connection, IReadOnlyList<AffectedFactBatchItem> items, CancellationToken ct)
    {
        var projections = items
            .SelectMany(item => item.Facts.Select(fact => new
            {
                item.VulnerabilityId,
                Fact = fact,
                DisplayName = fact.PackageName ?? fact.Purl ?? fact.Cpe23Uri
            }))
            .Where(x => !string.IsNullOrWhiteSpace(x.DisplayName))
            .GroupBy(x => new
            {
                x.VulnerabilityId,
                x.Fact.Ecosystem,
                x.DisplayName,
                x.Fact.Purl,
                x.Fact.Cpe23Uri,
                x.Fact.VersionRange,
                x.Fact.RangeType
            })
            .Select(group => group.First())
            .ToList();

        if (projections.Count == 0) return;

        var tempName = $"tmp_affected_projection_{Guid.NewGuid():N}";
        await using (var createTemp = new NpgsqlCommand($"""
            create temporary table {tempName} (
              vulnerability_id uuid not null,
              ecosystem text,
              package_name text,
              display_name text not null,
              primary_purl text,
              primary_cpe23_uri text,
              normalized_range text,
              range_type text
            )
            """, connection))
        {
            await createTemp.ExecuteNonQueryAsync(ct);
        }

        await using (var writer = await connection.BeginBinaryImportAsync($"""
            copy {tempName}
              (vulnerability_id, ecosystem, package_name, display_name, primary_purl,
               primary_cpe23_uri, normalized_range, range_type)
            from stdin (format binary)
            """, ct))
        {
            foreach (var projection in projections)
            {
                await writer.StartRowAsync(ct);
                await writer.WriteAsync(projection.VulnerabilityId, NpgsqlDbType.Uuid, ct);
                await WriteNullableTextAsync(writer, projection.Fact.Ecosystem, ct);
                await WriteNullableTextAsync(writer, projection.Fact.PackageName, ct);
                await writer.WriteAsync(projection.DisplayName!, NpgsqlDbType.Text, ct);
                await WriteNullableTextAsync(writer, projection.Fact.Purl, ct);
                await WriteNullableTextAsync(writer, projection.Fact.Cpe23Uri, ct);
                await WriteNullableTextAsync(writer, projection.Fact.VersionRange, ct);
                await WriteNullableTextAsync(writer, projection.Fact.RangeType, ct);
            }
            await writer.CompleteAsync(ct);
        }

        await using (var cmd = new NpgsqlCommand($"""
                insert into vulnerability_affected_components
                  (vulnerability_id, ecosystem, package_name, display_name, primary_purl,
                   primary_cpe23_uri, normalized_range, range_type, evidence_count, evidence_summary, selected_by_rule)
                select vulnerability_id, ecosystem, package_name, display_name, primary_purl,
                       primary_cpe23_uri, normalized_range, range_type,
                       1, 'source facts', 'default-source-fact-hook'
                from {tempName}
                on conflict (
                  vulnerability_id,
                  (coalesce(ecosystem, '')),
                  (coalesce(display_name, '')),
                  (coalesce(primary_purl, '')),
                  (coalesce(primary_cpe23_uri, '')),
                  (coalesce(normalized_range, '')),
                  (coalesce(range_type, ''))
                ) do nothing
                """, connection))
        {
            cmd.CommandTimeout = 300;
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

            await SyncDuckDbAffectedComponentsAsync(connection, batch, ct);
        }
    }

    private async Task SyncDuckDbAffectedComponentsAsync(NpgsqlConnection connection, IReadOnlyCollection<Guid> vulnerabilityIds, CancellationToken ct)
    {
        if (!duckDb.Enabled || vulnerabilityIds.Count == 0) return;

        var rows = new List<DuckDbAffectedComponentProjection>();
        await using (var cmd = new NpgsqlCommand("""
            select id, vulnerability_id, component_id, ecosystem, package_name, display_name,
                   primary_purl, primary_cpe23_uri, normalized_range, range_type,
                   confidence, evidence_count, resolution_status
            from vulnerability_affected_components
            where vulnerability_id = any($1)
            order by vulnerability_id, ecosystem nulls last, display_name, id
            """, connection))
        {
            cmd.CommandTimeout = 300;
            cmd.Parameters.AddWithValue(vulnerabilityIds.ToArray());
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                rows.Add(new DuckDbAffectedComponentProjection(
                    reader.GetGuid(0),
                    reader.GetGuid(1),
                    reader.IsDBNull(2) ? null : reader.GetGuid(2),
                    reader.IsDBNull(3) ? null : reader.GetString(3),
                    reader.IsDBNull(4) ? null : reader.GetString(4),
                    reader.GetString(5),
                    reader.IsDBNull(6) ? null : reader.GetString(6),
                    reader.IsDBNull(7) ? null : reader.GetString(7),
                    reader.IsDBNull(8) ? null : reader.GetString(8),
                    reader.IsDBNull(9) ? null : reader.GetString(9),
                    reader.GetDecimal(10),
                    reader.GetInt32(11),
                    reader.GetString(12)));
            }
        }

        await duckDb.ReplaceAffectedComponentsAsync(vulnerabilityIds, rows, ct);
    }

    private static Task WriteNullableTextAsync(NpgsqlBinaryImporter writer, string? value, CancellationToken ct) =>
        string.IsNullOrWhiteSpace(value)
            ? writer.WriteNullAsync(ct)
            : writer.WriteAsync(value, NpgsqlDbType.Text, ct);
}
