using Npgsql;

namespace VulTrack.App;

public sealed class StagingPayloadCompactor(
    NpgsqlDataSource db,
    ILogger<StagingPayloadCompactor> logger)
{
    private static readonly string[] Tables =
    [
        "stg_osv_vulnerabilities",
        "stg_ubuntu_osv",
        "stg_nvd_cves",
        "stg_cve_list_records",
        "stg_android_osv",
        "stg_ecosystem_advisories",
        "stg_debian_security_tracker",
        "stg_ghsa_advisories",
        "stg_npm_advisories",
        "stg_pypi_advisories",
        "stg_external_advisories",
        "stg_exploit_pocs",
        "stg_alpine_secdb"
    ];

    public async Task<int> CompactAsync(Guid[] rawIndexIds, CancellationToken ct)
    {
        if (rawIndexIds.Length == 0) return 0;

        await using var connection = await db.OpenConnectionAsync(ct);
        var compacted = 0;
        foreach (var table in Tables)
        {
            await using var command = new NpgsqlCommand($"""
                update {table} t
                   set payload = jsonb_build_object()
                  from source_raw_index r
                  join source_objects o on o.id = r.object_id
                 where t.raw_index_id = r.id
                   and r.id = any($1)
                   and r.normalize_status in ('succeeded', 'superseded')
                   and o.compressed_content is not null
                   and t.payload <> jsonb_build_object()
                """, connection);
            command.CommandTimeout = 300;
            command.Parameters.AddWithValue(rawIndexIds);
            compacted += await command.ExecuteNonQueryAsync(ct);
        }

        if (compacted > 0)
        {
            logger.LogInformation("Compacted {Count} staging payloads after DuckDB projection.", compacted);
        }
        return compacted;
    }
}
