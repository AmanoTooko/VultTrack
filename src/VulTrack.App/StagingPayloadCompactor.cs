using Npgsql;

namespace VulTrack.App;

public sealed class StagingPayloadCompactor(
    NpgsqlDataSource db,
    IConfiguration configuration,
    ILogger<StagingPayloadCompactor> logger)
{
    private static readonly string[] Tables =
    [
        "stg_osv_vulnerabilities",
        "stg_ubuntu_osv",
        "stg_nvd_cves",
        "stg_nvd_cpe_dictionary",
        "stg_cve_list_records",
        "stg_android_osv",
        "stg_ecosystem_advisories",
        "stg_debian_security_tracker",
        "stg_ghsa_advisories",
        "stg_npm_advisories",
        "stg_pypi_advisories",
        "stg_external_advisories",
        "stg_exploit_pocs",
        "stg_alpine_secdb",
        "stg_threat_intel_records",
        "stg_registry_packages"
    ];

    public async Task<int> CompactAsync(Guid[] rawIndexIds, CancellationToken ct)
    {
        if (rawIndexIds.Length == 0) return 0;

        await using var connection = await db.OpenConnectionAsync(ct);
        var prune = ReadBoolean("VULTRACK_PRUNE_STAGING_AFTER_DUCKDB", "VulTrack:DuckDb:PruneStagingAfterProjection");
        var compacted = 0;
        foreach (var table in Tables)
        {
            var sql = prune
                ? $"""
                    delete from {table} t
                    using source_raw_index r
                    where t.raw_index_id = r.id
                      and r.id = any($1)
                      and r.normalize_status in ('succeeded', 'superseded')
                    """
                : $"""
                    update {table} t
                       set payload = jsonb_build_object()
                      from source_raw_index r
                      join source_objects o on o.id = r.object_id
                     where t.raw_index_id = r.id
                       and r.id = any($1)
                       and r.normalize_status in ('succeeded', 'superseded')
                       and o.compressed_content is not null
                       and t.payload <> jsonb_build_object()
                    """;
            await using var command = new NpgsqlCommand(sql, connection);
            command.CommandTimeout = 300;
            command.Parameters.AddWithValue(rawIndexIds);
            compacted += await command.ExecuteNonQueryAsync(ct);
        }

        if (compacted > 0)
        {
            logger.LogInformation("{Action} {Count} staging rows after DuckDB projection.",
                prune ? "Pruned" : "Compacted", compacted);
        }
        return compacted;
    }

    private bool ReadBoolean(string environmentName, string configurationName)
    {
        var value = Environment.GetEnvironmentVariable(environmentName) ?? configuration[configurationName];
        return string.Equals(value, "true", StringComparison.OrdinalIgnoreCase);
    }
}
