using DuckDB.NET.Data;

namespace VulTrack.App;

public sealed partial class DuckDbEvidenceStore
{
    public async Task SaveSbomAsync(
        Guid id,
        string name,
        string metadataJson,
        IReadOnlyList<DuckDbSbomComponent> components,
        CancellationToken ct)
    {
        await InitializeAsync(ct);
        await _writeLock.WaitAsync(ct);
        try
        {
            using var connection = OpenConnection();
            Execute(connection, "begin transaction");
            try
            {
                var idValue = SqlValue(id.ToString("D"));
                Execute(connection, $"delete from sbom_matches where sbom_id = {idValue}");
                Execute(connection, $"delete from sbom_components where sbom_id = {idValue}");
                Execute(connection, $"delete from sbom_uploads where id = {idValue}");
                await CopyRowsAsync(connection, "sbom_uploads", "id, name, format, metadata, component_count, matched_count",
                    [CsvRow(id.ToString("D"), name, "cyclonedx", metadataJson, components.Count.ToString(), "0")], ct);
                await CopyRowsAsync(connection, "sbom_components", """
                    id, sbom_id, purl, name, version, ecosystem, group_name, vendor, product,
                    cpe23_uri, source_package_name, source_package_version, component_type, metadata, vuln_count
                    """, components.Select(component => CsvRow(
                        component.Id.ToString("D"), id.ToString("D"), component.Purl, component.Name,
                        component.Version, component.Ecosystem, component.GroupName, component.Vendor,
                        component.Product, component.Cpe23Uri, component.SourcePackageName,
                        component.SourcePackageVersion, component.ComponentType, component.MetadataJson, "0")), ct);
                Execute(connection, "commit");
            }
            catch
            {
                Execute(connection, "rollback");
                throw;
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<IReadOnlyList<DuckDbSbomUpload>> ListSbomsAsync(CancellationToken ct)
    {
        await InitializeAsync(ct);
        using var candidateLease = await RentReadConnectionAsync(ct);
        var candidateConnection = candidateLease.Connection;
        using var command = candidateConnection.CreateCommand();
        command.CommandText = "select id, name, format, component_count, matched_count, uploaded_at from sbom_uploads order by uploaded_at desc limit 50";
        var rows = new List<DuckDbSbomUpload>();
        using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            rows.Add(new DuckDbSbomUpload(Guid.Parse(reader.GetString(0)), reader.GetString(1), reader.GetString(2), reader.GetInt32(3), reader.GetInt32(4), reader.GetDateTime(5)));
        return rows;
    }

    public async Task<DuckDbSbomUpload?> GetSbomAsync(Guid id, CancellationToken ct)
    {
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        using var command = connection.CreateCommand();
        command.CommandText = "select id, name, format, component_count, matched_count, uploaded_at from sbom_uploads where id = $1 limit 1";
        command.Parameters.Add(new DuckDBParameter(id.ToString("D")));
        using var reader = await command.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct)
            ? new DuckDbSbomUpload(Guid.Parse(reader.GetString(0)), reader.GetString(1), reader.GetString(2), reader.GetInt32(3), reader.GetInt32(4), reader.GetDateTime(5))
            : null;
    }

    public async Task<IReadOnlyList<DuckDbSbomComponent>> GetSbomComponentsAsync(Guid sbomId, CancellationToken ct)
    {
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        using var command = connection.CreateCommand();
        command.CommandText = """
            select id, sbom_id, purl, name, version, ecosystem, group_name, vendor, product,
                   cpe23_uri, source_package_name, source_package_version, component_type, metadata, vuln_count
            from sbom_components where sbom_id = $1 order by ecosystem, name
            """;
        command.Parameters.Add(new DuckDBParameter(sbomId.ToString("D")));
        var rows = new List<DuckDbSbomComponent>();
        using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            rows.Add(new DuckDbSbomComponent(
                Guid.Parse(reader.GetString(0)), Guid.Parse(reader.GetString(1)),
                NullableString(reader, 2), NullableString(reader, 3), NullableString(reader, 4), NullableString(reader, 5),
                NullableString(reader, 6), NullableString(reader, 7), NullableString(reader, 8), NullableString(reader, 9),
                NullableString(reader, 10), NullableString(reader, 11), NullableString(reader, 12),
                NullableString(reader, 13) ?? "{}", reader.GetInt32(14)));
        return rows;
    }

    public async Task<int> ReplaceSbomMatchesAsync(Guid sbomId, IReadOnlyList<DuckDbSbomMatch> matches, CancellationToken ct)
    {
        await InitializeAsync(ct);
        await _writeLock.WaitAsync(ct);
        try
        {
            using var connection = OpenConnection();
            Execute(connection, "begin transaction");
            try
            {
                var sbom = SqlValue(sbomId.ToString("D"));
                Execute(connection, $"delete from sbom_matches where sbom_id = {sbom}");
                await CopyRowsAsync(connection, "sbom_matches", """
                    id, sbom_id, sbom_component_id, vulnerability_id, purl, display_name, ecosystem,
                    normalized_range, version_matched, match_basis, matched_version
                    """, matches
                        .GroupBy(match => (match.ComponentId, match.VulnerabilityId))
                        .Select(group => group.First())
                        .Select(match => CsvRow(
                            DeterministicRowId(match.ComponentId, match.VulnerabilityId), sbomId.ToString("D"),
                            match.ComponentId.ToString("D"), match.VulnerabilityId.ToString("D"), match.Purl,
                            match.DisplayName, match.Ecosystem, match.Range,
                            match.VersionMatched is null ? null : match.VersionMatched.Value ? "true" : "false",
                            match.Basis, match.MatchedVersion)), ct);
                Execute(connection, $"""
                    update sbom_components c set vuln_count = coalesce(m.cnt, 0)
                    from (select sbom_component_id, count(*)::integer cnt from sbom_matches where sbom_id = {sbom} group by sbom_component_id) m
                    where c.sbom_id = {sbom} and c.id = m.sbom_component_id
                    """);
                Execute(connection, $"""
                    update sbom_components set vuln_count = 0
                    where sbom_id = {sbom} and id not in (select sbom_component_id from sbom_matches where sbom_id = {sbom})
                    """);
                Execute(connection, $"""
                    update sbom_uploads set matched_count =
                      (select count(distinct vulnerability_id)::integer from sbom_matches where sbom_id = {sbom})
                    where id = {sbom}
                    """);
                Execute(connection, "commit");
                return matches.Count;
            }
            catch
            {
                Execute(connection, "rollback");
                throw;
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<IReadOnlyList<DuckDbSbomFinding>> GetSbomFindingsAsync(Guid sbomId, int limit, int offset, CancellationToken ct)
    {
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            select m.id, m.sbom_component_id, m.vulnerability_id, v.primary_identifier, v.title,
                   v.severity_label, v.max_cvss_score, m.display_name, m.ecosystem, m.normalized_range,
                   m.version_matched, m.match_basis, m.matched_version, v.identifiers_json
            from sbom_matches m join vulnerabilities v on v.id = m.vulnerability_id
            where m.sbom_id = $1
            order by v.max_cvss_score desc nulls last
            limit {Math.Clamp(limit, 1, 10000)} offset {Math.Max(offset, 0)}
            """;
        command.Parameters.Add(new DuckDBParameter(sbomId.ToString("D")));
        var rows = new List<DuckDbSbomFinding>();
        using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var primary = reader.GetString(3);
            var identifiers = JsonStringArray(NullableString(reader, 13));
            rows.Add(new DuckDbSbomFinding(
                Guid.ParseExact(reader.GetString(0), "N"), Guid.Parse(reader.GetString(1)), Guid.Parse(reader.GetString(2)),
                primary, NullableString(reader, 4), NullableString(reader, 5), reader.IsDBNull(6) ? null : reader.GetDouble(6),
                NullableString(reader, 7), NullableString(reader, 8), NullableString(reader, 9),
                reader.IsDBNull(10) ? null : reader.GetBoolean(10), NullableString(reader, 11), NullableString(reader, 12),
                identifiers, identifiers.Where(value => !value.Equals(primary, StringComparison.OrdinalIgnoreCase)).ToArray()));
        }
        return rows;
    }

    public async Task DeleteSbomAsync(Guid sbomId, CancellationToken ct)
    {
        await InitializeAsync(ct);
        await _writeLock.WaitAsync(ct);
        try
        {
            using var connection = OpenConnection();
            var id = SqlValue(sbomId.ToString("D"));
            Execute(connection, "begin transaction");
            Execute(connection, $"delete from sbom_matches where sbom_id = {id}");
            Execute(connection, $"delete from sbom_components where sbom_id = {id}");
            Execute(connection, $"delete from sbom_uploads where id = {id}");
            Execute(connection, "commit");
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<IReadOnlyList<DuckDbSbomCandidateMatch>> QuerySbomCandidateMatchesAsync(IReadOnlyList<DuckDbSbomMatchComponent> components, CancellationToken ct = default)
    {
        if (!Enabled || components.Count == 0) return Array.Empty<DuckDbSbomCandidateMatch>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);

        // Creates temp tables and COPYs rows, so it must not race the single writer.
        await _writeLock.WaitAsync(ct);
        try
        {
            return await QuerySbomCandidateMatchesCoreAsync(components, ct);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async Task<IReadOnlyList<DuckDbSbomCandidateMatch>> QuerySbomCandidateMatchesCoreAsync(IReadOnlyList<DuckDbSbomMatchComponent> components, CancellationToken ct)
    {
        using var connection = OpenConnection();
        Execute(connection, """
            create temporary table temp_sbom_match_components (
              component_id varchar,
              purl varchar,
              purl_decoded varchar,
              purl_decoded_lower varchar,
              purl_without_version varchar,
              purl_without_version_lower varchar,
              name varchar,
              name_lower varchar,
              version varchar,
              ecosystem varchar,
              mapped_ecosystem varchar,
              mapped_ecosystem_lower varchar,
              cpe23_uri varchar,
              cpe_prefix varchar,
              cpe_product varchar,
              cpe_product_lower varchar,
              source_package_name varchar,
              source_package_name_lower varchar,
              source_package_version varchar
            )
            """);

        await CopyRowsAsync(connection, "temp_sbom_match_components", """
            component_id, purl, purl_decoded, purl_decoded_lower, purl_without_version,
            purl_without_version_lower, name, name_lower, version, ecosystem,
            mapped_ecosystem, mapped_ecosystem_lower, cpe23_uri, cpe_prefix,
            cpe_product, cpe_product_lower, source_package_name, source_package_name_lower,
            source_package_version
            """, components.Select(component => CsvRow(
                component.ComponentId.ToString("D"),
                component.Purl,
                component.PurlDecoded,
                component.PurlDecoded?.ToLowerInvariant(),
                component.PurlWithoutVersion,
                component.PurlWithoutVersion?.ToLowerInvariant(),
                component.Name,
                component.Name?.ToLowerInvariant(),
                component.Version,
                component.Ecosystem,
                component.MappedEcosystem,
                component.MappedEcosystem?.ToLowerInvariant(),
                component.Cpe23Uri,
                component.CpePrefix,
                component.CpeProduct,
                component.CpeProduct?.ToLowerInvariant(),
                component.SourcePackageName,
                component.SourcePackageName?.ToLowerInvariant(),
                component.SourcePackageVersion)), ct);

        if (components.All(component =>
                !string.IsNullOrWhiteSpace(component.PurlWithoutVersion) &&
                string.IsNullOrWhiteSpace(component.Cpe23Uri) &&
                string.IsNullOrWhiteSpace(component.SourcePackageName)))
        {
            return await ReadSbomCandidateMatchesAsync(connection, """
                with candidates as (
                  select t.component_id, t.purl, t.version as component_version, t.cpe23_uri as component_cpe,
                         t.source_package_version, c.vulnerability_id, c.display_name, c.ecosystem,
                         c.normalized_range, c.primary_cpe23_uri, 2 as match_priority, 'purl' as match_basis
                  from temp_sbom_match_components t
                  join affected_components c on t.purl_without_version is not null
                   and c.purl_without_version = t.purl_without_version
                )
                select component_id, purl, component_version, component_cpe, source_package_version,
                       vulnerability_id, display_name, ecosystem, normalized_range, primary_cpe23_uri, match_basis
                from candidates
                qualify row_number() over (
                  partition by component_id, vulnerability_id, coalesce(normalized_range, ''), match_basis
                  order by match_priority
                ) = 1
                """, ct);
        }

        using var command = connection.CreateCommand();
        command.CommandText = """
            with candidates as (
              select t.component_id, t.purl, t.version as component_version, t.cpe23_uri as component_cpe,
                     t.source_package_version, c.vulnerability_id, c.display_name, c.ecosystem,
                     c.normalized_range, c.primary_cpe23_uri, 1 as match_priority, 'cpe-exact' as match_basis
              from temp_sbom_match_components t
              join affected_components c on t.cpe23_uri is not null and c.primary_cpe23_uri = t.cpe23_uri
              union all
              select t.component_id, t.purl, t.version as component_version, t.cpe23_uri as component_cpe,
                     t.source_package_version, c.vulnerability_id, c.display_name, c.ecosystem,
                     c.normalized_range, c.primary_cpe23_uri, 2 as match_priority, 'purl' as match_basis
              from temp_sbom_match_components t
              join affected_components c on t.purl_without_version_lower is not null
               and c.purl_without_version = t.purl_without_version
              union all
              select t.component_id, t.purl, t.version as component_version, t.cpe23_uri as component_cpe,
                     t.source_package_version, c.vulnerability_id, c.display_name, c.ecosystem,
                     c.normalized_range, c.primary_cpe23_uri, 3 as match_priority, 'source-package' as match_basis
              from temp_sbom_match_components t
              join affected_components c on t.source_package_name_lower is not null
               and c.package_name_lower = t.source_package_name_lower
               and (
                 t.mapped_ecosystem_lower is null
                 or c.ecosystem_lower = t.mapped_ecosystem_lower
                 or (instr(t.mapped_ecosystem_lower, ':') = 0 and c.ecosystem_lower like t.mapped_ecosystem_lower || ':%')
               )
              union all
              select t.component_id, t.purl, t.version as component_version, t.cpe23_uri as component_cpe,
                     t.source_package_version, c.vulnerability_id, c.display_name, c.ecosystem,
                     c.normalized_range, c.primary_cpe23_uri, 4 as match_priority, 'name' as match_basis
              from temp_sbom_match_components t
              join affected_components c on t.purl_without_version_lower is null
               and t.cpe23_uri is null
               and t.source_package_name_lower is null
               and t.name_lower is not null
               and c.display_name_lower = t.name_lower
               and (
                 t.mapped_ecosystem_lower is null
                 or c.ecosystem_lower = t.mapped_ecosystem_lower
                 or (instr(t.mapped_ecosystem_lower, ':') = 0 and c.ecosystem_lower like t.mapped_ecosystem_lower || ':%')
               )
              union all
              select t.component_id, t.purl, t.version as component_version, t.cpe23_uri as component_cpe,
                     t.source_package_version, c.vulnerability_id, c.display_name, c.ecosystem,
                     c.normalized_range, c.primary_cpe23_uri, 5 as match_priority, 'package' as match_basis
              from temp_sbom_match_components t
              join affected_components c on t.purl_without_version_lower is null
               and t.cpe23_uri is null
               and t.source_package_name_lower is null
               and t.name_lower is not null
               and c.package_name_lower = t.name_lower
               and (
                 t.mapped_ecosystem_lower is null
                 or c.ecosystem_lower = t.mapped_ecosystem_lower
                 or (instr(t.mapped_ecosystem_lower, ':') = 0 and c.ecosystem_lower like t.mapped_ecosystem_lower || ':%')
               )
              union all
              select t.component_id, t.purl, t.version as component_version, t.cpe23_uri as component_cpe,
                     t.source_package_version, c.vulnerability_id, c.display_name, c.ecosystem,
                     c.normalized_range, c.primary_cpe23_uri, 6 as match_priority, 'cpe-product' as match_basis
              from temp_sbom_match_components t
              join affected_components c on t.cpe_product_lower is not null
               and c.package_name_lower = t.cpe_product_lower
               and c.ecosystem_lower = 'cpe'
            )
            select component_id, purl, component_version, component_cpe, source_package_version,
                   vulnerability_id, display_name, ecosystem, normalized_range, primary_cpe23_uri, match_basis
            from candidates
            qualify row_number() over (
              partition by component_id, vulnerability_id, coalesce(normalized_range, ''), match_basis
              order by match_priority
            ) = 1
            """;

        var matches = new List<DuckDbSbomCandidateMatch>();
        using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            if (!Guid.TryParse(reader.GetString(0), out var componentId) ||
                !Guid.TryParse(reader.GetString(5), out var vulnerabilityId))
            {
                continue;
            }

            matches.Add(new DuckDbSbomCandidateMatch(
                componentId,
                reader.IsDBNull(1) ? null : reader.GetString(1),
                reader.IsDBNull(2) ? null : reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetString(3),
                reader.IsDBNull(4) ? null : reader.GetString(4),
                vulnerabilityId,
                reader.IsDBNull(6) ? null : reader.GetString(6),
                reader.IsDBNull(7) ? null : reader.GetString(7),
                reader.IsDBNull(8) ? null : reader.GetString(8),
                reader.IsDBNull(9) ? null : reader.GetString(9),
                reader.IsDBNull(10) ? null : reader.GetString(10)));
        }

        return matches;
    }

    private static async Task<IReadOnlyList<DuckDbSbomCandidateMatch>> ReadSbomCandidateMatchesAsync(DuckDBConnection connection, string sql, CancellationToken ct)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        var matches = new List<DuckDbSbomCandidateMatch>();
        using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            if (!Guid.TryParse(reader.GetString(0), out var componentId) ||
                !Guid.TryParse(reader.GetString(5), out var vulnerabilityId))
            {
                continue;
            }

            matches.Add(new DuckDbSbomCandidateMatch(
                componentId,
                reader.IsDBNull(1) ? null : reader.GetString(1),
                reader.IsDBNull(2) ? null : reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetString(3),
                reader.IsDBNull(4) ? null : reader.GetString(4),
                vulnerabilityId,
                reader.IsDBNull(6) ? null : reader.GetString(6),
                reader.IsDBNull(7) ? null : reader.GetString(7),
                reader.IsDBNull(8) ? null : reader.GetString(8),
                reader.IsDBNull(9) ? null : reader.GetString(9),
                reader.IsDBNull(10) ? null : reader.GetString(10)));
        }

        return matches;
    }
}
