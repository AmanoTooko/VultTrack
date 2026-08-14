using DuckDB.NET.Data;

namespace VulTrack.App;

public sealed partial class DuckDbEvidenceStore
{
    public async Task ResetAffectedComponentsAsync(CancellationToken ct)
    {
        if (!Enabled) return;
        await InitializeAsync(ct);
        await _writeLock.WaitAsync(ct);
        try
        {
            using var connection = OpenConnection();
            RecreateAffectedComponentsTable(connection);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task PrepareAffectedComponentsBulkLoadAsync(CancellationToken ct)
    {
        if (!Enabled) return;
        await InitializeAsync(ct);
        await _writeLock.WaitAsync(ct);
        try
        {
            using var connection = OpenConnection();
            RecreateAffectedComponentsTable(connection);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task FinalizeAffectedComponentsBulkLoadAsync(CancellationToken ct)
    {
        if (!Enabled) return;
        await _writeLock.WaitAsync(ct);
        try
        {
            using var connection = OpenConnection();
            foreach (var statement in AffectedComponentIndexStatements)
                Execute(connection, statement);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task AppendAffectedComponentsAsync(IReadOnlyList<DuckDbAffectedComponentProjection> rows, CancellationToken ct)
    {
        if (!Enabled || rows.Count == 0) return;
        await InitializeAsync(ct);
        await AppendAffectedComponentsWithoutInitializeAsync(rows, ct);
    }

    public async Task AppendAffectedComponentsBulkAsync(IReadOnlyList<DuckDbAffectedComponentProjection> rows, CancellationToken ct)
    {
        if (!Enabled || rows.Count == 0) return;
        await AppendAffectedComponentsWithoutInitializeAsync(rows, ct);
    }

    private async Task AppendAffectedComponentsWithoutInitializeAsync(IReadOnlyList<DuckDbAffectedComponentProjection> rows, CancellationToken ct)
    {
        await _writeLock.WaitAsync(ct);
        try
        {
            using var connection = OpenConnection();
            await CopyAffectedComponentsAsync(connection, rows, ct);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task ReplaceAffectedComponentsAsync(IReadOnlyCollection<Guid> vulnerabilityIds, IReadOnlyList<DuckDbAffectedComponentProjection> rows, CancellationToken ct)
    {
        if (!Enabled || vulnerabilityIds.Count == 0) return;
        await InitializeAsync(ct);
        await _writeLock.WaitAsync(ct);
        try
        {
            using var connection = OpenConnection();
            Execute(connection, "begin transaction");
            try
            {
                var ids = TextList(vulnerabilityIds.Select(id => id.ToString("D")));
                Execute(connection, $"delete from affected_components where vulnerability_id in ({ids})");
                if (rows.Count > 0)
                    await CopyAffectedComponentsAsync(connection, rows, ct);
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

    public async Task<long> CountAffectedComponentsAsync(CancellationToken ct = default)
    {
        if (!Enabled) return 0;
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        return Count(connection, "affected_components");
    }

    public async Task<IReadOnlyList<string>> QueryAffectedVulnerabilityKeysByRawIndexIdsAsync(IReadOnlyCollection<Guid> rawIndexIds, CancellationToken ct = default)
    {
        if (!Enabled || rawIndexIds.Count == 0) return Array.Empty<string>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            select distinct vulnerability_key
            from affected_facts
            where raw_index_id in ({TextList(rawIndexIds.Select(id => id.ToString("D")))})
              and vulnerability_key is not null
              and vulnerability_key <> ''
            """;
        var keys = new List<string>();
        using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            keys.Add(reader.GetString(0));
        return keys;
    }

    public async Task<IReadOnlyList<string>> QueryAllAffectedVulnerabilityKeysAsync(CancellationToken ct = default)
    {
        if (!Enabled) return Array.Empty<string>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        using var command = connection.CreateCommand();
        command.CommandText = """
            select distinct vulnerability_key
            from affected_facts
            where vulnerability_key is not null and vulnerability_key <> ''
            """;
        var keys = new List<string>();
        using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            keys.Add(reader.GetString(0));
        return keys;
    }

    public async Task<long> RebuildAffectedComponentsFromEvidenceAsync(
        IReadOnlyCollection<DuckDbVulnerabilityKeyMapping> vulnerabilityKeys,
        CancellationToken ct = default)
    {
        if (!Enabled || vulnerabilityKeys.Count == 0) return 0;
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        await _writeLock.WaitAsync(ct);
        try
        {
            using var connection = OpenConnection();
            Execute(connection, "begin transaction");
            try
            {
                Execute(connection, "create temporary table temp_duckdb_affected_key_map (vulnerability_id varchar, vulnerability_key varchar)");
                await CopyRowsAsync(
                    connection,
                    "temp_duckdb_affected_key_map",
                    "vulnerability_id, vulnerability_key",
                    vulnerabilityKeys.Select(pair => CsvRow(pair.VulnerabilityId.ToString("D"), NormalizeKey(pair.VulnerabilityKey))),
                    ct);
                Execute(connection, "drop table if exists affected_components_next");
                Execute(connection, """
                    create table affected_components_next as
                    with projected as (
                      select map.vulnerability_id, f.ecosystem, f.package_name,
                             coalesce(nullif(f.package_name, ''), nullif(f.purl, ''), nullif(f.cpe23_uri, '')) as display_name,
                             f.purl as primary_purl,
                             f.cpe23_uri as primary_cpe23_uri,
                             f.version_range_raw as normalized_range,
                             f.range_type
                      from affected_facts f
                      join temp_duckdb_affected_key_map map
                        on upper(f.vulnerability_key) = upper(map.vulnerability_key)
                      where f.vulnerable
                        and coalesce(nullif(f.package_name, ''), nullif(f.purl, ''), nullif(f.cpe23_uri, '')) is not null
                    )
                    select md5(concat_ws('|', vulnerability_id, coalesce(ecosystem,''), coalesce(package_name,''), display_name,
                                         coalesce(primary_purl,''), coalesce(primary_cpe23_uri,''), coalesce(normalized_range,''), coalesce(range_type,''))) as id,
                           vulnerability_id,
                           cast(null as varchar) as component_id,
                           ecosystem,
                           lower(coalesce(ecosystem, '')) as ecosystem_lower,
                           package_name,
                           lower(coalesce(package_name, '')) as package_name_lower,
                           display_name,
                           lower(display_name) as display_name_lower,
                           primary_purl,
                           case when primary_purl is null then null
                                else regexp_replace(split_part(split_part(primary_purl, '?', 1), '#', 1), '@[^/@]*$', '')
                           end as purl_without_version,
                           primary_cpe23_uri,
                           normalized_range,
                           range_type,
                           cast(1.0 as double) as confidence,
                           cast(count(*) as integer) as evidence_count,
                           'candidate' as resolution_status
                    from projected
                    group by vulnerability_id, ecosystem, package_name, display_name,
                             primary_purl, primary_cpe23_uri, normalized_range, range_type
                    """);
                Execute(connection, "drop table affected_components");
                Execute(connection, "alter table affected_components_next rename to affected_components");
                Execute(connection, "commit");
                return Count(connection, "affected_components");
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

    public async Task<IReadOnlyList<DuckDbAffectedComponentProjection>> ReplaceAffectedComponentsFromEvidenceAsync(
        IReadOnlyCollection<DuckDbVulnerabilityKeyMapping> vulnerabilityKeys,
        CancellationToken ct = default)
    {
        if (!Enabled || vulnerabilityKeys.Count == 0) return Array.Empty<DuckDbAffectedComponentProjection>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);

        await _writeLock.WaitAsync(ct);
        try
        {
            using var connection = OpenConnection();
            Execute(connection, "begin transaction");
            try
            {
                Execute(connection, "create temporary table temp_duckdb_affected_key_map (vulnerability_id varchar, vulnerability_key varchar)");
                await CopyRowsAsync(
                    connection,
                    "temp_duckdb_affected_key_map",
                    "vulnerability_id, vulnerability_key",
                    vulnerabilityKeys.Select(pair => CsvRow(pair.VulnerabilityId.ToString("D"), NormalizeKey(pair.VulnerabilityKey))),
                    ct);

                var rows = new List<DuckDbAffectedComponentProjection>();
                using (var command = connection.CreateCommand())
                {
                    command.CommandText = """
                        with projected as (
                          select map.vulnerability_id, f.ecosystem, f.package_name,
                                 coalesce(nullif(f.package_name, ''), nullif(f.purl, ''), nullif(f.cpe23_uri, '')) as display_name,
                                 f.purl as primary_purl,
                                 f.cpe23_uri as primary_cpe23_uri,
                                 f.version_range_raw as normalized_range,
                                 f.range_type
                          from affected_facts f
                          join temp_duckdb_affected_key_map map
                            on upper(f.vulnerability_key) = upper(map.vulnerability_key)
                          where f.vulnerable
                            and coalesce(nullif(f.package_name, ''), nullif(f.purl, ''), nullif(f.cpe23_uri, '')) is not null
                        )
                        select vulnerability_id, ecosystem, package_name, display_name,
                               primary_purl, primary_cpe23_uri, normalized_range, range_type,
                               count(*) as evidence_count
                        from projected
                        group by vulnerability_id, ecosystem, package_name, display_name,
                                 primary_purl, primary_cpe23_uri, normalized_range, range_type
                        order by vulnerability_id, ecosystem, display_name
                        """;
                    using var reader = await command.ExecuteReaderAsync(ct);
                    while (await reader.ReadAsync(ct))
                    {
                        if (!Guid.TryParse(reader.GetString(0), out var vulnerabilityId)) continue;
                        rows.Add(new DuckDbAffectedComponentProjection(
                            Guid.NewGuid(),
                            vulnerabilityId,
                            null,
                            reader.IsDBNull(1) ? null : reader.GetString(1),
                            reader.IsDBNull(2) ? null : reader.GetString(2),
                            reader.GetString(3),
                            reader.IsDBNull(4) ? null : reader.GetString(4),
                            reader.IsDBNull(5) ? null : reader.GetString(5),
                            reader.IsDBNull(6) ? null : reader.GetString(6),
                            reader.IsDBNull(7) ? null : reader.GetString(7),
                            1m,
                            Convert.ToInt32(reader.GetInt64(8)),
                            "candidate"));
                    }
                }

                var ids = TextList(vulnerabilityKeys.Select(pair => pair.VulnerabilityId.ToString("D")));
                Execute(connection, $"delete from affected_components where vulnerability_id in ({ids})");
                if (rows.Count > 0)
                    await CopyAffectedComponentsAsync(connection, rows, ct);
                Execute(connection, "commit");
                return rows;
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

    public async Task<IReadOnlyList<DuckDbAffectedComponentSummary>> QueryAffectedComponentSummariesAsync(IReadOnlyCollection<Guid> vulnerabilityIds, CancellationToken ct = default)
    {
        if (!Enabled || vulnerabilityIds.Count == 0) return Array.Empty<DuckDbAffectedComponentSummary>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            select vulnerability_id,
                   count(*) as component_count,
                   string_agg(distinct coalesce(ecosystem, ''), '|') as ecosystems,
                   string_agg(distinct display_name, '|') as names
            from affected_components
            where vulnerability_id in ({TextList(vulnerabilityIds.Select(id => id.ToString("D")))})
            group by vulnerability_id
            """;
        var rows = new List<DuckDbAffectedComponentSummary>();
        using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            if (!Guid.TryParse(reader.GetString(0), out var vulnerabilityId)) continue;
            rows.Add(new DuckDbAffectedComponentSummary(
                vulnerabilityId,
                Convert.ToInt32(reader.GetInt64(1)),
                SplitSummary(reader.IsDBNull(2) ? null : reader.GetString(2)),
                SplitSummary(reader.IsDBNull(3) ? null : reader.GetString(3))));
        }
        return rows;
    }

    public async Task StreamAffectedComponentSummaryBatchesAsync(
        int batchSize,
        Func<IReadOnlyList<DuckDbAffectedComponentSummary>, Task> consume,
        CancellationToken ct = default)
    {
        if (!Enabled) return;
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        using var command = connection.CreateCommand();
        command.CommandText = """
            select vulnerability_id,
                   count(*) as component_count,
                   string_agg(distinct coalesce(ecosystem, ''), '|') as ecosystems,
                   string_agg(distinct display_name, '|') as names
            from affected_components
            group by vulnerability_id
            order by vulnerability_id
            """;
        using var reader = await command.ExecuteReaderAsync(ct);
        var batch = new List<DuckDbAffectedComponentSummary>(Math.Max(1, batchSize));
        while (await reader.ReadAsync(ct))
        {
            if (!Guid.TryParse(reader.GetString(0), out var vulnerabilityId)) continue;
            batch.Add(new DuckDbAffectedComponentSummary(
                vulnerabilityId,
                Convert.ToInt32(reader.GetInt64(1)),
                SplitSummary(reader.IsDBNull(2) ? null : reader.GetString(2)),
                SplitSummary(reader.IsDBNull(3) ? null : reader.GetString(3))));
            if (batch.Count < batchSize) continue;
            await consume(batch);
            batch = new List<DuckDbAffectedComponentSummary>(Math.Max(1, batchSize));
        }

        if (batch.Count > 0)
            await consume(batch);
    }

    public async Task<IReadOnlyList<Guid>> QueryAffectedVulnerabilityIdsByEcosystemAsync(string ecosystem, int limit, int offset, CancellationToken ct = default)
    {
        if (!Enabled || string.IsNullOrWhiteSpace(ecosystem)) return Array.Empty<Guid>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            select distinct vulnerability_id
            from affected_components
            where (
                ecosystem_lower = lower($1)
                or (instr(lower($1), ':') = 0 and ecosystem_lower like lower($1) || ':%')
              )
              and (display_name is not null or package_name is not null)
            limit {Math.Clamp(limit, 1, 5000)}
            offset {Math.Clamp(offset, 0, 1_000_000)}
            """;
        command.Parameters.Add(new DuckDBParameter(ecosystem));

        var ids = new List<Guid>();
        using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            if (Guid.TryParse(reader.GetString(0), out var id)) ids.Add(id);
        }
        return ids;
    }

    public async Task<IReadOnlyList<DuckDbAffectedEcosystemPackageSummary>> QueryAffectedEcosystemPackageSummaryAsync(string ecosystem, string? packageName, int limit = 50, CancellationToken ct = default)
    {
        if (!Enabled || string.IsNullOrWhiteSpace(ecosystem)) return Array.Empty<DuckDbAffectedEcosystemPackageSummary>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        using var command = connection.CreateCommand();
        var packageFilter = string.IsNullOrWhiteSpace(packageName)
            ? ""
            : "and package_name_lower = lower($2)";
        var limitClause = string.IsNullOrWhiteSpace(packageName) ? $"limit {Math.Clamp(limit, 1, 500)}" : "";
        command.CommandText = $"""
            select ecosystem, package_name,
                   count(distinct vulnerability_id) as total_cves,
                   count(*) as fact_count
            from affected_components
            where (
                ecosystem_lower = lower($1)
                or (instr(lower($1), ':') = 0 and ecosystem_lower like lower($1) || ':%')
              )
              and package_name is not null
              {packageFilter}
            group by ecosystem, package_name
            order by total_cves desc
            {limitClause}
            """;
        command.Parameters.Add(new DuckDBParameter(ecosystem));
        if (!string.IsNullOrWhiteSpace(packageName))
            command.Parameters.Add(new DuckDBParameter(packageName));

        var rows = new List<DuckDbAffectedEcosystemPackageSummary>();
        using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            rows.Add(new DuckDbAffectedEcosystemPackageSummary(
                reader.IsDBNull(0) ? "" : reader.GetString(0),
                reader.IsDBNull(1) ? "" : reader.GetString(1),
                reader.GetInt64(2),
                reader.GetInt64(3)));
        }
        return rows;
    }

    public async Task<DuckDbAffectedEcosystemPackageSummary?> QueryAffectedPackageSummaryAsync(string name, CancellationToken ct = default)
    {
        if (!Enabled || string.IsNullOrWhiteSpace(name)) return null;
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        using var command = connection.CreateCommand();
        command.CommandText = """
            select lower(display_name) as name,
                   count(distinct vulnerability_id) as cves,
                   count(*) as facts,
                   string_agg(distinct ecosystem, ', ') as ecosystems
            from affected_components
            where display_name_lower = lower($1)
            group by lower(display_name)
            """;
        command.Parameters.Add(new DuckDBParameter(name));
        using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return null;
        return new DuckDbAffectedEcosystemPackageSummary(
            reader.IsDBNull(3) ? "" : reader.GetString(3),
            reader.GetString(0),
            reader.GetInt64(1),
            reader.GetInt64(2));
    }

    public async Task<IReadOnlyList<DuckDbAffectedMatchingQualitySummary>> QueryAffectedMatchingQualitySummaryAsync(string? ecosystem, string? packageName, int limit = 50, CancellationToken ct = default)
    {
        if (!Enabled) return Array.Empty<DuckDbAffectedMatchingQualitySummary>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            select
              coalesce(nullif(ecosystem_lower, ''), 'unknown') as ecosystem,
              count(*) as facts,
              count(distinct vulnerability_id) as vulnerabilities,
              count(*) filter (where primary_purl is not null and primary_purl <> '') as purl_facts,
              count(*) filter (where primary_cpe23_uri is not null and primary_cpe23_uri <> '') as cpe_facts,
              count(*) filter (where normalized_range is null or normalized_range = '') as no_range,
              count(*) filter (where regexp_matches(coalesce(normalized_range, ''), '^[[:space:]]*>[[:space:]]*0(\\.0+)*[[:space:]]*$')) as open_lower_bound,
              count(*) filter (
                where normalized_range is not null
                  and normalized_range <> ''
                  and not regexp_matches(normalized_range, '(<=|>=|==|=|<|>)')
              ) as unparseable_range
            from affected_components
            where (
                $1 is null
                or ecosystem_lower = lower($1)
                or (instr(lower($1), ':') = 0 and ecosystem_lower like lower($1) || ':%')
              )
              and ($2 is null or package_name_lower = lower($2) or display_name_lower = lower($2))
            group by coalesce(nullif(ecosystem_lower, ''), 'unknown')
            order by facts desc
            limit {Math.Clamp(limit, 1, 500)}
            """;
        command.Parameters.Add(new DuckDBParameter(string.IsNullOrWhiteSpace(ecosystem) ? DBNull.Value : ecosystem));
        command.Parameters.Add(new DuckDBParameter(string.IsNullOrWhiteSpace(packageName) ? DBNull.Value : packageName));

        var rows = new List<DuckDbAffectedMatchingQualitySummary>();
        using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            rows.Add(new DuckDbAffectedMatchingQualitySummary(
                reader.GetString(0),
                reader.GetInt64(1),
                reader.GetInt64(2),
                reader.GetInt64(3),
                reader.GetInt64(4),
                reader.GetInt64(5),
                reader.GetInt64(6),
                reader.GetInt64(7)));
        }
        return rows;
    }

    public async Task<IReadOnlyList<Dictionary<string, object?>>> QueryAffectedComponentsAsync(Guid vulnerabilityId, int limit = 60, CancellationToken ct = default)
    {
        if (!Enabled) return Array.Empty<Dictionary<string, object?>>();
        var grouped = await QueryAffectedComponentsManyAsync([vulnerabilityId], limit, ct);
        return grouped.TryGetValue(vulnerabilityId.ToString("D"), out var rows) ? rows : Array.Empty<Dictionary<string, object?>>();
    }

    public async Task<IReadOnlyDictionary<string, IReadOnlyList<Dictionary<string, object?>>>> QueryAffectedComponentsManyAsync(IReadOnlyCollection<Guid> vulnerabilityIds, int limitPerKey = 200, CancellationToken ct = default)
    {
        if (!Enabled || vulnerabilityIds.Count == 0) return new Dictionary<string, IReadOnlyList<Dictionary<string, object?>>>(StringComparer.OrdinalIgnoreCase);
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            with ranked as (
              select vulnerability_id, ecosystem, package_name, display_name,
                     left(coalesce(primary_purl,''), 80) as primary_purl,
                     left(coalesce(primary_cpe23_uri,''), 80) as primary_cpe23_uri,
                     normalized_range, range_type, confidence, evidence_count, resolution_status,
                     row_number() over (
                       partition by vulnerability_id
                       order by case when range_type in ('ECOSYSTEM','semver','vendor') then 0 else 1 end,
                                case when normalized_range is not null and normalized_range <> '' then 0 else 1 end,
                                ecosystem nulls last, display_name
                     ) as rn
              from affected_components
              where vulnerability_id in ({TextList(vulnerabilityIds.Select(id => id.ToString("D")))})
            )
            select vulnerability_id, ecosystem, package_name, display_name, primary_purl,
                   primary_cpe23_uri, normalized_range, range_type, confidence, evidence_count, resolution_status
            from ranked
            where rn <= {Math.Clamp(limitPerKey, 1, 1000)}
            order by vulnerability_id, rn
            """;
        return GroupRowsByKey(await ReadRowsAsync(command, ct), "vulnerability_id");
    }

    public async Task<IReadOnlyList<DuckDbComponentVulnerabilityCandidate>> QueryComponentVulnerabilityCandidatesAsync(ComponentQuery query, bool withRangeFilter, int limit, CancellationToken ct = default)
    {
        if (!Enabled || !query.HasLookup) return Array.Empty<DuckDbComponentVulnerabilityCandidate>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);

        var hasExplicitPurl = !string.IsNullOrWhiteSpace(query.PurlWithoutVersion);
        var nameList = TextList(hasExplicitPurl ? [] : query.NameCandidates);
        var purlList = TextList(query.PurlCandidates
            .Append(query.PurlWithoutVersion)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value!)
            .Distinct(StringComparer.Ordinal));
        var purlValues = query.PurlCandidates
            .Append(query.PurlWithoutVersion)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value!)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        var purlPredicate = TextEqualsOrIn("c.purl_without_version", purlValues);
        var ecosystem = query.Ecosystem?.ToLowerInvariant();
        var ecosystemFilter = SqlEcosystemFilter("c.ecosystem_lower", ecosystem);
        var rangeFilter = withRangeFilter ? "and c.normalized_range is not null and c.normalized_range <> ''" : "";

        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        using var command = connection.CreateCommand();
        command.CommandText = hasExplicitPurl
            ? $"""
              select distinct vulnerability_id, ecosystem, package_name, primary_purl, normalized_range, range_type
              from affected_components c
              where {purlPredicate}
                and {ecosystemFilter}
                {rangeFilter}
              limit {Math.Clamp(limit, 1, 20000)}
              """
            : $"""
            with matched as (
              select id, vulnerability_id, ecosystem, package_name, primary_purl, normalized_range, range_type, 1 as priority
              from affected_components c
              where {NonEmptyListPredicate(nameList)}
                and c.display_name_lower in ({nameList})
                and {ecosystemFilter}
                {rangeFilter}
              union all
              select id, vulnerability_id, ecosystem, package_name, primary_purl, normalized_range, range_type, 2 as priority
              from affected_components c
              where {NonEmptyListPredicate(nameList)}
                and c.package_name_lower in ({nameList})
                and {ecosystemFilter}
                {rangeFilter}
              union all
              select id, vulnerability_id, ecosystem, package_name, primary_purl, normalized_range, range_type, 3 as priority
              from affected_components c
              where {NonEmptyListPredicate(purlList)}
                and {purlPredicate}
                {rangeFilter}
            ),
            deduplicated as (
              select vulnerability_id, ecosystem, package_name, primary_purl, normalized_range, range_type,
                     row_number() over (
                       partition by vulnerability_id, coalesce(ecosystem, ''), coalesce(package_name, ''),
                                    coalesce(primary_purl, ''), coalesce(normalized_range, ''), coalesce(range_type, '')
                       order by priority
                     ) as rn
              from matched
            )
            select vulnerability_id, ecosystem, package_name, primary_purl, normalized_range, range_type
            from deduplicated
            where rn = 1
            limit {Math.Clamp(limit, 1, 20000)}
            """;

        var rows = new List<DuckDbComponentVulnerabilityCandidate>();
        using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            if (!Guid.TryParse(reader.GetString(0), out var vulnerabilityId)) continue;
            rows.Add(new DuckDbComponentVulnerabilityCandidate(
                vulnerabilityId,
                reader.IsDBNull(1) ? null : reader.GetString(1),
                reader.IsDBNull(2) ? null : reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetString(3),
                reader.IsDBNull(4) ? null : reader.GetString(4),
                reader.IsDBNull(5) ? null : reader.GetString(5)));
        }
        return rows;
    }

    private async Task CopyAffectedComponentsAsync(DuckDBConnection connection, IReadOnlyList<DuckDbAffectedComponentProjection> rows, CancellationToken ct, string tableName = "affected_components")
    {
        var csvRows = rows.Select(row => CsvRow(
            row.Id.ToString("D"),
            row.VulnerabilityId.ToString("D"),
            row.ComponentId?.ToString("D"),
            row.Ecosystem,
            row.Ecosystem?.ToLowerInvariant(),
            row.PackageName,
            row.PackageName?.ToLowerInvariant(),
            row.DisplayName,
            row.DisplayName.ToLowerInvariant(),
            row.PrimaryPurl,
            PurlWithoutVersion(row.PrimaryPurl),
            row.PrimaryCpe23Uri,
            row.NormalizedRange,
            row.RangeType,
            row.Confidence.ToString(System.Globalization.CultureInfo.InvariantCulture),
            row.EvidenceCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            row.ResolutionStatus));

        await CopyRowsAsync(connection, tableName, """
            id, vulnerability_id, component_id, ecosystem, ecosystem_lower,
            package_name, package_name_lower, display_name, display_name_lower,
            primary_purl, purl_without_version, primary_cpe23_uri, normalized_range,
            range_type, confidence, evidence_count, resolution_status
            """, csvRows, ct);
    }
}
