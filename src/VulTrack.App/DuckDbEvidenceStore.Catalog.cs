using DuckDB.NET.Data;

namespace VulTrack.App;

public sealed partial class DuckDbEvidenceStore
{
    public async Task ReplaceCatalogRecordsAsync(IReadOnlyList<DuckDbCatalogRecord> records, CancellationToken ct)
    {
        if (records.Count == 0) return;
        await InitializeAsync(ct);
        await _writeLock.WaitAsync(ct);
        try
        {
            using var connection = OpenConnection();
            Execute(connection, "begin transaction");
            try
            {
                foreach (var sourceGroup in records.GroupBy(record => record.SourceCode, StringComparer.OrdinalIgnoreCase))
                {
                    foreach (var batch in sourceGroup.Select(record => record.SourceRecordId).Distinct(StringComparer.OrdinalIgnoreCase).Chunk(1000))
                    {
                        var ids = string.Join(",", batch.Select(SqlValue));
                        var source = SqlValue(sourceGroup.Key);
                        Execute(connection, $"delete from source_record_relations where source_code = {source} and source_record_id in ({ids})");
                        Execute(connection, $"delete from source_record_identifiers where source_code = {source} and source_record_id in ({ids})");
                        Execute(connection, $"delete from source_records where source_code = {source} and source_record_id in ({ids})");
                    }
                }

                await CopyCatalogRowsAsync(connection, records, ct);
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

    public async Task<IReadOnlyList<DuckDbCatalogRecord>> FilterChangedCatalogRecordsAsync(
        IReadOnlyList<DuckDbCatalogRecord> records,
        CancellationToken ct)
    {
        if (records.Count == 0) return [];
        await InitializeAsync(ct);

        var existingVersions = new Dictionary<string, (string? Hash, string? Version)>(StringComparer.OrdinalIgnoreCase);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        foreach (var sourceGroup in records.GroupBy(record => record.SourceCode, StringComparer.OrdinalIgnoreCase))
        {
            foreach (var batch in sourceGroup
                         .Select(record => record.SourceRecordId)
                         .Distinct(StringComparer.OrdinalIgnoreCase)
                         .Chunk(1000))
            {
                using var command = connection.CreateCommand();
                command.CommandText = $"""
                    select source_record_id, record_hash, normalizer_version
                    from source_records
                    where source_code = $1
                      and source_record_id in ({string.Join(",", batch.Select(SqlValue))})
                    """;
                command.Parameters.Add(new DuckDBParameter(sourceGroup.Key));
                await using var reader = await command.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct))
                {
                    var sourceRecordId = reader.GetString(0);
                    var recordHash = reader.IsDBNull(1) ? null : reader.GetString(1);
                    var normalizerVersion = reader.IsDBNull(2) ? null : reader.GetString(2);
                    existingVersions[SourceRecordIdentity(sourceGroup.Key, sourceRecordId)] = (recordHash, normalizerVersion);
                }
            }
        }

        return records
            .Where(record =>
                string.IsNullOrWhiteSpace(record.RecordHash)
                || !existingVersions.TryGetValue(
                    SourceRecordIdentity(record.SourceCode, record.SourceRecordId),
                    out var existing)
                || !string.Equals(existing.Hash, record.RecordHash, StringComparison.Ordinal)
                || !string.Equals(existing.Version, record.NormalizationVersion, StringComparison.Ordinal))
            .ToArray();
    }

    public async Task<IReadOnlyList<string>> GetExistingCatalogKeysAsync(
        IReadOnlyList<DuckDbCatalogRecord> records,
        CancellationToken ct)
    {
        if (records.Count == 0) return [];
        await InitializeAsync(ct);
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        foreach (var sourceGroup in records.GroupBy(record => record.SourceCode, StringComparer.OrdinalIgnoreCase))
        {
            foreach (var batch in sourceGroup
                         .Select(record => record.SourceRecordId)
                         .Distinct(StringComparer.OrdinalIgnoreCase)
                         .Chunk(1000))
            {
                using var command = connection.CreateCommand();
                command.CommandText = $"""
                    select distinct vulnerability_key
                    from source_records
                    where source_code = $1
                      and source_record_id in ({string.Join(",", batch.Select(SqlValue))})
                    """;
                command.Parameters.Add(new DuckDBParameter(sourceGroup.Key));
                await using var reader = await command.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct))
                    if (!reader.IsDBNull(0)) keys.Add(reader.GetString(0));
            }
        }
        return keys.ToArray();
    }

    public async Task<DuckDbCatalogStats> RebuildCatalogAsync(CancellationToken ct)
    {
        await InitializeAsync(ct);
        await _writeLock.WaitAsync(ct);
        try
        {
            using var connection = OpenConnection();
            foreach (var statement in CatalogDropIndexStatements)
                Execute(connection, statement);
            Execute(connection, "begin transaction");
            try
            {
                Execute(connection, "delete from vulnerability_identifiers");
                Execute(connection, "delete from vulnerabilities");
                Execute(connection, """
                    insert into vulnerability_identifiers (identifier, vulnerability_id, vulnerability_key)
                    select identifier, min(vulnerability_id), min(vulnerability_key)
                    from source_record_identifiers
                    where regexp_full_match(identifier, '^(CVE-[0-9]{4}-[0-9]{4,}|[A-Z][A-Z0-9_.]*-[A-Z0-9][A-Z0-9_.:-]*)$')
                      and (not starts_with(identifier, 'CVE-') or identifier = vulnerability_key)
                      and source_code not in ('exploitdb', 'poc-in-github', 'nuclei-templates', 'metasploit', 'trickest-cve', 'seebug')
                    group by identifier
                    """);
                Execute(connection, """
                    insert into vulnerabilities
                    with record_rollup as (
                      select vulnerability_id, vulnerability_key,
                             first(nullif(title, '') order by
                               case
                                 when source_code in ('ghsa', 'maven-advisory', 'maven-osv', 'osv') then 0
                                 when source_code in ('cve-list-v5', 'nvd-cve', 'cisa-kev') then 1
                                 when source_code in ('exploitdb', 'poc-in-github', 'nuclei-templates', 'metasploit', 'trickest-cve', 'seebug') then 9
                                 else 3
                               end,
                               coalesce(modified_at, published_at, '') desc
                             ) filter (where nullif(title, '') is not null) as title,
                             first(nullif(description, '') order by
                               case
                                 when source_code in ('cve-list-v5', 'nvd-cve') then 0
                                 when source_code in ('ghsa', 'maven-advisory', 'maven-osv', 'osv') then 1
                                 when source_code in ('exploitdb', 'poc-in-github', 'nuclei-templates', 'metasploit', 'trickest-cve', 'seebug') then 9
                                 else 3
                               end,
                               coalesce(modified_at, published_at, '') desc
                             ) filter (where nullif(description, '') is not null) as description,
                             first(nullif(status, '') order by
                               case
                                 when source_code in ('cve-list-v5', 'nvd-cve', 'cisa-kev') then 0
                                 when source_code in ('exploitdb', 'poc-in-github', 'nuclei-templates', 'metasploit', 'trickest-cve', 'seebug') then 9
                                 else 3
                               end,
                               coalesce(modified_at, published_at, '') desc
                             ) filter (where nullif(status, '') is not null) as status,
                             min(nullif(published_at, '')) as published_at,
                             max(nullif(modified_at, '')) as modified_at,
                             count(*) as source_count
                      from source_records
                      where source_code <> 'nuclei-templates'
                      group by vulnerability_id, vulnerability_key
                    ), severity_rollup as (
                      select vulnerability_key, max(score) as max_cvss_score,
                             arg_max(severity_label, score) as severity_label
                      from severity_scores
                      group by vulnerability_key
                    )
                    select
                      r.vulnerability_id,
                      r.vulnerability_key as primary_identifier,
                      r.title,
                      r.description,
                      r.status,
                      r.published_at,
                      r.modified_at,
                      s.max_cvss_score,
                      s.severity_label,
                      coalesce(a.affected_count, 0) as affected_component_count,
                      coalesce(a.affected_names_json, '[]') as affected_component_names_json,
                      coalesce(i.identifiers_json, '[]') as identifiers_json,
                      r.source_count,
                      current_timestamp as updated_at
                    from record_rollup r
                    left join severity_rollup s on s.vulnerability_key = r.vulnerability_key
                    left join (
                      select vulnerability_key,
                             count(distinct coalesce(nullif(package_name, ''), nullif(cpe23_uri, ''), nullif(purl, ''))) as affected_count,
                             to_json(list(distinct coalesce(nullif(package_name, ''), nullif(cpe23_uri, ''), nullif(purl, '')))
                               filter (where coalesce(nullif(package_name, ''), nullif(cpe23_uri, ''), nullif(purl, '')) is not null))::varchar as affected_names_json
                      from affected_facts
                      group by vulnerability_key
                    ) a on a.vulnerability_key = r.vulnerability_key
                    left join (
                      select vulnerability_key,
                             to_json(list(distinct identifier order by identifier))::varchar as identifiers_json
                      from source_record_identifiers
                      where regexp_full_match(identifier, '^(CVE-[0-9]{4}-[0-9]{4,}|[A-Z][A-Z0-9_.]*-[A-Z0-9][A-Z0-9_.:-]*)$')
                        and (not starts_with(identifier, 'CVE-') or identifier = vulnerability_key)
                        and source_code not in ('exploitdb', 'poc-in-github', 'nuclei-templates', 'metasploit', 'trickest-cve', 'seebug')
                      group by vulnerability_key
                    ) i on i.vulnerability_key = r.vulnerability_key
                    """);
                Execute(connection, """
                    update ai_vulnerability_analyses a
                    set vulnerability_id = v.id
                    from vulnerabilities v
                    where a.primary_identifier = v.primary_identifier
                      and a.vulnerability_id <> v.id
                    """);
                RefreshLatestCatalog(connection);
                Execute(connection, "commit");
            }
            catch
            {
                Execute(connection, "rollback");
                throw;
            }
            foreach (var statement in CatalogIndexStatements)
                Execute(connection, statement);
            return new DuckDbCatalogStats(
                Count(connection, "source_records"),
                Count(connection, "vulnerabilities"),
                Count(connection, "vulnerability_identifiers"));
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<DuckDbCatalogStats> RebuildCatalogForKeysAsync(
        IReadOnlyCollection<string> vulnerabilityKeys,
        CancellationToken ct)
    {
        var keys = vulnerabilityKeys
            .Where(key => !string.IsNullOrWhiteSpace(key))
            .Select(NormalizeKey)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (keys.Length == 0)
        {
            await InitializeAsync(ct);
            using var readConnection = OpenConnection();
            return new DuckDbCatalogStats(
                Count(readConnection, "source_records"),
                Count(readConnection, "vulnerabilities"),
                Count(readConnection, "vulnerability_identifiers"));
        }

        await InitializeAsync(ct);
        await _writeLock.WaitAsync(ct);
        try
        {
            using var connection = OpenConnection();
            var keyList = KeyList(keys);
            Execute(connection, "begin transaction");
            try
            {
                Execute(connection, $"delete from vulnerability_identifiers where vulnerability_key in ({keyList})");
                Execute(connection, $"delete from vulnerabilities where primary_identifier in ({keyList})");
                Execute(connection, $$"""
                    insert into vulnerability_identifiers (identifier, vulnerability_id, vulnerability_key)
                    select identifier, min(vulnerability_id), min(vulnerability_key)
                    from source_record_identifiers
                    where vulnerability_key in ({{keyList}})
                      and regexp_full_match(identifier, '^(CVE-[0-9]{4}-[0-9]{4,}|[A-Z][A-Z0-9_.]*-[A-Z0-9][A-Z0-9_.:-]*)$')
                      and (not starts_with(identifier, 'CVE-') or identifier = vulnerability_key)
                      and source_code not in ('exploitdb', 'poc-in-github', 'nuclei-templates', 'metasploit', 'trickest-cve', 'seebug')
                    group by identifier
                    """);
                Execute(connection, $$"""
                    insert into vulnerabilities
                    with record_rollup as (
                      select vulnerability_id, vulnerability_key,
                             first(nullif(title, '') order by
                               case
                                 when source_code in ('ghsa', 'maven-advisory', 'maven-osv', 'osv') then 0
                                 when source_code in ('cve-list-v5', 'nvd-cve', 'cisa-kev') then 1
                                 when source_code in ('exploitdb', 'poc-in-github', 'nuclei-templates', 'metasploit', 'trickest-cve', 'seebug') then 9
                                 else 3
                               end,
                               coalesce(modified_at, published_at, '') desc
                             ) filter (where nullif(title, '') is not null) as title,
                             first(nullif(description, '') order by
                               case
                                 when source_code in ('cve-list-v5', 'nvd-cve') then 0
                                 when source_code in ('ghsa', 'maven-advisory', 'maven-osv', 'osv') then 1
                                 when source_code in ('exploitdb', 'poc-in-github', 'nuclei-templates', 'metasploit', 'trickest-cve', 'seebug') then 9
                                 else 3
                               end,
                               coalesce(modified_at, published_at, '') desc
                             ) filter (where nullif(description, '') is not null) as description,
                             first(nullif(status, '') order by
                               case
                                 when source_code in ('cve-list-v5', 'nvd-cve', 'cisa-kev') then 0
                                 when source_code in ('exploitdb', 'poc-in-github', 'nuclei-templates', 'metasploit', 'trickest-cve', 'seebug') then 9
                                 else 3
                               end,
                               coalesce(modified_at, published_at, '') desc
                             ) filter (where nullif(status, '') is not null) as status,
                             min(nullif(published_at, '')) as published_at,
                             max(nullif(modified_at, '')) as modified_at,
                             count(*) as source_count
                      from source_records
                      where vulnerability_key in ({{keyList}})
                        and source_code <> 'nuclei-templates'
                      group by vulnerability_id, vulnerability_key
                    ), severity_rollup as (
                      select vulnerability_key, max(score) as max_cvss_score,
                             arg_max(severity_label, score) as severity_label
                      from severity_scores
                      where vulnerability_key in ({{keyList}})
                      group by vulnerability_key
                    )
                    select
                      r.vulnerability_id,
                      r.vulnerability_key,
                      r.title,
                      r.description,
                      r.status,
                      r.published_at,
                      r.modified_at,
                      s.max_cvss_score,
                      s.severity_label,
                      coalesce(a.affected_count, 0),
                      coalesce(a.affected_names_json, '[]'),
                      coalesce(i.identifiers_json, '[]'),
                      r.source_count,
                      current_timestamp
                    from record_rollup r
                    left join severity_rollup s on s.vulnerability_key = r.vulnerability_key
                    left join (
                      select vulnerability_key,
                             count(distinct coalesce(nullif(package_name, ''), nullif(cpe23_uri, ''), nullif(purl, ''))) as affected_count,
                             to_json(list(distinct coalesce(nullif(package_name, ''), nullif(cpe23_uri, ''), nullif(purl, '')))
                               filter (where coalesce(nullif(package_name, ''), nullif(cpe23_uri, ''), nullif(purl, '')) is not null))::varchar as affected_names_json
                      from affected_facts
                      where vulnerability_key in ({{keyList}})
                      group by vulnerability_key
                    ) a on a.vulnerability_key = r.vulnerability_key
                    left join (
                      select vulnerability_key,
                             to_json(list(distinct identifier order by identifier))::varchar as identifiers_json
                      from source_record_identifiers
                      where vulnerability_key in ({{keyList}})
                        and regexp_full_match(identifier, '^(CVE-[0-9]{4}-[0-9]{4,}|[A-Z][A-Z0-9_.]*-[A-Z0-9][A-Z0-9_.:-]*)$')
                        and (not starts_with(identifier, 'CVE-') or identifier = vulnerability_key)
                        and source_code not in ('exploitdb', 'poc-in-github', 'nuclei-templates', 'metasploit', 'trickest-cve', 'seebug')
                      group by vulnerability_key
                    ) i on i.vulnerability_key = r.vulnerability_key
                    """);
                Execute(connection, $"""
                    update ai_vulnerability_analyses a
                    set vulnerability_id = v.id
                    from vulnerabilities v
                    where a.primary_identifier = v.primary_identifier
                      and a.primary_identifier in ({keyList})
                      and a.vulnerability_id <> v.id
                    """);
                RefreshLatestCatalog(connection);
                Execute(connection, "commit");
            }
            catch
            {
                Execute(connection, "rollback");
                throw;
            }
            return new DuckDbCatalogStats(
                Count(connection, "source_records"),
                Count(connection, "vulnerabilities"),
                Count(connection, "vulnerability_identifiers"));
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<long> RebuildAffectedComponentsFromCatalogAsync(CancellationToken ct)
    {
        await InitializeAsync(ct);
        await _writeLock.WaitAsync(ct);
        try
        {
            using var connection = OpenConnection();
            Execute(connection, "begin transaction");
            try
            {
                foreach (var statement in AffectedComponentDropIndexStatements)
                    Execute(connection, statement);
                Execute(connection, "delete from affected_components");
                Execute(connection, """
                    insert into affected_components
                    select
                      md5(concat_ws('|', v.id, f.source_code, coalesce(f.ecosystem, ''),
                                    coalesce(f.package_name, ''), coalesce(f.purl, ''),
                                    coalesce(f.cpe23_uri, ''), coalesce(f.version_range_raw, ''))) as id,
                      v.id as vulnerability_id,
                      null as component_id,
                      f.ecosystem,
                      lower(f.ecosystem) as ecosystem_lower,
                      f.package_name,
                      lower(f.package_name) as package_name_lower,
                      coalesce(nullif(f.package_name, ''), nullif(f.purl, ''), nullif(f.cpe23_uri, ''), 'unknown') as display_name,
                      lower(coalesce(nullif(f.package_name, ''), nullif(f.purl, ''), nullif(f.cpe23_uri, ''), 'unknown')) as display_name_lower,
                      f.purl as primary_purl,
                      case when f.purl is null then null
                           else regexp_replace(split_part(split_part(f.purl, '?', 1), '#', 1), '@[^/@]*$', '')
                      end,
                      f.cpe23_uri as primary_cpe23_uri,
                      f.version_range_raw as normalized_range,
                      f.range_type,
                      case when f.cpe23_uri is not null then 1.0 when f.purl is not null then 0.95 else 0.8 end as confidence,
                      count(*)::integer as evidence_count,
                      'resolved' as resolution_status
                    from affected_facts f
                    join vulnerabilities v on v.primary_identifier = f.vulnerability_key
                    where f.vulnerable
                    group by v.id, f.source_code, f.ecosystem, f.package_name, f.purl,
                             f.cpe23_uri, f.version_range_raw, f.range_type
                    """);
                foreach (var statement in AffectedComponentIndexStatements)
                    Execute(connection, statement);
                Execute(connection, "commit");
            }
            catch
            {
                Execute(connection, "rollback");
                throw;
            }
            return Count(connection, "affected_components");
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<long> RebuildAffectedComponentsForKeysAsync(
        IReadOnlyCollection<string> vulnerabilityKeys,
        CancellationToken ct)
    {
        var keys = vulnerabilityKeys
            .Where(key => !string.IsNullOrWhiteSpace(key))
            .Select(NormalizeKey)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (keys.Length == 0) return 0;

        await InitializeAsync(ct);
        await _writeLock.WaitAsync(ct);
        try
        {
            using var connection = OpenConnection();
            var keyList = KeyList(keys);
            Execute(connection, "begin transaction");
            try
            {
                Execute(connection, $"""
                    delete from affected_components
                    where vulnerability_id in (
                      select id from vulnerabilities where primary_identifier in ({keyList})
                    )
                    """);
                Execute(connection, $"""
                    insert into affected_components
                    select
                      md5(concat_ws('|', v.id, f.source_code, coalesce(f.ecosystem, ''),
                                    coalesce(f.package_name, ''), coalesce(f.purl, ''),
                                    coalesce(f.cpe23_uri, ''), coalesce(f.version_range_raw, ''))) as id,
                      v.id,
                      null,
                      f.ecosystem,
                      lower(f.ecosystem),
                      f.package_name,
                      lower(f.package_name),
                      coalesce(nullif(f.package_name, ''), nullif(f.purl, ''), nullif(f.cpe23_uri, ''), 'unknown'),
                      lower(coalesce(nullif(f.package_name, ''), nullif(f.purl, ''), nullif(f.cpe23_uri, ''), 'unknown')),
                      f.purl,
                      case when f.purl is null then null
                           else regexp_replace(split_part(split_part(f.purl, '?', 1), '#', 1), '@[^/@]*$', '')
                      end,
                      f.cpe23_uri,
                      f.version_range_raw,
                      f.range_type,
                      case when f.cpe23_uri is not null then 1.0 when f.purl is not null then 0.95 else 0.8 end,
                      count(*)::integer,
                      'resolved'
                    from affected_facts f
                    join vulnerabilities v on v.primary_identifier = f.vulnerability_key
                    where f.vulnerable
                      and f.vulnerability_key in ({keyList})
                    group by v.id, f.source_code, f.ecosystem, f.package_name, f.purl,
                             f.cpe23_uri, f.version_range_raw, f.range_type
                    """);
                Execute(connection, "commit");
            }
            catch
            {
                Execute(connection, "rollback");
                throw;
            }
            return keys.LongLength;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<DuckDbCatalogSearchResult> SearchCatalogAsync(VulnerabilitySearchRequest request, CancellationToken ct)
    {
        await InitializeAsync(ct);
        var page = Math.Max(1, request.Page);
        var pageSize = Math.Clamp(request.PageSize, 1, 200);
        var offset = (page - 1) * pageSize;
        var query = (request.Query ?? string.Empty).Trim();
        var normalized = string.IsNullOrWhiteSpace(query) ? string.Empty : Identifier.Normalize(query);
        var sort = request.Sort switch
        {
            "publishedAsc" => "publishedAsc",
            "publishedDesc" => "publishedDesc",
            "modifiedAsc" => "modifiedAsc",
            "identifierAsc" => "identifierAsc",
            "identifierDesc" => "identifierDesc",
            "severityDesc" => "severityDesc",
            _ => "modifiedDesc"
        };
        if (System.Text.RegularExpressions.Regex.IsMatch(
                normalized,
                @"^CVE-\d{4}-\d{4,}$",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase))
        {
            var exact = page == 1 ? await GetCatalogByIdentifierAsync(normalized, ct) : null;
            return new DuckDbCatalogSearchResult(
                exact is null ? [] : [ToCatalogListItem(exact)],
                page,
                pageSize,
                sort,
                false);
        }
        var orderBy = sort switch
        {
            "publishedAsc" => "published_at asc nulls last, primary_identifier asc",
            "publishedDesc" => "published_at desc nulls last, primary_identifier desc",
            "modifiedAsc" => "modified_at asc nulls last, primary_identifier asc",
            "identifierAsc" => "primary_identifier asc",
            "identifierDesc" => "primary_identifier desc",
            "severityDesc" => "max_cvss_score desc nulls last, modified_at desc nulls last",
            _ => "modified_at desc nulls last, primary_identifier desc"
        };

        using var searchLease = await RentReadConnectionAsync(ct);
        var searchConnection = searchLease.Connection;
        using var command = searchConnection.CreateCommand();
        if (string.IsNullOrWhiteSpace(query)
            && sort == "modifiedDesc"
            && offset + pageSize + 1 <= 5000)
        {
            command.CommandText = $"""
                select id, primary_identifier, title, severity_label, max_cvss_score,
                       affected_component_count, affected_component_names_json,
                       published_at, modified_at
                from vulnerability_latest
                order by {orderBy}
                limit {pageSize + 1}
                offset {offset}
                """;
        }
        else if (System.Text.RegularExpressions.Regex.IsMatch(
                     normalized,
                     @"^CVE-\d{4}$",
                     System.Text.RegularExpressions.RegexOptions.IgnoreCase)
                 && int.TryParse(normalized.AsSpan(4, 4), out var cveYear))
        {
            command.CommandText = $"""
                select id, primary_identifier, title, severity_label, max_cvss_score,
                       affected_component_count, affected_component_names_json,
                       published_at, modified_at
                from vulnerabilities
                where primary_identifier >= $1
                  and primary_identifier < $2
                order by {orderBy}
                limit {pageSize + 1}
                offset {offset}
                """;
            command.Parameters.Add(new DuckDBParameter($"CVE-{cveYear:D4}"));
            command.Parameters.Add(new DuckDBParameter($"CVE-{cveYear + 1:D4}"));
        }
        else
        {
            command.CommandText = $"""
                select id, primary_identifier, title, severity_label, max_cvss_score,
                       affected_component_count, affected_component_names_json,
                       published_at, modified_at
                from vulnerabilities v
                where primary_identifier = $1
                   or lower(primary_identifier) like lower($2)
                   or lower(coalesce(title, '')) like lower($2)
                   or lower(coalesce(identifiers_json, '')) like lower($2)
                   or exists (
                     select 1
                     from source_record_relations relation
                     where relation.vulnerability_id = v.id
                       and (relation.related_identifier = $1
                            or lower(relation.related_identifier) like lower($2))
                   )
                order by
                  case
                    when primary_identifier = $1 then 0
                    else 1
                  end,
                  {orderBy}
                limit {pageSize + 1}
                offset {offset}
                """;
            command.Parameters.Add(new DuckDBParameter(normalized));
            command.Parameters.Add(new DuckDBParameter($"%{query}%"));
        }
        var rows = await ReadCatalogListRowsAsync(command, ct);
        var hasMore = rows.Count > pageSize;
        if (hasMore) rows.RemoveAt(rows.Count - 1);
        return new DuckDbCatalogSearchResult(rows, page, pageSize, sort, hasMore);
    }

    public async Task<DuckDbCatalogVulnerability?> GetCatalogByIdAsync(Guid id, CancellationToken ct)
    {
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        using var command = connection.CreateCommand();
        command.CommandText = """
            select id, primary_identifier, title, description, status, severity_label, max_cvss_score,
                   affected_component_count, affected_component_names_json, identifiers_json,
                   published_at, modified_at, source_count
            from vulnerabilities
            where id = $1
            limit 1
            """;
        command.Parameters.Add(new DuckDBParameter(id.ToString("D")));
        return (await ReadCatalogRowsAsync(command, ct)).FirstOrDefault();
    }

    public async Task<IReadOnlyList<DuckDbCatalogVulnerability>> GetCatalogByIdsAsync(
        IReadOnlyCollection<Guid> ids,
        CancellationToken ct)
    {
        if (ids.Count == 0) return Array.Empty<DuckDbCatalogVulnerability>();
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        using var command = connection.CreateCommand();
        var idList = string.Join(',', ids.Select(id => SqlValue(id.ToString("D"))));
        command.CommandText = $"""
            select id, primary_identifier, title, description, status, severity_label, max_cvss_score,
                   affected_component_count, affected_component_names_json, identifiers_json,
                   published_at, modified_at, source_count
            from vulnerabilities
            where id in ({idList})
            """;
        return await ReadCatalogRowsAsync(command, ct);
    }

    public async Task<IReadOnlyDictionary<Guid, DuckDbVulnerabilityRelations>> GetRelationsByVulnerabilityIdsAsync(
        IReadOnlyCollection<Guid> ids,
        CancellationToken ct)
    {
        if (ids.Count == 0) return new Dictionary<Guid, DuckDbVulnerabilityRelations>();
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        return await ReadRelationsByVulnerabilityIdsAsync(lease.Connection, ids, ct);
    }

    private static async Task<IReadOnlyDictionary<Guid, DuckDbVulnerabilityRelations>> ReadRelationsByVulnerabilityIdsAsync(
        DuckDBConnection connection,
        IReadOnlyCollection<Guid> ids,
        CancellationToken ct)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            select vulnerability_id, relation_type, related_identifier
            from source_record_relations
            where vulnerability_id in ({string.Join(',', ids.Select(id => SqlValue(id.ToString("D"))))})
            order by vulnerability_id, relation_type, related_identifier
            """;
        var values = new Dictionary<Guid, (HashSet<string> Upstream, HashSet<string> Related)>();
        using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            if (!Guid.TryParse(reader.GetString(0), out var id)) continue;
            if (!values.TryGetValue(id, out var relation))
            {
                relation = (
                    new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                    new HashSet<string>(StringComparer.OrdinalIgnoreCase));
                values[id] = relation;
            }
            var identifier = reader.GetString(2);
            if (reader.GetString(1).Equals("upstream", StringComparison.OrdinalIgnoreCase))
                relation.Upstream.Add(identifier);
            else
                relation.Related.Add(identifier);
        }
        return values.ToDictionary(
            pair => pair.Key,
            pair => new DuckDbVulnerabilityRelations(
                pair.Value.Upstream.OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToArray(),
                pair.Value.Related.OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToArray()));
    }

    public async Task<IReadOnlyList<DuckDbComponentCatalogItem>> SearchComponentCatalogAsync(
        string? query,
        ComponentQuery lookup,
        int limit,
        CancellationToken ct)
    {
        await InitializeAsync(ct);
        var resultLimit = Math.Clamp(limit, 1, 200);
        var ecosystem = lookup.Ecosystem?.ToLowerInvariant();
        var ecosystemFilter = SqlEcosystemFilter("ecosystem_lower", ecosystem);
        var purls = lookup.PurlCandidates
            .Append(lookup.PurlWithoutVersion)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value!)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (purls.Length > 0)
        {
            var exactPurl = await QueryComponentCatalogAsync(
                TextEqualsOrIn("purl_without_version", purls),
                resultLimit,
                ct);
            if (exactPurl.Count > 0) return exactPurl;
        }

        var names = lookup.NameCandidates
            .Append(lookup.ComponentName)
            .Append(query)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value!.Trim().ToLowerInvariant())
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (names.Length > 0)
        {
            var exactName = await QueryComponentCatalogAsync(
                $"package_name_lower in ({TextList(names)}) and {ecosystemFilter}",
                resultLimit,
                ct);
            if (exactName.Count > 0) return exactName;
        }

        var queryText = query?.Trim() ?? lookup.ComponentName ?? string.Empty;
        if (string.IsNullOrWhiteSpace(queryText)) return [];
        var pattern = SqlValue($"%{queryText.ToLowerInvariant()}%");
        return await QueryComponentCatalogAsync(
            $"(display_name_lower like {pattern} or package_name_lower like {pattern} " +
            $"or lower(coalesce(primary_purl, '')) like {pattern} " +
            $"or lower(coalesce(primary_cpe23_uri, '')) like {pattern}) and {ecosystemFilter}",
            resultLimit,
            ct);
    }

    private async Task<IReadOnlyList<DuckDbComponentCatalogItem>> QueryComponentCatalogAsync(
        string whereClause,
        int limit,
        CancellationToken ct)
    {
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            select md5(concat_ws('|', coalesce(ecosystem, ''), display_name,
                                 coalesce(primary_purl, ''), coalesce(primary_cpe23_uri, ''))) as id,
                   display_name,
                   case when primary_cpe23_uri is not null then 'cpe' else 'package' end as component_type,
                   max(primary_purl) as primary_purl,
                   max(primary_cpe23_uri) as primary_cpe23_uri,
                   to_json(list(distinct coalesce(nullif(primary_purl, ''), nullif(primary_cpe23_uri, ''), display_name)))::varchar as identities
            from affected_components
            where {whereClause}
            group by ecosystem, display_name, primary_purl, primary_cpe23_uri
            order by display_name
            limit {Math.Clamp(limit, 1, 200)}
            """;
        var rows = new List<DuckDbComponentCatalogItem>();
        using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var identities = JsonStringArray(reader.IsDBNull(5) ? null : reader.GetString(5));
            rows.Add(new DuckDbComponentCatalogItem(
                Guid.ParseExact(reader.GetString(0), "N"),
                reader.GetString(1),
                reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetString(3),
                reader.IsDBNull(4) ? null : reader.GetString(4),
                identities));
        }
        return rows;
    }

    public async Task<DuckDbCatalogVulnerability?> GetCatalogByIdentifierAsync(string identifier, CancellationToken ct)
    {
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        var normalized = Identifier.Normalize(identifier);
        using (var primary = connection.CreateCommand())
        {
            primary.CommandText = $"""
                {CatalogSelectColumns}
                from vulnerabilities
                where primary_identifier = $1
                limit 1
                """;
            primary.Parameters.Add(new DuckDBParameter(normalized));
            var direct = (await ReadCatalogRowsAsync(primary, ct)).FirstOrDefault();
            if (direct is not null) return direct;
        }

        string? vulnerabilityId;
        using (var alias = connection.CreateCommand())
        {
            alias.CommandText = """
                select vulnerability_id
                from vulnerability_identifiers
                where identifier = $1
                limit 1
                """;
            alias.Parameters.Add(new DuckDBParameter(normalized));
            vulnerabilityId = (await alias.ExecuteScalarAsync(ct))?.ToString();
        }
        if (string.IsNullOrWhiteSpace(vulnerabilityId))
        {
            using var relation = connection.CreateCommand();
            relation.CommandText = """
                select vulnerability_id
                from source_record_relations
                where related_identifier = $1
                order by case relation_type when 'upstream' then 0 else 1 end, vulnerability_id
                limit 1
                """;
            relation.Parameters.Add(new DuckDBParameter(normalized));
            vulnerabilityId = (await relation.ExecuteScalarAsync(ct))?.ToString();
        }
        if (string.IsNullOrWhiteSpace(vulnerabilityId)) return null;

        using var matched = connection.CreateCommand();
        matched.CommandText = $"""
            {CatalogSelectColumns}
            from vulnerabilities
            where id = $1
            limit 1
            """;
        matched.Parameters.Add(new DuckDBParameter(vulnerabilityId));
        return (await ReadCatalogRowsAsync(matched, ct)).FirstOrDefault();
    }

    private static async Task<List<DuckDbCatalogVulnerability>> ReadCatalogRowsAsync(DuckDBCommand command, CancellationToken ct)
    {
        var rows = new List<DuckDbCatalogVulnerability>();
        using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            if (!Guid.TryParse(reader.GetString(0), out var id)) continue;
            rows.Add(new DuckDbCatalogVulnerability(
                id,
                reader.GetString(1),
                reader.IsDBNull(2) ? null : reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetString(3),
                reader.IsDBNull(4) ? null : reader.GetString(4),
                reader.IsDBNull(5) ? null : reader.GetString(5),
                reader.IsDBNull(6) ? null : reader.GetDouble(6),
                reader.IsDBNull(7) ? 0 : reader.GetInt64(7),
                JsonStringArray(reader.IsDBNull(8) ? null : reader.GetString(8)),
                JsonStringArray(reader.IsDBNull(9) ? null : reader.GetString(9)),
                reader.IsDBNull(10) ? null : reader.GetString(10),
                reader.IsDBNull(11) ? null : reader.GetString(11),
                reader.IsDBNull(12) ? 0 : reader.GetInt64(12)));
        }
        return rows;
    }

    private static async Task<List<DuckDbCatalogListItem>> ReadCatalogListRowsAsync(DuckDBCommand command, CancellationToken ct)
    {
        var rows = new List<DuckDbCatalogListItem>();
        using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            if (!Guid.TryParse(reader.GetString(0), out var id)) continue;
            rows.Add(new DuckDbCatalogListItem(
                id,
                reader.GetString(1),
                reader.IsDBNull(2) ? null : reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetString(3),
                reader.IsDBNull(4) ? null : reader.GetDouble(4),
                reader.IsDBNull(5) ? 0 : reader.GetInt64(5),
                JsonStringArray(reader.IsDBNull(6) ? null : reader.GetString(6)),
                reader.IsDBNull(7) ? null : reader.GetString(7),
                reader.IsDBNull(8) ? null : reader.GetString(8)));
        }
        return rows;
    }

    private static DuckDbCatalogListItem ToCatalogListItem(DuckDbCatalogVulnerability vulnerability) =>
        new(
            vulnerability.Id,
            vulnerability.PrimaryIdentifier,
            vulnerability.Title,
            vulnerability.SeverityLabel,
            vulnerability.MaxCvssScore,
            vulnerability.AffectedComponentCount,
            vulnerability.AffectedComponentNames,
            vulnerability.PublishedAt,
            vulnerability.ModifiedAt);

    private async Task CopyCatalogRowsAsync(DuckDBConnection connection, IReadOnlyList<DuckDbCatalogRecord> records, CancellationToken ct)
    {
        var sourceRows = records.Select(record => CsvRow(
            record.SourceCode,
            record.SourceRecordId,
            record.VulnerabilityId.ToString("D"),
            NormalizeKey(record.VulnerabilityKey),
            record.Title,
            record.Description,
            record.Status,
            record.PublishedAt,
            record.ModifiedAt,
            record.SourceUrl,
            record.RecordHash,
            record.NormalizationVersion));
        await CopyRowsAsync(connection, "source_records", """
            source_code, source_record_id, vulnerability_id, vulnerability_key, title, description,
            status, published_at, modified_at, source_url, record_hash, normalizer_version
            """, sourceRows, ct);

        var identifierRows = records.SelectMany(record => record.Identifiers
            .Where(identifier => !string.IsNullOrWhiteSpace(identifier))
            .Select(Identifier.Normalize)
            .Where(Identifier.IsVulnerabilityId)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(identifier => CsvRow(
                record.SourceCode,
                record.SourceRecordId,
                record.VulnerabilityId.ToString("D"),
                NormalizeKey(record.VulnerabilityKey),
                identifier)));
        await CopyRowsAsync(connection, "source_record_identifiers", """
            source_code, source_record_id, vulnerability_id, vulnerability_key, identifier
            """, identifierRows, ct);

        var relationRows = records.SelectMany(record =>
            (record.UpstreamIdentifiers ?? [])
                .Select(identifier => (Type: "upstream", Identifier: identifier))
                .Concat((record.RelatedIdentifiers ?? [])
                    .Select(identifier => (Type: "related", Identifier: identifier)))
                .Where(relation => !string.IsNullOrWhiteSpace(relation.Identifier))
                .Select(relation => (relation.Type, Identifier: Identifier.Normalize(relation.Identifier)))
                .Where(relation => Identifier.IsVulnerabilityId(relation.Identifier))
                .Distinct()
                .Select(relation => CsvRow(
                    record.SourceCode,
                    record.SourceRecordId,
                    record.VulnerabilityId.ToString("D"),
                    NormalizeKey(record.VulnerabilityKey),
                    relation.Type,
                    relation.Identifier)));
        await CopyRowsAsync(connection, "source_record_relations", """
            source_code, source_record_id, vulnerability_id, vulnerability_key, relation_type, related_identifier
            """, relationRows, ct);
    }

    private static void RefreshLatestCatalog(DuckDBConnection connection)
    {
        Execute(connection, "delete from vulnerability_latest");
        Execute(connection, """
            insert into vulnerability_latest
            select id, primary_identifier, title, severity_label, max_cvss_score,
                   affected_component_count, affected_component_names_json,
                   published_at, modified_at
            from vulnerabilities
            order by modified_at desc nulls last, primary_identifier desc
            limit 5000
            """);
    }
}
