using DuckDB.NET.Data;

namespace VulTrack.App;

public sealed record DuckDbAffectedFact(
    string FactType,
    string? Ecosystem,
    string? PackageName,
    string? Purl,
    string? Cpe23Uri,
    string? VersionRange,
    string? RangeType,
    bool Vulnerable);

public sealed record DuckDbSeverityScore(
    string ScoringSystem,
    string? ScoringVersion,
    string? ScoreType,
    string? VectorString,
    decimal? Score,
    string? SeverityLabel);

public sealed record DuckDbReference(
    string Url,
    string? RefType,
    string[] Tags);

public sealed record DuckDbWeakness(
    string WeaknessType,
    string? WeaknessId,
    string? Description);

public sealed record DuckDbEvidenceRecord(
    string SourceCode,
    Guid RawIndexId,
    string VulnerabilityKey,
    string SourceRecordId,
    IReadOnlyList<DuckDbAffectedFact> AffectedFacts,
    IReadOnlyList<DuckDbSeverityScore> SeverityScores,
    IReadOnlyList<DuckDbReference> References,
    IReadOnlyList<DuckDbWeakness> Weaknesses);

public sealed record DuckDbAffectedComponentProjection(
    Guid Id,
    Guid VulnerabilityId,
    Guid? ComponentId,
    string? Ecosystem,
    string? PackageName,
    string DisplayName,
    string? PrimaryPurl,
    string? PrimaryCpe23Uri,
    string? NormalizedRange,
    string? RangeType,
    decimal Confidence,
    int EvidenceCount,
    string ResolutionStatus);

public sealed record DuckDbEvidenceStats(
    string path,
    long fileBytes,
    long affectedFacts,
    long affectedComponents,
    long severityScores,
    long references,
    long weaknesses);

public sealed record DuckDbSbomMatchComponent(
    Guid ComponentId,
    string? Purl,
    string? PurlDecoded,
    string? PurlWithoutVersion,
    string? Name,
    string? Version,
    string? Ecosystem,
    string? MappedEcosystem,
    string? Cpe23Uri,
    string? CpePrefix,
    string? CpeProduct,
    string? SourcePackageName,
    string? SourcePackageVersion);

public sealed record DuckDbSbomCandidateMatch(
    Guid ComponentId,
    string? Purl,
    string? ComponentVersion,
    string? ComponentCpe,
    string? SourcePackageVersion,
    Guid VulnerabilityId,
    string? DisplayName,
    string? Ecosystem,
    string? Range,
    string? MatchedCpe,
    string? Basis);

public sealed record DuckDbComponentVulnerabilityCandidate(
    Guid VulnerabilityId,
    string? Ecosystem,
    string? PackageName,
    string? Purl,
    string? VersionRange,
    string? RangeType);

public sealed class DuckDbEvidenceStore(IConfiguration configuration)
{
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    public string DatabasePath { get; } = ResolvePath(configuration);

    public bool Enabled { get; } =
        string.Equals(Environment.GetEnvironmentVariable("VULTRACK_DUCKDB_ENABLED"), "true", StringComparison.OrdinalIgnoreCase)
        || string.Equals(configuration["VulTrack:DuckDb:Enabled"], "true", StringComparison.OrdinalIgnoreCase);

    public Task InitializeAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Directory.CreateDirectory(Path.GetDirectoryName(DatabasePath)!);
        using var connection = OpenConnection();
        foreach (var statement in SchemaStatements)
            Execute(connection, statement);
        return Task.CompletedTask;
    }

    public Task ResetAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        _writeLock.Wait(ct);
        try
        {
            using var connection = OpenConnection();
            foreach (var statement in SchemaStatements)
                Execute(connection, statement);
            foreach (var table in ResetTables)
                Execute(connection, $"delete from {table}");
            return Task.CompletedTask;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task ReplaceRecordsAsync(IReadOnlyList<DuckDbEvidenceRecord> records, CancellationToken ct)
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
                var sourceCode = records[0].SourceCode;
                var rawIds = records.Select(x => x.RawIndexId.ToString("D")).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
                foreach (var batch in rawIds.Chunk(1000))
                {
                    var idList = string.Join(",", batch.Select(SqlValue));
                    foreach (var table in RecordEvidenceTables)
                        Execute(connection, $"delete from {table} where source_code = {SqlValue(sourceCode)} and raw_index_id in ({idList})");
                }

                await CopyAffectedFactsAsync(connection, records, ct);
                await CopySeverityScoresAsync(connection, records, ct);
                await CopyReferencesAsync(connection, records, ct);
                await CopyWeaknessesAsync(connection, records, ct);

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
                Execute(connection, "create temporary table temp_replace_affected_component_ids (vulnerability_id varchar)");
                await CopyRowsAsync(
                    connection,
                    "temp_replace_affected_component_ids",
                    "vulnerability_id",
                    vulnerabilityIds.Distinct().Select(id => CsvRow(id.ToString("D"))),
                    ct);
                Execute(connection, """
                    create table affected_components_next as
                    select *
                    from affected_components existing
                    where not exists (
                      select 1
                      from temp_replace_affected_component_ids ids
                      where ids.vulnerability_id = existing.vulnerability_id
                    )
                    """);
                if (rows.Count > 0)
                    await CopyAffectedComponentsAsync(connection, rows, ct, "affected_components_next");
                Execute(connection, "drop table affected_components");
                Execute(connection, "alter table affected_components_next rename to affected_components");
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

    public Task<DuckDbEvidenceStats> StatsAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        using var connection = OpenConnection();
        foreach (var statement in SchemaStatements)
            Execute(connection, statement);

        var file = new FileInfo(DatabasePath);
        return Task.FromResult(new DuckDbEvidenceStats(
            DatabasePath,
            file.Exists ? file.Length : 0,
            Count(connection, "affected_facts"),
            Count(connection, "affected_components"),
            Count(connection, "severity_scores"),
            Count(connection, "evidence_references"),
            Count(connection, "weaknesses")));
    }

    public async Task<IReadOnlyList<Dictionary<string, object?>>> QueryAffectedFactsAsync(string vulnerabilityKey, int limit = 200, CancellationToken ct = default)
    {
        if (!Enabled) return Array.Empty<Dictionary<string, object?>>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            select source_code, fact_type, ecosystem, package_name,
                   purl, cpe23_uri, version_range_raw, range_type, vulnerable
            from affected_facts
            where vulnerability_key = $1
            order by case when cpe23_uri is not null then 0 else 1 end,
                     case when purl is not null then 0 else 1 end,
                     source_code nulls last, package_name nulls last
            limit {limit}
            """;
        command.Parameters.Add(new DuckDBParameter(NormalizeKey(vulnerabilityKey)));
        return await ReadRowsAsync(command, ct);
    }

    public async Task<IReadOnlyList<Dictionary<string, object?>>> QueryReferencesAsync(string vulnerabilityKey, int limit = 160, CancellationToken ct = default)
    {
        if (!Enabled) return Array.Empty<Dictionary<string, object?>>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            select source_code, url, ref_type
            from evidence_references
            where vulnerability_key = $1
            order by source_code nulls last, url
            limit {limit}
            """;
        command.Parameters.Add(new DuckDBParameter(NormalizeKey(vulnerabilityKey)));
        return await ReadRowsAsync(command, ct);
    }

    public async Task<IReadOnlyList<Dictionary<string, object?>>> QuerySeverityScoresAsync(string vulnerabilityKey, int limit = 40, CancellationToken ct = default)
    {
        if (!Enabled) return Array.Empty<Dictionary<string, object?>>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            select source_code, scoring_system, scoring_version, score_type,
                   vector_string, score, severity_label
            from severity_scores
            where vulnerability_key = $1
            order by score desc nulls last
            limit {limit}
            """;
        command.Parameters.Add(new DuckDBParameter(NormalizeKey(vulnerabilityKey)));
        return await ReadRowsAsync(command, ct);
    }

    public async Task<IReadOnlyDictionary<string, IReadOnlyList<Dictionary<string, object?>>>> QueryAffectedFactsManyAsync(IReadOnlyCollection<string> vulnerabilityKeys, int limitPerKey = 250, CancellationToken ct = default)
    {
        if (!Enabled || vulnerabilityKeys.Count == 0) return new Dictionary<string, IReadOnlyList<Dictionary<string, object?>>>(StringComparer.OrdinalIgnoreCase);
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            with ranked as (
              select vulnerability_key, source_code, fact_type, ecosystem, package_name,
                     purl, cpe23_uri, version_range_raw, range_type, vulnerable,
                     row_number() over (
                       partition by vulnerability_key
                       order by case when cpe23_uri is not null then 0 else 1 end,
                                case when purl is not null then 0 else 1 end,
                                source_code nulls last, package_name nulls last
                     ) as rn
              from affected_facts
              where vulnerability_key in ({KeyList(vulnerabilityKeys)})
            )
            select vulnerability_key, source_code, fact_type, ecosystem, package_name,
                   purl, cpe23_uri, version_range_raw, range_type, vulnerable
            from ranked
            where rn <= {Math.Clamp(limitPerKey, 1, 1000)}
            order by vulnerability_key, rn
            """;
        return GroupRowsByKey(await ReadRowsAsync(command, ct), "vulnerability_key");
    }

    public async Task<IReadOnlyDictionary<string, IReadOnlyList<Dictionary<string, object?>>>> QueryReferencesManyAsync(IReadOnlyCollection<string> vulnerabilityKeys, int limitPerKey = 160, CancellationToken ct = default)
    {
        if (!Enabled || vulnerabilityKeys.Count == 0) return new Dictionary<string, IReadOnlyList<Dictionary<string, object?>>>(StringComparer.OrdinalIgnoreCase);
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            with ranked as (
              select vulnerability_key, source_code, url, ref_type,
                     row_number() over (
                       partition by vulnerability_key
                       order by source_code nulls last, url
                     ) as rn
              from evidence_references
              where vulnerability_key in ({KeyList(vulnerabilityKeys)})
            )
            select vulnerability_key, source_code, url, ref_type
            from ranked
            where rn <= {Math.Clamp(limitPerKey, 1, 1000)}
            order by vulnerability_key, rn
            """;
        return GroupRowsByKey(await ReadRowsAsync(command, ct), "vulnerability_key");
    }

    public async Task<IReadOnlyDictionary<string, IReadOnlyList<Dictionary<string, object?>>>> QuerySeverityScoresManyAsync(IReadOnlyCollection<string> vulnerabilityKeys, int limitPerKey = 40, CancellationToken ct = default)
    {
        if (!Enabled || vulnerabilityKeys.Count == 0) return new Dictionary<string, IReadOnlyList<Dictionary<string, object?>>>(StringComparer.OrdinalIgnoreCase);
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            with ranked as (
              select vulnerability_key, source_code, scoring_system, scoring_version, score_type,
                     vector_string, score, severity_label,
                     row_number() over (
                       partition by vulnerability_key
                       order by score desc nulls last
                     ) as rn
              from severity_scores
              where vulnerability_key in ({KeyList(vulnerabilityKeys)})
            )
            select vulnerability_key, source_code, scoring_system, scoring_version, score_type,
                   vector_string, score, severity_label
            from ranked
            where rn <= {Math.Clamp(limitPerKey, 1, 200)}
            order by vulnerability_key, rn
            """;
        return GroupRowsByKey(await ReadRowsAsync(command, ct), "vulnerability_key");
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
        using var connection = OpenConnection();
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

        var nameList = TextList(query.NameCandidates);
        var purlList = TextList(query.PurlCandidates);
        var ecosystem = query.Ecosystem?.ToLowerInvariant();
        var ecosystemFilter = ecosystem is null
            ? "true"
            : $"lower(coalesce(c.ecosystem,'')) = {SqlValue(ecosystem)}";
        var rangeFilter = withRangeFilter ? "and c.normalized_range is not null and c.normalized_range <> ''" : "";

        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"""
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
                and (lower(coalesce(c.primary_purl,'')) in ({purlList}) or lower(coalesce(c.purl_without_version,'')) in ({purlList}))
                and {ecosystemFilter}
                {rangeFilter}
            ),
            ranked as (
              select vulnerability_id, ecosystem, package_name, primary_purl, normalized_range, range_type,
                     row_number() over (
                       partition by vulnerability_id
                       order by priority,
                                case when normalized_range is not null and normalized_range <> '' then 0 else 1 end
                     ) as rn
              from matched
            )
            select vulnerability_id, ecosystem, package_name, primary_purl, normalized_range, range_type
            from ranked
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

    public async Task<IReadOnlyList<DuckDbSbomCandidateMatch>> QuerySbomCandidateMatchesAsync(IReadOnlyList<DuckDbSbomMatchComponent> components, CancellationToken ct = default)
    {
        if (!Enabled || components.Count == 0) return Array.Empty<DuckDbSbomCandidateMatch>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);

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
                   and (
                     c.primary_purl = t.purl_without_version
                     or c.primary_purl = t.purl_decoded
                     or c.purl_without_version = t.purl_without_version
                   )
                   and (
                     t.mapped_ecosystem_lower is null
                     or c.ecosystem_lower = t.mapped_ecosystem_lower
                     or (instr(t.mapped_ecosystem_lower, ':') = 0 and c.ecosystem_lower like t.mapped_ecosystem_lower || ':%')
                   )
                ),
                ranked as (
                  select *,
                         row_number() over (
                           partition by component_id, vulnerability_id
                           order by match_priority,
                                    case when normalized_range is not null and normalized_range <> '' and left(ltrim(normalized_range), 1) in ('<', '>', '=') then 0 else 1 end
                         ) as rn
                  from candidates
                )
                select component_id, purl, component_version, component_cpe, source_package_version,
                       vulnerability_id, display_name, ecosystem, normalized_range, primary_cpe23_uri, match_basis
                from ranked
                where rn = 1
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
               and (
                 c.primary_purl = t.purl_without_version
                 or c.primary_purl = t.purl_decoded
                 or c.purl_without_version = t.purl_without_version
               )
               and (
                 t.mapped_ecosystem_lower is null
                 or c.ecosystem_lower = t.mapped_ecosystem_lower
                 or (instr(t.mapped_ecosystem_lower, ':') = 0 and c.ecosystem_lower like t.mapped_ecosystem_lower || ':%')
               )
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
              join affected_components c on t.cpe_prefix is not null and c.primary_cpe23_uri like t.cpe_prefix || '%'
              union all
              select t.component_id, t.purl, t.version as component_version, t.cpe23_uri as component_cpe,
                     t.source_package_version, c.vulnerability_id, c.display_name, c.ecosystem,
                     c.normalized_range, c.primary_cpe23_uri, 7 as match_priority, 'cpe-product' as match_basis
              from temp_sbom_match_components t
              join affected_components c on t.cpe_product_lower is not null
               and c.package_name_lower = t.cpe_product_lower
               and c.ecosystem_lower = 'cpe'
            ),
            ranked as (
              select *,
                     row_number() over (
                       partition by component_id, vulnerability_id
                       order by match_priority,
                                case when normalized_range is not null and normalized_range <> '' and left(ltrim(normalized_range), 1) in ('<', '>', '=') then 0 else 1 end
                     ) as rn
              from candidates
            )
            select component_id, purl, component_version, component_cpe, source_package_version,
                   vulnerability_id, display_name, ecosystem, normalized_range, primary_cpe23_uri, match_basis
            from ranked
            where rn = 1
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

    private static async Task<IReadOnlyList<Dictionary<string, object?>>> ReadRowsAsync(DuckDBCommand command, CancellationToken ct)
    {
        var rows = new List<Dictionary<string, object?>>();
        using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var dict = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            for (var i = 0; i < reader.FieldCount; i++)
                dict[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
            rows.Add(dict);
        }
        return rows;
    }

    private static IReadOnlyDictionary<string, IReadOnlyList<Dictionary<string, object?>>> GroupRowsByKey(IReadOnlyList<Dictionary<string, object?>> rows, string keyName)
    {
        var grouped = new Dictionary<string, List<Dictionary<string, object?>>>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in rows)
        {
            if (!row.TryGetValue(keyName, out var keyValue) || string.IsNullOrWhiteSpace(keyValue?.ToString())) continue;
            var key = keyValue.ToString()!;
            row.Remove(keyName);
            if (!grouped.TryGetValue(key, out var list))
            {
                list = [];
                grouped[key] = list;
            }
            list.Add(row);
        }

        return grouped.ToDictionary(x => x.Key, x => (IReadOnlyList<Dictionary<string, object?>>)x.Value, StringComparer.OrdinalIgnoreCase);
    }

    private DuckDBConnection OpenConnection()
    {
        var connection = new DuckDBConnection($"Data Source={DatabasePath}");
        connection.Open();
        return connection;
    }

    private async Task CopyAffectedFactsAsync(DuckDBConnection connection, IReadOnlyList<DuckDbEvidenceRecord> records, CancellationToken ct)
    {
        var rows = records.SelectMany(record => record.AffectedFacts
            .GroupBy(fact => $"{fact.FactType}|{fact.Ecosystem}|{fact.PackageName}|{fact.Purl}|{fact.Cpe23Uri}|{fact.VersionRange}|{fact.RangeType}|{fact.Vulnerable}")
            .Select(group => group.First())
            .Select(fact => CsvRow(
                record.SourceCode,
                record.RawIndexId.ToString("D"),
                NormalizeKey(record.VulnerabilityKey),
                record.SourceRecordId,
                fact.FactType,
                fact.Ecosystem,
                fact.PackageName,
                fact.PackageName?.ToLowerInvariant(),
                fact.Purl,
                PurlWithoutVersion(fact.Purl),
                fact.Cpe23Uri,
                fact.VersionRange,
                fact.RangeType,
                fact.Vulnerable ? "true" : "false")));

        await CopyRowsAsync(connection, "affected_facts", """
            source_code, raw_index_id, vulnerability_key, source_record_id, fact_type, ecosystem,
            package_name, normalized_package_name, purl, purl_without_version, cpe23_uri,
            version_range_raw, range_type, vulnerable
            """, rows, ct);
    }

    private async Task CopySeverityScoresAsync(DuckDBConnection connection, IReadOnlyList<DuckDbEvidenceRecord> records, CancellationToken ct)
    {
        var rows = records.SelectMany(record => record.SeverityScores.Select(score => CsvRow(
            record.SourceCode,
            record.RawIndexId.ToString("D"),
            NormalizeKey(record.VulnerabilityKey),
            record.SourceRecordId,
            score.ScoringSystem,
            score.ScoringVersion,
            score.ScoreType,
            score.VectorString,
            score.Score?.ToString(System.Globalization.CultureInfo.InvariantCulture),
            score.SeverityLabel)));

        await CopyRowsAsync(connection, "severity_scores", """
            source_code, raw_index_id, vulnerability_key, source_record_id, scoring_system,
            scoring_version, score_type, vector_string, score, severity_label
            """, rows, ct);
    }

    private async Task CopyReferencesAsync(DuckDBConnection connection, IReadOnlyList<DuckDbEvidenceRecord> records, CancellationToken ct)
    {
        var rows = records.SelectMany(record => record.References
            .Where(reference => !string.IsNullOrWhiteSpace(reference.Url))
            .DistinctBy(reference => reference.Url)
            .Select(reference => CsvRow(
                record.SourceCode,
                record.RawIndexId.ToString("D"),
                NormalizeKey(record.VulnerabilityKey),
                record.SourceRecordId,
                reference.Url,
                reference.Url.ToLowerInvariant(),
                reference.RefType,
                System.Text.Json.JsonSerializer.Serialize(reference.Tags))));

        await CopyRowsAsync(connection, "evidence_references", """
            source_code, raw_index_id, vulnerability_key, source_record_id, url, normalized_url, ref_type, tags_json
            """, rows, ct);
    }

    private async Task CopyWeaknessesAsync(DuckDBConnection connection, IReadOnlyList<DuckDbEvidenceRecord> records, CancellationToken ct)
    {
        var rows = records.SelectMany(record => record.Weaknesses
            .Where(weakness => !string.IsNullOrWhiteSpace(weakness.WeaknessId) || !string.IsNullOrWhiteSpace(weakness.Description))
            .DistinctBy(weakness => $"{weakness.WeaknessType}|{weakness.WeaknessId}|{weakness.Description}")
            .Select(weakness => CsvRow(
                record.SourceCode,
                record.RawIndexId.ToString("D"),
                NormalizeKey(record.VulnerabilityKey),
                record.SourceRecordId,
                weakness.WeaknessType,
                weakness.WeaknessId,
                weakness.Description)));

        await CopyRowsAsync(connection, "weaknesses", """
            source_code, raw_index_id, vulnerability_key, source_record_id, weakness_type, weakness_id, description
            """, rows, ct);
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

    private async Task CopyRowsAsync(DuckDBConnection connection, string tableName, string columns, IEnumerable<string> rows, CancellationToken ct)
    {
        var tempDir = Path.Combine(Path.GetDirectoryName(DatabasePath)!, "tmp");
        Directory.CreateDirectory(tempDir);
        var tempFile = Path.Combine(tempDir, $"{tableName}-{Guid.NewGuid():N}.csv");
        var count = 0;
        try
        {
            await using (var writer = new StreamWriter(tempFile))
            {
                foreach (var row in rows)
                {
                    ct.ThrowIfCancellationRequested();
                    await writer.WriteLineAsync(row);
                    count++;
                }
            }

            if (count == 0) return;
            Execute(connection, $"""
                copy {tableName} ({columns})
                from {SqlValue(tempFile)}
                (header false, delim ',', quote '"', escape '"', null '\N')
                """);
        }
        finally
        {
            try { File.Delete(tempFile); } catch { }
        }
    }

    private static long Count(DuckDBConnection connection, string tableName)
    {
        using var command = connection.CreateCommand();
        command.CommandText = $"select count(*) from {tableName}";
        return Convert.ToInt64(command.ExecuteScalar());
    }

    private static void Execute(DuckDBConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }

    private static void RecreateAffectedComponentsTable(DuckDBConnection connection)
    {
        Execute(connection, "drop table if exists affected_components");
        Execute(connection, AffectedComponentsTableStatement);
    }

    private static string SqlValue(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? "null"
            : $"'{value.Replace("'", "''")}'";

    private static string KeyList(IEnumerable<string> keys) =>
        string.Join(", ", keys
            .Where(key => !string.IsNullOrWhiteSpace(key))
            .Select(key => $"'{NormalizeKey(key).Replace("'", "''")}'")
            .Distinct(StringComparer.Ordinal));

    private static string TextList(IEnumerable<string?> values)
    {
        var list = values
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => $"'{value!.Replace("'", "''")}'")
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        return list.Length == 0 ? "null" : string.Join(", ", list);
    }

    private static string NonEmptyListPredicate(string list) => list == "null" ? "false" : "true";

    private static string NormalizeKey(string key) => Identifier.Normalize(key);

    private static string CsvRow(params string?[] values) =>
        string.Join(",", values.Select(CsvValue));

    private static string CsvValue(string? value)
    {
        if (value is null) return "\\N";
        return $"\"{value.Replace("\"", "\"\"")}\"";
    }

    private static string? PurlWithoutVersion(string? purl)
    {
        if (string.IsNullOrWhiteSpace(purl)) return null;
        var at = purl.LastIndexOf('@');
        return at > "pkg:".Length ? purl[..at] : purl;
    }

    private static string ResolvePath(IConfiguration configuration)
    {
        var configured = Environment.GetEnvironmentVariable("VULTRACK_DUCKDB_PATH")
            ?? configuration["VulTrack:DuckDb:Path"];
        if (!string.IsNullOrWhiteSpace(configured)) return Path.GetFullPath(configured);

        var root = Environment.GetEnvironmentVariable("VULTRACK_REPO_ROOT")
            ?? Directory.GetCurrentDirectory();
        return Path.GetFullPath(Path.Combine(root, "data", "duckdb", "vultrack-evidence.duckdb"));
    }

    private static readonly string[] RecordEvidenceTables =
    [
        "affected_facts",
        "severity_scores",
        "evidence_references",
        "weaknesses"
    ];

    private static readonly string[] ResetTables =
    [
        "affected_facts",
        "severity_scores",
        "evidence_references",
        "weaknesses",
        "cpe_entries",
        "exploits",
        "threat_scores"
    ];

    private static readonly string[] SchemaStatements =
    [
        """
        create table if not exists affected_facts (
          source_code varchar,
          raw_index_id varchar,
          vulnerability_key varchar,
          source_record_id varchar,
          fact_type varchar,
          ecosystem varchar,
          package_name varchar,
          normalized_package_name varchar,
          purl varchar,
          purl_without_version varchar,
          cpe23_uri varchar,
          version_range_raw varchar,
          range_type varchar,
          vulnerable boolean
        )
        """,
        AffectedComponentsTableStatement,
        """
        create table if not exists severity_scores (
          source_code varchar,
          raw_index_id varchar,
          vulnerability_key varchar,
          source_record_id varchar,
          scoring_system varchar,
          scoring_version varchar,
          score_type varchar,
          vector_string varchar,
          score double,
          severity_label varchar
        )
        """,
        """
        create table if not exists evidence_references (
          source_code varchar,
          raw_index_id varchar,
          vulnerability_key varchar,
          source_record_id varchar,
          url varchar,
          normalized_url varchar,
          ref_type varchar,
          tags_json varchar
        )
        """,
        """
        create table if not exists weaknesses (
          source_code varchar,
          raw_index_id varchar,
          vulnerability_key varchar,
          source_record_id varchar,
          weakness_type varchar,
          weakness_id varchar,
          description varchar
        )
        """,
        """
        create table if not exists cpe_entries (
          source_code varchar,
          raw_index_id varchar,
          cpe23_uri varchar,
          vendor varchar,
          product varchar,
          version varchar,
          part varchar,
          target_sw varchar,
          deprecated boolean
        )
        """,
        """
        create table if not exists exploits (
          source_code varchar,
          raw_index_id varchar,
          source_key varchar,
          identifiers varchar,
          title varchar,
          source_url varchar,
          artifact_type varchar,
          exploit_type varchar,
          maturity varchar,
          verification_status varchar,
          published_at varchar,
          modified_at varchar
        )
        """,
        """
        create table if not exists threat_scores (
          source_code varchar,
          raw_index_id varchar,
          vulnerability_key varchar,
          score_type varchar,
          score double,
          percentile double,
          observed_at varchar
        )
        """,
        """
        create index if not exists ix_duck_affected_facts_vulnerability_key on affected_facts(vulnerability_key)
        """,
        """
        create index if not exists ix_duck_severity_scores_vulnerability_key on severity_scores(vulnerability_key)
        """,
        """
        create index if not exists ix_duck_evidence_references_vulnerability_key on evidence_references(vulnerability_key)
        """,
        """
        create index if not exists ix_duck_weaknesses_vulnerability_key on weaknesses(vulnerability_key)
        """,
        """
        create index if not exists ix_duck_threat_scores_vulnerability_key on threat_scores(vulnerability_key)
        """
    ];

    private const string AffectedComponentsTableStatement = """
        create table if not exists affected_components (
          id varchar,
          vulnerability_id varchar,
          component_id varchar,
          ecosystem varchar,
          ecosystem_lower varchar,
          package_name varchar,
          package_name_lower varchar,
          display_name varchar,
          display_name_lower varchar,
          primary_purl varchar,
          purl_without_version varchar,
          primary_cpe23_uri varchar,
          normalized_range varchar,
          range_type varchar,
          confidence double,
          evidence_count integer,
          resolution_status varchar
        )
        """;

    private static readonly string[] AffectedComponentIndexStatements = [];

    private static readonly string[] AffectedComponentDropIndexStatements =
    [
        "drop index if exists ix_duck_affected_components_vulnerability_id",
        "drop index if exists ix_duck_affected_components_cpe",
        "drop index if exists ix_duck_affected_components_purl",
        "drop index if exists ix_duck_affected_components_purl_without_version",
        "drop index if exists ix_duck_affected_components_package_lower",
        "drop index if exists ix_duck_affected_components_display_lower"
    ];

    public async Task<IReadOnlyList<Dictionary<string, object?>>> QueryCpeEntriesAsync(string vendor, string product, int limit = 50, CancellationToken ct = default)
    {
        if (!Enabled) return Array.Empty<Dictionary<string, object?>>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            select source_code, cpe23_uri, vendor, product, version, part, target_sw, deprecated
            from cpe_entries
            where vendor like '%' || $1 || '%' or product like '%' || $2 || '%'
            limit {limit}
            """;
        command.Parameters.Add(new DuckDBParameter(vendor ?? ""));
        command.Parameters.Add(new DuckDBParameter(product ?? ""));
        return await ReadRowsAsync(command, ct);
    }

    public async Task<IReadOnlyList<Dictionary<string, object?>>> QueryExploitsAsync(string vulnerabilityKey, int limit = 40, CancellationToken ct = default)
    {
        if (!Enabled) return Array.Empty<Dictionary<string, object?>>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            select source_code, source_key, title, source_url, artifact_type,
                   exploit_type, maturity, verification_status, published_at, modified_at
            from exploits
            where identifiers like '%' || $1 || '%'
            limit {limit}
            """;
        command.Parameters.Add(new DuckDBParameter(NormalizeKey(vulnerabilityKey)));
        return await ReadRowsAsync(command, ct);
    }

    public async Task<IReadOnlyList<Dictionary<string, object?>>> QueryThreatScoresAsync(string vulnerabilityKey, int limit = 20, CancellationToken ct = default)
    {
        if (!Enabled) return Array.Empty<Dictionary<string, object?>>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            select source_code, score_type, score, percentile, observed_at
            from threat_scores
            where vulnerability_key = $1
            limit {limit}
            """;
        command.Parameters.Add(new DuckDBParameter(NormalizeKey(vulnerabilityKey)));
        return await ReadRowsAsync(command, ct);
    }
}
