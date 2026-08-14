using DuckDB.NET.Data;
using System.Collections.Concurrent;

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

public sealed record DuckDbExploit(
    string SourceCode,
    Guid RawIndexId,
    string SourceKey,
    string[] Identifiers,
    string? Title,
    string? SourceUrl,
    string? ArtifactType,
    string? ExploitType,
    string? Maturity,
    string? VerificationStatus,
    string? PublishedAt,
    string? ModifiedAt);

public sealed record DuckDbThreatScore(
    string SourceCode,
    Guid RawIndexId,
    string VulnerabilityKey,
    string ScoreType,
    double? Score,
    double? Percentile,
    string? ObservedAt);

public sealed record DuckDbEvidenceRecord(
    string SourceCode,
    Guid RawIndexId,
    string VulnerabilityKey,
    string SourceRecordId,
    IReadOnlyList<DuckDbAffectedFact> AffectedFacts,
    IReadOnlyList<DuckDbSeverityScore> SeverityScores,
    IReadOnlyList<DuckDbReference> References,
    IReadOnlyList<DuckDbWeakness> Weaknesses);

public sealed record DuckDbCatalogRecord(
    string SourceCode,
    string SourceRecordId,
    Guid VulnerabilityId,
    string VulnerabilityKey,
    string? Title,
    string? Description,
    string? Status,
    string? PublishedAt,
    string? ModifiedAt,
    string? SourceUrl,
    string RecordHash,
    IReadOnlyList<string> Identifiers,
    IReadOnlyList<string>? UpstreamIdentifiers = null,
    IReadOnlyList<string>? RelatedIdentifiers = null,
    string NormalizationVersion = "catalog-v1");

public sealed record DuckDbVulnerabilityRelations(
    string[] UpstreamIdentifiers,
    string[] RelatedIdentifiers);

public sealed record DuckDbCatalogStats(long SourceRecords, long Vulnerabilities, long Identifiers);
public sealed record DuckDbSourceProjectionState(IReadOnlyList<string> VulnerabilityKeys, bool HasAffectedFacts);
public sealed record DuckDbNucleiSnapshotStats(long ActiveRows, long ActiveDistinctRawIds);
public sealed record DuckDbFirstEpssApplyResult(
    long InputRows,
    long InsertedRows,
    long UpdatedRows,
    long UnchangedRows,
    long ElapsedMs);

public sealed record DuckDbCatalogVulnerability(
    Guid Id,
    string PrimaryIdentifier,
    string? Title,
    string? Description,
    string? Status,
    string? SeverityLabel,
    double? MaxCvssScore,
    long AffectedComponentCount,
    string[] AffectedComponentNames,
    string[] Identifiers,
    string? PublishedAt,
    string? ModifiedAt,
    long SourceCount);

public sealed record DuckDbCatalogListItem(
    Guid Id,
    string PrimaryIdentifier,
    string? Title,
    string? SeverityLabel,
    double? MaxCvssScore,
    long AffectedComponentCount,
    string[] AffectedComponentNames,
    string? PublishedAt,
    string? ModifiedAt);

public sealed record DuckDbCatalogSearchResult(
    IReadOnlyList<DuckDbCatalogListItem> Items,
    int Page,
    int PageSize,
    string Sort,
    bool HasMore);

public sealed record DuckDbComponentCatalogItem(
    Guid Id,
    string CanonicalName,
    string ComponentType,
    string? PrimaryPurl,
    string? PrimaryCpe23Uri,
    string[] Identities);

public sealed record DuckDbSbomUpload(
    Guid Id,
    string Name,
    string Format,
    int ComponentCount,
    int MatchedCount,
    DateTime UploadedAt);

public sealed record DuckDbSbomComponent(
    Guid Id,
    Guid SbomId,
    string? Purl,
    string? Name,
    string? Version,
    string? Ecosystem,
    string? GroupName,
    string? Vendor,
    string? Product,
    string? Cpe23Uri,
    string? SourcePackageName,
    string? SourcePackageVersion,
    string? ComponentType,
    string MetadataJson,
    int VulnCount);

public sealed record DuckDbSbomMatch(
    Guid ComponentId,
    Guid VulnerabilityId,
    string? Purl,
    string? DisplayName,
    string? Ecosystem,
    string? Range,
    bool? VersionMatched,
    string? Basis,
    string? MatchedVersion);

public sealed record DuckDbSbomFinding(
    Guid Id,
    Guid ComponentId,
    Guid VulnerabilityId,
    string PrimaryIdentifier,
    string? Title,
    string? SeverityLabel,
    double? CvssScore,
    string? ComponentName,
    string? Ecosystem,
    string? VersionRange,
    bool? VersionMatched,
    string? MatchBasis,
    string? MatchedVersion,
    string[] Identifiers,
    string[] Aliases);

public sealed record DuckDbAiImportResult(long InputRows, long MatchedRows, long UnmatchedRows, long StoredRows);

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

public sealed record DuckDbAffectedEcosystemPackageSummary(
    string Ecosystem,
    string PackageName,
    long TotalCves,
    long FactCount);

public sealed record DuckDbAffectedMatchingQualitySummary(
    string Ecosystem,
    long Facts,
    long Vulnerabilities,
    long PurlFacts,
    long CpeFacts,
    long NoRange,
    long OpenLowerBound,
    long UnparseableRange);

public sealed record DuckDbAffectedComponentSummary(
    Guid VulnerabilityId,
    int Count,
    string[] Ecosystems,
    string[] Names);

public sealed record DuckDbVulnerabilityKeyMapping(
    Guid VulnerabilityId,
    string VulnerabilityKey);

public sealed partial class DuckDbEvidenceStore(IConfiguration configuration) : IDisposable
{
    private const string CatalogSelectColumns = """
        select id, primary_identifier, title, description, status, severity_label, max_cvss_score,
               affected_component_count, affected_component_names_json, identifiers_json,
               published_at, modified_at, source_count
        """;

    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly SemaphoreSlim _initializeLock = new(1, 1);
    private readonly SemaphoreSlim _readPoolSlots = new(2, 2);
    private readonly ConcurrentBag<DuckDBConnection> _readPool = new();
    private bool _initialized;

    public string DatabasePath { get; } = ResolvePath(configuration);

    public bool Enabled { get; } =
        string.Equals(Environment.GetEnvironmentVariable("VULTRACK_DUCKDB_ENABLED"), "true", StringComparison.OrdinalIgnoreCase)
        || string.Equals(configuration["VulTrack:DuckDb:Enabled"], "true", StringComparison.OrdinalIgnoreCase);

    public async Task InitializeAsync(CancellationToken ct)
    {
        if (Volatile.Read(ref _initialized)) return;
        ct.ThrowIfCancellationRequested();
        await _initializeLock.WaitAsync(ct);
        try
        {
            if (_initialized) return;
            Directory.CreateDirectory(Path.GetDirectoryName(DatabasePath)!);
            using var connection = OpenConnection();
            foreach (var statement in SchemaStatements)
                Execute(connection, statement);
            Volatile.Write(ref _initialized, true);
        }
        finally
        {
            _initializeLock.Release();
        }
    }

    public async Task<DuckDbSourceProjectionState> GetSourceProjectionStateAsync(string sourceCode, CancellationToken ct)
    {
        await InitializeAsync(ct);
        using var connection = OpenConnection();
        var keys = new List<string>();
        using (var command = connection.CreateCommand())
        {
            command.CommandText = """
                select distinct vulnerability_key
                from source_records
                where source_code = $1 and vulnerability_key is not null
                """;
            command.Parameters.Add(new DuckDBParameter(sourceCode));
            using var reader = await command.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
                keys.Add(reader.GetString(0));
        }
        using var affectedCommand = connection.CreateCommand();
        affectedCommand.CommandText = "select exists(select 1 from affected_facts where source_code = $1 limit 1)";
        affectedCommand.Parameters.Add(new DuckDBParameter(sourceCode));
        var hasAffectedFacts = Convert.ToBoolean(await affectedCommand.ExecuteScalarAsync(ct));
        return new DuckDbSourceProjectionState(keys, hasAffectedFacts);
    }

    public async Task<bool> HasSourceRecordsAsync(string sourceCode, CancellationToken ct)
    {
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        using var command = connection.CreateCommand();
        command.CommandText = "select exists(select 1 from source_records where source_code = $1 limit 1)";
        command.Parameters.Add(new DuckDBParameter(sourceCode));
        return Convert.ToBoolean(await command.ExecuteScalarAsync(ct));
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
                var sourceRecordIds = records.Select(x => x.SourceRecordId).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
                foreach (var batch in rawIds.Chunk(1000))
                {
                    var idList = string.Join(",", batch.Select(SqlValue));
                    foreach (var table in RecordEvidenceTables)
                        Execute(connection, $"delete from {table} where source_code = {SqlValue(sourceCode)} and raw_index_id in ({idList})");
                }
                foreach (var batch in sourceRecordIds.Chunk(1000))
                {
                    var idList = string.Join(",", batch.Select(SqlValue));
                    foreach (var table in RecordEvidenceTables)
                        Execute(connection, $"delete from {table} where source_code = {SqlValue(sourceCode)} and source_record_id in ({idList})");
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

    public async Task ResetLogicalSourceAsync(string sourceCode, CancellationToken ct)
    {
        await InitializeAsync(ct);
        await _writeLock.WaitAsync(ct);
        try
        {
            using var connection = OpenConnection();
            Execute(connection, "begin transaction");
            try
            {
                var source = SqlValue(sourceCode);
                foreach (var table in RecordEvidenceTables)
                    Execute(connection, $"delete from {table} where source_code = {source}");
                Execute(connection, $"delete from exploits where source_code = {source}");
                Execute(connection, $"delete from threat_scores where source_code = {source}");
                Execute(connection, $"delete from source_record_relations where source_code = {source}");
                Execute(connection, $"delete from source_record_identifiers where source_code = {source}");
                Execute(connection, $"delete from source_records where source_code = {source}");
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

    public async Task AppendSpoolBatchAsync(
        IReadOnlyList<DuckDbEvidenceRecord> evidence,
        IReadOnlyList<DuckDbCatalogRecord> catalog,
        IReadOnlyList<DuckDbExploit> exploits,
        IReadOnlyList<DuckDbThreatScore> threatScores,
        CancellationToken ct)
    {
        if (evidence.Count == 0 && catalog.Count == 0 && exploits.Count == 0 && threatScores.Count == 0) return;
        await InitializeAsync(ct);
        await _writeLock.WaitAsync(ct);
        try
        {
            using var connection = OpenConnection();
            Execute(connection, "begin transaction");
            try
            {
                await CopyAffectedFactsAsync(connection, evidence, ct);
                await CopySeverityScoresAsync(connection, evidence, ct);
                await CopyReferencesAsync(connection, evidence, ct);
                await CopyWeaknessesAsync(connection, evidence, ct);
                await CopyCatalogRowsAsync(connection, catalog, ct);
                await CopyExploitsAsync(connection, exploits, ct);
                await CopyThreatScoresAsync(connection, threatScores, ct);
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

    public async Task ReplaceSpoolSupplementalAsync(
        IReadOnlyList<DuckDbExploit> exploits,
        IReadOnlyList<DuckDbThreatScore> threatScores,
        CancellationToken ct)
    {
        if (exploits.Count == 0 && threatScores.Count == 0) return;
        await InitializeAsync(ct);
        await _writeLock.WaitAsync(ct);
        try
        {
            using var connection = OpenConnection();
            Execute(connection, "begin transaction");
            try
            {
                await UpsertExploitRowsAsync(connection, exploits, snapshotId: null, ct);
                foreach (var sourceGroup in threatScores.GroupBy(row => row.SourceCode, StringComparer.OrdinalIgnoreCase))
                {
                    var source = SqlValue(sourceGroup.Key);
                    foreach (var batch in sourceGroup.Select(row => row.RawIndexId.ToString("D")).Distinct().Chunk(1000))
                        Execute(connection, $"delete from threat_scores where source_code = {source} and raw_index_id in ({string.Join(',', batch.Select(SqlValue))})");
                }
                await CopyThreatScoresAsync(connection, threatScores, ct);
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

    // Nuclei emits one complete Git revision. Apply it in a single transaction:
    // deterministic upsert, soft stale-row sweep, active-set verification, commit.
    public async Task<DuckDbNucleiSnapshotStats> ApplyNucleiSnapshotAsync(
        IReadOnlyList<DuckDbExploit> exploits,
        string snapshotId,
        CancellationToken ct)
    {
        if (exploits.Count == 0)
            throw new InvalidDataException("Nuclei snapshot must contain at least one template.");
        if (string.IsNullOrWhiteSpace(snapshotId))
            throw new InvalidDataException("Nuclei snapshot id is required for incremental projection.");
        if (exploits.Any(row => !string.Equals(row.SourceCode, "nuclei-templates", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidDataException("Nuclei snapshot upsert accepts only nuclei-templates rows.");
        var uniqueRows = exploits
            .GroupBy(row => row.RawIndexId)
            .Select(group => group.Last())
            .ToArray();

        await InitializeAsync(ct);
        await _writeLock.WaitAsync(ct);
        try
        {
            using var connection = OpenConnection();
            Execute(connection, "begin transaction");
            try
            {
                var existingStats = ReadNucleiSnapshotStats(connection);
                var dropThreshold = NucleiSnapshotDropThreshold();
                if (existingStats.ActiveRows > 0 &&
                    uniqueRows.Length < existingStats.ActiveRows * dropThreshold &&
                    !EnvironmentFlag("NUCLEI_ALLOW_LARGE_SNAPSHOT_DROP"))
                {
                    throw new InvalidDataException(
                        $"Nuclei snapshot rejected before mutation: incoming={uniqueRows.Length}, " +
                        $"active={existingStats.ActiveRows}, threshold={dropThreshold:P0}. " +
                        "Set NUCLEI_ALLOW_LARGE_SNAPSHOT_DROP=true only after verifying the upstream revision.");
                }
                await UpsertExploitRowsAsync(connection, uniqueRows, snapshotId, ct);
                Execute(connection, $"""
                    update exploits
                    set is_active = false
                    where source_code = 'nuclei-templates'
                      and coalesce(is_active, true)
                      and snapshot_id is distinct from {SqlValue(snapshotId)}
                    """);
                Execute(connection, """
                    update exploits
                    set is_active = false
                    where rowid in (
                      select rowid
                      from (
                        select rowid,
                               row_number() over (
                                 partition by raw_index_id
                                 order by coalesce(modified_at, '') desc, rowid desc
                               ) as row_number
                        from exploits
                        where source_code = 'nuclei-templates'
                          and coalesce(is_active, true)
                      ) duplicate_rows
                      where row_number > 1
                    )
                    """);
                var stats = ReadNucleiSnapshotStats(connection);
                if (stats.ActiveRows != uniqueRows.Length || stats.ActiveDistinctRawIds != uniqueRows.Length)
                    throw new InvalidDataException(
                        $"Nuclei snapshot verification failed: expected {uniqueRows.Length} active templates, " +
                        $"found rows={stats.ActiveRows}, distinctRawIds={stats.ActiveDistinctRawIds}.");
                Execute(connection, "commit");
                return stats;
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

    public async Task UpsertExploitProjectionAsync(
        IReadOnlyList<DuckDbExploit> exploits,
        CancellationToken ct)
    {
        if (exploits.Count == 0) return;

        await InitializeAsync(ct);
        await _writeLock.WaitAsync(ct);
        try
        {
            using var connection = OpenConnection();
            Execute(connection, "begin transaction");
            try
            {
                await UpsertExploitRowsAsync(connection, exploits, snapshotId: null, ct);
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

    public async Task<DuckDbNucleiSnapshotStats> GetNucleiSnapshotStatsAsync(CancellationToken ct)
    {
        await InitializeAsync(ct);
        using var connection = OpenConnection();
        return ReadNucleiSnapshotStats(connection);
    }

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
        using var connection = OpenConnection();
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
        using var connection = OpenConnection();
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
        using var connection = OpenConnection();
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
        using var connection = OpenConnection();
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
        using var connection = OpenConnection();
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

    public async Task<object?> GetCatalogDetailAsync(Guid id, CancellationToken ct)
    {
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        using var catalogCommand = connection.CreateCommand();
        catalogCommand.CommandText = """
            select id, primary_identifier, title, description, status, severity_label, max_cvss_score,
                   affected_component_count, affected_component_names_json, identifiers_json,
                   published_at, modified_at, source_count
            from vulnerabilities
            where id = $1
            limit 1
            """;
        catalogCommand.Parameters.Add(new DuckDBParameter(id.ToString("D")));
        var vulnerability = (await ReadCatalogRowsAsync(catalogCommand, ct)).FirstOrDefault();
        if (vulnerability is null) return null;
        var key = vulnerability.PrimaryIdentifier;
        var evidence = await QueryDetailEvidenceAsync(connection, id, key, ct);
        var relations = await ReadRelationsByVulnerabilityIdsAsync(connection, [id], ct);
        relations.TryGetValue(id, out var vulnerabilityRelations);
        return new
        {
            vulnerability = new
            {
                id = vulnerability.Id,
                primaryIdentifier = key,
                vulnerability.Title,
                vulnerability.Description,
                vulnerability.Status,
                severityLabel = vulnerability.SeverityLabel,
                maxCvssScore = vulnerability.MaxCvssScore,
                vulnerability.PublishedAt,
                vulnerability.ModifiedAt,
                vulnerability.Identifiers,
                aliases = vulnerability.Identifiers.Where(value => !value.Equals(key, StringComparison.OrdinalIgnoreCase)).ToArray(),
                upstreamIdentifiers = vulnerabilityRelations?.UpstreamIdentifiers ?? [],
                relatedIdentifiers = vulnerabilityRelations?.RelatedIdentifiers ?? [],
                vulnerability.SourceCount,
                vulnerability.AffectedComponentCount,
                vulnerability.AffectedComponentNames
            },
            descriptions = Array.Empty<object>(),
            affectedComponents = evidence.AffectedComponents,
            affectedFacts = evidence.AffectedFacts,
            severityScores = evidence.SeverityScores,
            references = evidence.References,
            weaknesses = evidence.Weaknesses,
            exploits = evidence.Exploits,
            threatScores = evidence.ThreatScores,
            history = Array.Empty<object>()
        };
    }

    private static async Task<DetailEvidence> QueryDetailEvidenceAsync(
        DuckDBConnection connection,
        Guid id,
        string vulnerabilityKey,
        CancellationToken ct)
    {
        var idValue = id.ToString("D");
        var key = NormalizeKey(vulnerabilityKey);
        var affectedComponents = await QueryDetailRowsAsync(connection, """
            select ecosystem, package_name, display_name,
                   left(coalesce(primary_purl,''), 80) as primary_purl,
                   left(coalesce(primary_cpe23_uri,''), 80) as primary_cpe23_uri,
                   normalized_range, range_type, confidence, evidence_count, resolution_status
            from affected_components
            where vulnerability_id = $1
            order by case when range_type in ('ECOSYSTEM','semver','vendor') then 0 else 1 end,
                     case when normalized_range is not null and normalized_range <> '' then 0 else 1 end,
                     ecosystem nulls last, display_name
            limit 200
            """, idValue, ct);
        var affectedFacts = await QueryDetailRowsAsync(connection, """
            select source_code as code, fact_type, ecosystem, package_name,
                   purl, purl_without_version, cpe23_uri, version_range_raw,
                   range_type, vulnerable, cast(null as double) as source_confidence
            from affected_facts
            where vulnerability_key = $1
            order by case when cpe23_uri is not null then 0 else 1 end,
                     case when purl is not null then 0 else 1 end,
                     source_code nulls last, package_name nulls last
            limit 250
            """, key, ct);
        var severityScores = await QueryDetailRowsAsync(connection, """
            select code, scoring_system, scoring_version, score_type,
                   vector_string, score, severity_label, rn = 1 as is_selected
            from (
              select source_code as code, scoring_system, scoring_version, score_type,
                     vector_string, score, severity_label,
                     row_number() over (order by score desc nulls last, source_code nulls last) as rn
              from severity_scores where vulnerability_key = $1
            ) ranked
            order by rn limit 40
            """, key, ct);
        var references = ParseReferenceTags(await QueryDetailRowsAsync(connection, """
            select source_code as code, url, ref_type, tags_json
            from evidence_references
            where vulnerability_key = $1
            order by source_code nulls last, url
            limit 160
            """, key, ct));
        var weaknesses = await QueryDetailRowsAsync(connection, """
            select source_code as code, weakness_type, weakness_id, description
            from weaknesses
            where vulnerability_key = $1
            order by case when weakness_id is not null and weakness_id <> '' then 0 else 1 end,
                     weakness_id nulls last, source_code nulls last
            limit 80
            """, key, ct);
        var exploits = await QueryDetailRowsAsync(connection, """
            select source_code, source_key, title, source_url, artifact_type,
                   exploit_type, maturity, verification_status, published_at, modified_at
            from exploits
            where coalesce(is_active, true)
              and identifiers like '%' || $1 || '%'
            limit 40
            """, key, ct);
        var threatScores = await QueryDetailRowsAsync(connection, """
            select source_code, score_type, score, percentile, observed_at
            from threat_scores
            where vulnerability_key = $1
            limit 20
            """, key, ct);
        return new DetailEvidence(
            affectedComponents, affectedFacts, severityScores, references,
            weaknesses, exploits, threatScores);
    }

    private static async Task<IReadOnlyList<Dictionary<string, object?>>> QueryDetailRowsAsync(
        DuckDBConnection connection,
        string sql,
        string parameter,
        CancellationToken ct)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.Parameters.Add(new DuckDBParameter(parameter));
        return await ReadRowsAsync(command, ct);
    }

    private sealed record DetailEvidence(
        IReadOnlyList<Dictionary<string, object?>> AffectedComponents,
        IReadOnlyList<Dictionary<string, object?>> AffectedFacts,
        IReadOnlyList<Dictionary<string, object?>> SeverityScores,
        IReadOnlyList<Dictionary<string, object?>> References,
        IReadOnlyList<Dictionary<string, object?>> Weaknesses,
        IReadOnlyList<Dictionary<string, object?>> Exploits,
        IReadOnlyList<Dictionary<string, object?>> ThreatScores);

    public async Task<DuckDbAiImportResult> ImportAiAnalysesAsync(string path, CancellationToken ct)
    {
        await InitializeAsync(ct);
        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath)) throw new FileNotFoundException("AI analysis import file not found.", fullPath);
        await _writeLock.WaitAsync(ct);
        try
        {
            using var connection = OpenConnection();
            Execute(connection, "begin transaction");
            try
            {
                Execute(connection, "drop table if exists temp_ai_import");
                Execute(connection, $"create temp table temp_ai_import as select * from read_csv_auto({SqlValue(fullPath)}, header=true, all_varchar=true)");
                var inputRows = Count(connection, "temp_ai_import");
                using var matchedCommand = connection.CreateCommand();
                matchedCommand.CommandText = """
                    select count(*)
                    from temp_ai_import i
                    join vulnerabilities v on v.primary_identifier = upper(trim(i.primary_identifier))
                    """;
                var matchedRows = Convert.ToInt64(matchedCommand.ExecuteScalar());
                Execute(connection, "delete from ai_vulnerability_analyses");
                Execute(connection, """
                    insert into ai_vulnerability_analyses
                    select
                      coalesce(v.id, md5('ai-unmatched:' || upper(trim(i.primary_identifier)))) as vulnerability_id,
                      upper(trim(i.primary_identifier)) as primary_identifier,
                      i.model,
                      i.prompt_version,
                      i.evidence_hash,
                      i.analysis_json,
                      i.input_json,
                      try_cast(i.input_chars as integer),
                      try_cast(i.output_chars as integer),
                      i.source_url,
                      i.created_at,
                      i.updated_at,
                      i.usage_json,
                      try_cast(i.prompt_tokens as bigint),
                      try_cast(i.completion_tokens as bigint),
                      try_cast(i.total_tokens as bigint),
                      try_cast(i.cached_tokens as bigint)
                    from temp_ai_import i
                    left join vulnerabilities v on v.primary_identifier = upper(trim(i.primary_identifier))
                    where nullif(trim(i.primary_identifier), '') is not null
                    """);
                var storedRows = Count(connection, "ai_vulnerability_analyses");
                Execute(connection, "drop table temp_ai_import");
                Execute(connection, "commit");
                return new DuckDbAiImportResult(inputRows, matchedRows, inputRows - matchedRows, storedRows);
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

    public async Task<object?> GetAiAnalysisAsync(Guid id, CancellationToken ct)
    {
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        using var command = connection.CreateCommand();
        command.CommandText = """
            select vulnerability_id, model, prompt_version, evidence_hash, analysis_json,
                   input_chars, output_chars, source_url, updated_at,
                   prompt_tokens, completion_tokens, total_tokens, cached_tokens
            from ai_vulnerability_analyses
            where vulnerability_id = $1
            order by updated_at desc nulls last
            limit 1
            """;
        command.Parameters.Add(new DuckDBParameter(id.ToString("D")));
        using var reader = await command.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return null;
        var analysis = reader.IsDBNull(4) ? null : System.Text.Json.Nodes.JsonNode.Parse(reader.GetString(4));
        return new
        {
            status = "analyzed",
            analyzed = true,
            vulnerabilityId = id,
            model = reader.GetString(1),
            promptVersion = reader.GetString(2),
            evidenceHash = reader.GetString(3),
            analysis,
            summary = analysis,
            cached = true,
            configured = false,
            inputChars = reader.IsDBNull(5) ? 0 : reader.GetInt32(5),
            outputChars = reader.IsDBNull(6) ? 0 : reader.GetInt32(6),
            sourceUrl = reader.IsDBNull(7) ? null : reader.GetString(7),
            updatedAt = reader.IsDBNull(8) ? null : reader.GetString(8),
            usage = new
            {
                promptTokens = reader.IsDBNull(9) ? 0 : reader.GetInt64(9),
                completionTokens = reader.IsDBNull(10) ? 0 : reader.GetInt64(10),
                totalTokens = reader.IsDBNull(11) ? 0 : reader.GetInt64(11),
                cachedTokens = reader.IsDBNull(12) ? 0 : reader.GetInt64(12)
            }
        };
    }

    public async Task<object> GetPrimaryStatusAsync(CancellationToken ct)
    {
        await InitializeAsync(ct);
        using var connection = OpenConnection();
        var spoolRoot = Environment.GetEnvironmentVariable("VULTRACK_SPOOL_PATH")
            ?? Path.Combine(Environment.GetEnvironmentVariable("VULTRACK_REPO_ROOT") ?? Directory.GetCurrentDirectory(), "data", "spool");
        var incoming = Path.Combine(spoolRoot, "incoming");
        var readyFiles = Directory.Exists(incoming)
            ? Directory.EnumerateFiles(incoming, "*.ndjson.ready").ToArray()
            : [];
        var processingFiles = Directory.Exists(incoming)
            ? Directory.EnumerateFiles(incoming, "*.ndjson.processing").ToArray()
            : [];
        var schedulerSources = (Environment.GetEnvironmentVariable("DUCKDB_FETCH_SOURCES")
                ?? "nvd-cve,osv,cisa-kev,first-epss,exploitdb,nuclei-templates,metasploit,poc-in-github,cargo-advisory")
            .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        return new
        {
            storageBackend = "duckdb",
            database = new
            {
                path = DatabasePath,
                fileBytes = File.Exists(DatabasePath) ? new FileInfo(DatabasePath).Length : 0,
                sourceRecords = Count(connection, "source_records"),
                vulnerabilities = Count(connection, "vulnerabilities"),
                identifiers = Count(connection, "vulnerability_identifiers"),
                affectedFacts = Count(connection, "affected_facts"),
                affectedComponents = Count(connection, "affected_components"),
                severityScores = Count(connection, "severity_scores"),
                references = Count(connection, "evidence_references"),
                weaknesses = Count(connection, "weaknesses"),
                exploits = CountActiveExploits(connection),
                threatScores = Count(connection, "threat_scores"),
                aiAnalyses = Count(connection, "ai_vulnerability_analyses"),
                sboms = Count(connection, "sbom_uploads")
            },
            queue = new
            {
                readyFiles = readyFiles.Length,
                readyBytes = readyFiles.Sum(file => new FileInfo(file).Length),
                processingFiles = processingFiles.Length
            },
            scheduler = new
            {
                enabled = string.Equals(Environment.GetEnvironmentVariable("VULTRACK_SCHEDULER_ENABLED"), "true", StringComparison.OrdinalIgnoreCase),
                sources = schedulerSources,
                sourceStatus = schedulerSources.Select(source => ReadSpoolSourceStatus(spoolRoot, source)).ToArray()
            }
        };
    }

    private static object ReadSpoolSourceStatus(string spoolRoot, string sourceCode)
    {
        var path = Path.Combine(spoolRoot, "state", $"{sourceCode}.json");
        if (!File.Exists(path))
            return new { code = sourceCode, status = "never-run", stateUpdatedAt = (DateTimeOffset?)null };

        try
        {
            var state = System.Text.Json.Nodes.JsonNode.Parse(File.ReadAllText(path));
            var checkpoint = state?["checkpoint"];
            var lastRun = state?["lastRun"];
            var skipReason = checkpoint?["skipped"]?.ToString();
            return new
            {
                code = sourceCode,
                status = lastRun?["status"]?.GetValue<string>() ?? "unknown",
                trigger = lastRun?["trigger"]?.GetValue<string>(),
                startedAt = lastRun?["started_at"]?.GetValue<string>(),
                finishedAt = lastRun?["finished_at"]?.GetValue<string>(),
                lastFetched = checkpoint?["lastFetched"]?.GetValue<string>()
                    ?? checkpoint?["lastChecked"]?.GetValue<string>()
                    ?? lastRun?["finished_at"]?.GetValue<string>(),
                fetchedCount = lastRun?["fetched_count"]?.GetValue<int>() ?? 0,
                parsedCount = lastRun?["parsed_count"]?.GetValue<int>() ?? 0,
                errorCount = lastRun?["error_count"]?.GetValue<int>() ?? 0,
                skipped = !string.IsNullOrWhiteSpace(skipReason)
                    && !string.Equals(skipReason, "false", StringComparison.OrdinalIgnoreCase),
                skipReason,
                stateUpdatedAt = new DateTimeOffset(File.GetLastWriteTimeUtc(path))
            };
        }
        catch
        {
            return new
            {
                code = sourceCode,
                status = "invalid-state",
                stateUpdatedAt = (DateTimeOffset?)new DateTimeOffset(File.GetLastWriteTimeUtc(path))
            };
        }
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

    private static string[] JsonStringArray(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return [];
        try { return System.Text.Json.JsonSerializer.Deserialize<string[]>(json) ?? []; }
        catch { return []; }
    }

    public async Task<SourceEvidenceReplaceSession> BeginSourceEvidenceReplaceAsync(string sourceCode, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(sourceCode))
            throw new ArgumentException("Source code is required.", nameof(sourceCode));
        await InitializeAsync(ct);
        await _writeLock.WaitAsync(ct);
        DuckDBConnection? connection = null;
        try
        {
            connection = OpenConnection();
            Execute(connection, "begin transaction");
            foreach (var table in RecordEvidenceTables)
                Execute(connection, $"delete from {table} where source_code = {SqlValue(sourceCode)}");
            return new SourceEvidenceReplaceSession(this, connection, sourceCode);
        }
        catch
        {
            if (connection is not null)
            {
                try { Execute(connection, "rollback"); } catch { }
                connection.Dispose();
            }
            _writeLock.Release();
            throw;
        }
    }

    public sealed class SourceEvidenceReplaceSession : IAsyncDisposable
    {
        private readonly DuckDbEvidenceStore store;
        private readonly DuckDBConnection connection;
        private bool completed;
        private bool disposed;

        internal SourceEvidenceReplaceSession(DuckDbEvidenceStore store, DuckDBConnection connection, string sourceCode)
        {
            this.store = store;
            this.connection = connection;
            SourceCode = sourceCode;
        }

        public string SourceCode { get; }

        public async Task AppendAsync(IReadOnlyList<DuckDbEvidenceRecord> records, CancellationToken ct)
        {
            if (disposed) throw new ObjectDisposedException(nameof(SourceEvidenceReplaceSession));
            if (records.Any(record => !record.SourceCode.Equals(SourceCode, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException("A source bulk replace cannot append records from another source.");
            await store.CopyAffectedFactsAsync(connection, records, ct);
            await store.CopySeverityScoresAsync(connection, records, ct);
            await store.CopyReferencesAsync(connection, records, ct);
            await store.CopyWeaknessesAsync(connection, records, ct);
        }

        public Task CompleteAsync(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            if (disposed) throw new ObjectDisposedException(nameof(SourceEvidenceReplaceSession));
            Execute(connection, "commit");
            completed = true;
            return Task.CompletedTask;
        }

        public ValueTask DisposeAsync()
        {
            if (disposed) return ValueTask.CompletedTask;
            disposed = true;
            if (!completed)
            {
                try { Execute(connection, "rollback"); } catch { }
            }
            connection.Dispose();
            store._writeLock.Release();
            return ValueTask.CompletedTask;
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

    public async Task<object> CoverageStatusAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var connection = OpenConnection();

        using var sourceCommand = connection.CreateCommand();
        sourceCommand.CommandText = """
            select source_code,
                   count(*) as records,
                   count(distinct vulnerability_key) as vulnerabilities,
                   max(nullif(modified_at, '')) as latest_modified_at
            from source_records
            group by source_code
            order by records desc, source_code
            """;
        var sources = await ReadRowsAsync(sourceCommand, ct);

        using var ecosystemCommand = connection.CreateCommand();
        ecosystemCommand.CommandText = """
            select coalesce(nullif(ecosystem_lower, ''), 'unknown') as ecosystem,
                   count(*) as components,
                   count(distinct vulnerability_id) as vulnerabilities,
                   count(*) filter (where normalized_range is not null and normalized_range <> '') as ranged_components,
                   count(*) filter (where purl_without_version is not null and purl_without_version <> '') as purl_components,
                   count(*) filter (where primary_cpe23_uri is not null and primary_cpe23_uri <> '') as cpe_components
            from affected_components
            group by coalesce(nullif(ecosystem_lower, ''), 'unknown')
            order by components desc, ecosystem
            """;
        var ecosystems = await ReadRowsAsync(ecosystemCommand, ct);

        return new
        {
            sources,
            ecosystems,
            generatedAt = DateTimeOffset.UtcNow
        };
    }

    public async Task<long> CountAffectedComponentsAsync(CancellationToken ct = default)
    {
        if (!Enabled) return 0;
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var connection = OpenConnection();
        return Count(connection, "affected_components");
    }

    public async Task<IReadOnlyList<string>> QueryAffectedVulnerabilityKeysByRawIndexIdsAsync(IReadOnlyCollection<Guid> rawIndexIds, CancellationToken ct = default)
    {
        if (!Enabled || rawIndexIds.Count == 0) return Array.Empty<string>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var connection = OpenConnection();
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
        using var connection = OpenConnection();
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
        using var connection = OpenConnection();
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
        using var connection = OpenConnection();
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
        using var connection = OpenConnection();
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
        using var connection = OpenConnection();
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
        using var connection = OpenConnection();
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
        using var connection = OpenConnection();
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

    public async Task<IReadOnlyList<Dictionary<string, object?>>> QueryAffectedFactsAsync(string vulnerabilityKey, int limit = 200, CancellationToken ct = default)
    {
        if (!Enabled) return Array.Empty<Dictionary<string, object?>>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            select source_code as code, fact_type, ecosystem, package_name,
                   purl, purl_without_version, cpe23_uri, version_range_raw,
                   range_type, vulnerable, cast(null as double) as source_confidence
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

    public async Task<IReadOnlyList<Dictionary<string, object?>>> QueryAffectedFactsForKeysAsync(
        IReadOnlyCollection<string> vulnerabilityKeys,
        int limit = 250,
        CancellationToken ct = default) =>
        MergeEvidenceRows(await QueryAffectedFactsManyAsync(vulnerabilityKeys, limit, ct), vulnerabilityKeys, limit);

    public async Task<IReadOnlyList<Dictionary<string, object?>>> QueryReferencesAsync(string vulnerabilityKey, int limit = 160, CancellationToken ct = default)
    {
        if (!Enabled) return Array.Empty<Dictionary<string, object?>>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            select source_code as code, url, ref_type, tags_json
            from evidence_references
            where vulnerability_key = $1
            order by source_code nulls last, url
            limit {limit}
            """;
        command.Parameters.Add(new DuckDBParameter(NormalizeKey(vulnerabilityKey)));
        return ParseReferenceTags(await ReadRowsAsync(command, ct));
    }

    public async Task<IReadOnlyList<Dictionary<string, object?>>> QueryReferencesForKeysAsync(
        IReadOnlyCollection<string> vulnerabilityKeys,
        int limit = 160,
        CancellationToken ct = default) =>
        MergeEvidenceRows(await QueryReferencesManyAsync(vulnerabilityKeys, limit, ct), vulnerabilityKeys, limit);

    public async Task<IReadOnlyList<Dictionary<string, object?>>> QuerySeverityScoresAsync(string vulnerabilityKey, int limit = 40, CancellationToken ct = default)
    {
        if (!Enabled) return Array.Empty<Dictionary<string, object?>>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            select code, scoring_system, scoring_version, score_type,
                   vector_string, score, severity_label, rn = 1 as is_selected
            from (
              select source_code as code, scoring_system, scoring_version, score_type,
                     vector_string, score, severity_label,
                     row_number() over (order by score desc nulls last, source_code nulls last) as rn
              from severity_scores
              where vulnerability_key = $1
            ) ranked
            order by rn
            limit {limit}
            """;
        command.Parameters.Add(new DuckDBParameter(NormalizeKey(vulnerabilityKey)));
        return await ReadRowsAsync(command, ct);
    }

    public async Task<IReadOnlyList<Dictionary<string, object?>>> QuerySeverityScoresForKeysAsync(
        IReadOnlyCollection<string> vulnerabilityKeys,
        int limit = 40,
        CancellationToken ct = default)
    {
        var rows = MergeEvidenceRows(
                await QuerySeverityScoresManyAsync(vulnerabilityKeys, limit, ct),
                vulnerabilityKeys,
                limit)
            .OrderByDescending(row => row.TryGetValue("score", out var score) && score is not null ? Convert.ToDecimal(score) : -1)
            .ToArray();
        for (var index = 0; index < rows.Length; index++)
            rows[index]["is_selected"] = index == 0;
        return rows;
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
              select vulnerability_key, source_code as code, fact_type, ecosystem, package_name,
                     purl, purl_without_version, cpe23_uri, version_range_raw, range_type, vulnerable,
                     row_number() over (
                       partition by vulnerability_key
                       order by case when cpe23_uri is not null then 0 else 1 end,
                                case when purl is not null then 0 else 1 end,
                                source_code nulls last, package_name nulls last
                     ) as rn
              from affected_facts
              where vulnerability_key in ({KeyList(vulnerabilityKeys)})
            )
            select vulnerability_key, code, fact_type, ecosystem, package_name,
                   purl, purl_without_version, cpe23_uri, version_range_raw, range_type,
                   vulnerable, cast(null as double) as source_confidence
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
              select vulnerability_key, source_code as code, url, ref_type, tags_json,
                     row_number() over (
                       partition by vulnerability_key
                       order by source_code nulls last, url
                     ) as rn
              from evidence_references
              where vulnerability_key in ({KeyList(vulnerabilityKeys)})
            )
            select vulnerability_key, code, url, ref_type, tags_json
            from ranked
            where rn <= {Math.Clamp(limitPerKey, 1, 1000)}
            order by vulnerability_key, rn
            """;
        return GroupRowsByKey(ParseReferenceTags(await ReadRowsAsync(command, ct)), "vulnerability_key");
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
              select vulnerability_key, source_code as code, scoring_system, scoring_version, score_type,
                     vector_string, score, severity_label,
                     row_number() over (
                       partition by vulnerability_key
                       order by score desc nulls last
                     ) as rn
              from severity_scores
              where vulnerability_key in ({KeyList(vulnerabilityKeys)})
            )
            select vulnerability_key, code, scoring_system, scoring_version, score_type,
                   vector_string, score, severity_label, rn = 1 as is_selected
            from ranked
            where rn <= {Math.Clamp(limitPerKey, 1, 200)}
            order by vulnerability_key, rn
            """;
        return GroupRowsByKey(await ReadRowsAsync(command, ct), "vulnerability_key");
    }

    public async Task<IReadOnlyList<Dictionary<string, object?>>> QueryWeaknessesAsync(string vulnerabilityKey, int limit = 80, CancellationToken ct = default)
    {
        var grouped = await QueryWeaknessesManyAsync([vulnerabilityKey], limit, ct);
        var key = NormalizeKey(vulnerabilityKey);
        return grouped.TryGetValue(key, out var rows) ? rows : Array.Empty<Dictionary<string, object?>>();
    }

    public async Task<IReadOnlyList<Dictionary<string, object?>>> QueryWeaknessesForKeysAsync(
        IReadOnlyCollection<string> vulnerabilityKeys,
        int limit = 80,
        CancellationToken ct = default) =>
        MergeEvidenceRows(await QueryWeaknessesManyAsync(vulnerabilityKeys, limit, ct), vulnerabilityKeys, limit);

    public async Task<IReadOnlyDictionary<string, IReadOnlyList<Dictionary<string, object?>>>> QueryWeaknessesManyAsync(
        IReadOnlyCollection<string> vulnerabilityKeys,
        int limitPerKey = 80,
        CancellationToken ct = default)
    {
        if (!Enabled || vulnerabilityKeys.Count == 0)
            return new Dictionary<string, IReadOnlyList<Dictionary<string, object?>>>(StringComparer.OrdinalIgnoreCase);
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = $"""
            with ranked as (
              select vulnerability_key, source_code as code, weakness_type, weakness_id, description,
                     row_number() over (
                       partition by vulnerability_key
                       order by case when weakness_id is not null and weakness_id <> '' then 0 else 1 end,
                                weakness_id nulls last, source_code nulls last
                     ) as rn
              from weaknesses
              where vulnerability_key in ({KeyList(vulnerabilityKeys)})
            )
            select vulnerability_key, code, weakness_type, weakness_id, description
            from ranked
            where rn <= {Math.Clamp(limitPerKey, 1, 500)}
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

    private static IReadOnlyList<Dictionary<string, object?>> ParseReferenceTags(
        IReadOnlyList<Dictionary<string, object?>> rows)
    {
        foreach (var row in rows)
        {
            row.TryGetValue("tags_json", out var rawTags);
            row.Remove("tags_json");
            try
            {
                row["tags"] = string.IsNullOrWhiteSpace(rawTags?.ToString())
                    ? Array.Empty<string>()
                    : System.Text.Json.JsonSerializer.Deserialize<string[]>(rawTags!.ToString()!) ?? Array.Empty<string>();
            }
            catch (System.Text.Json.JsonException)
            {
                row["tags"] = Array.Empty<string>();
            }
        }
        return rows;
    }

    private static IReadOnlyList<Dictionary<string, object?>> MergeEvidenceRows(
        IReadOnlyDictionary<string, IReadOnlyList<Dictionary<string, object?>>> grouped,
        IReadOnlyCollection<string> vulnerabilityKeys,
        int limit)
    {
        var rows = new List<Dictionary<string, object?>>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var key in vulnerabilityKeys.Select(NormalizeKey).Where(value => !string.IsNullOrWhiteSpace(value)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!grouped.TryGetValue(key, out var keyRows)) continue;
            foreach (var row in keyRows)
            {
                var fingerprint = System.Text.Json.JsonSerializer.Serialize(row);
                if (!seen.Add(fingerprint)) continue;
                rows.Add(row);
                if (rows.Count >= limit) return rows;
            }
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
        var memoryLimit = Environment.GetEnvironmentVariable("VULTRACK_DUCKDB_MEMORY_LIMIT");
        if (!string.IsNullOrWhiteSpace(memoryLimit))
            Execute(connection, $"set memory_limit = {SqlValue(memoryLimit)}");
        var threads = Environment.GetEnvironmentVariable("VULTRACK_DUCKDB_THREADS");
        if (int.TryParse(threads, out var threadCount) && threadCount > 0)
            Execute(connection, $"set threads = {Math.Clamp(threadCount, 1, 32)}");
        return connection;
    }

    private async Task<ReadConnectionLease> RentReadConnectionAsync(CancellationToken ct)
    {
        await _readPoolSlots.WaitAsync(ct);
        try
        {
            if (!_readPool.TryTake(out var connection)) connection = OpenConnection();
            return new ReadConnectionLease(this, connection);
        }
        catch
        {
            _readPoolSlots.Release();
            throw;
        }
    }

    public void Dispose()
    {
        while (_readPool.TryTake(out var connection)) connection.Dispose();
        _readPoolSlots.Dispose();
        _writeLock.Dispose();
        _initializeLock.Dispose();
    }

    private sealed class ReadConnectionLease(DuckDbEvidenceStore owner, DuckDBConnection connection) : IDisposable
    {
        private DuckDBConnection? _connection = connection;

        public DuckDBConnection Connection => _connection ?? throw new ObjectDisposedException(nameof(ReadConnectionLease));

        public void Dispose()
        {
            var returned = Interlocked.Exchange(ref _connection, null);
            if (returned is null) return;
            owner._readPool.Add(returned);
            owner._readPoolSlots.Release();
        }
    }

    private async Task CopyExploitsAsync(DuckDBConnection connection, IReadOnlyList<DuckDbExploit> exploits, CancellationToken ct)
    {
        var rows = exploits.Select(row => CsvRow(
            row.SourceCode,
            row.RawIndexId.ToString("D"),
            row.SourceKey,
            System.Text.Json.JsonSerializer.Serialize(row.Identifiers),
            row.Title,
            row.SourceUrl,
            row.ArtifactType,
            row.ExploitType,
            row.Maturity,
            row.VerificationStatus,
            row.PublishedAt,
            row.ModifiedAt));
        await CopyRowsAsync(connection, "exploits", """
            source_code, raw_index_id, source_key, identifiers, title, source_url,
            artifact_type, exploit_type, maturity, verification_status, published_at, modified_at
            """, rows, ct);
    }

    private async Task UpsertExploitRowsAsync(
        DuckDBConnection connection,
        IReadOnlyList<DuckDbExploit> exploits,
        string? snapshotId,
        CancellationToken ct)
    {
        if (exploits.Count == 0) return;

        const string stagingTable = "temp_spool_exploit_upserts";
        Execute(connection, $"drop table if exists {stagingTable}");
        Execute(connection, $"""
            create temporary table {stagingTable} (
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
              modified_at varchar,
              snapshot_id varchar
            )
            """);

        var rows = exploits
            .GroupBy(row => $"{row.SourceCode}\u001f{row.RawIndexId:D}", StringComparer.OrdinalIgnoreCase)
            .Select(group => group.Last())
            .Select(row => CsvRow(
                row.SourceCode,
                row.RawIndexId.ToString("D"),
                row.SourceKey,
                System.Text.Json.JsonSerializer.Serialize(row.Identifiers),
                row.Title,
                row.SourceUrl,
                row.ArtifactType,
                row.ExploitType,
                row.Maturity,
                row.VerificationStatus,
                row.PublishedAt,
                row.ModifiedAt,
                snapshotId));
        await CopyRowsAsync(connection, stagingTable, """
            source_code, raw_index_id, source_key, identifiers, title, source_url,
            artifact_type, exploit_type, maturity, verification_status, published_at, modified_at, snapshot_id
            """, rows, ct);

        // DuckDB 1.5 ART can invalidate a database when a large indexed DELETE
        // and COPY occur in the same refresh. This update/anti-join insert path
        // preserves the natural key without deleting any live exploit row.
        Execute(connection, $"""
            update exploits target
            set source_key = staged.source_key,
                identifiers = staged.identifiers,
                title = staged.title,
                source_url = staged.source_url,
                artifact_type = staged.artifact_type,
                exploit_type = staged.exploit_type,
                maturity = staged.maturity,
                verification_status = staged.verification_status,
                published_at = staged.published_at,
                modified_at = staged.modified_at,
                snapshot_id = coalesce(staged.snapshot_id, target.snapshot_id),
                is_active = true
            from {stagingTable} staged
            where target.source_code = staged.source_code
              and target.raw_index_id = staged.raw_index_id
              and (
                target.source_key is distinct from staged.source_key
                or target.identifiers is distinct from staged.identifiers
                or target.title is distinct from staged.title
                or target.source_url is distinct from staged.source_url
                or target.artifact_type is distinct from staged.artifact_type
                or target.exploit_type is distinct from staged.exploit_type
                or target.maturity is distinct from staged.maturity
                or target.verification_status is distinct from staged.verification_status
                or target.published_at is distinct from staged.published_at
                or target.modified_at is distinct from staged.modified_at
                or (staged.snapshot_id is not null and target.snapshot_id is distinct from staged.snapshot_id)
                or not coalesce(target.is_active, true)
              )
            """);
        Execute(connection, $"""
            insert into exploits (
              source_code, raw_index_id, source_key, identifiers, title, source_url,
              artifact_type, exploit_type, maturity, verification_status, published_at, modified_at,
              snapshot_id, is_active
            )
            select staged.source_code, staged.raw_index_id, staged.source_key, staged.identifiers,
                   staged.title, staged.source_url, staged.artifact_type, staged.exploit_type,
                   staged.maturity, staged.verification_status, staged.published_at, staged.modified_at,
                   staged.snapshot_id, true
            from {stagingTable} staged
            where not exists (
              select 1 from exploits target
              where target.source_code = staged.source_code
                and target.raw_index_id = staged.raw_index_id
            )
            """);
        Execute(connection, $"drop table {stagingTable}");
    }

    private async Task CopyThreatScoresAsync(DuckDBConnection connection, IReadOnlyList<DuckDbThreatScore> threatScores, CancellationToken ct)
    {
        var rows = threatScores.Select(row => CsvRow(
            row.SourceCode,
            row.RawIndexId.ToString("D"),
            NormalizeKey(row.VulnerabilityKey),
            row.ScoreType,
            row.Score?.ToString(System.Globalization.CultureInfo.InvariantCulture),
            row.Percentile?.ToString(System.Globalization.CultureInfo.InvariantCulture),
            row.ObservedAt));
        await CopyRowsAsync(connection, "threat_scores", """
            source_code, raw_index_id, vulnerability_key, score_type, score, percentile, observed_at
            """, rows, ct);
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
                (
                  auto_detect false,
                  header false,
                  delim ',',
                  quote '"',
                  escape '"',
                  new_line '\n',
                  null '\N',
                  strict_mode true,
                  max_line_size 8388608
                )
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

    private static long CountActiveExploits(DuckDBConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "select count(*) from exploits where coalesce(is_active, true)";
        return Convert.ToInt64(command.ExecuteScalar());
    }

    private static DuckDbNucleiSnapshotStats ReadNucleiSnapshotStats(DuckDBConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            select count(*)::bigint, count(distinct raw_index_id)::bigint
            from exploits
            where source_code = 'nuclei-templates'
              and coalesce(is_active, true)
            """;
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return new DuckDbNucleiSnapshotStats(0, 0);
        return new DuckDbNucleiSnapshotStats(reader.GetInt64(0), reader.GetInt64(1));
    }

    private static bool EnvironmentFlag(string name) =>
        bool.TryParse(Environment.GetEnvironmentVariable(name), out var value) && value;

    private static double NucleiSnapshotDropThreshold()
    {
        var raw = Environment.GetEnvironmentVariable("NUCLEI_LARGE_SNAPSHOT_DROP_THRESHOLD");
        if (double.TryParse(raw, System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out var configured))
            return Math.Clamp(configured, 0.0, 1.0);
        return 0.5;
    }

    private static void Execute(DuckDBConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
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

    private static void RecreateAffectedComponentsTable(DuckDBConnection connection)
    {
        Execute(connection, "drop table if exists affected_components");
        Execute(connection, AffectedComponentsTableStatement);
    }

    private static string SqlValue(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? "null"
            : $"'{value.Replace("'", "''")}'";

    private static string SqlEcosystemFilter(string column, string? ecosystem)
    {
        if (string.IsNullOrWhiteSpace(ecosystem)) return "true";

        var normalized = ecosystem.ToLowerInvariant();
        if (normalized is "cargo" or "crates.io")
            return $"{column} in ('cargo', 'crates.io')";

        return $"({column} = {SqlValue(normalized)} or " +
               $"(instr({SqlValue(normalized)}, ':') = 0 and {column} like {SqlValue(normalized + ":%")}))";
    }

    private static string SourceRecordIdentity(string sourceCode, string sourceRecordId) =>
        $"{sourceCode}\u001f{sourceRecordId}";

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

    private static string TextEqualsOrIn(string column, IEnumerable<string?> values)
    {
        var list = values
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => SqlValue(value))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        return list.Length switch
        {
            0 => "false",
            1 => $"{column} = {list[0]}",
            _ => $"{column} in ({string.Join(", ", list)})"
        };
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

    private static string? NullableString(System.Data.Common.DbDataReader reader, int ordinal) =>
        reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static string DeterministicRowId(Guid first, Guid second)
    {
        var bytes = System.Security.Cryptography.MD5.HashData(
            System.Text.Encoding.UTF8.GetBytes($"{first:D}|{second:D}"));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string? PurlWithoutVersion(string? purl) =>
        PurlIdentity.WithoutVersionAndQualifiers(purl);

    private static string[] SplitSummary(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? []
            : value.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

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
        "vulnerability_identifiers",
        "vulnerability_latest",
        "vulnerabilities",
        "source_record_identifiers",
        "source_record_relations",
        "source_records",
        "affected_facts",
        "severity_scores",
        "evidence_references",
        "weaknesses",
        "cpe_entries",
        "exploits",
        "threat_scores",
        "sbom_matches",
        "sbom_components",
        "sbom_uploads"
    ];

    private static readonly string[] SchemaStatements =
    [
        """
        create table if not exists source_records (
          source_code varchar,
          source_record_id varchar,
          vulnerability_id varchar,
          vulnerability_key varchar,
          title varchar,
          description varchar,
          status varchar,
          published_at varchar,
          modified_at varchar,
          source_url varchar,
          record_hash varchar,
          normalizer_version varchar
        )
        """,
        "alter table source_records add column if not exists normalizer_version varchar",
        """
        create table if not exists source_record_identifiers (
          source_code varchar,
          source_record_id varchar,
          vulnerability_id varchar,
          vulnerability_key varchar,
          identifier varchar
        )
        """,
        """
        create table if not exists source_record_relations (
          source_code varchar,
          source_record_id varchar,
          vulnerability_id varchar,
          vulnerability_key varchar,
          relation_type varchar,
          related_identifier varchar
        )
        """,
        """
        create table if not exists vulnerabilities (
          id varchar,
          primary_identifier varchar,
          title varchar,
          description varchar,
          status varchar,
          published_at varchar,
          modified_at varchar,
          max_cvss_score double,
          severity_label varchar,
          affected_component_count bigint,
          affected_component_names_json varchar,
          identifiers_json varchar,
          source_count bigint,
          updated_at timestamp
        )
        """,
        """
        create table if not exists vulnerability_latest (
          id varchar,
          primary_identifier varchar,
          title varchar,
          severity_label varchar,
          max_cvss_score double,
          affected_component_count bigint,
          affected_component_names_json varchar,
          published_at varchar,
          modified_at varchar
        )
        """,
        """
        insert into vulnerability_latest
        select id, primary_identifier, title, severity_label, max_cvss_score,
               affected_component_count, affected_component_names_json,
               published_at, modified_at
        from vulnerabilities
        where not exists (select 1 from vulnerability_latest limit 1)
        order by modified_at desc nulls last, primary_identifier desc
        limit 5000
        """,
        """
        create table if not exists vulnerability_identifiers (
          identifier varchar,
          vulnerability_id varchar,
          vulnerability_key varchar
        )
        """,
        """
        create table if not exists ai_vulnerability_analyses (
          vulnerability_id varchar,
          primary_identifier varchar,
          model varchar,
          prompt_version varchar,
          evidence_hash varchar,
          analysis_json varchar,
          input_json varchar,
          input_chars integer,
          output_chars integer,
          source_url varchar,
          created_at varchar,
          updated_at varchar,
          usage_json varchar,
          prompt_tokens bigint,
          completion_tokens bigint,
          total_tokens bigint,
          cached_tokens bigint
        )
        """,
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
          modified_at varchar,
          snapshot_id varchar,
          is_active boolean default true
        )
        """,
        """
        alter table exploits add column if not exists snapshot_id varchar
        """,
        """
        alter table exploits add column if not exists is_active boolean default true
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
        create table if not exists sbom_uploads (
          id varchar,
          name varchar,
          format varchar,
          metadata varchar,
          component_count integer,
          matched_count integer,
          uploaded_at timestamp default current_timestamp
        )
        """,
        """
        create table if not exists sbom_components (
          id varchar,
          sbom_id varchar,
          purl varchar,
          name varchar,
          version varchar,
          ecosystem varchar,
          group_name varchar,
          vendor varchar,
          product varchar,
          cpe23_uri varchar,
          source_package_name varchar,
          source_package_version varchar,
          component_type varchar,
          metadata varchar,
          vuln_count integer
        )
        """,
        """
        create table if not exists sbom_matches (
          id varchar,
          sbom_id varchar,
          sbom_component_id varchar,
          vulnerability_id varchar,
          purl varchar,
          display_name varchar,
          ecosystem varchar,
          normalized_range varchar,
          version_matched boolean,
          match_basis varchar,
          matched_version varchar
        )
        """,
        """
        create index if not exists ix_duck_affected_facts_vulnerability_key on affected_facts(vulnerability_key)
        """,
        """
        create index if not exists ix_duck_source_records_key on source_records(vulnerability_key)
        """,
        """
        create index if not exists ix_duck_vulnerabilities_primary on vulnerabilities(primary_identifier)
        """,
        """
        create index if not exists ix_duck_vulnerabilities_id on vulnerabilities(id)
        """,
        """
        create index if not exists ix_duck_vulnerability_identifiers_value on vulnerability_identifiers(identifier)
        """,
        """
        create index if not exists ix_duck_source_record_relations_vulnerability_id on source_record_relations(vulnerability_id)
        """,
        """
        create index if not exists ix_duck_source_record_relations_related_identifier on source_record_relations(related_identifier)
        """,
        """
        create index if not exists ix_duck_ai_vulnerability on ai_vulnerability_analyses(vulnerability_id)
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
        """,
        """
        create index if not exists ix_duck_affected_components_vulnerability_id on affected_components(vulnerability_id)
        """,
        """
        create index if not exists ix_duck_affected_components_purl_without_version on affected_components(purl_without_version)
        """,
        """
        create index if not exists ix_duck_affected_components_package_lower on affected_components(package_name_lower)
        """,
        """
        create index if not exists ix_duck_sbom_components_sbom on sbom_components(sbom_id)
        """,
        """
        create index if not exists ix_duck_sbom_matches_sbom on sbom_matches(sbom_id)
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

    private static readonly string[] AffectedComponentIndexStatements =
    [
        "create index if not exists ix_duck_affected_components_vulnerability_id on affected_components(vulnerability_id)",
        "create index if not exists ix_duck_affected_components_purl_without_version on affected_components(purl_without_version)",
        "create index if not exists ix_duck_affected_components_package_lower on affected_components(package_name_lower)"
    ];

    private static readonly string[] AffectedComponentDropIndexStatements =
    [
        "drop index if exists ix_duck_affected_components_vulnerability_id",
        "drop index if exists ix_duck_affected_components_cpe",
        "drop index if exists ix_duck_affected_components_purl",
        "drop index if exists ix_duck_affected_components_purl_without_version",
        "drop index if exists ix_duck_affected_components_package_lower",
        "drop index if exists ix_duck_affected_components_display_lower"
    ];

    private static readonly string[] CatalogIndexStatements =
    [
        "create index if not exists ix_duck_vulnerabilities_primary on vulnerabilities(primary_identifier)",
        "create index if not exists ix_duck_vulnerabilities_id on vulnerabilities(id)",
        "create index if not exists ix_duck_vulnerability_identifiers_value on vulnerability_identifiers(identifier)"
    ];

    private static readonly string[] CatalogDropIndexStatements =
    [
        "drop index if exists ix_duck_vulnerabilities_primary",
        "drop index if exists ix_duck_vulnerabilities_id",
        "drop index if exists ix_duck_vulnerability_identifiers_value"
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
            where coalesce(is_active, true)
              and identifiers like '%' || $1 || '%'
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
