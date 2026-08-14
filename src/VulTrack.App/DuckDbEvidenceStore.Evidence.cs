using DuckDB.NET.Data;

namespace VulTrack.App;

public sealed partial class DuckDbEvidenceStore
{
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
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
        return ReadNucleiSnapshotStats(connection);
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

    public async Task<IReadOnlyList<Dictionary<string, object?>>> QueryAffectedFactsAsync(string vulnerabilityKey, int limit = 200, CancellationToken ct = default)
    {
        if (!Enabled) return Array.Empty<Dictionary<string, object?>>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
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
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
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
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
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
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
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
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
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
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
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
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
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

    private static double NucleiSnapshotDropThreshold()
    {
        var raw = Environment.GetEnvironmentVariable("NUCLEI_LARGE_SNAPSHOT_DROP_THRESHOLD");
        if (double.TryParse(raw, System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out var configured))
            return Math.Clamp(configured, 0.0, 1.0);
        return 0.5;
    }

    public async Task<IReadOnlyList<Dictionary<string, object?>>> QueryCpeEntriesAsync(string vendor, string product, int limit = 50, CancellationToken ct = default)
    {
        if (!Enabled) return Array.Empty<Dictionary<string, object?>>();
        ct.ThrowIfCancellationRequested();
        await InitializeAsync(ct);
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
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
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
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
        using var lease = await RentReadConnectionAsync(ct);
        var connection = lease.Connection;
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
