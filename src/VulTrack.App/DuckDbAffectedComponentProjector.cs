using Npgsql;

namespace VulTrack.App;

public sealed record DuckDbAffectedComponentRebuildResult(
    bool ok,
    bool reset,
    int batchSize,
    int limit,
    long processed,
    long pgAffectedComponents,
    long duckDbAffectedComponents,
    double elapsedSeconds,
    double rowsPerSecond);

public sealed record DuckDbAffectedEvidenceSyncResult(
    int RawIndexes,
    int VulnerabilityKeys,
    int MappedVulnerabilities,
    long AffectedComponents);

public sealed record DuckDbAffectedEvidenceRebuildResult(
    int VulnerabilityKeys,
    int KeyMappings,
    int Vulnerabilities,
    long AffectedComponents,
    double ElapsedSeconds);

public sealed class DuckDbAffectedComponentProjector(
    NpgsqlDataSource db,
    DuckDbEvidenceStore store,
    ILogger<DuckDbAffectedComponentProjector> logger)
{
    private static bool DuckDbEvidenceOnly =>
        string.Equals(Environment.GetEnvironmentVariable("VULTRACK_DUCKDB_EVIDENCE_ONLY"), "true", StringComparison.OrdinalIgnoreCase);

    public async Task<DuckDbAffectedEvidenceSyncResult> QueueEvidenceForRawIndexesAsync(IReadOnlyCollection<Guid> rawIndexIds, CancellationToken ct)
    {
        if (!store.Enabled || rawIndexIds.Count == 0)
            return new DuckDbAffectedEvidenceSyncResult(rawIndexIds.Count, 0, 0, 0);

        var keys = await store.QueryAffectedVulnerabilityKeysByRawIndexIdsAsync(rawIndexIds, ct);
        if (keys.Count == 0)
            return new DuckDbAffectedEvidenceSyncResult(rawIndexIds.Count, 0, 0, 0);

        await using var connection = await db.OpenConnectionAsync(ct);
        var mappings = await ResolveVulnerabilityKeysAsync(connection, keys, ct);
        await EnqueueProjectionIdsAsync(connection, mappings.Select(x => x.VulnerabilityId).Distinct().ToArray(), ct);
        return new DuckDbAffectedEvidenceSyncResult(rawIndexIds.Count, keys.Count, mappings.Select(x => x.VulnerabilityId).Distinct().Count(), 0);
    }

    public async Task<DuckDbAffectedEvidenceSyncResult> SyncEvidenceForRawIndexesAsync(IReadOnlyCollection<Guid> rawIndexIds, CancellationToken ct)
    {
        if (!store.Enabled || rawIndexIds.Count == 0)
            return new DuckDbAffectedEvidenceSyncResult(rawIndexIds.Count, 0, 0, 0);

        var keys = await store.QueryAffectedVulnerabilityKeysByRawIndexIdsAsync(rawIndexIds, ct);
        if (keys.Count == 0)
            return new DuckDbAffectedEvidenceSyncResult(rawIndexIds.Count, 0, 0, 0);

        await using var connection = await db.OpenConnectionAsync(ct);
        var mappings = await ResolveVulnerabilityKeysAsync(connection, keys, ct);
        if (mappings.Count == 0)
            return new DuckDbAffectedEvidenceSyncResult(rawIndexIds.Count, keys.Count, 0, 0);

        var rows = await store.ReplaceAffectedComponentsFromEvidenceAsync(mappings, ct);
        await UpdateVulnerabilitySummariesAsync(connection, mappings.Select(x => x.VulnerabilityId).Distinct().ToArray(), ct);
        return new DuckDbAffectedEvidenceSyncResult(rawIndexIds.Count, keys.Count, mappings.Select(x => x.VulnerabilityId).Distinct().Count(), rows.Count);
    }

    public async Task<DuckDbAffectedEvidenceRebuildResult> RebuildFromDuckDbEvidenceAsync(CancellationToken ct)
    {
        if (!store.Enabled)
            return new DuckDbAffectedEvidenceRebuildResult(0, 0, 0, 0, 0);

        var startedAt = DateTimeOffset.UtcNow;
        var keys = await store.QueryAllAffectedVulnerabilityKeysAsync(ct);
        var mappings = new List<DuckDbVulnerabilityKeyMapping>();
        await using var connection = await db.OpenConnectionAsync(ct);
        // Keep the PostgreSQL lookup set small enough to stay entirely index-driven.
        // The DuckDB scan is the bulk operation; PG only maps stable identifiers to IDs.
        foreach (var batch in keys.Chunk(1000))
            mappings.AddRange(await ResolveVulnerabilityKeysAsync(connection, batch, ct));

        var affectedComponents = await store.RebuildAffectedComponentsFromEvidenceAsync(mappings, ct);
        await UpdateAllVulnerabilitySummariesAsync(
            connection,
            mappings.Select(x => x.VulnerabilityId).Distinct().ToArray(),
            ct);
        var elapsed = Math.Max(0.001, (DateTimeOffset.UtcNow - startedAt).TotalSeconds);
        logger.LogInformation(
            "DuckDB-native affected component rebuild completed: keys={Keys}, mappings={Mappings}, vulnerabilities={Vulnerabilities}, components={Components}, elapsed_seconds={ElapsedSeconds:F1}.",
            keys.Count,
            mappings.Count,
            mappings.Select(x => x.VulnerabilityId).Distinct().Count(),
            affectedComponents,
            elapsed);
        return new DuckDbAffectedEvidenceRebuildResult(
            keys.Count,
            mappings.Count,
            mappings.Select(x => x.VulnerabilityId).Distinct().Count(),
            affectedComponents,
            elapsed);
    }

    public async Task<DuckDbAffectedComponentQueueResult> ProcessQueueAsync(DuckDbAffectedComponentQueueRequest request, CancellationToken ct)
    {
        if (!store.Enabled)
        {
            return new DuckDbAffectedComponentQueueResult(false, request.Limit, request.BatchSize, 0, 0, 0, 0, 0, 0);
        }

        var limit = Math.Clamp(request.Limit <= 0 ? 5000 : request.Limit, 1, 100000);
        var batchSize = Math.Clamp(request.BatchSize <= 0 ? 1000 : request.BatchSize, 1, Math.Min(5000, limit));
        var startedAt = DateTimeOffset.UtcNow;
        var processedRows = 0L;
        var processedVulnerabilities = 0L;

        await using var connection = await db.OpenConnectionAsync(ct);
        var ids = await DequeueProjectionIdsAsync(connection, limit, ct);
        if (ids.Count == 0)
        {
            return new DuckDbAffectedComponentQueueResult(true, limit, batchSize, 0, 0, 0, 0, 0, 0);
        }

        if (DuckDbEvidenceOnly)
            return await ProcessEvidenceQueueAsync(connection, ids, limit, batchSize, startedAt, ct);

        foreach (var batch in ids.Chunk(batchSize))
        {
            var rows = await ReadProjectionRowsForVulnerabilitiesAsync(connection, batch, ct);
            await store.ReplaceAffectedComponentsAsync(batch, rows, ct);
            await DeleteProjectionQueueRowsAsync(connection, batch, ct);
            processedRows += rows.Count;
            processedVulnerabilities += batch.Length;
            var elapsed = Math.Max(0.001, (DateTimeOffset.UtcNow - startedAt).TotalSeconds);
            logger.LogInformation(
                "DuckDB affected component queue batch: vulnerabilities={Vulnerabilities}, rows={Rows}, processed_vulnerabilities={ProcessedVulnerabilities}, rows_per_second={RowsPerSecond:F1}.",
                batch.Length,
                rows.Count,
                processedVulnerabilities,
                processedRows / elapsed);
        }

        var totalElapsed = Math.Max(0.001, (DateTimeOffset.UtcNow - startedAt).TotalSeconds);
        return new DuckDbAffectedComponentQueueResult(
            true,
            limit,
            batchSize,
            ids.Count,
            processedRows,
            processedVulnerabilities,
            processedRows,
            totalElapsed,
            processedRows / totalElapsed);
    }

    public async Task<DuckDbAffectedComponentRebuildResult> RebuildAsync(DuckDbAffectedComponentRebuildRequest request, CancellationToken ct)
    {
        if (!store.Enabled)
        {
            return new DuckDbAffectedComponentRebuildResult(false, request.Reset, request.BatchSize, request.Limit, 0, 0, 0, 0, 0);
        }

        var batchSize = Math.Clamp(request.BatchSize <= 0 ? 100000 : request.BatchSize, 1000, 250000);
        var limit = Math.Max(0, request.Limit);
        var startedAt = DateTimeOffset.UtcNow;
        var processed = 0L;
        Guid? afterId = null;

        if (request.Reset)
            await store.PrepareAffectedComponentsBulkLoadAsync(ct);

        logger.LogInformation("DuckDB affected component projection rebuild started: reset={Reset}, batch_size={BatchSize}, limit={Limit}.",
            request.Reset, batchSize, limit);
        try
        {
            await using var connection = await db.OpenConnectionAsync(ct);
            await CreateProjectionWorkTableAsync(connection, ct);
            while (!ct.IsCancellationRequested)
            {
                var remaining = limit == 0 ? batchSize : (int)Math.Min(batchSize, limit - processed);
                if (remaining <= 0) break;

                var rows = await ReadBatchAsync(connection, afterId, remaining, ct);
                if (rows.Count == 0) break;

                if (request.Reset)
                    await store.AppendAffectedComponentsBulkAsync(rows, ct);
                else
                    await store.AppendAffectedComponentsAsync(rows, ct);
                processed += rows.Count;
                afterId = rows[^1].Id;
                var batchElapsed = Math.Max(0.001, (DateTimeOffset.UtcNow - startedAt).TotalSeconds);
                logger.LogInformation("DuckDB affected component projection batch: batch={Batch}, processed={Processed}, rows_per_second={RowsPerSecond:F1}.",
                    rows.Count, processed, processed / batchElapsed);
            }
        }
        finally
        {
            if (request.Reset)
                await store.FinalizeAffectedComponentsBulkLoadAsync(CancellationToken.None);
        }

        var stats = await store.StatsAsync(ct);
        var pgCount = processed;
        var elapsed = Math.Max(0.001, (DateTimeOffset.UtcNow - startedAt).TotalSeconds);
        logger.LogInformation("DuckDB affected component projection rebuild finished: processed={Processed}, pg={PgCount}, duckdb={DuckCount}, elapsed_seconds={ElapsedSeconds:F1}, rows_per_second={RowsPerSecond:F1}.",
            processed, pgCount, stats.affectedComponents, elapsed, processed / elapsed);
        return new DuckDbAffectedComponentRebuildResult(
            true,
            request.Reset,
            batchSize,
            limit,
            processed,
            pgCount,
            stats.affectedComponents,
            elapsed,
            processed / elapsed);
    }

    private static async Task<IReadOnlyList<Guid>> DequeueProjectionIdsAsync(NpgsqlConnection connection, int limit, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("""
            select vulnerability_id
            from duckdb_affected_component_queue
            order by queued_at, vulnerability_id
            limit $1
            """, connection);
        cmd.Parameters.AddWithValue(limit);
        var ids = new List<Guid>(limit);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            ids.Add(reader.GetGuid(0));
        return ids;
    }

    private async Task<DuckDbAffectedComponentQueueResult> ProcessEvidenceQueueAsync(
        NpgsqlConnection connection,
        IReadOnlyList<Guid> ids,
        int limit,
        int batchSize,
        DateTimeOffset startedAt,
        CancellationToken ct)
    {
        var processedRows = 0L;
        var processedVulnerabilities = 0L;
        foreach (var batch in ids.Chunk(batchSize))
        {
            var mappings = await ResolveVulnerabilityIdsToEvidenceKeysAsync(connection, batch, ct);
            var rows = await store.ReplaceAffectedComponentsFromEvidenceAsync(mappings, ct);
            await UpdateVulnerabilitySummariesAsync(connection, batch, ct);
            await DeleteProjectionQueueRowsAsync(connection, batch, ct);
            processedRows += rows.Count;
            processedVulnerabilities += batch.Length;
        }

        var elapsed = Math.Max(0.001, (DateTimeOffset.UtcNow - startedAt).TotalSeconds);
        return new DuckDbAffectedComponentQueueResult(
            true,
            limit,
            batchSize,
            ids.Count,
            processedRows,
            processedVulnerabilities,
            processedRows,
            elapsed,
            processedRows / elapsed);
    }

    private static async Task EnqueueProjectionIdsAsync(NpgsqlConnection connection, IReadOnlyCollection<Guid> vulnerabilityIds, CancellationToken ct)
    {
        if (vulnerabilityIds.Count == 0) return;
        await using var command = new NpgsqlCommand("""
            insert into duckdb_affected_component_queue(vulnerability_id, queued_at)
            select distinct id, now()
            from unnest($1::uuid[]) as ids(id)
            on conflict (vulnerability_id) do update set queued_at = excluded.queued_at
            """, connection);
        command.Parameters.AddWithValue(vulnerabilityIds.ToArray());
        await command.ExecuteNonQueryAsync(ct);
    }

    private static async Task<IReadOnlyList<DuckDbVulnerabilityKeyMapping>> ResolveVulnerabilityIdsToEvidenceKeysAsync(
        NpgsqlConnection connection,
        IReadOnlyCollection<Guid> vulnerabilityIds,
        CancellationToken ct)
    {
        if (vulnerabilityIds.Count == 0) return Array.Empty<DuckDbVulnerabilityKeyMapping>();
        await using var command = new NpgsqlCommand("""
            select distinct canonical_vulnerability_id, normalized_value
            from vulnerability_identifier_index
            where canonical_vulnerability_id = any($1)
              and normalized_value is not null
              and normalized_value <> ''
            union
            select id, upper(primary_identifier)
            from vulnerabilities
            where id = any($1)
            """, connection);
        command.Parameters.AddWithValue(vulnerabilityIds.ToArray());
        var mappings = new List<DuckDbVulnerabilityKeyMapping>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            mappings.Add(new DuckDbVulnerabilityKeyMapping(reader.GetGuid(0), reader.GetString(1)));
        return mappings;
    }

    private static async Task<IReadOnlyList<DuckDbVulnerabilityKeyMapping>> ResolveVulnerabilityKeysAsync(
        NpgsqlConnection connection,
        IReadOnlyCollection<string> vulnerabilityKeys,
        CancellationToken ct)
    {
        var keys = vulnerabilityKeys
            .Select(Identifier.Normalize)
            .Where(key => !string.IsNullOrWhiteSpace(key))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (keys.Length == 0) return Array.Empty<DuckDbVulnerabilityKeyMapping>();

        await using var command = new NpgsqlCommand("""
            with requested as (
              select distinct upper(keys.vulnerability_key) as vulnerability_key
              from unnest($1::text[]) as keys(vulnerability_key)
            ),
            candidates as (
              select requested.vulnerability_key,
                     identifier.canonical_vulnerability_id as vulnerability_id,
                     identifier.confidence,
                     0 as source_rank
              from requested
              join vulnerability_identifier_index identifier
                on identifier.normalized_value = requested.vulnerability_key
              where identifier.canonical_vulnerability_id is not null
              union all
              select requested.vulnerability_key,
                     vulnerability.id as vulnerability_id,
                     null::numeric as confidence,
                     1 as source_rank
              from requested
              join vulnerabilities vulnerability
                on vulnerability.primary_identifier = requested.vulnerability_key
            )
            select distinct on (vulnerability_key) vulnerability_id, vulnerability_key
            from candidates
            order by vulnerability_key, source_rank, confidence desc nulls last
            """, connection);
        command.CommandTimeout = 120;
        command.Parameters.AddWithValue(keys);
        var mappings = new List<DuckDbVulnerabilityKeyMapping>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            mappings.Add(new DuckDbVulnerabilityKeyMapping(reader.GetGuid(0), reader.GetString(1)));
        return mappings;
    }

    private async Task UpdateVulnerabilitySummariesAsync(NpgsqlConnection connection, IReadOnlyCollection<Guid> vulnerabilityIds, CancellationToken ct)
    {
        if (vulnerabilityIds.Count == 0) return;
        var summaries = await store.QueryAffectedComponentSummariesAsync(vulnerabilityIds, ct);
        var summaryIds = summaries.Select(summary => summary.VulnerabilityId).ToHashSet();
        await ResetVulnerabilitySummariesAsync(connection, vulnerabilityIds.Where(id => !summaryIds.Contains(id)).ToArray(), ct);
        await UpdateSummaryRowsAsync(connection, summaries, ct);
    }

    private async Task UpdateAllVulnerabilitySummariesAsync(
        NpgsqlConnection connection,
        IReadOnlyCollection<Guid> vulnerabilityIds,
        CancellationToken ct)
    {
        var summaryIds = new HashSet<Guid>();
        await store.StreamAffectedComponentSummaryBatchesAsync(1000, async summaries =>
        {
            foreach (var summary in summaries)
                summaryIds.Add(summary.VulnerabilityId);
            await UpdateSummaryRowsAsync(connection, summaries, ct);
        }, ct);

        foreach (var batch in vulnerabilityIds.Where(id => !summaryIds.Contains(id)).Chunk(1000))
            await ResetVulnerabilitySummariesAsync(connection, batch, ct);
    }

    private static async Task ResetVulnerabilitySummariesAsync(
        NpgsqlConnection connection,
        IReadOnlyCollection<Guid> vulnerabilityIds,
        CancellationToken ct)
    {
        if (vulnerabilityIds.Count == 0) return;
        await using var reset = new NpgsqlCommand("""
            update vulnerabilities
            set affected_component_count = 0,
                affected_ecosystems = '{}',
                affected_component_names = '{}',
                search_text = to_tsvector('simple',
                    coalesce(primary_identifier,'') || ' ' ||
                    coalesce(title,'') || ' ' ||
                    coalesce(description,'')),
                updated_at = now()
            where id = any($1)
              and (
                affected_component_count <> 0
                or affected_ecosystems <> '{}'
                or affected_component_names <> '{}'
              )
            """, connection);
        reset.Parameters.AddWithValue(vulnerabilityIds.ToArray());
        await reset.ExecuteNonQueryAsync(ct);
    }

    private static async Task UpdateSummaryRowsAsync(
        NpgsqlConnection connection,
        IReadOnlyCollection<DuckDbAffectedComponentSummary> summaries,
        CancellationToken ct)
    {
        foreach (var batch in summaries.Chunk(500))
        {
            var values = new List<string>();
            var parameters = new List<object>();
            var index = 1;
            foreach (var summary in batch)
            {
                values.Add($"(${index++},${index++},${index++},${index++})");
                parameters.Add(summary.VulnerabilityId);
                parameters.Add(summary.Count);
                parameters.Add(summary.Ecosystems);
                parameters.Add(summary.Names);
            }

            await using var update = new NpgsqlCommand($"""
                update vulnerabilities v
                set affected_component_count = incoming.component_count,
                    affected_ecosystems = incoming.ecosystems,
                    affected_component_names = incoming.names,
                    search_text = to_tsvector('simple',
                        coalesce(v.primary_identifier,'') || ' ' ||
                        coalesce(v.title,'') || ' ' ||
                        coalesce(v.description,'') || ' ' ||
                        coalesce(replace(array_to_string(incoming.names, ' '), '/', ''))),
                    updated_at = now()
                from (values {string.Join(",", values)}) as incoming(id, component_count, ecosystems, names)
                where v.id = incoming.id
                  and (
                    v.affected_component_count is distinct from incoming.component_count
                    or v.affected_ecosystems is distinct from incoming.ecosystems
                    or v.affected_component_names is distinct from incoming.names
                  )
                """, connection);
            foreach (var parameter in parameters) update.Parameters.AddWithValue(parameter);
            await update.ExecuteNonQueryAsync(ct);
        }
    }

    private static async Task DeleteProjectionQueueRowsAsync(NpgsqlConnection connection, IReadOnlyCollection<Guid> vulnerabilityIds, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("""
            delete from duckdb_affected_component_queue
            where vulnerability_id = any($1)
            """, connection);
        cmd.Parameters.AddWithValue(vulnerabilityIds.ToArray());
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static async Task<IReadOnlyList<DuckDbAffectedComponentProjection>> ReadProjectionRowsForVulnerabilitiesAsync(
        NpgsqlConnection connection,
        IReadOnlyCollection<Guid> vulnerabilityIds,
        CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("""
            with projected as (
              select vulnerability_id, component_id, ecosystem, package_name,
                     coalesce(nullif(package_name, ''), nullif(purl, ''), nullif(cpe23_uri, '')) as display_name,
                     purl as primary_purl,
                     cpe23_uri as primary_cpe23_uri,
                     version_range_raw as normalized_range,
                     range_type,
                     source_confidence
              from vulnerability_affected_facts
              where vulnerability_id = any($1)
                and coalesce(vulnerable, true)
                and coalesce(nullif(package_name, ''), nullif(purl, ''), nullif(cpe23_uri, '')) is not null
            ),
            grouped as (
              select vulnerability_id, component_id, ecosystem, package_name, display_name,
                     primary_purl, primary_cpe23_uri, normalized_range, range_type,
                     max(source_confidence) as confidence, count(*)::integer as evidence_count
              from projected
              group by vulnerability_id, component_id, ecosystem, package_name, display_name,
                       primary_purl, primary_cpe23_uri, normalized_range, range_type
            ),
            keyed as (
              select md5(concat_ws('|', vulnerability_id::text, coalesce(component_id::text,''), coalesce(ecosystem,''), coalesce(package_name,''), display_name, coalesce(primary_purl,''), coalesce(primary_cpe23_uri,''), coalesce(normalized_range,''), coalesce(range_type,''))) as hash,
                     *
              from grouped
            )
            select (substr(hash,1,8) || '-' || substr(hash,9,4) || '-' || substr(hash,13,4) || '-' || substr(hash,17,4) || '-' || substr(hash,21,12))::uuid as id,
                   vulnerability_id, component_id, ecosystem, package_name, display_name,
                   primary_purl, primary_cpe23_uri, normalized_range, range_type,
                   confidence, evidence_count, 'candidate'::text as resolution_status
            from keyed
            order by vulnerability_id, ecosystem nulls last, display_name, id
            """, connection);
        cmd.CommandTimeout = 300;
        cmd.Parameters.AddWithValue(vulnerabilityIds.ToArray());
        return await ReadProjectionRowsAsync(cmd, Math.Max(100, vulnerabilityIds.Count * 8), ct);
    }

    private static async Task<IReadOnlyList<DuckDbAffectedComponentProjection>> ReadBatchAsync(
        NpgsqlConnection connection,
        Guid? afterId,
        int limit,
        CancellationToken ct)
    {
        await using var cmd = afterId is null
            ? new NpgsqlCommand("""
                select id, vulnerability_id, component_id, ecosystem, package_name, display_name,
                       primary_purl, primary_cpe23_uri, normalized_range, range_type,
                       confidence, evidence_count, resolution_status
                from temp_duck_affected_component_projection
                order by id
                limit $1
                """, connection)
            : new NpgsqlCommand("""
                select id, vulnerability_id, component_id, ecosystem, package_name, display_name,
                       primary_purl, primary_cpe23_uri, normalized_range, range_type, confidence, evidence_count, 'candidate' as resolution_status
                from temp_duck_affected_component_projection
                where id > $1
                order by id
                limit $2
                """, connection);
        cmd.CommandTimeout = 300;
        if (afterId is null)
        {
            cmd.Parameters.AddWithValue(limit);
        }
        else
        {
            cmd.Parameters.AddWithValue(afterId.Value);
            cmd.Parameters.AddWithValue(limit);
        }

        return await ReadProjectionRowsAsync(cmd, limit, ct);
    }

    private static async Task<IReadOnlyList<DuckDbAffectedComponentProjection>> ReadProjectionRowsAsync(
        NpgsqlCommand cmd,
        int capacity,
        CancellationToken ct)
    {
        var rows = new List<DuckDbAffectedComponentProjection>(capacity);
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

        return rows;
    }

    private static async Task CreateProjectionWorkTableAsync(NpgsqlConnection connection, CancellationToken ct)
    {
        await using (var settings = new NpgsqlCommand("set work_mem = '512MB'", connection))
        {
            await settings.ExecuteNonQueryAsync(ct);
        }

        await using (var drop = new NpgsqlCommand("drop table if exists temp_duck_affected_component_projection", connection))
        {
            await drop.ExecuteNonQueryAsync(ct);
        }

        await using (var create = new NpgsqlCommand("""
            create temporary table temp_duck_affected_component_projection on commit preserve rows as
            with projected as (
              select vulnerability_id, component_id, ecosystem, package_name,
                     coalesce(nullif(package_name, ''), nullif(purl, ''), nullif(cpe23_uri, '')) as display_name,
                     purl as primary_purl,
                     cpe23_uri as primary_cpe23_uri,
                     version_range_raw as normalized_range,
                     range_type,
                     source_confidence
              from vulnerability_affected_facts
              where coalesce(vulnerable, true)
                and coalesce(nullif(package_name, ''), nullif(purl, ''), nullif(cpe23_uri, '')) is not null
            ),
            grouped as (
              select vulnerability_id, component_id, ecosystem, package_name, display_name,
                     primary_purl, primary_cpe23_uri, normalized_range, range_type,
                     max(source_confidence) as confidence, count(*)::integer as evidence_count
              from projected
              group by vulnerability_id, component_id, ecosystem, package_name, display_name,
                       primary_purl, primary_cpe23_uri, normalized_range, range_type
            ),
            keyed as (
              select md5(concat_ws('|', vulnerability_id::text, coalesce(component_id::text,''), coalesce(ecosystem,''), coalesce(package_name,''), display_name, coalesce(primary_purl,''), coalesce(primary_cpe23_uri,''), coalesce(normalized_range,''), coalesce(range_type,''))) as hash,
                     *
              from grouped
            )
            select (substr(hash,1,8) || '-' || substr(hash,9,4) || '-' || substr(hash,13,4) || '-' || substr(hash,17,4) || '-' || substr(hash,21,12))::uuid as id,
                   vulnerability_id, component_id, ecosystem, package_name, display_name,
                   primary_purl, primary_cpe23_uri, normalized_range, range_type,
                   confidence, evidence_count, 'candidate'::text as resolution_status
            from keyed
            """, connection))
        {
            create.CommandTimeout = 0;
            await create.ExecuteNonQueryAsync(ct);
        }

        await using (var index = new NpgsqlCommand("create index on temp_duck_affected_component_projection(id)", connection))
        {
            index.CommandTimeout = 0;
            await index.ExecuteNonQueryAsync(ct);
        }
    }

}
