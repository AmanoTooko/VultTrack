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

public sealed class DuckDbAffectedComponentProjector(
    NpgsqlDataSource db,
    DuckDbEvidenceStore store,
    ILogger<DuckDbAffectedComponentProjector> logger)
{
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
            var emptyStats = await store.StatsAsync(ct);
            return new DuckDbAffectedComponentQueueResult(true, limit, batchSize, 0, 0, 0, emptyStats.affectedComponents, 0, 0);
        }

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

        var stats = await store.StatsAsync(ct);
        var totalElapsed = Math.Max(0.001, (DateTimeOffset.UtcNow - startedAt).TotalSeconds);
        return new DuckDbAffectedComponentQueueResult(
            true,
            limit,
            batchSize,
            ids.Count,
            processedRows,
            processedVulnerabilities,
            stats.affectedComponents,
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
