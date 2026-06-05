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
        var pgCount = await CountPgAffectedComponentsAsync(ct);
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
                from vulnerability_affected_components
                order by id
                limit $1
                """, connection)
            : new NpgsqlCommand("""
                select id, vulnerability_id, component_id, ecosystem, package_name, display_name,
                       primary_purl, primary_cpe23_uri, normalized_range, range_type,
                       confidence, evidence_count, resolution_status
                from vulnerability_affected_components
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

        var rows = new List<DuckDbAffectedComponentProjection>(limit);
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

    private async Task<long> CountPgAffectedComponentsAsync(CancellationToken ct)
    {
        await using var cmd = db.CreateCommand("select count(*)::bigint from vulnerability_affected_components");
        return Convert.ToInt64(await cmd.ExecuteScalarAsync(ct));
    }
}
