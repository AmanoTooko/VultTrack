using Npgsql;

namespace VulTrack.App;

public sealed class RawNormalizationService(
    NpgsqlDataSource db,
    IEnumerable<IRawNormalizer> normalizers,
    ILogger<RawNormalizationService> logger) : IRawNormalizationService
{
    public async Task<IReadOnlyList<NormalizeBatchResult>> ProcessPendingAsync(int limitPerSource, CancellationToken ct)
    {
        var results = new List<NormalizeBatchResult>();
        await using var connection = await db.OpenConnectionAsync(ct);
        var enabledSources = await LoadEnabledAutomaticSourceCodesAsync(connection, ct);

        foreach (var normalizer in normalizers)
        {
            if (normalizer is ISourceScopedRawNormalizer scoped)
            {
                foreach (var sourceCode in scoped.SupportedSourceCodes.Where(enabledSources.Contains).Order(StringComparer.OrdinalIgnoreCase))
                {
                    results.Add(await ProcessOneSourceAsync(connection, scoped, sourceCode, limitPerSource, ct));
                }

                continue;
            }

            if (enabledSources.Contains(normalizer.SourceCode))
            {
                results.Add(await ProcessOneSourceAsync(connection, normalizer, normalizer.SourceCode, limitPerSource, ct));
            }
        }

        return results;
    }

    public async Task<NormalizeBatchResult> ProcessSourcePendingAsync(string sourceCode, int limit, CancellationToken ct)
    {
        await using var connection = await db.OpenConnectionAsync(ct);
        if (!await TryAcquireSourceNormalizeLockAsync(connection, sourceCode, ct))
        {
            logger.LogInformation("Normalizer {SourceCode} is already running; skipping overlapping request.", sourceCode);
            return new NormalizeBatchResult(sourceCode, 0, 0);
        }

        try
        {
            await SupersedeOlderPendingRawAsync(connection, sourceCode, ct);

            var scoped = normalizers.OfType<ISourceScopedRawNormalizer>()
                .FirstOrDefault(x => x.SupportedSourceCodes.Any(code => string.Equals(code, sourceCode, StringComparison.OrdinalIgnoreCase)));
            if (scoped is not null)
            {
                return await scoped.ProcessSourcePendingAsync(connection, sourceCode, limit, ct);
            }

            var normalizer = normalizers.FirstOrDefault(x => string.Equals(x.SourceCode, sourceCode, StringComparison.OrdinalIgnoreCase));
            if (normalizer is null)
            {
                return new NormalizeBatchResult(sourceCode, 0, 0);
            }

            try
            {
                var result = await normalizer.ProcessPendingAsync(connection, limit, ct);
                return result.SourceCode.Equals(sourceCode, StringComparison.OrdinalIgnoreCase)
                    ? result
                    : new NormalizeBatchResult(sourceCode, result.Processed, result.Failed);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Normalizer {SourceCode} failed for source-scoped request", sourceCode);
                return new NormalizeBatchResult(sourceCode, 0, 1);
            }
        }
        finally
        {
            await ReleaseSourceNormalizeLockAsync(connection, sourceCode, CancellationToken.None);
        }
    }

    private static async Task<bool> TryAcquireSourceNormalizeLockAsync(NpgsqlConnection connection, string sourceCode, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("select pg_try_advisory_lock(hashtext($1), 0)", connection);
        cmd.Parameters.AddWithValue($"normalize:{sourceCode.ToLowerInvariant()}");
        return (bool)(await cmd.ExecuteScalarAsync(ct) ?? false);
    }

    private static async Task ReleaseSourceNormalizeLockAsync(NpgsqlConnection connection, string sourceCode, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("select pg_advisory_unlock(hashtext($1), 0)", connection);
        cmd.Parameters.AddWithValue($"normalize:{sourceCode.ToLowerInvariant()}");
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private async Task<NormalizeBatchResult> ProcessOneSourceAsync(NpgsqlConnection connection, IRawNormalizer normalizer, string sourceCode, int limit, CancellationToken ct)
    {
        if (!await TryAcquireSourceNormalizeLockAsync(connection, sourceCode, ct))
        {
            logger.LogInformation("Normalizer {SourceCode} is already running; skipping overlapping batch request.", sourceCode);
            return new NormalizeBatchResult(sourceCode, 0, 0);
        }

        try
        {
            await SupersedeOlderPendingRawAsync(connection, sourceCode, ct);

            try
            {
                if (normalizer is ISourceScopedRawNormalizer scoped)
                {
                    return await scoped.ProcessSourcePendingAsync(connection, sourceCode, limit, ct);
                }

                var result = await normalizer.ProcessPendingAsync(connection, limit, ct);
                return result.SourceCode.Equals(sourceCode, StringComparison.OrdinalIgnoreCase)
                    ? result
                    : new NormalizeBatchResult(sourceCode, result.Processed, result.Failed);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Normalizer {SourceCode} failed", sourceCode);
                return new NormalizeBatchResult(sourceCode, 0, 1);
            }
        }
        finally
        {
            await ReleaseSourceNormalizeLockAsync(connection, sourceCode, CancellationToken.None);
        }
    }

    private static async Task<HashSet<string>> LoadEnabledAutomaticSourceCodesAsync(NpgsqlConnection connection, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("""
            select code
            from sources
            where enabled
              and coalesce(config_json->>'runMode', '') <> 'manual'
            """, connection);

        var codes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            codes.Add(reader.GetString(0));
        }

        return codes;
    }

    private async Task SupersedeOlderPendingRawAsync(NpgsqlConnection connection, string? sourceCode, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("""
            with ranked as (
              select r.id,
                     row_number() over (
                       partition by r.source_id, r.external_key
                       order by
                         case when r.status = 'priority' then 0 else 1 end,
                         r.source_modified_at desc nulls last,
                         r.updated_at desc,
                         r.created_at desc,
                         r.id desc
                     ) as rank
              from source_raw_index r
              join sources s on s.id = r.source_id
              where r.normalize_status in ('pending', 'failed')
                and ($1::text is null or s.code = $1)
            )
            update source_raw_index r
            set normalize_status = 'superseded',
                updated_at = now()
            from ranked
            where r.id = ranked.id
              and ranked.rank > 1
            """, connection);
        cmd.CommandTimeout = 300;
        cmd.Parameters.AddWithValue((object?)sourceCode ?? DBNull.Value);
        var superseded = await cmd.ExecuteNonQueryAsync(ct);
        if (superseded > 0)
        {
            logger.LogInformation("Marked {Count} older raw snapshots as superseded for {SourceCode}.", superseded, sourceCode ?? "all sources");
        }
    }
}
