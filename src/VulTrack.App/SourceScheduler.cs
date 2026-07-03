using System.Diagnostics;
using Microsoft.Extensions.Options;
using Npgsql;

namespace VulTrack.App;

public sealed class SourceScheduler(
    NpgsqlDataSource db,
    IRawNormalizationService normalizer,
    DuckDbAffectedComponentProjector affectedComponentProjector,
    VulnerabilityDetailSnapshotBuilder detailSnapshotBuilder,
    IOptions<VulTrackSchedulerOptions> options,
    ILogger<SourceScheduler> logger) : BackgroundService
{
    private VulTrackSchedulerOptions Options => options.Value;
    private DateTimeOffset _lastDuckDbAffectedQueueRun = DateTimeOffset.MinValue;
    private DateTimeOffset _lastDetailSnapshotQueueRun = DateTimeOffset.MinValue;
    private readonly SemaphoreSlim _duckDbAffectedQueueLock = new(1, 1);
    private readonly SemaphoreSlim _detailSnapshotQueueLock = new(1, 1);
    private readonly SemaphoreSlim _heavyWriteLock = new(1, 1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!EnvBool("VULTRACK_SCHEDULER_ENABLED", Options.Enabled))
        {
            logger.LogInformation("VulTrack scheduler is disabled.");
            return;
        }

        var normalizeInterval = TimeSpan.FromSeconds(EnvInt("SCHEDULER_INTERVAL_SECONDS", Options.NormalizeIntervalSeconds, 1));
        var fetchInterval = TimeSpan.FromHours(Math.Max(1, Options.FetchIntervalHours));

        await CloseInterruptedRunsAsync(stoppingToken);
        await Task.WhenAll(
            RunFetchLoopAsync(fetchInterval, stoppingToken),
            RunNormalizeLoopAsync(normalizeInterval, stoppingToken),
            RunDuckDbProjectionLoopAsync(stoppingToken),
            RunDetailSnapshotLoopAsync(stoppingToken));
    }

    private async Task CloseInterruptedRunsAsync(CancellationToken ct)
    {
        await using var cmd = db.CreateCommand("""
            update source_sync_runs
            set status = 'failed',
                finished_at = now(),
                error_count = greatest(error_count, 1),
                log_summary = coalesce(nullif(log_summary, ''), 'Interrupted before completion; scheduler restarted.')
            where status = 'running'
            """);
        var count = await cmd.ExecuteNonQueryAsync(ct);
        if (count > 0)
            logger.LogWarning("Closed {Count} interrupted source sync runs left by an earlier scheduler process.", count);
    }

    private async Task RunNormalizeLoopAsync(TimeSpan interval, CancellationToken ct)
    {
        var limit = EnvInt("SCHEDULER_NORMALIZE_LIMIT", Options.NormalizeLimit, 1);
        var parallelism = EnvInt("SCHEDULER_NORMALIZE_PARALLELISM", Options.NormalizeParallelism, 1);
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await DedupEpssPendingAsync(ct);
                var allSources = await LoadAllSourcesAsync(ct);
                await RunNormalizeSourcesAsync(allSources, limit, parallelism, "normalize cycle", ct);

            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Normalize cycle failed.");
            }
            await Task.Delay(interval, ct);
        }
    }

    private async Task RunDuckDbProjectionLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            await RunDuckDbAffectedComponentQueueAsync(ct);
            await Task.Delay(TimeSpan.FromSeconds(5), ct);
        }
    }

    private async Task RunDetailSnapshotLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            await RunDetailSnapshotQueueAsync(ct);
            await Task.Delay(TimeSpan.FromSeconds(5), ct);
        }
    }

    private async Task RunFetchLoopAsync(TimeSpan interval, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await CloseStaleScheduledRunsAsync(ct);
                var dueSources = await LoadDueSourcesAsync(ct);
                var parallelism = EnvInt("SCHEDULER_FETCH_PARALLELISM", Options.FetchParallelism, 1);
                await RunFetchSourcesAsync(dueSources, parallelism, "fetch cycle", ct);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Fetch cycle failed.");
            }
            await Task.Delay(interval, ct);
        }
    }

    public async Task RunDueSourcesAsync(CancellationToken ct)
    {
        await DedupEpssPendingAsync(ct);

        var limit = EnvInt("SCHEDULER_NORMALIZE_LIMIT", Options.NormalizeLimit, 1);
        var parallelism = EnvInt("SCHEDULER_NORMALIZE_PARALLELISM", Options.NormalizeParallelism, 1);
        var allSources = await LoadAllSourcesAsync(ct);
        await RunNormalizeSourcesAsync(allSources, limit, parallelism, "scheduled normalization", ct);

        await RunDuckDbAffectedComponentQueueAsync(ct);
        await RunDetailSnapshotQueueAsync(ct);

        await CloseStaleScheduledRunsAsync(ct);
        var dueSources = await LoadDueSourcesAsync(ct);
        var fetchParallelism = EnvInt("SCHEDULER_FETCH_PARALLELISM", Options.FetchParallelism, 1);
        await RunFetchSourcesAsync(dueSources, fetchParallelism, "manual due-source run", ct);
    }

    private async Task RunFetchSourcesAsync(IReadOnlyList<ScheduledSource> sources, int parallelism, string context, CancellationToken ct)
    {
        if (sources.Count == 0) return;

        var workerCount = Math.Clamp(parallelism, 1, Math.Min(8, sources.Count));
        logger.LogInformation("Running {Count} due fetchers with parallelism={Parallelism} for {Context}.", sources.Count, workerCount, context);
        var index = 0;
        async Task Worker()
        {
            while (!ct.IsCancellationRequested)
            {
                var current = Interlocked.Increment(ref index) - 1;
                if (current >= sources.Count) return;
                var source = sources[current];
                try
                {
                    await RunSourceAsync(source.Code, ct, trigger: "scheduled", fetchLimitOverride: source.FetchLimit);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "Fetcher {Source} failed; continuing {Context}.", source.Code, context);
                }
            }
        }

        await Task.WhenAll(Enumerable.Range(0, workerCount).Select(_ => Worker()));
    }

    private async Task RunNormalizeSourcesAsync(IReadOnlyList<ScheduledSource> sources, int limit, int parallelism, string context, CancellationToken ct)
    {
        if (sources.Count == 0) return;

        var workerCount = Math.Clamp(parallelism, 1, Math.Min(16, sources.Count));
        if (workerCount == 1)
        {
            foreach (var source in sources)
            {
                if (ct.IsCancellationRequested) break;
                await RunNormalizeSourceAsync(source.Code, limit, context, ct);
            }
            return;
        }

        logger.LogInformation("Running {Count} normalizer sources with parallelism={Parallelism} for {Context}.", sources.Count, workerCount, context);
        var index = 0;
        async Task Worker()
        {
            while (!ct.IsCancellationRequested)
            {
                var current = Interlocked.Increment(ref index) - 1;
                if (current >= sources.Count) return;
                await RunNormalizeSourceAsync(sources[current].Code, limit, context, ct);
            }
        }

        await Task.WhenAll(Enumerable.Range(0, workerCount).Select(_ => Worker()));
    }

    private async Task RunNormalizeSourceAsync(string sourceCode, int limit, string context, CancellationToken ct)
    {
        await _heavyWriteLock.WaitAsync(ct);
        try
        {
            try
            {
                var result = await normalizer.ProcessSourcePendingAsync(sourceCode, limit, ct);
                if (result.Processed > 0 || result.Failed > 0)
                {
                    logger.LogInformation("Normalizer {Source}: processed={Processed}, failed={Failed}",
                        result.SourceCode, result.Processed, result.Failed);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Normalizer {Source} failed; continuing {Context}.", sourceCode, context);
            }
        }
        finally
        {
            _heavyWriteLock.Release();
        }
    }

    private async Task RunDetailSnapshotQueueAsync(CancellationToken ct)
    {
        if (!EnvBool("SCHEDULER_DETAIL_SNAPSHOT_QUEUE_ENABLED", Options.DetailSnapshotQueueEnabled))
        {
            return;
        }

        var intervalSeconds = EnvInt("SCHEDULER_DETAIL_SNAPSHOT_QUEUE_INTERVAL_SECONDS", Options.DetailSnapshotQueueIntervalSeconds, 0);
        var now = DateTimeOffset.UtcNow;
        if (intervalSeconds > 0 && now - _lastDetailSnapshotQueueRun < TimeSpan.FromSeconds(intervalSeconds))
        {
            return;
        }

        if (!await _detailSnapshotQueueLock.WaitAsync(0, ct))
        {
            return;
        }

        var heavyLockAcquired = false;
        try
        {
            await _heavyWriteLock.WaitAsync(ct);
            heavyLockAcquired = true;
            _lastDetailSnapshotQueueRun = now;
            var request = new DetailSnapshotBuildRequest(
                Limit: EnvInt("SCHEDULER_DETAIL_SNAPSHOT_QUEUE_LIMIT", Options.DetailSnapshotQueueLimit, 1),
                ConsumeQueue: true,
                Concurrency: EnvInt("SCHEDULER_DETAIL_SNAPSHOT_QUEUE_CONCURRENCY", Options.DetailSnapshotQueueConcurrency, 1),
                GzipLevel: EnvInt("SCHEDULER_DETAIL_SNAPSHOT_GZIP_LEVEL", Options.DetailSnapshotGzipLevel, 1));
            var result = await detailSnapshotBuilder.RebuildAsync(request, ct);
            if (result.selected > 0 || result.failed > 0)
            {
                logger.LogInformation(
                    "Detail snapshot queue: selected={Selected}, written={Written}, removed={Removed}, failed={Failed}",
                    result.selected,
                    result.written,
                    result.removed,
                    result.failed);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Detail snapshot queue refresh failed; continuing scheduler cycle.");
        }
        finally
        {
            if (heavyLockAcquired) _heavyWriteLock.Release();
            _detailSnapshotQueueLock.Release();
        }
    }

    private async Task RunDuckDbAffectedComponentQueueAsync(CancellationToken ct)
    {
        if (!EnvBool("SCHEDULER_DUCKDB_AFFECTED_QUEUE_ENABLED", Options.DuckDbAffectedQueueEnabled))
        {
            return;
        }

        var intervalSeconds = EnvInt("SCHEDULER_DUCKDB_AFFECTED_QUEUE_INTERVAL_SECONDS", Options.DuckDbAffectedQueueIntervalSeconds, 0);
        var now = DateTimeOffset.UtcNow;
        if (intervalSeconds > 0 && now - _lastDuckDbAffectedQueueRun < TimeSpan.FromSeconds(intervalSeconds))
        {
            return;
        }

        if (!await _duckDbAffectedQueueLock.WaitAsync(0, ct))
        {
            return;
        }

        var heavyLockAcquired = false;
        try
        {
            await _heavyWriteLock.WaitAsync(ct);
            heavyLockAcquired = true;
            _lastDuckDbAffectedQueueRun = now;
            var request = new DuckDbAffectedComponentQueueRequest(
                Limit: EnvInt("SCHEDULER_DUCKDB_AFFECTED_QUEUE_LIMIT", Options.DuckDbAffectedQueueLimit, 1),
                BatchSize: EnvInt("SCHEDULER_DUCKDB_AFFECTED_QUEUE_BATCH_SIZE", Options.DuckDbAffectedQueueBatchSize, 1));
            var result = await affectedComponentProjector.ProcessQueueAsync(request, ct);
            if (result.selected > 0 || result.processedRows > 0)
            {
                logger.LogInformation(
                    "DuckDB affected component queue: selected={Selected}, processed_vulnerabilities={ProcessedVulnerabilities}, rows={Rows}, elapsed_seconds={ElapsedSeconds:F1}",
                    result.selected,
                    result.processedVulnerabilities,
                    result.processedRows,
                    result.elapsedSeconds);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "DuckDB affected component queue refresh failed; continuing scheduler cycle.");
        }
        finally
        {
            if (heavyLockAcquired) _heavyWriteLock.Release();
            _duckDbAffectedQueueLock.Release();
        }
    }

    public Task RunSourceNowAsync(string sourceCode, bool force, CancellationToken ct) =>
        RunSourceAsync(sourceCode, ct, force, "manual");

    private async Task<IReadOnlyList<ScheduledSource>> LoadAllSourcesAsync(CancellationToken ct)
    {
        var rows = new List<ScheduledSource>();
        await using var cmd = db.CreateCommand("""
            select s.code
            from sources s
            where s.enabled = true
            order by s.code
            """);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var code = reader.GetString(0);
            if (IsSourceAllowed(code))
                rows.Add(new ScheduledSource(code, "", null, null));
        }
        return rows;
    }

    private async Task<IReadOnlyList<ScheduledSource>> LoadDueSourcesAsync(CancellationToken ct)
    {
        var rows = new List<ScheduledSource>();
        await using var cmd = db.CreateCommand("""
            select s.code, s.schedule_cron, s.config_json->>'runMode' as run_mode,
                   max(r.finished_at) filter (where r.status = 'succeeded') as last_success,
                   s.checkpoint_json->>'initComplete' as init_complete,
                   s.config_json->>'fetchLimit' as fetch_limit,
                   bool_or(r.status = 'running' and r.started_at > now() - $2) as has_active_run
            from sources s
            left join source_sync_runs r on r.source_id = s.id
            where s.enabled = true
              and (
                s.schedule_cron is not null
                or ($1::boolean = true and s.config_json->>'runMode' = 'init')
              )
            group by s.id, s.code, s.schedule_cron, s.config_json->>'runMode', s.checkpoint_json->>'initComplete'
            order by
              case
                when s.config_json->>'runMode' = 'init' then 0
                when s.checkpoint_json->>'initComplete' = 'false' then 1
                else 2
              end,
              s.code
            """);
        cmd.Parameters.AddWithValue(EnvBool("SCHEDULER_INCLUDE_INIT_SOURCES", Options.IncludeInitSources));
        cmd.Parameters.AddWithValue(TimeSpan.FromSeconds(FetchTimeoutWithGraceSeconds()));
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var code = reader.GetString(0);
            if (!IsSourceAllowed(code))
            {
                continue;
            }

            var cron = reader.IsDBNull(1) ? null : reader.GetString(1);
            var runMode = reader.IsDBNull(2) ? null : reader.GetString(2);
            var lastSuccess = reader.IsDBNull(3) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(3);
            var initComplete = reader.IsDBNull(4) ? null : reader.GetString(4);
            var fetchLimit = reader.IsDBNull(5) ? null : reader.GetString(5);
            var hasActiveRun = !reader.IsDBNull(6) && reader.GetBoolean(6);
            if (hasActiveRun)
            {
                continue;
            }

            if (string.Equals(runMode, "init", StringComparison.OrdinalIgnoreCase) && cron is null)
            {
                if (lastSuccess is null || string.Equals(initComplete, "false", StringComparison.OrdinalIgnoreCase))
                    rows.Add(new ScheduledSource(code, "", lastSuccess, fetchLimit));
                continue;
            }

            if (cron is not null &&
                (string.Equals(initComplete, "false", StringComparison.OrdinalIgnoreCase) ||
                 IsDue(cron, lastSuccess, DateTimeOffset.UtcNow)))
            {
                rows.Add(new ScheduledSource(code, cron, lastSuccess, fetchLimit));
            }
        }

        return rows;
    }

    private bool IsSourceAllowed(string code)
    {
        var configured = Environment.GetEnvironmentVariable("SCHEDULER_SOURCE_CODES");
        if (string.IsNullOrWhiteSpace(configured))
        {
            return Options.SourceCodes.Length == 0 || Options.SourceCodes.Contains(code, StringComparer.OrdinalIgnoreCase);
        }

        return configured
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Contains(code, StringComparer.OrdinalIgnoreCase);
    }

    private async Task RunSourceAsync(string source, CancellationToken ct, bool force = false, string trigger = "scheduled", string? fetchLimitOverride = null)
    {
        var repoRoot = ResolveRepoRoot();
        var node = Environment.GetEnvironmentVariable("PLUGIN_NODE_BIN") ?? Options.PluginNodeBin;
        var timeout = TimeSpan.FromSeconds(EnvInt("SCHEDULER_FETCH_TIMEOUT_SECONDS", Options.FetchTimeoutSeconds, 30));
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeout);
        var psi = new ProcessStartInfo(node)
        {
            WorkingDirectory = repoRoot,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        psi.ArgumentList.Add("plugins/fetchers/run-fetcher.mjs");
        psi.ArgumentList.Add("--source");
        psi.ArgumentList.Add(source);
        psi.Environment["DATABASE_URL"] = ToPluginDatabaseUrl(Environment.GetEnvironmentVariable("DATABASE_URL") ?? "");
        psi.Environment["FETCHER_TIMEOUT_MS"] = ((int)timeout.TotalMilliseconds).ToString(System.Globalization.CultureInfo.InvariantCulture);
        var fetchLimit = FirstNonBlank(
            Environment.GetEnvironmentVariable("SCHEDULER_FETCH_LIMIT"),
            fetchLimitOverride,
            Options.FetchLimit);
        if (!string.IsNullOrWhiteSpace(fetchLimit))
        {
            psi.Environment["FETCHER_MAX_RECORDS"] = fetchLimit;
        }
        if (force)
        {
            psi.Environment["FETCHER_FORCE"] = "1";
        }
        psi.Environment["FETCHER_TRIGGER"] = trigger;

        logger.LogInformation("Starting fetcher {Source}", source);
        using var process = Process.Start(psi);
        if (process is null) throw new InvalidOperationException($"Failed to start fetcher process for {source}.");

        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        try
        {
            await process.WaitForExitAsync(timeoutCts.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            TryKill(process);
            await process.WaitForExitAsync(CancellationToken.None);
            var timeoutStderr = await stderrTask;
            await CloseRunsForSourceAsync(source, trigger, $"Fetcher {source} timed out after {timeout.TotalSeconds:n0}s. {Truncate(timeoutStderr, 1000)}", CancellationToken.None);
            throw new TimeoutException($"Fetcher {source} timed out after {timeout.TotalSeconds:n0}s. {timeoutStderr}");
        }

        var stdout = await stdoutTask;
        var stderr = await stderrTask;

        if (process.ExitCode != 0)
        {
            await CloseRunsForSourceAsync(source, trigger, $"Fetcher {source} failed with exit code {process.ExitCode}. {Truncate(stderr, 1000)}", ct);
            throw new InvalidOperationException($"Fetcher {source} failed: {stderr}");
        }

        logger.LogInformation("Fetcher {Source} completed: {Output}", source, stdout);
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
            // Best effort: the scheduler logs the timeout and continues with the next cycle.
        }
    }

    private async Task CloseStaleScheduledRunsAsync(CancellationToken ct)
    {
        await using var cmd = db.CreateCommand("""
            update source_sync_runs
            set status = 'failed',
                finished_at = now(),
                error_count = greatest(error_count, 1),
                log_summary = coalesce(nullif(log_summary, ''), 'Scheduled fetcher exceeded timeout without completing.')
            where status = 'running'
              and trigger = 'scheduled'
              and started_at < now() - $1
            """);
        cmd.Parameters.AddWithValue(TimeSpan.FromSeconds(FetchTimeoutWithGraceSeconds()));
        var count = await cmd.ExecuteNonQueryAsync(ct);
        if (count > 0)
        {
            logger.LogWarning("Closed {Count} stale scheduled source sync runs.", count);
        }
    }

    private async Task CloseRunsForSourceAsync(string sourceCode, string trigger, string message, CancellationToken ct)
    {
        await using var cmd = db.CreateCommand("""
            update source_sync_runs r
            set status = 'failed',
                finished_at = now(),
                error_count = greatest(r.error_count, 1),
                log_summary = left($2, 4000)
            from sources s
            where s.id = r.source_id
              and s.code = $1
              and r.status = 'running'
              and r.trigger = $3
            """);
        cmd.Parameters.AddWithValue(sourceCode);
        cmd.Parameters.AddWithValue(message);
        cmd.Parameters.AddWithValue(trigger);
        var count = await cmd.ExecuteNonQueryAsync(ct);
        if (count > 0)
        {
            logger.LogWarning("Closed {Count} failed scheduled source sync runs for {Source}.", count, sourceCode);
        }
    }

    private int FetchTimeoutWithGraceSeconds()
    {
        var timeout = EnvInt("SCHEDULER_FETCH_TIMEOUT_SECONDS", Options.FetchTimeoutSeconds, 30);
        return Math.Max(60, timeout + 60);
    }

    private static string Truncate(string value, int maxLength) =>
        value.Length <= maxLength ? value : value[..maxLength];

    private static string? FirstNonBlank(params string?[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));

    private static bool IsDue(string cron, DateTimeOffset? lastSuccess, DateTimeOffset now)
    {
        if (lastSuccess is null) return true;
        var minimumInterval = CronMinimumInterval(cron);
        return now - lastSuccess.Value >= minimumInterval;
    }

    private static TimeSpan CronMinimumInterval(string cron)
    {
        var parts = cron.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) return TimeSpan.FromHours(1);
        var hour = parts[1];
        if (hour.StartsWith("*/", StringComparison.Ordinal) && int.TryParse(hour[2..], out var everyHours))
        {
            return TimeSpan.FromHours(Math.Max(1, everyHours));
        }

        return TimeSpan.FromDays(1);
    }

    private static string ResolveRepoRoot()
    {
        if (Environment.GetEnvironmentVariable("VULTRACK_REPO_ROOT") is { Length: > 0 } configured)
        {
            return configured;
        }

        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "package.json")) &&
                Directory.Exists(Path.Combine(current.FullName, "plugins", "fetchers")))
            {
                return current.FullName;
            }
            current = current.Parent;
        }

        return Directory.GetCurrentDirectory();
    }

    private static string ToPluginDatabaseUrl(string value)
    {
        if (value.StartsWith("postgres://", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("postgresql://", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(value))
        {
            return value;
        }

        var parts = value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(part => part.Split('=', 2, StringSplitOptions.TrimEntries))
            .Where(part => part.Length == 2)
            .ToDictionary(part => part[0], part => part[1], StringComparer.OrdinalIgnoreCase);

        var host = GetPart(parts, "Host", "Server") ?? "localhost";
        var port = GetPart(parts, "Port") ?? "5432";
        var database = GetPart(parts, "Database", "Db") ?? "vultrack";
        var username = GetPart(parts, "Username", "User ID", "UserId", "User") ?? "vultrack";
        var password = GetPart(parts, "Password") ?? "";

        return $"postgres://{Uri.EscapeDataString(username)}:{Uri.EscapeDataString(password)}@{host}:{port}/{Uri.EscapeDataString(database)}";
    }

    private static string? GetPart(IReadOnlyDictionary<string, string> parts, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (parts.TryGetValue(key, out var value))
            {
                return value;
            }
        }

        return null;
    }

    private async Task DedupEpssPendingAsync(CancellationToken ct)
    {
        try
        {
            await using var cmd = db.CreateCommand("SELECT dedup_epss_pending()");
            await cmd.ExecuteNonQueryAsync(ct);
        }
        catch
        {
            // Function might not exist yet - ignore
        }
    }

    private sealed record ScheduledSource(string Code, string Cron, DateTimeOffset? LastSuccess, string? FetchLimit);

    private static int EnvInt(string name, int fallback, int min)
    {
        return int.TryParse(Environment.GetEnvironmentVariable(name), out var parsed)
            ? Math.Max(min, parsed)
            : Math.Max(min, fallback);
    }

    private static bool EnvBool(string name, bool fallback)
    {
        var value = Environment.GetEnvironmentVariable(name);
        return string.IsNullOrWhiteSpace(value)
            ? fallback
            : string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) || value == "1";
    }
}

public sealed class VulTrackSchedulerOptions
{
    public bool Enabled { get; init; }
    public int NormalizeIntervalSeconds { get; init; } = 15;
    public int FetchIntervalHours { get; init; } = 12;
    public int NormalizeLimit { get; init; } = 500;
    public int FetchTimeoutSeconds { get; init; } = 600;
    public int FetchParallelism { get; init; } = 2;
    public string? FetchLimit { get; init; }
    public string PluginNodeBin { get; init; } = "node";
    public string[] SourceCodes { get; init; } = [];
    public bool IncludeInitSources { get; init; }
    public int NormalizeParallelism { get; init; } = 1;
    public bool DetailSnapshotQueueEnabled { get; init; } = true;
    public int DetailSnapshotQueueIntervalSeconds { get; init; } = 300;
    public int DetailSnapshotQueueLimit { get; init; } = 500;
    public int DetailSnapshotQueueConcurrency { get; init; } = 4;
    public int DetailSnapshotGzipLevel { get; init; } = 6;
    public bool DuckDbAffectedQueueEnabled { get; init; } = true;
    public int DuckDbAffectedQueueIntervalSeconds { get; init; } = 60;
    public int DuckDbAffectedQueueLimit { get; init; } = 1000;
    public int DuckDbAffectedQueueBatchSize { get; init; } = 1000;
}
