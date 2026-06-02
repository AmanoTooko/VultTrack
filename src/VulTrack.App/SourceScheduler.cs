using System.Diagnostics;
using Microsoft.Extensions.Options;
using Npgsql;

namespace VulTrack.App;

public sealed class SourceScheduler(
    NpgsqlDataSource db,
    IRawNormalizationService normalizer,
    IOptions<VulTrackSchedulerOptions> options,
    ILogger<SourceScheduler> logger) : BackgroundService
{
    private VulTrackSchedulerOptions Options => options.Value;

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
        _ = Task.Run(() => RunFetchLoopAsync(fetchInterval, stoppingToken), stoppingToken);
        await RunNormalizeLoopAsync(normalizeInterval, stoppingToken);
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
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await DedupEpssPendingAsync(ct);
                var allSources = await LoadAllSourcesAsync(ct);
                foreach (var source in allSources)
                {
                    if (ct.IsCancellationRequested) break;
                    var result = await normalizer.ProcessSourcePendingAsync(source.Code, limit, ct);
                    if (result.Processed > 0 || result.Failed > 0)
                    {
                        logger.LogInformation("Normalizer {Source}: processed={Processed}, failed={Failed}",
                            result.SourceCode, result.Processed, result.Failed);
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Normalize cycle failed.");
            }
            await Task.Delay(interval, ct);
        }
    }

    private async Task RunFetchLoopAsync(TimeSpan interval, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var dueSources = await LoadDueSourcesAsync(ct);
                foreach (var source in dueSources)
                {
                    if (ct.IsCancellationRequested) break;
                    try
                    {
                        await RunSourceAsync(source.Code, ct);
                    }
                    catch (Exception ex)
                    {
                        logger.LogError(ex, "Fetcher {Source} failed", source.Code);
                    }
                }
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
        var allSources = await LoadAllSourcesAsync(ct);
        foreach (var source in allSources)
        {
            var result = await normalizer.ProcessSourcePendingAsync(source.Code, limit, ct);
            if (result.Processed > 0 || result.Failed > 0)
            {
                logger.LogInformation("Normalizer {Source}: processed={Processed}, failed={Failed}",
                    result.SourceCode, result.Processed, result.Failed);
            }
        }

        var dueSources = await LoadDueSourcesAsync(ct);
        foreach (var source in dueSources)
        {
            try
            {
                await RunSourceAsync(source.Code, ct);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Fetcher {Source} failed; continuing scheduled normalization.", source.Code);
            }
        }
    }

    public Task RunSourceNowAsync(string sourceCode, bool force, CancellationToken ct) =>
        RunSourceAsync(sourceCode, ct, force);

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
                rows.Add(new ScheduledSource(code, "", null));
        }
        return rows;
    }

    private async Task<IReadOnlyList<ScheduledSource>> LoadDueSourcesAsync(CancellationToken ct)
    {
        var rows = new List<ScheduledSource>();
        await using var cmd = db.CreateCommand("""
            select s.code, s.schedule_cron, s.config_json->>'runMode' as run_mode,
                   max(r.finished_at) filter (where r.status = 'succeeded') as last_success
            from sources s
            left join source_sync_runs r on r.source_id = s.id
            where s.enabled = true
              and (
                s.schedule_cron is not null
                or ($1::boolean = true and s.config_json->>'runMode' = 'init')
              )
            group by s.id, s.code, s.schedule_cron, s.config_json->>'runMode'
            order by s.code
            """);
        cmd.Parameters.AddWithValue(EnvBool("SCHEDULER_INCLUDE_INIT_SOURCES", Options.IncludeInitSources));
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
            if (string.Equals(runMode, "init", StringComparison.OrdinalIgnoreCase) && cron is null)
            {
                if (lastSuccess is null)
                    rows.Add(new ScheduledSource(code, "", lastSuccess));
                continue;
            }

            if (cron is not null && IsDue(cron, lastSuccess, DateTimeOffset.UtcNow))
            {
                rows.Add(new ScheduledSource(code, cron, lastSuccess));
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

    private async Task RunSourceAsync(string source, CancellationToken ct, bool force = false)
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
        var fetchLimit = Environment.GetEnvironmentVariable("SCHEDULER_FETCH_LIMIT") ?? Options.FetchLimit;
        if (!string.IsNullOrWhiteSpace(fetchLimit))
        {
            psi.Environment["FETCHER_MAX_RECORDS"] = fetchLimit;
        }
        if (force)
        {
            psi.Environment["FETCHER_FORCE"] = "1";
        }

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
            throw new TimeoutException($"Fetcher {source} timed out after {timeout.TotalSeconds:n0}s. {timeoutStderr}");
        }

        var stdout = await stdoutTask;
        var stderr = await stderrTask;

        if (process.ExitCode != 0)
        {
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

    private sealed record ScheduledSource(string Code, string Cron, DateTimeOffset? LastSuccess);

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
    public string? FetchLimit { get; init; }
    public string PluginNodeBin { get; init; } = "node";
    public string[] SourceCodes { get; init; } = [];
    public bool IncludeInitSources { get; init; }
}
