using System.Diagnostics;
using Npgsql;

namespace VulTrack.App;

public sealed class SourceScheduler(
    NpgsqlDataSource db,
    IRawNormalizationService normalizer,
    ILogger<SourceScheduler> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!string.Equals(Environment.GetEnvironmentVariable("VULTRACK_SCHEDULER_ENABLED"), "true", StringComparison.OrdinalIgnoreCase))
        {
            logger.LogInformation("VulTrack scheduler is disabled.");
            return;
        }

        var normalizeInterval = TimeSpan.FromSeconds(30);
        var fetchInterval = TimeSpan.FromHours(12);

        _ = Task.Run(() => RunFetchLoopAsync(fetchInterval, stoppingToken), stoppingToken);
        await RunNormalizeLoopAsync(normalizeInterval, stoppingToken);
    }

    private async Task RunNormalizeLoopAsync(TimeSpan interval, CancellationToken ct)
    {
        var limit = int.TryParse(Environment.GetEnvironmentVariable("SCHEDULER_NORMALIZE_LIMIT"), out var parsed) ? parsed : 500;
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
                        logger.LogInformation("Starting fetcher {Source}", source.Code);
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

        var limit = int.TryParse(Environment.GetEnvironmentVariable("SCHEDULER_NORMALIZE_LIMIT"), out var parsed) ? parsed : 500;
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
            select s.code, s.schedule_cron,
                   max(r.finished_at) filter (where r.status = 'succeeded') as last_success
            from sources s
            left join source_sync_runs r on r.source_id = s.id
            where s.enabled = true and s.schedule_cron is not null
            group by s.id, s.code, s.schedule_cron
            order by s.code
            """);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var code = reader.GetString(0);
            if (!IsSourceAllowed(code))
            {
                continue;
            }

            var cron = reader.GetString(1);
            var lastSuccess = reader.IsDBNull(2) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(2);
            if (IsDue(cron, lastSuccess, DateTimeOffset.UtcNow))
            {
                rows.Add(new ScheduledSource(code, cron, lastSuccess));
            }
        }

        return rows;
    }

    private static bool IsSourceAllowed(string code)
    {
        var configured = Environment.GetEnvironmentVariable("SCHEDULER_SOURCE_CODES");
        if (string.IsNullOrWhiteSpace(configured))
        {
            return true;
        }

        return configured
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Contains(code, StringComparer.OrdinalIgnoreCase);
    }

    private async Task RunSourceAsync(string source, CancellationToken ct)
    {
        var repoRoot = ResolveRepoRoot();
        var node = Environment.GetEnvironmentVariable("PLUGIN_NODE_BIN") ?? "node";
        var timeout = TimeSpan.FromSeconds(int.TryParse(Environment.GetEnvironmentVariable("SCHEDULER_FETCH_TIMEOUT_SECONDS"), out var timeoutSeconds)
            ? Math.Max(30, timeoutSeconds)
            : 600);
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
        if (Environment.GetEnvironmentVariable("SCHEDULER_FETCH_LIMIT") is { Length: > 0 } limit)
        {
            psi.Environment["FETCHER_MAX_RECORDS"] = limit;
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
}
  
// Add dedup logic in the normalize loop
