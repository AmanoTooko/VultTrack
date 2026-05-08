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

        var interval = TimeSpan.FromSeconds(int.TryParse(Environment.GetEnvironmentVariable("SCHEDULER_INTERVAL_SECONDS"), out var seconds) ? seconds : 3600);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RunDueSourcesAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Scheduled source cycle failed.");
            }

            await Task.Delay(interval, stoppingToken);
        }
    }

    public async Task RunDueSourcesAsync(CancellationToken ct)
    {
        var dueSources = await LoadDueSourcesAsync(ct);
        foreach (var source in dueSources)
        {
            await RunSourceAsync(source.Code, ct);
            var limit = int.TryParse(Environment.GetEnvironmentVariable("SCHEDULER_NORMALIZE_LIMIT"), out var parsed) ? parsed : 500;
            await normalizer.ProcessPendingAsync(limit, ct);
        }
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
            var cron = reader.GetString(1);
            var lastSuccess = reader.IsDBNull(2) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(2);
            if (IsDue(cron, lastSuccess, DateTimeOffset.UtcNow))
            {
                rows.Add(new ScheduledSource(code, cron, lastSuccess));
            }
        }

        return rows;
    }

    private async Task RunSourceAsync(string source, CancellationToken ct)
    {
        var repoRoot = ResolveRepoRoot();
        var node = Environment.GetEnvironmentVariable("PLUGIN_NODE_BIN") ?? "node";
        var psi = new ProcessStartInfo(node)
        {
            WorkingDirectory = repoRoot,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        psi.ArgumentList.Add("plugins/fetchers/run-fetcher.mjs");
        psi.ArgumentList.Add("--source");
        psi.ArgumentList.Add(source);
        psi.Environment["DATABASE_URL"] = Environment.GetEnvironmentVariable("DATABASE_URL") ?? "";
        if (Environment.GetEnvironmentVariable("SCHEDULER_FETCH_LIMIT") is { Length: > 0 } limit)
        {
            psi.Environment["FETCHER_MAX_RECORDS"] = limit;
        }

        logger.LogInformation("Starting fetcher {Source}", source);
        using var process = Process.Start(psi);
        if (process is null) throw new InvalidOperationException($"Failed to start fetcher process for {source}.");

        var stdoutTask = process.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = process.StandardError.ReadToEndAsync(ct);
        await process.WaitForExitAsync(ct);
        var stdout = await stdoutTask;
        var stderr = await stderrTask;

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException($"Fetcher {source} failed: {stderr}");
        }

        logger.LogInformation("Fetcher {Source} completed: {Output}", source, stdout);
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

    private sealed record ScheduledSource(string Code, string Cron, DateTimeOffset? LastSuccess);
}
