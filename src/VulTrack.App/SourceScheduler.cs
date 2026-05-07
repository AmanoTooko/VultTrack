using System.Diagnostics;

namespace VulTrack.App;

public sealed class SourceScheduler(
    IServiceProvider services,
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
                await RunNvdCycleAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Scheduled NVD cycle failed.");
            }
            await Task.Delay(interval, stoppingToken);
        }
    }

    private async Task RunNvdCycleAsync(CancellationToken ct)
    {
        var source = Environment.GetEnvironmentVariable("SCHEDULER_SOURCE") ?? "nvd-cve";
        var node = Environment.GetEnvironmentVariable("PLUGIN_NODE_BIN") ?? "node";
        var psi = new ProcessStartInfo(node, $"plugins/fetchers/run-fetcher.mjs --source {source}")
        {
            WorkingDirectory = AppContext.BaseDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        psi.Environment["DATABASE_URL"] = Environment.GetEnvironmentVariable("DATABASE_URL") ?? "";
        psi.Environment["FETCHER_MAX_RECORDS"] = Environment.GetEnvironmentVariable("SCHEDULER_FETCH_LIMIT") ?? "";

        using var process = Process.Start(psi);
        if (process is null) throw new InvalidOperationException("Failed to start fetcher process.");
        var stdout = await process.StandardOutput.ReadToEndAsync(ct);
        var stderr = await process.StandardError.ReadToEndAsync(ct);
        await process.WaitForExitAsync(ct);
        if (process.ExitCode != 0) throw new InvalidOperationException($"Fetcher failed: {stderr}");
        logger.LogInformation("Fetcher output: {Output}", stdout);

        using var scope = services.CreateScope();
        var processor = scope.ServiceProvider.GetRequiredService<NvdRawProcessor>();
        await processor.ProcessPendingAsync(500, ct);
    }
}
