using System.Diagnostics;
using System.Text.Json.Nodes;

namespace VulTrack.App;

public sealed class DuckDbFirstScheduler(
    DuckDbEvidenceNormalizer normalizer,
    DuckDbEvidenceStore store,
    ILogger<DuckDbFirstScheduler> logger) : BackgroundService
{
    private readonly SemaphoreSlim cycleLock = new(1, 1);
    private readonly HashSet<string> deferredChangedKeys = new(StringComparer.OrdinalIgnoreCase);
    private bool deferredFullCatalogRebuild;
    private bool deferredAffectedRebuild;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!EnvBool("VULTRACK_SCHEDULER_ENABLED", false))
        {
            logger.LogInformation("DuckDB-first scheduler is disabled.");
            return;
        }

        var interval = TimeSpan.FromSeconds(EnvInt("DUCKDB_FETCH_INTERVAL_SECONDS", 21600, 60));
        var initialDelay = TimeSpan.FromSeconds(EnvInt("DUCKDB_FETCH_INITIAL_DELAY_SECONDS", 15, 0));
        await ConsumeReadyFilesAsync(stoppingToken);
        await FlushDeferredCatalogRebuildAsync(stoppingToken);
        if (initialDelay > TimeSpan.Zero) await Task.Delay(initialDelay, stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RunCycleAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "DuckDB-first scheduler cycle failed; the next cycle will retry.");
            }
            await Task.Delay(interval, stoppingToken);
        }
    }

    public async Task RunCycleAsync(CancellationToken ct)
    {
        if (!await cycleLock.WaitAsync(0, ct)) return;
        try
        {
            foreach (var source in SourceCodes())
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    var fetchSource = await ResolveScheduledSourceAsync(source, ct);
                    await RunFetcherAsync(fetchSource, force: false, ct);
                    await ConsumeReadyFilesAsync(ct);
                    if (fetchSource.Equals("osv", StringComparison.OrdinalIgnoreCase))
                    {
                        var maxPendingBatches = Math.Clamp(EnvInt("OSV_PENDING_MAX_BATCHES_PER_CYCLE", 3, 1), 1, 12);
                        for (var batch = 1; batch < maxPendingBatches && HasOsvPending(); batch++)
                        {
                            await RunFetcherAsync("osv", force: false, ct);
                            await ConsumeReadyFilesAsync(ct);
                        }
                    }
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    logger.LogError(ex, "DuckDB-first scheduled source {SourceCode} failed; continuing with the remaining sources.", source);
                }
            }
            await FlushDeferredCatalogRebuildAsync(ct);
        }
        finally
        {
            cycleLock.Release();
        }
    }

    public async Task RunSourceAsync(string sourceCode, bool force, CancellationToken ct)
    {
        if (!await cycleLock.WaitAsync(0, ct))
            throw new InvalidOperationException("A DuckDB-first fetch cycle is already running.");
        try
        {
            await RunFetcherAsync(sourceCode, force, ct);
            await ConsumeReadyFilesAsync(ct);
            await FlushDeferredCatalogRebuildAsync(ct);
        }
        finally
        {
            cycleLock.Release();
        }
    }

    private async Task ConsumeReadyFilesAsync(CancellationToken ct)
    {
        var epss = await normalizer.IngestFirstEpssSnapshotsAsync(maxFiles: 10, ct);
        if (epss.Files.Count > 0)
        {
            logger.LogInformation(
                "DuckDB-first scheduler committed {Files} FIRST EPSS snapshots; rows={Rows}, inserted={Inserted}, updated={Updated}.",
                epss.Files.Count,
                epss.Files.Sum(file => file.InputRows),
                epss.Files.Sum(file => file.InsertedRows),
                epss.Files.Sum(file => file.UpdatedRows));
        }
        while (Directory.Exists(SpoolIncomingPath()) && HasGenericReadyFiles())
        {
            var result = await normalizer.IngestSpoolAsync(
                new DuckDbSpoolIngestRequest(BatchSize: 5000, MaxFiles: 1000, DeferCatalogRebuild: true), ct);
            if (result.files.Count == 0) break;
            deferredChangedKeys.UnionWith(result.deferredChangedKeys);
            deferredFullCatalogRebuild |= result.deferredFullCatalogRebuild;
            deferredAffectedRebuild |= result.deferredAffectedRebuild;
            logger.LogInformation(
                "DuckDB-first scheduler consumed {Files} files; changedKeys={ChangedKeys} (catalog rebuild deferred to cycle end).",
                result.files.Count, result.deferredChangedKeys.Count);
        }
    }

    private async Task FlushDeferredCatalogRebuildAsync(CancellationToken ct)
    {
        if (deferredChangedKeys.Count == 0 && !deferredFullCatalogRebuild && !deferredAffectedRebuild) return;
        var changedKeys = deferredChangedKeys.ToArray();
        var fullCatalogRebuild = deferredFullCatalogRebuild
            || changedKeys.Length > DuckDbEvidenceNormalizer.FullCatalogRebuildKeyThreshold;
        var requiresAffectedRebuild = deferredAffectedRebuild;
        deferredChangedKeys.Clear();
        deferredFullCatalogRebuild = false;
        deferredAffectedRebuild = false;

        logger.LogInformation(
            "DuckDB-first deferred catalog rebuild starting: changedKeys={ChangedKeys}, fullRebuild={FullRebuild}, affectedRebuild={AffectedRebuild}.",
            changedKeys.Length, fullCatalogRebuild, requiresAffectedRebuild);
        var catalog = fullCatalogRebuild
            ? await store.RebuildCatalogAsync(ct)
            : await store.RebuildCatalogForKeysAsync(changedKeys, ct);
        if (requiresAffectedRebuild)
        {
            if (fullCatalogRebuild)
                await store.RebuildAffectedComponentsFromCatalogAsync(ct);
            else
                await store.RebuildAffectedComponentsForKeysAsync(changedKeys, ct);
        }
        logger.LogInformation(
            "DuckDB-first deferred catalog rebuild completed: vulnerabilities={Vulnerabilities}, identifiers={Identifiers}.",
            catalog.Vulnerabilities, catalog.Identifiers);
    }

    private async Task RunFetcherAsync(string sourceCode, bool force, CancellationToken ct)
    {
        var root = Environment.GetEnvironmentVariable("VULTRACK_REPO_ROOT") ?? "/workspace";
        var start = new ProcessStartInfo
        {
            FileName = "node",
            WorkingDirectory = root,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        start.ArgumentList.Add(Path.Combine(root, "plugins", "fetchers", "run-fetcher.mjs"));
        start.ArgumentList.Add("--source");
        start.ArgumentList.Add(sourceCode);
        start.Environment["VULTRACK_STORAGE_BACKEND"] = "duckdb";
        start.Environment["VULTRACK_SPOOL_PATH"] = SpoolRootPath();
        start.Environment["FETCHER_TRIGGER"] = "scheduled";
        if (sourceCode.Equals("osv", StringComparison.OrdinalIgnoreCase)
            && ReadCheckpoint("osv")?["cursor"] is null
            && ReadCheckpoint("osv")?["lastModifiedWatermark"] is null)
        {
            var baseline = ReadCheckpoint("osv-init");
            var watermark = baseline?["incrementalSince"]?.GetValue<string>();
            if (!string.IsNullOrWhiteSpace(watermark))
                start.Environment["OSV_BOOTSTRAP_WATERMARK"] = watermark;
        }
        if (force) start.Environment["FETCHER_FORCE"] = "1";

        using var process = Process.Start(start) ?? throw new InvalidOperationException($"Unable to start fetcher {sourceCode}.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = CaptureFetcherDiagnosticsAsync(process.StandardError, sourceCode, ct);
        await process.WaitForExitAsync(ct);
        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        if (process.ExitCode != 0)
        {
            logger.LogError("DuckDB-first fetcher {SourceCode} failed with exit={ExitCode}: {Error}", sourceCode, process.ExitCode, stderr);
            throw new InvalidOperationException($"DuckDB-first fetcher {sourceCode} failed with exit {process.ExitCode}: {stderr}");
        }
        logger.LogInformation("DuckDB-first fetcher {SourceCode} completed: {Result}", sourceCode, LastLine(stdout));
    }

    private async Task<string> CaptureFetcherDiagnosticsAsync(StreamReader reader, string sourceCode, CancellationToken ct)
    {
        var recent = new Queue<string>(50);
        while (await reader.ReadLineAsync(ct) is { } line)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;
            logger.LogInformation("DuckDB-first fetcher {SourceCode}: {Message}", sourceCode, line);
            if (recent.Count == 50) recent.Dequeue();
            recent.Enqueue(line);
        }
        return recent.LastOrDefault() ?? string.Empty;
    }

    private static string[] SourceCodes() =>
        (Environment.GetEnvironmentVariable("DUCKDB_FETCH_SOURCES") ?? "nvd-cve,osv,cisa-kev,first-epss,exploitdb,nuclei-templates,metasploit,poc-in-github,cargo-advisory")
            .Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private async Task<string> ResolveScheduledSourceAsync(string sourceCode, CancellationToken ct)
    {
        var baselineSource = sourceCode.ToLowerInvariant() switch
        {
            "nvd-cve" or "nvd-cve-init" => "nvd-cve-init",
            "osv" or "osv-init" => "osv-init",
            _ => null
        };
        if (baselineSource is null) return sourceCode;
        if (sourceCode.EndsWith("-init", StringComparison.OrdinalIgnoreCase))
            return RequireAutomaticInit(sourceCode, sourceCode, "an init source was configured for an automatic scheduler cycle");

        var checkpoint = ReadCheckpoint(baselineSource);
        if (checkpoint?["initComplete"]?.GetValue<bool>() == false)
            return RequireAutomaticInit(sourceCode, baselineSource, "the baseline checkpoint is incomplete");
        if (checkpoint?["initComplete"]?.GetValue<bool>() == true)
            return sourceCode;

        if (await store.HasSourceRecordsAsync(sourceCode, ct)) return sourceCode;
        return RequireAutomaticInit(sourceCode, baselineSource, "no completed baseline checkpoint or source records exist");
    }

    private string RequireAutomaticInit(string sourceCode, string baselineSource, string reason)
    {
        if (EnvBool("DUCKDB_ALLOW_AUTOMATIC_INIT", false)) return baselineSource;
        var message = $"Automatic init for {baselineSource} is blocked while scheduling {sourceCode}: {reason}. " +
                      "Set DUCKDB_ALLOW_AUTOMATIC_INIT=true only for an intentional baseline import.";
        logger.LogError("{Message}", message);
        throw new InvalidOperationException(message);
    }

    private static JsonObject? ReadCheckpoint(string sourceCode)
    {
        var path = Path.Combine(SpoolRootPath(), "state", $"{sourceCode}.json");
        if (!File.Exists(path)) return null;
        try
        {
            return JsonNode.Parse(File.ReadAllText(path))?["checkpoint"] as JsonObject;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static bool HasOsvPending() => ReadCheckpoint("osv")?["pending"] is JsonObject;

    private static string SpoolRootPath()
    {
        var configured = Environment.GetEnvironmentVariable("VULTRACK_SPOOL_PATH");
        if (!string.IsNullOrWhiteSpace(configured)) return Path.GetFullPath(configured);
        return Path.Combine(Environment.GetEnvironmentVariable("VULTRACK_REPO_ROOT") ?? Directory.GetCurrentDirectory(), "data", "spool");
    }

    private static string SpoolIncomingPath() => Path.Combine(SpoolRootPath(), "incoming");

    private static bool HasGenericReadyFiles() =>
        Directory.EnumerateFiles(SpoolIncomingPath(), "*.ndjson.ready")
            .Any(path => !Path.GetFileName(path).StartsWith("first-epss-", StringComparison.OrdinalIgnoreCase));

    private static string LastLine(string value) => value
        .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .LastOrDefault() ?? string.Empty;

    private static bool EnvBool(string name, bool fallback) =>
        bool.TryParse(Environment.GetEnvironmentVariable(name), out var value) ? value : fallback;

    private static int EnvInt(string name, int fallback, int minimum) =>
        int.TryParse(Environment.GetEnvironmentVariable(name), out var value) ? Math.Max(minimum, value) : fallback;
}
