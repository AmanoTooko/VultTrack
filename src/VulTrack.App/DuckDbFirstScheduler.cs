using System.Diagnostics;
using System.Text.Json.Nodes;

namespace VulTrack.App;

public sealed class DuckDbFirstScheduler(
    DuckDbEvidenceNormalizer normalizer,
    DuckDbEvidenceStore store,
    VulTrackOptions options,
    ILogger<DuckDbFirstScheduler> logger) : BackgroundService
{
    public const int MaxManualFetchRecords = 50_000;
    private readonly SemaphoreSlim cycleLock = new(1, 1);
    private readonly HashSet<string> deferredChangedKeys = new(StringComparer.OrdinalIgnoreCase);
    private bool deferredFullCatalogRebuild;
    private bool deferredAffectedRebuild;
    private Exception? fatalStorageError;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Scheduler.Enabled)
        {
            logger.LogInformation("DuckDB-first scheduler is disabled.");
            return;
        }

        var interval = TimeSpan.FromSeconds(options.Scheduler.FetchIntervalSeconds);
        var initialDelay = TimeSpan.FromSeconds(options.Scheduler.InitialDelaySeconds);
        // The startup drain must not be able to stop the host. A single malformed spool file
        // (for example a stale nuclei revision) throws here, and because ExecuteAsync is a
        // BackgroundService entry point the default BackgroundServiceExceptionBehavior of
        // StopHost would take the whole API down with it. The failing file is already
        // quarantined as .failed by the normalizer, so the scheduled cycle can continue.
        try
        {
            await ConsumeReadyFilesAsync(stoppingToken);
            await FlushDeferredCatalogRebuildAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            return;
        }
        catch (Exception ex)
        {
            if (IsFatalDuckDbInvalidation(ex))
            {
                Volatile.Write(ref fatalStorageError, ex);
                logger.LogCritical(ex, "DuckDB was invalidated by a fatal storage error; stopping the scheduler to prevent repeated writes. Restart only after the database and indexes have been checked.");
                return;
            }
            logger.LogError(ex, "DuckDB-first startup spool drain failed; the offending file was quarantined and the scheduled cycle will continue.");
        }

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
                if (IsFatalDuckDbInvalidation(ex))
                {
                    Volatile.Write(ref fatalStorageError, ex);
                    logger.LogCritical(ex, "DuckDB was invalidated by a fatal storage error; stopping the scheduler to prevent repeated writes. Restart only after the database and indexes have been checked.");
                    return;
                }
                logger.LogError(ex, "DuckDB-first scheduler cycle failed; the next cycle will retry.");
            }
            await Task.Delay(interval, stoppingToken);
        }
    }

    public async Task RunCycleAsync(CancellationToken ct)
    {
        ThrowIfStorageInvalidated();
        if (!await cycleLock.WaitAsync(0, ct)) return;
        try
        {
            foreach (var source in SourceCodes())
            {
                ThrowIfStorageInvalidated();
                ct.ThrowIfCancellationRequested();
                try
                {
                    var fetchSource = await ResolveScheduledSourceAsync(source, ct);
                    await RunFetcherAsync(fetchSource, force: false, ct);
                    await ConsumeReadyFilesAsync(ct);
                    if (fetchSource.Equals("osv", StringComparison.OrdinalIgnoreCase))
                    {
                        var maxPendingBatches = options.Scheduler.OsvPendingMaxBatchesPerCycle;
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
                    if (IsFatalDuckDbInvalidation(ex)) throw;
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

    public Task RunSourceAsync(string sourceCode, bool force, CancellationToken ct)
        => RunSourceAsync(sourceCode, force, limit: 0, ct);

    public async Task RunSourceAsync(string sourceCode, bool force, int limit, CancellationToken ct)
    {
        ThrowIfStorageInvalidated();
        if (limit < 0 || limit > MaxManualFetchRecords)
            throw new ArgumentOutOfRangeException(nameof(limit), $"Fetch limit must be 0..{MaxManualFetchRecords}.");
        if (!await cycleLock.WaitAsync(0, ct))
            throw new InvalidOperationException("A DuckDB-first fetch cycle is already running.");
        try
        {
            try
            {
                await RunFetcherAsync(sourceCode, force, limit, ct);
                await ConsumeReadyFilesAsync(ct);
                await FlushDeferredCatalogRebuildAsync(ct);
            }
            catch (Exception ex) when (IsFatalDuckDbInvalidation(ex))
            {
                Volatile.Write(ref fatalStorageError, ex);
                logger.LogCritical(ex, "Manual DuckDB source run encountered a fatal storage error; all scheduler writes are now blocked until restart.");
                throw;
            }
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

    private Task RunFetcherAsync(string sourceCode, bool force, CancellationToken ct)
        => RunFetcherAsync(sourceCode, force, limit: 0, ct);

    private async Task RunFetcherAsync(string sourceCode, bool force, int limit, CancellationToken ct)
    {
        var root = options.RepoRoot ?? "/workspace";
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
        if (sourceCode.Equals("ghsa", StringComparison.OrdinalIgnoreCase)
            && ReadCheckpoint("ghsa")?["updatedSince"] is null)
        {
            var baseline = ReadCheckpoint("ghsa-init");
            var watermark = baseline?["incrementalSince"]?.GetValue<string>();
            if (!string.IsNullOrWhiteSpace(watermark))
                start.Environment["GHSA_BOOTSTRAP_WATERMARK"] = watermark;
        }
        if (force) start.Environment["FETCHER_FORCE"] = "1";
        if (limit > 0)
            start.Environment["FETCHER_MAX_RECORDS"] = limit.ToString(System.Globalization.CultureInfo.InvariantCulture);

        using var process = Process.Start(start) ?? throw new InvalidOperationException($"Unable to start fetcher {sourceCode}.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = CaptureFetcherDiagnosticsAsync(process.StandardError, sourceCode, CancellationToken.None);
        try
        {
            await process.WaitForExitAsync(ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            var terminated = false;
            try
            {
                if (!process.HasExited) process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync(CancellationToken.None);
                terminated = true;
            }
            catch (Exception killError)
            {
                logger.LogWarning(killError, "Failed to terminate cancelled fetcher {SourceCode}; check for an orphan process.", sourceCode);
            }
            if (terminated)
            {
                try { await stdoutTask; } catch { }
                try { await stderrTask; } catch { }
            }
            throw;
        }
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

    private string[] SourceCodes() => options.Scheduler.SourceCodes();

    private async Task<string> ResolveScheduledSourceAsync(string sourceCode, CancellationToken ct)
    {
        var baselineSource = sourceCode.ToLowerInvariant() switch
        {
            "nvd-cve" or "nvd-cve-init" => "nvd-cve-init",
            "osv" or "osv-init" => "osv-init",
            "ghsa" or "ghsa-init" => "ghsa-init",
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
        if (options.Scheduler.AllowAutomaticInit) return baselineSource;
        var message = $"Automatic init for {baselineSource} is blocked while scheduling {sourceCode}: {reason}. " +
                      "Set DUCKDB_ALLOW_AUTOMATIC_INIT=true only for an intentional baseline import.";
        logger.LogError("{Message}", message);
        throw new InvalidOperationException(message);
    }

    private JsonObject? ReadCheckpoint(string sourceCode)
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

    private bool HasOsvPending() => ReadCheckpoint("osv")?["pending"] is JsonObject;

    private string SpoolRootPath() => options.ResolveSpoolRoot();

    private string SpoolIncomingPath() => Path.Combine(SpoolRootPath(), "incoming");

    private bool HasGenericReadyFiles() =>
        Directory.EnumerateFiles(SpoolIncomingPath(), "*.ndjson.ready")
            .Any(path => !Path.GetFileName(path).StartsWith("first-epss-", StringComparison.OrdinalIgnoreCase));

    private static string LastLine(string value) => value
        .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .LastOrDefault() ?? string.Empty;

    private static bool IsFatalDuckDbInvalidation(Exception exception)
    {
        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (current.Message.Contains("database has been invalidated", StringComparison.OrdinalIgnoreCase)
                || current.Message.Contains("Failed to delete all rows from index", StringComparison.OrdinalIgnoreCase)
                || current.Message.Contains("Corrupted ART index", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private void ThrowIfStorageInvalidated()
    {
        var fatal = Volatile.Read(ref fatalStorageError);
        if (fatal is not null)
            throw new InvalidOperationException(
                "DuckDB writes are blocked after a fatal storage error; restart only after checking the database and indexes.",
                fatal);
    }
}
