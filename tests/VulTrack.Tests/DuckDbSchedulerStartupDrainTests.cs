using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VulTrack.App;

namespace VulTrack.Tests;

[Collection("DuckDbSpoolEnvironment")]
public sealed class DuckDbSchedulerStartupDrainTests
{
    private sealed class RecordingLogger<T> : ILogger<T>
    {
        public readonly List<string> Messages = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Messages.Add($"{logLevel}: {formatter(state, exception)}");
        }
    }

    [Fact]
    public async Task ExecuteAsync_SwallowsStartupSpoolDrainFailure_AndKeepsScheduling()
    {
        var root = Path.Combine(Path.GetTempPath(), "vultrack-scheduler-drain-tests", Guid.NewGuid().ToString("N"));
        var incoming = Path.Combine(root, "incoming");
        Directory.CreateDirectory(incoming);
        Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", root);
        Environment.SetEnvironmentVariable("DUCKDB_FETCH_SOURCES", "");
        Environment.SetEnvironmentVariable("VULTRACK_SCHEDULER_ENABLED", "true");
        Environment.SetEnvironmentVariable("DUCKDB_FETCH_INITIAL_DELAY_SECONDS", "0");
        try
        {
            // A ready spool file whose lines cannot be parsed increments the error counter and
            // fails the ingest with InvalidDataException, which then propagates out of
            // ConsumeReadyFilesAsync. Before the fix this escaped ExecuteAsync and took the
            // whole BackgroundService host down (StopHost); the scheduler must survive it.
            var corruptFile = Path.Combine(incoming, "nuclei-templates-corrupt.ndjson.ready");
            await File.WriteAllTextAsync(corruptFile, "this is not json\n{also not json\n");

            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["VulTrack:DuckDb:Path"] = Path.Combine(root, "drain.duckdb"),
                    ["VulTrack:DuckDb:Enabled"] = "true"
                })
                .Build();
            using var store = new DuckDbEvidenceStore(configuration);
            var normalizer = new DuckDbEvidenceNormalizer(
                new UnusedServiceProvider(), store, NullLogger<DuckDbEvidenceNormalizer>.Instance);
            var logger = new RecordingLogger<DuckDbFirstScheduler>();
            var scheduler = new DuckDbFirstScheduler(
                normalizer,
                store,
                VulTrackOptions.Load(configuration),
                logger);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await scheduler.StartAsync(cts.Token);

            // Wait for the corrupt file to be consumed and quarantined as .failed.
            var deadline = DateTime.UtcNow.AddSeconds(30);
            while (DateTime.UtcNow < deadline)
            {
                if (File.Exists(Path.Combine(incoming, "nuclei-templates-corrupt.ndjson.failed"))) break;
                await Task.Delay(100, cts.Token);
            }
            Assert.True(
                File.Exists(Path.Combine(incoming, "nuclei-templates-corrupt.ndjson.failed")),
                "The corrupt spool file should have been quarantined as .failed.");

            // Give the scheduler a moment to continue into its cycle loop, then stop it.
            await Task.Delay(500, CancellationToken.None);
            await scheduler.StopAsync(CancellationToken.None);

            Assert.Contains(
                logger.Messages,
                message => message.Contains("startup spool drain failed", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(
                logger.Messages,
                message => message.Contains("DuckDB was invalidated", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Environment.SetEnvironmentVariable("VULTRACK_SPOOL_PATH", null);
            Environment.SetEnvironmentVariable("DUCKDB_FETCH_SOURCES", null);
            Environment.SetEnvironmentVariable("VULTRACK_SCHEDULER_ENABLED", null);
            Environment.SetEnvironmentVariable("DUCKDB_FETCH_INITIAL_DELAY_SECONDS", null);
            Directory.Delete(root, recursive: true);
        }
    }

    private sealed class UnusedServiceProvider : IServiceProvider
    {
        public object? GetService(Type serviceType) => null;
    }
}
