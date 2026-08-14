using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace VulTrack.App;

public sealed record DuckDbFirstEpssIngestFileResult(
    string File,
    long InputRows,
    long InsertedRows,
    long UpdatedRows,
    long UnchangedRows,
    long Bytes,
    long ElapsedMs);

public sealed record DuckDbFirstEpssIngestResult(
    bool Ok,
    IReadOnlyList<DuckDbFirstEpssIngestFileResult> Files);

public sealed partial class DuckDbEvidenceNormalizer
{
    private static readonly JsonSerializerOptions FirstEpssManifestJsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private sealed record FirstEpssManifest(
        int SchemaVersion,
        string SourceCode,
        string RunId,
        DateTimeOffset ObservedAt,
        string ContentHash,
        long Bytes,
        string? SourceUrl);

    // This is intentionally separate from IngestSpoolAsync. EPSS is a scalar
    // feed and must never reset a logical source or rebuild catalog/affected
    // projections just because a daily score file arrived.
    public async Task<DuckDbFirstEpssIngestResult> IngestFirstEpssSnapshotsAsync(
        int maxFiles,
        CancellationToken ct)
    {
        await _spoolIngestLock.WaitAsync(ct);
        try
        {
            await store.InitializeAsync(ct);
            var incoming = ResolveSpoolIncomingPath();
            Directory.CreateDirectory(incoming);
            var manifests = Directory.EnumerateFiles(incoming, "first-epss-*.epss.json.ready")
                .OrderBy(Path.GetFileName, StringComparer.Ordinal)
                .Take(Math.Clamp(maxFiles, 1, 1000))
                .ToArray();
            var results = new List<DuckDbFirstEpssIngestFileResult>(manifests.Length);
            foreach (var manifestPath in manifests)
                results.Add(await IngestFirstEpssSnapshotAsync(manifestPath, ct));
            return new DuckDbFirstEpssIngestResult(true, results);
        }
        finally
        {
            _spoolIngestLock.Release();
        }
    }

    private async Task<DuckDbFirstEpssIngestFileResult> IngestFirstEpssSnapshotAsync(string readyManifestPath, CancellationToken ct)
    {
        var readyCsvPath = readyManifestPath.Replace(".epss.json.ready", ".epss.csv.gz.ready", StringComparison.Ordinal);
        if (!File.Exists(readyCsvPath))
            throw new InvalidDataException($"FIRST EPSS manifest is missing its gzip CSV: {Path.GetFileName(readyManifestPath)}.");

        var processingManifestPath = readyManifestPath.Replace(".ready", ".processing", StringComparison.Ordinal);
        var processingCsvPath = readyCsvPath.Replace(".ready", ".processing", StringComparison.Ordinal);
        File.Move(readyManifestPath, processingManifestPath);
        try
        {
            File.Move(readyCsvPath, processingCsvPath);
        }
        catch
        {
            File.Move(processingManifestPath, readyManifestPath, overwrite: true);
            throw;
        }

        try
        {
            var manifest = await ReadFirstEpssManifestAsync(processingManifestPath, ct);
            var info = new FileInfo(processingCsvPath);
            if (info.Length != manifest.Bytes)
                throw new InvalidDataException("FIRST EPSS gzip byte count does not match its manifest.");
            await VerifyFirstEpssHashAsync(processingCsvPath, manifest.ContentHash, ct);

            var watch = Stopwatch.StartNew();
            var applied = await store.ApplyFirstEpssSnapshotAsync(processingCsvPath, manifest.ObservedAt, ct);
            await AdvanceFirstEpssCheckpointAsync(manifest, applied, ct);
            watch.Stop();

            File.Delete(processingCsvPath);
            File.Delete(processingManifestPath);
            logger.LogInformation(
                "DuckDB FIRST EPSS committed {InputRows} rows: inserted={InsertedRows}, updated={UpdatedRows}, unchanged={UnchangedRows}, elapsed={Elapsed}ms.",
                applied.InputRows, applied.InsertedRows, applied.UpdatedRows, applied.UnchangedRows, watch.ElapsedMilliseconds);
            return new DuckDbFirstEpssIngestFileResult(
                Path.GetFileName(readyManifestPath),
                applied.InputRows,
                applied.InsertedRows,
                applied.UpdatedRows,
                applied.UnchangedRows,
                info.Length,
                watch.ElapsedMilliseconds);
        }
        catch
        {
            // Keep the exact gzip and manifest ready for an idempotent retry.
            if (File.Exists(processingCsvPath)) File.Move(processingCsvPath, readyCsvPath, overwrite: true);
            if (File.Exists(processingManifestPath)) File.Move(processingManifestPath, readyManifestPath, overwrite: true);
            throw;
        }
    }

    private static async Task<FirstEpssManifest> ReadFirstEpssManifestAsync(string path, CancellationToken ct)
    {
        await using var stream = File.OpenRead(path);
        var manifest = await JsonSerializer.DeserializeAsync<FirstEpssManifest>(
            stream,
            FirstEpssManifestJsonOptions,
            ct)
            ?? throw new InvalidDataException("FIRST EPSS manifest is empty.");
        if (manifest.SchemaVersion != 1 ||
            !string.Equals(manifest.SourceCode, "first-epss", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(manifest.RunId) ||
            string.IsNullOrWhiteSpace(manifest.ContentHash) ||
            manifest.Bytes <= 0)
            throw new InvalidDataException("FIRST EPSS manifest has an unsupported format.");
        if (manifest.ObservedAt == default)
            throw new InvalidDataException("FIRST EPSS manifest is missing observedAt.");
        return manifest;
    }

    private static async Task VerifyFirstEpssHashAsync(string path, string expectedHash, CancellationToken ct)
    {
        var expected = expectedHash.Trim().ToLowerInvariant();
        if (expected.Length != 64 || expected.Any(character => !Uri.IsHexDigit(character)))
            throw new InvalidDataException("FIRST EPSS manifest contentHash is not a SHA-256 hash.");
        await using var stream = File.OpenRead(path);
        var actual = Convert.ToHexString(await SHA256.HashDataAsync(stream, ct)).ToLowerInvariant();
        if (!CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.ASCII.GetBytes(actual),
                System.Text.Encoding.ASCII.GetBytes(expected)))
            throw new InvalidDataException("FIRST EPSS gzip content hash does not match its manifest.");
    }

    private async Task AdvanceFirstEpssCheckpointAsync(
        FirstEpssManifest manifest,
        DuckDbFirstEpssApplyResult applied,
        CancellationToken ct)
    {
        var spoolRoot = Directory.GetParent(ResolveSpoolIncomingPath())?.FullName
            ?? throw new InvalidDataException("FIRST EPSS spool root cannot be resolved.");
        var stateDirectory = Path.Combine(spoolRoot, "state");
        var statePath = Path.Combine(stateDirectory, "first-epss.json");
        JsonObject state;
        try
        {
            state = File.Exists(statePath)
                ? JsonNode.Parse(await File.ReadAllTextAsync(statePath, ct))?.AsObject() ?? new JsonObject()
                : new JsonObject();
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("FIRST EPSS source state is invalid JSON.", ex);
        }

        state["checkpoint"] = new JsonObject
        {
            ["contentHash"] = manifest.ContentHash,
            ["lastFetched"] = manifest.ObservedAt.UtcDateTime.ToString("O"),
            ["rowCount"] = applied.InputRows,
            ["formatVersion"] = manifest.SchemaVersion
        };
        state["hasRecords"] = true;
        state["lastEpssImport"] = new JsonObject
        {
            ["runId"] = manifest.RunId,
            ["insertedRows"] = applied.InsertedRows,
            ["updatedRows"] = applied.UpdatedRows,
            ["unchangedRows"] = applied.UnchangedRows,
            ["committedAt"] = DateTimeOffset.UtcNow.ToString("O")
        };

        Directory.CreateDirectory(stateDirectory);
        var temporary = $"{statePath}.{Guid.NewGuid():N}.tmp";
        await File.WriteAllTextAsync(temporary, state.ToJsonString(), ct);
        File.Move(temporary, statePath, overwrite: true);
    }
}
