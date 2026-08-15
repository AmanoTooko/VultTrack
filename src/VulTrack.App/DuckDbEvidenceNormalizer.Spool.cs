using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace VulTrack.App;

public sealed record DuckDbSpoolIngestRequest(
    string? File = null,
    int BatchSize = 2000,
    int MaxFiles = 1,
    bool DeleteOnSuccess = true,
    bool DeferCatalogRebuild = false);

public sealed record DuckDbSpoolFileResult(
    string file,
    string sourceCode,
    long records,
    long affectedFacts,
    long errors,
    long bytes,
    long elapsedMs);

public sealed record DuckDbSpoolIngestResult(
    bool ok,
    IReadOnlyList<DuckDbSpoolFileResult> files,
    DuckDbCatalogStats catalog,
    DuckDbEvidenceStats evidence,
    IReadOnlyList<string> deferredChangedKeys,
    bool deferredFullCatalogRebuild,
    bool deferredAffectedRebuild);

public sealed partial class DuckDbEvidenceNormalizer
{
    internal const int FullCatalogRebuildKeyThreshold = 50_000;
    private sealed record SpoolFileIngestOutcome(
        DuckDbSpoolFileResult Result,
        IReadOnlySet<string> ChangedKeys,
        bool RequiresFullCatalogRebuild,
        bool RequiresAffectedRebuild,
        string StagedPath);

    private sealed record ParsedSpoolRecord(
        DuckDbEvidenceRecord Evidence,
        DuckDbCatalogRecord Catalog,
        DuckDbExploit? Exploit,
        DuckDbThreatScore? ThreatScore);

    private readonly SemaphoreSlim _spoolIngestLock = new(1, 1);

    public async Task<DuckDbSpoolIngestResult> IngestSpoolAsync(DuckDbSpoolIngestRequest request, CancellationToken ct)
    {
        await _spoolIngestLock.WaitAsync(ct);
        var outcomes = new List<SpoolFileIngestOutcome>();
        try
        {
            await store.InitializeAsync(ct);
            var incoming = ResolveSpoolIncomingPath();
            Directory.CreateDirectory(incoming);
            RecoverInterruptedSpoolFiles(incoming);
            var files = string.IsNullOrWhiteSpace(request.File)
                ? Directory.EnumerateFiles(incoming, "*.ndjson.ready")
                    .Where(path => !Path.GetFileName(path).StartsWith("first-epss-", StringComparison.OrdinalIgnoreCase))
                    .OrderBy(SpoolRunPrefix, StringComparer.Ordinal)
                    .ThenBy(SpoolSequence)
                    .Take(Math.Clamp(request.MaxFiles, 1, 1000))
                    .ToArray()
                : [ResolveReadyFile(incoming, request.File)];

            if (files.Any(path => Path.GetFileName(path).StartsWith("first-epss-", StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException("FIRST EPSS must be imported through the native gzip snapshot pipeline.");

            foreach (var readyPath in files)
                outcomes.Add(await IngestSpoolFileAsync(readyPath, Math.Clamp(request.BatchSize, 100, 20_000), ct));

            var changedKeys = outcomes
                .SelectMany(outcome => outcome.ChangedKeys)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            var fullCatalogRebuild = outcomes.Any(outcome => outcome.RequiresFullCatalogRebuild)
                || changedKeys.Length > FullCatalogRebuildKeyThreshold;
            var requiresAffectedRebuild = outcomes.Any(outcome => outcome.RequiresAffectedRebuild);
            var catalog = new DuckDbCatalogStats(0, 0, 0);
            if (request.DeferCatalogRebuild)
            {
                logger.LogInformation(
                    "DuckDB-first catalog rebuild deferred: changedKeys={ChangedKeys}, fullRebuild={FullRebuild}, affectedRebuild={AffectedRebuild}.",
                    changedKeys.Length, fullCatalogRebuild, requiresAffectedRebuild);
            }
            else
            {
                catalog = fullCatalogRebuild
                    ? await store.RebuildCatalogAsync(ct)
                    : await store.RebuildCatalogForKeysAsync(changedKeys, ct);
                if (requiresAffectedRebuild)
                {
                    if (fullCatalogRebuild)
                        await store.RebuildAffectedComponentsFromCatalogAsync(ct);
                    else
                        await store.RebuildAffectedComponentsForKeysAsync(changedKeys, ct);
                }
            }

            FinalizeStagedFiles(outcomes, request.DeleteOnSuccess);
            CleanupCompletedSourceMirrors(incoming, outcomes);
            return new DuckDbSpoolIngestResult(
                true,
                outcomes.Select(outcome => outcome.Result).ToArray(),
                catalog,
                await store.StatsAsync(ct),
                changedKeys,
                fullCatalogRebuild,
                requiresAffectedRebuild);
        }
        catch
        {
            RestoreStagedFiles(outcomes);
            throw;
        }
        finally
        {
            _spoolIngestLock.Release();
        }
    }

    private async Task<SpoolFileIngestOutcome> IngestSpoolFileAsync(string readyPath, int batchSize, CancellationToken ct)
    {
        var processingPath = readyPath[..^".ready".Length] + ".processing";
        var stagedPath = readyPath[..^".ready".Length] + ".staged";
        File.Move(readyPath, processingPath);
        var inputBytes = new FileInfo(processingPath).Length;
        var watch = Stopwatch.StartNew();
        var evidenceBatch = new List<DuckDbEvidenceRecord>(batchSize);
        var catalogBatch = new List<DuckDbCatalogRecord>(batchSize);
        var exploitBatch = new List<DuckDbExploit>(batchSize);
        var threatScoreBatch = new List<DuckDbThreatScore>(batchSize);
        long records = 0;
        long affectedFacts = 0;
        long errors = 0;
        var changedKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string? sourceCode = null;
        var replaceLogicalSource = false;
        var sourceReset = false;
        var removedSourceAffectedFacts = false;
        string? nucleiSnapshotId = null;

        try
        {
            await using var stream = new FileStream(processingPath, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan);
            using var reader = new StreamReader(stream, Encoding.UTF8, true, 1 << 20);
            while (await reader.ReadLineAsync(ct) is { } line)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                JsonObject envelope;
                ParsedSpoolRecord item;
                try
                {
                    envelope = JsonNode.Parse(line)?.AsObject() ?? throw new InvalidDataException("Spool line is not a JSON object.");
                    item = BuildSpoolRecords(envelope);
                }
                catch (Exception ex)
                {
                    errors++;
                    logger.LogError(ex, "Failed to parse DuckDB spool record {Record} in {File}.", records + errors, processingPath);
                    continue;
                }

                sourceCode ??= envelope["sourceCode"]?.GetValue<string>();
                if (!string.Equals(sourceCode, envelope["sourceCode"]?.GetValue<string>(), StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException("A spool file must contain exactly one source.");
                if (IsNucleiSpoolSource(sourceCode))
                {
                    var recordSnapshotId = NucleiSnapshotId(envelope);
                    if (string.IsNullOrWhiteSpace(recordSnapshotId))
                        throw new InvalidDataException("Nuclei spool record is missing snapshotId.");
                    if (!IsTrue(envelope["snapshotComplete"]))
                        throw new InvalidDataException("Nuclei spool record is not a complete revision snapshot.");
                    if (!string.IsNullOrWhiteSpace(StringValue(envelope["sourceMode"])))
                        throw new InvalidDataException("Nuclei snapshots must be emitted as one non-append spool file.");
                    if (nucleiSnapshotId is not null && !string.Equals(nucleiSnapshotId, recordSnapshotId, StringComparison.Ordinal))
                        throw new InvalidDataException("Nuclei spool file contains more than one Git revision.");
                    nucleiSnapshotId = recordSnapshotId;
                }
                replaceLogicalSource =
                    (sourceCode?.EndsWith("-init", StringComparison.OrdinalIgnoreCase) == true
                     && !string.Equals(envelope["sourceMode"]?.GetValue<string>(), "append", StringComparison.OrdinalIgnoreCase))
                    || string.Equals(sourceCode, "first-epss", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(sourceCode, "cisa-kev", StringComparison.OrdinalIgnoreCase);
                if (replaceLogicalSource && !sourceReset)
                {
                    var logicalSource = CanonicalEvidenceSourceCode(sourceCode!);
                    var previous = await store.GetSourceProjectionStateAsync(logicalSource, ct);
                    changedKeys.UnionWith(previous.VulnerabilityKeys);
                    removedSourceAffectedFacts = previous.HasAffectedFacts;
                    await store.ResetLogicalSourceAsync(logicalSource, ct);
                    sourceReset = true;
                }
                var pureThreatRecord = string.Equals(
                    item.Evidence.SourceCode,
                    "first-epss",
                    StringComparison.OrdinalIgnoreCase);
                if (!pureThreatRecord && !IsNucleiSpoolSource(sourceCode))
                {
                    evidenceBatch.Add(item.Evidence);
                    catalogBatch.Add(item.Catalog);
                }
                if (item.Exploit is not null) exploitBatch.Add(item.Exploit);
                if (item.ThreatScore is not null) threatScoreBatch.Add(item.ThreatScore);
                records++;
                affectedFacts += item.Evidence.AffectedFacts.Count;
                if (!IsNucleiSpoolSource(sourceCode) &&
                    (evidenceBatch.Count >= batchSize || exploitBatch.Count >= batchSize || threatScoreBatch.Count >= batchSize))
                    changedKeys.UnionWith(await FlushSpoolBatchAsync(
                        evidenceBatch,
                        catalogBatch,
                        exploitBatch,
                        threatScoreBatch,
                        replaceLogicalSource,
                        ct));
            }
            if (errors > 0)
                throw new InvalidDataException($"Spool import contained {errors} invalid records.");
            if (IsNucleiSpoolSource(sourceCode))
            {
                var expectedRecordCount = EnsureCurrentNucleiSnapshot(nucleiSnapshotId);
                var distinctRawIds = exploitBatch
                    .Select(exploit => exploit.RawIndexId)
                    .Distinct()
                    .Count();
                if (records != expectedRecordCount ||
                    exploitBatch.Count != expectedRecordCount ||
                    distinctRawIds != expectedRecordCount)
                {
                    throw new InvalidDataException(
                        $"Nuclei spool is not a complete checkpoint snapshot: expected={expectedRecordCount}, " +
                        $"records={records}, exploits={exploitBatch.Count}, distinctRawIds={distinctRawIds}.");
                }
                await store.ApplyNucleiSnapshotAsync(exploitBatch, nucleiSnapshotId!, ct);
            }
            else
            {
                changedKeys.UnionWith(await FlushSpoolBatchAsync(
                    evidenceBatch,
                    catalogBatch,
                    exploitBatch,
                    threatScoreBatch,
                    replaceLogicalSource,
                    ct));
            }

            File.Move(processingPath, stagedPath, overwrite: true);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            File.Move(processingPath, readyPath, overwrite: true);
            throw;
        }
        catch
        {
            var failedPath = processingPath[..^".processing".Length] + ".failed";
            File.Move(processingPath, failedPath, overwrite: true);
            throw;
        }

        watch.Stop();
        var result = new DuckDbSpoolFileResult(
            Path.GetFileName(readyPath),
            sourceCode ?? "unknown",
            records,
            affectedFacts,
            errors,
            inputBytes,
            watch.ElapsedMilliseconds);
        logger.LogInformation(
            "DuckDB-first spool imported {SourceCode}: records={Records}, facts={Facts}, elapsed={Elapsed}ms.",
            result.sourceCode, result.records, result.affectedFacts, result.elapsedMs);
        return new SpoolFileIngestOutcome(
            result,
            changedKeys,
            sourceReset && sourceCode?.EndsWith("-init", StringComparison.OrdinalIgnoreCase) == true,
            affectedFacts > 0 || removedSourceAffectedFacts,
            stagedPath);
    }

    private static void RecoverInterruptedSpoolFiles(string incoming)
    {
        foreach (var path in Directory.EnumerateFiles(incoming, "*.ndjson.processing")
                     .Concat(Directory.EnumerateFiles(incoming, "*.ndjson.staged")))
        {
            var suffix = path.EndsWith(".processing", StringComparison.Ordinal)
                ? ".processing"
                : ".staged";
            var readyPath = path[..^suffix.Length] + ".ready";
            File.Move(path, readyPath, overwrite: true);
        }
    }

    private static void FinalizeStagedFiles(IEnumerable<SpoolFileIngestOutcome> outcomes, bool deleteOnSuccess)
    {
        foreach (var outcome in outcomes)
        {
            if (!File.Exists(outcome.StagedPath)) continue;
            if (deleteOnSuccess)
                File.Delete(outcome.StagedPath);
            else
                File.Move(
                    outcome.StagedPath,
                    outcome.StagedPath[..^".staged".Length] + ".completed",
                    overwrite: true);
        }
    }

    private static void RestoreStagedFiles(IEnumerable<SpoolFileIngestOutcome> outcomes)
    {
        foreach (var outcome in outcomes)
        {
            if (!File.Exists(outcome.StagedPath)) continue;
            File.Move(
                outcome.StagedPath,
                outcome.StagedPath[..^".staged".Length] + ".ready",
                overwrite: true);
        }
    }

    private void CleanupCompletedSourceMirrors(
        string incoming,
        IEnumerable<SpoolFileIngestOutcome> outcomes)
    {
        foreach (var sourceCode in outcomes
                     .Select(outcome => outcome.Result.sourceCode)
                     .Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var mirrorName = sourceCode.ToLowerInvariant() switch
            {
                "osv-init" => "osv-all.zip",
                "android-osv-init" => "osv-android-all.zip",
                _ => null
            };
            if (mirrorName is null || HasOutstandingSourceSpool(incoming, sourceCode)) continue;

            var spoolRoot = Directory.GetParent(incoming)?.FullName;
            if (spoolRoot is null) continue;
            var statePath = Path.Combine(spoolRoot, "state", $"{sourceCode}.json");
            if (!CheckpointIsComplete(statePath)) continue;

            var repoRoot = store.Options.RepoRoot
                ?? Directory.GetCurrentDirectory();
            var mirrorPath = Path.Combine(repoRoot, "data", "mirrors", mirrorName);
            try { File.Delete(mirrorPath); } catch { }
        }
    }

    private int EnsureCurrentNucleiSnapshot(string? snapshotId)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(snapshotId))
                throw new InvalidDataException("Nuclei snapshot id is required.");
            var spoolRoot = Directory.GetParent(ResolveSpoolIncomingPath())?.FullName;
            if (spoolRoot is null)
                throw new InvalidDataException("Nuclei spool root cannot be resolved.");
            var statePath = Path.Combine(spoolRoot, "state", "nuclei-templates.json");
            var checkpoint = JsonNode.Parse(File.ReadAllText(statePath))?["checkpoint"];
            var revision = StringValue(checkpoint?["gitRevision"]);
            var completedRevision = StringValue(checkpoint?["completedGitRevision"]);
            var expectedRecordCount = IntegerValue(checkpoint?["recordCount"]);
            if (!IsTrue(checkpoint?["snapshotComplete"]) ||
                !string.Equals(snapshotId, revision, StringComparison.Ordinal) ||
                !string.Equals(snapshotId, completedRevision, StringComparison.Ordinal) ||
                expectedRecordCount is not > 0)
            {
                throw new InvalidDataException(
                    "Nuclei spool revision is not the current completed checkpoint revision with a positive recordCount.");
            }
            return expectedRecordCount.Value;
        }
        catch (InvalidDataException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new InvalidDataException("Nuclei checkpoint could not be validated for spool recovery.", ex);
        }
    }

    private static bool HasOutstandingSourceSpool(string incoming, string sourceCode)
    {
        var prefix = $"{sourceCode}-";
        return Directory.EnumerateFiles(incoming)
            .Select(Path.GetFileName)
            .Any(name => name is not null
                && name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                && (name.EndsWith(".ready", StringComparison.Ordinal)
                    || name.EndsWith(".processing", StringComparison.Ordinal)
                    || name.EndsWith(".staged", StringComparison.Ordinal)
                    || name.EndsWith(".failed", StringComparison.Ordinal)));
    }

    private static bool CheckpointIsComplete(string statePath)
    {
        try
        {
            return JsonNode.Parse(File.ReadAllText(statePath))?["checkpoint"]?["initComplete"]?.GetValue<bool>() == true;
        }
        catch
        {
            return false;
        }
    }

    private static string SpoolRunPrefix(string path)
    {
        var name = Path.GetFileName(path);
        var match = Regex.Match(name, @"-s(?<sequence>\d+)\.ndjson\.ready$");
        return match.Success
            ? name[..match.Index]
            : name[..^".ndjson.ready".Length];
    }

    private static int SpoolSequence(string path)
    {
        var match = Regex.Match(Path.GetFileName(path), @"-s(?<sequence>\d+)\.ndjson\.ready$");
        return match.Success && int.TryParse(match.Groups["sequence"].Value, out var sequence)
            ? sequence
            : 0;
    }

    private async Task<IReadOnlyList<string>> FlushSpoolBatchAsync(
        List<DuckDbEvidenceRecord> evidence,
        List<DuckDbCatalogRecord> catalog,
        List<DuckDbExploit> exploits,
        List<DuckDbThreatScore> threatScores,
        bool appendOnly,
        CancellationToken ct)
    {
        if (evidence.Count == 0 && catalog.Count == 0 && exploits.Count == 0 && threatScores.Count == 0)
            return [];

        IReadOnlyList<DuckDbCatalogRecord> changedCatalog = catalog;
        IReadOnlyList<DuckDbEvidenceRecord> changedEvidence = evidence;
        IReadOnlyList<string> previousKeys = [];
        if (!appendOnly && catalog.Count > 0)
        {
            changedCatalog = await store.FilterChangedCatalogRecordsAsync(catalog, ct);
            previousKeys = await store.GetExistingCatalogKeysAsync(changedCatalog, ct);
            var changedRecords = changedCatalog
                .Select(record => SourceRecordIdentity(record.SourceCode, record.SourceRecordId))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            changedEvidence = evidence
                .Where(record => changedRecords.Contains(
                    SourceRecordIdentity(record.SourceCode, record.SourceRecordId)))
                .ToArray();
        }

        if (appendOnly)
            await store.AppendSpoolBatchAsync(evidence, catalog, exploits, threatScores, ct);
        else
        {
            await store.ReplaceRecordsAsync(changedEvidence, ct);
            await store.ReplaceCatalogRecordsAsync(changedCatalog, ct);
            await store.ReplaceSpoolSupplementalAsync(exploits, threatScores, ct);
        }
        var changedKeys = changedCatalog
            .Select(record => record.VulnerabilityKey)
            .Concat(previousKeys)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        evidence.Clear();
        catalog.Clear();
        exploits.Clear();
        threatScores.Clear();
        return changedKeys;
    }

    private static string SourceRecordIdentity(string sourceCode, string sourceRecordId) =>
        $"{sourceCode}\u001f{sourceRecordId}";

    private static ParsedSpoolRecord BuildSpoolRecords(JsonObject envelope)
    {
        var inputSourceCode = envelope["sourceCode"]?.GetValue<string>()
            ?? throw new InvalidDataException("sourceCode is required.");
        var evidenceSourceCode = CanonicalEvidenceSourceCode(inputSourceCode);
        var externalKey = envelope["externalKey"]?.GetValue<string>()
            ?? throw new InvalidDataException("externalKey is required.");
        var externalId = envelope["externalId"]?.GetValue<string>() ?? externalKey;
        var recordHash = envelope["recordHash"]?.GetValue<string>() ?? string.Empty;
        var sourceUrl = envelope["sourceUrl"]?.GetValue<string>();
        var publishedAt = envelope["publishedAt"]?.GetValue<string>();
        var modifiedAt = envelope["modifiedAt"]?.GetValue<string>();
        var payload = envelope["payload"] ?? throw new InvalidDataException("payload is required.");
        var rawId = DeterministicGuid($"raw:{evidenceSourceCode}:{externalKey}");

        string key;
        string? title;
        string? description;
        string? status;
        string[] identifiers;
        string[] upstreamIdentifiers = [];
        string[] relatedIdentifiers = [];
        var normalizationVersion = "catalog-v1";
        IReadOnlyList<DuckDbAffectedFact> affected;
        IReadOnlyList<DuckDbSeverityScore> severity;
        IReadOnlyList<DuckDbReference> references;
        IReadOnlyList<DuckDbWeakness> weaknesses;
        DuckDbExploit? exploit = null;
        DuckDbThreatScore? threatScore = null;

        switch (inputSourceCode.ToLowerInvariant())
        {
            case "nvd-cve":
            case "nvd-cve-init":
                {
                    var cve = payload["cve"] ?? payload;
                    key = cve["id"]?.GetValue<string>() ?? externalKey;
                    identifiers = [Identifier.Normalize(key)];
                    description = FirstLocalizedValue(cve["descriptions"], "en");
                    title = description is { Length: <= 220 } ? description : null;
                    status = cve["vulnStatus"]?.GetValue<string>();
                    publishedAt ??= cve["published"]?.GetValue<string>();
                    modifiedAt ??= cve["lastModified"]?.GetValue<string>();
                    affected = ExtractNvdFacts(cve["configurations"]).ToList();
                    severity = ExtractNvdSeverity(cve["metrics"]).ToList();
                    references = ExtractReferences(cve["references"]).ToList();
                    weaknesses = ExtractNvdWeaknesses(cve["weaknesses"]).ToList();
                    break;
                }
            case "osv":
            case "osv-init":
            case "ghsa-init":
            case "android-osv":
            case "android-osv-init":
            case "google-osv":
            case "google-osv-init":
            case "maven-osv":
            case "maven-osv-init":
            case "go-advisory":
            case "cargo-advisory":
            case "ubuntu-osv":
            case "pypi-advisory":
                {
                    var osvId = payload["id"]?.GetValue<string>() ?? externalId;
                    var aliases = StringArray(payload["aliases"]);
                    var directCveAliases = aliases
                        .Select(Identifier.Normalize)
                        .Where(Identifier.IsCve)
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToArray();
                    identifiers = OsvIdentifierExtractor.Extract(osvId, aliases, payload)
                        .Select(Identifier.Normalize)
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToArray();
                    upstreamIdentifiers = OsvIdentifierExtractor.ExtractUpstream(payload);
                    relatedIdentifiers = OsvIdentifierExtractor.ExtractRelated(payload);
                    if (directCveAliases.Length > 1)
                    {
                        // Several direct CVE aliases are ambiguous identity evidence. Keep the
                        // advisory independent, but retain every CVE as a searchable relation.
                        relatedIdentifiers = relatedIdentifiers
                            .Concat(directCveAliases)
                            .Distinct(StringComparer.OrdinalIgnoreCase)
                            .ToArray();
                    }
                    normalizationVersion = "osv-relations-v3";
                    key = osvId;
                    title = payload["summary"]?.GetValue<string>();
                    description = payload["details"]?.GetValue<string>() ?? title;
                    status = payload["withdrawn"] is null ? "active" : "withdrawn";
                    publishedAt ??= payload["published"]?.GetValue<string>();
                    modifiedAt ??= payload["modified"]?.GetValue<string>();
                    affected = ExtractOsvFacts(payload["affected"]).ToList();
                    severity = ExtractOsvSeverity(payload["severity"]).ToList();
                    references = ExtractReferences(payload["references"]).ToList();
                    weaknesses = [];
                    break;
                }
            case "ghsa":
            case "npm-advisory":
            case "npm-audit":
                {
                    identifiers = GenericIdentifiers(envelope, payload, externalId);
                    key = externalId;
                    title = StringValue(payload["summary"]);
                    description = StringValue(payload["description"]) ?? title;
                    status = StringValue(payload["withdrawn_at"]) is null ? "active" : "withdrawn";
                    publishedAt ??= StringValue(payload["published_at"]);
                    modifiedAt ??= StringValue(payload["updated_at"]);
                    affected = ExtractGhsaFacts(payload["vulnerabilities"]).ToList();
                    severity = ExtractGenericSeverity(payload).ToList();
                    references = ExtractReferences(payload["references"]).ToList();
                    weaknesses = ExtractGenericWeaknesses(payload["cwes"]).ToList();
                    break;
                }
            case "cve-list-v5":
                {
                    var metadata = payload["cveMetadata"];
                    var cna = payload["containers"]?["cna"];
                    identifiers = GenericIdentifiers(envelope, payload, externalId)
                        .Append(StringValue(metadata?["cveId"]) ?? externalId)
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToArray();
                    key = StringValue(metadata?["cveId"]) ?? PreferredIdentifier(identifiers, externalId);
                    title = StringValue(cna?["title"]);
                    description = FirstLocalizedValue(cna?["descriptions"], "en") ?? title;
                    status = StringValue(metadata?["state"]) ?? "active";
                    publishedAt ??= StringValue(metadata?["datePublished"]);
                    modifiedAt ??= StringValue(metadata?["dateUpdated"]);
                    affected = ExtractCveListFacts(cna).ToList();
                    severity = [];
                    references = ExtractCveListReferences(cna?["references"]).ToList();
                    weaknesses = [];
                    break;
                }
            case "cisa-kev":
                {
                    identifiers = GenericIdentifiers(envelope, payload, externalId);
                    key = StringValue(payload["cveID"]) ?? PreferredIdentifier(identifiers, externalId);
                    title = StringValue(payload["vulnerabilityName"]);
                    description = StringValue(payload["shortDescription"]) ?? title;
                    status = "known-exploited";
                    publishedAt ??= StringValue(payload["dateAdded"]);
                    affected = GenericProductFacts(payload, inputSourceCode).ToList();
                    severity = [];
                    references = GenericReferences(payload, sourceUrl, "kev");
                    weaknesses = [];
                    break;
                }
            case "first-epss":
                {
                    identifiers = GenericIdentifiers(envelope, payload, externalId);
                    key = StringValue(payload["cve"]) ?? PreferredIdentifier(identifiers, externalId);
                    title = null;
                    description = null;
                    status = "active";
                    affected = [];
                    severity = [];
                    references = [];
                    weaknesses = [];
                    break;
                }
            default:
                {
                    identifiers = GenericIdentifiers(envelope, payload, externalId);
                    key = externalId;
                    title = FirstString(payload, "title", "summary", "name", "vulnerabilityName");
                    description = FirstString(payload, "description", "details", "shortDescription", "summary") ?? title;
                    status = FirstString(payload, "status", "state") ?? "active";
                    publishedAt ??= FirstString(payload, "publishedAt", "published_at", "published", "dateAdded");
                    modifiedAt ??= FirstString(payload, "modifiedAt", "updated_at", "modified", "updatedAt");
                    affected = GenericProductFacts(payload, inputSourceCode).ToList();
                    severity = ExtractGenericSeverity(payload).ToList();
                    references = GenericReferences(payload, sourceUrl, "advisory");
                    weaknesses = ExtractGenericWeaknesses(payload["cwes"] ?? payload["weaknesses"]).ToList();
                    break;
                }
        }

        key = Identifier.Normalize(key);
        var promotedKey = Identifier.ResolveCanonicalIdentity(key, identifiers);
        if (!string.Equals(promotedKey, key, StringComparison.OrdinalIgnoreCase))
        {
            // The original identifier stays below as a searchable alias. Upstream/related IDs are
            // never passed to the resolver because relationships are not identity assertions.
            key = promotedKey;
            normalizationVersion = "identity-links-v4";
        }
        identifiers = identifiers
            .Append(key)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(Identifier.Normalize)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (IsExploitSource(inputSourceCode, payload))
        {
            exploit = new DuckDbExploit(
                evidenceSourceCode,
                rawId,
                StringValue(payload["sourceKey"]) ?? externalId,
                identifiers,
                title,
                StringValue(payload["sourceUrl"]) ?? sourceUrl,
                StringValue(payload["artifactType"]),
                StringValue(payload["exploitType"]),
                StringValue(payload["maturity"]),
                StringValue(payload["verificationStatus"]),
                publishedAt,
                modifiedAt);
        }
        if (string.Equals(inputSourceCode, "first-epss", StringComparison.OrdinalIgnoreCase))
        {
            threatScore = new DuckDbThreatScore(
                evidenceSourceCode,
                rawId,
                key,
                "epss",
                DoubleValue(payload["epss"]),
                DoubleValue(payload["percentile"]),
                StringValue(payload["observedAt"]));
        }
        else if (string.Equals(inputSourceCode, "cisa-kev", StringComparison.OrdinalIgnoreCase))
        {
            threatScore = new DuckDbThreatScore(
                evidenceSourceCode,
                rawId,
                key,
                "known-exploited",
                1,
                null,
                StringValue(payload["dateAdded"]));
        }
        var vulnerabilityId = Identifier.DeterministicVulnerabilityId(key);
        return new ParsedSpoolRecord(
            EmptyRecord(evidenceSourceCode, rawId, key, externalId) with
            {
                AffectedFacts = affected,
                SeverityScores = severity,
                References = references,
                Weaknesses = weaknesses
            },
            new DuckDbCatalogRecord(
                evidenceSourceCode,
                externalId,
                vulnerabilityId,
                key,
                title,
                description,
                status,
                publishedAt,
                modifiedAt,
                sourceUrl,
                recordHash,
                identifiers,
                upstreamIdentifiers,
                relatedIdentifiers,
                normalizationVersion),
            exploit,
            threatScore);
    }

    private static string? FirstLocalizedValue(JsonNode? node, string language)
    {
        foreach (var item in ArrayItems(node))
        {
            var lang = item?["lang"]?.GetValue<string>();
            var value = item?["value"]?.GetValue<string>();
            if (string.Equals(lang, language, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(value))
                return value;
        }
        return null;
    }

    private static string[] StringArray(JsonNode? node) => ArrayItems(node)
        .Select(item => item?.GetValue<string>())
        .Where(value => !string.IsNullOrWhiteSpace(value))
        .Select(value => value!)
        .ToArray();

    private static string[] GenericIdentifiers(JsonObject envelope, JsonNode payload, string externalId)
    {
        var values = new List<string> { externalId };
        values.AddRange(StringArray(envelope["identifiers"]));
        values.AddRange(StringArray(payload["aliases"]));
        foreach (var item in ArrayItems(payload["identifiers"]))
        {
            var value = item switch
            {
                JsonValue => StringValue(item),
                JsonObject obj => StringValue(obj["value"]) ?? StringValue(obj["id"]),
                _ => null
            };
            if (!string.IsNullOrWhiteSpace(value)) values.Add(value);
        }
        return values
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(Identifier.Normalize)
            .Where(Identifier.IsVulnerabilityId)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static string PreferredIdentifier(IEnumerable<string> identifiers, string fallback) =>
        identifiers.FirstOrDefault(value => value.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase))
        ?? identifiers.FirstOrDefault(value => value.StartsWith("GHSA-", StringComparison.OrdinalIgnoreCase))
        ?? identifiers.FirstOrDefault()
        ?? fallback;

    private static string? FirstString(JsonNode payload, params string[] names)
    {
        foreach (var name in names)
        {
            var value = StringValue(payload[name]);
            if (!string.IsNullOrWhiteSpace(value)) return value;
        }
        return null;
    }

    private static double? DoubleValue(JsonNode? node)
    {
        if (node is null) return null;
        try { return node.GetValue<double>(); }
        catch
        {
            return double.TryParse(StringValue(node), System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out var value) ? value : null;
        }
    }

    private static IEnumerable<DuckDbAffectedFact> ExtractGhsaFacts(JsonNode? vulnerabilities)
    {
        foreach (var item in ArrayItems(vulnerabilities))
        {
            var package = item?["package"];
            var ecosystem = FirstString(package ?? new JsonObject(), "ecosystem", "type");
            var name = StringValue(package?["name"]);
            if (string.IsNullOrWhiteSpace(name)) continue;
            var range = StringValue(item?["vulnerable_version_range"]);
            yield return new DuckDbAffectedFact(
                "package", ecosystem, name, ToPurl(ecosystem, name), null, range, "ghsa", true);
        }
    }

    private static IEnumerable<DuckDbAffectedFact> GenericProductFacts(JsonNode payload, string? sourceCode = null)
    {
        if (payload["packages"] is JsonObject packages)
        {
            foreach (var fact in ExtractDebianFacts(packages)) yield return fact;
            yield break;
        }

        var ecosystem = FirstString(payload, "ecosystem", "packageEcosystem") ?? sourceCode switch
        {
            "nuget-advisory" => "nuget",
            "maven-advisory" => "maven",
            "npm-advisory" or "npm-audit" => "npm",
            "pypi-advisory" => "pypi",
            _ => null
        };
        var packageName = FirstString(payload, "packageName", "package_name", "product");
        if (!string.IsNullOrWhiteSpace(packageName))
        {
            var purl = FirstString(payload, "purl") ?? ToPurl(ecosystem, packageName);
            var ranges = ArrayItems(payload["vulnerableRanges"])
                .Select(StringValue)
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(value => value!)
                .ToList();
            var advisoryRange = StringValue(payload["advisory"]?["versions"]);
            if (!string.IsNullOrWhiteSpace(advisoryRange)) ranges.Add(advisoryRange);
            if (ranges.Count == 0)
                yield return new DuckDbAffectedFact("package", ecosystem, packageName, purl, null, null, "source", true);
            else
                foreach (var range in ranges.Distinct(StringComparer.OrdinalIgnoreCase))
                    yield return new DuckDbAffectedFact("package", ecosystem, packageName, purl, null, range, "vendor", true);
        }

        foreach (var item in ArrayItems(payload["affectedProducts"]))
        {
            var name = StringValue(item);
            if (!string.IsNullOrWhiteSpace(name))
                yield return new DuckDbAffectedFact("product", ecosystem, name, null, null, null, "source", true);
        }
        var vendor = StringValue(payload["vendorProject"]);
        var product = StringValue(payload["product"]);
        if (!string.IsNullOrWhiteSpace(product))
        {
            var display = string.IsNullOrWhiteSpace(vendor) ? product : $"{vendor}:{product}";
            yield return new DuckDbAffectedFact("product", null, display, null, null, null, "source", true);
        }
    }

    private static IEnumerable<DuckDbSeverityScore> ExtractGenericSeverity(JsonNode payload)
    {
        var cvssRows = ExtractGhsaSeverity(payload["cvss"]).ToArray();
        foreach (var row in cvssRows) yield return row;
        if (cvssRows.Length > 0) yield break;

        var label = FirstString(payload, "severityLabel", "severity", "hazardLevel");
        var score = DecimalValue(payload["score"] ?? payload["cvssScore"]);
        if (label is not null || score is not null)
            yield return new DuckDbSeverityScore("source", null, "base", null, score, label ?? SeverityFromScore(score!.Value));
    }

    private static IReadOnlyList<DuckDbReference> GenericReferences(JsonNode payload, string? sourceUrl, string refType)
    {
        var references = ExtractReferences(payload["references"]).ToList();
        foreach (var name in new[] { "sourceUrl", "artifactUrl", "notes", "knownRansomwareCampaignUse" })
        {
            var value = StringValue(payload[name]);
            if (Uri.TryCreate(value, UriKind.Absolute, out _))
                references.Add(new DuckDbReference(value!, refType, [refType]));
        }
        if (!string.IsNullOrWhiteSpace(sourceUrl))
            references.Add(new DuckDbReference(sourceUrl, refType, [refType]));
        return references.DistinctBy(reference => reference.Url, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static IEnumerable<DuckDbWeakness> ExtractGenericWeaknesses(JsonNode? weaknesses)
    {
        foreach (var item in ArrayItems(weaknesses))
        {
            if (item is JsonValue)
            {
                var value = StringValue(item);
                if (!string.IsNullOrWhiteSpace(value)) yield return new DuckDbWeakness("CWE", value, null);
                continue;
            }
            var id = StringValue(item?["cwe_id"]) ?? StringValue(item?["id"]);
            var description = StringValue(item?["name"]) ?? StringValue(item?["description"]);
            if (id is not null || description is not null) yield return new DuckDbWeakness("CWE", id, description);
        }
    }

    private static bool IsExploitSource(string sourceCode, JsonNode payload) =>
        payload["sourceKey"] is not null &&
        (payload["artifactType"] is not null || sourceCode is "exploitdb" or "metasploit" or "nuclei-templates" or "poc-in-github" or "trickest-cve" or "seebug");

    private static bool IsNucleiSpoolSource(string? sourceCode) =>
        string.Equals(sourceCode, "nuclei-templates", StringComparison.OrdinalIgnoreCase);

    private static string? NucleiSnapshotId(JsonObject envelope) =>
        StringValue(envelope["snapshotId"]);

    private static bool IsTrue(JsonNode? node) =>
        node is JsonValue value && value.TryGetValue<bool>(out var result) && result;

    private static int? IntegerValue(JsonNode? node)
    {
        if (node is JsonValue value)
        {
            if (value.TryGetValue<int>(out var intValue)) return intValue;
            if (value.TryGetValue<long>(out var longValue) && longValue is >= int.MinValue and <= int.MaxValue)
                return (int)longValue;
        }
        return int.TryParse(StringValue(node), out var parsed) ? parsed : null;
    }

    private static Guid DeterministicGuid(string value)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        Span<byte> bytes = stackalloc byte[16];
        hash.AsSpan(0, 16).CopyTo(bytes);
        bytes[6] = (byte)((bytes[6] & 0x0f) | 0x50);
        bytes[8] = (byte)((bytes[8] & 0x3f) | 0x80);
        return new Guid(bytes);
    }

    private string ResolveSpoolIncomingPath() => store.Options.ResolveSpoolIncoming();

    private static string ResolveReadyFile(string incoming, string requested)
    {
        var candidate = Path.GetFullPath(Path.IsPathRooted(requested) ? requested : Path.Combine(incoming, requested));
        var root = Path.GetFullPath(incoming) + Path.DirectorySeparatorChar;
        if (!candidate.StartsWith(root, StringComparison.Ordinal) || !candidate.EndsWith(".ndjson.ready", StringComparison.Ordinal))
            throw new InvalidOperationException("Spool file must be a .ndjson.ready file inside the configured incoming directory.");
        if (!File.Exists(candidate)) throw new FileNotFoundException("Spool file not found.", candidate);
        return candidate;
    }
}
