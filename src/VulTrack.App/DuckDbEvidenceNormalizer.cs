using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;

namespace VulTrack.App;

public sealed record DuckDbEvidenceNormalizeRequest(
    string? SourceCode,
    int Limit = 1000,
    bool Reset = false,
    int BatchSize = 10000);

public sealed record DuckDbEvidenceSourceResult(
    string sourceCode,
    int records,
    int affectedFacts,
    int severityScores,
    int references,
    int weaknesses,
    long elapsedMs);

public sealed record DuckDbEvidenceNormalizeResult(
    bool ok,
    string path,
    IReadOnlyList<DuckDbEvidenceSourceResult> sources,
    DuckDbEvidenceStats stats);

public sealed class DuckDbEvidenceNormalizer(NpgsqlDataSource db, DuckDbEvidenceStore store, ILogger<DuckDbEvidenceNormalizer> logger)
{
    private static readonly string[] DefaultSources =
    [
        "debian-security-tracker",
        "osv",
        "ubuntu-osv",
        "android-osv",
        "google-osv",
        "ghsa",
        "maven-osv",
        "maven-advisory",
        "cve-list-v5",
        "nvd-cve",
        "nvd-cpe",
        "suse-csaf",
        "alpine-secdb",
        "redhat-csaf",
        "nuget-advisory",
        "npm-advisory",
        "npm-audit",
        "pypi-advisory",
        "go-advisory",
        "cargo-advisory",
        "first-epss",
        "cisa-kev",
        "exploitdb",
        "poc-in-github",
        "nuclei-templates",
        "metasploit",
        "trickest-cve",
        "cnnvd"
    ];

    public async Task<DuckDbEvidenceNormalizeResult> NormalizeAsync(DuckDbEvidenceNormalizeRequest request, CancellationToken ct)
    {
        if (request.Reset) await store.ResetAsync(ct);
        else await store.InitializeAsync(ct);

        var limit = Math.Clamp(request.Limit <= 0 ? 5000000 : request.Limit, 1, 5000000);
        var batchSize = Math.Clamp(request.BatchSize <= 0 ? 10000 : request.BatchSize, 1, limit);
        var sourceCodes = string.IsNullOrWhiteSpace(request.SourceCode)
            ? DefaultSources
            : request.SourceCode.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        var results = new List<DuckDbEvidenceSourceResult>();

        foreach (var sourceCode in sourceCodes)
        {
            var watch = Stopwatch.StartNew();
            var recordsRead = 0;
            var affectedFacts = 0;
            var severityScores = 0;
            var references = 0;
            var weaknesses = 0;
            if (sourceCode.Equals("nvd-cpe", StringComparison.OrdinalIgnoreCase))
            {
                recordsRead = await RebuildCpeEntriesAsync(limit, ct);
                watch.Stop();
                var cpeResult = new DuckDbEvidenceSourceResult(sourceCode, recordsRead, 0, 0, 0, 0, watch.ElapsedMilliseconds);
                results.Add(cpeResult);
                logger.LogInformation("DuckDB evidence normalized {SourceCode}: records={Records}, elapsed={Elapsed}ms.",
                    sourceCode, cpeResult.records, cpeResult.elapsedMs);
                continue;
            }

            for (var offset = 0; offset < limit; offset += batchSize)
            {
                var take = Math.Min(batchSize, limit - offset);
                var records = await LoadSourceAsync(sourceCode, take, offset, ct);
                if (records.Count == 0) break;
                await store.ReplaceRecordsAsync(records, ct);
                recordsRead += records.Count;
                affectedFacts += records.Sum(x => x.AffectedFacts.Count);
                severityScores += records.Sum(x => x.SeverityScores.Count);
                references += records.Sum(x => x.References.Count);
                weaknesses += records.Sum(x => x.Weaknesses.Count);
            }
            watch.Stop();
            var result = new DuckDbEvidenceSourceResult(
                sourceCode,
                recordsRead,
                affectedFacts,
                severityScores,
                references,
                weaknesses,
                watch.ElapsedMilliseconds);
            results.Add(result);
            logger.LogInformation("DuckDB evidence normalized {SourceCode}: records={Records}, facts={Facts}, refs={References}, elapsed={Elapsed}ms.",
                sourceCode, result.records, result.affectedFacts, result.references, result.elapsedMs);
        }

        return new DuckDbEvidenceNormalizeResult(true, store.DatabasePath, results, await store.StatsAsync(ct));
    }

    private Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadSourceAsync(string sourceCode, int limit, int offset, CancellationToken ct) =>
        sourceCode.ToLowerInvariant() switch
        {
            "debian-security-tracker" => LoadDebianAsync(limit, offset, ct),
            "osv" => LoadOsvAsync("osv", "stg_osv_vulnerabilities", limit, offset, ct),
            "ubuntu-osv" => LoadOsvAsync("ubuntu-osv", "stg_ubuntu_osv", limit, offset, ct),
            "android-osv" => LoadOsvAsync("android-osv", "stg_android_osv", limit, offset, ct),
            "google-osv" => LoadGoogleOsvAsync(limit, offset, ct),
            "ghsa" => LoadGhsaAsync("ghsa", limit, offset, ct),
            "maven-osv" => LoadOsvAsync("maven-osv", "stg_osv_vulnerabilities", limit, offset, ct),
            "maven-advisory" => LoadEcosystemAsync("maven-advisory", "osv-maven-query", limit, offset, ct),
            "cve-list-v5" => LoadCveListAsync(limit, offset, ct),
            "nvd-cve" => LoadNvdAsync(limit, offset, ct),
            "suse-csaf" => LoadCsafAsync("suse-csaf", limit, offset, ct),
            "alpine-secdb" => LoadAlpineAsync(limit, offset, ct),
            "redhat-csaf" => LoadCsafAsync("redhat-csaf", limit, offset, ct),
            "nuget-advisory" => LoadEcosystemAsync("nuget-advisory", "nuget-vulnerability-info", limit, offset, ct),
            "npm-advisory" => LoadNpmAdvisoryAsync("npm-advisory", limit, offset, ct),
            "npm-audit" => LoadNpmAdvisoryAsync("npm-audit", limit, offset, ct),
            "pypi-advisory" => LoadPypiAdvisoryAsync(limit, offset, ct),
            "go-advisory" => LoadOsvAsync("go-advisory", "stg_osv_vulnerabilities", limit, offset, ct),
            "cargo-advisory" => LoadOsvAsync("cargo-advisory", "stg_osv_vulnerabilities", limit, offset, ct),
            "first-epss" => LoadThreatIntelAsync("first-epss", limit, offset, ct),
            "cisa-kev" => LoadThreatIntelAsync("cisa-kev", limit, offset, ct),
            "exploitdb" => LoadExploitAsync("exploitdb", limit, offset, ct),
            "poc-in-github" => LoadExploitAsync("poc-in-github", limit, offset, ct),
            "nuclei-templates" => LoadExploitAsync("nuclei-templates", limit, offset, ct),
            "metasploit" => LoadExploitAsync("metasploit", limit, offset, ct),
            "trickest-cve" => LoadExploitAsync("trickest-cve", limit, offset, ct),
            "cnnvd" => LoadCnnvdAsync(limit, offset, ct),
            _ => Task.FromResult<IReadOnlyList<DuckDbEvidenceRecord>>([])
        };

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadDebianAsync(int limit, int offset, CancellationToken ct)
    {
        await using var command = db.CreateCommand("""
            select raw_index_id, cve_id, packages::text
            from stg_debian_security_tracker s
            join source_raw_index r on r.id = s.raw_index_id
            where r.normalize_status <> 'superseded'
            order by s.raw_index_id
            limit $1
            offset $2
            """);
        command.CommandTimeout = 300;
        command.Parameters.AddWithValue(limit);
        command.Parameters.AddWithValue(offset);
        var records = new List<DuckDbEvidenceRecord>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var rawIndexId = reader.GetGuid(0);
            var key = reader.GetString(1);
            var packages = JsonNode.Parse(reader.GetString(2));
            records.AddRange(BuildDebianRecords(rawIndexId, key, packages));
        }
        return records;
    }

    private static IEnumerable<DuckDbEvidenceRecord> BuildDebianRecords(Guid rawIndexId, string key, JsonNode? packages)
    {
        if (IsDebianVulnerabilityIdentifier(key))
        {
            var facts = ExtractDebianFacts(packages).ToList();
            if (facts.Count > 0)
                yield return EmptyRecord("debian-security-tracker", rawIndexId, key, key) with { AffectedFacts = facts };
            yield break;
        }

        if (packages is not JsonObject cves) yield break;
        var packageName = key;
        foreach (var (identifier, advisory) in cves)
        {
            if (!IsDebianVulnerabilityIdentifier(identifier)) continue;
            var facts = ExtractDebianFacts(packageName, advisory).ToList();
            if (facts.Count > 0)
                yield return EmptyRecord("debian-security-tracker", rawIndexId, identifier, packageName) with { AffectedFacts = facts };
        }
    }

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadOsvAsync(string sourceCode, string tableName, int limit, int offset, CancellationToken ct)
    {
        await using var command = db.CreateCommand($"""
            with source_record_ids as (
              select s.raw_index_id
              from {tableName} s
              join source_raw_index r on r.id = s.raw_index_id
              join sources src on src.id = r.source_id
              where src.code = $1
                and r.normalize_status <> 'superseded'
              order by s.raw_index_id
              limit $2
              offset $3
            )
            select s.raw_index_id, s.osv_id, s.aliases, s.payload::text
            from {tableName} s
            join source_record_ids ids on ids.raw_index_id = s.raw_index_id
            order by s.raw_index_id
            """);
        command.CommandTimeout = 300;
        command.Parameters.AddWithValue(sourceCode);
        command.Parameters.AddWithValue(limit);
        command.Parameters.AddWithValue(offset);

        var records = new List<DuckDbEvidenceRecord>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var rawIndexId = reader.GetGuid(0);
            var osvId = reader.GetString(1);
            var aliases = reader.GetFieldValue<string[]>(2);
            var key = PreferredIdentifier(osvId, aliases);
            var payload = JsonNode.Parse(reader.GetString(3));
            records.Add(EmptyRecord(sourceCode, rawIndexId, key, osvId) with
            {
                AffectedFacts = ExtractOsvFacts(payload?["affected"]).ToList(),
                SeverityScores = ExtractOsvSeverity(payload?["severity"]).ToList(),
                References = ExtractReferences(payload?["references"]).ToList()
            });
        }
        return records;
    }

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadGoogleOsvAsync(int limit, int offset, CancellationToken ct)
    {
        var androidRows = await CountOsvRowsAsync("google-osv", "stg_android_osv", ct);
        if (offset < androidRows)
        {
            var firstTake = Math.Min(limit, androidRows - offset);
            var records = (await LoadOsvAsync("google-osv", "stg_android_osv", firstTake, offset, ct)).ToList();
            var remaining = limit - firstTake;
            if (remaining > 0)
                records.AddRange(await LoadOsvAsync("google-osv", "stg_osv_vulnerabilities", remaining, 0, ct));
            return records;
        }

        return await LoadOsvAsync("google-osv", "stg_osv_vulnerabilities", limit, offset - androidRows, ct);
    }

    private async Task<int> CountOsvRowsAsync(string sourceCode, string tableName, CancellationToken ct)
    {
        await using var command = db.CreateCommand($"""
            select count(*)::integer
            from {tableName} s
            join source_raw_index r on r.id = s.raw_index_id
            join sources src on src.id = r.source_id
            where src.code = $1
              and r.normalize_status <> 'superseded'
            """);
        command.Parameters.AddWithValue(sourceCode);
        command.CommandTimeout = 300;
        return (int)(await command.ExecuteScalarAsync(ct) ?? 0);
    }

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadGhsaAsync(string sourceCode, int limit, int offset, CancellationToken ct)
    {
        await using var command = db.CreateCommand("""
            select s.raw_index_id, s.ghsa_id, s.cve_id, s.ecosystem, s.package_name, s.vulnerable_ranges::text,
                   cvss::text, cwes::text, references_json::text, payload::text
            from stg_ghsa_advisories s
            join source_raw_index r on r.id = s.raw_index_id
            join sources src on src.id = r.source_id
            where src.code = $1
              and r.normalize_status <> 'superseded'
            order by s.raw_index_id
            limit $2
            offset $3
            """);
        command.CommandTimeout = 300;
        command.Parameters.AddWithValue(sourceCode);
        command.Parameters.AddWithValue(limit);
        command.Parameters.AddWithValue(offset);

        var records = new List<DuckDbEvidenceRecord>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var rawIndexId = reader.GetGuid(0);
            var ghsaId = reader.GetString(1);
            var cve = reader.IsDBNull(2) ? null : reader.GetString(2);
            var ecosystem = reader.IsDBNull(3) ? null : reader.GetString(3);
            var packageName = reader.IsDBNull(4) ? null : reader.GetString(4);
            var key = string.IsNullOrWhiteSpace(cve) ? ghsaId : cve;
            var vulnerableRanges = JsonNode.Parse(reader.GetString(5));
            var cvss = JsonNode.Parse(reader.GetString(6));
            var cwes = JsonNode.Parse(reader.GetString(7));
            var references = JsonNode.Parse(reader.GetString(8));
            records.Add(EmptyRecord(sourceCode, rawIndexId, key, ghsaId) with
            {
                AffectedFacts = ExtractVendorRangeFacts(ecosystem, packageName, vulnerableRanges).ToList(),
                SeverityScores = ExtractGhsaSeverity(cvss).ToList(),
                Weaknesses = ExtractGhsaWeaknesses(cwes).ToList(),
                References = ExtractReferences(references).ToList()
            });
        }
        return records;
    }

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadNvdAsync(int limit, int offset, CancellationToken ct)
    {
        await using var command = db.CreateCommand("""
            select raw_index_id, cve_id, configurations::text, metrics::text, weaknesses::text, references_json::text
            from stg_nvd_cves s
            join source_raw_index r on r.id = s.raw_index_id
            where r.normalize_status <> 'superseded'
            order by s.raw_index_id
            limit $1
            offset $2
            """);
        command.CommandTimeout = 300;
        command.Parameters.AddWithValue(limit);
        command.Parameters.AddWithValue(offset);

        var records = new List<DuckDbEvidenceRecord>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var rawIndexId = reader.GetGuid(0);
            var cveId = reader.GetString(1);
            records.Add(EmptyRecord("nvd-cve", rawIndexId, cveId, cveId) with
            {
                AffectedFacts = ExtractNvdFacts(JsonNode.Parse(reader.GetString(2))).ToList(),
                SeverityScores = ExtractNvdSeverity(JsonNode.Parse(reader.GetString(3))).ToList(),
                Weaknesses = ExtractNvdWeaknesses(JsonNode.Parse(reader.GetString(4))).ToList(),
                References = ExtractReferences(JsonNode.Parse(reader.GetString(5))).ToList()
            });
        }
        return records;
    }

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadCveListAsync(int limit, int offset, CancellationToken ct)
    {
        await using var command = db.CreateCommand("""
            select s.raw_index_id, s.cve_id, s.containers_cna::text
            from stg_cve_list_records s
            join source_raw_index r on r.id = s.raw_index_id
            where r.normalize_status <> 'superseded'
            order by s.raw_index_id
            limit $1
            offset $2
            """);
        command.CommandTimeout = 300;
        command.Parameters.AddWithValue(limit);
        command.Parameters.AddWithValue(offset);

        var records = new List<DuckDbEvidenceRecord>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var rawIndexId = reader.GetGuid(0);
            var cveId = reader.GetString(1);
            var cna = JsonNode.Parse(reader.GetString(2));
            records.Add(EmptyRecord("cve-list-v5", rawIndexId, cveId, cveId) with
            {
                AffectedFacts = ExtractCveListFacts(cna).ToList(),
                References = ExtractCveListReferences(cna?["references"]).ToList()
            });
        }
        return records;
    }

    private static IEnumerable<DuckDbAffectedFact> ExtractDebianFacts(JsonNode? packages)
    {
        if (packages is not JsonObject obj) yield break;
        foreach (var (packageName, advisory) in obj)
        {
            if (string.IsNullOrWhiteSpace(packageName)) continue;
            foreach (var fact in ExtractDebianFacts(packageName, advisory))
                yield return fact;
        }
    }

    private static IEnumerable<DuckDbAffectedFact> ExtractDebianFacts(string packageName, JsonNode? advisory)
    {
        if (advisory?["releases"] is not JsonObject releases) yield break;
        foreach (var (release, item) in releases)
        {
            var status = item?["status"]?.GetValue<string>()?.ToLowerInvariant();
            var fixedVersion = item?["fixed_version"]?.GetValue<string>();
            var range = status switch
            {
                "open" => ">= 0",
                "resolved" when !string.IsNullOrWhiteSpace(fixedVersion) && fixedVersion != "0" => $"< {fixedVersion}",
                _ => null
            };
            if (range is null) continue;
            yield return new DuckDbAffectedFact(
                "package",
                DebianEcosystem(release),
                packageName,
                $"pkg:deb/debian/{Uri.EscapeDataString(packageName)}",
                null,
                range,
                $"security-tracker:{status}",
                true);
        }
    }

    private static IEnumerable<DuckDbAffectedFact> ExtractOsvFacts(JsonNode? affected)
    {
        foreach (var item in ArrayItems(affected))
        {
            var package = item?["package"];
            var ecosystem = package?["ecosystem"]?.GetValue<string>();
            var name = package?["name"]?.GetValue<string>();
            var purl = package?["purl"]?.GetValue<string>() ?? ToPurl(ecosystem, name);
            var hadRange = false;
            var rangesNode = item?["ranges"];
            foreach (var range in ArrayItems(rangesNode))
            {
                hadRange = true;
                yield return new DuckDbAffectedFact("package", ecosystem, name, purl, null, OsvRange(range), range?["type"]?.GetValue<string>(), true);
            }

            if (!hadRange && rangesNode is null && !string.IsNullOrWhiteSpace(name))
                yield return new DuckDbAffectedFact("package", ecosystem, name, purl, null, null, null, true);
        }
    }

    private static IEnumerable<DuckDbAffectedFact> ExtractVendorRangeFacts(string? ecosystem, string? packageName, JsonNode? rangesNode)
    {
        if (string.IsNullOrWhiteSpace(packageName)) yield break;
        var ranges = ArrayItems(rangesNode)
            .Select(x => x?.GetValue<string>())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x!)
            .ToArray();
        if (ranges.Length == 0)
        {
            yield return new DuckDbAffectedFact("package", ecosystem, packageName, ToPurl(ecosystem, packageName), null, null, "vendor", true);
            yield break;
        }
        foreach (var range in ranges)
        {
            yield return new DuckDbAffectedFact("package", ecosystem, packageName, ToPurl(ecosystem, packageName), null, range, "vendor", true);
        }
    }

    private static IEnumerable<DuckDbAffectedFact> ExtractNvdFacts(JsonNode? configurations)
    {
        foreach (var cpeMatch in WalkCpeMatches(configurations))
        {
            var criteria = cpeMatch?["criteria"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(criteria)) continue;
            var range = CpeRange(cpeMatch);
            yield return new DuckDbAffectedFact(
                "cpe",
                "cpe",
                ParseCpeProduct(criteria),
                null,
                criteria,
                range,
                range is null ? "cpe_match_no_range" : "cpe_match",
                cpeMatch?["vulnerable"]?.GetValue<bool>() ?? true);
        }
    }

    private static IEnumerable<DuckDbAffectedFact> ExtractCveListFacts(JsonNode? cna)
    {
        foreach (var affected in ArrayItems(cna?["affected"]))
        {
            var vendor = affected?["vendor"]?.GetValue<string>();
            var product = affected?["product"]?.GetValue<string>();
            var name = string.Join(':', new[] { vendor, product }.Where(x => !string.IsNullOrWhiteSpace(x)));
            if (string.IsNullOrWhiteSpace(name)) continue;
            foreach (var version in ArrayItems(affected?["versions"]))
            {
                var status = version?["status"]?.GetValue<string>();
                if (!string.Equals(status, "affected", StringComparison.OrdinalIgnoreCase)) continue;
                var lessThan = version?["lessThan"]?.GetValue<string>();
                var lessThanOrEqual = version?["lessThanOrEqual"]?.GetValue<string>();
                var exactVersion = version?["version"]?.GetValue<string>();
                string? rawRange;
                if (exactVersion is not null && lessThan is not null)
                    rawRange = $">= {exactVersion}, < {lessThan}";
                else if (exactVersion is not null && lessThanOrEqual is not null)
                    rawRange = $">= {exactVersion}, <= {lessThanOrEqual}";
                else if (lessThan is not null)
                    rawRange = $"< {lessThan}";
                else if (lessThanOrEqual is not null)
                    rawRange = $"<= {lessThanOrEqual}";
                else if (exactVersion is not null)
                    rawRange = $"= {exactVersion}";
                else
                    rawRange = version?.ToJsonString();
                yield return new DuckDbAffectedFact("package", null, name, null, null, rawRange, "cve-list", true);
            }
        }
    }

    private static IEnumerable<DuckDbReference> ExtractCveListReferences(JsonNode? references)
    {
        foreach (var reference in ArrayItems(references))
        {
            var url = reference?["url"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(url)) continue;
            var tags = ArrayItems(reference?["tags"])
                .Select(x => x?.GetValue<string>())
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(x => x!)
                .ToArray();
            yield return new DuckDbReference(url, null, tags);
        }
    }

    private static IEnumerable<DuckDbSeverityScore> ExtractOsvSeverity(JsonNode? severity)
    {
        foreach (var item in ArrayItems(severity))
        {
            var type = item?["type"]?.GetValue<string>() ?? "vendor";
            var scoreText = item?["score"]?.GetValue<string>();
            var versionFromType = CvssVersionFromType(type);
            var calculatedScore = CvssScoreCalculator.CalculateBaseScore(scoreText, versionFromType);
            var vector = scoreText?.StartsWith("CVSS:", StringComparison.OrdinalIgnoreCase) == true || calculatedScore is not null
                ? scoreText
                : null;
            var numeric = DecimalValue(item?["score"]);
            var score = numeric ?? calculatedScore;
            var version = CvssVersion(vector) ?? versionFromType;
            yield return new DuckDbSeverityScore(
                type.StartsWith("CVSS", StringComparison.OrdinalIgnoreCase) ? "cvss" : type.ToLowerInvariant(),
                version,
                "base",
                vector,
                score,
                score is null ? null : SeverityFromScore(score.Value, version));
        }
    }

    private static IEnumerable<DuckDbSeverityScore> ExtractGhsaSeverity(JsonNode? cvss)
    {
        var vector = cvss?["vector_string"]?.GetValue<string>() ?? cvss?["vector"]?.GetValue<string>();
        var score = DecimalValue(cvss?["score"]);
        var version = vector?.StartsWith("CVSS:4.", StringComparison.OrdinalIgnoreCase) == true ? "4.0"
            : vector?.StartsWith("CVSS:3.1", StringComparison.OrdinalIgnoreCase) == true ? "3.1"
            : vector?.StartsWith("CVSS:3.0", StringComparison.OrdinalIgnoreCase) == true ? "3.0"
            : null;
        if (vector is not null || score is not null)
            yield return new DuckDbSeverityScore("cvss", version, "base", vector, score, score is null ? null : SeverityFromScore(score.Value, version));
    }

    private static IEnumerable<DuckDbSeverityScore> ExtractNvdSeverity(JsonNode? metrics)
    {
        if (metrics is not JsonObject obj) yield break;
        foreach (var (metricName, metricArray) in obj)
        {
            foreach (var item in ArrayItems(metricArray))
            {
                var data = item?["cvssData"];
                var version = data?["version"]?.GetValue<string>();
                var vector = data?["vectorString"]?.GetValue<string>();
                var score = DecimalValue(data?["baseScore"]);
                var label = data?["baseSeverity"]?.GetValue<string>() ?? item?["baseSeverity"]?.GetValue<string>();
                yield return new DuckDbSeverityScore("cvss", version, "base", vector, score, label);
            }
        }
    }

    private static IEnumerable<DuckDbReference> ExtractReferences(JsonNode? references)
    {
        foreach (var item in ArrayItems(references))
        {
            var url = item switch
            {
                JsonValue value => value.TryGetValue<string>(out var text) ? text : null,
                JsonObject obj => obj["url"]?.GetValue<string>() ?? obj["href"]?.GetValue<string>(),
                _ => null
            };
            if (string.IsNullOrWhiteSpace(url)) continue;
            var tags = item is JsonObject objWithTags
                ? ArrayItems(objWithTags["tags"]).Select(x => x?.GetValue<string>()).Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x!).ToArray()
                : [];
            var refType = item is JsonObject objWithType
                ? objWithType["type"]?.GetValue<string>() ?? objWithType["refsource"]?.GetValue<string>()
                : null;
            yield return new DuckDbReference(url, refType, tags);
        }
    }

    private static IEnumerable<DuckDbWeakness> ExtractGhsaWeaknesses(JsonNode? cwes)
    {
        foreach (var item in ArrayItems(cwes))
        {
            var id = item?["cwe_id"]?.GetValue<string>() ?? item?["id"]?.GetValue<string>();
            var name = item?["name"]?.GetValue<string>();
            if (id is not null || name is not null)
                yield return new DuckDbWeakness("CWE", id, name);
        }
    }

    private static IEnumerable<DuckDbWeakness> ExtractNvdWeaknesses(JsonNode? weaknesses)
    {
        foreach (var item in ArrayItems(weaknesses))
        {
            foreach (var description in ArrayItems(item?["description"]))
            {
                var value = description?["value"]?.GetValue<string>();
                if (!string.IsNullOrWhiteSpace(value))
                    yield return new DuckDbWeakness("CWE", value, null);
            }
        }
    }

    private static IEnumerable<JsonNode?> WalkCpeMatches(JsonNode? node)
    {
        if (node is null) yield break;
        if (node is JsonArray arr)
        {
            foreach (var item in arr)
            {
                foreach (var nested in WalkCpeMatches(item))
                    yield return nested;
            }
            yield break;
        }

        if (node is not JsonObject obj) yield break;

        if (obj["criteria"] is not null)
            yield return node;
        foreach (var child in ArrayItems(obj["nodes"]))
        {
            foreach (var nested in WalkCpeMatches(child))
                yield return nested;
        }
        foreach (var match in ArrayItems(obj["cpeMatch"]))
            yield return match;
    }

    private static string? OsvRange(JsonNode? range)
    {
        var events = ArrayItems(range?["events"]).ToArray();
        var introduced = events.FirstOrDefault(x => x?["introduced"] is not null)?["introduced"]?.GetValue<string>();
        var fixedVersion = events.FirstOrDefault(x => x?["fixed"] is not null)?["fixed"]?.GetValue<string>();
        if (introduced is not null && fixedVersion is not null) return $">= {introduced}, < {fixedVersion}";
        if (fixedVersion is not null) return $"< {fixedVersion}";
        if (introduced is not null) return $">= {introduced}";
        return range?.ToJsonString();
    }

    private static string? CpeRange(JsonNode? cpeMatch)
    {
        var parts = new List<string>();
        AddCpeRangePart(parts, ">=", cpeMatch?["versionStartIncluding"]?.GetValue<string>());
        AddCpeRangePart(parts, ">", cpeMatch?["versionStartExcluding"]?.GetValue<string>());
        AddCpeRangePart(parts, "<=", cpeMatch?["versionEndIncluding"]?.GetValue<string>());
        AddCpeRangePart(parts, "<", cpeMatch?["versionEndExcluding"]?.GetValue<string>());
        return parts.Count == 0 ? null : string.Join(", ", parts);
    }

    private static void AddCpeRangePart(List<string> parts, string op, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value)) parts.Add($"{op} {value}");
    }

    private static IEnumerable<JsonNode?> ArrayItems(JsonNode? node)
    {
        if (node is not JsonArray array) yield break;
        foreach (var item in array) yield return item;
    }

    private static decimal? DecimalValue(JsonNode? node)
    {
        if (node is null) return null;
        try { return node.GetValue<decimal>(); }
        catch { return null; }
    }

    private static string? CvssVersion(string? vector)
    {
        if (string.IsNullOrWhiteSpace(vector) || !vector.StartsWith("CVSS:", StringComparison.OrdinalIgnoreCase)) return null;
        var slash = vector.IndexOf('/');
        return slash > "CVSS:".Length ? vector["CVSS:".Length..slash] : null;
    }

    private static string? CvssVersionFromType(string? type) =>
        type?.ToUpperInvariant() switch
        {
            "CVSS_V4" or "CVSS_V4_0" => "4.0",
            "CVSS_V3" or "CVSS_V3_1" => "3.1",
            "CVSS_V3_0" => "3.0",
            "CVSS_V2" => "2.0",
            _ => null
        };

    private static string SeverityFromScore(decimal score, string? version = null) =>
        version?.StartsWith("2", StringComparison.Ordinal) == true
            ? score switch
            {
                >= 7.0m => "HIGH",
                >= 4.0m => "MEDIUM",
                _ => "LOW"
            }
            : score switch
            {
                >= 9.0m => "CRITICAL",
                >= 7.0m => "HIGH",
                >= 4.0m => "MEDIUM",
                > 0m => "LOW",
                _ => "NONE"
            };

    private static string PreferredIdentifier(string fallback, IEnumerable<string> aliases) =>
        aliases.FirstOrDefault(x => x.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase))
        ?? ExtractCveIdentifier(fallback)
        ?? fallback;

    private static string? ExtractCveIdentifier(string value)
    {
        var match = System.Text.RegularExpressions.Regex.Match(value, @"CVE-\d{4}-\d{4,}", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        return match.Success ? match.Value.ToUpperInvariant() : null;
    }

    private static bool IsDebianVulnerabilityIdentifier(string value) =>
        value.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)
        || value.StartsWith("TEMP-", StringComparison.OrdinalIgnoreCase);

    private static string DebianEcosystem(string release) => release.ToLowerInvariant() switch
    {
        "etch" => "debian:4",
        "lenny" => "debian:5",
        "squeeze" => "debian:6",
        "wheezy" => "debian:7",
        "jessie" => "debian:8",
        "stretch" => "debian:9",
        "buster" => "debian:10",
        "bullseye" => "debian:11",
        "bookworm" => "debian:12",
        "trixie" => "debian:13",
        "forky" => "debian:14",
        var value => $"debian:{value}"
    };

    private static string AlpineEcosystem(string release)
    {
        var normalized = release.Split('/', 2)[0].TrimStart('v', 'V');
        return $"alpine:{normalized}";
    }

    private static string? AlpineFixedVersion(JsonNode? secfixes, string identifier)
    {
        if (secfixes is not JsonObject obj) return null;
        foreach (var (fixedVersion, identifiers) in obj)
        {
            if (ArrayItems(identifiers).Any(item =>
                string.Equals(item?.GetValue<string>(), identifier, StringComparison.OrdinalIgnoreCase)))
                return fixedVersion;
        }
        return null;
    }

    private static string? ToPurl(string? ecosystem, string? packageName)
    {
        if (string.IsNullOrWhiteSpace(ecosystem) || string.IsNullOrWhiteSpace(packageName)) return null;
        return ecosystem.ToLowerInvariant() switch
        {
            "npm" => $"pkg:npm/{Uri.EscapeDataString(packageName)}",
            "pip" or "pypi" => $"pkg:pypi/{Uri.EscapeDataString(packageName.ToLowerInvariant())}",
            "maven" when packageName.Contains(':') => $"pkg:maven/{Uri.EscapeDataString(packageName.Split(':')[0])}/{Uri.EscapeDataString(packageName.Split(':')[1])}",
            "nuget" => $"pkg:nuget/{Uri.EscapeDataString(packageName)}",
            "go" => $"pkg:golang/{packageName}",
            "alpine" => $"pkg:apk/alpine/{Uri.EscapeDataString(packageName)}",
            _ => null
        };
    }

    private static string? ParseCpeProduct(string cpe23Uri)
    {
        var parts = cpe23Uri.Split(':');
        return parts.Length > 5 ? parts[5].Replace("\\:", ":") : null;
    }

    private static DuckDbEvidenceRecord EmptyRecord(string sourceCode, Guid rawIndexId, string vulnerabilityKey, string sourceRecordId) =>
        new(sourceCode, rawIndexId, vulnerabilityKey, sourceRecordId, [], [], [], []);

    private async Task<int> RebuildCpeEntriesAsync(int limit, CancellationToken ct)
    {
        await using var command = db.CreateCommand("""
            select raw_index_id, cpe23_uri, vendor, product, version, part, target_sw, deprecated
            from stg_nvd_cpe_dictionary s
            join source_raw_index r on r.id = s.raw_index_id
            where r.normalize_status <> 'superseded'
            order by s.raw_index_id
            limit $1
            """);
        command.Parameters.AddWithValue(limit);
        command.CommandTimeout = 0;
        var count = 0;
        var tempDir = Path.Combine(Path.GetDirectoryName(store.DatabasePath)!, "tmp");
        Directory.CreateDirectory(tempDir);
        var tempFile = Path.Combine(tempDir, $"cpe_entries-{Guid.NewGuid():N}.csv");
        try
        {
            await using (var writer = new StreamWriter(tempFile))
            {
                await using var reader = await command.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct))
                {
                    ct.ThrowIfCancellationRequested();
                    await writer.WriteLineAsync(CsvRow(
                        "nvd-cpe",
                        reader.GetGuid(0).ToString("D"),
                        reader.GetString(1),
                        reader.IsDBNull(2) ? null : reader.GetString(2),
                        reader.IsDBNull(3) ? null : reader.GetString(3),
                        reader.IsDBNull(4) ? null : reader.GetString(4),
                        reader.IsDBNull(5) ? null : reader.GetString(5),
                        reader.IsDBNull(6) ? null : reader.GetString(6),
                        reader.IsDBNull(7) ? null : reader.GetBoolean(7).ToString().ToLowerInvariant()));
                    count++;
                }
            }

            using var conn = new DuckDB.NET.Data.DuckDBConnection($"Data Source={store.DatabasePath}");
            conn.Open();
            ExecuteDuck(conn, "begin transaction");
            try
            {
                ExecuteDuck(conn, "delete from cpe_entries where source_code = 'nvd-cpe'");
                ExecuteDuck(conn, $"""
                    copy cpe_entries (source_code, raw_index_id, cpe23_uri, vendor, product, version, part, target_sw, deprecated)
                    from {DuckSqlString(tempFile)}
                    (header false, delim ',', quote '"', escape '"', null '\N')
                    """);
                ExecuteDuck(conn, "commit");
            }
            catch
            {
                ExecuteDuck(conn, "rollback");
                throw;
            }

            return count;
        }
        finally
        {
            try { File.Delete(tempFile); } catch { }
        }
    }

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadCsafAsync(string sourceCode, int limit, int offset, CancellationToken ct)
    {
        var provider = sourceCode; // suse-csaf or redhat-csaf
        await using var command = db.CreateCommand("""
            select raw_index_id, advisory_id, identifiers, payload::text
            from stg_ecosystem_advisories s
            join source_raw_index r on r.id = s.raw_index_id
            where provider = $1
              and r.normalize_status <> 'superseded'
            order by s.raw_index_id
            limit $2
            offset $3
            """);
        command.Parameters.AddWithValue(provider);
        command.Parameters.AddWithValue(limit);
        command.Parameters.AddWithValue(offset);
        command.CommandTimeout = 300;
        var records = new List<DuckDbEvidenceRecord>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var rawId = reader.GetGuid(0);
            var advisoryId = reader.GetString(1);
            var identifiers = reader.IsDBNull(2) ? [] : reader.GetFieldValue<string[]>(2);
            if (reader.IsDBNull(3)) continue;
            var payload = JsonNode.Parse(reader.GetString(3));
            if (payload is null) continue;
            if (sourceCode.Equals("redhat-csaf", StringComparison.OrdinalIgnoreCase) && payload["vulnerabilities"] is null)
            {
                foreach (var cve in RedHatCves(identifiers, payload))
                {
                    records.Add(EmptyRecord(sourceCode, rawId, cve, advisoryId) with
                    {
                        SeverityScores = LabelSeverity(payload["severity"]?.GetValue<string>()).ToList(),
                        References = RedHatReferences(payload).ToList()
                    });
                }
                continue;
            }

            // Parse CSAF payload: {"cves": ["CVE-xxx"], "products": [...], "references": [...]}
            var cves = new List<string>();
            // Try to find CVE from identifiers first, then from payload
            foreach (var id in identifiers)
                if (id.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase))
                    cves.Add(id);
            if (cves.Count == 0)
            {
                var payloadCves = payload["cves"]?.AsArray() ?? [];
                foreach (var c in payloadCves)
                {
                    var cv = c?.GetValue<string>();
                    if (!string.IsNullOrWhiteSpace(cv)) cves.Add(cv);
                }
            }
            if (cves.Count > 0)
            {
                foreach (var cve in cves)
                {
                    var facts = ExtractCsafFacts(payload, cve).ToList();
                    var refs = ExtractCsafReferences(payload, cve).ToList();
                    var severities = ExtractCsafSeverity(payload, cve).ToList();
                    records.Add(EmptyRecord(sourceCode, rawId, cve, advisoryId) with
                    {
                        AffectedFacts = facts,
                        References = refs,
                        SeverityScores = severities
                    });
                }
            }
            else
            {
                var facts = ExtractCsafFacts(payload, "").ToList();
                var refs = ExtractCsafReferences(payload, null).ToList();
                if (facts.Count > 0)
                    records.Add(EmptyRecord(sourceCode, rawId, advisoryId, advisoryId) with { AffectedFacts = facts, References = refs });
            }
        }
        return records;
    }

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadAlpineAsync(int limit, int offset, CancellationToken ct)
    {
        await using var command = db.CreateCommand("""
            select raw_index_id, distro_release, package_name, identifiers, secfixes::text
            from stg_alpine_secdb s
            join source_raw_index r on r.id = s.raw_index_id
            where r.normalize_status <> 'superseded'
            order by s.raw_index_id
            limit $1
            offset $2
            """);
        command.Parameters.AddWithValue(limit);
        command.Parameters.AddWithValue(offset);
        command.CommandTimeout = 300;
        var records = new List<DuckDbEvidenceRecord>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var rawId = reader.GetGuid(0);
            var release = reader.GetString(1);
            var pkg = reader.GetString(2);
            var identifiers = reader.IsDBNull(3) ? [] : reader.GetFieldValue<string[]>(3);
            var secfixes = reader.IsDBNull(4) ? null : JsonNode.Parse(reader.GetString(4));
            foreach (var id in identifiers)
            {
                var cveKey = id;
                var fixedVer = AlpineFixedVersion(secfixes, id);
                var range = fixedVer is not null ? $"< {fixedVer}" : null;
                if (range is null) continue;
                var fact = new DuckDbAffectedFact("package", AlpineEcosystem(release), pkg, ToPurl("alpine", pkg), null, range, "secfixes", true);
                records.Add(EmptyRecord("alpine-secdb", rawId, cveKey, $"{release}:{pkg}:{cveKey}") with { AffectedFacts = [fact] });
            }
        }
        return records;
    }

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadExternalAdvisoryAsync(string sourceCode, int limit, int offset, CancellationToken ct)
    {
        await using var command = db.CreateCommand("""
            select raw_index_id, advisory_id, identifiers, title, summary, description, severity_label,
                   references_json::text, affected_products::text, payload::text
            from stg_external_advisories
            join source_raw_index r on r.id = raw_index_id
            where provider = $1
              and r.normalize_status <> 'superseded'
            order by raw_index_id
            limit $2
            offset $3
            """);
        command.Parameters.AddWithValue(sourceCode);
        command.Parameters.AddWithValue(limit);
        command.Parameters.AddWithValue(offset);
        command.CommandTimeout = 300;
        var records = new List<DuckDbEvidenceRecord>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var rawId = reader.GetGuid(0);
            var advisoryId = reader.GetString(1);
            var identifiers = reader.IsDBNull(2) ? [] : reader.GetFieldValue<string[]>(2);
            var title = reader.IsDBNull(3) ? null : reader.GetString(3);
            var desc = reader.IsDBNull(4) ? null : reader.GetString(4);
            var sevLabel = reader.IsDBNull(6) ? null : reader.GetString(6);
            var refs = reader.IsDBNull(7) ? null : JsonNode.Parse(reader.GetString(7));
            var affectedJson = reader.IsDBNull(8) ? null : reader.GetString(8);
            var key = identifiers.FirstOrDefault(x => x.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)) ?? advisoryId;
            var facts = new List<DuckDbAffectedFact>();
            if (affectedJson is not null)
            {
                try
                {
                    var products = JsonNode.Parse(affectedJson)?.AsArray() ?? [];
                    foreach (var p in products)
                    {
                        var pkgName = p?["name"]?.GetValue<string>();
                        var pkgVer = p?["version"]?.GetValue<string>();
                        var eco = sourceCode switch { "npm-advisory" => "npm", "pypi-advisory" => "pypi", "nuget-advisory" => "nuget", _ => sourceCode };
                        if (!string.IsNullOrWhiteSpace(pkgName))
                            facts.Add(new DuckDbAffectedFact("package", eco, pkgName, ToPurl(eco, pkgName), null, pkgVer is not null ? $"<= {pkgVer}" : null, "SEMVER", true));
                    }
                }
                catch { }
            }
            records.Add(new DuckDbEvidenceRecord(sourceCode, rawId, key, advisoryId, facts,
                sevLabel is not null ? [new DuckDbSeverityScore(sourceCode, null, null, null, null, sevLabel)] : [],
                ExtractReferences(refs).ToList(), []));
        }
        return records;
    }

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadEcosystemAsync(string sourceCode, int limit, int offset, CancellationToken ct) =>
        await LoadEcosystemAsync(sourceCode, sourceCode, limit, offset, ct);

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadEcosystemAsync(string sourceCode, string provider, int limit, int offset, CancellationToken ct)
    {
        var eco = sourceCode switch { "go-advisory" => "go", "cargo-advisory" => "cargo", "nuget-advisory" => "nuget", _ => sourceCode };
        await using var command = db.CreateCommand("""
            select raw_index_id, advisory_id, identifiers, ecosystem, package_name, purl,
                   vulnerable_ranges::text, severity_label, cvss::text, references_json::text, payload::text
            from stg_ecosystem_advisories s
            join source_raw_index r on r.id = s.raw_index_id
            where provider = $1
              and r.normalize_status <> 'superseded'
            order by s.raw_index_id
            limit $2
            offset $3
            """);
        command.Parameters.AddWithValue(provider);
        command.Parameters.AddWithValue(limit);
        command.Parameters.AddWithValue(offset);
        command.CommandTimeout = 300;
        var records = new List<DuckDbEvidenceRecord>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var rawId = reader.GetGuid(0);
            var advisoryId = reader.GetString(1);
            var identifiers = reader.IsDBNull(2) ? [] : reader.GetFieldValue<string[]>(2);
            var ecosystem = reader.IsDBNull(3) ? eco : reader.GetString(3);
            var pkgName = reader.IsDBNull(4) ? null : reader.GetString(4);
            var purl = reader.IsDBNull(5) ? null : reader.GetString(5);
            var key = identifiers.FirstOrDefault(x => x.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)) ?? advisoryId;
            var severityLabel = reader.IsDBNull(7) ? null : reader.GetString(7);
            var cvss = reader.IsDBNull(8) ? null : JsonNode.Parse(reader.GetString(8));
            var refs = reader.IsDBNull(9) ? null : JsonNode.Parse(reader.GetString(9));
            var payload = reader.IsDBNull(10) ? "{}" : reader.GetString(10);
            var facts = new List<DuckDbAffectedFact>();
            if (!reader.IsDBNull(6) && !string.IsNullOrWhiteSpace(pkgName))
            {
                var ranges = JsonNode.Parse(reader.GetString(6))?.AsArray() ?? [];
                foreach (var range in ranges)
                {
                    var rawRange = RangeFromNode(range);
                    facts.Add(new DuckDbAffectedFact("package", ecosystem, pkgName, purl, null, rawRange, "vendor", true));
                }
            }
            if (facts.Count == 0 && !string.IsNullOrWhiteSpace(pkgName))
                facts.Add(new DuckDbAffectedFact("package", ecosystem, pkgName, purl, null, null, "vendor", true));
            records.Add(EmptyRecord(sourceCode, rawId, key, advisoryId) with
            {
                AffectedFacts = facts,
                SeverityScores = ExtractCvssSeverities(cvss)
                    .Concat(LabelSeverity(severityLabel))
                    .ToList(),
                References = ExtractReferences(refs).ToList()
            });
        }
        return records;
    }

    private static string? RangeFromNode(JsonNode? range) => range switch
    {
        JsonValue value => value.TryGetValue<string>(out var text) ? text : null,
        JsonObject obj => EcosystemRange(obj),
        _ => null
    };

    private static string? EcosystemRange(JsonObject range)
    {
        var introduced = range["introduced"]?.GetValue<string>();
        var fixedVer = range["fixed"]?.GetValue<string>();
        return fixedVer is not null
            ? (introduced is not null ? $">= {introduced}, < {fixedVer}" : $"< {fixedVer}")
            : (introduced is not null ? $">= {introduced}" : null);
    }

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadThreatIntelAsync(string sourceCode, int limit, int offset, CancellationToken ct)
    {
        await using var command = db.CreateCommand("""
            select raw_index_id, identifier, epss_score, epss_percentile, observed_at
            from stg_threat_intel_records s
            join source_raw_index r on r.id = s.raw_index_id
            where provider = $1
              and r.normalize_status <> 'superseded'
            order by s.raw_index_id
            limit $2
            offset $3
            """);
        command.Parameters.AddWithValue(sourceCode);
        command.Parameters.AddWithValue(limit);
        command.Parameters.AddWithValue(offset);
        command.CommandTimeout = 300;
        var records = new List<DuckDbEvidenceRecord>();
        var rows = new List<string>();
        var rawIds = new List<string>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var rawId = reader.GetGuid(0);
            var identifier = reader.GetString(1);
            rawIds.Add(rawId.ToString("D"));
            var epss = reader.IsDBNull(2) ? (double?)null : (double)reader.GetDecimal(2);
            var pct = reader.IsDBNull(3) ? (double?)null : (double)reader.GetDecimal(3);
            var observed = reader.IsDBNull(4) ? (string?)null : reader.GetDateTime(4).ToString("O");
            if (epss.HasValue || pct.HasValue)
            {
                rows.Add(CsvRow(
                    sourceCode,
                    rawId.ToString("D"),
                    identifier,
                    "epss",
                    epss?.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    pct?.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    observed));
            }
            records.Add(EmptyRecord(sourceCode, rawId, identifier, identifier));
        }
        if (rows.Count > 0)
        {
            var tempFile = Path.GetTempFileName() + ".csv";
            await File.WriteAllLinesAsync(tempFile, rows, ct);
            try
            {
                using var conn = new DuckDB.NET.Data.DuckDBConnection($"Data Source={store.DatabasePath}");
                conn.Open();
                DeleteDuckRows(conn, "threat_scores", sourceCode, rawIds);
                using var cmd = conn.CreateCommand();
                cmd.CommandText = $"copy threat_scores (source_code, raw_index_id, vulnerability_key, score_type, score, percentile, observed_at) from {DuckSqlString(tempFile)} (header false, delim ',', quote '\"', escape '\"', null '\\N')";
                cmd.ExecuteNonQuery();
            }
            finally { try { File.Delete(tempFile); } catch { } }
        }
        return records;
    }

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadExploitAsync(string sourceCode, int limit, int offset, CancellationToken ct)
    {
        await using var command = db.CreateCommand("""
            select s.raw_index_id, s.source_key, s.identifiers, s.title, s.source_url, s.artifact_type, s.exploit_type,
                   s.maturity, s.verification_status, s.published_at, s.modified_at
            from stg_exploit_pocs s
            join source_raw_index r on r.id = s.raw_index_id
            where provider = $1
              and r.normalize_status <> 'superseded'
            order by s.raw_index_id
            limit $2
            offset $3
            """);
        command.Parameters.AddWithValue(sourceCode);
        command.Parameters.AddWithValue(limit);
        command.Parameters.AddWithValue(offset);
        command.CommandTimeout = 300;
        var rows = new List<string>();
        var records = new List<DuckDbEvidenceRecord>();
        var rawIds = new List<string>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var rawId = reader.GetGuid(0);
            var sourceKey = reader.GetString(1);
            rawIds.Add(rawId.ToString("D"));
            var identifierValues = reader.IsDBNull(2) ? [] : reader.GetFieldValue<string[]>(2);
            var identifiers = System.Text.Json.JsonSerializer.Serialize(identifierValues);
            rows.Add(CsvRow(
                sourceCode,
                rawId.ToString("D"),
                sourceKey,
                identifiers,
                reader.IsDBNull(3) ? null : reader.GetString(3),
                reader.IsDBNull(4) ? null : reader.GetString(4),
                reader.IsDBNull(5) ? null : reader.GetString(5),
                reader.IsDBNull(6) ? null : reader.GetString(6),
                reader.IsDBNull(7) ? null : reader.GetString(7),
                reader.IsDBNull(8) ? null : reader.GetString(8),
                reader.IsDBNull(9) ? null : reader.GetDateTime(9).ToString("O"),
                reader.IsDBNull(10) ? null : reader.GetDateTime(10).ToString("O")));
            var key = identifierValues.FirstOrDefault(x => x.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)) ?? sourceKey;
            var references = reader.IsDBNull(4)
                ? []
                : new[] { new DuckDbReference(reader.GetString(4), "exploit", []) };
            records.Add(EmptyRecord(sourceCode, rawId, key, sourceKey) with { References = references });
        }
        if (rows.Count > 0)
        {
            var tempFile = Path.GetTempFileName() + ".csv";
            await File.WriteAllLinesAsync(tempFile, rows, ct);
            try
            {
                using var conn = new DuckDB.NET.Data.DuckDBConnection($"Data Source={store.DatabasePath}");
                conn.Open();
                DeleteDuckRows(conn, "exploits", sourceCode, rawIds);
                using var cmd = conn.CreateCommand();
                cmd.CommandText = $"copy exploits (source_code, raw_index_id, source_key, identifiers, title, source_url, artifact_type, exploit_type, maturity, verification_status, published_at, modified_at) from {DuckSqlString(tempFile)} (header false, delim ',', quote '\"', escape '\"', null '\\N')";
                cmd.ExecuteNonQuery();
            }
            finally { try { File.Delete(tempFile); } catch { } }
        }
        return records;
    }

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadCnnvdAsync(int limit, int offset, CancellationToken ct)
    {
        await using var command = db.CreateCommand("""
            select raw_index_id, advisory_id, identifiers, severity_label, references_json::text, payload::text
            from stg_external_advisories s
            join source_raw_index r on r.id = s.raw_index_id
            where provider = 'cnnvd'
              and r.normalize_status <> 'superseded'
            order by s.raw_index_id
            limit $1
            offset $2
            """);
        command.Parameters.AddWithValue(limit);
        command.Parameters.AddWithValue(offset);
        command.CommandTimeout = 300;
        var records = new List<DuckDbEvidenceRecord>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var rawId = reader.GetGuid(0);
            var advisoryId = reader.GetString(1);
            var identifiers = reader.IsDBNull(2) ? [] : reader.GetFieldValue<string[]>(2);
            var severityLabel = reader.IsDBNull(3) ? null : reader.GetString(3);
            var refs = reader.IsDBNull(4) ? null : JsonNode.Parse(reader.GetString(4));
            if (reader.IsDBNull(5)) continue;
            var payload = JsonNode.Parse(reader.GetString(5));
            if (payload is null) continue;
            var key = identifiers.FirstOrDefault(x => x.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)) ?? advisoryId;
            var cve = payload["cveId"]?.GetValue<string>()
                ?? payload["cve_id"]?.GetValue<string>()
                ?? payload["cve"]?.GetValue<string>()
                ?? payload["list"]?["cveCode"]?.GetValue<string>()
                ?? payload["detail"]?["cveCode"]?.GetValue<string>()
                ?? key;
            var sev = severityLabel ?? payload["severity"]?.GetValue<string>() ?? CnnvdSeverityLabel(payload);
            var affected = payload["affected"]?.AsArray() ?? [];
            var facts = new List<DuckDbAffectedFact>();
            foreach (var a in affected)
            {
                var name = a?["product"]?.GetValue<string>() ?? a?["vendor"]?.GetValue<string>() ?? a?.GetValue<string>();
                if (!string.IsNullOrWhiteSpace(name))
                    facts.Add(new DuckDbAffectedFact("package", null, name, null, null, null, null, true));
            }
            records.Add(EmptyRecord("cnnvd", rawId, cve, advisoryId) with
            {
                AffectedFacts = facts,
                SeverityScores = sev is not null ? [new DuckDbSeverityScore("vendor", null, "advisory", null, null, sev)] : [],
                References = ExtractReferences(refs).ToList()
            });
        }
        return records;
    }

    private static IEnumerable<string> RedHatCves(string[] identifiers, JsonNode payload)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var id in identifiers)
            if (id.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase) && seen.Add(id))
                yield return id;
        foreach (var item in ArrayItems(payload["CVEs"] ?? payload["cves"]))
        {
            var cve = item?.GetValue<string>();
            if (!string.IsNullOrWhiteSpace(cve) && seen.Add(cve))
                yield return cve;
        }
    }

    private static IEnumerable<DuckDbReference> RedHatReferences(JsonNode payload)
    {
        var url = payload["resource_url"]?.GetValue<string>();
        if (!string.IsNullOrWhiteSpace(url))
            yield return new DuckDbReference(url, "resource_url", []);
    }

    private static string? CnnvdSeverityLabel(JsonNode payload)
    {
        var text = payload["detail"]?["hazardLevel"]?.ToString()
            ?? payload["list"]?["hazardLevel"]?.ToString()
            ?? payload["detail"]?["varchar1"]?.GetValue<string>();
        return text switch
        {
            "4" => "CRITICAL",
            "3" => "HIGH",
            "2" => "MEDIUM",
            "1" => "LOW",
            _ => string.IsNullOrWhiteSpace(text) ? null : text
        };
    }

    private static IEnumerable<DuckDbAffectedFact> ExtractCsafFacts(JsonNode? payload, string cve)
    {
        if (payload is null) yield break;
        // Fast path: use relationships array (flat, no recursion)
        var productTree = payload["product_tree"];
        var productNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var relationships = productTree?["relationships"]?.AsArray() ?? [];
        foreach (var rel in relationships)
        {
            var fullName = rel?["full_product_name"]?["name"]?.GetValue<string>();
            var pid = rel?["product_reference"]?.GetValue<string>() ?? rel?["full_product_name"]?["product_id"]?.GetValue<string>();
            if (!string.IsNullOrWhiteSpace(pid) && !string.IsNullOrWhiteSpace(fullName))
                productNames[pid] = fullName;
        }
        // Extract affected products per CVE from vulnerabilities array
        var vulns = payload["vulnerabilities"]?.AsArray() ?? [];
        var productSeen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var vuln in vulns)
        {
            var vulnCve = vuln?["cve"]?.GetValue<string>() ?? "";
            if (!string.IsNullOrWhiteSpace(cve) && !vulnCve.Equals(cve, StringComparison.OrdinalIgnoreCase)) continue;
            var productIds = vuln?["product_status"]?["known_affected"]?.AsArray()
                ?? vuln?["product_status"]?["recommended"]?.AsArray()
                ?? vuln?["product_status"]?["first_fixed"]?.AsArray()
                ?? [];
            foreach (var pid in productIds)
            {
                var pidStr = pid?.GetValue<string>();
                if (string.IsNullOrWhiteSpace(pidStr)) continue;
                var product = productNames.TryGetValue(pidStr, out var n) ? n : pidStr;
                var name = ParseSuseProductName(product);
                if (string.IsNullOrWhiteSpace(name) || !productSeen.Add(name)) continue;
                yield return new DuckDbAffectedFact("package", DetectSuseEcosystem(product), name, null, null, product, "csaf-product", true);
            }
        }
    }

    private static string ParseSuseProductName(string product)
    {
        if (string.IsNullOrWhiteSpace(product)) return product;
        var colonIdx = product.IndexOf(':');
        var name = colonIdx > 0 && colonIdx < product.Length - 1 ? product[(colonIdx + 1)..] : product;
        var parts = name.Split('-', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length <= 1) return name;
        var result = new List<string>();
        foreach (var part in parts)
        {
            if (char.IsDigit(part[0]) && part.Contains('.'))
                break;
            result.Add(part);
        }
        return result.Count > 0 ? string.Join("-", result) : name;
    }

    private static string DetectSuseEcosystem(string product)
    {
        var lower = product.ToLowerInvariant();
        if (lower.Contains("suse") || lower.Contains("opensuse") || lower.Contains("sles")) return "rpm";
        return "rpm";
    }

    private static IEnumerable<DuckDbSeverityScore> ExtractCsafSeverity(JsonNode? payload, string cve)
    {
        foreach (var vuln in CsafVulnerabilities(payload, cve))
        {
            foreach (var score in ArrayItems(vuln?["scores"]))
            {
                foreach (var scoreNode in new[] { score?["cvss_v4"], score?["cvss_v3"], score?["cvss_v2"] })
                {
                    if (scoreNode is null) continue;
                    var version = scoreNode["version"]?.GetValue<string>();
                    var vector = scoreNode["vectorString"]?.GetValue<string>() ?? scoreNode["vector_string"]?.GetValue<string>();
                    var value = DecimalValue(scoreNode["baseScore"] ?? scoreNode["base_score"]);
                    var label = scoreNode["baseSeverity"]?.GetValue<string>() ?? scoreNode["base_severity"]?.GetValue<string>();
                    yield return new DuckDbSeverityScore("cvss", version, "base", vector, value, label);
                }
            }
        }
    }

    private static IEnumerable<DuckDbReference> ExtractCsafReferences(JsonNode? payload, string? cve)
    {
        if (payload is null) yield break;
        if (!string.IsNullOrWhiteSpace(cve))
        {
            foreach (var vuln in CsafVulnerabilities(payload, cve))
            {
                foreach (var reference in ExtractCsafReferenceItems(vuln?["references"]))
                    yield return reference;
                foreach (var id in ArrayItems(vuln?["ids"]))
                {
                    var url = id?["text"]?.GetValue<string>();
                    if (!string.IsNullOrWhiteSpace(url) && url.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                        yield return new DuckDbReference(url, id?["system_name"]?.GetValue<string>(), []);
                }
            }
            yield break;
        }

        var docRefs = payload["document"]?["references"]?.AsArray() ?? [];
        foreach (var reference in ExtractCsafReferenceItems(docRefs))
            yield return reference;
    }

    private static IEnumerable<JsonNode?> CsafVulnerabilities(JsonNode? payload, string cve)
    {
        foreach (var vuln in ArrayItems(payload?["vulnerabilities"]))
        {
            var vulnCve = vuln?["cve"]?.GetValue<string>() ?? "";
            if (vulnCve.Equals(cve, StringComparison.OrdinalIgnoreCase))
                yield return vuln;
        }
    }

    private static IEnumerable<DuckDbReference> ExtractCsafReferenceItems(JsonNode? references)
    {
        foreach (var r in ArrayItems(references))
        {
            var url = r?["url"]?.GetValue<string>();
            if (!string.IsNullOrWhiteSpace(url))
                yield return new DuckDbReference(url, r?["category"]?.GetValue<string>(), []);
        }
    }

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadNpmAdvisoryAsync(string sourceCode, int limit, int offset, CancellationToken ct)
    {
        await using var command = db.CreateCommand("""
            select s.raw_index_id, s.ghsa_id, s.cve_id, s.package_name, s.vulnerable_ranges::text, s.cvss::text, s.cwes::text
            from stg_npm_advisories s
            join source_raw_index r on r.id = s.raw_index_id
            join sources src on src.id = r.source_id
            where src.code = $1
              and r.normalize_status <> 'superseded'
            order by s.raw_index_id
            limit $2
            offset $3
            """);
        command.Parameters.AddWithValue(sourceCode);
        command.Parameters.AddWithValue(limit);
        command.Parameters.AddWithValue(offset);
        command.CommandTimeout = 300;
        var records = new List<DuckDbEvidenceRecord>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var rawId = reader.GetGuid(0);
            var ghsaId = reader.GetString(1);
            var cve = reader.IsDBNull(2) ? null : reader.GetString(2);
            var pkgName = reader.IsDBNull(3) ? null : reader.GetString(3);
            var key = string.IsNullOrWhiteSpace(cve) ? ghsaId : cve;
            var facts = new List<DuckDbAffectedFact>();
            if (!reader.IsDBNull(4) && !string.IsNullOrWhiteSpace(pkgName))
            {
                var ranges = JsonNode.Parse(reader.GetString(4))?.AsArray() ?? [];
                foreach (var range in ranges)
                {
                    var rawRange = RangeFromNode(range);
                    facts.Add(new DuckDbAffectedFact("package", "npm", pkgName, $"pkg:npm/{Uri.EscapeDataString(pkgName)}", null, rawRange, "vendor", true));
                }
            }
            if (facts.Count == 0 && !string.IsNullOrWhiteSpace(pkgName))
                facts.Add(new DuckDbAffectedFact("package", "npm", pkgName, $"pkg:npm/{Uri.EscapeDataString(pkgName)}", null, null, "vendor", true));
            var cvss = reader.IsDBNull(5) ? null : JsonNode.Parse(reader.GetString(5));
            var cwes = reader.IsDBNull(6) ? null : JsonNode.Parse(reader.GetString(6));
            records.Add(EmptyRecord(sourceCode, rawId, key, ghsaId) with
            {
                AffectedFacts = facts,
                SeverityScores = ExtractGhsaSeverity(cvss).ToList(),
                Weaknesses = ExtractGhsaWeaknesses(cwes).ToList()
            });
        }
        return records;
    }

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadPypiAdvisoryAsync(int limit, int offset, CancellationToken ct)
    {
        await using var command = db.CreateCommand("""
            select raw_index_id, pysec_id, aliases, package_name, affected::text, severity::text, references_json::text, payload::text
            from stg_pypi_advisories s
            join source_raw_index r on r.id = s.raw_index_id
            where r.normalize_status <> 'superseded'
            order by s.raw_index_id
            limit $1
            offset $2
            """);
        command.Parameters.AddWithValue(limit);
        command.Parameters.AddWithValue(offset);
        command.CommandTimeout = 300;
        var records = new List<DuckDbEvidenceRecord>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var rawId = reader.GetGuid(0);
            var pysecId = reader.GetString(1);
            var aliases = reader.IsDBNull(2) ? [] : reader.GetFieldValue<string[]>(2);
            var pkgName = reader.IsDBNull(3) ? null : reader.GetString(3);
            var key = aliases.FirstOrDefault(x => x.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)) ?? pysecId;
            var facts = new List<DuckDbAffectedFact>();
            if (!reader.IsDBNull(4) && !string.IsNullOrWhiteSpace(pkgName))
            {
                var affected = JsonNode.Parse(reader.GetString(4))?.AsArray() ?? [];
                foreach (var a in affected)
                {
                    var rawRange = OsvRange(a);
                    facts.Add(new DuckDbAffectedFact("package", "PyPI", pkgName, $"pkg:pypi/{Uri.EscapeDataString(pkgName.ToLowerInvariant())}", null, rawRange, a?["type"]?.GetValue<string>(), true));
                }
            }
            if (facts.Count == 0 && !string.IsNullOrWhiteSpace(pkgName))
                facts.Add(new DuckDbAffectedFact("package", "PyPI", pkgName, $"pkg:pypi/{Uri.EscapeDataString(pkgName.ToLowerInvariant())}", null, null, null, true));
            var severity = reader.IsDBNull(5) ? null : JsonNode.Parse(reader.GetString(5));
            var refs = reader.IsDBNull(6) ? null : JsonNode.Parse(reader.GetString(6));
            var payload = reader.IsDBNull(7) ? null : JsonNode.Parse(reader.GetString(7));
            records.Add(EmptyRecord("pypi-advisory", rawId, key, pysecId) with
            {
                AffectedFacts = facts,
                SeverityScores = ExtractOsvSeverity(payload?["severity"] ?? severity).ToList(),
                References = ExtractReferences(payload?["references"] ?? refs).ToList()
            });
        }
        return records;
    }

    private static IEnumerable<DuckDbSeverityScore> ExtractCvssSeverities(JsonNode? cvss)
    {
        foreach (var item in WalkObjects(cvss))
        {
            var vector = StringValue(item["vectorString"]) ?? StringValue(item["vector_string"]);
            var version = CvssVersion(vector) ?? StringValue(item["version"]);
            var score = DecimalValue(item["score"])
                ?? DecimalValue(item["baseScore"])
                ?? DecimalValue(item["base_score"])
                ?? CvssScoreCalculator.CalculateBaseScore(vector, version);
            var label = StringValue(item["severity"])
                ?? StringValue(item["baseSeverity"])
                ?? (score is null ? null : SeverityFromScore(score.Value, version));

            if (vector is null && score is null && label is null) continue;
            yield return new DuckDbSeverityScore("cvss", version, "base", vector, score, label);
        }
    }

    private static IEnumerable<DuckDbSeverityScore> LabelSeverity(string? label)
    {
        if (!string.IsNullOrWhiteSpace(label))
            yield return new DuckDbSeverityScore("vendor", null, "advisory", null, null, label);
    }

    private static IEnumerable<JsonObject> WalkObjects(JsonNode? node)
    {
        if (node is JsonObject obj)
        {
            yield return obj;
            foreach (var child in obj.Select(x => x.Value))
            {
                foreach (var nested in WalkObjects(child)) yield return nested;
            }
        }
        else if (node is JsonArray array)
        {
            foreach (var child in array)
            {
                foreach (var nested in WalkObjects(child)) yield return nested;
            }
        }
    }

    private static string? StringValue(JsonNode? node)
    {
        if (node is null || node.GetValueKind() == System.Text.Json.JsonValueKind.Null) return null;
        return node.GetValueKind() == System.Text.Json.JsonValueKind.String ? node.GetValue<string>() : node.ToJsonString();
    }

    private static string CsvRow(params string?[] values) =>
        string.Join(",", values.Select(CsvValue));

    private static string CsvValue(string? value)
    {
        if (value is null) return "\\N";
        return $"\"{value.Replace("\"", "\"\"")}\"";
    }

    private static void DeleteDuckRows(DuckDB.NET.Data.DuckDBConnection connection, string tableName, string sourceCode, IReadOnlyList<string> rawIds)
    {
        foreach (var batch in rawIds.Distinct(StringComparer.OrdinalIgnoreCase).Chunk(1000))
        {
            var rawIdList = string.Join(",", batch.Select(DuckSqlString));
            using var cmd = connection.CreateCommand();
            cmd.CommandText = $"delete from {tableName} where source_code = {DuckSqlString(sourceCode)} and raw_index_id in ({rawIdList})";
            cmd.ExecuteNonQuery();
        }
    }

    private static void ExecuteDuck(DuckDB.NET.Data.DuckDBConnection connection, string sql)
    {
        using var cmd = connection.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }

    private static string DuckSqlString(string value) => $"'{value.Replace("'", "''")}'";
}
