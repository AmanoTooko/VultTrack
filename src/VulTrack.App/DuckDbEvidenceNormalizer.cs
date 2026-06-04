using System.Diagnostics;
using System.Text.Json.Nodes;
using Npgsql;

namespace VulTrack.App;

public sealed record DuckDbEvidenceNormalizeRequest(
    string? SourceCode,
    int Limit = 1000,
    bool Reset = false);

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
        "nvd-cve",
        "nvd-cpe",
        "suse-csaf",
        "alpine-secdb",
        "redhat-csaf",
        "nuget-advisory",
        "npm-advisory",
        "pypi-advisory",
        "go-advisory",
        "cargo-advisory",
        "first-epss",
        "cisa-kev",
        "exploitdb",
        "poc-in-github",
        "nuclei-templates",
        "metasploit",
        "cnnvd"
    ];

    public async Task<DuckDbEvidenceNormalizeResult> NormalizeAsync(DuckDbEvidenceNormalizeRequest request, CancellationToken ct)
    {
        if (request.Reset) await store.ResetAsync(ct);
        else await store.InitializeAsync(ct);

        var limit = Math.Clamp(request.Limit <= 0 ? 5000000 : request.Limit, 1, 5000000);
        var sourceCodes = string.IsNullOrWhiteSpace(request.SourceCode)
            ? DefaultSources
            : request.SourceCode.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        var results = new List<DuckDbEvidenceSourceResult>();

        foreach (var sourceCode in sourceCodes)
        {
            var watch = Stopwatch.StartNew();
            var records = sourceCode.ToLowerInvariant() switch
            {
                "debian-security-tracker" => await LoadDebianAsync(limit, ct),
                "osv" => await LoadOsvAsync("osv", "stg_osv_vulnerabilities", limit, ct),
                "ubuntu-osv" => await LoadOsvAsync("ubuntu-osv", "stg_ubuntu_osv", limit, ct),
                "android-osv" => await LoadOsvAsync("android-osv", "stg_android_osv", limit, ct),
                "google-osv" => await LoadOsvAsync("google-osv", "stg_osv_vulnerabilities", limit, ct),
                "ghsa" => await LoadGhsaAsync(limit, ct),
                "nvd-cve" => await LoadNvdAsync(limit, ct),
                "nvd-cpe" => await LoadCpeAsync(limit, ct),
                "suse-csaf" => await LoadCsafAsync("suse-csaf", limit, ct),
                "alpine-secdb" => await LoadAlpineAsync(limit, ct),
                "redhat-csaf" => await LoadCsafAsync("redhat-csaf", limit, ct),
                "nuget-advisory" => await LoadExternalAdvisoryAsync("nuget-advisory", limit, ct),
                "npm-advisory" => await LoadExternalAdvisoryAsync("npm-advisory", limit, ct),
                "pypi-advisory" => await LoadExternalAdvisoryAsync("pypi-advisory", limit, ct),
                "go-advisory" => await LoadEcosystemAsync("go-advisory", limit, ct),
                "cargo-advisory" => await LoadEcosystemAsync("cargo-advisory", limit, ct),
                "first-epss" => await LoadThreatIntelAsync("first-epss", limit, ct),
                "cisa-kev" => await LoadThreatIntelAsync("cisa-kev", limit, ct),
                "exploitdb" => await LoadThreatIntelAsync("exploitdb", limit, ct),
                "poc-in-github" => await LoadExploitAsync("poc-in-github", limit, ct),
                "nuclei-templates" => await LoadExploitAsync("nuclei-templates", limit, ct),
                "metasploit" => await LoadExploitAsync("metasploit", limit, ct),
                "cnnvd" => await LoadCnnvdAsync(limit, ct),
                _ => []
            };
            await store.ReplaceRecordsAsync(records, ct);
            watch.Stop();
            var result = new DuckDbEvidenceSourceResult(
                sourceCode,
                records.Count,
                records.Sum(x => x.AffectedFacts.Count),
                records.Sum(x => x.SeverityScores.Count),
                records.Sum(x => x.References.Count),
                records.Sum(x => x.Weaknesses.Count),
                watch.ElapsedMilliseconds);
            results.Add(result);
            logger.LogInformation("DuckDB evidence normalized {SourceCode}: records={Records}, facts={Facts}, refs={References}, elapsed={Elapsed}ms.",
                sourceCode, result.records, result.affectedFacts, result.references, result.elapsedMs);
        }

        return new DuckDbEvidenceNormalizeResult(true, store.DatabasePath, results, await store.StatsAsync(ct));
    }

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadDebianAsync(int limit, CancellationToken ct)
    {
        await using var command = db.CreateCommand("""
            select raw_index_id, cve_id, packages::text
            from stg_debian_security_tracker
            limit $1
            """);
        command.CommandTimeout = 300;
        command.Parameters.AddWithValue(limit);
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

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadOsvAsync(string sourceCode, string tableName, int limit, CancellationToken ct)
    {
        var hasSeverity = tableName != "stg_ubuntu_osv";
        var selectSeverity = hasSeverity ? "severity::text" : "'[]'";
        var selectRefs = hasSeverity ? "references_json::text" : "'[]'";
        await using var command = db.CreateCommand($"""
            select raw_index_id, osv_id, aliases, affected::text, {selectSeverity}, {selectRefs}
            from {tableName}
            limit $1
            """);
        command.CommandTimeout = 300;
        command.Parameters.AddWithValue(limit);

        var records = new List<DuckDbEvidenceRecord>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var rawIndexId = reader.GetGuid(0);
            var osvId = reader.GetString(1);
            var aliases = reader.GetFieldValue<string[]>(2);
            var key = PreferredIdentifier(osvId, aliases);
            var affected = JsonNode.Parse(reader.GetString(3));
            var severity = JsonNode.Parse(reader.GetString(4));
            var references = JsonNode.Parse(reader.GetString(5));
            records.Add(EmptyRecord(sourceCode, rawIndexId, key, osvId) with
            {
                AffectedFacts = ExtractOsvFacts(affected).ToList(),
                SeverityScores = ExtractOsvSeverity(severity).ToList(),
                References = ExtractReferences(references).ToList()
            });
        }
        return records;
    }

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadGhsaAsync(int limit, CancellationToken ct)
    {
        await using var command = db.CreateCommand("""
            select raw_index_id, ghsa_id, cve_id, vulnerable_ranges::text, cvss::text, cwes::text, references_json::text, payload::text
            from stg_ghsa_advisories
            limit $1
            """);
        command.CommandTimeout = 300;
        command.Parameters.AddWithValue(limit);

        var records = new List<DuckDbEvidenceRecord>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var rawIndexId = reader.GetGuid(0);
            var ghsaId = reader.GetString(1);
            var cve = reader.IsDBNull(2) ? null : reader.GetString(2);
            var key = string.IsNullOrWhiteSpace(cve) ? ghsaId : cve;
            var payload = JsonNode.Parse(reader.GetString(7));
            var cvss = JsonNode.Parse(reader.GetString(4));
            var cwes = JsonNode.Parse(reader.GetString(5));
            var references = JsonNode.Parse(reader.GetString(6));
            records.Add(EmptyRecord("ghsa", rawIndexId, key, ghsaId) with
            {
                AffectedFacts = ExtractGhsaFacts(payload).ToList(),
                SeverityScores = ExtractGhsaSeverity(cvss).ToList(),
                Weaknesses = ExtractGhsaWeaknesses(cwes).ToList(),
                References = ExtractReferences(references).ToList()
            });
        }
        return records;
    }

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadNvdAsync(int limit, CancellationToken ct)
    {
        await using var command = db.CreateCommand("""
            select raw_index_id, cve_id, configurations::text, metrics::text, weaknesses::text, references_json::text
            from stg_nvd_cves
            limit $1
            """);
        command.CommandTimeout = 300;
        command.Parameters.AddWithValue(limit);

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
            foreach (var range in ArrayItems(item?["ranges"]))
            {
                hadRange = true;
                yield return new DuckDbAffectedFact("package", ecosystem, name, purl, null, OsvRange(range), range?["type"]?.GetValue<string>(), true);
            }

            if (!hadRange && !string.IsNullOrWhiteSpace(name))
                yield return new DuckDbAffectedFact("package", ecosystem, name, purl, null, null, null, true);
        }
    }

    private static IEnumerable<DuckDbAffectedFact> ExtractGhsaFacts(JsonNode? payload)
    {
        foreach (var vulnerability in ArrayItems(payload?["vulnerabilities"]))
        {
            var package = vulnerability?["package"];
            var ecosystem = package?["ecosystem"]?.GetValue<string>() ?? package?["type"]?.GetValue<string>();
            var name = package?["name"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(name)) continue;
            yield return new DuckDbAffectedFact(
                "package",
                ecosystem,
                name,
                ToPurl(ecosystem, name),
                null,
                vulnerability?["vulnerable_version_range"]?.GetValue<string>(),
                "vendor",
                true);
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

    private static IEnumerable<DuckDbSeverityScore> ExtractOsvSeverity(JsonNode? severity)
    {
        foreach (var item in ArrayItems(severity))
        {
            var type = item?["type"]?.GetValue<string>() ?? "OSV";
            var score = item?["score"]?.GetValue<string>();
            yield return new DuckDbSeverityScore(type, null, null, score, null, null);
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
            yield return new DuckDbSeverityScore("CVSS", version, null, vector, score, null);
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
                yield return new DuckDbSeverityScore("CVSS", version, metricName, vector, score, label);
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
                JsonObject obj => obj["url"]?.GetValue<string>(),
                _ => null
            };
            if (string.IsNullOrWhiteSpace(url)) continue;
            var tags = item is JsonObject objWithTags
                ? ArrayItems(objWithTags["tags"]).Select(x => x?.GetValue<string>()).Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x!).ToArray()
                : [];
            var refType = item is JsonObject objWithType ? objWithType["type"]?.GetValue<string>() : null;
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

    private static string PreferredIdentifier(string fallback, IEnumerable<string> aliases) =>
        aliases.FirstOrDefault(x => x.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)) ?? fallback;

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

    private static string? ToPurl(string? ecosystem, string? packageName)
    {
        if (string.IsNullOrWhiteSpace(ecosystem) || string.IsNullOrWhiteSpace(packageName)) return null;
        return ecosystem.ToLowerInvariant() switch
        {
            "npm" => $"pkg:npm/{Uri.EscapeDataString(packageName)}",
            "pypi" => $"pkg:pypi/{Uri.EscapeDataString(packageName.ToLowerInvariant())}",
            "maven" when packageName.Contains(':') => $"pkg:maven/{Uri.EscapeDataString(packageName.Split(':')[0])}/{Uri.EscapeDataString(packageName.Split(':')[1])}",
            "nuget" => $"pkg:nuget/{Uri.EscapeDataString(packageName)}",
            "go" => $"pkg:golang/{packageName}",
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

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadCpeAsync(int limit, CancellationToken ct)
    {
        // CPE data goes to a separate DuckDB table, return empty evidence records for stats tracking
        await using var command = db.CreateCommand("select raw_index_id, cpe23_uri, vendor, product, version, part, target_sw, deprecated from stg_nvd_cpe_dictionary limit $1");
        command.Parameters.AddWithValue(limit);
        command.CommandTimeout = 300;
        var count = 0;
        var rows = new List<string>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            rows.Add(string.Join(",", [
                SqlValue("nvd-cpe"),
                SqlValue(reader.GetGuid(0).ToString("D")),
                SqlValue(reader.GetString(1)),
                SqlValue(reader.IsDBNull(2) ? null : reader.GetString(2)),
                SqlValue(reader.IsDBNull(3) ? null : reader.GetString(3)),
                SqlValue(reader.IsDBNull(4) ? null : reader.GetString(4)),
                SqlValue(reader.IsDBNull(5) ? null : reader.GetString(5)),
                SqlValue(reader.IsDBNull(6) ? null : reader.GetString(6)),
                reader.IsDBNull(7) ? "null" : reader.GetBoolean(7).ToString().ToLowerInvariant()
            ]));
            count++;
        }
        if (count > 0)
        {
            var tempFile = Path.GetTempFileName() + ".csv";
            await File.WriteAllLinesAsync(tempFile, rows, ct);
            try
            {
                using var conn = new DuckDB.NET.Data.DuckDBConnection($"Data Source={store.DatabasePath}");
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = $"copy cpe_entries (source_code, raw_index_id, cpe23_uri, vendor, product, version, part, target_sw, deprecated) from '{tempFile}' (header false, delim ',', quote '\"', escape '\"', null 'null')";
                cmd.ExecuteNonQuery();
            }
            finally { try { File.Delete(tempFile); } catch { } }
        }
        return [new DuckDbEvidenceRecord("nvd-cpe", Guid.Empty, "nvd-cpe", "nvd-cpe", [], [], [], [])];
    }

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadCsafAsync(string sourceCode, int limit, CancellationToken ct)
    {
        await using var command = db.CreateCommand("""
            select r.id, r.external_key, r.payload::text, s.code
            from source_raw_index r
            join sources s on s.id = r.source_id
            where s.code = $1 and r.normalize_status in ('pending', 'succeeded')
            limit $2
            """);
        command.Parameters.AddWithValue(sourceCode);
        command.Parameters.AddWithValue(limit);
        command.CommandTimeout = 300;
        var records = new List<DuckDbEvidenceRecord>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var rawId = reader.GetGuid(0);
            var key = reader.GetString(1);
            var payload = JsonNode.Parse(reader.GetString(2));
            var cves = payload?["cves"]?.AsArray() ?? [];
            foreach (var cveNode in cves)
            {
                var cve = cveNode?.GetValue<string>();
                if (string.IsNullOrWhiteSpace(cve)) continue;
                records.Add(EmptyRecord(sourceCode, rawId, cve, key) with
                {
                    AffectedFacts = ExtractCsafFacts(payload, cve).ToList(),
                    References = ExtractCsafReferences(payload).ToList()
                });
            }
        }
        return records;
    }

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadAlpineAsync(int limit, CancellationToken ct)
    {
        await using var command = db.CreateCommand("select raw_index_id, cve_id, package_name, version, fixed_version, release from stg_alpine_secdb limit $1");
        command.Parameters.AddWithValue(limit);
        command.CommandTimeout = 300;
        var records = new List<DuckDbEvidenceRecord>();
        var seen = new Dictionary<string, List<DuckDbAffectedFact>>(StringComparer.OrdinalIgnoreCase);
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var rawId = reader.GetGuid(0);
            var cve = reader.GetString(1);
            var pkg = reader.GetString(2);
            var ver = reader.IsDBNull(3) ? null : reader.GetString(3);
            var fixedVer = reader.IsDBNull(4) ? null : reader.GetString(4);
            var release = reader.IsDBNull(5) ? null : reader.GetString(5);
            var cveKey = $"CVE-{cve}";
            var range = fixedVer is not null ? $"< {fixedVer}" : (ver is not null ? $"= {ver}" : null);
            if (!seen.TryGetValue(cveKey, out var facts)) { facts = []; seen[cveKey] = facts; }
            facts.Add(new DuckDbAffectedFact("package", $"alpine:{release ?? "edge"}", pkg, ToPurl("alpine", pkg), null, range, "SEMVER", true));
        }
        foreach (var (cveKey, facts) in seen)
            records.Add(new DuckDbEvidenceRecord("alpine-secdb", Guid.Empty, cveKey, cveKey, facts, [], [], []));
        return records;
    }

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadExternalAdvisoryAsync(string sourceCode, int limit, CancellationToken ct)
    {
        await using var command = db.CreateCommand("""
            select raw_index_id, advisory_id, identifiers, title, summary, description, severity_label,
                   references_json::text, affected_products::text, payload::text
            from stg_external_advisories where provider = $1 limit $2
            """);
        command.Parameters.AddWithValue(sourceCode);
        command.Parameters.AddWithValue(limit);
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

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadEcosystemAsync(string sourceCode, int limit, CancellationToken ct)
    {
        var eco = sourceCode switch { "go-advisory" => "go", "cargo-advisory" => "cargo", _ => sourceCode };
        await using var command = db.CreateCommand("""
            select raw_index_id, advisory_id, identifiers, ecosystem, package_name, purl, version_range_raw, range_type, payload::text
            from stg_ecosystem_advisories where provider = $1 limit $2
            """);
        command.Parameters.AddWithValue(sourceCode);
        command.Parameters.AddWithValue(limit);
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
            var range = reader.IsDBNull(6) ? null : reader.GetString(6);
            var rangeType = reader.IsDBNull(7) ? null : reader.GetString(7);
            var key = identifiers.FirstOrDefault(x => x.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)) ?? advisoryId;
            records.Add(EmptyRecord(sourceCode, rawId, key, advisoryId) with
            {
                AffectedFacts = pkgName is not null ? [new DuckDbAffectedFact("package", ecosystem, pkgName, purl, null, range, rangeType, true)] : []
            });
        }
        return records;
    }

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadThreatIntelAsync(string sourceCode, int limit, CancellationToken ct)
    {
        await using var command = db.CreateCommand("""
            select raw_index_id, identifier, epss_score, epss_percentile, observed_at
            from stg_threat_intel_records where provider = $1 limit $2
            """);
        command.Parameters.AddWithValue(sourceCode);
        command.Parameters.AddWithValue(limit);
        command.CommandTimeout = 300;
        var records = new List<DuckDbEvidenceRecord>();
        var rows = new List<string>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var rawId = reader.GetGuid(0);
            var identifier = reader.GetString(1);
            var epss = reader.IsDBNull(2) ? (double?)null : (double)reader.GetDecimal(2);
            var pct = reader.IsDBNull(3) ? (double?)null : (double)reader.GetDecimal(3);
            var observed = reader.IsDBNull(4) ? (string?)null : reader.GetDateTime(4).ToString("O");
            if (epss.HasValue || pct.HasValue)
            {
                rows.Add(string.Join(",", [
                    SqlValue(sourceCode), SqlValue(rawId.ToString("D")), SqlValue(identifier),
                    SqlValue("epss"), epss?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "null",
                    pct?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "null", SqlValue(observed)
                ]));
            }
            records.Add(EmptyRecord(sourceCode, rawId, identifier, identifier) with
            {
                SeverityScores = epss.HasValue ? [new DuckDbSeverityScore("epss", "1.0", null, null, (decimal?)epss, null)] : []
            });
        }
        if (rows.Count > 0)
        {
            var tempFile = Path.GetTempFileName() + ".csv";
            await File.WriteAllLinesAsync(tempFile, rows, ct);
            try
            {
                using var conn = new DuckDB.NET.Data.DuckDBConnection($"Data Source={store.DatabasePath}");
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = $"copy threat_scores (source_code, raw_index_id, vulnerability_key, score_type, score, percentile, observed_at) from '{tempFile}' (header false, delim ',', quote '\"', escape '\"', null 'null')";
                cmd.ExecuteNonQuery();
            }
            finally { try { File.Delete(tempFile); } catch { } }
        }
        return records;
    }

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadExploitAsync(string sourceCode, int limit, CancellationToken ct)
    {
        await using var command = db.CreateCommand("""
            select raw_index_id, source_key, identifiers, title, source_url, artifact_type, exploit_type,
                   maturity, verification_status, published_at, modified_at
            from stg_exploit_pocs where provider = $1 limit $2
            """);
        command.Parameters.AddWithValue(sourceCode);
        command.Parameters.AddWithValue(limit);
        command.CommandTimeout = 300;
        var rows = new List<string>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var rawId = reader.GetGuid(0);
            var sourceKey = reader.GetString(1);
            var identifiers = reader.IsDBNull(2) ? "[]" : System.Text.Json.JsonSerializer.Serialize(reader.GetFieldValue<string[]>(2));
            rows.Add(string.Join(",", [
                SqlValue(sourceCode), SqlValue(rawId.ToString("D")), SqlValue(sourceKey), SqlValue(identifiers),
                SqlValue(reader.IsDBNull(3) ? null : reader.GetString(3)),
                SqlValue(reader.IsDBNull(4) ? null : reader.GetString(4)),
                SqlValue(reader.IsDBNull(5) ? null : reader.GetString(5)),
                SqlValue(reader.IsDBNull(6) ? null : reader.GetString(6)),
                SqlValue(reader.IsDBNull(7) ? null : reader.GetString(7)),
                SqlValue(reader.IsDBNull(8) ? null : reader.GetString(8)),
                reader.IsDBNull(9) ? "null" : SqlValue(reader.GetDateTime(9).ToString("O")),
                reader.IsDBNull(10) ? "null" : SqlValue(reader.GetDateTime(10).ToString("O"))
            ]));
        }
        if (rows.Count > 0)
        {
            var tempFile = Path.GetTempFileName() + ".csv";
            await File.WriteAllLinesAsync(tempFile, rows, ct);
            try
            {
                using var conn = new DuckDB.NET.Data.DuckDBConnection($"Data Source={store.DatabasePath}");
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = $"copy exploits (source_code, raw_index_id, source_key, identifiers, title, source_url, artifact_type, exploit_type, maturity, verification_status, published_at, modified_at) from '{tempFile}' (header false, delim ',', quote '\"', escape '\"', null 'null')";
                cmd.ExecuteNonQuery();
            }
            finally { try { File.Delete(tempFile); } catch { } }
        }
        return [new DuckDbEvidenceRecord(sourceCode, Guid.Empty, sourceCode, sourceCode, [], [], [], [])];
    }

    private async Task<IReadOnlyList<DuckDbEvidenceRecord>> LoadCnnvdAsync(int limit, CancellationToken ct)
    {
        await using var command = db.CreateCommand("""
            select r.id, r.external_key, r.payload::text
            from source_raw_index r
            join sources s on s.id = r.source_id
            where s.code = 'cnnvd' and r.normalize_status = 'succeeded'
            limit $1
            """);
        command.Parameters.AddWithValue(limit);
        command.CommandTimeout = 300;
        var records = new List<DuckDbEvidenceRecord>();
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var rawId = reader.GetGuid(0);
            var key = reader.GetString(1);
            var payload = reader.IsDBNull(2) ? null : JsonNode.Parse(reader.GetString(2));
            var cve = payload?["cveId"]?.GetValue<string>() ?? key;
            var title = payload?["vulName"]?.GetValue<string>();
            var desc = payload?["vulDesc"]?.GetValue<string>();
            var sev = payload?["severity"]?.GetValue<string>();
            var affected = payload?["affected"]?.AsArray() ?? [];
            var facts = new List<DuckDbAffectedFact>();
            foreach (var a in affected)
            {
                var name = a?["product"]?.GetValue<string>() ?? a?["vendor"]?.GetValue<string>();
                if (!string.IsNullOrWhiteSpace(name))
                    facts.Add(new DuckDbAffectedFact("package", null, name, null, null, null, null, true));
            }
            records.Add(EmptyRecord("cnnvd", rawId, cve, key) with
            {
                AffectedFacts = facts,
                SeverityScores = sev is not null ? [new DuckDbSeverityScore("cnnvd", null, null, null, null, sev)] : []
            });
        }
        return records;
    }

    private static IEnumerable<DuckDbAffectedFact> ExtractCsafFacts(JsonNode? payload, string cve)
    {
        if (payload is null) yield break;
        var products = payload["products"]?.AsArray() ?? [];
        foreach (var p in products)
        {
            var name = p?["name"]?.GetValue<string>();
            if (string.IsNullOrWhiteSpace(name)) continue;
            var eco = p?["type"]?.GetValue<string>() ?? p?["ecosystem"]?.GetValue<string>();
            var cpe = p?["cpe"]?.GetValue<string>();
            var vers = p?["versions"]?.AsArray();
            if (vers is not null)
            {
                foreach (var v in vers)
                    yield return new DuckDbAffectedFact("package", eco, name, null, cpe, v?.GetValue<string>(), "SEMVER", true);
            }
            else
                yield return new DuckDbAffectedFact("package", eco, name, null, cpe, null, null, true);
        }
    }

    private static IEnumerable<DuckDbReference> ExtractCsafReferences(JsonNode? payload)
    {
        if (payload is null) yield break;
        var refs = payload["references"]?.AsArray() ?? [];
        foreach (var r in refs)
        {
            var url = r?["url"]?.GetValue<string>();
            if (!string.IsNullOrWhiteSpace(url))
                yield return new DuckDbReference(url, r?["category"]?.GetValue<string>(), []);
        }
    }

    private static string SqlValue(string? value) =>
        string.IsNullOrWhiteSpace(value) ? "null" : $"\"{value.Replace("\"", "\"\"")}\"";
}
