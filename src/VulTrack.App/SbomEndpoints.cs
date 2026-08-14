using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;

namespace VulTrack.App;

public static class SbomEndpoints
{
    public static void Map(WebApplication app, bool duckDbPrimary = false)
    {
        if (duckDbPrimary)
        {
            app.MapPost("/api/v1/sbom.upload", UploadDuckDb).DisableAntiforgery();
            app.MapGet("/api/v1/sbom.list", ListDuckDb);
            app.MapGet("/api/v1/sbom.get", GetDuckDb);
            app.MapPost("/api/v1/sbom.match", MatchDuckDb);
            app.MapGet("/api/v1/sbom.export", ExportDuckDb);
            app.MapPost("/api/v1/sbom.delete", DeleteDuckDb);
            return;
        }
        app.MapPost("/api/v1/sbom.upload", Upload).DisableAntiforgery();
        app.MapGet("/api/v1/sbom.list", List);
        app.MapGet("/api/v1/sbom.get", Get);
        app.MapPost("/api/v1/sbom.match", Match);
        app.MapGet("/api/v1/sbom.export", Export);
        app.MapPost("/api/v1/sbom.delete", Delete);
    }

    private static async Task<IResult> UploadDuckDb(DuckDbEvidenceStore duckDb, HttpRequest request, CancellationToken ct)
    {
        try
        {
            using var reader = new StreamReader(request.Body);
            var json = await reader.ReadToEndAsync(ct);
            var doc = JsonNode.Parse(json);
            if (doc is null) return ApiResult.Error("INVALID", "Cannot parse JSON");

            var meta = doc["metadata"];
            var metadataName = $"{Text(meta?["component"]?["name"])} {Text(meta?["component"]?["version"])}".Trim();
            var name = FirstText(request.Query["name"].ToString(), metadataName,
                SbomNameFromSerial(Text(doc["serialNumber"])), "CycloneDX SBOM");
            var id = Guid.NewGuid();
            var drafts = (doc["components"]?.AsArray() ?? [])
                .Select(ToSbomComponent)
                .Where(component => !string.IsNullOrWhiteSpace(component.Purl) || !string.IsNullOrWhiteSpace(component.Cpe23Uri))
                .GroupBy(component => (component.Purl ?? "", component.Cpe23Uri ?? "", component.Name ?? "", component.Version ?? "", component.Ecosystem ?? ""))
                .Select(group => group.First())
                .ToList();
            var components = drafts.Select(draft => new DuckDbSbomComponent(
                Guid.NewGuid(), id, draft.Purl, draft.Name, draft.Version, draft.Ecosystem, draft.GroupName,
                draft.Vendor, draft.Product, draft.Cpe23Uri, draft.SourcePackageName, draft.SourcePackageVersion,
                draft.ComponentType, draft.MetadataJson, 0)).ToList();
            await duckDb.SaveSbomAsync(id, name, json, components, ct);
            return ApiResult.Ok(new { id, name, componentCount = components.Count });
        }
        catch (Exception ex)
        {
            return ApiResult.Error("UPLOAD_FAILED", ex.Message);
        }
    }

    private static async Task<IResult> ListDuckDb(DuckDbEvidenceStore duckDb, CancellationToken ct)
    {
        var items = (await duckDb.ListSbomsAsync(ct)).Select(item => new
        {
            id = item.Id,
            item.Name,
            item.Format,
            item.ComponentCount,
            item.MatchedCount,
            item.UploadedAt
        });
        return ApiResult.Ok(new { items });
    }

    private static async Task<IResult> GetDuckDb(
        DuckDbEvidenceStore duckDb,
        Guid id,
        int? vulnerabilityLimit,
        int? vulnerabilityOffset,
        CancellationToken ct)
    {
        var upload = await duckDb.GetSbomAsync(id, ct);
        if (upload is null) return ApiResult.NotFound("NOT_FOUND", id.ToString());
        var components = (await duckDb.GetSbomComponentsAsync(id, ct)).Select(component => new
        {
            id = component.Id,
            purl = component.Purl,
            name = component.Name,
            version = component.Version,
            ecosystem = component.Ecosystem,
            type = component.ComponentType,
            vulnCount = component.VulnCount,
            vendor = component.Vendor,
            product = component.Product,
            cpe23Uri = component.Cpe23Uri,
            sourcePackageName = component.SourcePackageName,
            sourcePackageVersion = component.SourcePackageVersion
        });
        var vulnerabilities = (await duckDb.GetSbomFindingsAsync(
            id, Math.Clamp(vulnerabilityLimit ?? 2000, 1, 10000), Math.Max(vulnerabilityOffset ?? 0, 0), ct))
            .Select(finding => new
            {
                id = finding.Id,
                componentId = finding.ComponentId,
                vulnerabilityId = finding.VulnerabilityId,
                primaryIdentifier = finding.PrimaryIdentifier,
                title = finding.Title,
                severityLabel = finding.SeverityLabel,
                cvssScore = finding.CvssScore,
                componentName = finding.ComponentName,
                ecosystem = finding.Ecosystem,
                versionRange = finding.VersionRange,
                versionMatched = finding.VersionMatched,
                matchBasis = finding.MatchBasis,
                matchedVersion = finding.MatchedVersion,
                identifiers = finding.Identifiers,
                aliases = finding.Aliases
            });
        var sbom = new
        {
            id = upload.Id,
            upload.Name,
            upload.Format,
            upload.ComponentCount,
            upload.MatchedCount,
            upload.UploadedAt
        };
        return ApiResult.Ok(new { sbom, components, vulnerabilities });
    }

    private static async Task<IResult> MatchDuckDb(
        DuckDbEvidenceStore duckDb,
        SbomMatchRequest req,
        CancellationToken ct)
    {
        var components = await duckDb.GetSbomComponentsAsync(req.SbomId, ct);
        if (components.Count == 0 && await duckDb.GetSbomAsync(req.SbomId, ct) is null)
            return ApiResult.NotFound("NOT_FOUND", req.SbomId.ToString());

        var matchComponents = components.Select(component =>
        {
            var decodedPurl = string.IsNullOrWhiteSpace(component.Purl) ? null : Uri.UnescapeDataString(component.Purl);
            var purlWithoutVersion = decodedPurl is null ? null : StripVersion(decodedPurl) ?? decodedPurl;
            return new DuckDbSbomMatchComponent(
                component.Id, component.Purl, decodedPurl, purlWithoutVersion, component.Name, component.Version,
                component.Ecosystem, MapEcosystem(component.Ecosystem), component.Cpe23Uri,
                CpeProductPrefix(component.Cpe23Uri), ParseCpe(component.Cpe23Uri)?.Product,
                component.SourcePackageName, component.SourcePackageVersion);
        }).ToList();
        var candidates = await duckDb.QuerySbomCandidateMatchesAsync(matchComponents, ct);
        var evaluated = candidates.Select(item =>
        {
            var matchedVersion = string.Equals(item.Basis, "source-package", StringComparison.OrdinalIgnoreCase)
                ? item.SourcePackageVersion ?? item.ComponentVersion
                : item.ComponentVersion;
            var versionMatched = ResolveSbomVersionMatch(matchedVersion, item.Range, item.Ecosystem, item.ComponentCpe, item.MatchedCpe, item.Basis);
            var possible = versionMatched != true && IsPossibleSbomMatch(matchedVersion, item.Range, item.Basis);
            return new DuckDbSbomMatch(
                item.ComponentId, item.VulnerabilityId, item.Purl, item.DisplayName, item.Ecosystem, item.Range,
                possible ? null : versionMatched, possible ? $"possible-{item.Basis}" : item.Basis, matchedVersion);
        })
        .ToList();
        var matches = evaluated
            .Where(item => item.VersionMatched == true || item.Basis?.StartsWith("possible-", StringComparison.OrdinalIgnoreCase) == true)
            .GroupBy(item => (item.ComponentId, item.VulnerabilityId))
            .Select(group => group
                .OrderByDescending(item => item.VersionMatched == true)
                .ThenBy(item => MatchBasisPriority(item.Basis))
                .ThenBy(item => item.Range?.Length ?? int.MaxValue)
                .First())
            .ToList();
        await duckDb.ReplaceSbomMatchesAsync(req.SbomId, matches, ct);
        return ApiResult.Ok(new { matched = matches.Count, source = "duckdb" });
    }

    private static int MatchBasisPriority(string? basis)
    {
        var normalized = basis?.StartsWith("possible-", StringComparison.OrdinalIgnoreCase) == true
            ? basis["possible-".Length..]
            : basis;
        return normalized?.ToLowerInvariant() switch
        {
            "cpe-exact" => 0,
            "purl" => 1,
            "source-package" => 2,
            "name" => 3,
            "package" => 4,
            "cpe-product" => 5,
            _ => 9
        };
    }

    private static async Task<IResult> DeleteDuckDb(DuckDbEvidenceStore duckDb, SbomDeleteRequest req, CancellationToken ct)
    {
        await duckDb.DeleteSbomAsync(req.SbomId, ct);
        return ApiResult.Ok(new { deleted = true });
    }

    private static async Task<IResult> ExportDuckDb(DuckDbEvidenceStore duckDb, Guid id, CancellationToken ct)
    {
        if (await duckDb.GetSbomAsync(id, ct) is null)
            return ApiResult.NotFound("NOT_FOUND", id.ToString());
        var components = await duckDb.GetSbomComponentsAsync(id, ct);
        var findings = await duckDb.GetSbomFindingsAsync(id, 10000, 0, ct);
        var keys = findings.Select(finding => finding.PrimaryIdentifier).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var weaknesses = await duckDb.QueryWeaknessesManyAsync(keys, 80, ct);
        var references = await duckDb.QueryReferencesManyAsync(keys, 160, ct);
        var findingsByComponent = findings.GroupBy(finding => finding.ComponentId).ToDictionary(group => group.Key, group => group.ToArray());
        var rows = new StringBuilder();
        rows.AppendLine("""
            <html><head><meta charset="utf-8"></head><body><table border="1">
            <thead><tr><th>Component Name</th><th>Component PURL</th><th>CPE 2.3 URI</th><th>Vendor</th><th>Product</th><th>Component Version</th><th>CVE</th><th>Affected Version / Range</th><th>Version Matched</th><th>Severity</th><th>CVSS</th><th>CWE</th><th>URLs</th><th>Title</th></tr></thead><tbody>
            """);
        foreach (var component in components)
        {
            var componentFindings = findingsByComponent.GetValueOrDefault(component.Id) ?? [];
            if (componentFindings.Length == 0)
            {
                AppendCells(rows, component.Name ?? "", component.Purl ?? "", component.Cpe23Uri ?? "",
                    component.Vendor ?? "", component.Product ?? "", component.Version ?? "",
                    "", "", "", "", "", "", "", "");
                continue;
            }
            foreach (var finding in componentFindings)
            {
                var cwes = weaknesses.GetValueOrDefault(finding.PrimaryIdentifier) ?? [];
                var urls = references.GetValueOrDefault(finding.PrimaryIdentifier) ?? [];
                AppendCells(rows, component.Name ?? "", component.Purl ?? "", component.Cpe23Uri ?? "",
                    component.Vendor ?? "", component.Product ?? "", component.Version ?? "",
                    finding.PrimaryIdentifier, finding.VersionRange ?? "", finding.VersionMatched?.ToString() ?? "",
                    finding.SeverityLabel ?? "", finding.CvssScore?.ToString() ?? "",
                    string.Join("; ", cwes.Select(row => Convert.ToString(row.GetValueOrDefault("weakness_id"))).Where(value => !string.IsNullOrWhiteSpace(value))),
                    string.Join("; ", urls.Select(row => Convert.ToString(row.GetValueOrDefault("url"))).Where(value => !string.IsNullOrWhiteSpace(value))),
                    finding.Title ?? "");
            }
        }
        rows.AppendLine("</tbody></table></body></html>");
        return Results.File(Encoding.UTF8.GetBytes(rows.ToString()), "application/vnd.ms-excel; charset=utf-8", $"vultrack-sbom-{id:N}.xls");
    }

    private static async Task<IResult> Upload(NpgsqlDataSource db, HttpRequest request, CancellationToken ct)
    {
        try
        {
            using var reader = new StreamReader(request.Body);
            var json = await reader.ReadToEndAsync(ct);
            var doc = JsonNode.Parse(json);
            if (doc is null) return ApiResult.Error("INVALID", "Cannot parse JSON");

            var meta = doc["metadata"];
            var metadataName = $"{Text(meta?["component"]?["name"])} {Text(meta?["component"]?["version"])}".Trim();
            var name = FirstText(
                request.Query["name"].ToString(),
                metadataName,
                SbomNameFromSerial(Text(doc["serialNumber"])),
                "CycloneDX SBOM");
            var sid = Guid.NewGuid();

            var comps = (doc["components"]?.AsArray() ?? [])
                .Select(ToSbomComponent)
                .Where(x => !string.IsNullOrWhiteSpace(x.Purl) || !string.IsNullOrWhiteSpace(x.Cpe23Uri))
                .ToList();
            var deduped = comps
                .GroupBy(x => (x.Purl ?? "", x.Cpe23Uri ?? "", x.Name ?? "", x.Version ?? "", x.Ecosystem ?? ""))
                .Select(g => g.First())
                .ToList();

            await using var cmd = db.CreateCommand(
                "INSERT INTO sbom_uploads(id,name,format,metadata,component_count) VALUES($1,$2,'cyclonedx',$3::jsonb,$4)");
            cmd.Parameters.AddWithValue(sid);
            cmd.Parameters.AddWithValue(name);
            cmd.Parameters.AddWithValue(json);
            cmd.Parameters.AddWithValue(deduped.Count);
            await cmd.ExecuteNonQueryAsync(ct);

            if (deduped.Count > 0)
            {
                var p = 1;
                var vals = new List<string>();
                var pl = new List<object>();
                foreach (var item in deduped)
                {
                    vals.Add($"(${p++},${p++},${p++},${p++},${p++},${p++},${p++},${p++},${p++},${p++},${p++},${p++},${p++}::jsonb)");
                    pl.Add(sid); pl.Add((object?)item.Purl ?? DBNull.Value); pl.Add((object?)item.Name ?? DBNull.Value);
                    pl.Add((object?)item.Version ?? DBNull.Value); pl.Add((object?)item.Ecosystem ?? DBNull.Value);
                    pl.Add((object?)item.GroupName ?? DBNull.Value); pl.Add((object?)item.Vendor ?? DBNull.Value);
                    pl.Add((object?)item.Product ?? DBNull.Value); pl.Add((object?)item.Cpe23Uri ?? DBNull.Value);
                    pl.Add((object?)item.SourcePackageName ?? DBNull.Value); pl.Add((object?)item.SourcePackageVersion ?? DBNull.Value);
                    pl.Add((object?)item.ComponentType ?? DBNull.Value); pl.Add(item.MetadataJson);
                }
                await using var ic = db.CreateCommand(
                    $"INSERT INTO sbom_components(sbom_id,purl,name,version,ecosystem,group_name,vendor,product,cpe23_uri,source_package_name,source_package_version,component_type,metadata) VALUES {string.Join(",", vals)}");
                foreach (var v in pl) ic.Parameters.AddWithValue(v);
                await ic.ExecuteNonQueryAsync(ct);

                await using var uc = db.CreateCommand("UPDATE sbom_uploads SET component_count=$1 WHERE id=$2");
                uc.Parameters.AddWithValue(deduped.Count);
                uc.Parameters.AddWithValue(sid);
                await uc.ExecuteNonQueryAsync(ct);
            }

            return ApiResult.Ok(new { id = sid, name, componentCount = deduped.Count });
        }
        catch (Exception ex) { return ApiResult.Error("UPLOAD_FAILED", ex.Message); }
    }

    private static async Task<IResult> List(NpgsqlDataSource db, CancellationToken ct)
    {
        var items = new List<object>();
        await using var c = db.CreateCommand(
            "SELECT id,name,format,component_count,matched_count,uploaded_at FROM sbom_uploads ORDER BY uploaded_at DESC LIMIT 50");
        await using var r = await c.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            items.Add(new
            {
                id = r.GetGuid(0),
                name = r.GetString(1),
                format = r.GetString(2),
                componentCount = r.GetInt32(3),
                matchedCount = r.GetInt32(4),
                uploadedAt = r.GetFieldValue<DateTimeOffset>(5)
            });
        return ApiResult.Ok(new { items });
    }

    private static async Task<IResult> Get(NpgsqlDataSource db, Guid id, int? vulnerabilityLimit, int? vulnerabilityOffset, CancellationToken ct)
    {
        object? sbom = null;
        await using (var c = db.CreateCommand(
            "SELECT id,name,format,component_count,matched_count,uploaded_at FROM sbom_uploads WHERE id=$1"))
        {
            c.Parameters.AddWithValue(id); await using var r = await c.ExecuteReaderAsync(ct);
            if (await r.ReadAsync(ct)) sbom = new
            {
                id = r.GetGuid(0),
                name = r.GetString(1),
                format = r.GetString(2),
                componentCount = r.GetInt32(3),
                matchedCount = r.GetInt32(4),
                uploadedAt = r.GetFieldValue<DateTimeOffset>(5)
            };
        }
        if (sbom is null) return ApiResult.NotFound("NOT_FOUND", id.ToString());

        var comps = new List<object>();
        await using (var cc = db.CreateCommand(
            "SELECT id,purl,name,version,ecosystem,component_type,vuln_count,vendor,product,cpe23_uri,source_package_name,source_package_version FROM sbom_components WHERE sbom_id=$1 ORDER BY ecosystem,name"))
        {
            cc.Parameters.AddWithValue(id); await using var r = await cc.ExecuteReaderAsync(ct);
            while (await r.ReadAsync(ct)) comps.Add(new
            {
                id = r.GetGuid(0),
                purl = r.IsDBNull(1) ? null : r.GetString(1),
                name = r.IsDBNull(2) ? null : r.GetString(2),
                version = r.IsDBNull(3) ? null : r.GetString(3),
                ecosystem = r.IsDBNull(4) ? null : r.GetString(4),
                type = r.IsDBNull(5) ? null : r.GetString(5),
                vulnCount = r.GetInt32(6),
                vendor = r.IsDBNull(7) ? null : r.GetString(7),
                product = r.IsDBNull(8) ? null : r.GetString(8),
                cpe23Uri = r.IsDBNull(9) ? null : r.GetString(9),
                sourcePackageName = r.IsDBNull(10) ? null : r.GetString(10),
                sourcePackageVersion = r.IsDBNull(11) ? null : r.GetString(11)
            });
        }

        var vulns = new List<object>();
        await using (var vc = db.CreateCommand(
            "SELECT sv.id,sv.sbom_component_id,sv.vulnerability_id,v.primary_identifier,v.title,v.severity_label,v.max_cvss_score,sv.display_name,sv.ecosystem,sv.normalized_range,sv.version_matched,sv.match_basis,sv.matched_version,v.identifiers,v.aliases FROM sbom_vulnerabilities sv JOIN vulnerabilities v ON v.id=sv.vulnerability_id JOIN sbom_components c ON c.id=sv.sbom_component_id WHERE c.sbom_id=$1 ORDER BY coalesce(v.max_cvss_score,0) DESC LIMIT $2 OFFSET $3"))
        {
            vc.Parameters.AddWithValue(id);
            vc.Parameters.AddWithValue(Math.Clamp(vulnerabilityLimit ?? 2000, 1, 10000));
            vc.Parameters.AddWithValue(Math.Max(vulnerabilityOffset ?? 0, 0));
            await using var r = await vc.ExecuteReaderAsync(ct);
            while (await r.ReadAsync(ct)) vulns.Add(new
            {
                id = r.GetGuid(0),
                componentId = r.GetGuid(1),
                vulnerabilityId = r.GetGuid(2),
                primaryIdentifier = r.GetString(3),
                title = r.IsDBNull(4) ? null : r.GetString(4),
                severityLabel = r.IsDBNull(5) ? null : r.GetString(5),
                cvssScore = r.IsDBNull(6) ? (decimal?)null : r.GetDecimal(6),
                componentName = r.IsDBNull(7) ? null : r.GetString(7),
                ecosystem = r.IsDBNull(8) ? null : r.GetString(8),
                versionRange = r.IsDBNull(9) ? null : r.GetString(9),
                versionMatched = r.IsDBNull(10) ? (bool?)null : r.GetBoolean(10),
                matchBasis = r.IsDBNull(11) ? null : r.GetString(11),
                matchedVersion = r.IsDBNull(12) ? null : r.GetString(12),
                identifiers = r.GetFieldValue<string[]>(13),
                aliases = r.GetFieldValue<string[]>(14)
            });
        }

        return ApiResult.Ok(new { sbom, components = comps, vulnerabilities = vulns });
    }

    private static async Task<IResult> Match(NpgsqlDataSource db, DuckDbEvidenceStore duckDb, SbomMatchRequest req, CancellationToken ct)
    {
        var m = 0;
        await using var conn = await db.OpenConnectionAsync(ct);
        await using var transaction = await conn.BeginTransactionAsync(ct);
        var comps = new List<(Guid Id, string? Purl, string? Name, string? Version, string? Eco, string? Vendor, string? Product, string? Cpe23Uri, string? SourcePackageName, string? SourcePackageVersion)>();
        await using (var s = new NpgsqlCommand(
            "SELECT id,purl,name,version,ecosystem,vendor,product,cpe23_uri,source_package_name,source_package_version FROM sbom_components WHERE sbom_id=$1", conn))
        {
            s.Parameters.AddWithValue(req.SbomId); await using var r = await s.ExecuteReaderAsync(ct);
            while (await r.ReadAsync(ct))
                comps.Add((r.GetGuid(0), r.IsDBNull(1) ? null : r.GetString(1), r.IsDBNull(2) ? null : r.GetString(2),
                    r.IsDBNull(3) ? null : r.GetString(3), r.IsDBNull(4) ? null : r.GetString(4),
                    r.IsDBNull(5) ? null : r.GetString(5), r.IsDBNull(6) ? null : r.GetString(6),
                    r.IsDBNull(7) ? null : r.GetString(7), r.IsDBNull(8) ? null : r.GetString(8),
                    r.IsDBNull(9) ? null : r.GetString(9)));
        }

        await using (var clear = new NpgsqlCommand("""
            delete from sbom_vulnerabilities sv
            using sbom_components sc
            where sc.id = sv.sbom_component_id and sc.sbom_id = $1
            """, conn))
        {
            clear.Parameters.AddWithValue(req.SbomId);
            await clear.ExecuteNonQueryAsync(ct);
        }
        await using (var reset = new NpgsqlCommand(
            "update sbom_components set vuln_count = 0 where sbom_id = $1", conn))
        {
            reset.Parameters.AddWithValue(req.SbomId);
            await reset.ExecuteNonQueryAsync(ct);
        }

        if (!duckDb.Enabled)
            return ApiResult.Error("DUCKDB_DISABLED", "SBOM matching requires DuckDB affected component projection.");

        var matchComponents = comps.Select(component =>
        {
            var purlDec = string.IsNullOrWhiteSpace(component.Purl) ? null : Uri.UnescapeDataString(component.Purl);
            var pwv = purlDec is null ? null : StripVersion(purlDec) ?? purlDec;
            var meco = MapEcosystem(component.Eco);
            return new DuckDbSbomMatchComponent(
                component.Id,
                component.Purl,
                purlDec,
                pwv,
                component.Name,
                component.Version,
                component.Eco,
                meco,
                component.Cpe23Uri,
                CpeProductPrefix(component.Cpe23Uri),
                ParseCpe(component.Cpe23Uri)?.Product,
                component.SourcePackageName,
                component.SourcePackageVersion);
        }).ToList();
        var matches = await duckDb.QuerySbomCandidateMatchesAsync(matchComponents, ct);

        var matched = matches
            .Select(item =>
            {
                var matchedVersion = string.Equals(item.Basis, "source-package", StringComparison.OrdinalIgnoreCase)
                    ? item.SourcePackageVersion ?? item.ComponentVersion
                    : item.ComponentVersion;
                var versionMatched = ResolveSbomVersionMatch(matchedVersion, item.Range, item.Ecosystem, item.ComponentCpe, item.MatchedCpe, item.Basis);
                var possible = versionMatched != true && IsPossibleSbomMatch(matchedVersion, item.Range, item.Basis);
                return new
                {
                    item.ComponentId,
                    item.VulnerabilityId,
                    item.Purl,
                    item.DisplayName,
                    item.Ecosystem,
                    item.Range,
                    Basis = possible ? $"possible-{item.Basis}" : item.Basis,
                    MatchedVersion = matchedVersion,
                    VersionMatched = possible ? (bool?)null : versionMatched
                };
            })
            .Where(item => item.VersionMatched == true || item.Basis?.StartsWith("possible-", StringComparison.OrdinalIgnoreCase) == true)
            .ToList();

        foreach (var chunk in matched.Chunk(1000))
        {
            var p = 1;
            var values = new List<string>();
            var parameters = new List<object>();
            foreach (var item in chunk)
            {
                values.Add($"(${p++},${p++},${p++},${p++},${p++},${p++},${p++},${p++},${p++})");
                parameters.Add(item.ComponentId);
                parameters.Add(item.VulnerabilityId);
                parameters.Add((object?)item.Purl ?? DBNull.Value);
                parameters.Add((object?)item.DisplayName ?? DBNull.Value);
                parameters.Add((object?)item.Ecosystem ?? DBNull.Value);
                parameters.Add((object?)item.Range ?? DBNull.Value);
                parameters.Add((object?)item.VersionMatched ?? DBNull.Value);
                parameters.Add((object?)item.Basis ?? DBNull.Value);
                parameters.Add((object?)item.MatchedVersion ?? DBNull.Value);
            }
            await using var ins = new NpgsqlCommand($"""
                insert into sbom_vulnerabilities(sbom_component_id,vulnerability_id,purl,display_name,ecosystem,normalized_range,version_matched,match_basis,matched_version)
                values {string.Join(",", values)}
                on conflict(sbom_component_id,vulnerability_id)
                do update set version_matched = coalesce(excluded.version_matched, sbom_vulnerabilities.version_matched),
                              normalized_range = coalesce(excluded.normalized_range, sbom_vulnerabilities.normalized_range),
                              display_name = coalesce(excluded.display_name, sbom_vulnerabilities.display_name),
                              ecosystem = coalesce(excluded.ecosystem, sbom_vulnerabilities.ecosystem),
                              match_basis = coalesce(excluded.match_basis, sbom_vulnerabilities.match_basis),
                              matched_version = coalesce(excluded.matched_version, sbom_vulnerabilities.matched_version)
                """, conn);
            foreach (var parameter in parameters) ins.Parameters.AddWithValue(parameter);
            await ins.ExecuteNonQueryAsync(ct);
        }
        m = matched.Count;

        await using (var updateCounts = new NpgsqlCommand("""
            update sbom_components sc
            set vuln_count = coalesce(t.cnt, 0)
            from (
              select sc2.id, count(sv.*)::integer as cnt
              from sbom_components sc2
              left join sbom_vulnerabilities sv on sv.sbom_component_id = sc2.id
              where sc2.sbom_id = $1
              group by sc2.id
            ) t
            where sc.id = t.id
            """, conn))
        {
            updateCounts.Parameters.AddWithValue(req.SbomId);
            await updateCounts.ExecuteNonQueryAsync(ct);
        }

        await using var us = new NpgsqlCommand(
            "UPDATE sbom_uploads SET matched_count=(SELECT count(DISTINCT sv.vulnerability_id) FROM sbom_vulnerabilities sv JOIN sbom_components sc ON sc.id=sv.sbom_component_id WHERE sc.sbom_id=$1) WHERE id=$1", conn);
        us.Parameters.AddWithValue(req.SbomId);
        await us.ExecuteNonQueryAsync(ct);

        await transaction.CommitAsync(ct);
        return ApiResult.Ok(new { matched = m });
    }

    private static async Task<IResult> Delete(NpgsqlDataSource db, SbomDeleteRequest req, CancellationToken ct)
    {
        await using var c = db.CreateCommand("DELETE FROM sbom_uploads WHERE id=$1");
        c.Parameters.AddWithValue(req.SbomId);
        await c.ExecuteNonQueryAsync(ct);
        return ApiResult.Ok(new { deleted = true });
    }

    private static async Task<IResult> Export(NpgsqlDataSource db, DuckDbEvidenceStore duckDb, VulnerabilityDetailSnapshotStore snapshots, Guid id, CancellationToken ct)
    {
        var exportRows = new List<SbomExportRow>();
        await using var cmd = db.CreateCommand("""
            select sc.name, sc.purl, sc.cpe23_uri, sc.vendor, sc.product, sc.version,
                   sv.vulnerability_id,
                   v.primary_identifier, sv.normalized_range, sv.version_matched,
                   v.severity_label, v.max_cvss_score, v.title
            from sbom_components sc
            left join sbom_vulnerabilities sv on sv.sbom_component_id = sc.id
            left join vulnerabilities v on v.id = sv.vulnerability_id
            where sc.sbom_id = $1
            order by lower(coalesce(sc.name, sc.product, sc.purl, sc.cpe23_uri, '')), coalesce(v.max_cvss_score, 0) desc nulls last, v.primary_identifier
            """);
        cmd.Parameters.AddWithValue(id);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            exportRows.Add(new SbomExportRow(
                reader.IsDBNull(0) ? "" : reader.GetString(0),
                reader.IsDBNull(1) ? "" : reader.GetString(1),
                reader.IsDBNull(2) ? "" : reader.GetString(2),
                reader.IsDBNull(3) ? "" : reader.GetString(3),
                reader.IsDBNull(4) ? "" : reader.GetString(4),
                reader.IsDBNull(5) ? "" : reader.GetString(5),
                reader.IsDBNull(6) ? null : reader.GetGuid(6),
                reader.IsDBNull(7) ? "" : reader.GetString(7),
                reader.IsDBNull(8) ? "" : reader.GetString(8),
                reader.IsDBNull(9) ? null : reader.GetBoolean(9),
                reader.IsDBNull(10) ? "" : reader.GetString(10),
                reader.IsDBNull(11) ? null : reader.GetDecimal(11),
                reader.IsDBNull(12) ? "" : reader.GetString(12)));
        }

        var vulnerabilityIds = exportRows
            .Select(row => row.VulnerabilityId)
            .Where(id => id.HasValue)
            .Select(id => id!.Value)
            .Distinct()
            .ToArray();
        var snapshotDetails = await snapshots.TryGetManyAsync(vulnerabilityIds, ct);
        var fallbackIds = vulnerabilityIds
            .Where(vulnerabilityId =>
                !snapshotDetails.TryGetValue(vulnerabilityId, out var detail) ||
                string.IsNullOrWhiteSpace(SnapshotWeaknesses(detail)) ||
                string.IsNullOrWhiteSpace(SnapshotReferenceUrls(detail)))
            .ToArray();
        var fallbackKeys = exportRows
            .Where(row => row.VulnerabilityId.HasValue && fallbackIds.Contains(row.VulnerabilityId.Value) && !string.IsNullOrWhiteSpace(row.Cve))
            .GroupBy(row => row.VulnerabilityId!.Value)
            .ToDictionary(group => group.Key, group => group.First().Cve);
        var fallbackDetails = duckDb.Enabled
            ? await LoadSbomExportDuckDbFallbackDetailsAsync(duckDb, fallbackKeys, ct)
            : await LoadSbomExportFallbackDetailsAsync(db, fallbackIds, ct);

        var rows = new StringBuilder();
        rows.AppendLine("""
            <html><head><meta charset="utf-8"></head><body>
            <table border="1">
            <thead><tr>
              <th>Component Name</th><th>Component PURL</th><th>CPE 2.3 URI</th><th>Vendor</th><th>Product</th><th>Component Version</th>
              <th>CVE</th><th>Affected Version / Range</th><th>Version Matched</th><th>Severity</th><th>CVSS</th><th>CWE</th><th>URLs</th><th>Title</th>
            </tr></thead><tbody>
            """);

        foreach (var row in exportRows)
        {
            JsonElement? snapshotDetail = row.VulnerabilityId is Guid vulnerabilityId && snapshotDetails.TryGetValue(vulnerabilityId, out var detail)
                ? detail
                : null;
            var fallback = row.VulnerabilityId is Guid fallbackId && fallbackDetails.TryGetValue(fallbackId, out var fallbackDetail)
                ? fallbackDetail
                : SbomExportDetail.Empty;
            var severity = SnapshotVulnerabilityText(snapshotDetail, "severityLabel") ?? row.Severity;
            var cvss = SnapshotVulnerabilityDecimal(snapshotDetail, "maxCvssScore") ?? row.Cvss;
            var title = SnapshotVulnerabilityText(snapshotDetail, "title") ?? row.Title;
            var cwes = FirstText(SnapshotWeaknesses(snapshotDetail), fallback.Cwes);
            var urls = FirstText(SnapshotReferenceUrls(snapshotDetail), fallback.Urls);

            AppendCells(rows,
                row.ComponentName,
                row.ComponentPurl,
                row.Cpe23Uri,
                row.Vendor,
                row.Product,
                row.ComponentVersion,
                row.Cve,
                row.AffectedRange,
                row.VersionMatched?.ToString() ?? "",
                severity,
                cvss?.ToString() ?? "",
                cwes,
                urls,
                title);
        }

        rows.AppendLine("</tbody></table></body></html>");

        return Results.File(
            Encoding.UTF8.GetBytes(rows.ToString()),
            "application/vnd.ms-excel; charset=utf-8",
            $"vultrack-sbom-{id:N}.xls");
    }

    private static async Task<IReadOnlyDictionary<Guid, SbomExportDetail>> LoadSbomExportFallbackDetailsAsync(NpgsqlDataSource db, IReadOnlyCollection<Guid> vulnerabilityIds, CancellationToken ct)
    {
        var details = new Dictionary<Guid, SbomExportDetail>();
        if (vulnerabilityIds.Count == 0) return details;

        await using (var cweCmd = db.CreateCommand("""
            select vulnerability_id, string_agg(distinct nullif(weakness_id,''), '; ') as cwes
            from vulnerability_weaknesses
            where vulnerability_id = any($1)
            group by vulnerability_id
            """))
        {
            cweCmd.Parameters.AddWithValue(vulnerabilityIds.ToArray());
            await using var reader = await cweCmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var vulnerabilityId = reader.GetGuid(0);
                var current = details.TryGetValue(vulnerabilityId, out var existing)
                    ? existing
                    : SbomExportDetail.Empty;
                details[vulnerabilityId] = current with
                {
                    Cwes = reader.IsDBNull(1) ? "" : reader.GetString(1)
                };
            }
        }

        await using (var urlsCmd = db.CreateCommand("""
            with distinct_urls as (
              select distinct vulnerability_id, url
              from vulnerability_references
              where vulnerability_id = any($1)
                and url is not null
            ),
            ranked_urls as (
              select vulnerability_id, url,
                     row_number() over (partition by vulnerability_id order by url) as rn
              from distinct_urls
            )
            select vulnerability_id, string_agg(url, '; ' order by url) as urls
            from ranked_urls
            where rn <= 20
            group by vulnerability_id
            """))
        {
            urlsCmd.Parameters.AddWithValue(vulnerabilityIds.ToArray());
            await using var reader = await urlsCmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                var vulnerabilityId = reader.GetGuid(0);
                var current = details.TryGetValue(vulnerabilityId, out var existing)
                    ? existing
                    : SbomExportDetail.Empty;
                details[vulnerabilityId] = current with
                {
                    Urls = reader.IsDBNull(1) ? "" : reader.GetString(1)
                };
            }
        }

        return details;
    }

    private static async Task<IReadOnlyDictionary<Guid, SbomExportDetail>> LoadSbomExportDuckDbFallbackDetailsAsync(
        DuckDbEvidenceStore duckDb,
        IReadOnlyDictionary<Guid, string> vulnerabilityKeys,
        CancellationToken ct)
    {
        var details = new Dictionary<Guid, SbomExportDetail>();
        if (vulnerabilityKeys.Count == 0) return details;

        var keys = vulnerabilityKeys.Values.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var weaknessesTask = duckDb.QueryWeaknessesManyAsync(keys, 80, ct);
        var referencesTask = duckDb.QueryReferencesManyAsync(keys, 20, ct);
        await Task.WhenAll(weaknessesTask, referencesTask);

        var weaknesses = await weaknessesTask;
        var references = await referencesTask;
        foreach (var (vulnerabilityId, key) in vulnerabilityKeys)
        {
            weaknesses.TryGetValue(key, out var weaknessRows);
            references.TryGetValue(key, out var referenceRows);
            details[vulnerabilityId] = new SbomExportDetail(
                string.Join("; ", (weaknessRows ?? [])
                    .Select(row => row.GetValueOrDefault("weakness_id")?.ToString())
                    .Where(value => !string.IsNullOrWhiteSpace(value))
                    .Distinct(StringComparer.OrdinalIgnoreCase)),
                string.Join("; ", (referenceRows ?? [])
                    .Select(row => row.GetValueOrDefault("url")?.ToString())
                    .Where(value => !string.IsNullOrWhiteSpace(value))
                    .Distinct(StringComparer.OrdinalIgnoreCase)));
        }

        return details;
    }

    private static void AppendCells(StringBuilder rows, params string?[] values)
    {
        rows.Append("<tr>");
        foreach (var value in values)
            rows.Append("<td>").Append(Html(value ?? "")).Append("</td>");
        rows.AppendLine("</tr>");
    }

    private static string? SnapshotVulnerabilityText(JsonElement? detail, string propertyName)
    {
        if (detail is not JsonElement element ||
            !element.TryGetProperty("vulnerability", out var vulnerability) ||
            !vulnerability.TryGetProperty(propertyName, out var value) ||
            value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return null;
        }

        return value.ValueKind == JsonValueKind.String ? value.GetString() : value.ToString();
    }

    private static decimal? SnapshotVulnerabilityDecimal(JsonElement? detail, string propertyName)
    {
        if (detail is not JsonElement element ||
            !element.TryGetProperty("vulnerability", out var vulnerability) ||
            !vulnerability.TryGetProperty(propertyName, out var value) ||
            value.ValueKind != JsonValueKind.Number)
        {
            return null;
        }

        return value.TryGetDecimal(out var parsed) ? parsed : null;
    }

    private static string SnapshotWeaknesses(JsonElement? detail)
    {
        if (detail is not JsonElement element ||
            !element.TryGetProperty("weaknesses", out var weaknesses) ||
            weaknesses.ValueKind != JsonValueKind.Array)
        {
            return "";
        }

        return string.Join("; ", weaknesses
            .EnumerateArray()
            .Select(weakness =>
                JsonPropertyText(weakness, "weakness_id") ??
                JsonPropertyText(weakness, "weaknessId") ??
                JsonPropertyText(weakness, "description"))
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(30));
    }

    private static string SnapshotReferenceUrls(JsonElement? detail)
    {
        if (detail is not JsonElement element) return "";

        var urls = new List<string>();
        if (element.TryGetProperty("references", out var references) &&
            references.ValueKind == JsonValueKind.Array)
        {
            urls.AddRange(references
                .EnumerateArray()
                .Select(reference => JsonPropertyText(reference, "url"))
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(value => value!));
        }

        if (urls.Count == 0 &&
            element.TryGetProperty("sourceUrls", out var sourceUrls) &&
            sourceUrls.ValueKind == JsonValueKind.Object)
        {
            urls.AddRange(sourceUrls
                .EnumerateObject()
                .Select(property => property.Value.ValueKind == JsonValueKind.String ? property.Value.GetString() : null)
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(value => value!));
        }

        return string.Join("; ", urls
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .Take(20));
    }

    private static string? JsonPropertyText(JsonElement element, string propertyName)
    {
        return element.TryGetProperty(propertyName, out var value) &&
               value.ValueKind != JsonValueKind.Null &&
               value.ValueKind != JsonValueKind.Undefined
            ? value.ValueKind == JsonValueKind.String ? value.GetString() : value.ToString()
            : null;
    }

    private static string? StripVersion(string purl) =>
        PurlIdentity.WithoutVersionAndQualifiers(purl);

    private static SbomComponentDraft ToSbomComponent(JsonNode? c)
    {
        var purl = Text(c?["purl"]);
        var cpe = Text(c?["cpe"]) ?? ComponentProperty(c, "cpe") ?? ComponentProperty(c, "cpe23Uri") ?? ComponentProperty(c, "cpe23");
        var cpeParts = ParseCpe(cpe);
        var purlParts = ParsePurl(purl);
        var name = Text(c?["name"]) ?? cpeParts?.Product;
        var group = Text(c?["group"]) ?? purlParts?.Namespace;
        var vendor = Text(c?["supplier"]?["name"]) ?? Text(c?["publisher"]) ?? group ?? cpeParts?.Vendor;
        var product = name ?? purlParts?.Name ?? cpeParts?.Product;
        var ecosystem = PurlToEcosystem(purl) ?? (cpe is null ? null : "cpe");
        var sourcePackageName = ComponentProperty(c, "aquasecurity:trivy:SrcName");
        var sourceVersion = ComponentProperty(c, "aquasecurity:trivy:SrcVersion");
        var sourceEpoch = ComponentProperty(c, "aquasecurity:trivy:SrcEpoch");
        var sourceRelease = ComponentProperty(c, "aquasecurity:trivy:SrcRelease");
        return new SbomComponentDraft(
            purl,
            name,
            Text(c?["version"]) ?? cpeParts?.Version,
            ecosystem,
            group,
            vendor,
            product,
            cpe,
            sourcePackageName,
            JoinPackageVersion(sourceEpoch, sourceVersion, sourceRelease),
            Text(c?["type"]),
            c?.ToJsonString() ?? "{}");
    }

    private static bool? ResolveSbomVersionMatch(string? version, string? range, string? ecosystem, string? componentCpe, string? matchedCpe, string? basis)
    {
        if (!string.IsNullOrWhiteSpace(range) && range.StartsWith("cpe:", StringComparison.OrdinalIgnoreCase))
            matchedCpe = range;
        else if (!string.IsNullOrWhiteSpace(range) && !string.IsNullOrWhiteSpace(version))
            return VersionRangeMatcher.Matches(version, range, ecosystem);

        if (string.IsNullOrWhiteSpace(componentCpe) || string.IsNullOrWhiteSpace(matchedCpe))
            return null;

        var component = ParseCpe(componentCpe);
        var matched = ParseCpe(matchedCpe);
        if (component is null || matched is null) return null;
        if (!string.Equals(component.Vendor, matched.Vendor, StringComparison.OrdinalIgnoreCase)) return false;
        if (!string.Equals(component.Product, matched.Product, StringComparison.OrdinalIgnoreCase)) return false;
        if (string.Equals(basis, "cpe-exact", StringComparison.OrdinalIgnoreCase)) return true;
        if (matched.Version is "*" or "-" or null) return true;
        return string.Equals(component.Version, matched.Version, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsPossibleSbomMatch(string? version, string? range, string? basis)
    {
        if (string.IsNullOrWhiteSpace(version) || string.IsNullOrWhiteSpace(range)) return false;
        var commitRange = System.Text.RegularExpressions.Regex.Matches(range, @"(?:<=|>=|==|=|<|>)\s*([^\s,]+)")
            .Select(match => match.Groups[1].Value)
            .Any(EcosystemVersionComparer.IsCommitLikeVersion);
        if (!EcosystemVersionComparer.IsCommitLikeVersion(version) && !commitRange) return false;
        return basis is not null && (
            basis.Equals("purl", StringComparison.OrdinalIgnoreCase) ||
            basis.Equals("source-package", StringComparison.OrdinalIgnoreCase) ||
            basis.Equals("cpe-exact", StringComparison.OrdinalIgnoreCase));
    }

    private static string? CpeProductPrefix(string? cpe)
    {
        var parsed = ParseCpe(cpe);
        if (parsed is null) return null;
        return $"cpe:2.3:{parsed.Part}:{EscapeCpePart(parsed.Vendor)}:{EscapeCpePart(parsed.Product)}:";
    }

    private static CpeParts? ParseCpe(string? cpe)
    {
        if (string.IsNullOrWhiteSpace(cpe)) return null;
        var parts = cpe.Split(':');
        if (parts.Length < 6 || !string.Equals(parts[0], "cpe", StringComparison.OrdinalIgnoreCase)) return null;
        var offset = parts.Length > 2 && parts[1] == "2.3" ? 2 : 1;
        if (parts.Length <= offset + 3) return null;
        return new CpeParts(UnescapeCpePart(parts[offset]), UnescapeCpePart(parts[offset + 1]), UnescapeCpePart(parts[offset + 2]), UnescapeCpePart(parts[offset + 3]));
    }

    private static PurlParts? ParsePurl(string? purl)
    {
        if (string.IsNullOrWhiteSpace(purl) || !purl.StartsWith("pkg:", StringComparison.OrdinalIgnoreCase)) return null;
        var withoutVersion = StripVersion(purl);
        var withoutQualifiers = (withoutVersion ?? purl).Split('?', 2)[0];
        var slash = withoutQualifiers.IndexOf('/');
        if (slash <= "pkg:".Length) return null;
        var type = withoutQualifiers["pkg:".Length..slash];
        var identity = withoutQualifiers[(slash + 1)..];
        var lastSlash = identity.LastIndexOf('/');
        var ns = lastSlash > 0 ? identity[..lastSlash] : null;
        var name = lastSlash > 0 ? identity[(lastSlash + 1)..] : identity;
        return new PurlParts(type, Uri.UnescapeDataString(ns ?? ""), Uri.UnescapeDataString(name));
    }

    private static string? ComponentProperty(JsonNode? c, string name)
    {
        foreach (var property in c?["properties"]?.AsArray() ?? [])
        {
            if (string.Equals(Text(property?["name"]), name, StringComparison.OrdinalIgnoreCase))
                return Text(property?["value"]);
        }
        return null;
    }

    private static string? Text(JsonNode? node) => node?.GetValue<string>();

    private static string? JoinPackageVersion(string? epoch, string? version, string? release)
    {
        if (string.IsNullOrWhiteSpace(version)) return null;
        var value = string.IsNullOrWhiteSpace(epoch) || epoch == "0" ? version : $"{epoch}:{version}";
        return string.IsNullOrWhiteSpace(release) ? value : $"{value}-{release}";
    }

    private static string FirstText(params string?[] values) =>
        values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x))?.Trim() ?? "";

    private static string? SbomNameFromSerial(string? serialNumber)
    {
        if (string.IsNullOrWhiteSpace(serialNumber)) return null;
        return serialNumber.StartsWith("urn:uuid:", StringComparison.OrdinalIgnoreCase)
            ? serialNumber["urn:uuid:".Length..]
            : serialNumber;
    }

    private static string Html(string value) => WebUtility.HtmlEncode(value);

    private static string UnescapeCpePart(string value) => value.Replace("\\:", ":").Replace("\\\\", "\\");

    private static string EscapeCpePart(string value) => value.Replace("\\", "\\\\").Replace(":", "\\:");

    private sealed record SbomExportRow(
        string ComponentName,
        string ComponentPurl,
        string Cpe23Uri,
        string Vendor,
        string Product,
        string ComponentVersion,
        Guid? VulnerabilityId,
        string Cve,
        string AffectedRange,
        bool? VersionMatched,
        string Severity,
        decimal? Cvss,
        string Title);

    private sealed record SbomExportDetail(string Cwes = "", string Urls = "")
    {
        public static readonly SbomExportDetail Empty = new();
    }

    private sealed record SbomComponentDraft(
        string? Purl,
        string? Name,
        string? Version,
        string? Ecosystem,
        string? GroupName,
        string? Vendor,
        string? Product,
        string? Cpe23Uri,
        string? SourcePackageName,
        string? SourcePackageVersion,
        string? ComponentType,
        string MetadataJson);

    private sealed record CpeParts(string Part, string Vendor, string Product, string? Version);

    private sealed record PurlParts(string Type, string? Namespace, string Name);

    private sealed record SbomCandidateMatch(
        Guid ComponentId,
        string? Purl,
        string? ComponentVersion,
        string? ComponentCpe,
        string? SourcePackageVersion,
        Guid VulnerabilityId,
        string? DisplayName,
        string? Ecosystem,
        string? Range,
        string? MatchedCpe,
        string? Basis);

    private static string? MapEcosystem(string? eco) => eco?.ToLowerInvariant() switch
    {
        "deb" => "debian",
        "apk" => "alpine",
        "rpm" => "rpm",
        null => null,
        var x => x
    };

    private static string? PurlToEcosystem(string? purl)
        => PurlIdentity.EcosystemFromPurl(purl);
}
