using System.Text.Json.Nodes;
using Npgsql;

namespace VulTrack.App;

public static class SbomEndpoints
{
    public static void Map(WebApplication app)
    {
        app.MapPost("/api/v1/sbom.upload", Upload).DisableAntiforgery();
        app.MapGet("/api/v1/sbom.list", List);
        app.MapGet("/api/v1/sbom.get", Get);
        app.MapPost("/api/v1/sbom.match", Match);
        app.MapPost("/api/v1/sbom.delete", Delete);
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
            var name = $"{meta?["component"]?["name"]?.GetValue<string>() ?? "unknown"} {meta?["component"]?["version"]?.GetValue<string>() ?? ""}".Trim();
            var sid = Guid.NewGuid();

            var comps = (doc["components"]?.AsArray() ?? [])
                .Select(c => (Purl: c?["purl"]?.GetValue<string>(),
                              Name: c?["name"]?.GetValue<string>(),
                              Version: c?["version"]?.GetValue<string>()))
                .Where(x => !string.IsNullOrWhiteSpace(x.Purl))
                .Select(x => (x.Purl!, x.Name, x.Version, Eco: PurlToEcosystem(x.Purl!)))
                .ToList();

            await using var cmd = db.CreateCommand(
                "INSERT INTO sbom_uploads(id,name,format,metadata,component_count) VALUES($1,$2,'cyclonedx',$3,$4)");
            cmd.Parameters.AddWithValue(sid);
            cmd.Parameters.AddWithValue(name);
            cmd.Parameters.AddWithValue(json);
            cmd.Parameters.AddWithValue(comps.Count);
            await cmd.ExecuteNonQueryAsync(ct);

            if (comps.Count > 0)
            {
                var deduped = comps
                    .GroupBy(x => (x.Item1, x.Name ?? "", x.Version ?? "", x.Eco ?? ""))
                    .Select(g => g.First())
                    .ToList();

                var p = 1;
                var vals = new List<string>();
                var pl = new List<object>();
                foreach (var item in deduped)
                {
                    vals.Add($"(${p++},${p++},${p++},${p++},${p++},${p++},${p++})");
                    pl.Add(sid); pl.Add(item.Item1); pl.Add((object?)item.Name ?? DBNull.Value);
                    pl.Add((object?)item.Version ?? DBNull.Value); pl.Add((object?)item.Eco ?? DBNull.Value);
                    pl.Add((object?)null ?? DBNull.Value); pl.Add("{}");
                }
                await using var ic = db.CreateCommand(
                    $"INSERT INTO sbom_components(sbom_id,purl,name,version,ecosystem,component_type,metadata) VALUES {string.Join(",", vals)}");
                foreach (var v in pl) ic.Parameters.AddWithValue(v);
                await ic.ExecuteNonQueryAsync(ct);

                await using var uc = db.CreateCommand("UPDATE sbom_uploads SET component_count=$1 WHERE id=$2");
                uc.Parameters.AddWithValue(deduped.Count);
                uc.Parameters.AddWithValue(sid);
                await uc.ExecuteNonQueryAsync(ct);
            }

            return ApiResult.Ok(new { id = sid, name, componentCount = comps.Count });
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
            items.Add(new { id = r.GetGuid(0), name = r.GetString(1), format = r.GetString(2),
                componentCount = r.GetInt32(3), matchedCount = r.GetInt32(4),
                uploadedAt = r.GetFieldValue<DateTimeOffset>(5) });
        return ApiResult.Ok(new { items });
    }

    private static async Task<IResult> Get(NpgsqlDataSource db, Guid id, CancellationToken ct)
    {
        object? sbom = null;
        await using (var c = db.CreateCommand(
            "SELECT id,name,format,component_count,matched_count,uploaded_at FROM sbom_uploads WHERE id=$1"))
        { c.Parameters.AddWithValue(id); await using var r = await c.ExecuteReaderAsync(ct);
          if (await r.ReadAsync(ct)) sbom = new { id = r.GetGuid(0), name = r.GetString(1), format = r.GetString(2),
              componentCount = r.GetInt32(3), matchedCount = r.GetInt32(4), uploadedAt = r.GetFieldValue<DateTimeOffset>(5) }; }
        if (sbom is null) return ApiResult.NotFound("NOT_FOUND", id.ToString());

        var comps = new List<object>();
        await using (var cc = db.CreateCommand(
            "SELECT id,purl,name,version,ecosystem,component_type,vuln_count FROM sbom_components WHERE sbom_id=$1 ORDER BY ecosystem,name"))
        { cc.Parameters.AddWithValue(id); await using var r = await cc.ExecuteReaderAsync(ct);
          while (await r.ReadAsync(ct)) comps.Add(new { id = r.GetGuid(0), purl = r.GetString(1),
              name = r.IsDBNull(2) ? null : r.GetString(2), version = r.IsDBNull(3) ? null : r.GetString(3),
              ecosystem = r.IsDBNull(4) ? null : r.GetString(4), type = r.IsDBNull(5) ? null : r.GetString(5),
              vulnCount = r.GetInt32(6) }); }

        var vulns = new List<object>();
        await using (var vc = db.CreateCommand(
            "SELECT sv.id,sv.sbom_component_id,sv.vulnerability_id,v.primary_identifier,v.title,v.severity_label,v.max_cvss_score,sv.display_name,sv.ecosystem,sv.normalized_range,sv.version_matched FROM sbom_vulnerabilities sv JOIN vulnerabilities v ON v.id=sv.vulnerability_id JOIN sbom_components c ON c.id=sv.sbom_component_id WHERE c.sbom_id=$1 ORDER BY coalesce(v.max_cvss_score,0) DESC LIMIT 2000"))
        { vc.Parameters.AddWithValue(id); await using var r = await vc.ExecuteReaderAsync(ct);
          while (await r.ReadAsync(ct)) vulns.Add(new { id = r.GetGuid(0), componentId = r.GetGuid(1),
              vulnerabilityId = r.GetGuid(2), primaryIdentifier = r.GetString(3),
              title = r.IsDBNull(4) ? null : r.GetString(4), severityLabel = r.IsDBNull(5) ? null : r.GetString(5),
              cvssScore = r.IsDBNull(6) ? (decimal?)null : r.GetDecimal(6),
              componentName = r.IsDBNull(7) ? null : r.GetString(7),
              ecosystem = r.IsDBNull(8) ? null : r.GetString(8),
              versionRange = r.IsDBNull(9) ? null : r.GetString(9),
              versionMatched = r.IsDBNull(10) ? (bool?)null : r.GetBoolean(10) }); }

        return ApiResult.Ok(new { sbom, components = comps, vulnerabilities = vulns });
    }

    private static async Task<IResult> Match(NpgsqlDataSource db, SbomMatchRequest req, CancellationToken ct)
    {
        var m = 0;
        await using var conn = await db.OpenConnectionAsync(ct);
        var comps = new List<(Guid Id, string Purl, string? Name, string? Version, string? Eco)>();
        await using (var s = new NpgsqlCommand(
            "SELECT id,purl,name,version,ecosystem FROM sbom_components WHERE sbom_id=$1", conn))
        { s.Parameters.AddWithValue(req.SbomId); await using var r = await s.ExecuteReaderAsync(ct);
          while (await r.ReadAsync(ct))
              comps.Add((r.GetGuid(0), r.GetString(1), r.IsDBNull(2) ? null : r.GetString(2),
                  r.IsDBNull(3) ? null : r.GetString(3), r.IsDBNull(4) ? null : r.GetString(4))); }

        foreach (var (cid, purl, name, ver, eco) in comps)
        {
            var purlDec = Uri.UnescapeDataString(purl);
            var pwv = StripVersion(purlDec) ?? purlDec;
            var meco = MapEcosystem(eco);

            await using var sq = new NpgsqlCommand(@"
                SELECT DISTINCT ON (v.id) v.id,v.primary_identifier,v.title,v.severity_label,v.max_cvss_score,
                       c.display_name,c.ecosystem,c.normalized_range
                FROM vulnerability_affected_components c
                JOIN vulnerabilities v ON v.id=c.vulnerability_id
                WHERE c.primary_purl LIKE $1||'%' OR c.primary_purl=$2
                   OR (lower(c.display_name)=lower($3) AND ($4::text IS NULL OR lower(coalesce(c.ecosystem,'')) LIKE lower($4) || '%'))
                   OR (lower(c.package_name)=lower($3) AND ($4::text IS NULL OR lower(coalesce(c.ecosystem,'')) LIKE lower($4) || '%'))
                ORDER BY v.id,
                  CASE WHEN c.normalized_range IS NOT NULL AND c.normalized_range <> '' AND c.normalized_range ~ '^[<>]=?' THEN 0 ELSE 1 END,
                  coalesce(v.max_cvss_score,0) DESC
                LIMIT 200", conn);
            sq.Parameters.AddWithValue(pwv);
            sq.Parameters.AddWithValue(purlDec);
            sq.Parameters.AddWithValue((object?)name ?? DBNull.Value);
            sq.Parameters.AddWithValue((object?)meco ?? DBNull.Value);

            var matches = new List<(Guid VulnId, string? PrimaryId, string? Title, string? SeveLabel, decimal? Cvss,
                string? DisplayName, string? Eco, string? Range)>();
            await using (var sr = await sq.ExecuteReaderAsync(ct))
                while (await sr.ReadAsync(ct))
                    matches.Add((sr.GetGuid(0), sr.IsDBNull(1) ? null : sr.GetString(1),
                        sr.IsDBNull(2) ? null : sr.GetString(2), sr.IsDBNull(3) ? null : sr.GetString(3),
                        sr.IsDBNull(4) ? (decimal?)null : sr.GetDecimal(4), sr.IsDBNull(5) ? null : sr.GetString(5),
                        sr.IsDBNull(6) ? null : sr.GetString(6), sr.IsDBNull(7) ? null : sr.GetString(7)));

            foreach (var (vid, _, _, _, _, dname, ecosys, range) in matches)
            {
                if (string.IsNullOrEmpty(range)) continue;
                var vm = ver is not null && range is not null && ver is not null
                    ? VersionRangeMatcher.Matches(ver, range) : (bool?)null;

                if (vm == false) continue;

                await using var ins = new NpgsqlCommand(@"
                    INSERT INTO sbom_vulnerabilities(sbom_component_id,vulnerability_id,purl,display_name,ecosystem,normalized_range,version_matched)
                    VALUES($1,$2,$3,$4,$5,$6,$7)
                    ON CONFLICT(sbom_component_id,vulnerability_id)
                    DO UPDATE SET version_matched = coalesce(excluded.version_matched, sbom_vulnerabilities.version_matched),
                                  normalized_range = coalesce(excluded.normalized_range, sbom_vulnerabilities.normalized_range),
                                  display_name = coalesce(excluded.display_name, sbom_vulnerabilities.display_name),
                                  ecosystem = coalesce(excluded.ecosystem, sbom_vulnerabilities.ecosystem)", conn);
                ins.Parameters.AddWithValue(cid); ins.Parameters.AddWithValue(vid); ins.Parameters.AddWithValue(purl);
                ins.Parameters.AddWithValue((object?)dname ?? DBNull.Value); ins.Parameters.AddWithValue((object?)ecosys ?? DBNull.Value);
                ins.Parameters.AddWithValue((object?)range ?? DBNull.Value); ins.Parameters.AddWithValue((object?)vm ?? DBNull.Value);
                await ins.ExecuteNonQueryAsync(ct);
                m++;
            }

            await using var uc = new NpgsqlCommand(
                "UPDATE sbom_components SET vuln_count=(SELECT count(*) FROM sbom_vulnerabilities WHERE sbom_component_id=$1) WHERE id=$1", conn);
            uc.Parameters.AddWithValue(cid);
            await uc.ExecuteNonQueryAsync(ct);
        }

        await using var us = new NpgsqlCommand(
            "UPDATE sbom_uploads SET matched_count=(SELECT count(DISTINCT sv.vulnerability_id) FROM sbom_vulnerabilities sv JOIN sbom_components sc ON sc.id=sv.sbom_component_id WHERE sc.sbom_id=$1) WHERE id=$1", conn);
        us.Parameters.AddWithValue(req.SbomId);
        await us.ExecuteNonQueryAsync(ct);

        return ApiResult.Ok(new { matched = m });
    }

    private static async Task<IResult> Delete(NpgsqlDataSource db, SbomDeleteRequest req, CancellationToken ct)
    {
        await using var c = db.CreateCommand("DELETE FROM sbom_uploads WHERE id=$1");
        c.Parameters.AddWithValue(req.SbomId);
        await c.ExecuteNonQueryAsync(ct);
        return ApiResult.Ok(new { deleted = true });
    }

    private static string? StripVersion(string purl) =>
        purl.Contains('@') && purl.LastIndexOf('@') > "pkg:".Length
            ? purl[..purl.LastIndexOf('@')] : purl;

    private static string? MapEcosystem(string? eco) => eco?.ToLowerInvariant() switch
    {
        "deb" => "debian", "apk" => "alpine", "rpm" => "rpm", null => null, var x => x
    };

    private static string? PurlToEcosystem(string? purl)
    {
        if (purl is null || !purl.StartsWith("pkg:")) return null;
        var slash = purl.IndexOf('/');
        if (slash < 0) return null;
        return purl["pkg:".Length..slash].ToLowerInvariant() switch
        {
            "deb" => "debian", "apk" => "alpine", "rpm" => "rpm", var x => x
        };
    }
}
