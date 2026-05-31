using System.Net;
using System.Text;
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
        app.MapGet("/api/v1/sbom.export", Export);
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
                "INSERT INTO sbom_uploads(id,name,format,metadata,component_count) VALUES($1,$2,'cyclonedx',$3,$4)");
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
                    vals.Add($"(${p++},${p++},${p++},${p++},${p++},${p++},${p++},${p++},${p++},${p++},${p++})");
                    pl.Add(sid); pl.Add((object?)item.Purl ?? DBNull.Value); pl.Add((object?)item.Name ?? DBNull.Value);
                    pl.Add((object?)item.Version ?? DBNull.Value); pl.Add((object?)item.Ecosystem ?? DBNull.Value);
                    pl.Add((object?)item.GroupName ?? DBNull.Value); pl.Add((object?)item.Vendor ?? DBNull.Value);
                    pl.Add((object?)item.Product ?? DBNull.Value); pl.Add((object?)item.Cpe23Uri ?? DBNull.Value);
                    pl.Add((object?)item.ComponentType ?? DBNull.Value); pl.Add(item.MetadataJson);
                }
                await using var ic = db.CreateCommand(
                    $"INSERT INTO sbom_components(sbom_id,purl,name,version,ecosystem,group_name,vendor,product,cpe23_uri,component_type,metadata) VALUES {string.Join(",", vals)}");
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

    private static async Task<IResult> Get(NpgsqlDataSource db, Guid id, CancellationToken ct)
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
            "SELECT id,purl,name,version,ecosystem,component_type,vuln_count,vendor,product,cpe23_uri FROM sbom_components WHERE sbom_id=$1 ORDER BY ecosystem,name"))
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
                cpe23Uri = r.IsDBNull(9) ? null : r.GetString(9)
            });
        }

        var vulns = new List<object>();
        await using (var vc = db.CreateCommand(
            "SELECT sv.id,sv.sbom_component_id,sv.vulnerability_id,v.primary_identifier,v.title,v.severity_label,v.max_cvss_score,sv.display_name,sv.ecosystem,sv.normalized_range,sv.version_matched FROM sbom_vulnerabilities sv JOIN vulnerabilities v ON v.id=sv.vulnerability_id JOIN sbom_components c ON c.id=sv.sbom_component_id WHERE c.sbom_id=$1 ORDER BY coalesce(v.max_cvss_score,0) DESC LIMIT 2000"))
        {
            vc.Parameters.AddWithValue(id); await using var r = await vc.ExecuteReaderAsync(ct);
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
                versionMatched = r.IsDBNull(10) ? (bool?)null : r.GetBoolean(10)
            });
        }

        return ApiResult.Ok(new { sbom, components = comps, vulnerabilities = vulns });
    }

    private static async Task<IResult> Match(NpgsqlDataSource db, SbomMatchRequest req, CancellationToken ct)
    {
        var m = 0;
        await using var conn = await db.OpenConnectionAsync(ct);
        await using var transaction = await conn.BeginTransactionAsync(ct);
        var comps = new List<(Guid Id, string? Purl, string? Name, string? Version, string? Eco, string? Vendor, string? Product, string? Cpe23Uri)>();
        await using (var s = new NpgsqlCommand(
            "SELECT id,purl,name,version,ecosystem,vendor,product,cpe23_uri FROM sbom_components WHERE sbom_id=$1", conn))
        {
            s.Parameters.AddWithValue(req.SbomId); await using var r = await s.ExecuteReaderAsync(ct);
            while (await r.ReadAsync(ct))
                comps.Add((r.GetGuid(0), r.IsDBNull(1) ? null : r.GetString(1), r.IsDBNull(2) ? null : r.GetString(2),
                    r.IsDBNull(3) ? null : r.GetString(3), r.IsDBNull(4) ? null : r.GetString(4),
                    r.IsDBNull(5) ? null : r.GetString(5), r.IsDBNull(6) ? null : r.GetString(6),
                    r.IsDBNull(7) ? null : r.GetString(7)));
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

        foreach (var (cid, purl, name, ver, eco, vendor, product, cpe23Uri) in comps)
        {
            var purlDec = string.IsNullOrWhiteSpace(purl) ? null : Uri.UnescapeDataString(purl);
            var pwv = purlDec is null ? null : StripVersion(purlDec) ?? purlDec;
            var meco = MapEcosystem(eco);
            var cpePrefix = CpeProductPrefix(cpe23Uri);
            var cpeProduct = ParseCpe(cpe23Uri)?.Product ?? product;

            await using var sq = new NpgsqlCommand(@"
                with candidates as (
                  select c.vulnerability_id, c.display_name, c.ecosystem, c.normalized_range, c.primary_cpe23_uri, 1 as match_priority, 'cpe-exact' as match_basis
                  from vulnerability_affected_components c
                  where $5::text is not null and c.primary_cpe23_uri = $5
                  union all
                  select c.vulnerability_id, c.display_name, c.ecosystem, c.normalized_range, c.primary_cpe23_uri, 2 as match_priority, 'purl' as match_basis
                  from vulnerability_affected_components c
                  where $1::text is not null and (c.primary_purl = $2 or c.primary_purl like $1 || '%')
                    and ($4::text is null or lower(coalesce(c.ecosystem,'')) like lower($4) || '%')
                  union all
                  select c.vulnerability_id, c.display_name, c.ecosystem, c.normalized_range, c.primary_cpe23_uri, 3 as match_priority, 'name' as match_basis
                  from vulnerability_affected_components c
                  where $3::text is not null and lower(c.display_name)=lower($3) and ($4::text is null or lower(coalesce(c.ecosystem,'')) like lower($4) || '%')
                  union all
                  select c.vulnerability_id, c.display_name, c.ecosystem, c.normalized_range, c.primary_cpe23_uri, 4 as match_priority, 'package' as match_basis
                  from vulnerability_affected_components c
                  where $3::text is not null and lower(c.package_name)=lower($3) and ($4::text is null or lower(coalesce(c.ecosystem,'')) like lower($4) || '%')
                  union all
                  select c.vulnerability_id, c.display_name, c.ecosystem, c.normalized_range, c.primary_cpe23_uri, 5 as match_priority, 'cpe-product' as match_basis
                  from vulnerability_affected_components c
                  where $6::text is not null and c.primary_cpe23_uri like $6 || '%'
                  union all
                  select c.vulnerability_id, c.display_name, c.ecosystem, c.normalized_range, c.primary_cpe23_uri, 6 as match_priority, 'cpe-product' as match_basis
                  from vulnerability_affected_components c
                  where $7::text is not null and lower(c.package_name)=lower($7) and lower(coalesce(c.ecosystem,''))='cpe'
                )
                SELECT DISTINCT ON (v.id) v.id,v.primary_identifier,v.title,v.severity_label,v.max_cvss_score,
                       c.display_name,c.ecosystem,c.normalized_range,c.primary_cpe23_uri,c.match_basis
                FROM candidates c
                JOIN vulnerabilities v ON v.id=c.vulnerability_id
                ORDER BY v.id, c.match_priority,
                  CASE WHEN c.normalized_range IS NOT NULL AND c.normalized_range <> '' AND c.normalized_range ~ '^[<>]=?' THEN 0 ELSE 1 END,
                  coalesce(v.max_cvss_score,0) DESC
                LIMIT 200", conn);
            sq.Parameters.AddWithValue((object?)pwv ?? DBNull.Value);
            sq.Parameters.AddWithValue((object?)purlDec ?? DBNull.Value);
            sq.Parameters.AddWithValue((object?)name ?? DBNull.Value);
            sq.Parameters.AddWithValue((object?)meco ?? DBNull.Value);
            sq.Parameters.AddWithValue((object?)cpe23Uri ?? DBNull.Value);
            sq.Parameters.AddWithValue((object?)cpePrefix ?? DBNull.Value);
            sq.Parameters.AddWithValue((object?)cpeProduct ?? DBNull.Value);

            var matches = new List<(Guid VulnId, string? PrimaryId, string? Title, string? SeveLabel, decimal? Cvss,
                string? DisplayName, string? Eco, string? Range, string? MatchedCpe, string? Basis)>();
            await using (var sr = await sq.ExecuteReaderAsync(ct))
                while (await sr.ReadAsync(ct))
                    matches.Add((sr.GetGuid(0), sr.IsDBNull(1) ? null : sr.GetString(1),
                        sr.IsDBNull(2) ? null : sr.GetString(2), sr.IsDBNull(3) ? null : sr.GetString(3),
                        sr.IsDBNull(4) ? (decimal?)null : sr.GetDecimal(4), sr.IsDBNull(5) ? null : sr.GetString(5),
                        sr.IsDBNull(6) ? null : sr.GetString(6), sr.IsDBNull(7) ? null : sr.GetString(7),
                        sr.IsDBNull(8) ? null : sr.GetString(8), sr.IsDBNull(9) ? null : sr.GetString(9)));

            foreach (var (vid, _, _, _, _, dname, ecosys, range, matchedCpe, basis) in matches)
            {
                var vm = ResolveSbomVersionMatch(ver, range, cpe23Uri, matchedCpe, basis);

                if (vm != true) continue;

                await using var ins = new NpgsqlCommand(@"
                    INSERT INTO sbom_vulnerabilities(sbom_component_id,vulnerability_id,purl,display_name,ecosystem,normalized_range,version_matched)
                    VALUES($1,$2,$3,$4,$5,$6,$7)
                    ON CONFLICT(sbom_component_id,vulnerability_id)
                    DO UPDATE SET version_matched = coalesce(excluded.version_matched, sbom_vulnerabilities.version_matched),
                                  normalized_range = coalesce(excluded.normalized_range, sbom_vulnerabilities.normalized_range),
                                  display_name = coalesce(excluded.display_name, sbom_vulnerabilities.display_name),
                                  ecosystem = coalesce(excluded.ecosystem, sbom_vulnerabilities.ecosystem)", conn);
                ins.Parameters.AddWithValue(cid); ins.Parameters.AddWithValue(vid); ins.Parameters.AddWithValue((object?)purl ?? DBNull.Value);
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

    private static async Task<IResult> Export(NpgsqlDataSource db, Guid id, CancellationToken ct)
    {
        var rows = new StringBuilder();
        rows.AppendLine("""
            <html><head><meta charset="utf-8"></head><body>
            <table border="1">
            <thead><tr>
              <th>Component Name</th><th>Component PURL</th><th>CPE 2.3 URI</th><th>Vendor</th><th>Product</th><th>Component Version</th>
              <th>CVE</th><th>Affected Version / Range</th><th>Version Matched</th><th>Severity</th><th>CVSS</th><th>CWE</th><th>URLs</th><th>Title</th>
            </tr></thead><tbody>
            """);

        await using var cmd = db.CreateCommand("""
            select sc.name, sc.purl, sc.cpe23_uri, sc.vendor, sc.product, sc.version,
                   v.primary_identifier, sv.normalized_range, sv.version_matched,
                   v.severity_label, v.max_cvss_score, v.title,
                   coalesce(w.cwes, '') as cwes,
                   coalesce(refs.urls, '') as urls
            from sbom_components sc
            left join sbom_vulnerabilities sv on sv.sbom_component_id = sc.id
            left join vulnerabilities v on v.id = sv.vulnerability_id
            left join lateral (
              select string_agg(distinct nullif(weakness_id,''), '; ') as cwes
              from vulnerability_weaknesses
              where vulnerability_id = v.id
            ) w on true
            left join lateral (
              select string_agg(url, '; ') as urls
              from (
                select distinct url
                from vulnerability_references
                where vulnerability_id = v.id and url is not null
                order by url
                limit 20
              ) r
            ) refs on true
            where sc.sbom_id = $1
            order by lower(coalesce(sc.name, sc.product, sc.purl, sc.cpe23_uri, '')), coalesce(v.max_cvss_score, 0) desc nulls last, v.primary_identifier
            """);
        cmd.Parameters.AddWithValue(id);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            rows.Append("<tr>");
            for (var i = 0; i < reader.FieldCount; i++)
                rows.Append("<td>").Append(Html(reader.IsDBNull(i) ? "" : reader.GetValue(i)?.ToString() ?? "")).Append("</td>");
            rows.AppendLine("</tr>");
        }
        rows.AppendLine("</tbody></table></body></html>");

        return Results.File(
            Encoding.UTF8.GetBytes(rows.ToString()),
            "application/vnd.ms-excel; charset=utf-8",
            $"vultrack-sbom-{id:N}.xls");
    }

    private static string? StripVersion(string purl) =>
        purl.Contains('@') && purl.LastIndexOf('@') > "pkg:".Length
            ? purl[..purl.LastIndexOf('@')] : purl;

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
        return new SbomComponentDraft(
            purl,
            name,
            Text(c?["version"]) ?? cpeParts?.Version,
            ecosystem,
            group,
            vendor,
            product,
            cpe,
            Text(c?["type"]),
            c?.ToJsonString() ?? "{}");
    }

    private static bool? ResolveSbomVersionMatch(string? version, string? range, string? componentCpe, string? matchedCpe, string? basis)
    {
        if (!string.IsNullOrWhiteSpace(range) && range.StartsWith("cpe:", StringComparison.OrdinalIgnoreCase))
            matchedCpe = range;
        else if (!string.IsNullOrWhiteSpace(range) && !string.IsNullOrWhiteSpace(version))
            return VersionRangeMatcher.Matches(version, range);

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

    private static string FirstText(params string?[] values) =>
        values.First(x => !string.IsNullOrWhiteSpace(x))!.Trim();

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

    private sealed record SbomComponentDraft(
        string? Purl,
        string? Name,
        string? Version,
        string? Ecosystem,
        string? GroupName,
        string? Vendor,
        string? Product,
        string? Cpe23Uri,
        string? ComponentType,
        string MetadataJson);

    private sealed record CpeParts(string Part, string Vendor, string Product, string? Version);

    private sealed record PurlParts(string Type, string? Namespace, string Name);

    private static string? MapEcosystem(string? eco) => eco?.ToLowerInvariant() switch
    {
        "deb" => "debian",
        "apk" => "alpine",
        "rpm" => "rpm",
        null => null,
        var x => x
    };

    private static string? PurlToEcosystem(string? purl)
    {
        if (purl is null || !purl.StartsWith("pkg:")) return null;
        var slash = purl.IndexOf('/');
        if (slash < 0) return null;
        return purl["pkg:".Length..slash].ToLowerInvariant() switch
        {
            "deb" => DistroEcosystem("debian", PurlQualifier(purl, "distro")),
            "apk" => DistroEcosystem("alpine", PurlQualifier(purl, "distro")),
            "golang" => "go",
            "rpm" => "rpm",
            var x => x
        };
    }

    private static string? PurlQualifier(string purl, string key)
    {
        var query = purl.Split('?', 2).ElementAtOrDefault(1);
        if (string.IsNullOrWhiteSpace(query)) return null;
        foreach (var pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = pair.Split('=', 2);
            if (parts.Length == 2 && string.Equals(parts[0], key, StringComparison.OrdinalIgnoreCase))
                return Uri.UnescapeDataString(parts[1]);
        }
        return null;
    }

    private static string DistroEcosystem(string ecosystem, string? distro)
    {
        if (string.IsNullOrWhiteSpace(distro)) return ecosystem;
        var match = System.Text.RegularExpressions.Regex.Match(distro, @"(?:^|[-_])(\d+)(?:[._-]|$)");
        return match.Success ? $"{ecosystem}:{match.Groups[1].Value}" : ecosystem;
    }
}
