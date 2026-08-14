using System.Net;
using System.Text;
using System.Text.Json.Nodes;

namespace VulTrack.App;

public static class SbomEndpoints
{
    public static void Map(WebApplication app)
    {
        app.MapPost("/api/v1/sbom.upload", UploadDuckDb).DisableAntiforgery();
        app.MapGet("/api/v1/sbom.list", ListDuckDb);
        app.MapGet("/api/v1/sbom.get", GetDuckDb);
        app.MapPost("/api/v1/sbom.match", MatchDuckDb);
        app.MapGet("/api/v1/sbom.export", ExportDuckDb);
        app.MapPost("/api/v1/sbom.delete", DeleteDuckDb);
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

    private static void AppendCells(StringBuilder rows, params string?[] values)
    {
        rows.Append("<tr>");
        foreach (var value in values)
            rows.Append("<td>").Append(Html(value ?? "")).Append("</td>");
        rows.AppendLine("</tr>");
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
