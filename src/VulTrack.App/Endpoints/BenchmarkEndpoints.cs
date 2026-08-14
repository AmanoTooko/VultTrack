namespace VulTrack.App;

public static class BenchmarkEndpoints
{
    public static WebApplication MapBenchmarkEndpoints(this WebApplication app)
    {
        app.MapGet("/api/v1/benchmark.ecosystemCveCount", async (DuckDbEvidenceStore duckDb, string? ecosystem, string? package, string? version, CancellationToken ct) =>
        {
            var duckRows = await duckDb.QueryAffectedEcosystemPackageSummaryAsync(ecosystem ?? "go", package, 50, ct);
            var duckItems = duckRows.Select(row =>
            {
                int? affectedIfVersion = null;
                int? notAffectedIfVersion = null;
                if (!string.IsNullOrWhiteSpace(version))
                    notAffectedIfVersion = null;
                return new
                {
                    ecosystem = row.Ecosystem,
                    package = row.PackageName,
                    totalCves = row.TotalCves,
                    affectedIfVersion,
                    notAffectedIfVersion,
                    factCount = row.FactCount
                };
            }).ToList<object>();
            return ApiResult.Ok(new { items = duckItems, source = "duckdb" });
        });

        app.MapGet("/api/v1/benchmark.packageCves", async (DuckDbEvidenceStore duckDb, string name, CancellationToken ct) =>
        {
            var summary = await duckDb.QueryAffectedPackageSummaryAsync(name, ct);
            return summary is null
                ? ApiResult.Ok(new { name, cves = 0, source = "duckdb" })
                : ApiResult.Ok(new { name, cves = summary.TotalCves, facts = summary.FactCount, ecosystems = summary.Ecosystem, source = "duckdb" });
        });

        app.MapGet("/api/v1/benchmark.matchingQuality", async (DuckDbEvidenceStore duckDb, string? ecosystem, string? packageName, Guid? sbomId, CancellationToken ct) =>
        {
            var affectedSummary = new List<object>();
            var useSbomScope = sbomId is not null && string.IsNullOrWhiteSpace(ecosystem) && string.IsNullOrWhiteSpace(packageName);
            if (useSbomScope)
            {
                var scopedFindings = await duckDb.GetSbomFindingsAsync(sbomId!.Value, 10000, 0, ct);
                foreach (var group in scopedFindings.GroupBy(item => item.Ecosystem ?? "unknown", StringComparer.OrdinalIgnoreCase))
                {
                    affectedSummary.Add(new
                    {
                        ecosystem = group.Key,
                        facts = group.LongCount(),
                        vulnerabilities = group.Select(item => item.VulnerabilityId).Distinct().LongCount(),
                        purlFacts = group.Count(item => string.Equals(item.MatchBasis, "purl", StringComparison.OrdinalIgnoreCase)),
                        cpeFacts = group.Count(item => string.Equals(item.MatchBasis, "cpe-exact", StringComparison.OrdinalIgnoreCase)),
                        noRange = group.Count(item => string.IsNullOrWhiteSpace(item.VersionRange)),
                        openLowerBound = 0,
                        unparseableRange = group.Count(item => item.VersionMatched is null && !string.IsNullOrWhiteSpace(item.VersionRange)),
                        actionableRangeRatio = group.Any() ? Math.Round((double)group.Count(item => item.VersionMatched is not null) / group.Count(), 4) : 0,
                        source = "duckdb-sbom"
                    });
                }
                var scopedSummary = new
                {
                    sbomId,
                    findings = scopedFindings.Count,
                    affected = scopedFindings.Count(item => item.VersionMatched == true),
                    notAffected = scopedFindings.Count(item => item.VersionMatched == false),
                    unknown = scopedFindings.Count(item => item.VersionMatched is null),
                    noRange = scopedFindings.Count(item => string.IsNullOrWhiteSpace(item.VersionRange)),
                    componentsWithFindings = scopedFindings.Select(item => item.ComponentId).Distinct().Count()
                };
                return ApiResult.Ok(new
                {
                    filters = new { ecosystem, packageName, sbomId },
                    affectedSummary,
                    sbomSummary = scopedSummary,
                    source = "duckdb"
                });
            }

            var summaries = await duckDb.QueryAffectedMatchingQualitySummaryAsync(ecosystem, packageName, 50, ct);
            foreach (var row in summaries)
            {
                var actionable = row.Facts - row.NoRange - row.UnparseableRange;
                affectedSummary.Add(new
                {
                    ecosystem = row.Ecosystem,
                    facts = row.Facts,
                    vulnerabilities = row.Vulnerabilities,
                    purlFacts = row.PurlFacts,
                    cpeFacts = row.CpeFacts,
                    noRange = row.NoRange,
                    openLowerBound = row.OpenLowerBound,
                    unparseableRange = row.UnparseableRange,
                    actionableRangeRatio = row.Facts == 0 ? 0 : Math.Round((double)actionable / row.Facts, 4),
                    source = "duckdb"
                });
            }

            object? sbomSummary = null;
            if (sbomId is not null)
            {
                var findings = await duckDb.GetSbomFindingsAsync(sbomId.Value, 10000, 0, ct);
                sbomSummary = new
                {
                    sbomId,
                    findings = findings.Count,
                    affected = findings.Count(item => item.VersionMatched == true),
                    notAffected = findings.Count(item => item.VersionMatched == false),
                    unknown = findings.Count(item => item.VersionMatched is null),
                    noRange = findings.Count(item => string.IsNullOrWhiteSpace(item.VersionRange)),
                    componentsWithFindings = findings.Select(item => item.ComponentId).Distinct().Count()
                };
            }

            return ApiResult.Ok(new
            {
                filters = new { ecosystem, packageName, sbomId },
                affectedSummary,
                sbomSummary,
                standard = new
                {
                    affected = "exact purl or normalized package match plus a parseable normalized_range where VersionRangeMatcher returns true",
                    notAffected = "same component identity but VersionRangeMatcher returns false",
                    unknown = "component identity matches but version is absent, range is absent, or range cannot be parsed",
                    suspiciousBroadRange = "ranges like >0 are counted separately because they may mean source-level coarse package association"
                }
            });
        });

        return app;
    }
}
