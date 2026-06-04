using System.Text.Json.Nodes;
using Npgsql;
using VulTrack.App;

var builder = WebApplication.CreateBuilder(args);

var databaseUrl = Environment.GetEnvironmentVariable("DATABASE_URL")
    ?? builder.Configuration.GetConnectionString("Default")
    ?? "Host=localhost;Port=5432;Database=vultrack;Username=vultrack;Password=vultrack";

builder.Services.AddSingleton(NpgsqlDataSource.Create(ToNpgsqlConnectionString(databaseUrl)));
builder.Services.Configure<VulTrackSchedulerOptions>(builder.Configuration.GetSection("VulTrack:Scheduler"));
builder.Services.AddSingleton<NvdRawProcessor>();
builder.Services.AddSingleton<IVulnerabilityCanonicalizer, VulnerabilityCanonicalizer>();
builder.Services.AddSingleton<IAffectedComponentHook, DefaultAffectedComponentHook>();
builder.Services.AddSingleton<IRawNormalizer, NvdRawNormalizer>();
builder.Services.AddSingleton<IRawNormalizer, OsvRawNormalizer>();
builder.Services.AddSingleton<IRawNormalizer, GhsaRawNormalizer>();
builder.Services.AddSingleton<IRawNormalizer, EcosystemAdvisoryNormalizer>();
builder.Services.AddSingleton<IRawNormalizer, PypiRawNormalizer>();
builder.Services.AddSingleton<IRawNormalizer, CveListRawNormalizer>();
builder.Services.AddSingleton<IRawNormalizer, ThreatIntelRawNormalizer>();
builder.Services.AddSingleton<IRawNormalizer, ExploitPocRawNormalizer>();
builder.Services.AddSingleton<IRawNormalizer, ExternalAdvisoryRawNormalizer>();
builder.Services.AddSingleton<IRawNormalizer, DistroRawNormalizer>();
builder.Services.AddSingleton<IRawNormalizer, ComponentCatalogNormalizer>();
var normalizerBackend = Environment.GetEnvironmentVariable("VULTRACK_NORMALIZER_BACKEND")
    ?? builder.Configuration["VulTrack:NormalizerBackend"]
    ?? "postgres";
if (string.Equals(normalizerBackend, "duckdb", StringComparison.OrdinalIgnoreCase))
    builder.Services.AddSingleton<IRawNormalizationService, DuckDbRawNormalizationService>();
else
    builder.Services.AddSingleton<IRawNormalizationService, RawNormalizationService>();
builder.Services.AddSingleton<ComponentVulnerabilitySearchService>();
builder.Services.AddSingleton<AdminAuthService>();
builder.Services.AddSingleton<SourceScheduler>();
builder.Services.AddMemoryCache();
builder.Services.AddSingleton<DuckDbEvidenceStore>();
builder.Services.AddSingleton<DuckDbEvidenceNormalizer>();
builder.Services.AddSingleton<VulnerabilityDetailService>();
builder.Services.AddSingleton<VulnerabilityDetailSnapshotStore>();
builder.Services.AddSingleton<VulnerabilityDetailSnapshotBuilder>();
builder.Services.AddHttpClient<AiVulnerabilitySummaryService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<SourceScheduler>());

var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/", () => Results.Redirect("/index.html"));

await EnsureRuntimeIndexesAsync(app.Services.GetRequiredService<NpgsqlDataSource>());
await BackfillCvssScoresAsync(app.Services.GetRequiredService<NpgsqlDataSource>());

app.MapGet("/api/v1/system.health", () => ApiResult.Ok(new
{
    status = "healthy",
    service = "vultrack-app",
    dotnet = Environment.Version.ToString()
}));

app.MapGet("/api/v1/system.ready", async (NpgsqlDataSource db, CancellationToken ct) =>
{
    await using var cmd = db.CreateCommand("select 1");
    await cmd.ExecuteScalarAsync(ct);
    return ApiResult.Ok(new { status = "ready" });
});

app.MapGet("/api/v1/auth.session", (HttpContext context, AdminAuthService auth) =>
    ApiResult.Ok(new { authenticated = auth.IsAuthenticated(context), username = auth.IsAuthenticated(context) ? auth.Username : null }));

app.MapPost("/api/v1/auth.login", (HttpContext context, AdminAuthService auth, AdminLoginRequest request) =>
{
    if (!auth.ValidateCredentials(request.Username, request.Password))
        return ApiResult.Unauthorized("Invalid username or password.");
    context.Response.Cookies.Append(AdminAuthService.CookieName, auth.CreateSession(), AdminAuthService.CookieOptions(context));
    return ApiResult.Ok(new { authenticated = true, username = auth.Username });
});

app.MapPost("/api/v1/auth.logout", (HttpContext context, AdminAuthService auth) =>
{
    auth.Revoke(context);
    context.Response.Cookies.Delete(AdminAuthService.CookieName, AdminAuthService.CookieOptions(context));
    return ApiResult.Ok(new { authenticated = false });
});

app.MapGet("/api/v1/source.list", async (NpgsqlDataSource db, CancellationToken ct) =>
{
    var rows = new List<object>();
    await using var cmd = db.CreateCommand("""
        select code, name, kind, enabled, plugin_name, schedule_cron
        from sources
        order by code
        """);
    await using var reader = await cmd.ExecuteReaderAsync(ct);
    while (await reader.ReadAsync(ct))
    {
        rows.Add(new
        {
            code = reader.GetString(0),
            name = reader.GetString(1),
            kind = reader.GetString(2),
            enabled = reader.GetBoolean(3),
            pluginName = reader.GetString(4),
            scheduleCron = reader.IsDBNull(5) ? null : reader.GetString(5)
        });
    }
    return ApiResult.Ok(rows);
});

var systemStatusCache = new StatusCache();
var systemStatusFastCache = new StatusCache();

app.MapGet("/api/v1/system.status", async (HttpContext context, AdminAuthService auth, NpgsqlDataSource db, bool? fast, CancellationToken ct) =>
{
    if (!auth.IsAuthenticated(context)) return ApiResult.Unauthorized();
    if (fast == true)
        return ApiResult.Ok(await GetFastSystemStatusAsync(db, systemStatusFastCache, ct));

    var now = DateTimeOffset.UtcNow;
    if (systemStatusCache.Value is not null && systemStatusCache.ExpiresAt > now)
        return ApiResult.Ok(systemStatusCache.Value);

    await systemStatusCache.RefreshLock.WaitAsync(ct);
    try
    {
        now = DateTimeOffset.UtcNow;
        if (systemStatusCache.Value is not null && systemStatusCache.ExpiresAt > now)
            return ApiResult.Ok(systemStatusCache.Value);

        var sourceStatus = new List<object>();
        var sourcePendingRows = new List<(string SourceCode, long Pending)>();
        var totalRaw = 0L;
        var parsePendingTotal = 0L;
        var parseSucceededTotal = 0L;
        var parseFailedTotal = 0L;
        var normalizePendingTotal = 0L;
        var normalizeSucceededTotal = 0L;
        var normalizeFailedTotal = 0L;
        await using (var cmd = db.CreateCommand("""
        with raw_counts as (
          select raw.source_id,
                 count(*) as raw_total,
                 count(*) filter (where src.enabled and coalesce(src.config_json->>'runMode', '') <> 'manual' and parse_status = 'pending') as parse_pending,
                 count(*) filter (where parse_status = 'succeeded') as parse_succeeded,
                 count(*) filter (where src.enabled and coalesce(src.config_json->>'runMode', '') <> 'manual' and parse_status = 'failed') as parse_failed,
                 count(*) filter (where src.enabled and coalesce(src.config_json->>'runMode', '') <> 'manual' and normalize_status = 'pending') as normalize_pending,
                 count(*) filter (where normalize_status = 'succeeded') as normalize_succeeded,
                 count(*) filter (where src.enabled and coalesce(src.config_json->>'runMode', '') <> 'manual' and normalize_status = 'failed') as normalize_failed,
                 max(raw.updated_at) as raw_updated_at
          from source_raw_index raw
          join sources src on src.id = raw.source_id
          group by raw.source_id
        ),
        latest_runs as (
          select distinct on (source_id)
                 source_id, status, trigger, started_at, finished_at,
                 fetched_count, changed_count, parsed_count, normalized_count,
                 error_count, log_summary
          from source_sync_runs
          order by source_id, started_at desc
        ),
        successful_runs as (
          select source_id, max(finished_at) as last_success_at
          from source_sync_runs
          where status = 'succeeded'
          group by source_id
        )
        select s.code, s.name, s.kind, s.enabled, s.plugin_name, s.schedule_cron,
               s.config_json->>'runMode' as run_mode,
               coalesce(r.raw_total, 0), coalesce(r.parse_pending, 0), coalesce(r.parse_succeeded, 0),
               coalesce(r.parse_failed, 0), coalesce(r.normalize_pending, 0),
               coalesce(r.normalize_succeeded, 0), coalesce(r.normalize_failed, 0),
               r.raw_updated_at,
               lr.status, lr.trigger, lr.started_at, lr.finished_at,
               coalesce(lr.fetched_count, 0), coalesce(lr.changed_count, 0),
               coalesce(lr.parsed_count, 0), coalesce(lr.normalized_count, 0),
               coalesce(lr.error_count, 0), lr.log_summary,
               sr.last_success_at
        from sources s
        left join raw_counts r on r.source_id = s.id
        left join latest_runs lr on lr.source_id = s.id
        left join successful_runs sr on sr.source_id = s.id
        order by s.enabled desc, s.kind, s.code
        """))
        await using (var reader = await cmd.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            {
                var rawTotal = reader.GetInt64(7);
                var parsePending = reader.GetInt64(8);
                var parseSucceeded = reader.GetInt64(9);
                var parseFailed = reader.GetInt64(10);
                var normalizePending = reader.GetInt64(11);
                var normalizeSucceeded = reader.GetInt64(12);
                var normalizeFailed = reader.GetInt64(13);
                totalRaw += rawTotal;
                parsePendingTotal += parsePending;
                parseSucceededTotal += parseSucceeded;
                parseFailedTotal += parseFailed;
                normalizePendingTotal += normalizePending;
                normalizeSucceededTotal += normalizeSucceeded;
                normalizeFailedTotal += normalizeFailed;
                if (normalizePending + normalizeFailed > 0)
                    sourcePendingRows.Add((reader.GetString(0), normalizePending + normalizeFailed));
                sourceStatus.Add(new
                {
                    code = reader.GetString(0),
                    name = reader.GetString(1),
                    kind = reader.GetString(2),
                    enabled = reader.GetBoolean(3),
                    pluginName = reader.GetString(4),
                    scheduleCron = reader.IsDBNull(5) ? null : reader.GetString(5),
                    runMode = reader.IsDBNull(6) ? null : reader.GetString(6),
                    rawTotal,
                    parsePending,
                    parseSucceeded,
                    parseFailed,
                    normalizePending,
                    normalizeSucceeded,
                    normalizeFailed,
                    normalizeProgress = rawTotal <= 0 ? 0 : Math.Round((double)normalizeSucceeded / rawTotal * 100, 2),
                    rawUpdatedAt = reader.IsDBNull(14) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(14),
                    latestRun = reader.IsDBNull(15) ? null : new
                    {
                        status = reader.GetString(15),
                        trigger = reader.IsDBNull(16) ? null : reader.GetString(16),
                        startedAt = reader.GetFieldValue<DateTimeOffset>(17),
                        finishedAt = reader.IsDBNull(18) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(18),
                        fetchedCount = reader.GetInt32(19),
                        changedCount = reader.GetInt32(20),
                        parsedCount = reader.GetInt32(21),
                        normalizedCount = reader.GetInt32(22),
                        errorCount = reader.GetInt32(23),
                        logSummary = reader.IsDBNull(24) ? null : reader.GetString(24)
                    },
                    lastSuccessAt = reader.IsDBNull(25) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(25)
                });
            }
        }

        var normalizeStatus = new List<object>
    {
        new { status = "pending", count = normalizePendingTotal, estimated = false },
        new { status = "failed", count = normalizeFailedTotal, estimated = false },
        new { status = "succeeded", count = normalizeSucceededTotal, estimated = false }
    };
        var parseStatus = new List<object>
    {
        new { status = "pending", count = parsePendingTotal, estimated = false },
        new { status = "failed", count = parseFailedTotal, estimated = false },
        new { status = "succeeded", count = parseSucceededTotal, estimated = false }
    };
        var pendingBySource = sourcePendingRows
            .OrderByDescending(x => x.Pending)
            .ThenBy(x => x.SourceCode, StringComparer.Ordinal)
            .Take(25)
            .Select(x => new { sourceCode = x.SourceCode, pending = x.Pending })
            .ToList<object>();

        var totals = await CountTablesAsync(db, [
            "vulnerabilities",
        "vulnerability_records",
        "vulnerability_exploits",
        "vulnerability_affected_components",
        "components",
        "registry_packages",
        "cpe_entries"
        ], ct);

        var status = new
        {
            vulnerabilities = totals["vulnerabilities"],
            vulnerabilityRecords = totals["vulnerability_records"],
            vulnerabilityExploits = totals["vulnerability_exploits"],
            affectedComponents = totals["vulnerability_affected_components"],
            components = totals["components"],
            registryPackages = totals["registry_packages"],
            cpeEntries = totals["cpe_entries"],
            sourceRawRecords = totalRaw,
            sources = sourceStatus.Count,
            countsEstimated = false,
            parseStatus,
            normalizeStatus,
            pendingBySource,
            sourceStatus,
            generatedAt = DateTimeOffset.UtcNow
        };
        systemStatusCache.Value = status;
        systemStatusCache.ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(15);
        return ApiResult.Ok(status);
    }
    finally
    {
        systemStatusCache.RefreshLock.Release();
    }
});

app.MapPost("/api/v1/nvd.processPending", async (HttpContext context, AdminAuthService auth, NvdRawProcessor processor, ProcessPendingRequest request, CancellationToken ct) =>
{
    if (!auth.IsAuthenticated(context)) return ApiResult.Unauthorized();
    var result = await processor.ProcessPendingAsync(request.Limit <= 0 ? 100 : request.Limit, ct);
    return ApiResult.Ok(result);
});

app.MapPost("/api/v1/raw.normalizePending", async (HttpContext context, AdminAuthService auth, IRawNormalizationService processor, NormalizePendingRequest request, CancellationToken ct) =>
{
    if (!auth.IsAuthenticated(context)) return ApiResult.Unauthorized();
    var result = await processor.ProcessPendingAsync(request.LimitPerSource <= 0 ? 100 : request.LimitPerSource, ct);
    return ApiResult.Ok(result);
});

app.MapPost("/api/v1/raw.normalizeSource", async (HttpContext context, AdminAuthService auth, IRawNormalizationService processor, NormalizeSourceRequest request, CancellationToken ct) =>
{
    if (!auth.IsAuthenticated(context)) return ApiResult.Unauthorized();
    var limit = request.Limit <= 0 ? 100 : request.Limit;
    var result = await processor.ProcessSourcePendingAsync(request.SourceCode, limit, ct);
    return ApiResult.Ok(result);
});

app.MapGet("/api/v1/admin.source.list", async (HttpContext context, AdminAuthService auth, NpgsqlDataSource db, CancellationToken ct) =>
{
    if (!auth.IsAuthenticated(context)) return ApiResult.Unauthorized();
    var rows = new List<object>();
    await using var cmd = db.CreateCommand("""
        select s.code, s.name, s.kind, s.enabled, s.plugin_name, s.schedule_cron,
               s.config_json->>'runMode' as run_mode, s.checkpoint_json,
               coalesce(r.raw_total, 0), lr.status, lr.started_at, lr.finished_at,
               coalesce(lr.fetched_count, 0), coalesce(lr.parsed_count, 0), coalesce(lr.error_count, 0)
        from sources s
        left join lateral (
          select count(*) as raw_total from source_raw_index raw where raw.source_id = s.id
        ) r on true
        left join lateral (
          select status, started_at, finished_at, fetched_count, parsed_count, error_count
          from source_sync_runs run where run.source_id = s.id order by started_at desc limit 1
        ) lr on true
        order by s.kind, s.code
        """);
    await using var reader = await cmd.ExecuteReaderAsync(ct);
    while (await reader.ReadAsync(ct))
    {
        rows.Add(new
        {
            code = reader.GetString(0),
            name = reader.GetString(1),
            kind = reader.GetString(2),
            enabled = reader.GetBoolean(3),
            pluginName = reader.GetString(4),
            scheduleCron = reader.IsDBNull(5) ? null : reader.GetString(5),
            runMode = reader.IsDBNull(6) ? null : reader.GetString(6),
            checkpoint = reader.GetString(7),
            rawTotal = reader.GetInt64(8),
            latestRun = reader.IsDBNull(9) ? null : new
            {
                status = reader.GetString(9),
                startedAt = reader.GetFieldValue<DateTimeOffset>(10),
                finishedAt = reader.IsDBNull(11) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(11),
                fetchedCount = reader.GetInt32(12),
                parsedCount = reader.GetInt32(13),
                errorCount = reader.GetInt32(14)
            }
        });
    }
    return ApiResult.Ok(rows);
});

app.MapPost("/api/v1/admin.source.update", async (HttpContext context, AdminAuthService auth, NpgsqlDataSource db, AdminSourceUpdateRequest request, CancellationToken ct) =>
{
    if (!auth.IsAuthenticated(context)) return ApiResult.Unauthorized();
    if (!IsValidSourceCode(request.SourceCode)) return ApiResult.Error("INVALID_SOURCE", "Invalid source code.");
    var runMode = string.IsNullOrWhiteSpace(request.RunMode) ? null : request.RunMode.Trim().ToLowerInvariant();
    if (runMode is not null and not "manual" and not "init") return ApiResult.Error("INVALID_RUN_MODE", "Run mode must be manual, init, or empty.");
    await using var cmd = db.CreateCommand("""
        update sources
        set enabled = $2,
            schedule_cron = nullif($3, ''),
            config_json = case when $4::text is null then config_json - 'runMode' else jsonb_set(config_json, '{runMode}', to_jsonb($4::text), true) end,
            updated_at = now()
        where code = $1
        """);
    cmd.Parameters.AddWithValue(request.SourceCode);
    cmd.Parameters.AddWithValue(request.Enabled);
    cmd.Parameters.AddWithValue(request.ScheduleCron?.Trim() ?? "");
    cmd.Parameters.AddWithValue((object?)runMode ?? DBNull.Value);
    return await cmd.ExecuteNonQueryAsync(ct) == 0
        ? ApiResult.NotFound("SOURCE_NOT_FOUND", request.SourceCode)
        : ApiResult.Ok(new { sourceCode = request.SourceCode, request.Enabled, scheduleCron = request.ScheduleCron, runMode });
});

app.MapPost("/api/v1/admin.source.fetch", async (HttpContext context, AdminAuthService auth, SourceScheduler scheduler, AdminSourceActionRequest request, CancellationToken ct) =>
{
    if (!auth.IsAuthenticated(context)) return ApiResult.Unauthorized();
    if (!IsValidSourceCode(request.SourceCode)) return ApiResult.Error("INVALID_SOURCE", "Invalid source code.");
    await scheduler.RunSourceNowAsync(request.SourceCode, request.Force, ct);
    return ApiResult.Ok(new { sourceCode = request.SourceCode, fetched = true, request.Force });
});

app.MapPost("/api/v1/admin.source.normalize", async (HttpContext context, AdminAuthService auth, IRawNormalizationService processor, AdminSourceActionRequest request, CancellationToken ct) =>
{
    if (!auth.IsAuthenticated(context)) return ApiResult.Unauthorized();
    var result = await processor.ProcessSourcePendingAsync(request.SourceCode, request.Limit <= 0 ? 100 : request.Limit, ct);
    return ApiResult.Ok(result);
});

app.MapPost("/api/v1/admin.source.reprocess", async (HttpContext context, AdminAuthService auth, NpgsqlDataSource db, AdminSourceActionRequest request, CancellationToken ct) =>
{
    if (!auth.IsAuthenticated(context)) return ApiResult.Unauthorized();
    if (!IsValidSourceCode(request.SourceCode)) return ApiResult.Error("INVALID_SOURCE", "Invalid source code.");
    await using var cmd = db.CreateCommand("""
        update source_raw_index raw
        set normalize_status = 'pending', updated_at = now()
        from sources s
        where raw.source_id = s.id and s.code = $1
        """);
    cmd.Parameters.AddWithValue(request.SourceCode);
    var rows = await cmd.ExecuteNonQueryAsync(ct);
    return ApiResult.Ok(new { sourceCode = request.SourceCode, queued = rows });
});

app.MapPost("/api/v1/admin.scheduler.runDue", async (HttpContext context, AdminAuthService auth, SourceScheduler scheduler, CancellationToken ct) =>
{
    if (!auth.IsAuthenticated(context)) return ApiResult.Unauthorized();
    await scheduler.RunDueSourcesAsync(ct);
    return ApiResult.Ok(new { completed = true });
});

app.MapPost("/api/v1/admin.duckdbEvidence.normalize", async (HttpContext context, AdminAuthService auth, DuckDbEvidenceNormalizer normalizer, DuckDbEvidenceNormalizeRequest request, CancellationToken ct) =>
{
    if (!auth.IsAuthenticated(context)) return ApiResult.Unauthorized();
    var result = await normalizer.NormalizeAsync(request, ct);
    return ApiResult.Ok(result);
});

app.MapGet("/api/v1/admin.duckdbEvidence.stats", async (HttpContext context, AdminAuthService auth, DuckDbEvidenceStore store, CancellationToken ct) =>
{
    if (!auth.IsAuthenticated(context)) return ApiResult.Unauthorized();
    return ApiResult.Ok(await store.StatsAsync(ct));
});

app.MapPost("/api/v1/admin.detailSnapshot.rebuild", async (HttpContext context, AdminAuthService auth, VulnerabilityDetailSnapshotBuilder builder, DetailSnapshotBuildRequest request, CancellationToken ct) =>
{
    if (!auth.IsAuthenticated(context)) return ApiResult.Unauthorized();
    var result = await builder.RebuildAsync(request, ct);
    return ApiResult.Ok(result);
});

app.MapGet("/api/v1/vulnerability.aiSummary", async (AiVulnerabilitySummaryService summaries, Guid id, CancellationToken ct) =>
{
    var result = await summaries.GetAsync(id, generate: false, force: false, ct);
    return result is null
        ? ApiResult.NotFound("VULNERABILITY_NOT_FOUND", id.ToString())
        : ApiResult.Ok(result);
});

app.MapPost("/api/v1/admin.vulnerability.aiSummary", async (HttpContext context, AdminAuthService auth, AiVulnerabilitySummaryService summaries, AiSummaryRequest request, CancellationToken ct) =>
{
    if (!auth.IsAuthenticated(context)) return ApiResult.Unauthorized();
    var result = await summaries.GetAsync(request.Id, generate: true, force: request.Force, ct);
    return result is null
        ? ApiResult.NotFound("VULNERABILITY_NOT_FOUND", request.Id.ToString())
        : ApiResult.Ok(result);
});

app.MapPost("/api/v1/vulnerability.search", async (NpgsqlDataSource db, VulnerabilitySearchRequest request, CancellationToken ct) =>
{
    var rows = new List<object>();
    var rawQuery = (request.Query ?? "").Trim();
    var pattern = $"%{rawQuery}%";
    var exact = string.IsNullOrWhiteSpace(rawQuery) ? "" : rawQuery;
    var normalizedExact = string.IsNullOrWhiteSpace(exact) ? "" : Identifier.Normalize(exact);
    var exactIsCompleteCve = System.Text.RegularExpressions.Regex.IsMatch(
        normalizedExact,
        @"^CVE-\d{4}-\d{4,}$",
        System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    var page = Math.Max(1, request.Page);
    var pageSize = ClampPageSize(request.PageSize);
    var fetchLimit = pageSize + 1;
    var offset = (page - 1) * pageSize;
    var sort = NormalizeVulnerabilitySort(request.Sort);
    var orderBy = VulnerabilityOrderBy(sort, "v");

    var queryHasCveIdentifier = Identifier.ExpandWithEmbeddedCves(rawQuery).Any(x => Identifier.TypeOf(x) == "CVE");
    var ecosystemVersion = queryHasCveIdentifier ? null : ParseEcosystemVersion(rawQuery);

    if (ecosystemVersion is not null)
    {
        await using var cmd = db.CreateCommand($"""
            select v.id, v.primary_identifier, v.title, v.severity_label, v.max_cvss_score,
                   v.affected_component_count, v.affected_component_names, v.published_at, v.modified_at,
                   v.identifiers, v.aliases
            from vulnerabilities v
            where v.id in (
                select c.vulnerability_id
                from vulnerability_affected_components c
                where lower(c.ecosystem) = lower($1)
                  and (c.display_name is not null or c.package_name is not null)
            )
            order by {orderBy}
            limit $2 offset $3
            """);
        cmd.Parameters.AddWithValue(ecosystemVersion.Value.Ecosystem);
        cmd.Parameters.AddWithValue(fetchLimit);
        cmd.Parameters.AddWithValue(offset);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            rows.Add(new
            {
                id = reader.GetGuid(0),
                primaryIdentifier = reader.GetString(1),
                title = reader.IsDBNull(2) ? null : reader.GetString(2),
                severityLabel = reader.IsDBNull(3) ? null : reader.GetString(3),
                maxCvssScore = reader.IsDBNull(4) ? (decimal?)null : reader.GetDecimal(4),
                affectedComponentCount = reader.GetInt32(5),
                affectedComponentNames = TruncateNames(reader.GetFieldValue<string[]>(6)),
                publishedAt = reader.IsDBNull(7) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(7),
                modifiedAt = reader.IsDBNull(8) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(8),
                identifiers = reader.GetFieldValue<string[]>(9),
                aliases = reader.GetFieldValue<string[]>(10),
                matchedByEcosystem = true,
                matchedVersion = ecosystemVersion.Value.Version
            });
        }
    }
    else
    {
        var hasQuery = !string.IsNullOrWhiteSpace(rawQuery);
        var cveRange = TryGetCvePrefixRange(rawQuery);
        if (hasQuery && !string.IsNullOrWhiteSpace(exact) && (cveRange is null || exactIsCompleteCve))
        {
            await using var fastCmd = exactIsCompleteCve
                ? db.CreateCommand($"""
                with matched as (
                  select 0 as match_rank, v.id, v.primary_identifier, v.title, v.severity_label, v.max_cvss_score,
                         v.affected_component_count, v.affected_component_names, v.published_at, v.modified_at,
                         v.identifiers, v.aliases
                  from vulnerabilities v
                  where v.primary_identifier = $1
                  union all
                  select 1 as match_rank, v.id, v.primary_identifier, v.title, v.severity_label, v.max_cvss_score,
                         v.affected_component_count, v.affected_component_names, v.published_at, v.modified_at,
                         v.identifiers, v.aliases
                  from vulnerability_identifier_index i
                  join vulnerabilities v on v.id = i.canonical_vulnerability_id
                  where i.normalized_value = $1
                    and v.primary_identifier <> $1
                )
                select id, primary_identifier, title, severity_label, max_cvss_score,
                       affected_component_count, affected_component_names, published_at, modified_at,
                       identifiers, aliases
                from matched
                order by match_rank, modified_at desc nulls last, primary_identifier desc
                limit $2
                """)
                : db.CreateCommand($"""
                with matched as (
                  select 0 as match_rank, v.id, v.primary_identifier, v.title, v.severity_label, v.max_cvss_score,
                         v.affected_component_count, v.affected_component_names, v.published_at, v.modified_at,
                         v.identifiers, v.aliases
                  from vulnerabilities v
                  where v.primary_identifier = $1
                  union all
                  select 1 as match_rank, v.id, v.primary_identifier, v.title, v.severity_label, v.max_cvss_score,
                         v.affected_component_count, v.affected_component_names, v.published_at, v.modified_at,
                         v.identifiers, v.aliases
                  from vulnerability_identifier_index i
                  join vulnerabilities v on v.id = i.canonical_vulnerability_id
                  where i.normalized_value = $1
                    and v.primary_identifier <> $1
                )
                select id, primary_identifier, title, severity_label, max_cvss_score,
                       affected_component_count, affected_component_names, published_at, modified_at,
                       identifiers, aliases
                from matched
                order by match_rank, modified_at desc nulls last, primary_identifier desc
                limit $2
                """);
            fastCmd.Parameters.AddWithValue(normalizedExact);
            fastCmd.Parameters.AddWithValue(fetchLimit);
            await using var fastReader = await fastCmd.ExecuteReaderAsync(ct);
            var found = 0;
            while (await fastReader.ReadAsync(ct))
            {
                rows.Add(MakeResult(fastReader));
                found++;
            }
            if (found > 0 || exactIsCompleteCve)
            {
                var exactHasMore = rows.Count > pageSize;
                if (exactHasMore) rows.RemoveAt(rows.Count - 1);
                return ApiResult.Ok(new { items = rows, page = 1, pageSize, sort, hasMore = exactHasMore });
            }
        }

        await using var cmd = cveRange is not null
            ? db.CreateCommand($"""
                select v.id, v.primary_identifier, v.title, v.severity_label, v.max_cvss_score,
                       v.affected_component_count, v.affected_component_names, v.published_at, v.modified_at,
                       v.identifiers, v.aliases
                from vulnerabilities v
                where v.primary_identifier >= $1 and v.primary_identifier < $2
                order by {orderBy}
                limit $3 offset $4
                """)
            : hasQuery
            ? db.CreateCommand($"""
                with matched as materialized (
                  select v.id
                  from vulnerabilities v
                  where v.identifiers @> array[$1]::text[]
                  union
                  select v.id
                  from vulnerabilities v
                  where v.aliases @> array[$1]::text[]
                  union
                  select v.id
                  from vulnerabilities v
                  where v.search_text @@ plainto_tsquery('simple', $3)
                  union
                  select v.id
                  from vulnerabilities v
                  where v.primary_identifier ilike $2
                  union
                  select v.id
                  from vulnerabilities v
                  where v.title ilike $2
                  union
                  select v.id
                  from vulnerabilities v
                  where v.affected_component_names @> array[$1]::text[]
                )
                select v.id, v.primary_identifier, v.title, v.severity_label, v.max_cvss_score,
                       v.affected_component_count, v.affected_component_names, v.published_at, v.modified_at,
                       v.identifiers, v.aliases
                from vulnerabilities v
                join matched m on m.id = v.id
                order by {orderBy}
                limit $4 offset $5
                """)
            : db.CreateCommand($"""
                select v.id, v.primary_identifier, v.title, v.severity_label, v.max_cvss_score,
                       v.affected_component_count, v.affected_component_names, v.published_at, v.modified_at,
                       v.identifiers, v.aliases
                from vulnerabilities v
                order by {orderBy}
                limit $1 offset $2
                """);
        if (cveRange is not null)
        {
            cmd.Parameters.AddWithValue(cveRange.Value.Start);
            cmd.Parameters.AddWithValue(cveRange.Value.End);
            cmd.Parameters.AddWithValue(fetchLimit);
            cmd.Parameters.AddWithValue(offset);
        }
        else if (hasQuery)
        {
            cmd.Parameters.AddWithValue(normalizedExact);
            cmd.Parameters.AddWithValue(pattern);
            cmd.Parameters.AddWithValue(rawQuery);
            cmd.Parameters.AddWithValue(fetchLimit);
            cmd.Parameters.AddWithValue(offset);
        }
        else
        {
            cmd.Parameters.AddWithValue(fetchLimit);
            cmd.Parameters.AddWithValue(offset);
        }
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            rows.Add(MakeResult(reader));
        }
    }

    var hasMore = rows.Count > pageSize;
    if (hasMore) rows.RemoveAt(rows.Count - 1);
    return ApiResult.Ok(new { items = rows, page, pageSize, sort, hasMore });
});

app.MapGet("/api/v1/vulnerability.getByIdentifier", async (NpgsqlDataSource db, string identifier, CancellationToken ct) =>
{
    var normalized = Identifier.Normalize(identifier);
    await using var cmd = db.CreateCommand("""
        with matched as (
          select 0 as match_rank, v.id, v.primary_identifier, v.title, v.description, v.severity_label,
                 v.max_cvss_score, v.modified_at, v.identifiers, v.aliases
          from vulnerabilities v
          where v.primary_identifier = $1
          union all
          select 1 as match_rank, v.id, v.primary_identifier, v.title, v.description, v.severity_label,
                 v.max_cvss_score, v.modified_at, v.identifiers, v.aliases
          from vulnerability_identifier_index i
          join vulnerabilities v on v.id = i.canonical_vulnerability_id
          where i.normalized_value = $1
            and v.primary_identifier <> $1
        )
        select id, primary_identifier, title, description, severity_label, max_cvss_score, identifiers, aliases
        from matched
        order by match_rank, modified_at desc nulls last, primary_identifier desc
        limit 1
        """);
    cmd.Parameters.AddWithValue(normalized);
    await using var reader = await cmd.ExecuteReaderAsync(ct);
    if (!await reader.ReadAsync(ct)) return ApiResult.NotFound("VULNERABILITY_NOT_FOUND", identifier);
    return ApiResult.Ok(new
    {
        id = reader.GetGuid(0),
        primaryIdentifier = reader.GetString(1),
        title = reader.IsDBNull(2) ? null : reader.GetString(2),
        description = reader.IsDBNull(3) ? null : reader.GetString(3),
        severityLabel = reader.IsDBNull(4) ? null : reader.GetString(4),
        maxCvssScore = reader.IsDBNull(5) ? (decimal?)null : reader.GetDecimal(5),
        identifiers = reader.GetFieldValue<string[]>(6),
        aliases = reader.GetFieldValue<string[]>(7)
    });
});

app.MapGet("/api/v1/vulnerability.get", async (NpgsqlDataSource db, Guid id, CancellationToken ct) =>
{
    await using var cmd = db.CreateCommand("""
        select id, primary_identifier, title, description, severity_label, max_cvss_score,
               affected_component_count, affected_component_names, identifiers
        from vulnerabilities
        where id = $1
        """);
    cmd.Parameters.AddWithValue(id);
    await using var reader = await cmd.ExecuteReaderAsync(ct);
    if (!await reader.ReadAsync(ct)) return ApiResult.NotFound("VULNERABILITY_NOT_FOUND", id.ToString());
    return ApiResult.Ok(new
    {
        id = reader.GetGuid(0),
        primaryIdentifier = reader.GetString(1),
        title = reader.IsDBNull(2) ? null : reader.GetString(2),
        description = reader.IsDBNull(3) ? null : reader.GetString(3),
        severity = new
        {
            label = reader.IsDBNull(4) ? null : reader.GetString(4),
            cvssScore = reader.IsDBNull(5) ? (decimal?)null : reader.GetDecimal(5)
        },
        affectedComponentCount = reader.GetInt32(6),
        affectedComponentNames = reader.GetFieldValue<string[]>(7),
        identifiers = reader.GetFieldValue<string[]>(8)
    });
});

app.MapGet("/api/v1/vulnerability.detail", async (NpgsqlDataSource db, DuckDbEvidenceStore duckDb, string? source, Guid id, CancellationToken ct) =>
{
    await using var cmd = db.CreateCommand("""
        select v.id, v.primary_identifier, coalesce(preferred_title.value, v.title), coalesce(preferred_description.value, v.description),
               v.status, v.severity_label, v.max_cvss_score, v.max_cvss_version, v.max_cvss_vector,
               v.epss_score, v.epss_percentile, v.kev_date_added, v.known_ransomware,
               coalesce(actual_sources.source_count, 0), v.affected_component_count,
               v.affected_ecosystems, v.affected_component_names, v.identifiers, v.aliases,
               coalesce(nvd_dates.published_at, v.published_at),
               coalesce(nvd_dates.modified_at, v.modified_at),
               v.updated_at, v.published_at, v.modified_at
        from vulnerabilities v
        left join lateral (
          select nullif(trim(vr.title), '') as value
          from vulnerability_records vr
          join sources s on s.id = vr.source_id
          where vr.vulnerability_id = v.id
            and nullif(trim(vr.title), '') is not null
            and length(vr.title) <= 220
            and lower(vr.title) !~ '^cve-[0-9]{4}-[0-9]{4,}[[:space:]]+(debian security tracker|ubuntu|osv|nvd|cve list)$'
            and lower(vr.title) !~ '^security update for '
          order by case
                     when s.code in ('ghsa', 'maven-advisory', 'maven-osv', 'maven-osv-init', 'osv', 'osv-init') then 0
                     when s.code in ('cisa-kev', 'debian-security-tracker') then 1
                     when s.code in ('nvd-cve', 'nvd-cve-init') then 2
                     when s.code in ('metasploit', 'exploitdb') then 4
                     else 2
                   end,
                   case when length(vr.title) between 12 and 120 then 0 else 1 end,
                   length(vr.title),
                   vr.updated_at desc
          limit 1
        ) preferred_title on true
        left join lateral (
          select r.source_published_at as published_at, r.source_modified_at as modified_at
          from source_raw_index r
          join sources s on s.id = r.source_id
          where s.code in ('nvd-cve', 'nvd-cve-init')
            and r.external_key = v.primary_identifier
          order by r.source_modified_at desc nulls last, r.created_at desc
          limit 1
        ) nvd_dates on true
        left join lateral (
          select d.value
          from vulnerability_descriptions d
          join sources s on s.id = d.source_id
          where d.vulnerability_id = v.id
            and nullif(trim(d.value), '') is not null
          order by case when lower(d.lang) = 'en' then 0 else 1 end,
                   case
                     when trim(d.value) like '#%' or d.value like E'%\n#%' or d.value like '%](/%' or d.value like '%](http%' then 0
                     else 1
                   end,
                   case when d.description_type = 'detail' then 0 else 1 end,
                   case
                     when s.code in ('ghsa', 'maven-advisory', 'maven-osv', 'maven-osv-init', 'osv', 'osv-init') then 0
                     when s.code in ('nvd-cve', 'nvd-cve-init') then 1
                     else 2
                   end,
                   length(d.value) desc,
                   d.is_selected desc
          limit 1
        ) preferred_description on true
        left join lateral (
          select count(distinct vr.source_id)::integer as source_count
          from vulnerability_records vr
          where vr.vulnerability_id = v.id
        ) actual_sources on true
        where v.id = $1
        """);
    cmd.Parameters.AddWithValue(id);
    await using var reader = await cmd.ExecuteReaderAsync(ct);
    if (!await reader.ReadAsync(ct)) return ApiResult.NotFound("VULNERABILITY_NOT_FOUND", id.ToString());

    var vulnerability = new
    {
        id = reader.GetGuid(0),
        primaryIdentifier = reader.GetString(1),
        title = reader.IsDBNull(2) ? null : reader.GetString(2),
        description = reader.IsDBNull(3) ? null : reader.GetString(3),
        status = reader.GetString(4),
        severityLabel = reader.IsDBNull(5) ? null : reader.GetString(5),
        maxCvssScore = reader.IsDBNull(6) ? (decimal?)null : reader.GetDecimal(6),
        maxCvssVersion = reader.IsDBNull(7) ? null : reader.GetString(7),
        maxCvssVector = reader.IsDBNull(8) ? null : reader.GetString(8),
        epssScore = reader.IsDBNull(9) ? (decimal?)null : reader.GetDecimal(9),
        epssPercentile = reader.IsDBNull(10) ? (decimal?)null : reader.GetDecimal(10),
        kevDateAdded = reader.IsDBNull(11) ? null : reader.GetDateTime(11).ToString("yyyy-MM-dd"),
        knownRansomware = reader.IsDBNull(12) ? (bool?)null : reader.GetBoolean(12),
        sourceCount = reader.GetInt32(13),
        affectedComponentCount = reader.GetInt32(14),
        affectedEcosystems = reader.GetFieldValue<string[]>(15),
        affectedComponentNames = reader.GetFieldValue<string[]>(16),
        identifiers = reader.GetFieldValue<string[]>(17),
        aliases = reader.GetFieldValue<string[]>(18),
        publishedAt = reader.IsDBNull(19) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(19),
        modifiedAt = reader.IsDBNull(20) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(20),
        updatedAt = reader.GetFieldValue<DateTimeOffset>(21),
        canonicalPublishedAt = reader.IsDBNull(22) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(22),
        canonicalModifiedAt = reader.IsDBNull(23) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(23)
    };

    var actualId = id;
    if (string.IsNullOrWhiteSpace(vulnerability.description) && vulnerability.sourceCount <= 1)
    {
        // Try to find a richer entry (merged CVE that has description)
        await using var best = db.CreateCommand("SELECT id FROM vulnerabilities WHERE primary_identifier = $1 ORDER BY coalesce(source_count,0) DESC, coalesce(length(description),0) DESC LIMIT 1");
        best.Parameters.AddWithValue(vulnerability.primaryIdentifier);
        await using var bestReader = await best.ExecuteReaderAsync(ct);
        if (await bestReader.ReadAsync(ct))
            actualId = bestReader.GetGuid(0);
    }

    var sourceUrls = BuildSourceUrls(vulnerability.primaryIdentifier, vulnerability.aliases);

    var queryId = actualId;
    var useDuckDb = source == "duckdb" || (duckDb.Enabled && source != "pgsql");

    return ApiResult.Ok(new
    {
        vulnerability,
        sourceUrls,
        identifiers = await QueryRowsAsync(db, """
            select i.identifier_type, i.identifier_value, i.normalized_value, i.evidence_strength,
                   i.confidence, s.code
            from vulnerability_identifier_index i
            left join sources s on s.id = i.source_id
            where i.canonical_vulnerability_id = $1
            order by i.identifier_type, i.identifier_value
            limit 50
            """, queryId, ct),
        records = await QueryRecordsGroupedAsync(db, queryId, ct),
        affectedComponents = await QueryRowsAsync(db, """
            select ecosystem, package_name, display_name,
                   left(coalesce(primary_purl,''), 80) as primary_purl,
                   left(coalesce(primary_cpe23_uri,''), 80) as primary_cpe23_uri,
                   normalized_range, range_type, confidence, evidence_count, resolution_status
            from vulnerability_affected_components
            where vulnerability_id = $1
            order by CASE WHEN range_type IN ('ECOSYSTEM','semver','vendor') THEN 0 ELSE 1 END,
                     CASE WHEN normalized_range IS NOT NULL AND normalized_range <> '' THEN 0 ELSE 1 END,
                     ecosystem nulls last, display_name
            limit 60
            """, queryId, ct),
        affectedExpressions = useDuckDb
            ? (await duckDb.QueryAffectedFactsAsync(vulnerability.primaryIdentifier, 250, ct))
            : await QueryRowsAsync(db, """
            select s.code, f.fact_type, f.ecosystem, f.package_name, f.purl,
                   f.purl_without_version, f.cpe23_uri, f.version_range_raw,
                   f.range_type, f.vulnerable, f.source_confidence
            from vulnerability_affected_facts f
            left join sources s on s.id = f.source_id
            where f.vulnerability_id = $1
            order by case when f.cpe23_uri is not null then 0 else 1 end,
                     case when f.purl is not null then 0 else 1 end,
                     s.code nulls last, f.package_name nulls last, f.version_range_raw nulls last
            limit 250
            """, queryId, ct),
        descriptions = await QueryRowsAsync(db, """
            select s.code, lang, description_type, left(value, 4000) as value, is_selected
            from vulnerability_descriptions d
            left join sources s on s.id = d.source_id
            where d.vulnerability_id = $1
            order by case when lower(lang) = 'en' then 0 else 1 end,
                     case
                       when trim(value) like '#%' or value like E'%\n#%' or value like '%](/%' or value like '%](http%' then 0
                       else 1
                     end,
                     case when description_type = 'detail' then 0 else 1 end,
                     case
                       when s.code in ('ghsa', 'maven-advisory', 'maven-osv', 'maven-osv-init', 'osv', 'osv-init') then 0
                       when s.code in ('nvd-cve', 'nvd-cve-init') then 1
                       else 2
                     end,
                     length(value) desc,
                     is_selected desc,
                     s.code nulls last
            limit 16
            """, queryId, ct),
        severities = useDuckDb
            ? (await duckDb.QuerySeverityScoresAsync(vulnerability.primaryIdentifier, 20, ct))
            : await QueryRowsAsync(db, """
            select s.code, scoring_system, scoring_version, score_type, vector_string,
                   score, severity_label, is_selected
            from vulnerability_severity_scores vss
            left join sources s on s.id = vss.source_id
            where vss.vulnerability_id = $1
            order by case when s.code in ('nvd-cve', 'nvd-cve-init') then 0 else 1 end,
                     is_selected desc, score desc nulls last
            limit 20
            """, queryId, ct),
        references = useDuckDb
            ? (await duckDb.QueryReferencesAsync(vulnerability.primaryIdentifier, 160, ct))
            : await QueryRowsAsync(db, """
            with ranked as (
              select s.code, url, ref_type, tags,
                     row_number() over (partition by s.code order by url) as source_rank
              from vulnerability_references r
              left join sources s on s.id = r.source_id
              where r.vulnerability_id = $1
            )
            select code, url, ref_type, tags
            from ranked
            where source_rank <= 40
            order by code nulls last, source_rank, url
            limit 160
            """, queryId, ct),
        exploits = await QueryRowsAsync(db, """
            select s.code, e.source_key, e.title, e.source_url, e.artifact_url,
                   e.artifact_type, e.exploit_type, e.maturity, e.verification_status,
                   e.requires_auth, e.requires_user_interaction, e.language, e.platform,
                   e.author, e.published_at, e.modified_at, e.tags
            from vulnerability_exploits e
            join sources s on s.id = e.source_id
            where e.vulnerability_id = $1
            order by case e.maturity
                       when 'metasploit' then 0
                       when 'functional' then 1
                       when 'source_verified' then 2
                       when 'verified-template' then 3
                       when 'detection-template' then 4
                       else 9
                     end,
                     e.modified_at desc nulls last,
                     s.code,
                     e.source_key
            limit 40
            """, queryId, ct),
        history = await QueryRowsAsync(db, """
            select s.code, vr.source_record_id, ri.source_published_at, ri.source_modified_at,
                   ri.created_at as ingested_at, vr.updated_at as normalized_at,
                   left(ri.record_hash, 16) as record_hash,
                   case
                     when row_number() over (
                       partition by vr.source_id, vr.source_record_id
                       order by ri.created_at, vr.created_at
                     ) = 1 then 'added'
                     else 'updated'
                   end as change_type
            from vulnerability_records vr
            join sources s on s.id = vr.source_id
            join source_raw_index ri on ri.id = vr.raw_index_id
            where vr.vulnerability_id = $1
            order by coalesce(ri.source_modified_at, ri.created_at) desc, s.code
            limit 40
            """, queryId, ct)
    });
});

app.MapPost("/api/v1/component.vulnerabilitySearch", async (ComponentVulnerabilitySearchService search, ComponentVulnerabilitySearchRequest request, CancellationToken ct) =>
{
    var result = await search.SearchAsync(request, ct);
    return ApiResult.Ok(result);
});

app.MapPost("/api/v1/component.search", async (NpgsqlDataSource db, ComponentSearchRequest request, CancellationToken ct) =>
{
    var pageSize = request.PageSize <= 0 ? 50 : Math.Min(request.PageSize, 200);
    var lookup = ComponentQuery.Normalize(request.Name ?? request.Query, request.Vendor, request.Purl, request.Ecosystem);
    var queryText = request.Query?.Trim() ?? request.Name?.Trim() ?? "";
    var query = $"%{queryText}%";

    var components = new List<object>();
    await using (var cmd = db.CreateCommand("""
        select id, canonical_name, component_type, primary_purl, primary_cpe23_uri,
               primary_repository_url, identities
        from components
        where (
            $1 = '%%'
            or canonical_name ilike $1
            or primary_purl ilike $1
            or primary_cpe23_uri ilike $1
            or identities @> array[$2]
            or (cardinality($3::text[]) > 0 and lower(canonical_name) = any($3))
            or (cardinality($4::text[]) > 0 and lower(coalesce(primary_purl, '')) = any($4))
            or ($5::text is not null and lower(coalesce(primary_purl, '')) like $5 || '%')
        )
          and ($6::text is null or primary_purl ilike ('pkg:' || $6 || '/%'))
        order by updated_at desc
        limit $7
        """))
    {
        cmd.Parameters.AddWithValue(query);
        cmd.Parameters.AddWithValue(queryText);
        cmd.Parameters.AddWithValue(lookup.NameCandidates);
        cmd.Parameters.AddWithValue(lookup.PurlCandidates);
        cmd.Parameters.AddWithValue((object?)lookup.PurlWithoutVersionLower ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)lookup.Ecosystem ?? DBNull.Value);
        cmd.Parameters.AddWithValue(pageSize);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            components.Add(new
            {
                id = reader.GetGuid(0),
                canonicalName = reader.GetString(1),
                componentType = reader.GetString(2),
                primaryPurl = reader.IsDBNull(3) ? null : reader.GetString(3),
                primaryCpe23Uri = reader.IsDBNull(4) ? null : reader.GetString(4),
                primaryRepositoryUrl = reader.IsDBNull(5) ? null : reader.GetString(5),
                identities = reader.GetFieldValue<string[]>(6)
            });
        }
    }

    var registryPackages = new List<object>();
    await using (var cmd = db.CreateCommand("""
        select ecosystem, registry_url, namespace, name, latest_version, purl_without_version,
               homepage_url, repository_url, metadata_json::text, last_seen_at
        from registry_packages
        where (
            $1 = '%%'
            or name ilike $1
            or namespace ilike $1
            or purl_without_version ilike $1
            or (cardinality($2::text[]) > 0 and lower(name) = any($2))
            or (cardinality($3::text[]) > 0 and lower(coalesce(purl_without_version, '')) = any($3))
            or ($4::text is not null and lower(coalesce(purl_without_version, '')) like $4 || '%')
        )
          and ($5::text is null or lower(ecosystem) = lower($5))
        order by last_seen_at desc
        limit $6
        """))
    {
        cmd.Parameters.AddWithValue(query);
        cmd.Parameters.AddWithValue(lookup.NameCandidates);
        cmd.Parameters.AddWithValue(lookup.PurlCandidates);
        cmd.Parameters.AddWithValue((object?)lookup.PurlWithoutVersionLower ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)lookup.Ecosystem ?? DBNull.Value);
        cmd.Parameters.AddWithValue(pageSize);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            registryPackages.Add(new
            {
                ecosystem = reader.GetString(0),
                registryUrl = reader.IsDBNull(1) ? null : reader.GetString(1),
                namespaceName = reader.IsDBNull(2) ? null : reader.GetString(2),
                name = reader.GetString(3),
                latestVersion = reader.IsDBNull(4) ? null : reader.GetString(4),
                purlWithoutVersion = reader.IsDBNull(5) ? null : reader.GetString(5),
                homepageUrl = reader.IsDBNull(6) ? null : reader.GetString(6),
                repositoryUrl = reader.IsDBNull(7) ? null : reader.GetString(7),
                metadata = JsonOrNull(reader.GetString(8)),
                lastSeenAt = reader.GetFieldValue<DateTimeOffset>(9)
            });
        }
    }

    return ApiResult.Ok(new { components, registryPackages });
});
SbomEndpoints.Map(app);

app.MapGet("/api/v1/benchmark.ecosystemCveCount", async (NpgsqlDataSource db, string? ecosystem, string? package, string? version, CancellationToken ct) =>
{
    string whereFilter, limitClause = "LIMIT 50";
    var parameters = new List<object> { (object?)ecosystem ?? "go" };

    if (string.IsNullOrWhiteSpace(package))
    {
        whereFilter = "WHERE lower(c.ecosystem) = lower($1)";
    }
    else
    {
        whereFilter = "WHERE lower(c.ecosystem) = lower($1) AND lower(c.package_name) = lower($2)";
        parameters.Add(package);
        limitClause = "";
    }

    await using var cmd = db.CreateCommand($"""
        SELECT c.ecosystem, c.package_name,
               count(DISTINCT c.vulnerability_id) as total_cves,
               count(*) as fact_count
        FROM vulnerability_affected_components c
        {whereFilter}
        GROUP BY c.ecosystem, c.package_name
        ORDER BY total_cves DESC
        {limitClause}
        """);
    for (var i = 0; i < parameters.Count; i++) cmd.Parameters.AddWithValue(parameters[i]);
    var items = new List<object>();
    await using var r = await cmd.ExecuteReaderAsync(ct);
    while (await r.ReadAsync(ct))
    {
        var eco = r.GetString(0);
        var pkg = r.GetString(1);
        var totalCves = r.GetInt32(2);
        var factCount = r.GetInt32(3);
        int? affectedIfVersion = null, notAffectedIfVersion = null;

        if (!string.IsNullOrWhiteSpace(version))
        {
            using var vc = db.CreateCommand("""
                SELECT count(DISTINCT c.vulnerability_id)
                FROM vulnerability_affected_components c
                WHERE lower(c.ecosystem) = lower($1) AND lower(c.package_name) = lower($2)
                  AND c.normalized_range IS NOT NULL
                """);
            vc.Parameters.AddWithValue(eco); vc.Parameters.AddWithValue(pkg);
            await using var vr = await vc.ExecuteReaderAsync(ct);
            if (await vr.ReadAsync(ct)) { var hasRange = vr.GetInt32(0); notAffectedIfVersion = totalCves - hasRange; affectedIfVersion = null; }
        }
        items.Add(new { ecosystem = eco, package = pkg, totalCves, affectedIfVersion, notAffectedIfVersion, factCount });
    }
    return ApiResult.Ok(new { items });
});

app.MapGet("/api/v1/benchmark.packageCves", async (NpgsqlDataSource db, string name, CancellationToken ct) =>
{
    await using var cmd = db.CreateCommand("""
        SELECT lower(display_name), count(DISTINCT vulnerability_id) as cves,
               count(*) as facts, string_agg(DISTINCT ecosystem, ', ') as ecosystems
        FROM vulnerability_affected_components
        WHERE lower(display_name) = lower($1)
        GROUP BY lower(display_name)
        """);
    cmd.Parameters.AddWithValue(name);
    await using var r = await cmd.ExecuteReaderAsync(ct);
    if (await r.ReadAsync(ct))
        return ApiResult.Ok(new { name, cves = r.GetInt32(1), facts = r.GetInt32(2), ecosystems = r.GetString(3) });
    return ApiResult.Ok(new { name, cves = 0 });
});

app.MapGet("/api/v1/benchmark.matchingQuality", async (NpgsqlDataSource db, string? ecosystem, string? packageName, Guid? sbomId, CancellationToken ct) =>
{
    var affectedSummary = new List<object>();
    var useSbomScope = sbomId is not null && string.IsNullOrWhiteSpace(ecosystem) && string.IsNullOrWhiteSpace(packageName);
    await using (var cmd = useSbomScope
        ? db.CreateCommand("""
            with sbom_names as (
              select distinct lower(coalesce(ecosystem, '')) as ecosystem, lower(name) as name
              from sbom_components
              where sbom_id = $1 and name is not null and name <> ''
            ),
            scoped as (
              select c.id, c.ecosystem, c.vulnerability_id, c.primary_purl, c.primary_cpe23_uri, c.normalized_range
              from vulnerability_affected_components c
              join sbom_names s on lower(c.display_name) = s.name
                and (s.ecosystem = '' or lower(coalesce(c.ecosystem, '')) = s.ecosystem)
              union
              select c.id, c.ecosystem, c.vulnerability_id, c.primary_purl, c.primary_cpe23_uri, c.normalized_range
              from vulnerability_affected_components c
              join sbom_names s on lower(c.package_name) = s.name
                and (s.ecosystem = '' or lower(coalesce(c.ecosystem, '')) = s.ecosystem)
            )
            select
              coalesce(nullif(lower(ecosystem), ''), 'unknown') as ecosystem,
              count(*) as facts,
              count(distinct vulnerability_id) as vulnerabilities,
              count(*) filter (where primary_purl is not null and primary_purl <> '') as purl_facts,
              count(*) filter (where primary_cpe23_uri is not null and primary_cpe23_uri <> '') as cpe_facts,
              count(*) filter (where normalized_range is null or normalized_range = '') as no_range,
              count(*) filter (where normalized_range ~ '^[[:space:]]*>[[:space:]]*0(\.0+)*[[:space:]]*$') as open_lower_bound,
              count(*) filter (where normalized_range is not null and normalized_range <> '' and normalized_range !~ '(<=|>=|==|=|<|>)') as unparseable_range
            from scoped
            group by coalesce(nullif(lower(ecosystem), ''), 'unknown')
            order by facts desc
            limit 50
            """)
        : db.CreateCommand("""
            select
              coalesce(nullif(lower(ecosystem), ''), 'unknown') as ecosystem,
              count(*) as facts,
              count(distinct vulnerability_id) as vulnerabilities,
              count(*) filter (where primary_purl is not null and primary_purl <> '') as purl_facts,
              count(*) filter (where primary_cpe23_uri is not null and primary_cpe23_uri <> '') as cpe_facts,
              count(*) filter (where normalized_range is null or normalized_range = '') as no_range,
              count(*) filter (where normalized_range ~ '^[[:space:]]*>[[:space:]]*0(\.0+)*[[:space:]]*$') as open_lower_bound,
              count(*) filter (where normalized_range is not null and normalized_range <> '' and normalized_range !~ '(<=|>=|==|=|<|>)') as unparseable_range
            from vulnerability_affected_components
            where ($1::text is null or lower(ecosystem) = lower($1))
              and ($2::text is null or lower(package_name) = lower($2) or lower(display_name) = lower($2))
            group by coalesce(nullif(lower(ecosystem), ''), 'unknown')
            order by facts desc
            limit 50
            """))
    {
        if (useSbomScope)
        {
            cmd.Parameters.AddWithValue(sbomId!.Value);
        }
        else
        {
            cmd.Parameters.AddWithValue((object?)ecosystem ?? DBNull.Value);
            cmd.Parameters.AddWithValue((object?)packageName ?? DBNull.Value);
        }
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var facts = reader.GetInt64(1);
            var noRange = reader.GetInt64(5);
            var unparseable = reader.GetInt64(7);
            affectedSummary.Add(new
            {
                ecosystem = reader.GetString(0),
                facts,
                vulnerabilities = reader.GetInt64(2),
                purlFacts = reader.GetInt64(3),
                cpeFacts = reader.GetInt64(4),
                noRange,
                openLowerBound = reader.GetInt64(6),
                unparseableRange = unparseable,
                actionableRangeRatio = facts == 0 ? 0 : Math.Round((double)(facts - noRange - unparseable) / facts, 4)
            });
        }
    }

    object? sbomSummary = null;
    if (sbomId is not null)
    {
        await using var cmd = db.CreateCommand("""
            select
              count(*) as findings,
              count(*) filter (where sv.version_matched = true) as affected,
              count(*) filter (where sv.version_matched = false) as fixed,
              count(*) filter (where sv.version_matched is null) as unknown,
              count(*) filter (where sv.normalized_range is null or sv.normalized_range = '') as no_range,
              count(distinct sv.sbom_component_id) as components_with_findings
            from sbom_vulnerabilities sv
            join sbom_components sc on sc.id = sv.sbom_component_id
            where sc.sbom_id = $1
            """);
        cmd.Parameters.AddWithValue(sbomId.Value);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (await reader.ReadAsync(ct))
        {
            sbomSummary = new
            {
                sbomId,
                findings = reader.GetInt64(0),
                affected = reader.GetInt64(1),
                notAffected = reader.GetInt64(2),
                unknown = reader.GetInt64(3),
                noRange = reader.GetInt64(4),
                componentsWithFindings = reader.GetInt64(5)
            };
        }
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

static Dictionary<string, string> BuildSourceUrls(string primaryIdentifier, string[] aliases)
{
    var urls = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    if (!string.IsNullOrWhiteSpace(primaryIdentifier) && primaryIdentifier.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase))
    {
        urls["NVD"] = $"https://nvd.nist.gov/vuln/detail/{primaryIdentifier}";
        urls["CVE.org"] = $"https://www.cve.org/CVERecord?id={primaryIdentifier}";
        urls["MITRE"] = $"https://cve.mitre.org/cgi-bin/cvename.cgi?name={primaryIdentifier}";
        urls["OSV"] = $"https://osv.dev/vulnerability/{primaryIdentifier}";
    }
    foreach (var alias in aliases.Prepend(primaryIdentifier).Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase))
    {
        if (alias.StartsWith("GHSA-", StringComparison.OrdinalIgnoreCase))
            urls["GitHub Advisory"] = $"https://github.com/advisories/{alias}";
        if (alias.StartsWith("OSV-", StringComparison.OrdinalIgnoreCase))
            urls["OSV"] = $"https://osv.dev/vulnerability/{alias}";
        if (alias.StartsWith("USN-", StringComparison.OrdinalIgnoreCase))
            urls["Ubuntu"] = $"https://ubuntu.com/security/notices/{alias}";
        if (alias.StartsWith("CNNVD-", StringComparison.OrdinalIgnoreCase))
            urls["CNNVD"] = $"https://www.cnnvd.org.cn/home/detail?cnnvdCode={Uri.EscapeDataString(alias)}";
        if (alias.StartsWith("CNVD-", StringComparison.OrdinalIgnoreCase))
            urls["CNVD"] = $"https://www.cnvd.org.cn/flaw/show/{Uri.EscapeDataString(alias)}";
        if (alias.StartsWith("SSV-", StringComparison.OrdinalIgnoreCase))
            urls["Seebug"] = $"https://www.seebug.org/vuldb/ssvid-{Uri.EscapeDataString(alias[4..])}";
        if (alias.StartsWith("AVD-", StringComparison.OrdinalIgnoreCase))
            urls["Aliyun AVD"] = $"https://avd.aliyun.com/detail?id={Uri.EscapeDataString(alias)}";
        if (alias.StartsWith("CT-", StringComparison.OrdinalIgnoreCase))
            urls["Chaitin"] = $"https://stack.chaitin.com/vuldb/index?search={Uri.EscapeDataString(alias)}";
        if (alias.StartsWith("NSFOCUS-", StringComparison.OrdinalIgnoreCase))
            urls["NSFOCUS"] = $"https://www.nsfocus.net/vulndb/{Uri.EscapeDataString(alias[8..])}";
        if (alias.StartsWith("CERT360-", StringComparison.OrdinalIgnoreCase))
            urls["360CERT"] = $"https://cert.360.cn/report/detail?id={Uri.EscapeDataString(alias[8..])}";
    }
    return urls;
}

static async Task<List<object>> QueryRecordsGroupedAsync(NpgsqlDataSource db, Guid vulnId, CancellationToken ct)
{
    await using var cmd = db.CreateCommand("""
        select s.code, s.name, vr.source_record_id, left(vr.title, 200) as title,
               ri.source_published_at, ri.source_modified_at, ri.created_at, vr.updated_at
        from vulnerability_records vr
        join sources s on s.id = vr.source_id
        join source_raw_index ri on ri.id = vr.raw_index_id
        where vr.vulnerability_id = $1
        order by s.code, vr.updated_at desc
        limit 60
        """);
    cmd.Parameters.AddWithValue(vulnId);
    var rows = new List<object>();
    await using var r = await cmd.ExecuteReaderAsync(ct);
    while (await r.ReadAsync(ct))
        rows.Add(new
        {
            code = r.GetString(0),
            name = r.GetString(1),
            recordId = r.GetString(2),
            title = r.IsDBNull(3) ? null : r.GetString(3),
            sourcePublishedAt = r.IsDBNull(4) ? (DateTimeOffset?)null : r.GetFieldValue<DateTimeOffset>(4),
            sourceModifiedAt = r.IsDBNull(5) ? (DateTimeOffset?)null : r.GetFieldValue<DateTimeOffset>(5),
            ingestedAt = r.GetFieldValue<DateTimeOffset>(6),
            normalizedAt = r.GetFieldValue<DateTimeOffset>(7)
        });
    return rows;
}

app.Run();

static async Task EnsureRuntimeIndexesAsync(NpgsqlDataSource db)
{
    foreach (var statement in new[]
    {
        "create index if not exists ix_vuln_modified on vulnerabilities(modified_at desc nulls last)",
        "create index if not exists ix_vuln_published on vulnerabilities(published_at desc nulls last)",
        "create index if not exists ix_vuln_sort on vulnerabilities((coalesce(max_cvss_score, 0)) desc, modified_at desc nulls last)",
        "create index if not exists ix_vuln_cvss_identifier_filter on vulnerabilities((coalesce(max_cvss_score, 0)) desc, modified_at desc nulls last, primary_identifier)",
        "create index if not exists ix_vuln_primary_identifier_trgm on vulnerabilities using gin(primary_identifier gin_trgm_ops)",
        "create index if not exists ix_vuln_aliases on vulnerabilities using gin(aliases)",
        "create index if not exists ix_raw_normalize_latest on source_raw_index(source_id, external_key, source_modified_at desc nulls last, updated_at desc, created_at desc, id desc) where normalize_status in ('pending', 'failed')",
        "create index if not exists ix_raw_pending_status_by_source on source_raw_index(source_id, normalize_status) where normalize_status in ('pending', 'failed')",
        "create index if not exists ix_raw_pending_source_updated on source_raw_index(source_id, normalize_status, updated_at, id) where normalize_status in ('pending', 'failed')",
        "create index if not exists ix_raw_pending_source_order on source_raw_index(source_id, updated_at, id) where normalize_status in ('pending', 'failed')",
        "create index if not exists ix_raw_source_id_order on source_raw_index(source_id, id)",
        "drop index if exists ix_raw_pending_by_source",
        "create index if not exists ix_stg_nvd_cpe_normalize_order on stg_nvd_cpe_dictionary(cpe23_uri, raw_index_id)",
        "create index if not exists ix_stg_nvd_cves_normalize_order on stg_nvd_cves(modified_at nulls last, cve_id, raw_index_id)",
        "create index if not exists ix_stg_threat_intel_normalize_order on stg_threat_intel_records(observed_at nulls last, identifier, raw_index_id)",
        "create index if not exists ix_stg_registry_normalize_order on stg_registry_packages(ecosystem, namespace, name, raw_index_id)",
        "create index if not exists ix_stg_exploit_normalize_order on stg_exploit_pocs(modified_at desc nulls last, raw_index_id)",
        "create index if not exists ix_component_identity_component_lookup on component_identity_index(component_id, identity_type, normalized_value)",
        "create index if not exists ix_records_source_fk on vulnerability_records(source_id)",
        "create index if not exists ix_descriptions_record_fk on vulnerability_descriptions(vulnerability_record_id)",
        "create index if not exists ix_severity_record_fk on vulnerability_severity_scores(vulnerability_record_id)",
        "create index if not exists ix_severity_source_fk on vulnerability_severity_scores(source_id)",
        "create index if not exists ix_weaknesses_record_fk on vulnerability_weaknesses(vulnerability_record_id)",
        "create index if not exists ix_weaknesses_source_fk on vulnerability_weaknesses(source_id)",
        "create index if not exists ix_refs_record_fk on vulnerability_references(vulnerability_record_id)",
        "create index if not exists ix_refs_source_fk on vulnerability_references(source_id)",
        "create index if not exists ix_source_properties_record_fk on vulnerability_source_properties(vulnerability_record_id)",
        "create index if not exists ix_detail_blocks_record_fk on vulnerability_detail_blocks(vulnerability_record_id)",
        "create index if not exists ix_detail_blocks_source_fk on vulnerability_detail_blocks(source_id)",
        "create index if not exists ix_affected_facts_record_fk on vulnerability_affected_facts(vulnerability_record_id)",
        "create index if not exists ix_affected_facts_source_fk on vulnerability_affected_facts(source_id)",
        "create index if not exists ix_descriptions_source_fk on vulnerability_descriptions(source_id)",
        "create index if not exists ix_identifier_edges_source_fk on vulnerability_identifier_edges(source_id)",
        "create index if not exists ix_identifier_index_source_fk on vulnerability_identifier_index(source_id)",
        """
        create table if not exists ai_vulnerability_summaries (
          vulnerability_id uuid not null references vulnerabilities(id) on delete cascade,
          model text not null,
          prompt_version text not null,
          evidence_hash text not null,
          summary_json jsonb not null,
          input_json jsonb not null,
          input_chars integer not null default 0,
          output_chars integer not null default 0,
          created_at timestamptz not null default now(),
          updated_at timestamptz not null default now(),
          primary key (vulnerability_id, model, prompt_version, evidence_hash)
        )
        """,
        "create index if not exists ix_ai_summaries_vuln_latest on ai_vulnerability_summaries(vulnerability_id, updated_at desc)",
        """
        do $$
        begin
          if to_regclass('public.sbom_components') is not null then
            if exists (
              select 1
              from pg_attribute
              where attrelid = to_regclass('public.sbom_components')
                and attname = 'purl'
                and attnotnull
                and not attisdropped
            ) then
              alter table sbom_components alter column purl drop not null;
            end if;

            if not exists (
              select 1
              from pg_attribute
              where attrelid = to_regclass('public.sbom_components')
                and attname = 'vendor'
                and not attisdropped
            ) then
              alter table sbom_components add column vendor text;
            end if;

            if not exists (
              select 1
              from pg_attribute
              where attrelid = to_regclass('public.sbom_components')
                and attname = 'product'
                and not attisdropped
            ) then
              alter table sbom_components add column product text;
            end if;

            if not exists (
              select 1
              from pg_attribute
              where attrelid = to_regclass('public.sbom_components')
                and attname = 'cpe23_uri'
                and not attisdropped
            ) then
              alter table sbom_components add column cpe23_uri text;
            end if;

            if not exists (
              select 1
              from pg_attribute
              where attrelid = to_regclass('public.sbom_components')
                and attname = 'source_package_name'
                and not attisdropped
            ) then
              alter table sbom_components add column source_package_name text;
            end if;

            if not exists (
              select 1
              from pg_attribute
              where attrelid = to_regclass('public.sbom_components')
                and attname = 'source_package_version'
                and not attisdropped
            ) then
              alter table sbom_components add column source_package_version text;
            end if;
          end if;

          if to_regclass('public.sbom_vulnerabilities') is not null then
            if not exists (
              select 1
              from pg_attribute
              where attrelid = to_regclass('public.sbom_vulnerabilities')
                and attname = 'match_basis'
                and not attisdropped
            ) then
              alter table sbom_vulnerabilities add column match_basis text;
            end if;

            if not exists (
              select 1
              from pg_attribute
              where attrelid = to_regclass('public.sbom_vulnerabilities')
                and attname = 'matched_version'
                and not attisdropped
            ) then
              alter table sbom_vulnerabilities add column matched_version text;
            end if;
          end if;
        end $$;
        """,
        "create index if not exists ix_sbom_components_purl on sbom_components(purl) where purl is not null",
        "create index if not exists ix_sbom_components_cpe on sbom_components(cpe23_uri) where cpe23_uri is not null",
        "create index if not exists ix_affected_components_purl_exact on vulnerability_affected_components(primary_purl, lower(ecosystem), vulnerability_id) where primary_purl is not null",
        "create index if not exists ix_affected_components_cpe_prefix on vulnerability_affected_components(primary_cpe23_uri text_pattern_ops, vulnerability_id) where primary_cpe23_uri is not null",
        """
        insert into sources (code, name, kind, homepage_url, plugin_name, schedule_cron)
        values
          ('exploitdb', 'Exploit-DB Public Exploits', 'exploit', 'https://www.exploit-db.com/', 'exploit-intel', '0 */12 * * *'),
          ('metasploit', 'Metasploit Framework Modules', 'exploit', 'https://github.com/rapid7/metasploit-framework', 'exploit-intel', '0 */12 * * *'),
          ('nuclei-templates', 'ProjectDiscovery Nuclei Templates', 'exploit', 'https://github.com/projectdiscovery/nuclei-templates', 'exploit-intel', '0 */12 * * *'),
          ('poc-in-github', 'PoC-in-GitHub CVE Repository Index', 'exploit', 'https://github.com/nomi-sec/PoC-in-GitHub', 'exploit-intel', '0 */12 * * *')
        on conflict (code) do update set
          name = excluded.name,
          kind = excluded.kind,
          homepage_url = excluded.homepage_url,
          plugin_name = excluded.plugin_name,
          schedule_cron = excluded.schedule_cron,
          updated_at = now()
        """,
        """
        update sources
        set enabled = false,
            schedule_cron = null,
            config_json = jsonb_set(config_json, '{runMode}', '"manual"', true),
            updated_at = now()
        where code = 'trickest-cve'
        """
    })
    {
        await using var cmd = db.CreateCommand(statement);
        await cmd.ExecuteNonQueryAsync();
    }
}

static async Task BackfillCvssScoresAsync(NpgsqlDataSource db)
{
    var updates = new List<(Guid Id, Guid VulnerabilityId, decimal Score, string Label)>();
    await using (var cmd = db.CreateCommand("""
        select id, vulnerability_id, vector_string, scoring_version
        from vulnerability_severity_scores
        where score is null
          and vector_string is not null
          and (
            vector_string like 'CVSS:3.%'
            or vector_string like 'CVSS:2.%'
            or scoring_version like '2%'
          )
        """))
    await using (var reader = await cmd.ExecuteReaderAsync())
    {
        while (await reader.ReadAsync())
        {
            var score = CvssScoreCalculator.CalculateBaseScore(
                reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetString(3));
            if (score is null) continue;
            updates.Add((
                reader.GetGuid(0),
                reader.GetGuid(1),
                score.Value,
                CvssSeverityLabel(score.Value, reader.IsDBNull(3) ? null : reader.GetString(3))));
        }
    }

    foreach (var chunk in updates.Chunk(500))
    {
        var rows = chunk.ToArray();
        await using var updateScores = db.CreateCommand("""
            update vulnerability_severity_scores score
            set score = incoming.score,
                severity_label = coalesce(score.severity_label, incoming.label),
                normalized_severity = coalesce(score.normalized_severity, lower(incoming.label)),
                updated_at = now()
            from unnest($1::uuid[], $2::numeric[], $3::text[]) as incoming(id, score, label)
            where score.id = incoming.id
              and score.score is null
            """);
        updateScores.Parameters.AddWithValue(rows.Select(row => row.Id).ToArray());
        updateScores.Parameters.AddWithValue(rows.Select(row => row.Score).ToArray());
        updateScores.Parameters.AddWithValue(rows.Select(row => row.Label).ToArray());
        await updateScores.ExecuteNonQueryAsync();

        await using var updateVulnerabilities = db.CreateCommand("""
            with ranked as (
              select distinct on (vulnerability_id)
                     vulnerability_id, score, scoring_version, vector_string, severity_label
              from vulnerability_severity_scores
              where vulnerability_id = any($1)
                and score is not null
              order by vulnerability_id, score desc, is_selected desc
            )
            update vulnerabilities vulnerability
            set max_cvss_version = case
                  when vulnerability.max_cvss_score is null or ranked.score > vulnerability.max_cvss_score then ranked.scoring_version
                  else vulnerability.max_cvss_version
                end,
                max_cvss_vector = case
                  when vulnerability.max_cvss_score is null or ranked.score > vulnerability.max_cvss_score then ranked.vector_string
                  else vulnerability.max_cvss_vector
                end,
                severity_label = case
                  when vulnerability.max_cvss_score is null or ranked.score > vulnerability.max_cvss_score then ranked.severity_label
                  else vulnerability.severity_label
                end,
                max_cvss_score = greatest(coalesce(vulnerability.max_cvss_score, ranked.score), ranked.score),
                updated_at = now()
            from ranked
            where vulnerability.id = ranked.vulnerability_id
            """);
        updateVulnerabilities.Parameters.AddWithValue(rows.Select(row => row.VulnerabilityId).Distinct().ToArray());
        await updateVulnerabilities.ExecuteNonQueryAsync();
    }

    if (updates.Count > 0)
        Console.WriteLine($"Backfilled {updates.Count} CVSS vector scores.");
}

static string CvssSeverityLabel(decimal score, string? version) =>
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

static int ClampPageSize(int pageSize) => pageSize <= 0 ? 25 : Math.Min(pageSize, 200);

static bool IsValidSourceCode(string sourceCode) =>
    !string.IsNullOrWhiteSpace(sourceCode) &&
    System.Text.RegularExpressions.Regex.IsMatch(sourceCode, "^[a-z0-9-]+$");

static string NormalizeVulnerabilitySort(string? sort) =>
    (sort ?? "").Trim().ToLowerInvariant() switch
    {
        "cvssdesc" or "cvss_desc" => "cvssDesc",
        "cvssasc" or "cvss_asc" => "cvssAsc",
        "publisheddesc" or "published_desc" => "publishedDesc",
        "publishedasc" or "published_asc" => "publishedAsc",
        "identifierasc" or "identifier_asc" => "identifierAsc",
        "identifierdesc" or "identifier_desc" => "identifierDesc",
        _ => "modifiedDesc"
    };

static string VulnerabilityOrderBy(string sort, string alias)
{
    var p = string.IsNullOrWhiteSpace(alias) ? "" : $"{alias}.";
    return sort switch
    {
        "cvssDesc" => $"coalesce({p}max_cvss_score, 0) desc, {p}modified_at desc nulls last, {p}primary_identifier desc",
        "cvssAsc" => $"coalesce({p}max_cvss_score, 0) asc, {p}modified_at desc nulls last, {p}primary_identifier desc",
        "publishedDesc" => $"{p}published_at desc nulls last, {p}primary_identifier desc",
        "publishedAsc" => $"{p}published_at asc nulls last, {p}primary_identifier asc",
        "identifierAsc" => $"{p}primary_identifier asc",
        "identifierDesc" => $"{p}primary_identifier desc",
        _ => $"{p}modified_at desc nulls last, {p}primary_identifier desc"
    };
}

static (string Start, string End)? TryGetCvePrefixRange(string query)
{
    if (string.IsNullOrWhiteSpace(query)) return null;
    var prefix = query.Trim().ToUpperInvariant();
    if (!System.Text.RegularExpressions.Regex.IsMatch(prefix, @"^CVE-\d{4}(?:-\d*)?$"))
        return null;
    return (prefix, NextPrefix(prefix));
}

static string NextPrefix(string prefix)
{
    var chars = prefix.ToCharArray();
    for (var i = chars.Length - 1; i >= 0; i--)
    {
        if (chars[i] == char.MaxValue) continue;
        chars[i]++;
        return new string(chars, 0, i + 1);
    }
    return prefix + char.MinValue;
}

static string ToNpgsqlConnectionString(string value)
{
    if (!value.StartsWith("postgres://", StringComparison.OrdinalIgnoreCase) &&
        !value.StartsWith("postgresql://", StringComparison.OrdinalIgnoreCase))
    {
        return value;
    }

    var uri = new Uri(value);
    var userInfo = uri.UserInfo.Split(':', 2);
    return new NpgsqlConnectionStringBuilder
    {
        Host = uri.Host,
        Port = uri.Port,
        Database = uri.AbsolutePath.TrimStart('/'),
        Username = Uri.UnescapeDataString(userInfo[0]),
        Password = userInfo.Length > 1 ? Uri.UnescapeDataString(userInfo[1]) : "",
        SslMode = SslMode.Disable
    }.ConnectionString;
}

static async Task<long> CountTableAsync(NpgsqlDataSource db, string tableName, CancellationToken ct)
{
    var allowed = new HashSet<string>(StringComparer.Ordinal)
    {
        "source_raw_index",
        "vulnerabilities",
        "vulnerability_records",
        "vulnerability_exploits",
        "vulnerability_affected_components",
        "components",
        "registry_packages",
        "cpe_entries"
    };
    if (!allowed.Contains(tableName)) throw new ArgumentOutOfRangeException(nameof(tableName), tableName, "Unexpected table name.");

    await using var cmd = db.CreateCommand($"select count(*) from {tableName}");
    return (long)(await cmd.ExecuteScalarAsync(ct) ?? 0L);
}

static async Task<IReadOnlyDictionary<string, long>> CountTablesAsync(NpgsqlDataSource db, IReadOnlyList<string> tableNames, CancellationToken ct)
{
    var rows = await Task.WhenAll(tableNames.Select(async tableName => new
    {
        TableName = tableName,
        Count = await CountTableAsync(db, tableName, ct)
    }));
    return rows.ToDictionary(x => x.TableName, x => x.Count, StringComparer.Ordinal);
}

static async Task<object> GetFastSystemStatusAsync(NpgsqlDataSource db, StatusCache cache, CancellationToken ct)
{
    var now = DateTimeOffset.UtcNow;
    if (cache.Value is not null && cache.ExpiresAt > now)
        return cache.Value;

    await cache.RefreshLock.WaitAsync(ct);
    try
    {
        now = DateTimeOffset.UtcNow;
        if (cache.Value is not null && cache.ExpiresAt > now)
            return cache.Value;

        var sourceStatus = new List<object>();
        var sourcePendingRows = new List<(string SourceCode, long Pending)>();
        var pendingBySource = new Dictionary<Guid, (long Pending, long Failed)>();
        var rawBySource = new Dictionary<Guid, long>();
        var tables = await EstimateTablesAsync(db, [
            "vulnerabilities",
            "vulnerability_records",
            "vulnerability_exploits",
            "vulnerability_affected_components",
            "components",
            "registry_packages",
            "cpe_entries",
            "source_raw_index"
        ], ct);

        await using (var rawSampleCmd = db.CreateCommand("""
            with sample_counts as (
              select source_id, count(*)::bigint as sample_count
              from source_raw_index tablesample system (0.5)
              group by source_id
            ),
            sample_total as (
              select coalesce(sum(sample_count), 0)::numeric as total_count
              from sample_counts
            )
            select source_id,
                   case when total_count > 0
                        then round(sample_count::numeric / total_count * $1)::bigint
                        else 0::bigint
                   end as raw_total
            from sample_counts, sample_total
            """))
        {
            rawSampleCmd.Parameters.AddWithValue(tables["source_raw_index"]);
            await using var rawSampleReader = await rawSampleCmd.ExecuteReaderAsync(ct);
            while (await rawSampleReader.ReadAsync(ct))
                rawBySource[rawSampleReader.GetGuid(0)] = rawSampleReader.GetInt64(1);
        }

        await using (var pendingCmd = db.CreateCommand("""
            select raw.source_id,
                   count(*) filter (where raw.normalize_status = 'pending') as normalize_pending,
                   count(*) filter (where raw.normalize_status = 'failed') as normalize_failed
            from source_raw_index raw
            join sources src on src.id = raw.source_id
            where raw.normalize_status in ('pending', 'failed')
              and src.enabled
              and coalesce(src.config_json->>'runMode', '') <> 'manual'
            group by raw.source_id
            """))
        await using (var pendingReader = await pendingCmd.ExecuteReaderAsync(ct))
        {
            while (await pendingReader.ReadAsync(ct))
            {
                var sourceId = pendingReader.GetGuid(0);
                pendingBySource[sourceId] = (pendingReader.GetInt64(1), pendingReader.GetInt64(2));
            }
        }

        long parsedTotal = 0;
        long errorTotal = 0;
        long normalizePendingTotal = 0;
        long normalizeFailedTotal = 0;
        await using (var cmd = db.CreateCommand("""
            with latest_runs as (
              select distinct on (source_id)
                     source_id, status, trigger, started_at, finished_at,
                     fetched_count, changed_count, parsed_count, normalized_count,
                     error_count, log_summary
              from source_sync_runs
              order by source_id, started_at desc
            ),
            successful_runs as (
              select source_id, max(finished_at) as last_success_at
              from source_sync_runs
              where status = 'succeeded'
              group by source_id
            ),
            successful_counts as (
              select source_id,
                     coalesce(sum(fetched_count), 0)::bigint as fetched_total,
                     coalesce(sum(parsed_count), 0)::bigint as parsed_total
              from source_sync_runs
              where status = 'succeeded'
              group by source_id
            )
            select s.code, s.name, s.kind, s.enabled, s.plugin_name, s.schedule_cron,
                   s.config_json->>'runMode' as run_mode, s.id,
                   lr.status, lr.trigger, lr.started_at, lr.finished_at,
                   coalesce(lr.fetched_count, 0), coalesce(lr.changed_count, 0),
                   coalesce(lr.parsed_count, 0), coalesce(lr.normalized_count, 0),
                   coalesce(lr.error_count, 0), lr.log_summary,
                   sr.last_success_at,
                   coalesce(sc.fetched_total, 0),
                   coalesce(sc.parsed_total, 0)
            from sources s
            left join latest_runs lr on lr.source_id = s.id
            left join successful_runs sr on sr.source_id = s.id
            left join successful_counts sc on sc.source_id = s.id
            order by s.enabled desc, s.kind, s.code
            """))
        await using (var reader = await cmd.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            {
                var fetched = reader.GetInt32(12);
                var parsed = reader.GetInt32(14);
                var errors = reader.GetInt32(16);
                var sourceId = reader.GetGuid(7);
                var pending = pendingBySource.GetValueOrDefault(sourceId);
                var rawTotal = rawBySource.GetValueOrDefault(sourceId);
                if (rawTotal == 0)
                    rawTotal = Math.Max(reader.GetInt64(19), reader.GetInt64(20));
                var normalizedEstimate = Math.Max(0L, rawTotal - pending.Pending - pending.Failed);
                parsedTotal += parsed;
                errorTotal += errors;
                normalizePendingTotal += pending.Pending;
                normalizeFailedTotal += pending.Failed;
                if (pending.Pending + pending.Failed > 0)
                    sourcePendingRows.Add((reader.GetString(0), pending.Pending + pending.Failed));
                sourceStatus.Add(new
                {
                    code = reader.GetString(0),
                    name = reader.GetString(1),
                    kind = reader.GetString(2),
                    enabled = reader.GetBoolean(3),
                    pluginName = reader.GetString(4),
                    scheduleCron = reader.IsDBNull(5) ? null : reader.GetString(5),
                    runMode = reader.IsDBNull(6) ? null : reader.GetString(6),
                    rawTotal,
                    parsePending = 0L,
                    parseSucceeded = parsed,
                    parseFailed = errors,
                    normalizePending = pending.Pending,
                    normalizeSucceeded = normalizedEstimate,
                    normalizeFailed = pending.Failed,
                    normalizeProgress = rawTotal <= 0 ? 0 : Math.Round((double)normalizedEstimate / rawTotal * 100, 2),
                    rawUpdatedAt = reader.IsDBNull(11) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(11),
                    latestRun = reader.IsDBNull(8) ? null : new
                    {
                        status = reader.GetString(8),
                        trigger = reader.IsDBNull(9) ? null : reader.GetString(9),
                        startedAt = reader.GetFieldValue<DateTimeOffset>(10),
                        finishedAt = reader.IsDBNull(11) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(11),
                        fetchedCount = fetched,
                        changedCount = reader.GetInt32(13),
                        parsedCount = parsed,
                        normalizedCount = normalizedEstimate,
                        errorCount = errors,
                        logSummary = reader.IsDBNull(17) ? null : reader.GetString(17)
                    },
                    lastSuccessAt = reader.IsDBNull(18) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(18)
                });
            }
        }

        var normalizedStatusEstimate = Math.Max(0L, tables["source_raw_index"] - normalizePendingTotal - normalizeFailedTotal);

        var status = new
        {
            vulnerabilities = tables["vulnerabilities"],
            vulnerabilityRecords = tables["vulnerability_records"],
            vulnerabilityExploits = tables["vulnerability_exploits"],
            affectedComponents = tables["vulnerability_affected_components"],
            components = tables["components"],
            registryPackages = tables["registry_packages"],
            cpeEntries = tables["cpe_entries"],
            sourceRawRecords = tables["source_raw_index"],
            sources = sourceStatus.Count,
            countsEstimated = true,
            parseStatus = new List<object>
            {
                new { status = "pending", count = 0L, estimated = true },
                new { status = "failed", count = errorTotal, estimated = true },
                new { status = "succeeded", count = parsedTotal, estimated = true }
            },
            normalizeStatus = new List<object>
            {
                new { status = "pending", count = normalizePendingTotal, estimated = true },
                new { status = "failed", count = normalizeFailedTotal, estimated = true },
                new { status = "succeeded", count = normalizedStatusEstimate, estimated = true }
            },
            pendingBySource = sourcePendingRows
                .OrderByDescending(x => x.Pending)
                .ThenBy(x => x.SourceCode, StringComparer.Ordinal)
                .Take(25)
                .Select(x => new { sourceCode = x.SourceCode, pending = x.Pending })
                .ToList<object>(),
            sourceStatus,
            generatedAt = DateTimeOffset.UtcNow
        };

        cache.Value = status;
        cache.ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(60);
        return status;
    }
    finally
    {
        cache.RefreshLock.Release();
    }
}

static async Task<IReadOnlyDictionary<string, long>> EstimateTablesAsync(NpgsqlDataSource db, IReadOnlyList<string> tableNames, CancellationToken ct)
{
    var values = tableNames.ToDictionary(x => x, _ => 0L, StringComparer.Ordinal);
    await using var cmd = db.CreateCommand("""
        select relname, greatest(reltuples::bigint, 0)
        from pg_class
        where relkind in ('r', 'p') and relname = any($1)
        """);
    cmd.Parameters.AddWithValue(tableNames.ToArray());
    await using var reader = await cmd.ExecuteReaderAsync(ct);
    while (await reader.ReadAsync(ct))
        values[reader.GetString(0)] = reader.GetInt64(1);
    return values;
}

static async Task<IReadOnlyList<Dictionary<string, object?>>> QueryRowsAsync(NpgsqlDataSource db, string sql, Guid id, CancellationToken ct)
{
    var rows = new List<Dictionary<string, object?>>();
    await using var cmd = db.CreateCommand(sql);
    cmd.Parameters.AddWithValue(id);
    await using var reader = await cmd.ExecuteReaderAsync(ct);
    while (await reader.ReadAsync(ct))
    {
        var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < reader.FieldCount; i++)
        {
            var name = reader.GetName(i);
            if (reader.IsDBNull(i))
            {
                row[name] = null;
                continue;
            }

            var value = reader.GetValue(i);
            row[name] = value switch
            {
                string text when (name.Contains("json", StringComparison.OrdinalIgnoreCase) || name == "source_specific" || name == "metadata_json") => JsonOrText(text),
                string[] array => array,
                DateTimeOffset dto => dto,
                DateTime dt => dt,
                _ => value
            };
        }
        rows.Add(row);
    }

    return rows;
}

static object? JsonOrText(string value) => JsonOrNull(value) ?? value;

static JsonNode? JsonOrNull(string value)
{
    try
    {
        return JsonNode.Parse(value);
    }
    catch
    {
        return null;
    }
}

static object MakeResult(NpgsqlDataReader reader) => new
{
    id = reader.GetGuid(0),
    primaryIdentifier = reader.GetString(1),
    title = reader.IsDBNull(2) ? null : reader.GetString(2),
    severityLabel = reader.IsDBNull(3) ? null : reader.GetString(3),
    maxCvssScore = reader.IsDBNull(4) ? (decimal?)null : reader.GetDecimal(4),
    affectedComponentCount = reader.GetInt32(5),
    affectedComponentNames = TruncateNames(reader.GetFieldValue<string[]>(6)),
    publishedAt = reader.IsDBNull(7) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(7),
    modifiedAt = reader.IsDBNull(8) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(8),
    identifiers = reader.GetFieldValue<string[]>(9),
    aliases = reader.GetFieldValue<string[]>(10)
};

static string[] TruncateNames(string[] names) =>
    names is { Length: > 15 } ? names[..15].Append($"+{names.Length - 15} more").ToArray() : names;

static (string Ecosystem, string? Version)? ParseEcosystemVersion(string query)
{
    if (string.IsNullOrWhiteSpace(query)) return null;
    var lower = query.ToLowerInvariant().Trim();

    var ecosystemKeywords = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["go"] = "go",
        ["golang"] = "go",
        ["npm"] = "npm",
        ["node"] = "npm",
        ["nodejs"] = "npm",
        ["pypi"] = "PyPI",
        ["pip"] = "PyPI",
        ["python"] = "PyPI",
        ["maven"] = "maven",
        ["java"] = "maven",
        ["nuget"] = "nuget",
        [".net"] = "nuget",
        ["dotnet"] = "nuget",
        ["cargo"] = "cargo",
        ["rust"] = "cargo",
        ["crates"] = "cargo",
        ["rubygems"] = "RubyGems",
        ["ruby"] = "RubyGems",
        ["gem"] = "RubyGems",
        ["packagist"] = "Packagist",
        ["php"] = "Packagist",
        ["composer"] = "Packagist",
        ["alpine"] = "alpine",
        ["debian"] = "debian",
        ["ubuntu"] = "ubuntu",
        ["rpm"] = "rpm",
        ["suse"] = "rpm",
        ["redhat"] = "rpm",
        ["rhel"] = "rpm",
        ["centos"] = "rpm"
    };

    var versionPattern = @"(\d+\.\d+(?:\.\d+)?(?:[-.]\w+)*)";
    var match = System.Text.RegularExpressions.Regex.Match(lower, versionPattern);
    var version = match.Success ? match.Groups[1].Value : null;

    string? foundEcosystem = null;
    foreach (var kv in ecosystemKeywords)
    {
        if (System.Text.RegularExpressions.Regex.IsMatch(lower, $@"\b{System.Text.RegularExpressions.Regex.Escape(kv.Key)}\b"))
        {
            foundEcosystem = kv.Value;
            break;
        }
    }

    if (foundEcosystem is null) return null;
    return (foundEcosystem, version);
}

sealed class StatusCache
{
    public object? Value { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public SemaphoreSlim RefreshLock { get; } = new(1, 1);
}

public partial class Program;
