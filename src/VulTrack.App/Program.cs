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
builder.Services.AddSingleton<IRawNormalizationService, RawNormalizationService>();
builder.Services.AddSingleton<ComponentVulnerabilitySearchService>();
builder.Services.AddSingleton<AdminAuthService>();
builder.Services.AddSingleton<SourceScheduler>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<SourceScheduler>());

var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/", () => Results.Redirect("/index.html"));

await EnsureRuntimeIndexesAsync(app.Services.GetRequiredService<NpgsqlDataSource>());

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
          select source_id,
                 count(*) as raw_total,
                 count(*) filter (where parse_status = 'pending') as parse_pending,
                 count(*) filter (where parse_status = 'succeeded') as parse_succeeded,
                 count(*) filter (where parse_status = 'failed') as parse_failed,
                 count(*) filter (where normalize_status = 'pending') as normalize_pending,
                 count(*) filter (where normalize_status = 'succeeded') as normalize_succeeded,
                 count(*) filter (where normalize_status = 'failed') as normalize_failed,
                 max(updated_at) as raw_updated_at
          from source_raw_index
          group by source_id
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

app.MapPost("/api/v1/vulnerability.search", async (NpgsqlDataSource db, VulnerabilitySearchRequest request, CancellationToken ct) =>
{
    var rows = new List<object>();
    var rawQuery = (request.Query ?? "").Trim();
    var pattern = $"%{rawQuery}%";
    var exact = string.IsNullOrWhiteSpace(rawQuery) ? "" : rawQuery;
    var normalizedExact = string.IsNullOrWhiteSpace(exact) ? "" : Identifier.Normalize(exact);
    var page = Math.Max(1, request.Page);
    var pageSize = ClampPageSize(request.PageSize);
    var fetchLimit = pageSize + 1;
    var offset = (page - 1) * pageSize;
    var sort = NormalizeVulnerabilitySort(request.Sort);
    var orderBy = VulnerabilityOrderBy(sort, "v");

    var ecosystemVersion = ParseEcosystemVersion(rawQuery);

    if (ecosystemVersion is not null)
    {
        await using var cmd = db.CreateCommand($"""
            select v.id, v.primary_identifier, v.title, v.severity_label, v.max_cvss_score,
                   v.affected_component_count, v.affected_component_names, v.published_at, v.modified_at
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
                matchedByEcosystem = true,
                matchedVersion = ecosystemVersion.Value.Version
            });
        }
    }
    else
    {
        var hasQuery = !string.IsNullOrWhiteSpace(rawQuery);
        if (hasQuery && !string.IsNullOrWhiteSpace(exact))
        {
            await using var fastCmd = db.CreateCommand($"""
                select v.id, v.primary_identifier, v.title, v.severity_label, v.max_cvss_score,
                       v.affected_component_count, v.affected_component_names, v.published_at, v.modified_at
                from vulnerabilities v
                where exists (
                    select 1 from vulnerability_identifier_index i
                    where i.canonical_vulnerability_id = v.id and i.normalized_value = $1
                )
                order by {orderBy}
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
            if (found > 0)
            {
                var exactHasMore = rows.Count > pageSize;
                if (exactHasMore) rows.RemoveAt(rows.Count - 1);
                return ApiResult.Ok(new { items = rows, page = 1, pageSize, sort, hasMore = exactHasMore });
            }
        }

        var cveRange = TryGetCvePrefixRange(rawQuery);
        await using var cmd = cveRange is not null
            ? db.CreateCommand($"""
                select v.id, v.primary_identifier, v.title, v.severity_label, v.max_cvss_score,
                       v.affected_component_count, v.affected_component_names, v.published_at, v.modified_at
                from vulnerabilities v
                where v.primary_identifier >= $1 and v.primary_identifier < $2
                order by {orderBy}
                limit $3 offset $4
                """)
            : hasQuery
            ? db.CreateCommand($"""
                select v.id, v.primary_identifier, v.title, v.severity_label, v.max_cvss_score,
                       v.affected_component_count, v.affected_component_names, v.published_at, v.modified_at
                from vulnerabilities v
                where ($1 = any(identifiers))
                   or (search_text @@ plainto_tsquery('simple', $3))
                   or (v.primary_identifier ilike $2)
                   or (v.title ilike $2)
                   or ($1 = any(affected_component_names))
                order by {orderBy}
                limit $4 offset $5
                """)
            : db.CreateCommand($"""
                select v.id, v.primary_identifier, v.title, v.severity_label, v.max_cvss_score,
                       v.affected_component_count, v.affected_component_names, v.published_at, v.modified_at
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
        select v.id, v.primary_identifier, v.title, v.description, v.severity_label, v.max_cvss_score
        from vulnerability_identifier_index i
        join vulnerabilities v on v.id = i.canonical_vulnerability_id
        where i.normalized_value = $1
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
        maxCvssScore = reader.IsDBNull(5) ? (decimal?)null : reader.GetDecimal(5)
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

app.MapGet("/api/v1/vulnerability.detail", async (NpgsqlDataSource db, Guid id, CancellationToken ct) =>
{
    await using var cmd = db.CreateCommand("""
        select id, primary_identifier, title, description, status, severity_label, max_cvss_score,
               max_cvss_version, max_cvss_vector, epss_score, epss_percentile, kev_date_added,
               known_ransomware, source_count, affected_component_count, affected_ecosystems,
               affected_component_names, identifiers, aliases, published_at, modified_at, updated_at
        from vulnerabilities
        where id = $1
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
        updatedAt = reader.GetFieldValue<DateTimeOffset>(21)
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
            limit 50
            """, queryId, ct),
        descriptions = await QueryRowsAsync(db, """
            select s.code, lang, description_type, left(value, 4000) as value, is_selected
            from vulnerability_descriptions d
            left join sources s on s.id = d.source_id
            where d.vulnerability_id = $1
            order by is_selected desc, s.code nulls last
            limit 10
            """, queryId, ct),
        severities = await QueryRowsAsync(db, """
            select s.code, scoring_system, scoring_version, score_type, vector_string,
                   score, severity_label, is_selected
            from vulnerability_severity_scores vss
            left join sources s on s.id = vss.source_id
            where vss.vulnerability_id = $1
            order by is_selected desc, score desc nulls last
            limit 10
            """, queryId, ct),
        references = await QueryRowsAsync(db, """
            with ranked as (
              select s.code, url, ref_type, tags,
                     row_number() over (partition by s.code order by url) as source_rank
              from vulnerability_references r
              left join sources s on s.id = r.source_id
              where r.vulnerability_id = $1
            )
            select code, url, ref_type, tags
            from ranked
            where source_rank <= 20
            order by code nulls last, source_rank, url
            limit 100
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
            limit 100
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
        select s.code, s.name, vr.source_record_id, left(vr.title, 200) as title, vr.updated_at
        from vulnerability_records vr
        join sources s on s.id = vr.source_id
        where vr.vulnerability_id = $1
        order by s.code, vr.updated_at desc
        limit 100
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
            updatedAt = r.GetFieldValue<DateTimeOffset>(4)
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
        "create index if not exists ix_raw_source_status_cover on source_raw_index(source_id) include(parse_status, normalize_status, updated_at)",
        "alter table if exists sbom_components alter column purl drop not null",
        "alter table if exists sbom_components add column if not exists vendor text",
        "alter table if exists sbom_components add column if not exists product text",
        "alter table if exists sbom_components add column if not exists cpe23_uri text",
        "alter table if exists sbom_components add column if not exists source_package_name text",
        "alter table if exists sbom_components add column if not exists source_package_version text",
        "alter table if exists sbom_vulnerabilities add column if not exists match_basis text",
        "alter table if exists sbom_vulnerabilities add column if not exists matched_version text",
        "create index if not exists ix_sbom_components_purl on sbom_components(purl) where purl is not null",
        "create index if not exists ix_sbom_components_cpe on sbom_components(cpe23_uri) where cpe23_uri is not null",
        "create index if not exists ix_affected_components_cpe_prefix on vulnerability_affected_components(primary_cpe23_uri text_pattern_ops, vulnerability_id) where primary_cpe23_uri is not null",
        """
        insert into sources (code, name, kind, homepage_url, plugin_name, schedule_cron)
        values
          ('exploitdb', 'Exploit-DB Public Exploits', 'exploit', 'https://www.exploit-db.com/', 'exploit-intel', '0 */12 * * *'),
          ('metasploit', 'Metasploit Framework Modules', 'exploit', 'https://github.com/rapid7/metasploit-framework', 'exploit-intel', '0 */12 * * *'),
          ('nuclei-templates', 'ProjectDiscovery Nuclei Templates', 'exploit', 'https://github.com/projectdiscovery/nuclei-templates', 'exploit-intel', '0 */12 * * *'),
          ('poc-in-github', 'PoC-in-GitHub CVE Repository Index', 'exploit', 'https://github.com/nomi-sec/PoC-in-GitHub', 'exploit-intel', '0 */12 * * *'),
          ('trickest-cve', 'Trickest CVE PoC Index', 'exploit', 'https://github.com/trickest/cve', 'exploit-intel', '0 */12 * * *')
        on conflict (code) do update set
          name = excluded.name,
          kind = excluded.kind,
          homepage_url = excluded.homepage_url,
          plugin_name = excluded.plugin_name,
          schedule_cron = excluded.schedule_cron,
          updated_at = now()
        """
    })
    {
        await using var cmd = db.CreateCommand(statement);
        await cmd.ExecuteNonQueryAsync();
    }
}

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
        await using (var pendingCmd = db.CreateCommand("""
            select source_id,
                   count(*) filter (where normalize_status = 'pending') as normalize_pending,
                   count(*) filter (where normalize_status = 'failed') as normalize_failed
            from source_raw_index
            where normalize_status <> 'succeeded'
            group by source_id
            """))
        await using (var pendingReader = await pendingCmd.ExecuteReaderAsync(ct))
        {
            while (await pendingReader.ReadAsync(ct))
                pendingBySource[pendingReader.GetGuid(0)] = (pendingReader.GetInt64(1), pendingReader.GetInt64(2));
        }

        long parsedTotal = 0;
        long normalizedTotal = 0;
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
            )
            select s.code, s.name, s.kind, s.enabled, s.plugin_name, s.schedule_cron,
                   s.config_json->>'runMode' as run_mode, s.id,
                   lr.status, lr.trigger, lr.started_at, lr.finished_at,
                   coalesce(lr.fetched_count, 0), coalesce(lr.changed_count, 0),
                   coalesce(lr.parsed_count, 0), coalesce(lr.normalized_count, 0),
                   coalesce(lr.error_count, 0), lr.log_summary,
                   sr.last_success_at
            from sources s
            left join latest_runs lr on lr.source_id = s.id
            left join successful_runs sr on sr.source_id = s.id
            order by s.enabled desc, s.kind, s.code
            """))
        await using (var reader = await cmd.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            {
                var fetched = reader.GetInt32(12);
                var parsed = reader.GetInt32(14);
                var normalized = reader.GetInt32(15);
                var errors = reader.GetInt32(16);
                var pending = pendingBySource.GetValueOrDefault(reader.GetGuid(7));
                parsedTotal += parsed;
                normalizedTotal += normalized;
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
                    rawTotal = fetched,
                    parsePending = 0L,
                    parseSucceeded = parsed,
                    parseFailed = errors,
                    normalizePending = pending.Pending,
                    normalizeSucceeded = normalized,
                    normalizeFailed = pending.Failed,
                    normalizeProgress = fetched <= 0 ? 0 : Math.Round((double)normalized / fetched * 100, 2),
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
                        normalizedCount = normalized,
                        errorCount = errors,
                        logSummary = reader.IsDBNull(17) ? null : reader.GetString(17)
                    },
                    lastSuccessAt = reader.IsDBNull(18) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(18)
                });
            }
        }

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
                new { status = "pending", count = normalizePendingTotal, estimated = false },
                new { status = "failed", count = normalizeFailedTotal, estimated = false },
                new { status = "succeeded", count = normalizedTotal, estimated = true }
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
    modifiedAt = reader.IsDBNull(8) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(8)
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
