using System.Text.Json.Nodes;
using Npgsql;
using VulTrack.App;

var builder = WebApplication.CreateBuilder(args);

var databaseUrl = Environment.GetEnvironmentVariable("DATABASE_URL")
    ?? builder.Configuration.GetConnectionString("Default")
    ?? "Host=localhost;Port=5432;Database=vultrack;Username=vultrack;Password=vultrack";

builder.Services.AddSingleton(NpgsqlDataSource.Create(ToNpgsqlConnectionString(databaseUrl)));
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
builder.Services.AddSingleton<IRawNormalizer, DistroRawNormalizer>();
builder.Services.AddSingleton<IRawNormalizer, ComponentCatalogNormalizer>();
builder.Services.AddSingleton<IRawNormalizationService, RawNormalizationService>();
builder.Services.AddSingleton<ComponentVulnerabilitySearchService>();
builder.Services.AddSingleton<SourceScheduler>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<SourceScheduler>());

var app = builder.Build();

app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/", () => Results.Redirect("/index.html"));

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

app.MapGet("/api/v1/system.status", async (NpgsqlDataSource db, CancellationToken ct) =>
{
    var normalizeStatus = new List<object>();
    var nonSucceededRaw = 0L;
    await using (var cmd = db.CreateCommand("""
        select normalize_status, count(*)
        from source_raw_index
        where normalize_status <> 'succeeded'
        group by normalize_status
        order by normalize_status
        """))
    await using (var reader = await cmd.ExecuteReaderAsync(ct))
    {
        while (await reader.ReadAsync(ct))
        {
            var count = reader.GetInt64(1);
            nonSucceededRaw += count;
            normalizeStatus.Add(new { status = reader.GetString(0), count });
        }
    }

    var totalRaw = await EstimateTableCountAsync(db, "source_raw_index", ct);
    normalizeStatus.Add(new { status = "succeeded", count = Math.Max(0, totalRaw - nonSucceededRaw), estimated = true });

    var pendingBySource = new List<object>();
    await using (var cmd = db.CreateCommand("""
        select s.code, count(*)
        from source_raw_index r
        join sources s on s.id = r.source_id
        where r.normalize_status <> 'succeeded'
        group by s.code
        order by count(*) desc, s.code
        limit 25
        """))
    await using (var reader = await cmd.ExecuteReaderAsync(ct))
    {
        while (await reader.ReadAsync(ct))
        {
            pendingBySource.Add(new { sourceCode = reader.GetString(0), pending = reader.GetInt64(1) });
        }
    }

    var totals = await EstimateTableCountsAsync(db, [
        "vulnerabilities",
        "vulnerability_records",
        "vulnerability_affected_components",
        "components",
        "registry_packages",
        "cpe_entries"
    ], ct);

    return ApiResult.Ok(new
    {
        vulnerabilities = totals["vulnerabilities"],
        vulnerabilityRecords = totals["vulnerability_records"],
        affectedComponents = totals["vulnerability_affected_components"],
        components = totals["components"],
        registryPackages = totals["registry_packages"],
        cpeEntries = totals["cpe_entries"],
        countsEstimated = true,
        normalizeStatus,
        pendingBySource
    });
});

app.MapPost("/api/v1/nvd.processPending", async (NvdRawProcessor processor, ProcessPendingRequest request, CancellationToken ct) =>
{
    var result = await processor.ProcessPendingAsync(request.Limit <= 0 ? 100 : request.Limit, ct);
    return ApiResult.Ok(result);
});

app.MapPost("/api/v1/raw.normalizePending", async (IRawNormalizationService processor, NormalizePendingRequest request, CancellationToken ct) =>
{
    var result = await processor.ProcessPendingAsync(request.LimitPerSource <= 0 ? 100 : request.LimitPerSource, ct);
    return ApiResult.Ok(result);
});

app.MapPost("/api/v1/raw.normalizeSource", async (IRawNormalizationService processor, NormalizeSourceRequest request, CancellationToken ct) =>
{
    var limit = request.Limit <= 0 ? 100 : request.Limit;
    var result = await processor.ProcessSourcePendingAsync(request.SourceCode, limit, ct);
    return ApiResult.Ok(result);
});

app.MapPost("/api/v1/vulnerability.search", async (NpgsqlDataSource db, VulnerabilitySearchRequest request, CancellationToken ct) =>
{
    var rows = new List<object>();
    var rawQuery = (request.Query ?? "").Trim();
    var pattern = $"%{rawQuery}%";
    var exact = string.IsNullOrWhiteSpace(rawQuery) ? "" : rawQuery;

    var ecosystemVersion = ParseEcosystemVersion(rawQuery);

    if (ecosystemVersion is not null)
    {
        await using var cmd = db.CreateCommand("""
            select v.id, v.primary_identifier, v.title, v.severity_label, v.max_cvss_score,
                   v.affected_component_count, v.affected_component_names, v.published_at, v.modified_at
            from vulnerabilities v
            where v.id in (
                select c.vulnerability_id
                from vulnerability_affected_components c
                where lower(c.ecosystem) = lower($1)
                  and (c.display_name is not null or c.package_name is not null)
            )
            order by coalesce(v.max_cvss_score, 0) desc, v.modified_at desc nulls last
            limit $2
            """);
        cmd.Parameters.AddWithValue(ecosystemVersion.Value.Ecosystem);
        cmd.Parameters.AddWithValue(request.PageSize <= 0 ? 50 : Math.Min(request.PageSize, 200));
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
            await using var fastCmd = db.CreateCommand("""
                select v.id, v.primary_identifier, v.title, v.severity_label, v.max_cvss_score,
                       v.affected_component_count, v.affected_component_names, v.published_at, v.modified_at
                from vulnerability_identifier_index i
                join vulnerabilities v on v.id = i.canonical_vulnerability_id
                where i.normalized_value = $1
                order by coalesce(v.max_cvss_score, 0) desc
                limit $2
                """);
            fastCmd.Parameters.AddWithValue(exact);
            fastCmd.Parameters.AddWithValue(request.PageSize <= 0 ? 50 : Math.Min(request.PageSize, 200));
            await using var fastReader = await fastCmd.ExecuteReaderAsync(ct);
            var found = 0;
            while (await fastReader.ReadAsync(ct))
            {
                rows.Add(MakeResult(fastReader));
                found++;
            }
            if (found > 0)
            {
                return ApiResult.Ok(new { items = rows, page = 1, pageSize = request.PageSize <= 0 ? 50 : request.PageSize });
            }
        }

        await using var cmd = hasQuery
            ? db.CreateCommand("""
                select id, primary_identifier, title, severity_label, max_cvss_score,
                       affected_component_count, affected_component_names, published_at, modified_at
                from vulnerabilities
                where ($1 = any(identifiers))
                   or (search_text @@ plainto_tsquery('simple', $3))
                   or (primary_identifier ilike $2)
                   or (title ilike $2)
                   or ($1 = any(affected_component_names))
                order by coalesce(max_cvss_score, 0) desc, modified_at desc nulls last
                limit $4
                """)
            : db.CreateCommand("""
                select v.id, v.primary_identifier, v.title, v.severity_label, v.max_cvss_score,
                       v.affected_component_count, v.affected_component_names, v.published_at, v.modified_at
                from vulnerabilities v
                inner join (select id from vulnerabilities order by modified_at desc nulls last limit $4) t on t.id = v.id
                order by v.modified_at desc nulls last
                """);
        cmd.Parameters.AddWithValue(exact);
        cmd.Parameters.AddWithValue(pattern);
        cmd.Parameters.AddWithValue(rawQuery);
        cmd.Parameters.AddWithValue(request.PageSize <= 0 ? 50 : Math.Min(request.PageSize, 200));
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            rows.Add(MakeResult(reader));
        }
    }

    return ApiResult.Ok(new { items = rows, page = 1, pageSize = request.PageSize <= 0 ? 50 : request.PageSize });
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

    return ApiResult.Ok(new
    {
        vulnerability,
        identifiers = await QueryRowsAsync(db, """
            select i.identifier_type, i.identifier_value, i.normalized_value, i.evidence_strength,
                   i.confidence, s.code
            from vulnerability_identifier_index i
            left join sources s on s.id = i.source_id
            where i.canonical_vulnerability_id = $1
            order by i.identifier_type, i.identifier_value
            limit 50
            """, id, ct),
        records = await QueryRowsAsync(db, """
            select vr.id::text, s.code, s.name, vr.source_record_id, vr.title, vr.description,
                   vr.status, vr.confidence, left(vr.source_specific::text, 2000) as source_specific, vr.updated_at
            from vulnerability_records vr
            join sources s on s.id = vr.source_id
            where vr.vulnerability_id = $1
            order by s.code, vr.updated_at desc
            limit 50
            """, id, ct),
        affectedComponents = await QueryRowsAsync(db, """
            select ecosystem, package_name, display_name, primary_purl, primary_cpe23_uri,
                   normalized_range, range_type, confidence, evidence_count, resolution_status
            from vulnerability_affected_components
            where vulnerability_id = $1
            order by ecosystem nulls last, display_name
            limit 50
            """, id, ct),
        affectedFacts = await QueryRowsAsync(db, """
            select s.code, fact_type, ecosystem, package_name, purl, cpe23_uri,
                   version_range_raw, range_type, vulnerable, left(source_specific::text, 500) as source_specific
            from vulnerability_affected_facts f
            left join sources s on s.id = f.source_id
            where f.vulnerability_id = $1
            order by s.code, ecosystem nulls last, package_name nulls last
            limit 100
            """, id, ct),
        descriptions = await QueryRowsAsync(db, """
            select s.code, lang, description_type, left(value, 2000) as value, is_selected
            from vulnerability_descriptions d
            left join sources s on s.id = d.source_id
            where d.vulnerability_id = $1
            order by is_selected desc, s.code nulls last
            limit 30
            """, id, ct),
        severities = await QueryRowsAsync(db, """
            select s.code, scoring_system, scoring_version, score_type, vector_string,
                   score, severity_label, is_selected
            from vulnerability_severity_scores vss
            left join sources s on s.id = vss.source_id
            where vss.vulnerability_id = $1
            order by is_selected desc, score desc nulls last
            limit 30
            """, id, ct),
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
            """, id, ct)
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
app.Run();

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

static async Task<long> EstimateTableCountAsync(NpgsqlDataSource db, string tableName, CancellationToken ct)
{
    await using var cmd = db.CreateCommand("""
        select greatest(reltuples, 0)::bigint
        from pg_class
        where relname = $1
        """);
    cmd.Parameters.AddWithValue(tableName);
    return (long)(await cmd.ExecuteScalarAsync(ct) ?? 0L);
}

static async Task<IReadOnlyDictionary<string, long>> EstimateTableCountsAsync(NpgsqlDataSource db, IReadOnlyList<string> tableNames, CancellationToken ct)
{
    var estimates = tableNames.ToDictionary(x => x, _ => 0L, StringComparer.Ordinal);
    await using var cmd = db.CreateCommand("""
        select relname, greatest(reltuples, 0)::bigint
        from pg_class
        where relname = any($1)
        """);
    cmd.Parameters.AddWithValue(tableNames.ToArray());
    await using var reader = await cmd.ExecuteReaderAsync(ct);
    while (await reader.ReadAsync(ct))
    {
        estimates[reader.GetString(0)] = reader.GetInt64(1);
    }

    return estimates;
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

static string? PurlStripVersion(string purl) => purl.Contains('@') && purl.LastIndexOf('@') > "pkg:".Length ? purl[..purl.LastIndexOf('@')] : purl;

static string? EcosystemFromCyclonePurl(string? purl) => purl?.StartsWith("pkg:", StringComparison.OrdinalIgnoreCase) == true
    ? purl["pkg:".Length..purl.IndexOf('/')].ToLowerInvariant()
    : null;

static string? MapEcosystem(string? eco) => eco?.ToLowerInvariant() switch
{
    "deb" => "debian",
    "rpm" or "redhat" or "suse" => "rpm",
    null => null,
    var x => x
};

static async Task InsertSbomVuln(NpgsqlDataSource db, Guid cid, string purl, NpgsqlDataReader sr, string? ver, CancellationToken ct)
{
    var range = sr.IsDBNull(7) ? null : sr.GetString(7);
    var vm = ver is not null && range is not null ? VersionRangeMatcher.Matches(ver, range) : (bool?)null;
    await using var ins = db.CreateCommand("INSERT INTO sbom_vulnerabilities(sbom_component_id,vulnerability_id,purl,display_name,ecosystem,normalized_range,version_matched) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(sbom_component_id,vulnerability_id,COALESCE(normalized_range,'')) DO NOTHING");
    ins.Parameters.AddWithValue(cid); ins.Parameters.AddWithValue(sr.GetGuid(0)); ins.Parameters.AddWithValue(purl);
    ins.Parameters.AddWithValue((object?)sr.GetValue(6) ?? DBNull.Value); ins.Parameters.AddWithValue((object?)sr.GetValue(5) ?? DBNull.Value);
    ins.Parameters.AddWithValue((object?)sr.GetValue(7) ?? DBNull.Value); ins.Parameters.AddWithValue((object?)vm ?? DBNull.Value);
    await ins.ExecuteNonQueryAsync(ct);
}

static (string Ecosystem, string? Version)? ParseEcosystemVersion(string query)
{
    if (string.IsNullOrWhiteSpace(query)) return null;
    var lower = query.ToLowerInvariant().Trim();

    var ecosystemKeywords = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["go"] = "go", ["golang"] = "go",
        ["npm"] = "npm", ["node"] = "npm", ["nodejs"] = "npm",
        ["pypi"] = "PyPI", ["pip"] = "PyPI", ["python"] = "PyPI",
        ["maven"] = "maven", ["java"] = "maven",
        ["nuget"] = "nuget", [".net"] = "nuget", ["dotnet"] = "nuget",
        ["cargo"] = "cargo", ["rust"] = "cargo", ["crates"] = "cargo",
        ["rubygems"] = "RubyGems", ["ruby"] = "RubyGems", ["gem"] = "RubyGems",
        ["packagist"] = "Packagist", ["php"] = "Packagist", ["composer"] = "Packagist",
        ["alpine"] = "alpine",
        ["debian"] = "debian",
        ["ubuntu"] = "ubuntu",
        ["rpm"] = "rpm", ["suse"] = "rpm", ["redhat"] = "rpm", ["rhel"] = "rpm", ["centos"] = "rpm"
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

public partial class Program;
