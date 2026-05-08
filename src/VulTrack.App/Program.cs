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
builder.Services.AddSingleton<IRawNormalizationService, RawNormalizationService>();
builder.Services.AddSingleton<ComponentVulnerabilitySearchService>();
builder.Services.AddSingleton<SourceScheduler>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<SourceScheduler>());

var app = builder.Build();

app.MapGet("/", () => Results.Redirect("/api/v1/system.health"));

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

app.MapPost("/api/v1/vulnerability.search", async (NpgsqlDataSource db, VulnerabilitySearchRequest request, CancellationToken ct) =>
{
    var rows = new List<object>();
    var query = $"%{request.Query ?? ""}%";
    await using var cmd = db.CreateCommand("""
        select id, primary_identifier, title, severity_label, max_cvss_score,
               affected_component_count, affected_component_names, published_at, modified_at
        from vulnerabilities
        where ($1 = '%%' or primary_identifier ilike $1 or title ilike $1 or $2 = any(identifiers))
        order by coalesce(max_cvss_score, 0) desc, modified_at desc nulls last
        limit $3
        """);
    cmd.Parameters.AddWithValue(query);
    cmd.Parameters.AddWithValue(request.Query ?? "");
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
            affectedComponentNames = reader.GetFieldValue<string[]>(6),
            publishedAt = reader.IsDBNull(7) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(7),
            modifiedAt = reader.IsDBNull(8) ? (DateTimeOffset?)null : reader.GetFieldValue<DateTimeOffset>(8)
        });
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

app.MapPost("/api/v1/component.vulnerabilitySearch", async (ComponentVulnerabilitySearchService search, ComponentVulnerabilitySearchRequest request, CancellationToken ct) =>
{
    var result = await search.SearchAsync(request, ct);
    return ApiResult.Ok(result);
});

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

public partial class Program;
