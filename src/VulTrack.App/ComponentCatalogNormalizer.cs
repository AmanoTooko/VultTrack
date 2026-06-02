using Npgsql;

namespace VulTrack.App;

public sealed class ComponentCatalogNormalizer : ISourceScopedRawNormalizer
{
    public string SourceCode => "component-catalog";
    public IReadOnlySet<string> SupportedSourceCodes { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "nvd-cpe",
        "npm-registry",
        "nuget-registry",
        "maven-registry",
        "pypi-registry",
        "crates-registry",
        "rubygems-registry",
        "packagist-registry"
    };

    public async Task<NormalizeBatchResult> ProcessPendingAsync(NpgsqlConnection connection, int limit, CancellationToken ct)
    {
        var normalizedLimit = Math.Max(1, limit);
        var cpeLimit = Math.Max(1, normalizedLimit / 2);
        var registryLimit = Math.Max(1, normalizedLimit - cpeLimit);

        var cpe = await ProcessCpeAsync(connection, cpeLimit, ct);
        var registry = await ProcessRegistryAsync(connection, registryLimit + Math.Max(0, cpeLimit - cpe.Processed), ct);

        return new NormalizeBatchResult(SourceCode, cpe.Processed + registry.Processed, cpe.Failed + registry.Failed);
    }

    public Task<NormalizeBatchResult> ProcessSourcePendingAsync(NpgsqlConnection connection, string sourceCode, int limit, CancellationToken ct)
    {
        if (string.Equals(sourceCode, "nvd-cpe", StringComparison.OrdinalIgnoreCase))
        {
            return ProcessCpeAsync(connection, Math.Max(1, limit), ct);
        }

        if (!SupportedSourceCodes.Contains(sourceCode))
        {
            return Task.FromResult(new NormalizeBatchResult(sourceCode, 0, 0));
        }

        return ProcessRegistrySourceAsync(connection, sourceCode, Math.Max(1, limit), ct);
    }

    private static async Task<NormalizeBatchResult> ProcessCpeAsync(NpgsqlConnection connection, int limit, CancellationToken ct)
    {
        await using var select = new NpgsqlCommand("""
            select s.raw_index_id, s.cpe23_uri, s.part, s.vendor, s.product, s.version, s.target_sw,
                   s.titles::text, s.refs::text, s.deprecated, s.last_modified_at, r.source_id
            from stg_nvd_cpe_dictionary s
            join source_raw_index r on r.id = s.raw_index_id
            where r.normalize_status in ('pending', 'failed')
            order by s.cpe23_uri
            limit $1
            """, connection);
        select.Parameters.AddWithValue(Math.Max(1, limit));

        var rows = new List<CpeRow>();
        await using (var reader = await select.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            {
                rows.Add(new CpeRow(
                    reader.GetGuid(0),
                    reader.GetString(1),
                    reader.IsDBNull(2) ? null : reader.GetString(2),
                    reader.IsDBNull(3) ? null : reader.GetString(3),
                    reader.IsDBNull(4) ? null : reader.GetString(4),
                    reader.IsDBNull(5) ? null : reader.GetString(5),
                    reader.IsDBNull(6) ? null : reader.GetString(6),
                    reader.GetString(7),
                    reader.GetString(8),
                    reader.GetBoolean(9),
                    reader.IsDBNull(10) ? null : reader.GetFieldValue<DateTimeOffset>(10),
                    reader.GetGuid(11)));
            }
        }

        var processed = 0;
        var failed = 0;
        foreach (var row in rows)
        {
            try
            {
                await UpsertCpeEntryAsync(connection, row, ct);
                var componentId = await UpsertCpeComponentAsync(connection, row, ct);
                await UpsertIdentityAsync(connection, componentId, "cpe23", row.Cpe23Uri, row.Cpe23Uri, null, row.SourceId, "nvd-cpe-dictionary", 1.0m, ct);

                var vendorProduct = JoinIdentity(row.Vendor, row.Product);
                if (vendorProduct is not null)
                {
                    await UpsertIdentityAsync(connection, componentId, "cpe-vendor-product", vendorProduct, vendorProduct, null, row.SourceId, "nvd-cpe-dictionary", 0.9m, ct);
                }

                await MarkNormalizedAsync(connection, row.RawIndexId, ct);
                processed++;
            }
            catch
            {
                failed++;
            }
        }

        return new NormalizeBatchResult("nvd-cpe", processed, failed);
    }

    private static async Task<NormalizeBatchResult> ProcessRegistryAsync(NpgsqlConnection connection, int limit, CancellationToken ct)
    {
        await using var select = new NpgsqlCommand("""
            select s.raw_index_id, s.registry, s.ecosystem, s.namespace, s.name, s.version, s.purl,
                   s.repository_url, s.homepage_url, s.metadata::text, r.source_id
            from stg_registry_packages s
            join source_raw_index r on r.id = s.raw_index_id
            where r.normalize_status in ('pending', 'failed')
            order by s.ecosystem, s.namespace, s.name
            limit $1
            """, connection);
        select.Parameters.AddWithValue(Math.Max(1, limit));

        var rows = new List<RegistryRow>();
        await using (var reader = await select.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            {
                rows.Add(new RegistryRow(
                    reader.GetGuid(0),
                    reader.GetString(1),
                    reader.GetString(2),
                    reader.IsDBNull(3) ? null : reader.GetString(3),
                    reader.GetString(4),
                    reader.IsDBNull(5) ? null : reader.GetString(5),
                    reader.IsDBNull(6) ? null : reader.GetString(6),
                    reader.IsDBNull(7) ? null : reader.GetString(7),
                    reader.IsDBNull(8) ? null : reader.GetString(8),
                    reader.GetString(9),
                    reader.GetGuid(10)));
            }
        }

        var processed = 0;
        var failed = 0;
        foreach (var row in rows)
        {
            try
            {
                await UpsertRegistryPackageAsync(connection, row, ct);
                var componentId = await UpsertPackageComponentAsync(connection, row, ct);
                var packageIdentity = PackageIdentity(row.Namespace, row.Name);
                await UpsertIdentityAsync(connection, componentId, "package-name", packageIdentity, packageIdentity, row.Ecosystem, row.SourceId, "registry", 0.9m, ct);

                var purlWithoutVersion = PurlWithoutVersion(row.Purl);
                if (purlWithoutVersion is not null)
                {
                    await UpsertIdentityAsync(connection, componentId, "purl", purlWithoutVersion, purlWithoutVersion, row.Ecosystem, row.SourceId, "registry", 1.0m, ct);
                }

                await MarkNormalizedAsync(connection, row.RawIndexId, ct);
                processed++;
            }
            catch
            {
                failed++;
            }
        }

        return new NormalizeBatchResult("registry-packages", processed, failed);
    }

    private async Task<NormalizeBatchResult> ProcessRegistrySourceAsync(NpgsqlConnection connection, string sourceCode, int limit, CancellationToken ct)
    {
        await using var select = new NpgsqlCommand("""
            select s.raw_index_id, s.registry, s.ecosystem, s.namespace, s.name, s.version, s.purl,
                   s.repository_url, s.homepage_url, s.metadata::text, r.source_id
            from stg_registry_packages s
            join source_raw_index r on r.id = s.raw_index_id
            join sources src on src.id = r.source_id
            where r.normalize_status in ('pending', 'failed') and src.code = $1
            order by s.ecosystem, s.namespace, s.name
            limit $2
            """, connection);
        select.Parameters.AddWithValue(sourceCode);
        select.Parameters.AddWithValue(limit);

        var rows = new List<RegistryRow>();
        await using (var reader = await select.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            {
                rows.Add(new RegistryRow(
                    reader.GetGuid(0),
                    reader.GetString(1),
                    reader.GetString(2),
                    reader.IsDBNull(3) ? null : reader.GetString(3),
                    reader.GetString(4),
                    reader.IsDBNull(5) ? null : reader.GetString(5),
                    reader.IsDBNull(6) ? null : reader.GetString(6),
                    reader.IsDBNull(7) ? null : reader.GetString(7),
                    reader.IsDBNull(8) ? null : reader.GetString(8),
                    reader.GetString(9),
                    reader.GetGuid(10)));
            }
        }

        var processed = 0;
        var failed = 0;
        foreach (var row in rows)
        {
            try
            {
                await UpsertRegistryPackageAsync(connection, row, ct);
                var componentId = await UpsertPackageComponentAsync(connection, row, ct);
                var packageIdentity = PackageIdentity(row.Namespace, row.Name);
                await UpsertIdentityAsync(connection, componentId, "package-name", packageIdentity, packageIdentity, row.Ecosystem, row.SourceId, "registry", 0.9m, ct);

                var purlWithoutVersion = PurlWithoutVersion(row.Purl);
                if (purlWithoutVersion is not null)
                {
                    await UpsertIdentityAsync(connection, componentId, "purl", purlWithoutVersion, purlWithoutVersion, row.Ecosystem, row.SourceId, "registry", 1.0m, ct);
                }

                await MarkNormalizedAsync(connection, row.RawIndexId, ct);
                processed++;
            }
            catch
            {
                failed++;
            }
        }

        return new NormalizeBatchResult(sourceCode, processed, failed);
    }

    private static async Task UpsertCpeEntryAsync(NpgsqlConnection connection, CpeRow row, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("""
            insert into cpe_entries
              (cpe23_uri, part, vendor, product, version, target_sw, titles_json, refs_json, deprecated, last_modified_at)
            values ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9,$10)
            on conflict (cpe23_uri) do update set
              part = excluded.part,
              vendor = excluded.vendor,
              product = excluded.product,
              version = excluded.version,
              target_sw = excluded.target_sw,
              titles_json = excluded.titles_json,
              refs_json = excluded.refs_json,
              deprecated = excluded.deprecated,
              last_modified_at = excluded.last_modified_at
            """, connection);
        cmd.Parameters.AddWithValue(row.Cpe23Uri);
        cmd.Parameters.AddWithValue((object?)row.Part ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)row.Vendor ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)row.Product ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)row.Version ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)row.TargetSw ?? DBNull.Value);
        cmd.Parameters.AddWithValue(row.TitlesJson);
        cmd.Parameters.AddWithValue(row.RefsJson);
        cmd.Parameters.AddWithValue(row.Deprecated);
        cmd.Parameters.AddWithValue((object?)row.LastModifiedAt ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static async Task<Guid> UpsertCpeComponentAsync(NpgsqlConnection connection, CpeRow row, CancellationToken ct)
    {
        var componentKey = $"cpe:{row.Part ?? "*"}:{row.Vendor ?? "*"}:{row.Product ?? "*"}:{row.TargetSw ?? "*"}".ToLowerInvariant();
        var canonicalName = DisplayName(row.Vendor, row.Product);
        await using var cmd = new NpgsqlCommand("""
            insert into components
              (component_key, canonical_name, component_type, primary_cpe23_uri, identities)
            values ($1,$2,$3,$4,$5)
            on conflict (component_key) do update set
              canonical_name = excluded.canonical_name,
              primary_cpe23_uri = coalesce(components.primary_cpe23_uri, excluded.primary_cpe23_uri),
              identities = (select array_agg(distinct value) from unnest(components.identities || excluded.identities) value),
              updated_at = now()
            returning id
            """, connection);
        cmd.Parameters.AddWithValue(componentKey);
        cmd.Parameters.AddWithValue(canonicalName);
        cmd.Parameters.AddWithValue(CpePartToType(row.Part));
        cmd.Parameters.AddWithValue(row.Cpe23Uri);
        cmd.Parameters.AddWithValue(new[] { row.Cpe23Uri, componentKey });
        return (Guid)(await cmd.ExecuteScalarAsync(ct))!;
    }

    private static async Task UpsertRegistryPackageAsync(NpgsqlConnection connection, RegistryRow row, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("""
            with updated as (
              update registry_packages
              set latest_version = coalesce($5, latest_version),
                  purl_without_version = coalesce($6, purl_without_version),
                  repository_url = coalesce($7, repository_url),
                  homepage_url = coalesce($8, homepage_url),
                  metadata_json = $9::jsonb,
                  last_seen_at = now()
              where ecosystem = $1 and coalesce(namespace, '') = coalesce($3, '') and lower(name) = lower($4)
              returning id
            ), inserted as (
              insert into registry_packages
                (ecosystem, registry_url, namespace, name, normalized_name, purl_type, purl_without_version,
                 latest_version, repository_url, homepage_url, metadata_json)
              select $1,$2,$3,$4,lower($4),$10,$6,$5,$7,$8,$9::jsonb
              where not exists (select 1 from updated)
              returning id
            )
            select id from updated
            union all
            select id from inserted
            limit 1
            """, connection);
        cmd.Parameters.AddWithValue(row.Ecosystem);
        cmd.Parameters.AddWithValue(row.Registry);
        cmd.Parameters.AddWithValue((object?)row.Namespace ?? DBNull.Value);
        cmd.Parameters.AddWithValue(row.Name);
        cmd.Parameters.AddWithValue((object?)row.Version ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)PurlWithoutVersion(row.Purl) ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)row.RepositoryUrl ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)row.HomepageUrl ?? DBNull.Value);
        cmd.Parameters.AddWithValue(row.MetadataJson);
        cmd.Parameters.AddWithValue((object?)PurlType(row.Purl) ?? DBNull.Value);
        await cmd.ExecuteScalarAsync(ct);
    }

    private static async Task<Guid> UpsertPackageComponentAsync(NpgsqlConnection connection, RegistryRow row, CancellationToken ct)
    {
        var purlWithoutVersion = PurlWithoutVersion(row.Purl);
        var componentKey = (purlWithoutVersion ?? $"pkg:{row.Ecosystem}/{PackageIdentity(row.Namespace, row.Name)}").ToLowerInvariant();
        var displayName = PackageIdentity(row.Namespace, row.Name);
        await using var cmd = new NpgsqlCommand("""
            insert into components
              (component_key, canonical_name, component_type, primary_purl, primary_repository_url, identities)
            values ($1,$2,'package',$3,$4,$5)
            on conflict (component_key) do update set
              canonical_name = excluded.canonical_name,
              primary_purl = coalesce(components.primary_purl, excluded.primary_purl),
              primary_repository_url = coalesce(excluded.primary_repository_url, components.primary_repository_url),
              identities = (select array_agg(distinct value) from unnest(components.identities || excluded.identities) value),
              updated_at = now()
            returning id
            """, connection);
        cmd.Parameters.AddWithValue(componentKey);
        cmd.Parameters.AddWithValue(displayName);
        cmd.Parameters.AddWithValue((object?)purlWithoutVersion ?? DBNull.Value);
        cmd.Parameters.AddWithValue((object?)row.RepositoryUrl ?? DBNull.Value);
        cmd.Parameters.AddWithValue(new[] { componentKey, displayName });
        return (Guid)(await cmd.ExecuteScalarAsync(ct))!;
    }

    private static async Task UpsertIdentityAsync(
        NpgsqlConnection connection,
        Guid componentId,
        string identityType,
        string identityValue,
        string normalizedValue,
        string? ecosystem,
        Guid sourceId,
        string evidenceType,
        decimal confidence,
        CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("""
            insert into component_identity_index
              (component_id, identity_type, identity_value, normalized_value, ecosystem, source_id, evidence_type, confidence, status)
            select $1,$2,$3,$4,$5,$6,$7,$8,'accepted'
            where not exists (
              select 1 from component_identity_index
              where component_id = $1 and identity_type = $2 and normalized_value = $4
            )
            """, connection);
        cmd.Parameters.AddWithValue(componentId);
        cmd.Parameters.AddWithValue(identityType);
        cmd.Parameters.AddWithValue(identityValue);
        cmd.Parameters.AddWithValue(normalizedValue.ToLowerInvariant());
        cmd.Parameters.AddWithValue((object?)ecosystem ?? DBNull.Value);
        cmd.Parameters.AddWithValue(sourceId);
        cmd.Parameters.AddWithValue(evidenceType);
        cmd.Parameters.AddWithValue(confidence);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static async Task MarkNormalizedAsync(NpgsqlConnection connection, Guid rawIndexId, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand("update source_raw_index set normalize_status = 'succeeded', updated_at = now() where id = $1", connection);
        cmd.Parameters.AddWithValue(rawIndexId);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static string DisplayName(string? vendor, string? product) =>
        JoinIdentity(vendor, product) ?? "unknown-cpe-component";

    private static string PackageIdentity(string? ns, string name) =>
        string.IsNullOrWhiteSpace(ns) ? name : $"{ns}:{name}";

    private static string? JoinIdentity(string? left, string? right) =>
        string.IsNullOrWhiteSpace(left) || string.IsNullOrWhiteSpace(right) ? null : $"{left}:{right}";

    private static string CpePartToType(string? part) =>
        part?.ToLowerInvariant() switch
        {
            "a" => "application",
            "o" => "operating-system",
            "h" => "hardware",
            _ => "cpe"
        };

    private static string? PurlWithoutVersion(string? purl)
    {
        if (string.IsNullOrWhiteSpace(purl)) return null;
        var at = purl.LastIndexOf('@');
        return at > "pkg:".Length ? purl[..at] : purl;
    }

    private static string? PurlType(string? purl)
    {
        if (string.IsNullOrWhiteSpace(purl) || !purl.StartsWith("pkg:", StringComparison.OrdinalIgnoreCase)) return null;
        var slash = purl.IndexOf('/');
        return slash <= "pkg:".Length ? null : purl["pkg:".Length..slash].ToLowerInvariant();
    }

    private sealed record CpeRow(
        Guid RawIndexId,
        string Cpe23Uri,
        string? Part,
        string? Vendor,
        string? Product,
        string? Version,
        string? TargetSw,
        string TitlesJson,
        string RefsJson,
        bool Deprecated,
        DateTimeOffset? LastModifiedAt,
        Guid SourceId);

    private sealed record RegistryRow(
        Guid RawIndexId,
        string Registry,
        string Ecosystem,
        string? Namespace,
        string Name,
        string? Version,
        string? Purl,
        string? RepositoryUrl,
        string? HomepageUrl,
        string MetadataJson,
        Guid SourceId);
}
