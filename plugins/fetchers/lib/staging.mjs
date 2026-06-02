export async function upsertNvdCve(client, rawIndexId, item) {
  const cve = item.cve ?? item;
  await client.query(
    `insert into stg_nvd_cves
      (raw_index_id, cve_id, vuln_status, descriptions, metrics, weaknesses, configurations,
       references_json, published_at, modified_at, cisa_exploit_add, cisa_action_due, payload)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
     on conflict (raw_index_id) do update set payload = excluded.payload`,
    [
      rawIndexId,
      cve.id,
      cve.vulnStatus ?? null,
      JSON.stringify(cve.descriptions ?? []),
      JSON.stringify(cve.metrics ?? {}),
      JSON.stringify(cve.weaknesses ?? []),
      JSON.stringify(cve.configurations ?? []),
      JSON.stringify(cve.references ?? []),
      cve.published ?? null,
      cve.lastModified ?? null,
      cve.cisaExploitAdd ?? null,
      cve.cisaActionDue ?? null,
      JSON.stringify(item)
    ]
  );
}

export async function upsertNvdCpe(client, rawIndexId, item) {
  const cpe = item.cpe ?? item;
  const uri = cpe.cpeName ?? cpe.cpe23Uri ?? cpe.cpe23_uri;
  const parts = parseCpe23(uri);
  await client.query(
    `insert into stg_nvd_cpe_dictionary
      (raw_index_id, cpe23_uri, part, vendor, product, version, target_sw, titles, refs, deprecated, last_modified_at, payload)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
     on conflict (raw_index_id) do update set payload = excluded.payload`,
    [
      rawIndexId,
      uri,
      parts.part,
      parts.vendor,
      parts.product,
      parts.version,
      parts.target_sw,
      JSON.stringify(cpe.titles ?? []),
      JSON.stringify(cpe.refs ?? []),
      Boolean(cpe.deprecated),
      cpe.lastModified ?? null,
      JSON.stringify(item)
    ]
  );
}

export async function upsertGhsa(client, rawIndexId, item) {
  const identifiers = item.identifiers ?? [];
  const cve = identifiers.find((x) => x.type === 'CVE')?.value ?? item.cve_id ?? null;
  const vulnerabilities = item.vulnerabilities ?? [];
  const first = vulnerabilities[0] ?? {};
  await client.query(
    `insert into stg_ghsa_advisories
      (raw_index_id, ghsa_id, cve_id, identifiers, summary, description, ecosystem, package_name,
       vulnerable_ranges, patched_versions, cvss, cwes, references_json, published_at, updated_at, payload)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
     on conflict (raw_index_id) do update set payload = excluded.payload`,
    [
      rawIndexId,
      item.ghsa_id,
      cve,
      JSON.stringify(identifiers),
      item.summary ?? null,
      item.description ?? null,
      first.package?.ecosystem ?? first.package?.type ?? null,
      first.package?.name ?? null,
      JSON.stringify(vulnerabilities.map((x) => x.vulnerable_version_range).filter(Boolean)),
      JSON.stringify(vulnerabilities.map((x) => x.first_patched_version).filter(Boolean)),
      JSON.stringify(item.cvss ?? item.cvss_severities ?? {}),
      JSON.stringify(item.cwes ?? []),
      JSON.stringify(item.references ?? []),
      item.published_at ?? null,
      item.updated_at ?? null,
      JSON.stringify(item)
    ]
  );
}

export async function upsertOsv(client, rawIndexId, item, table = 'stg_osv_vulnerabilities') {
  const sql = table === 'stg_ubuntu_osv'
    ? `insert into stg_ubuntu_osv (raw_index_id, osv_id, aliases, affected, payload)
       values ($1,$2,$3,$4,$5)
       on conflict (raw_index_id) do update set payload = excluded.payload`
    : `insert into stg_osv_vulnerabilities
       (raw_index_id, osv_id, aliases, related, summary, details, affected, severity, references_json, published_at, modified_at, payload)
       values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       on conflict (raw_index_id) do update set payload = excluded.payload`;
  const values = table === 'stg_ubuntu_osv'
    ? [rawIndexId, item.id, item.aliases ?? [], JSON.stringify(item.affected ?? []), JSON.stringify(item)]
    : [
        rawIndexId,
        item.id,
        item.aliases ?? [],
        item.related ?? [],
        item.summary ?? null,
        item.details ?? null,
        JSON.stringify(item.affected ?? []),
        JSON.stringify(item.severity ?? []),
        JSON.stringify(item.references ?? []),
        item.published ?? null,
        item.modified ?? null,
        JSON.stringify(item)
      ];
  await client.query(sql, values);
}

export async function upsertCveList(client, rawIndexId, item) {
  const metadata = item.cveMetadata ?? {};
  await client.query(
    `insert into stg_cve_list_records
       (raw_index_id, cve_id, cve_metadata, containers_cna, containers_adp, state, published_at, updated_at, payload)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
     on conflict (raw_index_id) do update set payload = excluded.payload`,
    [
      rawIndexId,
      metadata.cveId,
      JSON.stringify(metadata),
      JSON.stringify(item.containers?.cna ?? {}),
      JSON.stringify(item.containers?.adp ?? []),
      metadata.state ?? null,
      metadata.datePublished ?? null,
      metadata.dateUpdated ?? metadata.dateReserved ?? null,
      JSON.stringify(item)
    ]
  );
}

export async function upsertThreatIntel(client, rawIndexId, provider, identifier, item, epss = null) {
  await client.query(
    `insert into stg_threat_intel_records
       (raw_index_id, provider, identifier, epss_score, epss_percentile, observed_at, payload)
     values ($1,$2,$3,$4,$5,$6,$7)
     on conflict (raw_index_id) do update set
       epss_score = excluded.epss_score,
       epss_percentile = excluded.epss_percentile,
       observed_at = excluded.observed_at,
       payload = excluded.payload`,
    [
      rawIndexId,
      provider,
      identifier,
      epss?.score ?? null,
      epss?.percentile ?? null,
      epss?.observedAt ?? null,
      JSON.stringify(item)
    ]
  );
}

export async function upsertAlpine(client, rawIndexId, release, pkg, identifiers, payload) {
  await client.query(
    `insert into stg_alpine_secdb
       (raw_index_id, distro_release, package_name, identifiers, secfixes, payload)
     values ($1,$2,$3,$4,$5,$6)
     on conflict (raw_index_id) do update set payload = excluded.payload`,
    [rawIndexId, release, pkg.pkg?.name ?? pkg.name, identifiers, JSON.stringify(pkg.pkg?.secfixes ?? pkg.secfixes ?? {}), JSON.stringify(payload)]
  );
}

export async function upsertDebian(client, rawIndexId, cveId, packages, payload) {
  await client.query(
    `insert into stg_debian_security_tracker
       (raw_index_id, cve_id, packages, payload)
     values ($1,$2,$3,$4)
     on conflict (raw_index_id) do update set payload = excluded.payload`,
    [rawIndexId, cveId, JSON.stringify(packages), JSON.stringify(payload)]
  );
}

export async function upsertRegistryPackage(client, rawIndexId, registry, ecosystem, item) {
  await client.query(
    `insert into stg_registry_packages
       (raw_index_id, registry, ecosystem, namespace, name, version, purl, repository_url, homepage_url, metadata, payload)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
     on conflict (raw_index_id) do update set payload = excluded.payload`,
    [
      rawIndexId,
      registry,
      ecosystem,
      item.namespace ?? null,
      item.name,
      item.version ?? null,
      item.purl ?? null,
      item.repositoryUrl ?? null,
      item.homepageUrl ?? null,
      JSON.stringify(item.metadata ?? {}),
      JSON.stringify(item.payload ?? item)
    ]
  );
}

export async function upsertEcosystemAdvisory(client, rawIndexId, item) {
  await client.query(
    `insert into stg_ecosystem_advisories
       (raw_index_id, provider, ecosystem, advisory_id, identifiers, package_name, purl,
        vulnerable_ranges, patched_versions, severity_label, cvss, references_json,
        published_at, modified_at, payload)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
     on conflict (raw_index_id) do update set
       provider = excluded.provider,
       ecosystem = excluded.ecosystem,
       advisory_id = excluded.advisory_id,
       identifiers = excluded.identifiers,
       package_name = excluded.package_name,
       purl = excluded.purl,
       vulnerable_ranges = excluded.vulnerable_ranges,
       patched_versions = excluded.patched_versions,
       severity_label = excluded.severity_label,
       cvss = excluded.cvss,
       references_json = excluded.references_json,
       published_at = excluded.published_at,
       modified_at = excluded.modified_at,
       payload = excluded.payload`,
    [
      rawIndexId,
      item.provider,
      item.ecosystem ?? null,
      item.advisoryId,
      item.identifiers ?? [],
      item.packageName ?? null,
      item.purl ?? null,
      JSON.stringify(item.vulnerableRanges ?? []),
      JSON.stringify(item.patchedVersions ?? []),
      item.severityLabel ?? null,
      JSON.stringify(item.cvss ?? {}),
      JSON.stringify(item.references ?? []),
      item.publishedAt ?? null,
      item.modifiedAt ?? null,
      JSON.stringify(item.payload ?? item)
    ]
  );
}

export async function upsertExploitPoc(client, rawIndexId, item) {
  await client.query(
    `insert into stg_exploit_pocs
       (raw_index_id, provider, source_key, identifiers, title, source_url, artifact_url,
        artifact_object_id, artifact_sha256, artifact_type, exploit_type, maturity,
        verification_status, requires_auth, requires_user_interaction, language, platform,
        author, published_at, modified_at, tags, payload)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
     on conflict (raw_index_id) do update set
       provider = excluded.provider,
       source_key = excluded.source_key,
       identifiers = excluded.identifiers,
       title = excluded.title,
       source_url = excluded.source_url,
       artifact_url = excluded.artifact_url,
       artifact_object_id = excluded.artifact_object_id,
       artifact_sha256 = excluded.artifact_sha256,
       artifact_type = excluded.artifact_type,
       exploit_type = excluded.exploit_type,
       maturity = excluded.maturity,
       verification_status = excluded.verification_status,
       requires_auth = excluded.requires_auth,
       requires_user_interaction = excluded.requires_user_interaction,
       language = excluded.language,
       platform = excluded.platform,
       author = excluded.author,
       published_at = excluded.published_at,
       modified_at = excluded.modified_at,
       tags = excluded.tags,
       payload = excluded.payload`,
    [
      rawIndexId,
      item.provider,
      item.sourceKey,
      item.identifiers ?? [],
      item.title ?? null,
      item.sourceUrl ?? null,
      item.artifactUrl ?? null,
      item.artifactObjectId ?? null,
      item.artifactSha256 ?? null,
      item.artifactType ?? 'poc_code',
      item.exploitType ?? null,
      item.maturity ?? 'poc',
      item.verificationStatus ?? 'unreviewed',
      item.requiresAuth ?? null,
      item.requiresUserInteraction ?? null,
      item.language ?? null,
      item.platform ?? null,
      item.author ?? null,
      item.publishedAt ?? null,
      item.modifiedAt ?? null,
      item.tags ?? [],
      JSON.stringify(item.payload ?? item)
    ]
  );
}

export async function upsertExternalAdvisory(client, rawIndexId, item) {
  await client.query(
    `insert into stg_external_advisories
       (raw_index_id, provider, advisory_id, identifiers, title, summary, description,
        severity_label, references_json, affected_products, affected_vendors, poc_available,
        detail_available, published_at, modified_at, payload)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
     on conflict (raw_index_id) do update set
       provider = excluded.provider,
       advisory_id = excluded.advisory_id,
       identifiers = excluded.identifiers,
       title = excluded.title,
       summary = excluded.summary,
       description = excluded.description,
       severity_label = excluded.severity_label,
       references_json = excluded.references_json,
       affected_products = excluded.affected_products,
       affected_vendors = excluded.affected_vendors,
       poc_available = excluded.poc_available,
       detail_available = excluded.detail_available,
       published_at = excluded.published_at,
       modified_at = excluded.modified_at,
       payload = excluded.payload`,
    [
      rawIndexId,
      item.provider,
      item.advisoryId,
      item.identifiers ?? [],
      item.title ?? null,
      item.summary ?? null,
      item.description ?? null,
      item.severityLabel ?? null,
      JSON.stringify(item.references ?? []),
      JSON.stringify(item.affectedProducts ?? []),
      JSON.stringify(item.affectedVendors ?? []),
      item.pocAvailable ?? null,
      item.detailAvailable ?? null,
      item.publishedAt ?? null,
      item.modifiedAt ?? null,
      JSON.stringify(item.payload ?? item)
    ]
  );
}

function parseCpe23(uri) {
  const raw = String(uri ?? '');
  const parts = raw.startsWith('cpe:2.3:') ? raw.split(':') : [];
  return {
    part: parts[2] ?? null,
    vendor: parts[3] ?? null,
    product: parts[4] ?? null,
    version: parts[5] ?? null,
    target_sw: parts[10] ?? null
  };
}

export async function upsertAndroidOsv(client, rawIndexId, item) {
  await client.query(
    `insert into stg_android_osv
       (raw_index_id, osv_id, aliases, affected, severity, summary, details, references_json, published_at, modified_at, payload)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
     on conflict (raw_index_id) do update set payload = excluded.payload`,
    [
      rawIndexId,
      item.id,
      item.aliases ?? [],
      JSON.stringify(item.affected ?? []),
      JSON.stringify(item.severity ?? []),
      item.summary ?? null,
      item.details ?? null,
      JSON.stringify(item.references ?? []),
      item.published ?? null,
      item.modified ?? null,
      JSON.stringify(item)
    ]
  );
}

export async function upsertNpmAdvisory(client, rawIndexId, item) {
  const identifiers = item.identifiers ?? [];
  const cve = identifiers.find((x) => x.type === 'CVE')?.value ?? item.cve_id ?? null;
  const vulnerabilities = item.vulnerabilities ?? [];
  const first = vulnerabilities[0] ?? {};
  await client.query(
    `insert into stg_npm_advisories
       (raw_index_id, ghsa_id, cve_id, ecosystem, package_name, severity, summary, description,
        vulnerable_ranges, patched_versions, cvss, cwes, references_json, published_at, updated_at, payload)
     values ($1,$2,$3,'npm',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
     on conflict (raw_index_id) do update set payload = excluded.payload`,
    [
      rawIndexId,
      item.ghsa_id,
      cve,
      first.package?.name ?? null,
      item.severity ?? null,
      item.summary ?? null,
      item.description ?? null,
      JSON.stringify(vulnerabilities.map((x) => x.vulnerable_version_range).filter(Boolean)),
      JSON.stringify(vulnerabilities.map((x) => x.first_patched_version).filter(Boolean)),
      JSON.stringify(item.cvss ?? item.cvss_severities ?? {}),
      JSON.stringify(item.cwes ?? []),
      JSON.stringify(item.references ?? []),
      item.published_at ?? null,
      item.updated_at ?? null,
      JSON.stringify(item)
    ]
  );
}

export async function upsertPypiAdvisory(client, rawIndexId, item) {
  await client.query(
    `insert into stg_pypi_advisories
       (raw_index_id, pysec_id, aliases, ecosystem, package_name, summary, details, affected,
        severity, references_json, published_at, modified_at, payload)
     values ($1,$2,$3,'PyPI',$4,$5,$6,$7,$8,$9,$10,$11,$12)
     on conflict (raw_index_id) do update set
       pysec_id = excluded.pysec_id,
       aliases = excluded.aliases,
       ecosystem = excluded.ecosystem,
       package_name = excluded.package_name,
       summary = excluded.summary,
       details = excluded.details,
       affected = excluded.affected,
       severity = excluded.severity,
       references_json = excluded.references_json,
       published_at = excluded.published_at,
       modified_at = excluded.modified_at,
       payload = excluded.payload`,
    [
      rawIndexId,
      item.id,
      item.aliases ?? [],
      item.affected?.[0]?.package?.name ?? null,
      item.summary ?? null,
      item.details ?? null,
      JSON.stringify(item.affected ?? []),
      JSON.stringify(item.severity ?? []),
      JSON.stringify(item.references ?? []),
      item.published ?? null,
      item.modified ?? null,
      JSON.stringify(item)
    ]
  );
}
