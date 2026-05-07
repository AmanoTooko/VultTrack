# Implementation Status

Date: 2026-05-08

## Review Assessment

The latest design review pushed the project from a broad design into a runnable MVP slice. The implementation in this commit follows these decisions:

- PostgreSQL is deployed locally through Docker and initialized with the core ingestion, staging, normalized vulnerability, component, affected evidence, plugin, and cache tables.
- Fetchers are independent Node.js programs that read shared environment variables and insert into source-specific staging tables.
- The .NET side is a single `.NET 10` service with API endpoints, a disabled-by-default scheduler, and an NVD raw processor.
- API style remains RPC-like and uses only GET/POST.
- Full-source synchronization is implemented as a fetcher capability, while automated tests use bounded smoke mode through `FETCHER_MAX_RECORDS` to avoid multi-hour or multi-GB runs.

## Implemented Sources

Independent fetchers now exist for:

1. `nvd-cve`
2. `nvd-cpe`
3. `ghsa`
4. `osv`
5. `cve-list-v5`
6. `cisa-kev`
7. `first-epss`
8. `alpine-secdb`
9. `debian-security-tracker`
10. `ubuntu-osv`
11. `npm-registry`

Run one source:

```bash
npm run fetch -- --source nvd-cve
```

Run bounded smoke sync for the 10 vulnerability/intel sources:

```bash
npm run fetch:all:smoke
```

Full sync is intentionally not part of CI because NVD CVE, NVD CPE, OSV all.zip, CVE List v5, EPSS, and distro trackers can be large and rate-limited. For production, run full sync source-by-source with monitoring and checkpoints.

## Local Database Status

PostgreSQL container:

```bash
docker compose up -d postgres
```

The initialization SQL creates 38 tables and seeds 11 sources.

Verified smoke data after bounded fetch:

```text
source_raw_index: 18
stg_nvd_cves: 2
stg_nvd_cpe_dictionary: 2
stg_ghsa_advisories: 2
stg_osv_vulnerabilities: 1
stg_cve_list_records: 1
stg_threat_intel_records: 4
stg_alpine_secdb: 2
stg_debian_security_tracker: 2
stg_ubuntu_osv: 2
```

## .NET Core App

Created:

- `src/VulTrack.App`
- `tests/VulTrack.Tests`

Implemented endpoints:

```text
GET  /api/v1/system.health
GET  /api/v1/system.ready
GET  /api/v1/source.list
POST /api/v1/nvd.processPending
POST /api/v1/vulnerability.search
GET  /api/v1/vulnerability.getByIdentifier
GET  /api/v1/vulnerability.get
```

Implemented processing:

- `NvdRawProcessor` converts `stg_nvd_cves` into:
  - `vulnerabilities`
  - `vulnerability_records`
  - `vulnerability_identifier_index`
  - `vulnerability_severity_scores`
  - `vulnerability_descriptions`
  - `vulnerability_weaknesses`
  - `vulnerability_references`
  - `vulnerability_affected_facts`

Verified result:

```text
vulnerabilities: 2
vulnerability_severity_scores: 2
vulnerability_affected_facts: 3
```

## Test Commands

```bash
npm test
npm run test:integration
npm run test:api
docker run --rm -v "$PWD:/workspace" -w /workspace/tests/VulTrack.Tests mcr.microsoft.com/dotnet/sdk:10.0 dotnet test
docker run --rm -v "$PWD:/workspace" -w /workspace mcr.microsoft.com/dotnet/sdk:10.0 dotnet build
```

## Current Limitations

- Full data crawling was not executed for all sources in this run because several sources are very large or rate-limited. The fetchers support full mode when `FETCHER_MAX_RECORDS` is unset.
- Identifier linking is partially implemented for NVD CVE records; multi-source union-find is still pending.
- Component aggregation and canonical affected set are not yet implemented in .NET.
- Scheduler exists and is disabled by default. It needs packaging work before running inside the production app image because the Node plugin path must be mounted into the app runtime.
- PostgreSQL is running locally; Redis is not used yet in this MVP slice.

