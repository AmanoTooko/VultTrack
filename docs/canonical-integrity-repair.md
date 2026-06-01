# Canonical integrity repair

Use this runbook when exact CVE searches return another CVE, detail pages contain
unrelated source records, or CPE facts exist without CPE projections.

## Why a rebuild is required

Canonical tables are derived from parsed source records. Older normalizer
versions allowed one source record containing multiple CVE identifiers to merge
those CVEs. Later records could then attach more CVEs, affected facts, and PoC
records to the polluted group.

The code fix prevents new cross-CVE merges. It cannot safely split historical
rows in place because the derived tables no longer retain a trustworthy split
boundary. Rebuild derived data from parsed raw records instead.

## Audit

```bash
npm run audit:canonical
```

Healthy output has:

- no `suspiciousCanonicalGroups`
- `cpeCoverage.cpe_projections` greater than zero after NVD normalization
- no unexpected growth in `staleProjectionCount`

Run the isolated regression smoke after resetting the benchmark stack:

```bash
./scripts/reset-benchmark-stack.sh
ALLOW_CANONICAL_SMOKE_SEED=1 npm run smoke:canonical
```

## Rebuild

Stop the API scheduler before rebuilding and create a PostgreSQL backup.

```bash
npm run rebuild:canonical
npm run rebuild:canonical -- --apply --confirm=REBUILD_CANONICAL_DATA
npm run normalize:parallel
npm run audit:canonical
```

The first rebuild command is a dry run. The apply command deletes only derived
canonical data and requeues successfully parsed raw records for normalization.
It does not delete raw source objects or staging records.
