# Trivy SBOM matching benchmark

Trivy is a comparison oracle, not an absolute truth source. A difference is a triage item until the upstream advisory confirms whether the installed version is affected.

## Matching standard

- Require both package identity and an ecosystem-aware version range before reporting an affected component.
- Treat Debian Security Tracker release facts as authoritative for Debian image packages.
- Match Debian binary packages to source advisories through CycloneDX `aquasecurity:trivy:SrcName` and `aquasecurity:trivy:SrcVersion`.
- Interpret a Trivy finding with `Status: fixed` as "a fix is available"; it does not mean the installed package is already fixed.
- Keep `>= 0` open ranges visible in benchmark output because they need vendor evidence review.
- Classify missing or unparseable ranges as unknown instead of affected.

## Clean benchmark stack

```bash
bash scripts/reset-benchmark-stack.sh
DATABASE_URL=postgres://vultrack:vultrack-benchmark@127.0.0.1:55432/vultrack npm run fetch -- debian-security-tracker
API_BASE_URL=http://127.0.0.1:5199 DATABASE_URL=postgres://vultrack:vultrack-benchmark@127.0.0.1:55432/vultrack npm run normalize:sources -- debian-security-tracker
API_BASE_URL=http://127.0.0.1:5199 npm run benchmark:trivy -- --sbom image.cdx.json --trivy image_scan.json --out report.json
```

Run `npm run audit:canonical` against an existing database before a rebuild. `npm run rebuild:canonical` is dry-run by default. The destructive mode requires both `--apply` and `--confirm=REBUILD_CANONICAL_DATA`.

Canonical CVE rows must never merge two distinct `CVE-*` identifiers. Multi-CVE CSAF documents and PoC artifacts are expanded into separate canonical associations during normalization. Existing databases created before this guard should be audited, backed up, and rebuilt from parsed raw records.
