# Component Matching Benchmark

This benchmark gives the matching engine a stable vocabulary, so SBOM results can be compared across normalizer and matcher changes.

## Standard

- `affected`: component identity matches by exact purl, purl without version, or normalized package/ecosystem, and the component version satisfies a parseable `normalized_range`.
- `notAffected`: component identity matches, the range is parseable, and the component version does not satisfy it.
- `unknown`: component identity matches, but the SBOM component has no version, the affected fact has no range, or the range cannot be parsed.
- `suspiciousBroadRange`: ranges such as `>0` are tracked separately. Treat them as review targets because they often represent coarse package association rather than a precise vulnerable interval.

The SBOM UI should show `affected` findings by default. `unknown` and `suspiciousBroadRange` are useful for benchmark review, but should not silently inflate affected counts.

## Run

```bash
API_BASE_URL=http://localhost:5099 npm run benchmark:matching
API_BASE_URL=http://localhost:5099 npm run benchmark:matching -- --ecosystem alpine
API_BASE_URL=http://localhost:5099 npm run benchmark:matching -- --ecosystem maven --package log4j-core
API_BASE_URL=http://localhost:5099 npm run benchmark:matching -- --sbom 00000000-0000-0000-0000-000000000000
```

The API endpoint is:

```text
GET /api/v1/benchmark.matchingQuality?ecosystem=&packageName=&sbomId=
```

Track these numbers after matcher changes:

- `actionableRangeRatio`: higher means more affected facts can produce deterministic version decisions.
- `noRange`: high values explain `unknown`/dropped SBOM findings.
- `openLowerBound`: high values identify `>0` style broad matches that need source-specific review.
- `unparseableRange`: should trend down as normalizers become more consistent.
