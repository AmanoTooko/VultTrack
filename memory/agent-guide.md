# Agent Guide

## First Read

1. Read `README.md` and every tracked file in `memory/`.
2. Read the module being changed and its tests before proposing an implementation.
3. Trust runtime code and schema over historical documents.

## Work Discipline

- One logical change per commit; every accepted code change is pushed to GitHub.
- Keep edits scoped and preserve existing patterns.
- Update memory in the same commit when architecture, production state, or backlog changes.
- Do not claim verification that was not run.
- Do not revert unrelated user changes in a dirty worktree.

## Environment Discipline

- Local macOS is for code and light inspection. Avoid large database copies, archive scans, and
  full Normalizer runs on constrained local storage.
- Use the designated amd64 development/data host for heavy builds, bulk scans, shadow databases,
  and first acceptance.
- Production ARM pulls green multi-architecture images; it does not build releases.
- Prefer generating official-bulk replay directly on production over transferring an 11+ GB
  database.
- Host addresses, keys, credentials, and private backup paths live in `memory/private/` or host
  environment files, never tracked Git files.

## Change Workflow

1. Inspect current Git status and relevant source/tests.
2. Add a focused regression test that fails against the bug when practical.
3. Run focused tests in the .NET 10 SDK or Node 22 environment.
4. Run the full relevant suite and formatting/lint checks.
5. Commit and push the logical change.
6. Wait for GitHub CI test and multi-architecture image jobs.
7. Deploy the full 40-character SHA to the development/data host.
8. Validate health, readiness, restart/OOM state, API behavior, and data-quality impact.
9. Deploy production only after development acceptance.
10. Update `memory/current-state.md` and remove completed work from `memory/backlog.md`.

## Test Commands

```bash
npm ci
npm test
npm run lint

docker run --rm -v "$PWD:/src" -w /src \
  -v vultrack-nuget:/root/.nuget/packages \
  mcr.microsoft.com/dotnet/sdk:10.0 \
  dotnet test VulTrack.slnx

API_BASE_URL=http://localhost:5099 npm run test:api
```

Use focused `dotnet test --filter ...` before the full suite. The host is not assumed to have a
native .NET SDK.

## Data Maintenance Workflow

- Stop the API/scheduler before opening the database with an external audit CLI.
- Preserve a rollback before a high-impact replay or rebuild.
- Feed official bulk records into the real spool/Normalizer path.
- Inspect manifests, missing IDs, segment continuity, `sourceMode`, and `forceNormalize` before
  ingestion.
- Keep exactly one writer while replay runs.
- Require import completion, deferred rebuild completion, zero restart/OOM, and health/readiness.
- Stop the writer and run `scripts/audit-duckdb-quality.sql`.
- Restore normal scheduler settings and observe one complete configured-source cycle.
- Clean only files whose ownership and recoverability are proven; never use a global Docker prune.

## Security

- Never echo or commit tokens, `.env`, SSH keys, databases, source dumps, backups, or private SBOMs.
- Inspect credential presence without printing values.
- Treat a token shown in logs as compromised and rotate it.
- Admin endpoints require a login session, not basic auth.

## Documentation Hygiene

- `memory/backlog.md` contains only unfinished work.
- `memory/current-state.md` contains the latest verified state, not a command transcript.
- `memory/architecture-decisions.md` contains durable reasons and invariants.
- `memory/archive/` contains useful historical incident lessons.
- `memory/private/` is ignored and may contain local operational handoff details.
