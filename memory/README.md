# VulTrack Agent Memory

This directory is the persistent, concise context for coding agents. Read it before changing the
project. It replaces the old chronological handoff and checked-off TODO documents.

## Reading Order

1. [current-state.md](current-state.md) - verified runtime, deployment, and data-quality state.
2. [architecture-decisions.md](architecture-decisions.md) - decisions that must survive refactors.
3. [agent-guide.md](agent-guide.md) - workflow, environment, safety, testing, and handoff rules.
4. [backlog.md](backlog.md) - only unfinished work; completed tasks do not belong here.

The project overview and design philosophy live in the repository [README](../README.md). The
detailed current architecture is [docs/design/duckdb-first-architecture.md](../docs/design/duckdb-first-architecture.md).

## Authority

When prose and implementation disagree, use this order:

1. Runtime schema and behavior in `src/VulTrack.App/`.
2. Fetcher behavior in `plugins/fetchers/`.
3. Current architecture and deployment runbooks.
4. Memory documents.
5. Historical documents.

Update the relevant memory document in the same commit when a change alters architecture,
operations, verified production state, or the backlog. Keep memory short and current; move useful
incident history to `memory/archive/` instead of accumulating a transcript.

Host addresses, credentials, tokens, private backup locations, and session transcripts belong in
the gitignored `memory/private/` directory, never in tracked memory.
