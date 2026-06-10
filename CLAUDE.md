# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

`claude-guardian` is an enterprise DLP (Data Loss Prevention) platform that integrates with Claude Code as hook scripts. It scans tool inputs/outputs and user prompts for secrets, credentials, and PII, then blocks, redacts, or routes them through an approval workflow. All events are persisted to a local SQLite database with a tamper-evident, hash-chained audit log.

## Commands

```bash
# Run (no build step required — Node strips types at runtime)
npm run dev                      # claude-guardian CLI via ts-native
npm run serve                    # start dashboard server

# Test
npm test                         # vitest run (all tests)
npm run test:watch               # vitest in watch mode
npx vitest run tests/engine.test.ts   # single test file

# Type-check & lint
npm run typecheck                # tsc --noEmit
npm run lint                     # biome lint src
npm run format                   # biome format --write src
npm run fix                      # biome check --write src (lint + format)
npm run ci                       # typecheck + biome check + vitest run
```

No build/compile step: scripts use `#!/usr/bin/env -S node --experimental-strip-types`, so TypeScript runs directly. Requires Node >= 22.6.0.

## Architecture

### Hook entry points

The three hooks in `src/hooks/` are the runtime entry points invoked by Claude Code:

| Hook | File | Contract |
|---|---|---|
| `PreToolUse` | `src/hooks/pre-tool-use.ts` | Exit 2 + JSON stdout to block; exit 0 to allow |
| `PostToolUse` | `src/hooks/post-tool-use.ts` | Audit-only, never blocks |
| `UserPromptSubmit` | `src/hooks/user-prompt-submit.ts` | Can block or redact; handles `[allow-guardian]` and `[request-exception: reason]` inline tags |

All hooks read JSON from stdin, run `scanSync` (synchronous, never async), and must complete within `engineTimeoutMs` (default 500 ms) — failing closed on timeout.

### Scan engine (`src/engine/`)

`scan()` (async) and `scanSync()` (sync, used by hooks) run all detectors, then apply a two-pass dedup:
1. Same-detector + same-raw-value duplicates are dropped.
2. Gitleaks findings whose raw value was already caught by a built-in detector are suppressed.

Allowlist entries are applied after dedup. The gitleaks detector (`src/engine/detectors/gitleaks.ts`) is an `extraDetector` — it is only added in `user-prompt-submit.ts` to avoid per-file-scan latency.

### Detectors (`src/engine/detectors/`)

Each detector implements `Detector` from `types.ts`:

```ts
interface Detector {
  id: string;
  label: string;
  dataType: DataType;
  severity: Severity;
  scan(text: string): DetectorFinding[];
}
```

`BUILT_IN_DETECTORS` in `index.ts` is ordered critical → high → medium. Adding a new detector means implementing the interface and adding it to that array.

### Policy engine (`src/lib/policy.ts`)

`evaluatePolicy(findings, tool, rules)` returns the single highest-priority `PolicyAction` across all matching rules: `block > require-approval > redact > allow`. Short-circuits on first `block`. Rules match on `dataTypes`, `tools`, `detectorIds`, and `minSeverity`.

### Approval workflow (`src/lib/approval.ts`)

When a rule fires `require-approval`, an `Approval` row is created with a scoped token and TTL. The scope key is `tool:dataType1,dataType2,...`. On subsequent hook calls, `findActiveApproval(db, scope)` checks for an active, non-expired approval before blocking again.

### Audit log (`src/lib/audit.ts`)

Append-only SHA-256 hash chain: each entry stores `prevHash` and `hash = sha256(seq|timestamp|type|payload|prevHash)`. `verifyAuditChain(db)` re-computes hashes to detect tampering. Raw secret values are never stored — only metadata (`dataType`, `severity`, `snippet`).

### Config (`src/config/`)

`loadConfig()` checks `./claude-guardian.config.json` (CWD) first, then falls back to `~/.config/claude-guardian/config.json`. Validation is done with Zod. Falls back to `DEFAULT_CONFIG` silently on parse failure (fail-open for config, fail-closed for scan timeouts).

### Dashboard server (`src/server/api.ts`)

Fastify server serving:
- `GET /dashboard` — static HTML from `public/dashboard.html`
- `GET /api/incidents`, `/api/approvals`, `/api/audit`, `/api/metrics`, `/api/policies`
- `POST /api/approvals/:id/resolve` — approve or deny
- `GET /api/events` — SSE stream for real-time updates

Auth: `X-Guardian-Token` header or `?token=` query param checked against `dashboardToken` in config. Dashboard and health routes are public.

### Database (`src/db/`)

Three tables: `incidents`, `approvals`, `audit_log`. `getDb()` opens (or creates) the SQLite file and applies the schema DDL idempotently on first call. The `incidents.findings` column stores JSON — raw values are excluded before storage.

### Enterprise mode (`src/server/store.ts`, `src/lib/central.ts`)

Additive central-server mode; local mode is unchanged when the new config fields are empty.

- **Server storage**: `buildServer` uses the async `GuardianStore` interface — `SqliteStore` (wraps the sync libs, default) or `PgStore` (when `databaseUrl`/`DATABASE_URL` is set; mirrored schema, own hash chain). Hooks never use this layer.
- **Agent endpoints**: `POST /api/agent/ingest` (idempotent upsert; findings arrive without `rawValue`) and `GET /api/agent/approvals/active?scope=`, both authed by `X-Guardian-Agent-Key` against `agentApiKey` (fail-closed when unset).
- **Client side**: when `centralUrl`+`centralApiKey` are configured, hooks mirror incidents/approvals via a disk outbox (`<db-dir>/outbox/`) flushed by a detached `central-flush.ts` process (store-and-forward, zero added latency), and check the central server for active approvals before re-blocking (1.5 s timeout, silent fallback to local).
- **Deploy**: `Dockerfile` + `docker-compose.yml` (Postgres) + Helm chart in `deploy/helm/claude-guardian` (EKS/ALB/RDS). Client rollout via `enterprise/install-agent.sh --server <url> --key <agent-key>` (wraps `init --central-url --central-key`). Docs: `docs/ENTERPRISE.md`.

## Key behaviors to know

- **`[allow-guardian]`** in the user's last message bypasses `pre-tool-use` entirely (checked by reading the transcript JSONL).
- **`[request-exception: <reason>]`** in a blocked prompt creates a pending approval and blocks with a dashboard URL.
- `.env` files are blocked by filename alone in `pre-tool-use`, before any content is read.
- `cat`/`head`/`tail`/etc. commands in Bash are parsed to extract file paths, which are then scanned.
- Env var values referenced in Bash commands (`$VAR`, `${VAR}`) are resolved from `process.env` and scanned.
- Engine timeout always blocks (fail-safe), not allow.
