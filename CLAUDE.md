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

`evaluatePolicy(findings, tool, rules)` returns the single highest-priority `PolicyAction` across all matching rules: `block > require-approval > substitute > redact > allow`. Short-circuits on first `block`. Rules match on `dataTypes`, `tools`, `detectorIds`, and `minSeverity`.

### Substitution — fake placeholders (`src/lib/substitute.ts`)

The `substitute` action rewrites egress with **plausible fictitious values** instead of blocking/masking, so the prompt can still be sent with fake data. **Egress-only, one-way**: nothing restores the LLM's response (no vault, no round-trip). `generateFake(dataType, rawValue, salt)` is **deterministic** (seeded by `sha256(salt:dataType:rawValue)`) → the same real value always maps to the same fake, giving referential integrity within and across turns without storing a map. Fakes are **format-preserving**: fake CPF/CNPJ pass their check digits, fake cards pass Luhn, emails use reserved `example.com`, names become `First Last`; dataTypes without a dedicated generator fall back to a length/char-class "skeleton scramble", then to mask. `substituteText(text, findings, salt)` replaces longest raw values first (avoids corrupting substrings). Wired into all egress surfaces (`user-prompt-submit`, `mcp-scan`, `web-scan`, `gui-scan`); every branch is **fail-closed** (any rewrite error → block). The HTTPS proxy forwards the rewritten body with a recomputed `content-length`.

### Entity detection — light NER (`src/engine/detectors/entity.ts`)

`entityDetectors` (person-name, postal-address) raise PII recall for what structured regex can't catch (names/addresses). **Opt-in** via `config.entityDetection` (added as extra detectors like gitleaks; local mode is unchanged when off). This is the fast in-process floor; a real ONNX NER model belongs in the persistent daemon (warm), plugged via the same `Detector` interface. Conservative on purpose (substitution fails open, so prefer a miss over false positives).

### Approval workflow (`src/lib/approval.ts`)

When a rule fires `require-approval`, an `Approval` row is created with a scoped token and TTL. The scope key is `tool:dataType1,dataType2,...`. On subsequent hook calls, `findActiveApproval(db, scope)` checks for an active, non-expired approval before blocking again.

### Audit log (`src/lib/audit.ts`)

Append-only SHA-256 hash chain: each entry stores `prevHash` and `hash = sha256(seq|timestamp|type|payload|prevHash)`. `verifyAuditChain(db)` re-computes hashes to detect tampering. Raw secret values are never stored — only metadata (`dataType`, `severity`, `snippet`).

### Config (`src/config/`)

`loadConfig()` checks `./claude-guardian.config.json` (CWD) first, then falls back to `~/.config/claude-guardian/config.json`. Validation is done with Zod. Falls back to `DEFAULT_CONFIG` silently on parse failure (fail-open for config, fail-closed for scan timeouts). Substitution knobs (both default to off/empty, keeping local mode identical): `substitutionSalt` (`GUARDIAN_SUBSTITUTION_SALT`) seeds the fake generators — set a secret per install to prevent cross-org fake correlation; `entityDetection` (`GUARDIAN_ENTITY_DETECTION=true`) enables the name/address detectors. `blockedWebModels` (`GUARDIAN_BLOCKED_WEB_MODELS`, comma-separated) blocks browser-extension sends whose declared model matches any pattern (case-insensitive substring, e.g. `fable` blocks `claude-fable-5`); empty = no restriction.

### Dashboard server (`src/server/api.ts`)

Fastify server serving:
- `GET /dashboard` — static HTML from `public/dashboard.html`
- `GET /api/incidents`, `/api/approvals`, `/api/audit`, `/api/metrics`, `/api/policies`
- `GET /api/detectors` — read-only catalog of every detector (built-in + async + entity + gitleaks + custom) with `kind` (`regex`/`heuristic`/`external`/`custom`) and `pattern` taken from the detector's own `X_RE.source` (never a hand-written copy — see `Detector.pattern`); rendered by the "Detectores" sub-tab of the Policies page (grouping, search, regex highlight, rule cross-reference)
- `POST /api/approvals/:id/resolve` — approve or deny
- `GET /api/events` — SSE stream for real-time updates

Auth: `X-Guardian-Token` header or `?token=` query param checked against `dashboardToken` in config. Dashboard and health routes are public.

### Database (`src/db/`)

Three tables: `incidents`, `approvals`, `audit_log`. `getDb()` opens (or creates) the SQLite file and applies the schema DDL idempotently on first call. The `incidents.findings` column stores JSON — raw values are excluded before storage.

### Enterprise mode (`src/server/store.ts`, `src/lib/central.ts`)

Additive central-server mode; local mode is unchanged when the new config fields are empty.

- **Server storage**: `buildServer` uses the async `GuardianStore` interface — `SqliteStore` (wraps the sync libs, default) or `PgStore` (when `databaseUrl`/`DATABASE_URL` is set; mirrored schema, own hash chain). Hooks never use this layer.
- **Agent endpoints**: `POST /api/agent/ingest` (idempotent upsert; findings arrive without `rawValue`) and `GET /api/agent/approvals/active?scope=`, both authed by `X-Guardian-Agent-Key` — per-machine keys issued by `POST /api/agent/enroll` (`enrollmentSecret`; sha256 stored in `agent_keys`, revocable via `/api/agent-keys`), with the legacy shared `agentApiKey` accepted while `allowLegacyAgentKey` is true (fail-closed when no valid key).
- **Client side**: when `centralUrl`+`centralApiKey` are configured, hooks mirror incidents/approvals via a disk outbox (`<db-dir>/outbox/`) flushed by a detached `central-flush.ts` process (store-and-forward, zero added latency), and check the central server for active approvals before re-blocking (1.5 s timeout, silent fallback to local).
- **Deploy**: `Dockerfile` + `docker-compose.yml` (Postgres) + Helm chart in `deploy/helm/claude-guardian` (EKS/ALB/RDS). Client rollout via `enterprise/install-agent.sh --server <url> --key <agent-key>` (wraps `init --central-url --central-key`; also installs the daemon as a systemd/launchd service) or `enterprise/install-agent.ps1` on Windows (scheduled task). Docs: `docs/ENTERPRISE.md`.

### Browser extension (`extension/`)

MV3 extension (plain JS, no build step; `manifest.firefox.json` for Firefox) covering claude.ai, ChatGPT, Gemini, Copilot, Mistral and Adapta One. `injected.js` runs as a `world: "MAIN"` content script hooking `fetch`/XHR (per-site `ADAPTERS` registry, fail-closed); messages between `content.js` and `injected.js` are authenticated by a `crypto.getRandomValues` nonce handed over via DOM attribute at `document_start` (anti-spoof). Scans go through `background.js` → local daemon `POST /api/scan-web` (`src/lib/web-scan.ts`, virtual tools `WebPrompt`/`WebUpload`; route registered only in SQLite mode). Enterprise config comes from `chrome.storage.managed` (options page becomes read-only). Adapters for Gemini/Copilot/Mistral/Adapta still need real-traffic validation — see `docs/ADAPTER-VALIDATION.md`.

**Model restriction**: adapters with a JSON `model` field (claude.ai, ChatGPT, Copilot, Mistral, Adapta) expose `extractModel(body)`; `decide()` forwards it as `context.model` and `scanWeb` blocks when it matches `config.blockedWebModels` (managed via the dashboard "Modelos bloqueados no navegador" card). The check runs before any content scan and also fires on empty prompts (the `!text` fail-open path still scans when a model is present).

**Attachment enforcement**: uploads are caught at the network layer in `injected.js` (endpoint-agnostic: any `fetch`/XHR body that is `FormData`/`File`/`Blob` → scanned as files). Small text files on claude.ai are NOT multipart uploads — the content is inlined into the `/completion` request as `attachments[].extracted_content`, so `claudeAdapter.extractText` reads that field too. Attachments are **fail-closed** (block when the daemon can't verify) via `adapter.carriesAttachment()`; plain text stays fail-open. Drag-and-drop is site-aware: most sites are blocked at the UI layer (`content.js`, with a synthetic-event overlay reset), but hosts in `NETWORK_ENFORCED_DROP` (claude.ai — its overlay ignores untrusted events) are left to the network/`/completion` layer instead.

### GUI Gateway (Claude Desktop / Kiro IDE) — `src/proxy/`

`src/proxy/mcp-proxy.ts` is a stdio shim injected into the MCP configs of Claude Desktop and Kiro IDE by `init` (`src/lib/mcp-install.ts`, idempotent + `.guardian.bak` backup). The client spawns the shim instead of the real MCP server; the shim spawns the real one and scans the JSON-RPC stream via `src/lib/mcp-scan.ts` (`scanMcp`, virtual tools `McpToolCall`/`McpToolResult`), reusing the same engine/policy/audit pipeline in-process (no daemon needed). Block = JSON-RPC error `-32001`.

**Phase 2 (HTTPS proxy — prompt/attachment on Claude Desktop):** `src/proxy/https-proxy.ts` is a selective CONNECT proxy (MITM only `*.anthropic.com`, passthrough otherwise) that terminates TLS with a per-SNI cert issued by the guardian CA (`src/lib/mitm-ca.ts`, node-forge), reads the HTTP/2 request and scans it via `src/lib/gui-scan.ts` (`scanGui`, virtual tools `DesktopPrompt`/`DesktopUpload`). Start it with `GUARDIAN_PROXY_PORT=<port> claude-guardian serve` (local mode). Verified: Claude Desktop does not cert-pin. The CA (`<db-dir>/guardian-ca.crt`) is distributed via MDM. Remaining: MDM CA/proxy artifacts + fleet tamper heartbeat. Docs: `docs/GUI-GATEWAY.md`.

### Fleet & managed settings

- `src/lib/managed-settings.ts` compiles console + MDM artifacts (`emit-managed-settings` CLI); `src/lib/browser-policies.ts` compiles browser policies per channel (Linux JSON, Windows `.reg`, macOS `.mobileconfig`, Firefox `policies.json`) when `--extension-id` is passed.
- `machines` table + `POST /api/agent/heartbeat` + `GET /api/fleet` (status via `computeMachineStatus`: hash mismatch or required-but-silent extension = `tampered`, silent machine = `stale`). Local daemon receives `POST /api/extension/heartbeat` (chrome.alarms ping every 5 min, carries `extractFailures` per provider = endpoint-drift signal) and mirrors machine heartbeats to the central every 5 min (`src/lib/fleet-client.ts`, best-effort).
- `GUARDIAN_BIND_HOST` controls the server bind address (`GUARDIAN_HOST` is reserved for hook host detection claude/kiro in `src/hosts/`).

## Key behaviors to know

- **`[allow-guardian]`** in the user's last message bypasses `pre-tool-use` entirely (checked by reading the transcript JSONL).
- **`[request-exception: <reason>]`** in a blocked prompt creates a pending approval and blocks with a dashboard URL.
- `.env` files are blocked by filename alone in `pre-tool-use`, before any content is read.
- `cat`/`head`/`tail`/etc. commands in Bash are parsed to extract file paths, which are then scanned.
- Env var values referenced in Bash commands (`$VAR`, `${VAR}`) are resolved from `process.env` and scanned.
- Engine timeout always blocks (fail-safe), not allow.
