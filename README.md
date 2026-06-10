# claude-guardian

Enterprise-grade Data Loss Prevention (DLP) platform for Claude Code. Intercepts prompts, file reads, bash commands, and writes **before** any data leaves your machine, with an auditable governance dashboard and approval workflow.

## Architecture

```
Claude Code ──────────────────────────────────────────────────────────────────┐
                                                                               │
  UserPromptSubmit ──► user-prompt-submit.ts ──┐                               │
  PreToolUse       ──► pre-tool-use.ts ─────── ┤                               │
  PostToolUse      ──► post-tool-use.ts ───────┘                               │
                                │                                               │
                                ▼                                               │
                     ┌─────────────────────┐                                   │
                     │  Detection Engine   │  (scanSync, <500ms, fail-safe)    │
                     │  40+ detectors      │  regex + entropy + Luhn/CPF/IBAN  │
                     └──────────┬──────────┘                                   │
                                │                                               │
                                ▼                                               │
                     ┌─────────────────────┐                                   │
                     │  Policy Engine      │  evaluatePolicy(findings, tool)   │
                     │  (declarative rules)│  allow / block / require-approval │
                     └──────────┬──────────┘                                   │
                                │                                               │
              ┌─────────────────┼─────────────────┐                            │
              ▼                 ▼                  ▼                            │
           allow             block          require-approval                    │
              │                │                   │                            │
              │         ┌──────┴────────┐   ┌──────┴──────────┐                │
              │         │  SQLite DB    │   │  Check active   │                │
              │         │  recordIncident│  │  approval scope │                │
              │         │  auditEntry   │   └──────┬──────────┘                │
              │         └──────────────┘          │                            │
              ▼                ▼              allow or block                   │
            exit 0          exit 2                │                            │
                        {"decision":"block",       ▼                            │
                         "reason":"..."}      claude-guardian approve <id>     │
                                                                               │
                                                    ▼                           │
                                         ┌──────────────────┐                  │
                                         │  Dashboard       │ localhost:7734   │
                                         │  Incidents  │  Approvals           │
                                         │  Audit log  │  Metrics             │
                                         └──────────────────┘                  │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Install

```bash
npm install -g claude-guardian
# or locally:
npm install claude-guardian
```

### 2. Initialize

```bash
claude-guardian init
```

This command:
- Creates `~/.config/claude-guardian/config.json` (with a generated dashboard token)
- Initializes the SQLite database at `~/.local/share/claude-guardian/guardian.db`
- Registers hooks in `~/.claude/settings.json`

Restart Claude Code to activate the hooks.

### 3. Start the Dashboard

```bash
claude-guardian serve
# → Dashboard at http://localhost:7734/dashboard
```

## Enterprise Mode

Para distribuir o guardian em todas as máquinas de uma empresa com um
**dashboard central** para o administrador, PostgreSQL e deploy em
Docker/EKS — sem mudar nada do modo local acima:

```bash
# Servidor central (Docker Compose)
cp deploy/docker.env.example .guardian.env   # edite os valores
docker compose --env-file .guardian.env up -d

# Em cada máquina de desenvolvedor
bash enterprise/install-agent.sh \
  --server https://guardian.empresa.com --key <GUARDIAN_AGENT_KEY>
```

Os hooks continuam decidindo localmente (mesma latência); incidentes são
espelhados ao servidor central via fila store-and-forward e as aprovações são
concedidas pelo admin no dashboard central. Segredos brutos nunca saem da
máquina de origem.

Guia completo (EKS/Helm, RDS, modelo de segurança): [docs/ENTERPRISE.md](docs/ENTERPRISE.md)

## Hook Registration (Manual)

If you prefer to register hooks manually, add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": ".*",
      "hooks": [{
        "type": "command",
        "command": "node --experimental-strip-types /path/to/claude-guardian/src/hooks/pre-tool-use.ts"
      }]
    }],
    "UserPromptSubmit": [{
      "hooks": [{
        "type": "command",
        "command": "node --experimental-strip-types /path/to/claude-guardian/src/hooks/user-prompt-submit.ts"
      }]
    }],
    "PostToolUse": [{
      "matcher": ".*",
      "hooks": [{
        "type": "command",
        "command": "node --experimental-strip-types /path/to/claude-guardian/src/hooks/post-tool-use.ts"
      }]
    }]
  }
}
```

> **Note:** The hook adapter contract is isolated in `src/hooks/`. If the Claude Code hook protocol changes between versions, only these three files need updating.

## CLI Reference

### `claude-guardian init [--show-token] [--hooks-dir <path>]`
Initialize database, config, and Claude Code hooks.

### `claude-guardian serve [-p <port>]`
Start the governance dashboard at `http://127.0.0.1:<port>`.

### `claude-guardian scan <file-or-text> [--text] [--json]`
Scan a file or literal text for sensitive data.

```bash
claude-guardian scan ./config.env
claude-guardian scan --text "my key is AKIAIOSFODNN7EXAMPLE"
claude-guardian scan --text "..." --json   # machine-readable output
```

### `claude-guardian approve <incidentId> -r "<reason>" [--ttl <seconds>]`
Grant an exception for a blocked incident. The approval is scoped to the tool + data-type combination and expires after TTL seconds (default: 3600).

```bash
claude-guardian approve a1b2c3d4e5f6 --reason "debugging prod outage" --ttl 1800
```

### `claude-guardian deny <incidentId>`
Deny a pending approval request.

### `claude-guardian policy list`
List all active policy rules.

## Configuration

Edit `~/.config/claude-guardian/config.json` (or `./claude-guardian.config.json` in the project root — local config takes precedence):

```json
{
  "dbPath": "~/.local/share/claude-guardian/guardian.db",
  "logLevel": "info",
  "dashboardPort": 7734,
  "dashboardToken": "<generated-at-init>",
  "engineTimeoutMs": 500,
  "policies": [
    {
      "id": "block-critical-secrets",
      "name": "Block critical secrets",
      "enabled": true,
      "dataTypes": ["aws-key", "private-key", "anthropic-key"],
      "minSeverity": "critical",
      "action": "block"
    },
    {
      "id": "pii-approval",
      "name": "Require approval for PII",
      "enabled": true,
      "dataTypes": ["email", "credit-card", "cpf"],
      "action": "require-approval",
      "ttlSeconds": 3600
    }
  ],
  "allowlist": [
    {
      "id": "docs-example",
      "pattern": "AKIAIOSFODNN7EXAMPLE",
      "isRegex": false,
      "reason": "AWS documentation placeholder key"
    }
  ]
}
```

### Policy Actions

| Action | Behavior |
|--------|----------|
| `block` | Hard block. Decision recorded. User must add `[allow-guardian]` to bypass. |
| `require-approval` | Blocks on first occurrence. Run `claude-guardian approve <id>` to grant a time-limited exception. |
| `redact` | For `UserPromptSubmit`: replaces raw values with `[REDACTED:<detectorId>]`. |
| `allow` | Explicit allow (overrides lower-priority rules). |

Rules are evaluated in order; the **highest-priority** matching action wins (`block > require-approval > redact > allow`).

### Bypass

Add `[allow-guardian]` to your prompt to bypass all checks for the current turn. This bypass is **recorded in the audit log**.

```
[allow-guardian] Please read my .env file to debug this issue
```

To request a formal exception inline, use `[request-exception: <reason>]`. This creates a pending approval entry and returns the dashboard URL instead of blocking silently:

```
[request-exception: debugging prod outage] Please read config.yaml
```

## Detectors

| Detector | Data Type | Severity |
|----------|-----------|---------|
| AWS Access Key ID | `aws-key` | critical |
| AWS Secret Access Key | `aws-key` | critical |
| Anthropic API Key | `anthropic-key` | critical |
| OpenAI Legacy Key | `openai-key` | critical |
| OpenAI Project Key | `openai-key` | critical |
| GitHub PAT / Fine-grained | `github-token` | critical |
| GitLab PAT / CI / Runner | `gitlab-token` | high |
| Stripe Secret/Restricted Key | `stripe-key` | critical/high |
| GCP API Key | `gcp-key` | high |
| GCP Service Account JSON | `gcp-key` | critical |
| npm Token | `npm-token` | high |
| Slack Token / Webhook | `slack-token` | high |
| Discord Webhook | `generic-secret` | high |
| SendGrid API Key | `sendgrid-key` | high |
| JWT | `jwt` | high |
| PEM Private Key | `private-key` | critical |
| Database Connection String | `connection-string` | critical |
| Generic API Key (context-anchored) | `generic-secret` | medium |
| .env SECRET/PASSWORD assignment | `generic-secret` | medium |
| Credit Card (Luhn-validated) | `credit-card` | high |
| US SSN | `ssn` | high |
| Brazilian CPF (validated) | `cpf` | high |
| Brazilian CNPJ (validated) | `cnpj` | high |
| IBAN (validated) | `iban` | high |
| Email Address | `email` | medium |
| Brazilian Phone | `phone-br` | medium |
| US Phone | `phone-us` | low |
| Private IPv4 (RFC-1918) | `private-ip` | low |

### Adding a Custom Detector

Create a file `src/engine/detectors/my-detector.ts`:

```typescript
import type { Detector, DetectorFinding } from "./types.ts";
import { redact } from "../utils.ts";

const MY_PATTERN = /MY_SECRET_[A-Z0-9]{32}/g;

export const myDetector: Detector = {
  id: "my-secret",
  label: "My Corporate Secret",
  dataType: "my-secret",
  severity: "critical",
  scan(text): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(MY_PATTERN)) {
      findings.push({
        detectorId: this.id, label: this.label, dataType: this.dataType,
        severity: this.severity, snippet: redact(m[0]), rawValue: m[0],
        position: { start: m.index, end: m.index + m[0].length },
        confidence: 0.97,
      });
    }
    return findings;
  },
};
```

Then add it to `src/engine/detectors/index.ts` and `BUILT_IN_DETECTORS`. No changes to the engine core required.

## Audit Log

The audit log is an append-only SQLite table with SHA-256 hash chaining. Each entry includes:
- `seq`: monotonically increasing sequence number
- `timestamp`: ISO-8601 UTC timestamp
- `type`: event type (`block`, `approval-granted`, `redact`, etc.)
- `payload`: JSON (no raw secret values — always redacted/hashed)
- `prev_hash`: hash of the previous entry
- `hash`: SHA-256 of `seq|timestamp|type|payload|prev_hash`

To verify chain integrity:

```bash
# Via API
curl http://localhost:7734/api/audit/verify

# Via dashboard: Audit Log tab → "Verify Chain" button
```

A tampered entry is detected by recomputing every hash and comparing with stored values.

## Security Design

- **Fail-safe**: Any error, exception, or timeout in the detection engine results in a **block** decision. Never leaks on failure.
- **No raw secrets in persistence**: Only redacted snippets (e.g., `AKIA****MPLE`) are written to SQLite or log files.
- **Local only**: Dashboard binds to `127.0.0.1` only, never `0.0.0.0`.
- **Dashboard token**: Generated at `init` time. Stored in config file, required for all API calls.
- **ReDoS protection**: All regex patterns are linear (no nested quantifiers, no catastrophic backtracking).
- **Engine timeout**: Default 500ms. If scanning takes longer, the request is blocked (default-deny).

## Requirements

- Node.js ≥ 22.6.0
- Claude Code (any version supporting hooks)
- `npm install` (installs `better-sqlite3`, `fastify`, `commander`, `zod`, `pino`)

## Development

```bash
npm install
npm test          # run test suite
npm run typecheck # TypeScript type checking
npm run lint      # Biome lint
npm run ci        # typecheck + lint + test
```
