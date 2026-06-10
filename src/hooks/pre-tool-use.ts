#!/usr/bin/env -S node --experimental-strip-types

import {
  closeSync,
  existsSync,
  openSync,
  readFileSync,
  readSync,
  statSync,
} from "node:fs";
import { basename, join } from "node:path";

if (existsSync(join(process.cwd(), ".guardian-bypass"))) process.exit(0);

import { loadConfig } from "../config/loader.ts";
import { getDb } from "../db/client.ts";
import { loadCustomDetectors } from "../engine/detectors/custom.ts";
import { scanSync } from "../engine/index.ts";
import {
  buildScope,
  createApproval,
  findActiveApproval,
} from "../lib/approval.ts";
import { appendAuditEntry } from "../lib/audit.ts";
import {
  buildApprovalBlockReason,
  buildBlockReason,
  recordIncident,
} from "../lib/incident.ts";
import { evaluatePolicy, findApprovalTtl } from "../lib/policy.ts";
import type { DataType, DetectorFinding } from "../types/index.ts";

// ── Hook contract ─────────────────────────────────────────────────────────────
// Input:  JSON on stdin — { session_id?, transcript_path?, tool_name, tool_input }
// Output: JSON on stdout when blocking — { decision: "block", reason: "..." }
// Exit 0: allow  |  Exit 2: block

const MAX_FILE_BYTES = 1_048_576; // 1 MB

interface HookInput {
  session_id?: string;
  transcript_path?: string;
  tool_name?: string;
  tool_input?: {
    file_path?: string;
    command?: string;
    content?: string;
    new_string?: string;
  };
}

function blockAndExit(reason: string): never {
  process.stdout.write(JSON.stringify({ decision: "block", reason }) + "\n");
  process.exit(2);
}

function allowAndExit(): never {
  process.exit(0);
}

function readFileSafe(filePath: string): string | null {
  try {
    const stat = statSync(filePath);
    const size = Math.min(stat.size, MAX_FILE_BYTES);
    if (size === 0) return null;
    const buf = Buffer.alloc(size);
    const fd = openSync(filePath, "r");
    try {
      readSync(fd, buf, 0, size, 0);
    } finally {
      closeSync(fd);
    }
    const nulIdx = buf.indexOf(0);
    const text = (nulIdx === -1 ? buf : buf.subarray(0, nulIdx)).toString(
      "utf8",
    );
    return text.length > 0 ? text : null;
  } catch {
    return null;
  }
}

function isEnvFile(filePath: string): boolean {
  const base = basename(filePath);
  return base === ".env" || base.startsWith(".env.");
}

const ENV_VAR_RE = /\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g;
const FILE_READ_CMDS = new Set([
  "cat",
  "head",
  "tail",
  "less",
  "more",
  "bat",
  "nl",
]);

function extractEnvNames(cmd: string): string[] {
  const names = new Set<string>();
  for (const m of cmd.matchAll(ENV_VAR_RE)) {
    const name = m[1] ?? m[2];
    if (name) names.add(name);
  }
  return [...names];
}

function extractReadFilePaths(command: string): string[] {
  const paths: string[] = [];
  for (const segment of command.split(/\s*[|;&]+\s*/)) {
    const tokens = segment.trim().split(/\s+/).filter(Boolean);
    if (tokens.length < 2) continue;
    const cmd = basename(tokens[0] ?? "");
    if (!FILE_READ_CMDS.has(cmd)) continue;
    let skip = false;
    for (let i = 1; i < tokens.length; i++) {
      if (skip) {
        skip = false;
        continue;
      }
      const tok = tokens[i];
      if (!tok || tok.startsWith("-")) continue;
      if (tok === ">" || tok === ">>" || tok === "<") {
        skip = true;
        continue;
      }
      paths.push(tok);
    }
  }
  return [...new Set(paths)];
}

function checkAllowTag(transcriptPath: string | undefined): boolean {
  if (!transcriptPath) return false;
  try {
    const content = readFileSync(transcriptPath, "utf8");
    const lines = content.split("\n").filter(Boolean);
    for (let i = lines.length - 1; i >= 0; i--) {
      try {
        const parsed = JSON.parse(lines[i] ?? "") as {
          message?: { role?: string; content?: unknown };
        };
        const msg = parsed.message;
        if (!msg) continue;
        if (msg.role !== "user") continue;
        const text = typeof msg.content === "string" ? msg.content : "";
        return text.includes("[allow-guardian]");
      } catch {}
    }
  } catch {
    // ignore
  }
  return false;
}

// ── Main ──────────────────────────────────────────────────────────────────────

let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk: string) => (raw += chunk));
process.stdin.on("end", () => {
  const config = loadConfig();
  let data: HookInput;

  try {
    data = JSON.parse(raw) as HookInput;
  } catch {
    allowAndExit();
  }

  const tool = data.tool_name ?? "";
  const input = data.tool_input ?? {};
  const sessionId = data.session_id ?? "";

  if (checkAllowTag(data.transcript_path)) allowAndExit();

  const db = getDb(config.dbPath);
  const customDetectors = loadCustomDetectors(db);

  function doBlock(findings: DetectorFinding[]): string {
    const incident = recordIncident(db, tool, sessionId, findings, "block");
    appendAuditEntry(db, "block", {
      incidentId: incident.id,
      tool,
      dataTypes: incident.dataTypes,
      severities: incident.severities,
    });
    return incident.id;
  }

  function scanAndDecide(text: string, source: string): void {
    const { findings, timedOut } = scanSync(text, {
      timeoutMs: config.engineTimeoutMs,
      allowlist: config.allowlist,
      extraDetectors: customDetectors,
    });

    if (timedOut) {
      blockAndExit(
        `claude-guardian: engine timeout scanning ${source} — blocked by default`,
      );
    }

    if (findings.length === 0) return;

    const action = evaluatePolicy(findings, tool, config.policies);
    if (action === "allow") return;

    if (action === "require-approval") {
      const scope = buildScope(tool, [
        ...new Set(findings.map((f) => f.dataType)),
      ] as DataType[]);
      const active = findActiveApproval(db, scope);
      if (active) return;
      const incident = recordIncident(
        db,
        tool,
        sessionId,
        findings,
        "require-approval",
      );
      createApproval(
        db,
        incident.id,
        scope,
        "",
        findApprovalTtl(findings, tool, config.policies),
      );
      appendAuditEntry(db, "block-require-approval", {
        incidentId: incident.id,
        tool,
        dataTypes: incident.dataTypes,
      });
      blockAndExit(buildApprovalBlockReason(tool, findings, incident.id));
    }

    const incidentId = doBlock(findings);
    blockAndExit(buildBlockReason(source, findings, incidentId));
  }

  // ── Read tool ──────────────────────────────────────────────────────────────
  if (tool === "Read") {
    const filePath = input.file_path ?? "";
    if (!filePath) allowAndExit();

    if (isEnvFile(filePath)) {
      const sentinel: DetectorFinding = {
        detectorId: "env-file-name",
        label: ".env file (name-based block)",
        dataType: "generic-secret",
        severity: "critical",
        snippet: basename(filePath),
        rawValue: basename(filePath),
        position: { start: 0, end: 0 },
        confidence: 1.0,
      };
      const incidentId = doBlock([sentinel]);
      blockAndExit(buildBlockReason(filePath, [sentinel], incidentId));
    }

    const content = readFileSafe(filePath);
    if (!content) allowAndExit();
    scanAndDecide(content, filePath);
    allowAndExit();
  }

  // ── Bash tool ──────────────────────────────────────────────────────────────
  if (tool === "Bash") {
    const command = input.command ?? "";

    for (const varName of extractEnvNames(command)) {
      const value = process.env[varName];
      if (!value) continue;
      scanAndDecide(value, `$${varName}`);
    }

    scanAndDecide(command, "bash command");

    for (const fp of extractReadFilePaths(command)) {
      if (isEnvFile(fp)) {
        const sentinel: DetectorFinding = {
          detectorId: "env-file-name",
          label: ".env file (name-based block)",
          dataType: "generic-secret",
          severity: "critical",
          snippet: basename(fp),
          rawValue: basename(fp),
          position: { start: 0, end: 0 },
          confidence: 1.0,
        };
        const incidentId = doBlock([sentinel]);
        blockAndExit(buildBlockReason(`cat ${fp}`, [sentinel], incidentId));
      }
      const content = readFileSafe(fp);
      if (!content) continue;
      scanAndDecide(content, fp);
    }

    allowAndExit();
  }

  // ── Write / Edit tools ─────────────────────────────────────────────────────
  if (tool === "Write" || tool === "Edit") {
    const content =
      tool === "Write" ? (input.content ?? "") : (input.new_string ?? "");
    if (content) scanAndDecide(content, `${tool} content`);
    allowAndExit();
  }

  allowAndExit();
});
