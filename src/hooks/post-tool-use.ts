#!/usr/bin/env -S node --experimental-strip-types

import { existsSync } from "node:fs";
import { join } from "node:path";

if (existsSync(join(process.cwd(), ".guardian-bypass"))) process.exit(0);

import { loadConfig } from "../config/loader.ts";
import { getDb } from "../db/client.ts";
import { loadCustomDetectors } from "../engine/detectors/custom.ts";
import { scanSync } from "../engine/index.ts";
import { appendAuditEntry } from "../lib/audit.ts";
import { recordIncident } from "../lib/incident.ts";
import { evaluatePolicy } from "../lib/policy.ts";

// PostToolUse hook: audit-only, never blocks.
// Records incidents when secrets appear in tool responses.

interface HookInput {
  session_id?: string;
  tool_name?: string;
  tool_response?: {
    output?: string;
    content?: string;
  };
}

let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk: string) => (raw += chunk));
process.stdin.on("end", () => {
  let data: HookInput;
  try {
    data = JSON.parse(raw) as HookInput;
  } catch {
    process.exit(0);
  }

  const tool = data.tool_name ?? "";
  const response = data.tool_response ?? {};
  const content = response.output ?? response.content ?? "";
  const sessionId = data.session_id ?? "";

  if (!content) process.exit(0);

  let config: ReturnType<typeof loadConfig>;
  try {
    config = loadConfig();
  } catch {
    process.exit(0);
  }

  const db = getDb(config.dbPath);
  const customDetectors = loadCustomDetectors(db);

  const { findings, timedOut } = scanSync(content, {
    timeoutMs: config.engineTimeoutMs,
    allowlist: config.allowlist,
    extraDetectors: customDetectors,
  });

  if (timedOut || findings.length === 0) process.exit(0);

  const action = evaluatePolicy(findings, tool, config.policies);
  if (action === "allow") process.exit(0);

  try {
    const incident = recordIncident(db, `${tool}:response`, sessionId, findings, "block");
    appendAuditEntry(db, "post-tool-response-audit", {
      incidentId: incident.id,
      tool,
      dataTypes: incident.dataTypes,
    });
  } catch {
    // Never let post-hook errors propagate — the tool already executed.
  }

  process.exit(0);
});
