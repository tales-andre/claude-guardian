import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { Severity } from "../../types/index.ts";
import type { Detector, DetectorFinding } from "./types.ts";
import { makeFinding } from "./types.ts";

// Gitleaks v8 JSON report entry (subset we consume).
interface GitleaksLeak {
  Description: string;
  Secret: string;
  RuleID: string;
  Tags: string[];
  Entropy: number;
}

// Derive severity from gitleaks tags first, then from the rule ID family.
// Gitleaks default ruleset doesn't include severity tags, so the fallback
// covers the common rule-ID naming patterns from gitleaks-rules.toml.
function inferSeverity(ruleId: string, tags: string[]): Severity {
  for (const tag of tags) {
    switch (tag.toLowerCase()) {
      case "critical":
        return "critical";
      case "high":
        return "high";
      case "medium":
        return "medium";
      case "low":
        return "low";
    }
  }
  if (/private-key|rsa|dsa|ec-key|openssh|pgp/.test(ruleId)) return "critical";
  if (/aws.*key|gcp|azure|alibaba|github|gitlab|bitbucket/.test(ruleId))
    return "critical";
  if (/stripe|openai|anthropic|shopify|heroku|paypal|braintree/.test(ruleId))
    return "high";
  if (/slack|sendgrid|mailgun|discord|telegram|twilio|jwt/.test(ruleId))
    return "high";
  return "medium";
}

// Locate the gitleaks binary: check PATH, then common install prefixes.
function findGitleaksBinary(): string | null {
  const probe = spawnSync(
    process.platform === "win32" ? "where" : "which",
    ["gitleaks"],
    { encoding: "utf8", timeout: 2000 },
  );
  if (probe.status === 0) {
    const first = probe.stdout.split("\n")[0]?.trim();
    if (first) return first;
  }
  for (const candidate of [
    "/usr/local/bin/gitleaks",
    "/usr/bin/gitleaks",
    path.join(os.homedir(), ".local", "bin", "gitleaks"),
    path.join(os.homedir(), "go", "bin", "gitleaks"),
  ]) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

// Cached after first lookup so repeated calls within one process are free.
let _binary: string | null | undefined;
function binary(): string | null {
  if (_binary === undefined) _binary = findGitleaksBinary();
  return _binary;
}

/**
 * Run gitleaks on arbitrary text and return findings.
 * Returns [] when gitleaks is not installed — callers should treat this as
 * "no additional findings", not as an error.
 *
 * Installation (one command):
 *   curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/main/scripts/install.sh \
 *     | sh -s -- -b /usr/local/bin
 */
export function scanWithGitleaks(text: string): DetectorFinding[] {
  const bin = binary();
  if (!bin) return [];

  // Write to a temp directory: gitleaks --source requires a path, not stdin.
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cg-gl-"));
  try {
    fs.writeFileSync(path.join(tmpDir, "scan.txt"), text, "utf8");
    const reportPath = path.join(tmpDir, "report.json");

    const result = spawnSync(
      bin,
      [
        "detect",
        `--source=${tmpDir}`,
        "--no-git",
        "--report-format=json",
        `--report-path=${reportPath}`,
        "--exit-code=0", // always exit 0; we read findings from JSON
        "--quiet",
      ],
      { timeout: 400, encoding: "utf8" },
    );

    if (result.error || !fs.existsSync(reportPath)) return [];

    const raw = fs.readFileSync(reportPath, "utf8").trim();
    if (!raw || raw === "null") return [];

    const leaks: GitleaksLeak[] = JSON.parse(raw) ?? [];
    return leaks
      .filter((l) => Boolean(l.Secret))
      .map((l) => {
        const sev = inferSeverity(l.RuleID, l.Tags ?? []);
        const snippet =
          l.Secret.length <= 8
            ? "****"
            : `${l.Secret.slice(0, 4)}****${l.Secret.slice(-4)}`;
        // Confidence scales with entropy: high-entropy secrets are more reliable.
        const confidence = Math.min(0.97, 0.72 + l.Entropy * 0.05);
        return makeFinding(
          {
            id: `gl:${l.RuleID}`,
            label: l.Description,
            dataType: "generic-secret",
            severity: sev,
          },
          l.Secret,
          snippet,
          0,
          l.Secret.length,
          confidence,
        );
      });
  } catch {
    return [];
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  }
}

export const gitleaksDetector: Detector = {
  id: "gitleaks",
  label: "Gitleaks Secret Scanner",
  dataType: "generic-secret",
  severity: "high",
  scan: scanWithGitleaks,
};
