import type {
  AllowlistEntry,
  DetectorFinding,
  ScanResult,
} from "../types/index.ts";
import { BUILT_IN_DETECTORS } from "./detectors/index.ts";
import type { Detector } from "./detectors/types.ts";

// Two-pass deduplication:
// 1. Remove same-detector duplicates (original per-detector dedup).
// 2. Suppress gitleaks findings whose rawValue was already caught by a
//    built-in detector — prevents double-reporting the same secret when
//    both layers match (e.g., our AWS detector + gitleaks aws-access-key-id).
function dedup(findings: DetectorFinding[]): DetectorFinding[] {
  const seen = new Set<string>();
  const dedupedByDetector = findings.filter((f) => {
    const key = `${f.detectorId}:${f.rawValue}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const builtInValues = new Set(
    dedupedByDetector
      .filter((f) => !f.detectorId.startsWith("gl:"))
      .map((f) => f.rawValue),
  );
  return dedupedByDetector.filter(
    (f) => !f.detectorId.startsWith("gl:") || !builtInValues.has(f.rawValue),
  );
}

function matchesAllowlist(
  finding: DetectorFinding,
  allowlist: AllowlistEntry[],
): boolean {
  const now = new Date().toISOString();
  for (const entry of allowlist) {
    if (entry.expiresAt && entry.expiresAt < now) continue;
    if (entry.detectorIds && !entry.detectorIds.includes(finding.detectorId))
      continue;
    if (entry.isRegex) {
      try {
        if (new RegExp(entry.pattern).test(finding.rawValue)) return true;
      } catch {
        // invalid regex in allowlist entry — skip
      }
    } else {
      if (finding.rawValue.includes(entry.pattern)) return true;
    }
  }
  return false;
}

export interface EngineOptions {
  timeoutMs?: number;
  allowlist?: AllowlistEntry[];
  extraDetectors?: Detector[];
}

export async function scan(
  text: string,
  options: EngineOptions = {},
): Promise<ScanResult> {
  const { timeoutMs = 500, allowlist = [], extraDetectors = [] } = options;
  const detectors = [...BUILT_IN_DETECTORS, ...extraDetectors];

  const start = Date.now();

  const scanPromise = new Promise<DetectorFinding[]>((resolve, reject) => {
    try {
      const all: DetectorFinding[] = [];
      for (const detector of detectors) {
        const results = detector.scan(text);
        all.push(...results);
      }
      resolve(all);
    } catch (err) {
      reject(err);
    }
  });

  const timeoutPromise = new Promise<"timeout">((resolve) =>
    setTimeout(() => resolve("timeout"), timeoutMs),
  );

  const result = await Promise.race([scanPromise, timeoutPromise]);

  if (result === "timeout") {
    return { findings: [], elapsedMs: Date.now() - start, timedOut: true };
  }

  const filtered = dedup(result).filter((f) => !matchesAllowlist(f, allowlist));

  return { findings: filtered, elapsedMs: Date.now() - start, timedOut: false };
}

// Synchronous scan for hook context where async is not needed (must be fast).
export function scanSync(
  text: string,
  options: EngineOptions = {},
): ScanResult {
  const { timeoutMs = 500, allowlist = [], extraDetectors = [] } = options;
  const detectors = [...BUILT_IN_DETECTORS, ...extraDetectors];
  const start = Date.now();

  try {
    const all: DetectorFinding[] = [];
    for (const detector of detectors) {
      if (Date.now() - start >= timeoutMs) {
        return { findings: [], elapsedMs: Date.now() - start, timedOut: true };
      }
      const results = detector.scan(text);
      all.push(...results);
    }
    const filtered = dedup(all).filter((f) => !matchesAllowlist(f, allowlist));
    return {
      findings: filtered,
      elapsedMs: Date.now() - start,
      timedOut: false,
    };
  } catch {
    return { findings: [], elapsedMs: Date.now() - start, timedOut: true };
  }
}
