import { readFileSync } from "node:fs";
import { loadConfig } from "../../config/loader.ts";
import { scan } from "../../engine/index.ts";
import { evaluatePolicy } from "../../lib/policy.ts";

interface ScanOptions {
  text?: boolean;
  config?: string;
  json?: boolean;
}

export async function cmdScan(
  target: string,
  opts: ScanOptions,
): Promise<void> {
  const config = loadConfig(opts.config);

  let content: string;
  if (opts.text) {
    content = target;
  } else {
    try {
      content = readFileSync(target, "utf8");
    } catch (err) {
      process.stderr.write(`Cannot read file: ${String(err)}\n`);
      process.exit(1);
    }
  }

  const { findings, elapsedMs, timedOut } = await scan(content, {
    timeoutMs: config.engineTimeoutMs,
    allowlist: config.allowlist,
  });

  if (timedOut) {
    process.stderr.write(
      `⚠ Engine timeout after ${config.engineTimeoutMs}ms — partial results\n`,
    );
  }

  if (opts.json) {
    process.stdout.write(
      JSON.stringify({ findings, elapsedMs, timedOut }, null, 2) + "\n",
    );
    return;
  }

  if (findings.length === 0) {
    console.log(`✓ No sensitive data found (${elapsedMs}ms)`);
    return;
  }

  const action = evaluatePolicy(findings, "scan", config.policies);
  console.log(
    `claude-guardian scan (${elapsedMs}ms) — ${findings.length} finding(s) — policy: ${action}\n`,
  );

  for (const f of findings) {
    const sev = f.severity.toUpperCase().padEnd(8);
    console.log(`  [${sev}] ${f.label} (${f.detectorId}): ${f.snippet}`);
    console.log(`           confidence: ${(f.confidence * 100).toFixed(0)}%`);
  }

  process.exit(findings.length > 0 ? 1 : 0);
}
