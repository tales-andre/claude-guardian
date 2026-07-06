import { redact } from "../utils.ts";
import type { Detector, DetectorFinding } from "./types.ts";
import { makeFinding } from "./types.ts";

// Database connection strings with embedded credentials.
// Matched as: scheme://user:password@host — password is the captured group.
const CONN_RE =
  /(mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis(?:s)?|mssql|amqp(?:s)?|jdbc:[a-z]+):\/\/([^:\s@]{1,64}):([^@\s]{1,256})@/g;

// DSN-style: key=value pairs with password keyword.
const DSN_RE = /(?:password|passwd|pwd)\s*=\s*([^;\s]{4,128})/gi;

export const connectionStringDetector: Detector = {
  id: "connection-string",
  label: "Database / Service Connection String",
  dataType: "connection-string",
  severity: "critical",
  pattern: CONN_RE.source,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(CONN_RE)) {
      const password = m[3];
      if (!password) continue;
      findings.push(
        makeFinding(
          this,
          password,
          `[${m[1] ?? "db"}://user:${redact(password)}@...]`,
          m.index,
          m.index + m[0].length,
          0.92,
        ),
      );
    }
    return findings;
  },
};

export const dsnPasswordDetector: Detector = {
  id: "dsn-password",
  label: "DSN Password Parameter",
  dataType: "connection-string",
  severity: "high",
  pattern: DSN_RE.source,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(DSN_RE)) {
      const raw = m[1];
      if (!raw) continue;
      findings.push(
        makeFinding(
          this,
          raw,
          redact(raw),
          m.index,
          m.index + m[0].length,
          0.8,
        ),
      );
    }
    return findings;
  },
};
