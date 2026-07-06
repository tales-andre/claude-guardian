import type { Detector, DetectorFinding } from "./types.ts";
import { makeFinding } from "./types.ts";

// RFC-1918 private IPv4 ranges only — public IPs are not PII.
const PRIVATE_IP_RE =
  /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g;

export const privateIpDetector: Detector = {
  id: "pii-private-ip",
  label: "Private IPv4 Address (RFC-1918)",
  dataType: "private-ip",
  severity: "low",
  pattern: PRIVATE_IP_RE.source,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(PRIVATE_IP_RE)) {
      const raw = m[0];
      findings.push(
        makeFinding(
          this,
          raw,
          "*.*.*.* (private IP)",
          m.index,
          m.index + raw.length,
          0.8,
        ),
      );
    }
    return findings;
  },
};
