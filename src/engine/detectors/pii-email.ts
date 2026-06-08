import { redact } from "../utils.ts";
import { makeFinding } from "./types.ts";
import type { Detector, DetectorFinding } from "./types.ts";

// RFC-5321 compatible email, bounded to prevent ReDoS.
const EMAIL_RE = /\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,}\b/g;

export const emailDetector: Detector = {
  id: "pii-email",
  label: "Email Address",
  dataType: "email",
  severity: "medium",
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(EMAIL_RE)) {
      const raw = m[0];
      findings.push(makeFinding(this, raw, redact(raw), m.index, m.index + raw.length, 0.85));
    }
    return findings;
  },
};
