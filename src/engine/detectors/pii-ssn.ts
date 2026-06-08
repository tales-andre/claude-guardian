import { redact } from "../utils.ts";
import { makeFinding } from "./types.ts";
import type { Detector, DetectorFinding } from "./types.ts";

// US Social Security Number. Excludes invalid area codes (000, 666, 9xx)
// and serial/group numbers of all zeros.
const SSN_RE = /\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b/g;

export const ssnDetector: Detector = {
  id: "pii-ssn",
  label: "US Social Security Number",
  dataType: "ssn",
  severity: "high",
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(SSN_RE)) {
      const raw = m[0];
      findings.push(makeFinding(this, raw, redact(raw.replace(/[- ]/g, "")), m.index, m.index + raw.length, 0.9));
    }
    return findings;
  },
};
