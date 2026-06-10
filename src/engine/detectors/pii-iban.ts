import { validIban } from "../utils.ts";
import type { Detector, DetectorFinding } from "./types.ts";
import { makeFinding } from "./types.ts";

// IBAN: 2-letter country code + 2 check digits + up to 30 alphanumeric chars.
// Spaces every 4 chars are optional (print format).
const IBAN_RE = /\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4,30}(?:\s[A-Z0-9]{1,4}){0,7}\b/g;

export const ibanDetector: Detector = {
  id: "pii-iban",
  label: "IBAN (International Bank Account Number)",
  dataType: "iban",
  severity: "high",
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(IBAN_RE)) {
      const raw = m[0];
      if (!validIban(raw)) continue;
      const clean = raw.replace(/\s/g, "");
      const snippet = `${clean.slice(0, 4)}****${clean.slice(-4)}`;
      findings.push(
        makeFinding(this, raw, snippet, m.index, m.index + raw.length, 0.95),
      );
    }
    return findings;
  },
};
