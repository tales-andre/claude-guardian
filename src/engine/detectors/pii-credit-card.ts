import { luhn, redact } from "../utils.ts";
import { makeFinding } from "./types.ts";
import type { Detector, DetectorFinding } from "./types.ts";

// Credit card patterns with optional separators.
// Visa (16d), Mastercard (16d), Amex (15d), Discover (16d).
// Anchored at word boundaries to reduce false positives.
const CC_RE =
  /\b(?:4[0-9]{3}(?:[\s-]?[0-9]{4}){3}|5[1-5][0-9]{2}(?:[\s-]?[0-9]{4}){3}|3[47][0-9]{2}[\s-]?[0-9]{6}[\s-]?[0-9]{5}|6(?:011|5[0-9]{2})[0-9](?:[\s-]?[0-9]{4}){3})\b/g;

export const creditCardDetector: Detector = {
  id: "credit-card",
  label: "Credit Card Number",
  dataType: "credit-card",
  severity: "high",
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(CC_RE)) {
      const raw = m[0];
      if (!luhn(raw)) continue;
      findings.push(makeFinding(this, raw, redact(raw.replace(/[\s-]/g, "")), m.index, m.index + raw.length, 0.97));
    }
    return findings;
  },
};
