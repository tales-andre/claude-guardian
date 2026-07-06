import type { Detector, DetectorFinding } from "./types.ts";
import { makeFinding } from "./types.ts";

// US phone numbers: (555) 123-4567 / 555-123-4567 / +1 555 123 4567
const US_RE = /\b(\+1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b/g;

// Japanese phone numbers: 03-1234-5678 / 090-1234-5678
const JP_RE = /\b0\d{1,4}[\s-]\d{1,4}[\s-]\d{4}\b/g;

// Japanese postal code: requires 〒 prefix to avoid false positives.
const JP_POSTAL_RE = /〒\d{3}[\s-]\d{4}/g;

export const phoneUsDetector: Detector = {
  id: "pii-phone-us",
  label: "US Phone Number",
  dataType: "phone-us",
  severity: "low",
  pattern: US_RE.source,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(US_RE)) {
      const raw = m[0];
      findings.push(
        makeFinding(
          this,
          raw,
          "(***) ***-****",
          m.index,
          m.index + raw.length,
          0.75,
        ),
      );
    }
    return findings;
  },
};

export const phoneJpDetector: Detector = {
  id: "pii-phone-jp",
  label: "Japanese Phone Number",
  dataType: "phone-jp",
  severity: "low",
  pattern: JP_RE.source,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(JP_RE)) {
      const raw = m[0];
      findings.push(
        makeFinding(
          this,
          raw,
          "0*-****-****",
          m.index,
          m.index + raw.length,
          0.75,
        ),
      );
    }
    return findings;
  },
};

export const postalJpDetector: Detector = {
  id: "pii-postal-jp",
  label: "Japanese Postal Code",
  dataType: "phone-jp",
  severity: "low",
  pattern: JP_POSTAL_RE.source,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(JP_POSTAL_RE)) {
      const raw = m[0];
      findings.push(
        makeFinding(
          this,
          raw,
          "〒***-****",
          m.index,
          m.index + raw.length,
          0.9,
        ),
      );
    }
    return findings;
  },
};
