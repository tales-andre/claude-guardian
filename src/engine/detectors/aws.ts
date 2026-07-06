import { redact } from "../utils.ts";
import type { Detector, DetectorFinding } from "./types.ts";
import { makeFinding } from "./types.ts";

// AWS Access Key IDs start with AKIA/ABIA/ACCA/AGPA/AIDA/AROA/AIPA/ANPA/ANVA/ASIA.
// 20 characters total. Linear regex — no backtracking.
const ACCESS_KEY_RE =
  /\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/g;

// AWS Secret Access Keys: 40 base64 chars, high entropy. Context anchor keeps FP low.
const SECRET_KEY_RE =
  /(?:aws[_-]?secret[_-]?(?:access[_-]?)?key|aws[_-]?secret)\s*[=:]\s*['"]?([A-Za-z0-9/+]{40})['"]?/gi;

export const awsAccessKeyDetector: Detector = {
  id: "aws-access-key",
  label: "AWS Access Key ID",
  dataType: "aws-key",
  severity: "critical",
  pattern: ACCESS_KEY_RE.source,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(ACCESS_KEY_RE)) {
      const raw = m[0];
      findings.push(
        makeFinding(
          this,
          raw,
          redact(raw),
          m.index,
          m.index + raw.length,
          0.97,
        ),
      );
    }
    return findings;
  },
};

export const awsSecretKeyDetector: Detector = {
  id: "aws-secret-key",
  label: "AWS Secret Access Key",
  dataType: "aws-key",
  severity: "critical",
  pattern: SECRET_KEY_RE.source,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(SECRET_KEY_RE)) {
      const raw = m[1];
      if (!raw) continue;
      findings.push(
        makeFinding(
          this,
          raw,
          redact(raw),
          m.index,
          m.index + m[0].length,
          0.9,
        ),
      );
    }
    return findings;
  },
};
