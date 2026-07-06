import { redact } from "../utils.ts";
import type { Detector, DetectorFinding } from "./types.ts";
import { makeFinding } from "./types.ts";

// JWT: three base64url segments separated by dots. Header starts with eyJ ({"alg").
const JWT_RE =
  /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;

export const jwtDetector: Detector = {
  id: "jwt",
  label: "JSON Web Token (JWT)",
  dataType: "jwt",
  severity: "high",
  pattern: JWT_RE.source,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(JWT_RE)) {
      const raw = m[0];
      findings.push(
        makeFinding(this, raw, redact(raw), m.index, m.index + raw.length, 0.9),
      );
    }
    return findings;
  },
};
