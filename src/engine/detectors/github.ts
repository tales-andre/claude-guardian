import { redact } from "../utils.ts";
import type { Detector, DetectorFinding } from "./types.ts";
import { makeFinding } from "./types.ts";

const PAT_RE = /gh[pousr]_[A-Za-z0-9]{36,255}/g;
const FINE_GRAINED_RE = /github_pat_[A-Za-z0-9_]{82}/g;
const APP_SECRET_RE = /ghs_[A-Za-z0-9]{36}/g;

export const githubPatDetector: Detector = {
  id: "github-pat",
  label: "GitHub Personal Access Token",
  dataType: "github-token",
  severity: "critical",
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(PAT_RE)) {
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

export const githubFineGrainedDetector: Detector = {
  id: "github-fine-grained",
  label: "GitHub Fine-Grained Token",
  dataType: "github-token",
  severity: "critical",
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(FINE_GRAINED_RE)) {
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

export const githubAppSecretDetector: Detector = {
  id: "github-app-secret",
  label: "GitHub App Installation Token",
  dataType: "github-token",
  severity: "critical",
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(APP_SECRET_RE)) {
      const raw = m[0];
      findings.push(
        makeFinding(
          this,
          raw,
          redact(raw),
          m.index,
          m.index + raw.length,
          0.95,
        ),
      );
    }
    return findings;
  },
};
