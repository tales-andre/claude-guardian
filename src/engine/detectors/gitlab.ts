import { redact } from "../utils.ts";
import type { Detector, DetectorFinding } from "./types.ts";
import { makeFinding } from "./types.ts";

const PAT_RE = /glpat-[A-Za-z0-9_=-]{20,22}/g;
const CI_JOB_TOKEN_RE = /glcbt-[0-9]{2}_[A-Za-z0-9_-]{20}/g;
const RUNNER_TOKEN_RE = /glrt-[A-Za-z0-9_-]{20}/g;

export const gitlabPatDetector: Detector = {
  id: "gitlab-pat",
  label: "GitLab Personal Access Token",
  dataType: "gitlab-token",
  severity: "high",
  pattern: PAT_RE.source,
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
          0.95,
        ),
      );
    }
    return findings;
  },
};

export const gitlabCiJobTokenDetector: Detector = {
  id: "gitlab-ci-job-token",
  label: "GitLab CI/CD Job Token",
  dataType: "gitlab-token",
  severity: "high",
  pattern: CI_JOB_TOKEN_RE.source,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(CI_JOB_TOKEN_RE)) {
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

export const gitlabRunnerTokenDetector: Detector = {
  id: "gitlab-runner-token",
  label: "GitLab Runner Registration Token",
  dataType: "gitlab-token",
  severity: "high",
  pattern: RUNNER_TOKEN_RE.source,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(RUNNER_TOKEN_RE)) {
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
