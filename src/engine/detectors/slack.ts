import { redact } from "../utils.ts";
import type { Detector, DetectorFinding } from "./types.ts";
import { makeFinding } from "./types.ts";

const TOKEN_RE = /xox[baprs]-[0-9a-zA-Z-]{10,72}/g;

// Slack webhook URL: strict structure, no open-ended backtracking.
const WEBHOOK_RE =
  /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]{8,10}\/B[A-Za-z0-9_]{8,12}\/[A-Za-z0-9_]{23,24}/g;

export const slackTokenDetector: Detector = {
  id: "slack-token",
  label: "Slack API Token",
  dataType: "slack-token",
  severity: "high",
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(TOKEN_RE)) {
      const raw = m[0];
      findings.push(
        makeFinding(
          this,
          raw,
          redact(raw),
          m.index,
          m.index + raw.length,
          0.93,
        ),
      );
    }
    return findings;
  },
};

export const slackWebhookDetector: Detector = {
  id: "slack-webhook",
  label: "Slack Incoming Webhook URL",
  dataType: "slack-token",
  severity: "high",
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(WEBHOOK_RE)) {
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
