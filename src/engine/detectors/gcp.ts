import { redact } from "../utils.ts";
import type { Detector, DetectorFinding } from "./types.ts";
import { makeFinding } from "./types.ts";

const GCP_API_KEY_RE = /AIza[0-9A-Za-z_-]{35}/g;

const GCP_SERVICE_ACCOUNT_RE =
  /"type"\s*:\s*"service_account"[\s\S]{0,200}"private_key"\s*:\s*"(-----BEGIN[^"]+)"/g;

export const gcpApiKeyDetector: Detector = {
  id: "gcp-api-key",
  label: "Google Cloud API Key",
  dataType: "gcp-key",
  severity: "high",
  pattern: GCP_API_KEY_RE.source,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(GCP_API_KEY_RE)) {
      const raw = m[0];
      findings.push(
        makeFinding(this, raw, redact(raw), m.index, m.index + raw.length, 0.9),
      );
    }
    return findings;
  },
};

export const gcpServiceAccountDetector: Detector = {
  id: "gcp-service-account",
  label: "GCP Service Account JSON",
  dataType: "gcp-key",
  severity: "critical",
  pattern: GCP_SERVICE_ACCOUNT_RE.source,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(GCP_SERVICE_ACCOUNT_RE)) {
      const raw = m[1] ?? m[0];
      findings.push(
        makeFinding(
          this,
          raw,
          "[GCP service account key]",
          m.index,
          m.index + m[0].length,
          0.95,
        ),
      );
    }
    return findings;
  },
};
