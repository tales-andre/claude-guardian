import { redact } from "../utils.ts";
import type { Detector, DetectorFinding } from "./types.ts";
import { makeFinding } from "./types.ts";

const SECRET_KEY_RE = /sk_(live|test)_[0-9a-zA-Z]{24,}/g;
const RESTRICTED_KEY_RE = /rk_(live|test)_[0-9a-zA-Z]{24,}/g;
const WEBHOOK_SECRET_RE = /whsec_[A-Za-z0-9+/]{32,}/g;

export const stripeSecretKeyDetector: Detector = {
  id: "stripe-secret-key",
  label: "Stripe Secret Key",
  dataType: "stripe-key",
  severity: "critical",
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(SECRET_KEY_RE)) {
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

export const stripeRestrictedKeyDetector: Detector = {
  id: "stripe-restricted-key",
  label: "Stripe Restricted Key",
  dataType: "stripe-key",
  severity: "high",
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(RESTRICTED_KEY_RE)) {
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

export const stripeWebhookSecretDetector: Detector = {
  id: "stripe-webhook-secret",
  label: "Stripe Webhook Signing Secret",
  dataType: "stripe-key",
  severity: "high",
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(WEBHOOK_SECRET_RE)) {
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
