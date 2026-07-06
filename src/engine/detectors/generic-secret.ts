import { entropy, redact } from "../utils.ts";
import type { Detector, DetectorFinding } from "./types.ts";
import { makeFinding } from "./types.ts";

// Context-anchored generic secrets: key=value, key: value patterns.
// The context anchor (api_key, secret, token...) keeps false-positive rate low.
const GENERIC_RE =
  /(?:api[_-]?key|secret[_-]?key|access[_-]?token|api[_-]?secret|auth[_-]?token)\s*[:=]\s*['"]?([A-Za-z0-9\-_.+/]{20,})['"]?/gi;

// Bare env-file assignments: ALL_CAPS_KEY=<value>, no quotes required.
const ENV_RE =
  /\b[A-Z_]*(SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|PRIVATE_KEY|AUTH_TOKEN|ACCESS_KEY)[A-Z_0-9]*\s*=\s*(\S{8,})/g;

// npm, SendGrid, Mailgun, Mailchimp tokens.
const NPM_RE = /npm_[A-Za-z0-9]{36}/g;
const SENDGRID_RE = /SG\.[A-Za-z0-9_-]{20,24}\.[A-Za-z0-9_-]{39,50}/g;
const MAILGUN_RE = /key-[0-9a-zA-Z]{32}/g;
const MAILCHIMP_RE = /[0-9a-f]{32}-us[0-9]{1,2}/g;
const TWILIO_SID_RE = /\bAC[0-9a-f]{32}\b/g;
const DISCORD_WEBHOOK_RE =
  /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]{17,20}\/[A-Za-z0-9_-]{68}/g;
const TELEGRAM_BOT_RE = /\b[0-9]{8,10}:AA[0-9A-Za-z_-]{33}\b/g;

export const genericSecretDetector: Detector = {
  id: "generic-secret",
  label: "Generic API Key / Secret",
  dataType: "generic-secret",
  severity: "medium",
  pattern: GENERIC_RE.source,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(GENERIC_RE)) {
      const raw = m[1];
      if (!raw || entropy(raw) < 3.5) continue;
      findings.push(
        makeFinding(
          this,
          raw,
          redact(raw),
          m.index,
          m.index + m[0].length,
          0.7,
        ),
      );
    }
    return findings;
  },
};

export const envAssignmentDetector: Detector = {
  id: "env-assignment",
  label: ".env-style secret assignment",
  dataType: "generic-secret",
  severity: "medium",
  pattern: ENV_RE.source,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(ENV_RE)) {
      const raw = m[2];
      if (!raw || entropy(raw) < 3.0) continue;
      findings.push(
        makeFinding(
          this,
          raw,
          redact(raw),
          m.index,
          m.index + m[0].length,
          0.75,
        ),
      );
    }
    return findings;
  },
};

export const npmTokenDetector: Detector = {
  id: "npm-token",
  label: "npm Access Token",
  dataType: "npm-token",
  severity: "high",
  pattern: NPM_RE.source,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(NPM_RE)) {
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

export const sendgridKeyDetector: Detector = {
  id: "sendgrid-key",
  label: "SendGrid API Key",
  dataType: "sendgrid-key",
  severity: "high",
  pattern: SENDGRID_RE.source,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(SENDGRID_RE)) {
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

export const mailgunKeyDetector: Detector = {
  id: "mailgun-key",
  label: "Mailgun API Key",
  dataType: "generic-secret",
  severity: "high",
  pattern: MAILGUN_RE.source,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(MAILGUN_RE)) {
      const raw = m[0];
      findings.push(
        makeFinding(this, raw, redact(raw), m.index, m.index + raw.length, 0.9),
      );
    }
    return findings;
  },
};

export const mailchimpKeyDetector: Detector = {
  id: "mailchimp-key",
  label: "Mailchimp API Key",
  dataType: "generic-secret",
  severity: "high",
  pattern: MAILCHIMP_RE.source,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(MAILCHIMP_RE)) {
      const raw = m[0];
      findings.push(
        makeFinding(this, raw, redact(raw), m.index, m.index + raw.length, 0.9),
      );
    }
    return findings;
  },
};

export const twilioSidDetector: Detector = {
  id: "twilio-sid",
  label: "Twilio Account SID",
  dataType: "generic-secret",
  severity: "medium",
  pattern: TWILIO_SID_RE.source,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(TWILIO_SID_RE)) {
      const raw = m[0];
      findings.push(
        makeFinding(
          this,
          raw,
          redact(raw),
          m.index,
          m.index + raw.length,
          0.85,
        ),
      );
    }
    return findings;
  },
};

export const discordWebhookDetector: Detector = {
  id: "discord-webhook",
  label: "Discord Webhook URL",
  dataType: "generic-secret",
  severity: "high",
  pattern: DISCORD_WEBHOOK_RE.source,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(DISCORD_WEBHOOK_RE)) {
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

export const telegramBotTokenDetector: Detector = {
  id: "telegram-bot-token",
  label: "Telegram Bot Token",
  dataType: "generic-secret",
  severity: "high",
  pattern: TELEGRAM_BOT_RE.source,
  scan(text: string): DetectorFinding[] {
    const findings: DetectorFinding[] = [];
    for (const m of text.matchAll(TELEGRAM_BOT_RE)) {
      const raw = m[0];
      findings.push(
        makeFinding(this, raw, redact(raw), m.index, m.index + raw.length, 0.9),
      );
    }
    return findings;
  },
};
