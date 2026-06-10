import { awsAccessKeyDetector, awsSecretKeyDetector } from "./aws.ts";
import {
  connectionStringDetector,
  dsnPasswordDetector,
} from "./connection-string.ts";
import { gcpApiKeyDetector, gcpServiceAccountDetector } from "./gcp.ts";
import {
  discordWebhookDetector,
  envAssignmentDetector,
  genericSecretDetector,
  mailchimpKeyDetector,
  mailgunKeyDetector,
  npmTokenDetector,
  sendgridKeyDetector,
  telegramBotTokenDetector,
  twilioSidDetector,
} from "./generic-secret.ts";
import {
  githubAppSecretDetector,
  githubFineGrainedDetector,
  githubPatDetector,
} from "./github.ts";
import {
  gitlabCiJobTokenDetector,
  gitlabPatDetector,
  gitlabRunnerTokenDetector,
} from "./gitlab.ts";
import {
  embeddedKeyDetector,
  hexHighEntropyDetector,
  n8nApiKeyDetector,
} from "./high-entropy.ts";
import { jwtDetector } from "./jwt.ts";
import {
  anthropicKeyDetector,
  openAiLegacyKeyDetector,
  openAiProjectKeyDetector,
} from "./openai.ts";
import { cnpjDetector, cpfDetector, phoneBrDetector } from "./pii-br.ts";
import { creditCardDetector } from "./pii-credit-card.ts";
import { emailDetector } from "./pii-email.ts";
import { ibanDetector } from "./pii-iban.ts";
import { privateIpDetector } from "./pii-ip.ts";
import {
  phoneJpDetector,
  phoneUsDetector,
  postalJpDetector,
} from "./pii-phone.ts";
import { ssnDetector } from "./pii-ssn.ts";
import { privateKeyDetector } from "./private-key.ts";
import { slackTokenDetector, slackWebhookDetector } from "./slack.ts";
import {
  stripeRestrictedKeyDetector,
  stripeSecretKeyDetector,
  stripeWebhookSecretDetector,
} from "./stripe.ts";
import type { Detector } from "./types.ts";

export type { Detector };

export const BUILT_IN_DETECTORS: readonly Detector[] = [
  // Highest-confidence secrets first (critical → high → medium)
  awsAccessKeyDetector,
  awsSecretKeyDetector,
  anthropicKeyDetector,
  openAiLegacyKeyDetector,
  openAiProjectKeyDetector,
  privateKeyDetector,
  githubPatDetector,
  githubFineGrainedDetector,
  githubAppSecretDetector,
  gitlabPatDetector,
  gitlabCiJobTokenDetector,
  gitlabRunnerTokenDetector,
  stripeSecretKeyDetector,
  stripeRestrictedKeyDetector,
  stripeWebhookSecretDetector,
  gcpApiKeyDetector,
  gcpServiceAccountDetector,
  npmTokenDetector,
  slackTokenDetector,
  slackWebhookDetector,
  discordWebhookDetector,
  telegramBotTokenDetector,
  sendgridKeyDetector,
  mailgunKeyDetector,
  mailchimpKeyDetector,
  twilioSidDetector,
  jwtDetector,
  n8nApiKeyDetector,
  embeddedKeyDetector,
  connectionStringDetector,
  dsnPasswordDetector,
  genericSecretDetector,
  envAssignmentDetector,
  hexHighEntropyDetector,
  // PII
  creditCardDetector,
  ssnDetector,
  cpfDetector,
  cnpjDetector,
  ibanDetector,
  emailDetector,
  phoneBrDetector,
  phoneUsDetector,
  phoneJpDetector,
  postalJpDetector,
  privateIpDetector,
] as const;
