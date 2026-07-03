import { base64SecretDetector } from "./base64-secret.ts";
import type { Detector } from "./types.ts";

// ── Detectores async-only (detecção tiered) ───────────────────────────────────
// Detectores caros/de alta recall que NÃO podem entrar no caminho síncrono de
// bloqueio (PreToolUse, orçamento de 500ms fail-closed). São aplicados apenas no
// PostToolUse e no servidor central, onde latência não bloqueia o usuário.
// Adicione aqui NER/PII estilo Presidio, verificação ao-vivo de credencial
// (TruffleHog) e o analisador LLM-based conforme forem implementados.

export const ASYNC_DETECTORS: readonly Detector[] = [base64SecretDetector];
