// Autoridade certificadora do guardian para o proxy HTTPS (GUI Gateway Fase 2).
// Gera uma CA local (uma vez, persistida no dir de config) e emite certs de
// servidor por-SNI, assinados por ela, para os hosts que o proxy intercepta.
// Usa node-forge (JS puro, portável Windows/Mac/Linux — openssl não é garantido
// no Windows). A CA é distribuída às máquinas via MDM; o proxy usa a chave.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import forge from "node-forge";

export interface GuardianCa {
  caCertPem: string;
  caKeyPem: string;
  fingerprint: string; // SHA-256 do DER, hex com ':' (para MDM/telemetria)
  // Objetos forge reusados na emissão de leaves.
  caCert: forge.pki.Certificate;
  caKey: forge.pki.rsa.PrivateKey;
  leafKeyPem: string;
  leafPublicKey: forge.pki.rsa.PublicKey;
}

const CA_CRT = "guardian-ca.crt";
const CA_KEY = "guardian-ca.key";

function sha256Fingerprint(cert: forge.pki.Certificate): string {
  const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  const md = forge.md.sha256.create();
  md.update(der);
  const hex = md.digest().toHex().toUpperCase();
  return (hex.match(/../g) ?? []).join(":");
}

function makeSerial(): string {
  // Serial positivo aleatório (hex). Determinístico-free: node-forge exige string.
  const bytes = forge.random.getBytesSync(16);
  let hex = forge.util.bytesToHex(bytes);
  // Garante 1º byte < 0x80 (serial positivo).
  const first = Number.parseInt(hex.slice(0, 2), 16) & 0x7f;
  hex = first.toString(16).padStart(2, "0") + hex.slice(2);
  return hex;
}

function generateCa(): {
  caCert: forge.pki.Certificate;
  caKey: forge.pki.rsa.PrivateKey;
} {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = makeSerial();
  cert.validity.notBefore = new Date(2020, 0, 1);
  cert.validity.notAfter = new Date(2035, 0, 1);
  const attrs = [
    { name: "commonName", value: "Claude Guardian DLP CA" },
    { name: "organizationName", value: "claude-guardian" },
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: "basicConstraints", cA: true, critical: true },
    { name: "keyUsage", keyCertSign: true, cRLSign: true, critical: true },
    { name: "subjectKeyIdentifier" },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return { caCert: cert, caKey: keys.privateKey };
}

/** Carrega (ou cria uma vez) a CA do guardian no diretório de config. */
export function ensureCa(dir: string): GuardianCa {
  mkdirSync(dir, { recursive: true });
  const crtPath = join(dir, CA_CRT);
  const keyPath = join(dir, CA_KEY);

  let caCert: forge.pki.Certificate;
  let caKey: forge.pki.rsa.PrivateKey;
  if (existsSync(crtPath) && existsSync(keyPath)) {
    caCert = forge.pki.certificateFromPem(readFileSync(crtPath, "utf8"));
    caKey = forge.pki.privateKeyFromPem(
      readFileSync(keyPath, "utf8"),
    ) as forge.pki.rsa.PrivateKey;
  } else {
    ({ caCert, caKey } = generateCa());
    writeFileSync(crtPath, forge.pki.certificateToPem(caCert), "utf8");
    writeFileSync(keyPath, forge.pki.privateKeyToPem(caKey), {
      encoding: "utf8",
      mode: 0o600,
    });
  }

  // Keypair de leaf só em memória (reusada em todos os hosts — só o cert muda).
  // Não precisa persistir: só a CA precisa ser estável (o fingerprint é o que o
  // MDM distribui como confiável). Regenerar por processo é seguro.
  const leafKeys = forge.pki.rsa.generateKeyPair(2048);

  return {
    caCertPem: forge.pki.certificateToPem(caCert),
    caKeyPem: forge.pki.privateKeyToPem(caKey),
    fingerprint: sha256Fingerprint(caCert),
    caCert,
    caKey,
    leafKeyPem: forge.pki.privateKeyToPem(leafKeys.privateKey),
    leafPublicKey: leafKeys.publicKey,
  };
}

export interface LeafCert {
  certPem: string;
  keyPem: string;
}

/** Emite (e cacheia) um cert de servidor para `host`, assinado pela CA. */
const leafCache = new Map<string, LeafCert>();
export function issueLeaf(ca: GuardianCa, host: string): LeafCert {
  const cached = leafCache.get(host);
  if (cached) return cached;

  const cert = forge.pki.createCertificate();
  cert.publicKey = ca.leafPublicKey;
  cert.serialNumber = makeSerial();
  cert.validity.notBefore = new Date(2020, 0, 1);
  cert.validity.notAfter = new Date(2035, 0, 1);
  cert.setSubject([{ name: "commonName", value: host }]);
  cert.setIssuer(ca.caCert.subject.attributes);
  cert.setExtensions([
    { name: "basicConstraints", cA: false },
    {
      name: "keyUsage",
      digitalSignature: true,
      keyEncipherment: true,
      critical: true,
    },
    { name: "extKeyUsage", serverAuth: true },
    { name: "subjectAltName", altNames: [{ type: 2, value: host }] }, // type 2 = DNS
  ]);
  cert.sign(ca.caKey, forge.md.sha256.create());

  const leaf: LeafCert = {
    certPem: forge.pki.certificateToPem(cert),
    keyPem: ca.leafKeyPem,
  };
  leafCache.set(host, leaf);
  return leaf;
}
