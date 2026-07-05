// Corpus de avaliação dos detectores.
//
// Positivos: um valor sensível 100% FICTÍCIO por amostra (chaves de exemplo
// públicas, números de teste Luhn-válidos, CPF/CNPJ com dígitos verificadores
// válidos porém inexistentes). Negativos: textos limpos que costumam gerar
// falso positivo (hashes com contexto, UUIDs, base64, números inválidos).
//
// IMPORTANTE: os valores são construídos por CONCATENAÇÃO para que este
// arquivo nunca contenha um padrão detectável literal — senão o próprio
// guardian (e qualquer secret scanner de CI) bloquearia edições aqui.

export interface CorpusSample {
  name: string;
  dataType: string;
  text: string;
}

function b64url(value: object): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

export const positives: CorpusSample[] = [
  {
    name: "aws-access-key",
    dataType: "aws-key",
    text: `aws configure usando ${"AKIA" + "IOSFODNN7EXAMPLE"} no perfil default`,
  },
  {
    name: "github-pat",
    dataType: "github-token",
    text: `git remote com token ${"ghp_" + "AbCd".repeat(9)}`,
  },
  {
    name: "openai-key",
    dataType: "openai-key",
    text: `OPENAI: ${"sk-" + "A1b2".repeat(12)}`,
  },
  {
    name: "stripe-key",
    dataType: "stripe-key",
    text: `cobrança via ${"sk_" + "test_" + "a1B2".repeat(6)}`,
  },
  {
    name: "slack-token",
    dataType: "slack-token",
    text: `bot do slack: ${"xoxb-" + "123456789012-abcdefABCDEF"}`,
  },
  {
    name: "gcp-api-key",
    dataType: "gcp-key",
    text: `maps key ${"AIza" + "SyA" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"}`,
  },
  {
    name: "gitlab-pat",
    dataType: "gitlab-token",
    text: `CI usa ${"glpat-" + "a1B2c3D4e5F6g7H8i9J0"}`,
  },
  {
    name: "jwt",
    dataType: "jwt",
    text: `Authorization: Bearer ${b64url({ alg: "HS256", typ: "JWT" })}.${b64url(
      { sub: "1234567890", name: "Fulano" },
    )}.${"fakesignature12345"}`,
  },
  {
    name: "private-key-pem",
    dataType: "private-key",
    text: [
      "-----BEGIN " + "RSA PRIVATE " + "KEY-----",
      "MIIEfakefakefakefakefakefakefake",
      "-----END " + "RSA PRIVATE " + "KEY-----",
    ].join("\n"),
  },
  {
    name: "connection-string",
    dataType: "connection-string",
    text: `DATABASE: ${"postgres" + "://app_user:" + "s3cr3tpass" + "@db.internal:5432/app"}`,
  },
  {
    name: "env-assignment",
    dataType: "generic-secret",
    text: `no .env ficou ${"API_" + "KEY=" + "hunter2secret42"}`,
  },
  {
    name: "email",
    dataType: "email",
    text: `contato: ${"maria.silva" + "@example.com"}`,
  },
  {
    name: "credit-card-visa",
    dataType: "credit-card",
    text: `pagamento no cartão ${"4111 " + "1111 1111 1111"}`,
  },
  {
    name: "cpf",
    dataType: "cpf",
    text: `CPF do cliente: ${"529.982." + "247-25"}`,
  },
  {
    name: "cnpj",
    dataType: "cnpj",
    text: `CNPJ da filial: ${"11.222." + "333/0001-81"}`,
  },
  {
    name: "phone-br",
    dataType: "phone-br",
    text: `liga no ${"(11) 9" + "8765-4321"}`,
  },
  {
    name: "iban",
    dataType: "iban",
    text: `transferir para ${"DE89" + "370400440532013000"}`,
  },
  {
    name: "ssn",
    dataType: "ssn",
    text: `SSN on file: ${"078-05" + "-1120"}`,
  },
];

export const negatives: { name: string; text: string }[] = [
  {
    name: "uuid",
    text: "request id 550e8400-e29b-41d4-a716-446655440000 finalizado com sucesso",
  },
  {
    name: "git-commit-sha",
    text: "commit 3f2b8a91c4e5d6f7a8b9c0d1e2f3a4b5c6d7e8f9 no branch main",
  },
  {
    name: "sha256-digest",
    text: "sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  },
  {
    name: "md5-etag",
    text: "etag da resposta: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  },
  {
    name: "semver-e-data",
    text: "versão 2.14.3 lançada em 2026-07-05 às 14:30 com 12034 downloads",
  },
  {
    name: "codigo-fonte",
    text: 'const userEmailField = formData.get("email") ?? defaultValue;',
  },
  {
    name: "base64-imagem",
    text: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk",
  },
  {
    name: "cpf-invalido",
    text: "documento 123.456.789-00 reprovado na validação",
  },
  {
    name: "cartao-luhn-invalido",
    text: "número de teste 4111 1111 1111 1112 não passa no Luhn",
  },
  {
    name: "texto-corrido",
    text: "A reunião de planejamento da frota foi remarcada para quinta-feira, com pauta de orçamento e contratações.",
  },
];
