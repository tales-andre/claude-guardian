import { describe, expect, it } from "vitest";
import {
  buildEntityDetectors,
  personNameDetector,
  postalAddressDetector,
} from "../src/engine/detectors/entity.ts";
import { luhn, validCnpj, validCpf } from "../src/engine/utils.ts";
import { evaluatePolicy } from "../src/lib/policy.ts";
import { generateFake, substituteText } from "../src/lib/substitute.ts";
import type { DetectorFinding, PolicyRule } from "../src/types/index.ts";

function finding(
  dataType: string,
  rawValue: string,
  start = 0,
): DetectorFinding {
  return {
    detectorId: `d:${dataType}`,
    label: dataType,
    dataType,
    severity: "medium",
    snippet: "****",
    rawValue,
    position: { start, end: start + rawValue.length },
    confidence: 0.9,
  };
}

describe("generateFake — determinismo e integridade referencial", () => {
  it("mesmo (dataType, valor, salt) → mesmo fake", () => {
    const a = generateFake("email", "john@corp.com", "salt");
    const b = generateFake("email", "john@corp.com", "salt");
    expect(a).toBe(b);
  });

  it("salts diferentes → fakes diferentes", () => {
    const a = generateFake("email", "john@corp.com", "salt-a");
    const b = generateFake("email", "john@corp.com", "salt-b");
    expect(a).not.toBe(b);
  });

  it("nunca devolve o valor real", () => {
    for (const [dt, raw] of [
      ["email", "john.doe@corp.com"],
      ["cpf", "529.982.247-25"],
      ["person-name", "Roberto Carlos"],
      ["aws-key", "AKIAIOSFODNN7EXAMPLE"],
      ["credit-card", "4111 1111 1111 1111"],
    ] as const) {
      expect(generateFake(dt, raw)).not.toBe(raw);
      expect(generateFake(dt, raw)).not.toContain(raw);
    }
  });
});

describe("generateFake — fidelidade de formato", () => {
  it("CPF fake é válido e preserva pontuação", () => {
    const f = generateFake("cpf", "529.982.247-25");
    expect(f).toMatch(/^\d{3}\.\d{3}\.\d{3}-\d{2}$/);
    expect(validCpf(f.replace(/\D/g, ""))).toBe(true);
  });

  it("CPF fake sem pontuação continua só dígitos e válido", () => {
    const f = generateFake("cpf", "52998224725");
    expect(f).toMatch(/^\d{11}$/);
    expect(validCpf(f)).toBe(true);
  });

  it("CNPJ fake é válido", () => {
    const f = generateFake("cnpj", "11.222.333/0001-81");
    expect(validCnpj(f.replace(/\D/g, ""))).toBe(true);
  });

  it("cartão fake passa no Luhn e preserva agrupamento", () => {
    const f = generateFake("credit-card", "4111 1111 1111 1111");
    expect(f).toMatch(/^\d{4} \d{4} \d{4} \d{4}$/);
    expect(luhn(f)).toBe(true);
  });

  it("email fake usa domínio reservado example.com", () => {
    const f = generateFake("email", "alice@corp.com");
    expect(f).toMatch(/^[a-z]+\.[a-z]+\d+@example\.com$/);
  });

  it("nome fake é 'Nome Sobrenome'", () => {
    const f = generateFake("person-name", "Roberto Carlos");
    expect(f).toMatch(/^[A-Za-zÀ-ÿ]+ [A-Za-zÀ-ÿ]+$/);
  });

  it("segredo genérico: skeleton preserva comprimento e separadores", () => {
    const raw = "ghp_AbCd1234-xyZ";
    const f = generateFake("github-token", raw);
    expect(f).toHaveLength(raw.length);
    expect(f[3]).toBe("_"); // separador preservado na mesma posição
    expect(f.indexOf("-")).toBe(raw.indexOf("-"));
  });
});

describe("substituteText", () => {
  it("troca todas as ocorrências do mesmo valor pelo MESMO fake", () => {
    const cpf = "529.982.247-25";
    const text = `CPF ${cpf} e novamente ${cpf}.`;
    const out = substituteText(text, [finding("cpf", cpf)], "s");
    expect(out).not.toContain(cpf);
    const fake = generateFake("cpf", cpf, "s");
    expect(out.split(fake).length - 1).toBe(2);
  });

  it("substitui valores mais longos primeiro (evita corromper substring)", () => {
    const text = "token=ABCDEFGH e id=ABCD";
    const out = substituteText(
      text,
      [
        finding("generic-secret", "ABCD", 20),
        finding("generic-secret", "ABCDEFGH", 6),
      ],
      "s",
    );
    expect(out).not.toContain("ABCDEFGH");
    expect(out).not.toContain("ABCD");
  });
});

describe("entity detectors", () => {
  it("detecta nome ancorado por apresentação", () => {
    const f = personNameDetector.scan("Olá, meu nome é Roberto Carlos e ...");
    expect(f.some((x) => x.rawValue === "Roberto Carlos")).toBe(true);
  });

  it("ignora tokens comuns capitalizados (stoplist)", () => {
    const f = personNameDetector.scan("Segue Isso Aqui");
    expect(f).toHaveLength(0);
  });

  it("não marca termos técnicos Titlecase como nome (FP real: questão de certificação AWS)", () => {
    const text =
      "B. Transit Gateway sharing is useful for central network connectivity. " +
      "Even so, AWS Network Manager helps with centralized visibility, and the " +
      "security team keeps Route Tables and Network ACLs in the networking account.";
    expect(personNameDetector.scan(text)).toHaveLength(0);
  });

  it("não marca bigrama Titlecase colado a sigla ALL-CAPS (nome de produto)", () => {
    const f = personNameDetector.scan(
      "habilite o AWS Fault Injection no ambiente de teste",
    );
    expect(f).toHaveLength(0);
  });

  it("buildEntityDetectors aceita stopwords customizadas (gerenciáveis pelo dash)", () => {
    const texto = "apresentar ao Conselho Diretor amanhã";
    const padrao = personNameDetector.scan(texto);
    expect(padrao.length).toBeGreaterThan(0);
    const [custom] = buildEntityDetectors(["conselho"]);
    expect(custom?.scan(texto)).toHaveLength(0);
    // Nomes reais seguem detectados com a stoplist custom ativa.
    expect(
      custom?.scan("agendar com Mariana Duarte").some((f) => f.rawValue === "Mariana Duarte"),
    ).toBe(true);
  });

  it("continua detectando nome real mesmo perto de texto técnico", () => {
    const f = personNameDetector.scan(
      "O relatório do Transit Gateway foi revisado por Mariana Duarte ontem.",
    );
    expect(f.some((x) => x.rawValue === "Mariana Duarte")).toBe(true);
  });

  it("detecta endereço com logradouro e número", () => {
    const f = postalAddressDetector.scan(
      "Moro na Rua das Flores, 123 no centro",
    );
    expect(f.length).toBeGreaterThan(0);
    expect(f[0]?.dataType).toBe("postal-address");
  });
});

describe("policy — ranking da ação substitute", () => {
  const cpf = finding("cpf", "529.982.247-25");
  const subRule: PolicyRule = {
    id: "sub",
    name: "substitui cpf",
    enabled: true,
    dataTypes: ["cpf"],
    action: "substitute",
  };
  const redactRule: PolicyRule = {
    id: "red",
    name: "redige cpf",
    enabled: true,
    dataTypes: ["cpf"],
    action: "redact",
  };
  const approvalRule: PolicyRule = {
    id: "appr",
    name: "aprova cpf",
    enabled: true,
    dataTypes: ["cpf"],
    action: "require-approval",
  };

  it("substitute vence redact", () => {
    expect(
      evaluatePolicy([cpf], "UserPromptSubmit", [subRule, redactRule]),
    ).toBe("substitute");
  });

  it("require-approval vence substitute", () => {
    expect(
      evaluatePolicy([cpf], "UserPromptSubmit", [subRule, approvalRule]),
    ).toBe("require-approval");
  });
});
