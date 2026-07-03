# Claude Guardian — Guia para Apresentação

Explicação simples do que é o projeto, como ele funciona e o que tem em cada pasta.

---

## 1. O que é o projeto?

O **Claude Guardian** é uma ferramenta de **DLP (Data Loss Prevention / Prevenção de Vazamento de Dados)**
para o **Claude Code** (o assistente de IA que roda no terminal).

**Problema que resolve:** quando você usa um assistente de IA, ele lê arquivos, roda comandos e
recebe textos seus. Às vezes, sem querer, isso pode incluir senhas, chaves de API, tokens, CPF,
e-mails, cartões de crédito etc. Esses dados podem acabar indo para a IA (e potencialmente
vazando) sem ninguém perceber.

**O que o Guardian faz:** ele se "encaixa" no Claude Code como um porteiro. Antes (e depois) de
cada ação — ler um arquivo, rodar um comando, enviar uma mensagem — ele **escaneia o conteúdo**
procurando por segredos e dados sensíveis. Dependendo da política configurada, ele pode:

- ✅ **Permitir** (allow)
- ⛔ **Bloquear** (block)
- ✏️ **Censurar/redigir** o conteúdo (redact) — troca o valor sensível por `[REDACTED:...]`
- ⏸️ **Pedir aprovação** (require-approval) — fica pendente até alguém aprovar manualmente

Tudo fica registrado em um **log de auditoria à prova de adulteração** (hash chain), e existe um
**dashboard web** para visualizar incidentes, aprovações e métricas.

---

## 2. Como ele "se conecta" ao Claude Code

O Claude Code tem um sistema de **hooks** (ganchos): pontos onde ele chama scripts externos antes
ou depois de certas ações. O Guardian se registra em 3 desses hooks:

| Hook | Quando dispara | O que pode fazer |
|---|---|---|
| **UserPromptSubmit** | Quando você envia uma mensagem | Bloquear ou censurar o que você digitou |
| **PreToolUse** | Antes da IA usar uma ferramenta (ler arquivo, rodar comando, etc.) | Bloquear a ação |
| **PostToolUse** | Depois que a ferramenta rodou | Apenas registra (auditoria), não bloqueia |

Cada hook recebe um JSON pela entrada padrão (stdin), roda o "motor de varredura" em até **500ms**
(se demorar mais, bloqueia por segurança — "fail-safe"), e responde permitindo ou bloqueando.

---

## 3. Fluxo geral (passo a passo)

```
Você digita algo / a IA tenta ler um arquivo ou rodar um comando
        │
        ▼
   Hook é chamado (pre-tool-use, user-prompt-submit ou post-tool-use)
        │
        ▼
   Motor de varredura (engine) roda 40+ "detectores"
   procurando chaves de API, senhas, CPF, cartão, e-mail etc.
        │
        ▼
   Motor de políticas decide: allow / block / redact / require-approval
        │
        ├── allow  → segue normalmente
        ├── redact → troca o trecho sensível por [REDACTED:...]
        ├── block  → ação é cancelada, erro mostrado pro usuário
        └── require-approval → fica pendente até alguém aprovar no dashboard/CLI
        │
        ▼
   Tudo é gravado no banco SQLite:
   - "incidents" (o que foi achado)
   - "approvals" (pedidos de aprovação)
   - "audit_log" (log com hash em cadeia, não pode ser adulterado sem detectar)
        │
        ▼
   Dashboard (localhost:7734) mostra tudo isso em tempo real
```

---

## 4. Estrutura de pastas (o que tem em cada lugar)

```
claude-guardian/
├── src/
│   ├── hooks/              ← os 3 "pontos de entrada" chamados pelo Claude Code
│   │   ├── pre-tool-use.ts        (antes de rodar uma ferramenta — pode bloquear)
│   │   ├── post-tool-use.ts       (depois — só audita, nunca bloqueia)
│   │   └── user-prompt-submit.ts  (quando você manda uma mensagem)
│   │
│   ├── engine/              ← o "motor" que faz a varredura de conteúdo
│   │   ├── index.ts                (função scan/scanSync — roda todos os detectores)
│   │   ├── utils.ts
│   │   └── detectors/              ← cada arquivo é um "detector" de um tipo de dado
│   │       ├── aws.ts, github.ts, gitlab.ts, slack.ts, stripe.ts, openai.ts, gcp.ts...
│   │       │     (detectam chaves/tokens de cada serviço)
│   │       ├── pii-email.ts, pii-cpf/cnpj (pii-br.ts), pii-credit-card.ts,
│   │       │   pii-ssn.ts, pii-iban.ts, pii-phone.ts, pii-ip.ts
│   │       │     (detectam dados pessoais: e-mail, CPF, cartão, telefone, IP...)
│   │       ├── private-key.ts, jwt.ts, connection-string.ts, generic-secret.ts,
│   │       │   high-entropy.ts, gitleaks.ts
│   │       │     (detectam chaves privadas, tokens JWT, strings de conexão de
│   │       │      banco de dados, senhas genéricas, e segredos "aleatórios")
│   │       └── index.ts            (lista todos os detectores numa lista única)
│   │
│   ├── lib/                 ← regras de negócio
│   │   ├── policy.ts               (decide allow/block/redact/require-approval)
│   │   ├── approval.ts             (gerencia pedidos de aprovação e seus prazos)
│   │   ├── audit.ts                (cria e verifica o log de auditoria com hash chain)
│   │   ├── incident.ts             (salva os "incidentes" encontrados no banco)
│   │   └── regex-generator.ts      (ajuda a criar novas regras/regex)
│   │
│   ├── config/              ← carregamento e valores padrão de configuração
│   │   ├── defaults.ts
│   │   └── loader.ts
│   │
│   ├── db/                   ← banco de dados (SQLite)
│   │   ├── client.ts               (abre/cria o banco)
│   │   └── schema.ts               (estrutura das tabelas: incidents, approvals, audit_log)
│   │
│   ├── server/               ← servidor do dashboard
│   │   └── api.ts                  (API web: /dashboard, /api/incidents, /api/approvals...)
│   │
│   ├── cli/                  ← comandos de linha de comando
│   │   ├── index.ts
│   │   └── commands/
│   │       ├── init.ts             (configura tudo na primeira vez)
│   │       ├── serve.ts            (sobe o dashboard)
│   │       ├── scan.ts             (escaneia um arquivo/texto manualmente)
│   │       ├── approve.ts          (aprova/nega pedidos de exceção)
│   │       └── policy.ts           (lista as regras/políticas ativas)
│   │
│   └── types/                ← tipos TypeScript compartilhados
│
├── public/
│   └── dashboard.html        ← página HTML do dashboard
│
├── tests/                     ← testes automatizados (vitest)
│   ├── engine.test.ts, policy.test.ts, audit.test.ts, adapter.test.ts
│
├── claude-guardian.config.json          ← configuração ativa (regras, políticas, allowlist)
├── claude-guardian.config.example.json  ← exemplo de configuração
├── README.md                  ← documentação técnica completa
├── CLAUDE.md                  ← guia do projeto para o Claude Code
├── init.sh / init.ps1         ← scripts de instalação (Linux/Mac e Windows)
└── package.json                ← dependências e scripts npm
```

---

## 5. Os "detectores" — o que ele consegue identificar

São mais de 40 detectores, organizados em duas categorias:

**Segredos / credenciais (críticos):**
- Chaves AWS, Anthropic, OpenAI, GitHub, GitLab, Stripe, GCP, Slack, npm, SendGrid,
  Mailgun, Mailchimp, Twilio, Discord, Telegram
- Chaves privadas (PEM), tokens JWT, strings de conexão de banco de dados
- Senhas/segredos genéricos em arquivos `.env`
- Valores com "alta entropia" (parecem chaves aleatórias mesmo sem padrão conhecido)

**Dados pessoais (PII):**
- E-mail, telefone (BR/US/JP), CPF, CNPJ, cartão de crédito (validado por Luhn),
  SSN (americano), IBAN, IPs privados

Cada detector tem uma **severidade** (critical / high / medium / low), que é usada pelo motor de
políticas para decidir o que fazer.

---

## 6. Motor de políticas (regras)

As regras ficam no `claude-guardian.config.json`. Exemplo simples:

- "Se achar uma chave AWS ou chave privada **crítica** → **bloquear**"
- "Se achar e-mail, CPF ou cartão de crédito → **pedir aprovação** antes de continuar"

A regra de **maior prioridade** vence: `block > require-approval > redact > allow`.

---

## 7. Funcionalidades especiais

- **`[allow-guardian]`**: se você colocar essa tag na sua mensagem, o Guardian libera aquela
  ação (mas registra no log de auditoria que isso aconteceu).
- **`[request-exception: motivo]`**: pede uma exceção formal — cria um pedido de aprovação
  pendente e te dá o link do dashboard para acompanhar.
- Arquivos `.env` são bloqueados **só pelo nome**, antes mesmo de tentar ler o conteúdo.
- Comandos de terminal (`cat`, `head`, `tail`...) também são analisados para ver quais
  arquivos eles tentam abrir.

---

## 8. Dashboard

Rodando `npm run serve`, abre em `http://localhost:7734/dashboard`:
- **Incidentes**: tudo que foi detectado
- **Aprovações**: pedidos pendentes de exceção
- **Audit Log**: histórico completo, com botão para "Verificar Cadeia" (verifica se ninguém
  adulterou o log)
- **Métricas**: estatísticas gerais

Acesso protegido por um token (`X-Guardian-Token` ou `?token=`).

---

## 9. Resumo para a apresentação (1 frase por seção)

1. **Objetivo**: evitar que segredos e dados pessoais vazem para a IA durante o uso do Claude Code.
2. **Como entra**: via 3 hooks do Claude Code (antes/depois de ações e ao enviar mensagens).
3. **Como detecta**: 40+ detectores baseados em regex/validação (AWS, GitHub, CPF, e-mail etc.).
4. **Como decide**: motor de políticas configurável (bloquear, censurar, pedir aprovação, permitir).
5. **Onde guarda**: banco SQLite local, com log de auditoria à prova de adulteração (hash chain).
6. **Como visualiza**: dashboard web local (`localhost:7734`).
7. **Segurança**: roda 100% local, falha sempre para o lado seguro (bloqueia em caso de erro/timeout).
