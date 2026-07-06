# Catálogo de Detectores na aba Policies

## Papel

Você é o engenheiro responsável pelo `claude-guardian`, um DLP que roda como hooks do Claude Code. Vai estender a aba "Policies" do dashboard (`public/dashboard.html`) para expor um catálogo de detectores, sem tocar no fluxo de edição de regras já existente.

## Objetivo

Hoje a aba Policies só mostra a tabela de **regras** (`config.policies`) — ação, severidade-limite, enabled/disabled. Não existe visão por **detector**: os ~35 detectores built-in não expõem o regex que usam (é uma `const` privada dentro de cada arquivo de detector, fechada no `scan()`), e não há agrupamento por categoria. Adicione uma seção "Detectores" dentro da aba Policies que resolve isso, com uma interface mais densa e profissional que a atual.

## Contexto (arquitetura atual, já investigada)

- `Detector` (`src/engine/detectors/types.ts`) tem hoje `id/label/dataType/severity/scan`. Cada detector exportado usa **exatamente 1 regex própria** guardada como `const` no topo do arquivo (ex.: `EMAIL_RE` em `pii-email.ts`, `ACCESS_KEY_RE`/`SECRET_KEY_RE` em `aws.ts`, `NPM_RE`/`SENDGRID_RE`/etc. em `generic-secret.ts` — um detector por regex, mesmo quando várias constantes convivem no mesmo arquivo). Não há nenhum detector com múltiplos regexes internos.
- `BUILT_IN_DETECTORS` (`src/engine/detectors/index.ts`) é a lista estática desses detectores, já ordenada critical → high → medium.
- `entityDetectors` (`src/engine/detectors/entity.ts`, exportado como `entityDetectors`) tem 2 detectores **sem regex**: `personNameDetector` (heurística de tokens capitalizados + blocklist de falsos positivos, ver `NON_NAMES`) e `postalAddressDetector` (heurística de padrão de endereço). São extraDetectors, só entram quando `config.entityDetection` é true.
- `gitleaksDetector` (`src/engine/detectors/gitleaks.ts`) é um wrapper de uma ferramenta externa: gera sub-detectores dinâmicos `gl:${RuleID}` só em tempo de scan, a partir do ruleset vendorizado. Não há lista estática enumerável.
- Detectores **custom** (criados pelo usuário via `POST /api/policies/custom`) já guardam o regex como dado real (`store.listCustomDetectors()` retorna `{id, name, description, regex, severity, action, examples, createdAt}`), e a tabela de regras atual (`public/dashboard.html`, função `loadPolicies`, ~linha 2122) já renderiza esse regex num `<span class="regex-pill">` quando a regra é custom.
- CSS já existe para reaproveitar: `.regex-pill` (linha ~585), `.custom-badge` (linha ~578), função JS `badge(text, cls)` (linha ~1482), variáveis de cor por severidade `--critical/--critical-light/--critical-border`, `--high/-light/-border`, `--medium/-light/-border`, `--low/-light/-border`.
- A aba Policies vive em `<div class="tab-content" id="tab-policies">` (linha ~1182); o carregamento ao trocar de aba está em `if (name === 'policies') { loadPolicies(); loadAllowlist(); loadSettings(); }` (linha ~1424).

## Tarefas

### 1. Backend — expor o regex real sem duplicar a fonte da verdade

Em cada arquivo de `src/engine/detectors/*.ts` que define um detector built-in regex-based, adicione ao objeto `Detector` um campo `pattern: <NOME_DA_CONST>.source` (reaproveitando a mesma constante já usada dentro do `scan()` — não crie uma segunda string com o regex, isso criaria risco de divergência entre o que a tela mostra e o que realmente roda).

- Adicione `pattern?: string` à interface `Detector` em `src/engine/detectors/types.ts`.
- Adicione também `kind?: "regex" | "heuristic" | "external"` (default implícito `"regex"` quando `pattern` está presente) e `description?: string` (usado pelos casos sem regex).
- Em `entity.ts`: `personNameDetector` e `postalAddressDetector` recebem `kind: "heuristic"` e uma `description` curta e honesta (baseada nos comentários já existentes no arquivo — não invente detalhes que o código não implementa).
- Em `gitleaks.ts`: o detector `gitleaksDetector` (o objeto estático exportado, não os `gl:*` dinâmicos) recebe `kind: "external"`, sem `pattern`, com `description: "Motor de regras vendorizado (gitleaks) — dispara sub-regras dinâmicas (gl:<RuleID>) que não são enumeráveis estaticamente."`.
- Detectores custom continuam vindo pelo endpoint `/api/policies/custom` já existente — não precisam de `pattern`/`kind` no objeto `Detector`, o endpoint novo (passo 2) já sabe tratá-los como `kind: "custom"`.

### 2. Backend — novo endpoint `GET /api/detectors`

Em `src/server/api.ts`, ao lado do bloco `// ── Policies ──` (~linha 514), adicione:

```
GET /api/detectors
```

Retorna um array combinando:
- `BUILT_IN_DETECTORS` (importe de `../engine/detectors/index.ts`) serializados como `{id, label, dataType, severity, kind: d.kind ?? "regex", pattern: d.pattern, description: d.description}`.
- `entityDetectors` (importe de `../engine/detectors/entity.ts`), sempre incluídos no catálogo (mesmo que `config.entityDetection` esteja off — a tela é sobre o que existe, não sobre o que está ativo; se quiser sinalizar "inativo" use um campo `active: config.entityDetection`).
- O `gitleaksDetector` estático (importe de `../engine/detectors/gitleaks.ts`), com `active: true` sempre (é adicionado incondicionalmente em `user-prompt-submit.ts`).
- `await store.listCustomDetectors()`, mapeados para o mesmo shape com `kind: "custom"`, `pattern: c.regex`.

Cada item do array final deve ter o shape uniforme: `{ id, label, dataType, severity, kind, pattern?, description?, active? }`.

### 3. Frontend — sub-navegação dentro da aba Policies

Dentro de `#tab-policies`, logo abaixo de `.policies-toolbar` (~linha 1183) e antes da tabela de regras existente, adicione um sub-seletor de duas abas: **"Regras"** (mostra a tabela atual, sem nenhuma mudança de comportamento) e **"Detectores"** (nova seção). Use o mesmo padrão visual dos `.nav-item` já existentes, adaptado a um contexto de sub-tab (pill/segmented control), guardando o estado em uma variável JS simples (ex.: `policiesSubTab`) e chamando `loadDetectors()` na primeira vez que "Detectores" é aberto.

### 4. Frontend — catálogo de detectores

Implemente `async function loadDetectors()` que busca `GET /api/detectors` e renderiza:

- **Agrupamento por categoria**, na ordem: Secrets (`kind === "regex"` com `dataType` em algo como aws-key/github/gitlab/stripe/gcp/npm/slack/discord/telegram/sendgrid/mailgun/mailchimp/twilio/jwt/private-key/generic-secret/connection-string/hex — use o `dataType` do detector, não invente uma nova taxonomia: agrupe visualmente por `dataType` dentro da seção "Secrets" vs "PII"), PII (`email/phone-*/cpf/cnpj/ssn/credit-card/iban/private-ip/person-name/postal-address`), Custom (`kind === "custom"`), Heurístico (`kind === "heuristic"`), Externo (`kind === "external"`).
- Cada detector é uma linha/card com: `id` (mono, pequeno), `label`, badge de severidade (reaproveite `badge()` + as cores `--critical/--high/--medium/--low` já existentes), badge de `dataType`.
- Se `kind === "regex"` ou `"custom"`: mostre o `pattern` num `<code>` dentro de `.regex-pill` (reaproveite a classe existente), com **highlight leve de sintaxe** feito em JS puro (sem lib nova): tokenize a string em metacaracteres (`\ ^ $ . | ? * + ( ) [ ] { }`) vs literais, envolvendo os metacaracteres num `<span>` com uma cor discreta diferente do texto literal. Mantenha simples — não é para construir um parser de regex completo, só diferenciar visualmente metachar de literal caractere a caractere.
- Se `kind === "heuristic"` ou `"external"`: no lugar do regex, mostre a `description` em texto normal (itálico ou cor secundária), sem fingir que existe um pattern.
- Adicione um campo de busca (filtra por `id`, `label`, `dataType` e, quando existir, `pattern`) e botões de filtro por categoria acima da lista.
- **Cross-reference com regras**: para cada detector, calcule client-side quantas regras de `config.policies` (já carregadas por `loadPolicies`) o referenciam — via `detectorIds` contendo o `id`, ou via `dataTypes` contendo o `dataType` do detector. Mostre essa contagem como badge clicável; ao clicar, mude para a sub-aba "Regras" e dê scroll/highlight temporário (ex.: classe CSS com transição de background por ~1.5s) nas linhas correspondentes da tabela de regras.
- Sempre escape valores vindos da API com a função `escHtml` já usada no arquivo (evite XSS via `label`/`description`/`pattern` de detectores custom, que são input do usuário).

## Regras

- Não altere o comportamento nem o schema de `/api/policies`, `/api/policies/custom` ou a tabela de regras existente — a nova seção é 100% aditiva.
- Não crie um "toggle on/off" por detector built-in — isso não foi pedido e hoje só existe no nível de regra.
- Não tente enumerar as sub-regras dinâmicas do gitleaks (`gl:*`) — trate o gitleaks como uma única entrada "externa".
- Não adicione um "testador de string ao vivo" contra os regexes — fora de escopo desta rodada.
- O campo `pattern` deve sempre vir do `.source` da regex real usada no `scan()` — nunca de uma string escrita à mão em paralelo.

## Critérios de qualidade

- `npm run typecheck` e `npm run lint` passam.
- Testes existentes (`tests/corpus.test.ts`, `tests/substitute.test.ts`, etc.) continuam passando sem alteração — a extensão de `Detector` com campos opcionais não pode quebrar nenhum detector existente.
- Abrir a aba Policies → sub-aba Detectores mostra os ~35 built-ins + 2 heurísticos + 1 externo (gitleaks) + custom (se houver), agrupados, com busca funcionando e regex/description corretos por amostragem manual (ex.: conferir que `pii-email` mostra o mesmo regex de `EMAIL_RE`).
- Clicar na contagem de regras de um detector realmente rola até e destaca a(s) linha(s) certa(s) na tabela de regras.

## Edge cases

- Detector custom com `pattern`/`label`/`description` contendo HTML ou aspas — não pode quebrar o layout nem executar script (escape obrigatório).
- `config.entityDetection` desligado — os 2 heurísticos ainda aparecem no catálogo, mas marcados como inativos (`active: false`), para o usuário saber que existem mas não estão rodando.
- Nenhuma regra referenciando um detector — badge de contagem mostra "0", sem erro.
- Busca sem resultados em nenhuma categoria — mostrar estado vazio, não uma tela em branco.
