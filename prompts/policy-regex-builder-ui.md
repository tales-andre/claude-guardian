# Prompt: Criador Intuitivo de Regras de Bloqueio por Regex no Dashboard de Policies

```
## Papel

Você é um engenheiro full-stack sênior com especialização em UI/UX para ferramentas de segurança e profundo conhecimento em geração inteligente de expressões regulares. Você vai implementar uma funcionalidade completa no dashboard existente do `claude-guardian`, uma plataforma DLP (Data Loss Prevention).

---

## Contexto da Aplicação

O `claude-guardian` é uma plataforma DLP que intercepta inputs/outputs do Claude Code via hooks. Ela possui um dashboard web (Fastify + HTML/JS vanilla em `public/dashboard.html`) com uma aba chamada **"Policies"** que exibe as regras de bloqueio ativas.

A configuração de policies é persistida em `claude-guardian.config.json` com o seguinte formato de regra:

```json
{
  "id": "custom-rule-001",
  "name": "Número de Projeto Interno",
  "dataTypes": ["custom"],
  "tools": ["*"],
  "action": "block",
  "detectorIds": ["custom-regex-001"]
}
```

Detectores customizados ficam em `src/engine/detectors/` e implementam a interface:

```ts
interface Detector {
  id: string;
  label: string;
  dataType: DataType;
  severity: Severity;
  scan(text: string): DetectorFinding[];
}
```

---

## Objetivo

Implemente, dentro da aba "Policies" do dashboard, um **criador intuitivo de regras de bloqueio por padrão** que permita ao usuário:

1. Descrever o que quer bloquear em linguagem natural (ex: "número de funcionário", "código de projeto")
2. Fornecer entre 3 e 10 exemplos reais do padrão (ex: `EMP-00123`, `EMP-99456`, `PROJ-ABC-01`)
3. Receber uma regex gerada automaticamente com explicação legível
4. Testar a regex em tempo real com novos valores antes de salvar
5. Salvar a regra, que passa a funcionar imediatamente nos hooks

---

## O Que Implementar

### 1. Modal/Painel "Nova Regra Customizada"

Adicione um botão **"+ Nova Regra"** na aba Policies. Ao clicar, abre um painel (modal ou sidebar expansível) com o seguinte fluxo em 3 etapas visuais:

**Etapa 1 — Descreva o padrão:**
- Campo: `Nome da regra` (ex: "Código de Projeto Interno")
- Campo: `Descrição livre` (ex: "Formato PROJ-[A-Z]+-[0-9]+")
- Ação pretendida: `[ ] Bloquear  [ ] Requerer aprovação  [ ] Redigir`
- Severidade: `[ ] critical  [ ] high  [ ] medium  [ ] low`

**Etapa 2 — Forneça exemplos:**
- Input dinâmico: o usuário digita um exemplo e pressiona Enter para adicionar à lista
- Mínimo de 2 exemplos para liberar o botão "Gerar Regex"
- Botão: **"Gerar Regex Inteligente"** — faz POST `/api/policies/generate-regex` com os exemplos

**Etapa 3 — Revise e teste:**
- Exibe a regex gerada com destaque de sintaxe
- Explicação em linguagem natural do que a regex captura (ex: "Captura strings no formato LETRA-LETRAS-NÚMEROS")
- Campo de teste ao vivo: o usuário digita um valor e vê em tempo real se dá match (verde) ou não (vermelho)
- Botão **"Salvar Regra"** — faz POST `/api/policies/custom`

---

### 2. Endpoint: `POST /api/policies/generate-regex`

**Input:**
```json
{
  "examples": ["EMP-00123", "EMP-99456", "EMP-10001"]
}
```

**Lógica de geração inteligente (implemente em `src/lib/regex-generator.ts`):**

Aplique as seguintes heurísticas em sequência para extrair estrutura dos exemplos:

1. **Prefixo/sufixo literal fixo**: detecte partes que aparecem idênticas em todos os exemplos → trate como literal
2. **Separadores consistentes**: detecte `-`, `_`, `/`, `.` que aparecem na mesma posição relativa → trate como literal
3. **Segmentos alfanuméricos**: para cada segmento variável, analise:
   - Apenas dígitos → `\d{min,max}` (use comprimento mínimo e máximo observados)
   - Apenas letras maiúsculas → `[A-Z]{min,max}`
   - Apenas letras minúsculas → `[a-z]{min,max}`
   - Misto → `[A-Za-z0-9]{min,max}`
4. **Âncoras de palavra**: adicione `\b` no início e fim para evitar matches parciais
5. **Fallback**: se não houver padrão detectável, retorne a regex mais literal possível e avise o usuário

**Output:**
```json
{
  "regex": "\\bEMP-\\d{4,6}\\b",
  "explanation": "Captura strings que começam com 'EMP-' seguido de 4 a 6 dígitos numéricos",
  "confidence": "high",
  "matchCount": 3,
  "missCount": 0
}
```

---

### 3. Endpoint: `POST /api/policies/custom`

**Input:**
```json
{
  "name": "Número de Funcionário",
  "description": "Identificador interno no formato EMP-NNNNN",
  "regex": "\\bEMP-\\d{4,6}\\b",
  "action": "block",
  "severity": "high",
  "examples": ["EMP-00123", "EMP-99456"]
}
```

**Comportamento:**
1. Valide a regex com `new RegExp(regex)` — retorne 400 se inválida
2. Gere IDs: `detectorId = "custom-" + slugify(name)`, `ruleId = "rule-" + detectorId`
3. Persista no banco: crie uma nova linha em `incidents`... não — salve em `custom_detectors` (crie a tabela se não existir): colunas `id`, `name`, `description`, `regex`, `severity`, `created_at`, `examples_json`
4. Salve também a policy rule no `config.json` vigente via `loadConfig()` + reescrita do arquivo
5. Retorne `{ success: true, detectorId, ruleId }`

---

### 4. Detector Dinâmico (`src/engine/detectors/custom.ts`)

Crie um detector que carrega as regras custom do banco no momento da inicialização:

```ts
export function loadCustomDetectors(db: Database): Detector[] {
  // lê linhas de custom_detectors, retorna array de Detector
  // cada Detector.scan() aplica a regex e retorna findings
}
```

Registre este loader em `src/engine/index.ts` junto com `BUILT_IN_DETECTORS`.

---

## Regras de Implementação

- Todo código novo em TypeScript estrito (sem `any`)
- Nenhuma dependência nova: use apenas o que já está em `package.json`
- A geração de regex acontece **no servidor** — o frontend só exibe o resultado
- O campo de **teste ao vivo** (Etapa 3) roda a regex no **frontend** via `new RegExp()` — sem chamada de rede
- O modal deve fechar e recarregar a lista de policies após salvar com sucesso
- Mensagens de erro no painel (não alertas do browser)
- A regex é exibida em `<code>` com fonte monoespaçada; a explicação em texto normal abaixo

---

## Critérios de Qualidade

- Regex geradas devem ter recall ≥ 100% nos exemplos fornecidos (nenhum exemplo pode falhar o match)
- A explicação deve ser legível por alguém sem conhecimento de regex
- O fluxo completo (descrever → exemplos → regex → testar → salvar) deve ser concluível em menos de 60 segundos
- Detectores custom carregados devem ser indistinguíveis dos built-ins na execução do engine

---

## Edge Cases a Tratar

- Exemplos contraditórios (ex: `ABC-123` e `123-ABC`) → avise que o padrão é inconsistente e sugira criar duas regras separadas
- Regex que retorne matches em branco (`""`) → rejeite e mostre erro
- Usuário salva regex que já existe (mesmo padrão) → avise de duplicata, não salve
- Banco sem tabela `custom_detectors` na primeira execução → crie automaticamente via DDL no `getDb()`
```
