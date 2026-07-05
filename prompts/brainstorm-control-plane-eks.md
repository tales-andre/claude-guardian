Você é engenheiro de plataforma/DevOps trabalhando no repositório `claude-guardian`. Deixe o **control-plane** (servidor central + dashboard + fleet) pronto para deploy repetível em EKS e **prove que funciona** com validação real local, sem acesso a um cluster EKS.

## Contexto (o que já existe — não reescreva, ajuste)
- Helm chart em `deploy/helm/claude-guardian` (deployment non-root, probes em `/health`, `GUARDIAN_BIND_HOST=0.0.0.0`, secrets para `GUARDIAN_DASHBOARD_TOKEN`/`GUARDIAN_AGENT_KEY` e `DATABASE_URL`, ServiceAccount pronto para IRSA, ingress ALB com anotações ACM/TLS).
- `Dockerfile` (node:22-slim, non-root, `GUARDIAN_PORT=7734`) e `docker-compose.yml` (com Postgres) na raiz.
- `PgStore` (`src/server/pg-store.ts`) **auto-migra** no boot via `PG_DDL` (`CREATE TABLE IF NOT EXISTS ...`) chamado em `init()`; `createStore` usa Postgres quando `databaseUrl`/`DATABASE_URL` está setado, senão SQLite.
- Em modo central (Postgres) o servidor é **stateless** — só a rota `scan-web` (modo SQLite local) abre `/data`; portanto o pod NÃO precisa de PVC.
- Endpoints centrais: `GET /health` (público), `POST /api/agent/ingest` e `GET /api/agent/approvals/active` (auth `X-Guardian-Agent-Key`), `GET /api/fleet`, `GET /dashboard` e `GET /api/*` (auth `X-Guardian-Token`).
- Restrição de arquitetura: o audit é um **hash-chain sequencial** — múltiplos writers concorrentes corrompem a cadeia. Manter `replicaCount: 1`.

## Tarefas (nesta ordem, com commits atômicos)
1. **Ajustes de deploy (sem quebrar o modo local):**
   - Garantir que `image.repository`/`image.tag` do `values.yaml` sejam claramente parametrizáveis para um URI de ECR (ex.: `123456789012.dkr.ecr.us-east-1.amazonaws.com/claude-guardian`), com comentário explicando o build→push.
   - Adicionar comentário em `values.yaml` e no template de deployment deixando explícito **por que `replicaCount` deve ser 1** (hash-chain do audit) e o que seria necessário para HA.
   - Manter o ALB **parametrizável**: default `scheme: internal` (mais seguro), com comentário claro de quando trocar para `internet-facing` (agentes em laptops fora da VPC/VPN). Não hardcodar.
2. **Validar o chart estaticamente:** rodar `helm lint deploy/helm/claude-guardian` e `helm template` com valores de exemplo (RDS URL, tokens, ingress host). Se `helm` não estiver disponível no ambiente, instalar localmente ou usar `docker run` com uma imagem que tenha helm; registrar o comando e a saída. O template deve renderizar sem erro.
3. **Prova real local (o coração da entrega):** subir o servidor central de verdade contra Postgres via `docker-compose` (build da imagem + Postgres do compose). Depois exercitar e **capturar evidência**:
   - `GET /health` → 200.
   - `POST /api/agent/ingest` com header `X-Guardian-Agent-Key` correto → aceita (idempotente); com chave errada/ausente → rejeita (fail-closed).
   - `GET /api/fleet` e `GET /api/incidents` (com `X-Guardian-Token`) → retornam o que foi ingerido.
   - Confirmar que as tabelas foram criadas automaticamente no Postgres (sem passo de migração manual).
   Reportar os códigos HTTP e trechos de resposta como prova. Derrubar o compose ao final.
4. **Runbook de deploy EKS:** criar/atualizar um doc (`docs/EKS-DEPLOY.md`) com o passo a passo real: build da imagem → push pro ECR → `helm install` com `--set` para `image.repository`, `database.url` (ou `existingSecret`), `auth.*`, `ingress.host` e ACM ARN; incluir os dois modos de ALB (interno vs internet-facing) e a nota de `replicaCount=1`. Sem placeholders vagos — comandos completos e prontos para copiar (com valores de exemplo claramente marcados).

## Regras
- Não quebrar o modo local (SQLite). Rodar `npm run ci` (typecheck + biome + vitest) e deixar verde.
- Não tentar deployar em um EKS real (sem acesso); a validação é local via docker-compose + `helm template`.
- Parametrizar tudo que é específico do ambiente (ECR URI, ALB scheme, host, ACM ARN) — nada hardcodado.
- Reportar faithfully: se `helm` ou `docker` não estiverem disponíveis, dizer explicitamente e entregar o que der, sem fingir sucesso.
- Commits atômicos e mensagens em pt-BR, terminando com a linha de co-autoria do projeto.

## Critérios de qualidade (a entrega só está pronta se)
- `helm template` renderiza o chart sem erro com os valores de exemplo.
- A prova local passou: `/health` 200, `ingest` autenticado aceito e não-autenticado rejeitado, `fleet`/`incidents` refletindo o ingerido, tabelas criadas automaticamente no Postgres — com evidência mostrada.
- `npm run ci` verde.
- `docs/EKS-DEPLOY.md` permite a um terceiro subir o control-plane sem adivinhar nada além dos valores específicos do ambiente dele.

## Edge cases a cobrir
- Postgres indisponível no boot → comportamento (crash claro vs retry) documentado.
- Chave de agente ausente/errada → ingest rejeitado (fail-closed), provado no teste.
- ALB interno com agentes externos → alertar no runbook que os agentes não alcançariam o central.
