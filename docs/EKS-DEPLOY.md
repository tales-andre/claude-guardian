# Deploy do control-plane no EKS

O control-plane do claude-guardian (dashboard + API central + fleet) é
**stateless** em modo central: todo o estado vive no Postgres (RDS/Aurora). O
pod não precisa de volume. Este guia sobe o servidor central; a distribuição do
cliente (agentes/extensão/proxy) é tratada à parte.

> **Escopo:** control-plane. Substitua os valores marcados `<...>` pelos do seu
> ambiente. Nada aqui precisa de CA/proxy — isso é da camada de cliente.

## Pré-requisitos
- Cluster EKS com o **AWS Load Balancer Controller** instalado (para o Ingress ALB).
- **RDS/Aurora PostgreSQL** acessível pelos nós do cluster (a mesma VPC/SG).
- Um repositório **ECR** para a imagem.
- `helm` (v3+/v4), `kubectl`, `docker` e `aws` CLI configurados.

## 1. Build e push da imagem para o ECR

```bash
AWS_ACCOUNT=<123456789012>
REGION=<us-east-1>
ECR=$AWS_ACCOUNT.dkr.ecr.$REGION.amazonaws.com/claude-guardian
TAG=1.0.0

# cria o repo (idempotente) e loga no ECR
aws ecr describe-repositories --repository-names claude-guardian --region $REGION >/dev/null 2>&1 \
  || aws ecr create-repository --repository-name claude-guardian --region $REGION
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ECR

# build + push (na raiz do repo, onde está o Dockerfile)
docker build -t $ECR:$TAG .
docker push $ECR:$TAG
```

## 2. Segredos (recomendado: Secret existente, não versionar credencial)

Gere os tokens e crie o Secret de auth + o de DB no namespace do deploy:

```bash
NS=guardian
kubectl create namespace $NS 2>/dev/null || true

kubectl -n $NS create secret generic guardian-auth \
  --from-literal=GUARDIAN_DASHBOARD_TOKEN="$(openssl rand -hex 24)" \
  --from-literal=GUARDIAN_AGENT_KEY="$(openssl rand -hex 24)"

kubectl -n $NS create secret generic guardian-db \
  --from-literal=DATABASE_URL="postgres://<user>:<senha>@<rds-endpoint>:5432/guardian"
```

Guarde o `GUARDIAN_DASHBOARD_TOKEN` (acesso do time de segurança ao dashboard) e
o `GUARDIAN_AGENT_KEY` (usado pelos agentes nas máquinas). As tabelas do Postgres
são criadas **automaticamente** no boot (`CREATE TABLE IF NOT EXISTS` em
`PgStore.init()`) — não há passo de migração manual.

## 3. `helm install`

```bash
helm install guardian deploy/helm/claude-guardian -n guardian \
  --set image.repository=$ECR \
  --set image.tag=$TAG \
  --set database.existingSecret=guardian-db \
  --set auth.existingSecret=guardian-auth \
  --set ingress.enabled=true \
  --set ingress.host=<guardian.suaempresa.com> \
  --set-string ingress.annotations."alb\.ingress\.kubernetes\.io/certificate-arn"=<arn:aws:acm:...>
```

Valide o render antes, se quiser: `helm template guardian deploy/helm/claude-guardian ... `.

### ALB interno vs internet-facing (decisão importante)
O default é `scheme: internal` (só dentro da VPC/VPN). Escolha pelo **onde os
agentes alcançam o central**:

- **Agentes na rede interna** (VPC/VPN) → mantenha `internal` (mais seguro).
- **Agentes em laptops fora da VPC** → troque para `internet-facing`, senão eles
  não conseguem espelhar incidentes:
  ```bash
  --set-string ingress.annotations."alb\.ingress\.kubernetes\.io/scheme"=internet-facing
  ```
  Com internet-facing, proteja com WAF/allowlist de IP e sempre TLS (ACM).

## 4. Verificação pós-deploy

```bash
kubectl -n guardian rollout status deploy/guardian-claude-guardian
kubectl -n guardian get ingress   # pegue o hostname do ALB

# health (público) e dashboard (com token)
curl -s https://<host>/health
curl -s https://<host>/api/incidents -H "X-Guardian-Token: <GUARDIAN_DASHBOARD_TOKEN>"
```

Um agente aponta para cá com `enterprise/install-agent.sh --server https://<host>
--key <GUARDIAN_AGENT_KEY>`.

## Restrições e operação
- **`replicaCount: 1` (obrigatório).** O audit é um hash-chain sequencial;
  múltiplos writers concorrentes corromperiam a cadeia. O volume de escrita é
  baixo (espelho de incidentes/heartbeats), então 1 réplica basta. HA exigiria
  um lock por-append.
- **Sem PVC.** Em modo central o pod é stateless (só o modo local usa SQLite).
- **Postgres fora do ar no boot** → o pod falha ao iniciar (readiness/liveness em
  `/health` mantêm o pod fora de serviço até o banco voltar); o Deployment
  reinicia. Garanta o SG/rota do RDS antes do deploy.
- **Backup/auditoria** → o estado de verdade é o RDS; use snapshots do RDS.

## Validação local (sem EKS)
Com Docker: `docker compose --env-file .guardian.env up -d` sobe o mesmo servidor
contra um Postgres local — útil para validar imagem + auto-migração antes do EKS.
