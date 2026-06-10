# claude-guardian — servidor central (dashboard + API de ingestão de agentes)
#
# Build:  docker build -t claude-guardian:latest .
# Run:    docker run -p 7734:7734 \
#           -e DATABASE_URL=postgres://user:pass@host:5432/guardian \
#           -e GUARDIAN_DASHBOARD_TOKEN=<token-admin> \
#           -e GUARDIAN_AGENT_KEY=<chave-dos-agentes> \
#           claude-guardian:latest
#
# Sem DATABASE_URL o servidor usa SQLite em /data (monte um volume).

# bookworm-slim (glibc): better-sqlite3 instala via prebuild, sem toolchain.
FROM node:22-bookworm-slim AS deps

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

FROM node:22-bookworm-slim

ENV NODE_ENV=production \
    GUARDIAN_HOST=0.0.0.0 \
    GUARDIAN_PORT=7734 \
    GUARDIAN_DB_PATH=/data/guardian.db

WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
COPY public ./public

# Usuário não-root + diretório de dados gravável (fallback SQLite)
RUN mkdir -p /data && chown -R node:node /data /app
USER node
VOLUME /data

EXPOSE 7734

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.GUARDIAN_PORT||7734)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "--experimental-strip-types", "src/cli/index.ts", "serve"]
