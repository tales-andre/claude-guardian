# Template de unit systemd para o daemon local do claude-guardian.
# Placeholders __NODE__/__REPO__/__USER__ são substituídos pelo install-agent.sh.
# A extensão de navegador é fail-closed: sem este daemon vivo, os sites de IA
# ficam bloqueados — por isso Restart=always.
[Unit]
Description=Claude Guardian DLP daemon (scan local para hooks e extensão de navegador)
After=network.target

[Service]
Type=simple
User=__USER__
ExecStart=__NODE__ --experimental-strip-types __REPO__/src/cli/index.ts serve
WorkingDirectory=__REPO__
Restart=always
RestartSec=3
# Loopback apenas; nunca exponha o daemon na rede.
Environment=GUARDIAN_BIND_HOST=127.0.0.1

[Install]
WantedBy=multi-user.target
