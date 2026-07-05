# install-agent.ps1 — instala o agente claude-guardian em uma máquina Windows
# e o conecta ao servidor central da empresa.
#
# Uso (PowerShell como usuário; a tarefa agendada pede elevação se necessário):
#   powershell -ExecutionPolicy Bypass -File enterprise\install-agent.ps1 `
#     -Server https://guardian.empresa.com -EnrollToken <GUARDIAN_ENROLLMENT_SECRET>
#   (ou -Key <GUARDIAN_AGENT_KEY> para a chave compartilhada legada)
#
# O que faz:
#   1. Verifica Node.js >= 22.6
#   2. Instala dependências npm
#   3. Registra os hooks no Claude Code (config apontando para o central)
#   4. Registra o daemon local como tarefa agendada de logon (sem dependências
#      externas — node.exe não implementa o protocolo SCM de serviço nativo)
#
# WSL: o daemon instalado aqui atende também os hooks rodando dentro da distro
# (WSL2 encaminha localhost) e a extensão dos browsers do Windows.
param(
  [Parameter(Mandatory = $true)][string]$Server,
  [string]$Key = "",
  [string]$EnrollToken = "",
  [switch]$NoService
)

if (-not $Key -and -not $EnrollToken) {
  throw "Informe -EnrollToken <token> (enrollment por maquina) ou -Key <chave legada>."
}

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)

function Ok($msg)   { Write-Host "[ok] $msg" -ForegroundColor Green }
function Info($msg) { Write-Host "[..] $msg" -ForegroundColor Cyan }
function Warn($msg) { Write-Host "[!!] $msg" -ForegroundColor Yellow }

# ── 1. Node.js ────────────────────────────────────────────────────────────────
Info "1/4 Verificando Node.js"
$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) { throw "Node.js nao encontrado. Instale Node.js >= 22.6.0: https://nodejs.org" }
$nodeVersion = (& node -e "process.stdout.write(process.version)")
$major = [int]($nodeVersion.TrimStart("v").Split(".")[0])
if ($major -lt 22) { throw "Node.js $nodeVersion detectado - minimo exigido: 22.6.0" }
Ok "Node.js $nodeVersion"

# ── 2. Dependências npm ───────────────────────────────────────────────────────
Info "2/4 Instalando dependencias npm"
Push-Location $RepoRoot
try {
  npm install --silent | Out-Null
  Ok "Dependencias instaladas"
} finally {
  Pop-Location
}

# ── 3. Hooks + config central ─────────────────────────────────────────────────
# Enrollment: troca o token de enrollment por uma chave individual desta
# maquina (revogavel no dashboard). Fail-closed: sem chave, sem instalacao.
if (-not $Key -and $EnrollToken) {
  Info "Registrando esta maquina no servidor central (enrollment)"
  $body = @{ hostname = $env:COMPUTERNAME } | ConvertTo-Json -Compress
  $resp = Invoke-RestMethod -Method Post -Uri "$($Server.TrimEnd('/'))/api/agent/enroll" `
    -Headers @{ "X-Guardian-Enrollment-Token" = $EnrollToken } `
    -ContentType "application/json" -Body $body -TimeoutSec 10
  if (-not $resp.agentKey) { throw "Enrollment nao retornou uma chave de agente." }
  $Key = $resp.agentKey
  Ok "Maquina registrada - chave individual emitida"
}

Info "3/4 Registrando hooks e config central"
& node --experimental-strip-types (Join-Path $RepoRoot "src\cli\index.ts") init `
  --central-url $Server --central-key $Key
Ok "Agente configurado"

# ── 4. Daemon como tarefa agendada de logon ───────────────────────────────────
# A extensao de navegador e fail-closed: sem o daemon em 127.0.0.1:7734, os
# sites de IA ficam bloqueados — o daemon precisa subir sozinho no logon.
if ($NoService) {
  Warn "-NoService: daemon nao registrado (suba com: npm run serve)"
} else {
  Info "4/4 Registrando o daemon como tarefa agendada de logon"
  $taskName = "ClaudeGuardianDaemon"
  $action = New-ScheduledTaskAction -Execute $node.Source `
    -Argument "--experimental-strip-types `"$(Join-Path $RepoRoot 'src\cli\index.ts')`" serve" `
    -WorkingDirectory $RepoRoot
  $trigger = New-ScheduledTaskTrigger -AtLogOn
  $settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Days 3650) -Hidden

  Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
  Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Settings $settings -Description "Claude Guardian DLP daemon (scan local)" | Out-Null
  Start-ScheduledTask -TaskName $taskName
  Ok "Tarefa '$taskName' registrada e iniciada (reinicia no logon)"
}

Write-Host ""
Write-Host "==============================================" -ForegroundColor White
Write-Host "  claude-guardian (agente enterprise) pronto"   -ForegroundColor White
Write-Host "==============================================" -ForegroundColor White
Write-Host ""
Write-Host "  Servidor central:  $Server"
Write-Host "  Daemon local:      http://127.0.0.1:7734 (extensao de navegador + WSL)"
Write-Host ""
Write-Host "  Reinicie o Claude Code para ativar os hooks." -ForegroundColor Yellow
