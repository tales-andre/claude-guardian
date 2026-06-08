# init.ps1 — instala dependências, gitleaks e sobe o dashboard do claude-guardian
# Requer PowerShell 5.1+ e Node.js >= 22.6.0
#Requires -Version 5.1
$ErrorActionPreference = "Stop"

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Definition
$DashboardPort = 7734
$PidFile    = Join-Path $ScriptDir ".dashboard.pid"
$LogFile    = Join-Path $ScriptDir ".dashboard.log"

function Write-Ok   ($msg) { Write-Host "  [OK] $msg" -ForegroundColor Green  }
function Write-Info ($msg) { Write-Host "    -> $msg" -ForegroundColor Cyan   }
function Write-Warn ($msg) { Write-Host "  [!]  $msg" -ForegroundColor Yellow }
function Write-Die  ($msg) { Write-Host "  [X]  $msg" -ForegroundColor Red; exit 1 }
function Write-Header ($msg) { Write-Host "`n$msg" -ForegroundColor White }

# ── 1. Node.js ────────────────────────────────────────────────────────────────
Write-Header "1/4  Verificando Node.js"

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Die "Node.js nao encontrado. Instale Node.js >= 22.6.0: https://nodejs.org"
}

$nodeVersion = node -e "process.stdout.write(process.version)"
$nodeMajor   = [int]($nodeVersion -replace '^v(\d+).*', '$1')
if ($nodeMajor -lt 22) {
    Write-Die "Node.js $nodeVersion detectado — versao minima exigida: 22.6.0"
}
Write-Ok "Node.js $nodeVersion"

# Aviso sobre better-sqlite3 (requer ferramentas de compilação C++)
Write-Info "Nota: better-sqlite3 requer Visual Studio Build Tools e Python para compilar."
Write-Info "Se o npm install falhar, instale-os em: https://github.com/nodejs/node-gyp#on-windows"

# ── 2. Dependências npm ───────────────────────────────────────────────────────
Write-Header "2/4  Instalando dependencias npm"

Set-Location $ScriptDir

$nmPath = Join-Path $ScriptDir "node_modules"
$pkgPath = Join-Path $ScriptDir "package.json"
if ((Test-Path $nmPath) -and ((Get-Item $nmPath).LastWriteTime -gt (Get-Item $pkgPath).LastWriteTime)) {
    Write-Ok "node_modules ja atualizado (pulando npm install)"
} else {
    Write-Info "Executando npm install..."
    npm install --silent
    if ($LASTEXITCODE -ne 0) { Write-Die "npm install falhou" }
    Write-Ok "Dependencias instaladas"
}

# ── 3. Gitleaks ───────────────────────────────────────────────────────────────
Write-Header "3/4  Verificando Gitleaks"

if (Get-Command gitleaks -ErrorAction SilentlyContinue) {
    $glVer = (gitleaks version 2>$null) -replace '^v', ''
    Write-Ok "Gitleaks ja instalado: $glVer"
} else {
    Write-Info "Gitleaks nao encontrado — instalando..."

    $InstallDir = Join-Path $env:USERPROFILE ".local\bin"
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

    try {
        $releaseJson = Invoke-RestMethod "https://api.github.com/repos/gitleaks/gitleaks/releases/latest"
        $glVersion   = $releaseJson.tag_name -replace '^v', ''
    } catch {
        Write-Warn "Nao foi possivel consultar a API do GitHub. Gitleaks nao sera instalado."
        Write-Warn "O claude-guardian funcionara sem ele (degradacao gracioso)."
        $glVersion = $null
    }

    if ($glVersion) {
        $arch    = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x32" }
        $zipUrl  = "https://github.com/gitleaks/gitleaks/releases/download/v${glVersion}/gitleaks_${glVersion}_windows_${arch}.zip"
        $zipPath = Join-Path $env:TEMP "gitleaks.zip"

        Write-Info "Baixando Gitleaks v${glVersion} (windows/${arch})..."
        try {
            Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing
            Expand-Archive -Path $zipPath -DestinationPath $env:TEMP -Force
            Move-Item -Path (Join-Path $env:TEMP "gitleaks.exe") -Destination (Join-Path $InstallDir "gitleaks.exe") -Force
            Remove-Item $zipPath -ErrorAction SilentlyContinue

            # Adiciona ao PATH desta sessao
            $env:PATH = "$InstallDir;$env:PATH"

            if (Get-Command gitleaks -ErrorAction SilentlyContinue) {
                Write-Ok "Gitleaks v${glVersion} instalado em $InstallDir"
                Write-Warn "Para usar em novas sessoes, adicione ao PATH permanente:"
                Write-Warn "  `$env:PATH += ';$InstallDir'  (ou via Painel de Controle > Variaveis de Ambiente)"
            } else {
                Write-Warn "Binario salvo em $InstallDir\gitleaks.exe mas nao esta no PATH."
                Write-Warn "Adicione $InstallDir ao PATH permanente."
            }
        } catch {
            Write-Warn "Falha no download do Gitleaks: $_"
            Write-Warn "O claude-guardian funcionara sem ele (degradacao gracioso)."
        }
    }
}

# ── 4. claude-guardian init ───────────────────────────────────────────────────
Write-Header "4/4  Inicializando claude-guardian"

Write-Info "Criando config, banco de dados e registrando hooks no Claude Code..."
node --experimental-strip-types "$ScriptDir\src\cli\index.ts" init --show-token
if ($LASTEXITCODE -ne 0) { Write-Die "claude-guardian init falhou" }
Write-Ok "claude-guardian inicializado"

# ── Dashboard ─────────────────────────────────────────────────────────────────
Write-Header "     Subindo dashboard"

# Para instancia anterior se existir
if (Test-Path $PidFile) {
    $oldPid = Get-Content $PidFile -ErrorAction SilentlyContinue
    if ($oldPid) {
        $proc = Get-Process -Id $oldPid -ErrorAction SilentlyContinue
        if ($proc) {
            Write-Info "Encerrando instancia anterior (PID $oldPid)..."
            Stop-Process -Id $oldPid -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 500
        }
    }
    Remove-Item $PidFile -ErrorAction SilentlyContinue
}

# Verifica se a porta ja esta em uso
$portInUse = Get-NetTCPConnection -LocalPort $DashboardPort -ErrorAction SilentlyContinue
if ($portInUse) {
    Write-Warn "Porta $DashboardPort ja em uso — o dashboard pode ja estar rodando."
    Write-Warn "Para forcar reinicio: Stop-Process -Id (Get-NetTCPConnection -LocalPort $DashboardPort).OwningProcess"
} else {
    $dashProc = Start-Process -FilePath "node" `
        -ArgumentList "--experimental-strip-types `"$ScriptDir\src\cli\index.ts`" serve" `
        -RedirectStandardOutput $LogFile `
        -RedirectStandardError  $LogFile `
        -NoNewWindow -PassThru

    $dashProc.Id | Set-Content $PidFile

    # Aguarda o servidor aceitar conexoes (ate 5s)
    $ready = $false
    for ($i = 0; $i -lt 10; $i++) {
        Start-Sleep -Milliseconds 500
        try {
            $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$DashboardPort/health" -UseBasicParsing -ErrorAction Stop
            if ($resp.StatusCode -eq 200) { $ready = $true; break }
        } catch {}
    }

    if ($ready) {
        Write-Ok "Dashboard iniciado (PID $($dashProc.Id))"
    } else {
        Write-Warn "Dashboard iniciado mas ainda nao respondeu em 5s."
        Write-Warn "Verifique os logs: Get-Content -Wait $LogFile"
    }
}

# ── Resumo ────────────────────────────────────────────────────────────────────
$ConfigFile = Join-Path $env:USERPROFILE ".config\claude-guardian\config.json"
$token = ""
if (Test-Path $ConfigFile) {
    try {
        $cfg   = Get-Content $ConfigFile -Raw | ConvertFrom-Json
        $token = $cfg.dashboardToken
    } catch {}
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor White
Write-Host "  claude-guardian pronto"                   -ForegroundColor White
Write-Host "==========================================" -ForegroundColor White
Write-Host ""
Write-Host "  Dashboard:  http://localhost:$DashboardPort/dashboard" -ForegroundColor Cyan
if ($token) { Write-Host "  Token:      $token" }
Write-Host ""
Write-Host "  Logs:       Get-Content -Wait $LogFile"
if (Test-Path $PidFile) {
    $pid = Get-Content $PidFile
    Write-Host "  Parar:      Stop-Process -Id $pid"
}
Write-Host ""
Write-Host "  Reinicie o Claude Code para ativar os hooks." -ForegroundColor Yellow
Write-Host ""
