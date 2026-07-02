# Onyx Agent Installer v3.0 - PowerShell Edition
# Alternativa al INSTALAR.bat para entornos donde el .bat no funciona correctamente.
# Ejecutar con: powershell -ExecutionPolicy Bypass -File instalar.ps1

$ErrorActionPreference = "Continue"
$InstallDir = "C:\ProgramData\Onyx"
$SourceDir  = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "  +=========================================================+" -ForegroundColor Cyan
Write-Host "  |   ONYX - Agente de Monitoreo - Instalador v3.0         |" -ForegroundColor Cyan
Write-Host "  |                    By Agentica                          |" -ForegroundColor Cyan
Write-Host "  +=========================================================+" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Equipo : $env:COMPUTERNAME"
Write-Host "  Fecha  : $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')"
Write-Host ""

# -----------------------------------------------
# PASO 1: Verificar archivos
# -----------------------------------------------
Write-Host "  [1/8] Verificando archivos de instalacion..." -ForegroundColor Yellow
$missing = $false
foreach ($f in @("onyx_agent.py","onyx_credentials.json","onyx_launcher.vbs","onyx_updater.py")) {
    if (-not (Test-Path "$SourceDir\$f")) {
        Write-Host "        [ERROR] $f - NO ENCONTRADO" -ForegroundColor Red
        $missing = $true
    } else {
        Write-Host "        [OK] $f" -ForegroundColor Green
    }
}
if ($missing) {
    Write-Host ""
    Write-Host "  ERROR: Faltan archivos. Extraiga todos los archivos del ZIP primero." -ForegroundColor Red
    Read-Host "  Presione Enter para salir"
    exit 1
}
Write-Host ""

# -----------------------------------------------
# PASO 2: Desinstalar agentes anteriores
# -----------------------------------------------
Write-Host "  [2/8] Barrido de versiones anteriores..." -ForegroundColor Yellow
try {
    $svc = Get-Service -Name "OnyxMonitor" -ErrorAction SilentlyContinue
    if ($svc) {
        Stop-Service -Name "OnyxMonitor" -Force -ErrorAction SilentlyContinue
        sc.exe delete "OnyxMonitor" | Out-Null
        Write-Host "        [OK] Servicio OnyxMonitor eliminado" -ForegroundColor Green
    }
    $svc2 = Get-Service -Name "OnyxAgent" -ErrorAction SilentlyContinue
    if ($svc2) {
        Stop-Service -Name "OnyxAgent" -Force -ErrorAction SilentlyContinue
        sc.exe delete "OnyxAgent" | Out-Null
        Write-Host "        [OK] Servicio OnyxAgent eliminado" -ForegroundColor Green
    }
} catch {}
foreach ($t in @("Onyx-Agent","Onyx_Monitor","Onyx Monitor","OnyxAgent")) {
    schtasks /delete /tn $t /f 2>$null | Out-Null
}
Write-Host "        [OK] Versiones anteriores eliminadas" -ForegroundColor Green
Write-Host ""

# -----------------------------------------------
# PASO 3: Buscar Python
# -----------------------------------------------
Write-Host "  [3/8] Buscando Python 3..." -ForegroundColor Yellow
$pythonExe = $null

$inPath = Get-Command python.exe -ErrorAction SilentlyContinue
if ($inPath) { $pythonExe = $inPath.Source }

if (-not $pythonExe) {
    $versions = @("Python314","Python313","Python312","Python311","Python310","Python39")
    foreach ($v in $versions) {
        foreach ($base in @("C:\$v","C:\Program Files\$v")) {
            if (Test-Path "$base\python.exe") { $pythonExe = "$base\python.exe"; break }
        }
        if ($pythonExe) { break }
    }
}

if (-not $pythonExe) {
    Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        foreach ($v in @("Python314","Python313","Python312","Python311","Python310","Python39")) {
            $p = "$($_.FullName)\AppData\Local\Programs\Python\$v\python.exe"
            if (Test-Path $p) { $pythonExe = $p }
        }
    }
}

if (-not $pythonExe) {
    Write-Host "        [WARN] Python no encontrado. Descargando Python 3.11..." -ForegroundColor Yellow
    $installer = "$env:TEMP\python-3.11.9-amd64.exe"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe" -OutFile $installer -UseBasicParsing
    & $installer /quiet InstallAllUsers=1 PrependPath=1 Include_pip=1
    Remove-Item $installer -Force -ErrorAction SilentlyContinue
    $pythonExe = "C:\Program Files\Python311\python.exe"
}

if (-not (Test-Path $pythonExe)) {
    Write-Host "        [ERROR] No se encontro Python. Instale desde python.org" -ForegroundColor Red
    Read-Host "  Presione Enter para salir"
    exit 1
}
Write-Host "        [OK] Python: $pythonExe" -ForegroundColor Green
Write-Host ""

# -----------------------------------------------
# PASO 4: Copiar archivos
# -----------------------------------------------
Write-Host "  [4/8] Instalando archivos del agente..." -ForegroundColor Yellow
if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }

foreach ($f in @("onyx_agent.py","onyx_updater.py","onyx_credentials.json","onyx_launcher.vbs")) {
    Copy-Item "$SourceDir\$f" "$InstallDir\$f" -Force
    Write-Host "        [OK] $f copiado" -ForegroundColor Green
}
# Siempre copiar onyx_config.json para garantizar dataset correcto en reinstalaciones
Copy-Item "$SourceDir\onyx_config.json" "$InstallDir\onyx_config.json" -Force
Write-Host "        [OK] onyx_config.json copiado" -ForegroundColor Green
Write-Host ""

# -----------------------------------------------
# PASO 5: Configurar config
# -----------------------------------------------
Write-Host "  [5/8] Configurando servidor de actualizaciones..." -ForegroundColor Yellow
$configFile = "$InstallDir\onyx_config.json"
$jsonContent = [PSCustomObject]@{
    device_id           = "auto"
    project_id          = "proy-anla-poc"
    dataset             = "onyx"
    interval_seconds    = 300
    offline_buffer_max  = 1000
    credentials_file    = "onyx_credentials.json"
    ping_target         = "8.8.8.8"
    log_file            = "onyx_agent.log"
    version             = "3.0.0"
    update_server       = "https://onyx-server-631753912632.us-central1.run.app"
}
# IMPORTANTE: Usar WriteAllText con UTF8 sin BOM (NO Set-Content -Encoding UTF8)
# PowerShell 5.x Set-Content -Encoding UTF8 agrega BOM que rompe json.load() en Python
$jsonStr = $jsonContent | ConvertTo-Json -Depth 3
[System.IO.File]::WriteAllText($configFile, $jsonStr, [System.Text.Encoding]::UTF8)
Write-Host "        [OK] Config escrita sin BOM (dataset=onyx)" -ForegroundColor Green
Write-Host ""

# -----------------------------------------------
# PASO 6: Instalar dependencias
# -----------------------------------------------
Write-Host "  [6/8] Instalando dependencias Python..." -ForegroundColor Yellow
Write-Host "        [..] psutil..."
& $pythonExe -m pip install --quiet --upgrade psutil 2>$null
Write-Host "        [OK] psutil listo" -ForegroundColor Green
Write-Host "        [..] google-cloud-bigquery..."
& $pythonExe -m pip install --quiet --upgrade google-cloud-bigquery 2>$null
Write-Host "        [OK] google-cloud-bigquery listo" -ForegroundColor Green
Write-Host ""

# -----------------------------------------------
# PASO 7: Exclusion Defender + Tarea programada
# -----------------------------------------------
Write-Host "  [7/8] Configurando seguridad y tarea programada..." -ForegroundColor Yellow
try {
    Add-MpPreference -ExclusionPath $InstallDir -ErrorAction Stop
    Write-Host "        [OK] Exclusion Windows Defender configurada" -ForegroundColor Green
} catch {
    Write-Host "        [WARN] Defender no disponible (otro antivirus activo)" -ForegroundColor Yellow
}

$launcher = "$InstallDir\onyx_launcher.vbs"
schtasks /create /tn "Onyx-Agent" /tr "wscript.exe `"$launcher`"" /sc minute /mo 5 /ru SYSTEM /rl HIGHEST /f 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "        [OK] Tarea Onyx-Agent creada como SYSTEM cada 5 min" -ForegroundColor Green
} else {
    schtasks /create /tn "Onyx-Agent" /tr "wscript.exe `"$launcher`"" /sc minute /mo 5 /f 2>&1 | Out-Null
    Write-Host "        [OK] Tarea Onyx-Agent creada para usuario actual cada 5 min" -ForegroundColor Green
}
Write-Host ""

# -----------------------------------------------
# PASO 8: Primera ejecucion
# -----------------------------------------------
Write-Host "  [8/8] Ejecutando primera recoleccion de datos..." -ForegroundColor Yellow
Write-Host "        [..] Enviando metricas a BigQuery..."
$proc = Start-Process -FilePath $pythonExe -ArgumentList "`"$InstallDir\onyx_agent.py`" --once" -Wait -PassThru -NoNewWindow 2>$null
if ($proc.ExitCode -eq 0) {
    Write-Host "        [OK] Datos enviados a BigQuery correctamente" -ForegroundColor Green
} else {
    Write-Host "        [WARN] Primera recoleccion con problema menor. El agente reintentara automaticamente." -ForegroundColor Yellow
}
Write-Host ""

# -----------------------------------------------
# RESUMEN
# -----------------------------------------------
Write-Host ""
Write-Host "  +=========================================================+" -ForegroundColor Green
Write-Host "  |      [OK]  INSTALACION COMPLETADA CON EXITO            |" -ForegroundColor Green
Write-Host "  +=========================================================+" -ForegroundColor Green
Write-Host "  | Equipo     : $env:COMPUTERNAME" -ForegroundColor Green
Write-Host "  | Directorio : $InstallDir" -ForegroundColor Green
Write-Host "  | Tarea      : Onyx-Agent cada 5 minutos" -ForegroundColor Green
Write-Host "  | Auto-Update: Habilitado" -ForegroundColor Green
Write-Host "  +=========================================================+" -ForegroundColor Green
Write-Host ""
Read-Host "  Presione Enter para cerrar"
