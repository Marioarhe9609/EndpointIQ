<#
.SYNOPSIS
    Onyx Agent - Instalador Windows Service v2.1
.DESCRIPTION
    Instala el agente de monitoreo Onyx como un SERVICIO DE WINDOWS real.
    - Se inicia automaticamente con Windows (antes del login)
    - Se reinicia solo si falla (en 5 segundos)
    - Visible en services.msc como "Onyx Agent"
    - No depende de tareas programadas
.NOTES
    Ejecutar como Administrador
#>

param(
    [string]$InstallDir = "C:\ProgramData\OnyxAgent",
    [string]$ServiceName = "OnyxAgent",
    [string]$ServiceDisplay = "Onyx Agent",
    [string]$ServiceDesc = "Onyx - Agente de monitoreo inteligente de endpoints. Recopila metricas de hardware y las envia a la nube."
)

$AGENT_SCRIPT = "eiq_agent.py"
$NSSM_URL = "https://nssm.cc/release/nssm-2.24.zip"
$NSSM_DIR = "C:\ProgramData\OnyxAgent\nssm"
$NSSM_EXE = "$NSSM_DIR\nssm.exe"

# --- Banner ---
Write-Host ""
Write-Host "  +====================================================+" -ForegroundColor Cyan
Write-Host "  |         ONYX Agent - Instalador v2.1              |" -ForegroundColor Cyan
Write-Host "  |         Instalando como Windows Service           |" -ForegroundColor Cyan
Write-Host "  +====================================================+" -ForegroundColor Cyan
Write-Host ""

# --- 1. Verificar Administrador ---
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "  [ERROR] Se requieren permisos de Administrador." -ForegroundColor Red
    Read-Host "  Presione Enter para salir"
    exit 1
}
Write-Host "  [OK] Permisos de Administrador verificados" -ForegroundColor Green

# --- 2. Verificar/Instalar Python ---
Write-Host "  [..] Buscando Python 3..." -ForegroundColor Yellow
$pythonExe = $null

$searchPaths = @(
    "python.exe", "python3.exe",
    "C:\Python313\python.exe", "C:\Python312\python.exe", "C:\Python311\python.exe", "C:\Python310\python.exe",
    "C:\Program Files\Python313\python.exe", "C:\Program Files\Python312\python.exe",
    "C:\Program Files\Python311\python.exe", "C:\Program Files\Python310\python.exe"
)
$localPyPaths = @("Python313","Python312","Python311","Python310")
foreach ($pyDir in $localPyPaths) {
    $searchPaths += Join-Path $env:LOCALAPPDATA "Programs\Python\$pyDir\python.exe"
}
# Buscar en todos los usuarios
if (Test-Path "C:\Users") {
    foreach ($uf in (Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue)) {
        foreach ($pyDir in $localPyPaths) {
            $searchPaths += Join-Path $uf.FullName "AppData\Local\Programs\Python\$pyDir\python.exe"
        }
    }
}

foreach ($candidate in $searchPaths) {
    try {
        $resolvedPath = $null
        if ($candidate -like "*\*") {
            if (Test-Path $candidate) { $resolvedPath = $candidate }
        } else {
            $found = Get-Command $candidate -ErrorAction SilentlyContinue
            if ($found) { $resolvedPath = $found.Source }
        }
        if ($resolvedPath) {
            $proc = Start-Process -FilePath $resolvedPath -ArgumentList "--version" -NoNewWindow -Wait -PassThru `
                -RedirectStandardOutput "$env:TEMP\pyver.txt" -RedirectStandardError "$env:TEMP\pyver_err.txt"
            $verText = Get-Content "$env:TEMP\pyver.txt" -ErrorAction SilentlyContinue
            if (-not $verText) { $verText = Get-Content "$env:TEMP\pyver_err.txt" -ErrorAction SilentlyContinue }
            if ($verText -match "Python 3") {
                $pythonExe = $resolvedPath
                Write-Host "  [OK] Python encontrado: $verText" -ForegroundColor Green
                Write-Host "       Ruta: $pythonExe" -ForegroundColor Gray
                break
            }
        }
    } catch { }
}
Remove-Item "$env:TEMP\pyver*.txt" -Force -ErrorAction SilentlyContinue

if (-not $pythonExe) {
    Write-Host "  [!!] Python 3 no encontrado. Descargando Python 3.11..." -ForegroundColor Yellow
    $installerUrl = "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe"
    $installerPath = Join-Path $env:TEMP "python-3.11.9-amd64.exe"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing
        Start-Process -FilePath $installerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_pip=1" -Wait -NoNewWindow
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        foreach ($np in @("C:\Program Files\Python311\python.exe","C:\Python311\python.exe")) {
            if (Test-Path $np) { $pythonExe = $np; break }
        }
        if (-not $pythonExe) {
            $found = Get-Command "python.exe" -ErrorAction SilentlyContinue
            if ($found) { $pythonExe = $found.Source }
        }
        Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
        Write-Host "  [OK] Python instalado: $pythonExe" -ForegroundColor Green
    } catch {
        Write-Host "  [ERROR] No se pudo instalar Python. Instale manualmente desde https://python.org" -ForegroundColor Red
        Read-Host "Presione Enter para salir"; exit 1
    }
}
if (-not $pythonExe) {
    Write-Host "  [ERROR] Python no encontrado." -ForegroundColor Red
    Read-Host "Presione Enter para salir"; exit 1
}

# --- 3. Instalar dependencias Python ---
Write-Host "  [..] Instalando dependencias Python..." -ForegroundColor Yellow
foreach ($pkg in @("psutil", "google-cloud-bigquery")) {
    Write-Host "    [+] $pkg..." -ForegroundColor Gray
    Start-Process -FilePath $pythonExe -ArgumentList "-m pip install --quiet --upgrade $pkg" -NoNewWindow -Wait `
        -RedirectStandardOutput "$env:TEMP\onyx_pip.txt" -RedirectStandardError "$env:TEMP\onyx_pip_err.txt"
}
Remove-Item "$env:TEMP\onyx_pip*.txt" -Force -ErrorAction SilentlyContinue
Write-Host "  [OK] Dependencias instaladas" -ForegroundColor Green

# --- 4. Crear directorio de instalacion ---
Write-Host "  [..] Creando directorio: $InstallDir" -ForegroundColor Yellow
if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }
if (-not (Test-Path $NSSM_DIR))   { New-Item -ItemType Directory -Path $NSSM_DIR -Force | Out-Null }
Write-Host "  [OK] Directorio creado" -ForegroundColor Green

# --- 5. Copiar archivos del agente ---
Write-Host "  [..] Copiando archivos del agente..." -ForegroundColor Yellow
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
foreach ($fileName in @("eiq_agent.py", "eiq_config.json", "eiq_credentials.json")) {
    $src = Join-Path $scriptDir $fileName
    $dst = Join-Path $InstallDir $fileName
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination $dst -Force
        Write-Host "    [+] $fileName" -ForegroundColor Gray
    } else {
        Write-Host "    [!] $fileName no encontrado" -ForegroundColor Red
    }
}
Write-Host "  [OK] Archivos copiados a $InstallDir" -ForegroundColor Green

# --- 6. Descargar NSSM (si no existe) ---
Write-Host "  [..] Verificando NSSM (gestor de servicios)..." -ForegroundColor Yellow
if (-not (Test-Path $NSSM_EXE)) {
    Write-Host "  [..] Descargando NSSM..." -ForegroundColor Yellow
    $nssmZip = Join-Path $env:TEMP "nssm.zip"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $NSSM_URL -OutFile $nssmZip -UseBasicParsing
        $extractDir = Join-Path $env:TEMP "nssm_extract"
        Expand-Archive -Path $nssmZip -DestinationPath $extractDir -Force
        # Encontrar el exe de 64 bits
        $nssmFound = Get-ChildItem -Path $extractDir -Filter "nssm.exe" -Recurse | Where-Object { $_.FullName -like "*win64*" } | Select-Object -First 1
        if (-not $nssmFound) {
            $nssmFound = Get-ChildItem -Path $extractDir -Filter "nssm.exe" -Recurse | Select-Object -First 1
        }
        if ($nssmFound) {
            Copy-Item -Path $nssmFound.FullName -Destination $NSSM_EXE -Force
            Write-Host "  [OK] NSSM instalado en $NSSM_EXE" -ForegroundColor Green
        } else {
            Write-Host "  [ERROR] No se encontro nssm.exe en el zip" -ForegroundColor Red
            exit 1
        }
        Remove-Item $nssmZip -Force -ErrorAction SilentlyContinue
        Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "  [ERROR] No se pudo descargar NSSM: $_" -ForegroundColor Red
        Read-Host "Presione Enter para salir"; exit 1
    }
} else {
    Write-Host "  [OK] NSSM ya instalado" -ForegroundColor Green
}

# --- 7. Detener y eliminar servicio anterior si existe ---
Write-Host "  [..] Verificando servicio existente..." -ForegroundColor Yellow
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "    [-] Deteniendo servicio anterior..." -ForegroundColor Gray
    & $NSSM_EXE stop $ServiceName confirm 2>$null | Out-Null
    Start-Sleep -Seconds 2
    & $NSSM_EXE remove $ServiceName confirm 2>$null | Out-Null
    Start-Sleep -Seconds 1
    Write-Host "    [-] Servicio anterior eliminado" -ForegroundColor Gray
}

# --- 8. Registrar como Windows Service con NSSM ---
Write-Host "  [..] Registrando Onyx Agent como Windows Service..." -ForegroundColor Yellow
$agentFullPath = Join-Path $InstallDir $AGENT_SCRIPT

# Instalar el servicio
& $NSSM_EXE install $ServiceName $pythonExe "$agentFullPath" | Out-Null

# Configurar directorio de trabajo
& $NSSM_EXE set $ServiceName AppDirectory $InstallDir | Out-Null

# Nombre visible y descripcion
& $NSSM_EXE set $ServiceName DisplayName $ServiceDisplay | Out-Null
& $NSSM_EXE set $ServiceName Description $ServiceDesc | Out-Null

# Ejecutar como SYSTEM (sin usuario logueado)
& $NSSM_EXE set $ServiceName ObjectName "LocalSystem" | Out-Null

# Tipo de inicio: automatico
& $NSSM_EXE set $ServiceName Start SERVICE_AUTO_START | Out-Null

# Redirigir logs del servicio
& $NSSM_EXE set $ServiceName AppStdout "$InstallDir\onyx_service.log" | Out-Null
& $NSSM_EXE set $ServiceName AppStderr "$InstallDir\onyx_service_err.log" | Out-Null
& $NSSM_EXE set $ServiceName AppRotateFiles 1 | Out-Null
& $NSSM_EXE set $ServiceName AppRotateBytes 5242880 | Out-Null  # 5MB max por log

# *** RECUPERACION AUTOMATICA EN CASO DE FALLO ***
# Si el servicio falla, reiniciar en 5 segundos
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/10000 | Out-Null

Write-Host "  [OK] Servicio registrado: $ServiceName" -ForegroundColor Green
Write-Host "  [OK] Recuperacion automatica: reinicio en 5s si falla" -ForegroundColor Green

# --- 9. Exclusion Windows Defender ---
Write-Host "  [..] Agregando exclusion en Windows Defender..." -ForegroundColor Yellow
try {
    Add-MpPreference -ExclusionPath $InstallDir -ErrorAction Stop
    Add-MpPreference -ExclusionProcess $pythonExe -ErrorAction SilentlyContinue
    Write-Host "  [OK] Exclusion agregada en Defender" -ForegroundColor Green
} catch {
    Write-Host "  [!!] No se pudo agregar exclusion (puede continuar)" -ForegroundColor Yellow
}

# --- 10. Iniciar el servicio ---
Write-Host "  [..] Iniciando Onyx Agent..." -ForegroundColor Yellow
& $NSSM_EXE start $ServiceName | Out-Null
Start-Sleep -Seconds 3

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Host "  [OK] Servicio corriendo correctamente" -ForegroundColor Green
} else {
    Write-Host "  [!!] El servicio puede tardar unos segundos en iniciar" -ForegroundColor Yellow
    Write-Host "       Verifique en services.msc buscando 'Onyx Agent'" -ForegroundColor Gray
}

# --- 11. Log de instalacion ---
$logData = @{
    installed_at   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    install_dir    = $InstallDir
    python_path    = $pythonExe
    nssm_path      = $NSSM_EXE
    service_name   = $ServiceName
    hostname       = $env:COMPUTERNAME
    username       = $env:USERNAME
    install_type   = "WindowsService"
}
$logData | ConvertTo-Json | Out-File -FilePath (Join-Path $InstallDir "install_info.json") -Encoding UTF8

# --- Resumen final ---
Write-Host ""
Write-Host "  +====================================================+" -ForegroundColor Green
Write-Host "  |       INSTALACION COMPLETADA CON EXITO            |" -ForegroundColor Green
Write-Host "  +----------------------------------------------------+" -ForegroundColor Green
Write-Host "  |  Servicio  : $ServiceName (Windows Service)   |" -ForegroundColor White
Write-Host "  |  Directorio: $InstallDir" -ForegroundColor White
Write-Host "  |  Equipo    : $($env:COMPUTERNAME)" -ForegroundColor White
Write-Host "  +----------------------------------------------------+" -ForegroundColor Green
Write-Host "  |  Inicio automatico con Windows: SI               |" -ForegroundColor Cyan
Write-Host "  |  Reinicio automatico si falla:  SI (5 segundos)  |" -ForegroundColor Cyan
Write-Host "  |  Funciona sin usuario logueado: SI               |" -ForegroundColor Cyan
Write-Host "  +----------------------------------------------------+" -ForegroundColor Green
Write-Host "  |  Ver en: services.msc -> 'Onyx Agent'            |" -ForegroundColor Yellow
Write-Host "  +====================================================+" -ForegroundColor Green
Write-Host ""
Read-Host "  Presione Enter para cerrar"
