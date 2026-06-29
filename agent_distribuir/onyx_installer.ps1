<#
.SYNOPSIS
    Onyx Agent - Instalador Universal para Windows 10/11
.DESCRIPTION
    Instala el agente de monitoreo Onyx con auto-actualizacion.
    El agente se actualiza automaticamente desde el servidor central.
.NOTES
    Ejecutar como Administrador: Click derecho > Ejecutar con PowerShell
#>

param(
    [string]$InstallDir = "C:\ProgramData\Onyx",
    [int]$IntervalMinutes = 5
)

# Global error handling
$ErrorActionPreference = "Continue"
trap {
    Write-Host ""
    Write-Host "  [ERROR CRITICO] $_" -ForegroundColor Red
    Write-Host "  Linea: $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red
    Write-Host ""
    Read-Host "  Presione Enter para salir"
    exit 1
}

$TASK_NAME = "Onyx-Agent"
$AGENT_SCRIPT = "onyx_agent.py"
$SERVER_URL = "https://proy-anla-poc-175647544738.us-central1.run.app"

# --- Banner ---
Write-Host ""
Write-Host "  +==================================================+"
Write-Host "  |     Onyx Agent - Instalador v2.0           |"
Write-Host "  |     Monitoreo Inteligente con Auto-Update        |"
Write-Host "  +==================================================+"
Write-Host ""

# --- 1. Verificar Administrador ---
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "  [ERROR] Se requieren permisos de Administrador." -ForegroundColor Red
    Write-Host "  Click derecho en el archivo > Ejecutar como Administrador" -ForegroundColor Yellow
    Read-Host "  Presione Enter para salir"
    exit 1
}
Write-Host "  [OK] Permisos de Administrador verificados" -ForegroundColor Green

# --- 2. Verificar Python ---
Write-Host "  [..] Buscando Python 3..." -ForegroundColor Yellow
$pythonExe = $null

# Construir lista de rutas de busqueda
$searchPaths = @()

# Rutas del PATH del sistema
$searchPaths += "python.exe"
$searchPaths += "python3.exe"

# Rutas globales comunes
$pyVersions = @("Python314", "Python313", "Python312", "Python311", "Python310", "Python39")
foreach ($pyDir in $pyVersions) {
    $searchPaths += "C:\$pyDir\python.exe"
    $searchPaths += "C:\Program Files\$pyDir\python.exe"
    $searchPaths += "C:\Program Files (x86)\$pyDir\python.exe"
}

# Rutas de AppData del usuario actual
foreach ($pyDir in $pyVersions) {
    $searchPaths += Join-Path $env:LOCALAPPDATA "Programs\Python\$pyDir\python.exe"
}

# Rutas de AppData de todos los usuarios
$usersDir = "C:\Users"
if (Test-Path $usersDir) {
    $userFolders = Get-ChildItem $usersDir -Directory -ErrorAction SilentlyContinue
    foreach ($uf in $userFolders) {
        foreach ($pyDir in $pyVersions) {
            $searchPaths += Join-Path $uf.FullName "AppData\Local\Programs\Python\$pyDir\python.exe"
        }
    }
}

# Microsoft Store Python
$searchPaths += Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps\python.exe"
$searchPaths += Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps\python3.exe"

foreach ($candidate in $searchPaths) {
    try {
        $resolvedPath = $null
        if ($candidate -like "*\*") {
            if (Test-Path $candidate) {
                $resolvedPath = $candidate
            }
        } else {
            $found = Get-Command $candidate -ErrorAction SilentlyContinue
            if ($found) {
                $resolvedPath = $found.Source
            }
        }

        if ($resolvedPath) {
            $verFile = Join-Path $env:TEMP "onyx_pyver.txt"
            $verErr = Join-Path $env:TEMP "onyx_pyver_err.txt"
            $proc = Start-Process -FilePath $resolvedPath -ArgumentList "--version" -NoNewWindow -Wait -PassThru -RedirectStandardOutput $verFile -RedirectStandardError $verErr
            $verText = Get-Content $verFile -ErrorAction SilentlyContinue
            if ($verText -match "Python 3") {
                $pythonExe = $resolvedPath
                Write-Host "  [OK] Encontrado: $verText" -ForegroundColor Green
                Write-Host "       Ruta: $pythonExe" -ForegroundColor Gray
                break
            }
            Remove-Item $verFile -Force -ErrorAction SilentlyContinue
            Remove-Item $verErr -Force -ErrorAction SilentlyContinue
        }
    } catch { }
}

# Limpiar temporales
Remove-Item (Join-Path $env:TEMP "onyx_pyver.txt") -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $env:TEMP "onyx_pyver_err.txt") -Force -ErrorAction SilentlyContinue

# Si no hay Python, descargar e instalar
if (-not $pythonExe) {
    Write-Host "  [!!] Python 3 no encontrado. Descargando..." -ForegroundColor Yellow

    $installerUrl = "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe"
    $installerPath = Join-Path $env:TEMP "python-3.11.9-amd64.exe"

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing
        Write-Host "  [OK] Python descargado" -ForegroundColor Green
    } catch {
        Write-Host "  [ERROR] No se pudo descargar Python." -ForegroundColor Red
        Write-Host "  Instale manualmente: https://www.python.org/downloads/" -ForegroundColor Yellow
        Read-Host "  Presione Enter para salir"
        exit 1
    }

    Write-Host "  [..] Instalando Python 3.11 (esto tarda ~2 min)..." -ForegroundColor Yellow
    Start-Process -FilePath $installerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_pip=1" -Wait -NoNewWindow

    # Refrescar PATH
    $machPath = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine)
    $usrPath = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::User)
    $env:Path = $machPath + ";" + $usrPath

    # Buscar el python recien instalado
    $newPyPaths = @("C:\Program Files\Python311\python.exe", "C:\Python311\python.exe")
    foreach ($pyDir in $pyVersions) {
        $newPyPaths += Join-Path $env:LOCALAPPDATA "Programs\Python\$pyDir\python.exe"
    }
    foreach ($np in $newPyPaths) {
        if (Test-Path $np) { $pythonExe = $np; break }
    }
    if (-not $pythonExe) {
        $found = Get-Command "python.exe" -ErrorAction SilentlyContinue
        if ($found) { $pythonExe = $found.Source }
    }

    Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK] Python 3.11 instalado: $pythonExe" -ForegroundColor Green
}

if (-not $pythonExe) {
    Write-Host "  [ERROR] No se pudo encontrar Python despues de instalar." -ForegroundColor Red
    Read-Host "  Presione Enter para salir"
    exit 1
}

# --- 3. Crear directorio ---
Write-Host "  [..] Creando directorio de instalacion..." -ForegroundColor Yellow
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
Write-Host "  [OK] Directorio: $InstallDir" -ForegroundColor Green

# --- 4. Copiar archivos ---
Write-Host "  [..] Copiando archivos del agente..." -ForegroundColor Yellow
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$fileList = @("onyx_agent.py", "onyx_config.json", "onyx_credentials.json", "onyx_launcher.vbs")
$copiedCount = 0
foreach ($fileName in $fileList) {
    $srcFile = Join-Path $scriptDir $fileName
    $dstFile = Join-Path $InstallDir $fileName
    if (Test-Path $srcFile) {
        Copy-Item -Path $srcFile -Destination $dstFile -Force
        Write-Host "    [+] $fileName" -ForegroundColor Gray
        $copiedCount++
    } else {
        Write-Host "    [!] $fileName NO encontrado en $scriptDir" -ForegroundColor Red
    }
}
Write-Host "  [OK] $copiedCount archivos copiados" -ForegroundColor Green

# --- 5. Escribir config con update_server ---
Write-Host "  [..] Configurando auto-actualizacion..." -ForegroundColor Yellow
$configPath = Join-Path $InstallDir "onyx_config.json"
if (Test-Path $configPath) {
    try {
        $configContent = Get-Content $configPath -Raw | ConvertFrom-Json
        # Asegurar que update_server esta configurado
        if (-not ($configContent | Get-Member -Name "update_server" -ErrorAction SilentlyContinue)) {
            $configContent | Add-Member -NotePropertyName "update_server" -NotePropertyValue $SERVER_URL
        } else {
            $configContent.update_server = $SERVER_URL
        }
        $configContent | ConvertTo-Json | Out-File -FilePath $configPath -Encoding UTF8
        Write-Host "  [OK] Auto-update configurado: $SERVER_URL" -ForegroundColor Green
    } catch {
        Write-Host "  [!!] No se pudo configurar auto-update" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [!!] Config no encontrada, sera creada en la primera ejecucion" -ForegroundColor Yellow
}

# --- 6. Instalar dependencias ---
Write-Host "  [..] Instalando dependencias de Python..." -ForegroundColor Yellow

$pipPkgs = @("psutil", "google-cloud-bigquery")
foreach ($pkg in $pipPkgs) {
    Write-Host "    [+] $pkg..." -ForegroundColor Gray
    $pipOut = Join-Path $env:TEMP "onyx_pip_out.txt"
    $pipErr = Join-Path $env:TEMP "onyx_pip_err.txt"
    Start-Process -FilePath $pythonExe -ArgumentList "-m pip install --quiet --upgrade $pkg" -NoNewWindow -Wait -RedirectStandardOutput $pipOut -RedirectStandardError $pipErr
    Remove-Item $pipOut -Force -ErrorAction SilentlyContinue
    Remove-Item $pipErr -Force -ErrorAction SilentlyContinue
}

Write-Host "  [OK] Dependencias instaladas" -ForegroundColor Green

# --- 7. Exclusion Windows Defender ---
Write-Host "  [..] Agregando exclusion en Windows Defender..." -ForegroundColor Yellow
try {
    Add-MpPreference -ExclusionPath $InstallDir -ErrorAction Stop
    Write-Host "  [OK] Exclusion agregada en Defender" -ForegroundColor Green
} catch {
    Write-Host "  [!!] No se pudo agregar exclusion (otro antivirus activo)" -ForegroundColor Yellow
}

# --- 8. Exclusion del Firewall ---
Write-Host "  [..] Configurando regla de Firewall..." -ForegroundColor Yellow
try {
    $existingRule = Get-NetFirewallRule -DisplayName "Onyx Agent" -ErrorAction SilentlyContinue
    if ($existingRule) {
        Remove-NetFirewallRule -DisplayName "Onyx Agent" -ErrorAction SilentlyContinue
    }
    New-NetFirewallRule -DisplayName "Onyx Agent" -Direction Outbound -Action Allow -Program $pythonExe -Protocol TCP -RemotePort 443 -ErrorAction Stop | Out-Null
    Write-Host "  [OK] Regla de Firewall creada (HTTPS saliente)" -ForegroundColor Green
} catch {
    Write-Host "  [!!] No se pudo crear regla de Firewall (no critico)" -ForegroundColor Yellow
}

# --- 9. Tarea Programada (100% invisible con XML Hidden + VBS launcher) ---
Write-Host "  [..] Configurando tarea programada (invisible)..." -ForegroundColor Yellow

$oldTask = Get-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
if ($oldTask) {
    Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false
    Write-Host "    [-] Tarea anterior eliminada" -ForegroundColor Gray
}

$agentFullPath = Join-Path $InstallDir $AGENT_SCRIPT
$vbsLauncher = Join-Path $InstallDir "onyx_launcher.vbs"

# Determinar comando y argumentos
if (Test-Path $vbsLauncher) {
    $taskCmd = "wscript.exe"
    $taskArgs = "//B //NoLogo `"$vbsLauncher`""
    Write-Host "    [OK] Usando VBS launcher (invisible)" -ForegroundColor Green
} else {
    $pythonwExe = $pythonExe -replace "python\.exe$", "pythonw.exe"
    if (Test-Path $pythonwExe) {
        $taskCmd = $pythonwExe
    } else {
        $taskCmd = $pythonExe
    }
    $taskArgs = "`"$agentFullPath`" --once"
    Write-Host "    [!!] VBS no encontrado, usando fallback" -ForegroundColor Yellow
}

# Usar XML con Hidden=true para garantizar 0 ventanas
$startTime = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Onyx - Monitoreo invisible cada $IntervalMinutes min</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PT${IntervalMinutes}M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>$startTime</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <Hidden>true</Hidden>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
  </Settings>
  <Actions>
    <Exec>
      <Command>$taskCmd</Command>
      <Arguments>$taskArgs</Arguments>
      <WorkingDirectory>$InstallDir</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

$xmlPath = Join-Path $env:TEMP "onyx_task.xml"
$taskXml | Out-File -Encoding Unicode $xmlPath

try {
    Register-ScheduledTask -TaskName $TASK_NAME -Xml (Get-Content $xmlPath -Raw) -Force | Out-Null
    Write-Host "  [OK] Tarea programada HIDDEN (cada $IntervalMinutes min, 0 ventanas)" -ForegroundColor Green
} catch {
    Write-Host "  [!!] Error creando tarea: $_" -ForegroundColor Red
}
Remove-Item $xmlPath -Force -ErrorAction SilentlyContinue

# --- 10. Primera ejecucion ---
Write-Host "  [..] Ejecutando primera recoleccion de prueba..." -ForegroundColor Yellow
$testOut = Join-Path $env:TEMP "onyx_test.txt"
$testErr = Join-Path $env:TEMP "onyx_test_err.txt"
try {
    $proc = Start-Process -FilePath $pythonExe -ArgumentList """$agentFullPath"" --once --verbose" -WorkingDirectory $InstallDir -NoNewWindow -Wait -PassThru -RedirectStandardOutput $testOut -RedirectStandardError $testErr
    if (Test-Path $testOut) {
        $output = Get-Content $testOut -ErrorAction SilentlyContinue
        foreach ($line in $output) {
            Write-Host "    $line" -ForegroundColor Gray
        }
    }
    if ($proc.ExitCode -eq 0) {
        Write-Host "  [OK] Primera recoleccion completada" -ForegroundColor Green
    } else {
        Write-Host "  [!!] Recoleccion termino con codigo: $($proc.ExitCode)" -ForegroundColor Yellow
        if (Test-Path $testErr) {
            $errContent = Get-Content $testErr -ErrorAction SilentlyContinue
            foreach ($line in $errContent) {
                Write-Host "    $line" -ForegroundColor Red
            }
        }
    }
} catch {
    Write-Host "  [!!] Error en primera ejecucion" -ForegroundColor Yellow
}
Remove-Item $testOut -Force -ErrorAction SilentlyContinue
Remove-Item $testErr -Force -ErrorAction SilentlyContinue

# --- 11. Log de instalacion ---
$logData = @{
    installed_at  = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    install_dir   = $InstallDir
    python_path   = $pythonExe
    interval      = $IntervalMinutes
    task          = $TASK_NAME
    hostname      = $env:COMPUTERNAME
    username      = $env:USERNAME
    agent_version = "2.0.0"
    update_server = $SERVER_URL
}
$logJson = $logData | ConvertTo-Json
$logFilePath = Join-Path $InstallDir "install_info.json"
$logJson | Out-File -FilePath $logFilePath -Encoding UTF8

# --- Resumen ---
Write-Host ""
Write-Host "  +==================================================+" -ForegroundColor Green
Write-Host "  |     INSTALACION COMPLETADA CON EXITO             |" -ForegroundColor Green
Write-Host "  +--------------------------------------------------+" -ForegroundColor Green
Write-Host "  |  Directorio  : $InstallDir" -ForegroundColor White
Write-Host "  |  Tarea       : $TASK_NAME" -ForegroundColor White
Write-Host "  |  Intervalo   : Cada $IntervalMinutes minutos" -ForegroundColor White
Write-Host "  |  Equipo      : $($env:COMPUTERNAME)" -ForegroundColor White
Write-Host "  |  Auto-Update : Habilitado" -ForegroundColor Cyan
Write-Host "  +--------------------------------------------------+" -ForegroundColor Green
Write-Host "  |  El agente reporta metricas y se actualiza       |" -ForegroundColor Cyan
Write-Host "  |  automaticamente desde el servidor central.      |" -ForegroundColor Cyan
Write-Host "  |                                                  |" -ForegroundColor Cyan
Write-Host "  |  Plataforma:                                     |" -ForegroundColor Cyan
Write-Host "  |  proy-anla-poc-175647544738.us-central1.run.app     |" -ForegroundColor Cyan
Write-Host "  +==================================================+" -ForegroundColor Green
Write-Host ""
Write-Host "  Instalacion completada exitosamente." -ForegroundColor Green
Write-Host ""
