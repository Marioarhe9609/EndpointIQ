<#
.SYNOPSIS
    Onyx Agent - Instalador para Windows 10/11
.DESCRIPTION
    Instala el agente de monitoreo Onyx.
    Compatible con cualquier version de Windows 10/11.
.NOTES
    Ejecutar como Administrador
#>

param(
    [string]$InstallDir = "C:\ProgramData\Onyx",
    [int]$IntervalMinutes = 5
)

$TASK_NAME = "Onyx-Agent"
$AGENT_SCRIPT = "onyx_agent.py"

# --- Banner ---
Write-Host ""
Write-Host "  +==================================================+"
Write-Host "  |       Onyx Agent - Instalador v1.0         |"
Write-Host "  |       Monitoreo Inteligente de Endpoints         |"
Write-Host "  +==================================================+"
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

# --- 2. Verificar Python ---
Write-Host "  [..] Buscando Python 3..." -ForegroundColor Yellow
$pythonExe = $null

# Buscar python.exe en PATH y en rutas comunes
$searchPaths = @(
    "python.exe",
    "python3.exe",
    "C:\Python313\python.exe",
    "C:\Python312\python.exe",
    "C:\Python311\python.exe",
    "C:\Python310\python.exe",
    "C:\Program Files\Python313\python.exe",
    "C:\Program Files\Python312\python.exe",
    "C:\Program Files\Python311\python.exe",
    "C:\Program Files\Python310\python.exe"
)

# Agregar rutas de AppData del usuario actual
$localPyPaths = @("Python313", "Python312", "Python311", "Python310")
foreach ($pyDir in $localPyPaths) {
    $searchPaths += Join-Path $env:LOCALAPPDATA "Programs\Python\$pyDir\python.exe"
}

# Agregar rutas de AppData de todos los usuarios en el disco
$usersDir = "C:\Users"
if (Test-Path $usersDir) {
    $userFolders = Get-ChildItem $usersDir -Directory -ErrorAction SilentlyContinue
    foreach ($uf in $userFolders) {
        foreach ($pyDir in $localPyPaths) {
            $searchPaths += Join-Path $uf.FullName "AppData\Local\Programs\Python\$pyDir\python.exe"
        }
    }
}

foreach ($candidate in $searchPaths) {
    try {
        $resolvedPath = $null
        if ($candidate -like "*\*") {
            # Full path
            if (Test-Path $candidate) {
                $resolvedPath = $candidate
            }
        } else {
            # Just filename - search in PATH
            $found = Get-Command $candidate -ErrorAction SilentlyContinue
            if ($found) {
                $resolvedPath = $found.Source
            }
        }

        if ($resolvedPath) {
            $proc = Start-Process -FilePath $resolvedPath -ArgumentList "--version" -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$env:TEMP\pyver.txt" -RedirectStandardError "$env:TEMP\pyver_err.txt"
            $verText = Get-Content "$env:TEMP\pyver.txt" -ErrorAction SilentlyContinue
            if ($verText -match "Python 3") {
                $pythonExe = $resolvedPath
                Write-Host "  [OK] Encontrado: $verText" -ForegroundColor Green
                Write-Host "    Ruta: $pythonExe" -ForegroundColor Gray
                break
            }
        }
    } catch { }
}

# Limpiar archivos temporales
Remove-Item "$env:TEMP\pyver.txt" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\pyver_err.txt" -Force -ErrorAction SilentlyContinue

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
        Write-Host "  Instale manualmente desde https://www.python.org/downloads/" -ForegroundColor Yellow
        Read-Host "  Presione Enter para salir"
        exit 1
    }

    Write-Host "  [..] Instalando Python 3.11..." -ForegroundColor Yellow
    Start-Process -FilePath $installerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_pip=1" -Wait -NoNewWindow

    # Refrescar PATH
    $machPath = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::Machine)
    $usrPath = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::User)
    $env:Path = $machPath + ";" + $usrPath

    # Buscar el python recien instalado
    $newPyPaths = @(
        "C:\Program Files\Python311\python.exe",
        "C:\Python311\python.exe"
    )
    foreach ($pyDir in $localPyPaths) {
        $newPyPaths += Join-Path $env:LOCALAPPDATA "Programs\Python\$pyDir\python.exe"
    }
    foreach ($np in $newPyPaths) {
        if (Test-Path $np) {
            $pythonExe = $np
            break
        }
    }
    if (-not $pythonExe) {
        $found = Get-Command "python.exe" -ErrorAction SilentlyContinue
        if ($found) { $pythonExe = $found.Source }
    }

    Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK] Python 3.11 instalado: $pythonExe" -ForegroundColor Green
}

if (-not $pythonExe) {
    Write-Host "  [ERROR] No se pudo encontrar Python." -ForegroundColor Red
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

$fileList = @("onyx_agent.py", "onyx_config.json", "onyx_credentials.json")
foreach ($fileName in $fileList) {
    $srcFile = Join-Path $scriptDir $fileName
    $dstFile = Join-Path $InstallDir $fileName
    if (Test-Path $srcFile) {
        Copy-Item -Path $srcFile -Destination $dstFile -Force
        Write-Host "    [+] $fileName" -ForegroundColor Gray
    } else {
        Write-Host "    [!] $fileName NO encontrado en $scriptDir" -ForegroundColor Red
    }
}
Write-Host "  [OK] Archivos copiados" -ForegroundColor Green

# --- 5. Instalar dependencias ---
Write-Host "  [..] Instalando dependencias de Python..." -ForegroundColor Yellow

Write-Host "    [+] psutil..." -ForegroundColor Gray
$pipLog1 = Join-Path $env:TEMP "onyx_pip1.txt"
Start-Process -FilePath $pythonExe -ArgumentList "-m pip install --quiet --upgrade psutil" -NoNewWindow -Wait -RedirectStandardOutput $pipLog1 -RedirectStandardError "$env:TEMP\onyx_pip1_err.txt"

Write-Host "    [+] google-cloud-bigquery..." -ForegroundColor Gray
$pipLog2 = Join-Path $env:TEMP "onyx_pip2.txt"
Start-Process -FilePath $pythonExe -ArgumentList "-m pip install --quiet --upgrade google-cloud-bigquery" -NoNewWindow -Wait -RedirectStandardOutput $pipLog2 -RedirectStandardError "$env:TEMP\onyx_pip2_err.txt"

# Limpiar logs temporales de pip
Remove-Item "$env:TEMP\onyx_pip*.txt" -Force -ErrorAction SilentlyContinue

Write-Host "  [OK] Dependencias instaladas" -ForegroundColor Green

# --- 6. Exclusion Windows Defender ---
Write-Host "  [..] Agregando exclusion en Windows Defender..." -ForegroundColor Yellow
try {
    Add-MpPreference -ExclusionPath $InstallDir -ErrorAction Stop
    Write-Host "  [OK] Exclusion agregada en Defender" -ForegroundColor Green
} catch {
    Write-Host "  [!!] No se pudo agregar exclusion (otro antivirus activo)" -ForegroundColor Yellow
}

# --- 7. Tarea Programada ---
Write-Host "  [..] Configurando tarea programada..." -ForegroundColor Yellow

$oldTask = Get-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
if ($oldTask) {
    Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false
    Write-Host "    [-] Tarea anterior eliminada" -ForegroundColor Gray
}

$agentFullPath = Join-Path $InstallDir $AGENT_SCRIPT
Write-Host "    Python: $pythonExe" -ForegroundColor Gray
Write-Host "    Agent:  $agentFullPath" -ForegroundColor Gray

$taskAction = New-ScheduledTaskAction -Execute $pythonExe -Argument "`"$agentFullPath`" --once" -WorkingDirectory $InstallDir

$taskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) -RepetitionDuration (New-TimeSpan -Days 9999)

$taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

$taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

$taskDescription = "Onyx - Agente de monitoreo cada $IntervalMinutes minutos."

Register-ScheduledTask -TaskName $TASK_NAME -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Principal $taskPrincipal -Description $taskDescription | Out-Null

Write-Host "  [OK] Tarea programada creada: $TASK_NAME" -ForegroundColor Green

# --- 8. Primera ejecucion de prueba ---
Write-Host "  [..] Ejecutando primera recoleccion..." -ForegroundColor Yellow
$testOut = Join-Path $env:TEMP "onyx_test.txt"
$testErr = Join-Path $env:TEMP "onyx_test_err.txt"
try {
    $proc = Start-Process -FilePath $pythonExe -ArgumentList "`"$agentFullPath`" --once --verbose" -WorkingDirectory $InstallDir -NoNewWindow -Wait -PassThru -RedirectStandardOutput $testOut -RedirectStandardError $testErr
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

# --- 9. Log de instalacion ---
$logData = @{
    installed_at = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    install_dir  = $InstallDir
    python_path  = $pythonExe
    interval     = $IntervalMinutes
    task         = $TASK_NAME
    hostname     = $env:COMPUTERNAME
    username     = $env:USERNAME
}
$logJson = $logData | ConvertTo-Json
$logFilePath = Join-Path $InstallDir "install_info.json"
$logJson | Out-File -FilePath $logFilePath -Encoding UTF8

# --- Resumen ---
Write-Host ""
Write-Host "  +==================================================+" -ForegroundColor Green
Write-Host "  |     INSTALACION COMPLETADA CON EXITO             |" -ForegroundColor Green
Write-Host "  +--------------------------------------------------+" -ForegroundColor Green
Write-Host "  |  Directorio : $InstallDir" -ForegroundColor White
Write-Host "  |  Tarea      : $TASK_NAME" -ForegroundColor White
Write-Host "  |  Intervalo  : Cada $IntervalMinutes minutos" -ForegroundColor White
Write-Host "  |  Equipo     : $($env:COMPUTERNAME)" -ForegroundColor White
Write-Host "  +--------------------------------------------------+" -ForegroundColor Green
Write-Host "  |  El agente ya esta reportando metricas.          |" -ForegroundColor Cyan
Write-Host "  |  Plataforma: proy-anla-poc-175647544738             |" -ForegroundColor Cyan
Write-Host "  |              .us-central1.run.app                |" -ForegroundColor Cyan
Write-Host "  +==================================================+" -ForegroundColor Green
Write-Host ""
Read-Host "  Presione Enter para cerrar"
