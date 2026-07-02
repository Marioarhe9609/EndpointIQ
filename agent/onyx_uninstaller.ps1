<#
.SYNOPSIS
    Onyx Agent - Desinstalador para Windows
.DESCRIPTION
    Elimina completamente el agente Onyx.
.NOTES
    Ejecutar como Administrador
#>

param(
    [string]$InstallDir = "C:\ProgramData\Onyx",
    [switch]$Sweep
)

$ErrorActionPreference = "SilentlyContinue"

if ($Sweep) {
    # ─── MODO BARRIDO SILENCIOSO DE DESINSTALACIÓN DE VERSIONES ANTERIORES ───
    Write-Host "  [..] Iniciando barrido de desinstalacion de versiones anteriores..." -ForegroundColor Yellow
    
    $oldTasks = @(
        "EndpointIQ-Agent",
        "EndpointIQ_Monitor",
        "EndpointIQ Monitor",
        "Onyx_Monitor",
        "Onyx Monitor",
        "Onyx-Agent"
    )

    $foldersToDelete = [System.Collections.Generic.List[string]]::new()
    $foldersToDelete.Add("C:\ProgramData\EndpointIQ")

    foreach ($tName in $oldTasks) {
        $task = Get-ScheduledTask -TaskName $tName -ErrorAction SilentlyContinue
        if ($task) {
            Write-Host "    [+] Detectada tarea antigua: $tName" -ForegroundColor Gray
            foreach ($action in $task.Actions) {
                if ($action.WorkingDirectory -and (Test-Path $action.WorkingDirectory)) {
                    $foldersToDelete.Add($action.WorkingDirectory)
                }
                if ($action.Arguments) {
                    if ($action.Arguments -match '([a-zA-Z]:\\[^"]+)') {
                        $matchedPath = $Matches[1]
                        if (Test-Path $matchedPath) {
                            $parentDir = Split-Path -Parent $matchedPath
                            if ($parentDir -and (Test-Path $parentDir)) {
                                $foldersToDelete.Add($parentDir)
                            }
                        }
                    }
                }
            }
        }
    }

    # Detener procesos activos de agentes anteriores
    Write-Host "  [..] Deteniendo procesos en segundo plano de agentes anteriores..." -ForegroundColor Yellow
    try {
        $processesToStop = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
            $_.CommandLine -like "*EndpointIQ*" -or 
            $_.CommandLine -like "*eiq_agent*" -or 
            $_.CommandLine -like "*eiq_launcher*" -or 
            $_.CommandLine -like "*eiq_updater*" -or 
            ($_.CommandLine -like "*onyx_agent*" -and $_.CommandLine -notlike "*$MyInvocation*") -or 
            $_.CommandLine -like "*onyx_launcher*" -or 
            $_.CommandLine -like "*onyx_updater*"
        }
        
        foreach ($proc in $processesToStop) {
            Write-Host "    [-] Deteniendo proceso PID $($proc.ProcessId): $($proc.Name)" -ForegroundColor Gray
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Host "    [!] Error al detener procesos en segundo plano: $($_.Exception.Message)" -ForegroundColor Red
    }

    # Eliminar tareas programadas
    Write-Host "  [..] Removiendo tareas programadas antiguas..." -ForegroundColor Yellow
    foreach ($tName in $oldTasks) {
        $oldTask = Get-ScheduledTask -TaskName $tName -ErrorAction SilentlyContinue
        if ($oldTask) {
            try {
                Unregister-ScheduledTask -TaskName $tName -Confirm:$false -ErrorAction Stop
                Write-Host "    [✓] Tarea removida: $tName" -ForegroundColor Green
            } catch {
                Write-Host "    [!] No se pudo remover la tarea ${tName}: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }

    # Eliminar carpetas físicas de agentes anteriores
    Write-Host "  [..] Limpiando archivos fisicos de versiones anteriores..." -ForegroundColor Yellow
    $uniqueFolders = $foldersToDelete | Select-Object -Unique
    $currentScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    
    foreach ($folder in $uniqueFolders) {
        if ($folder -and (Test-Path $folder)) {
            if ($folder -eq $currentScriptDir) {
                Write-Host "    [=] Omitiendo eliminacion de la carpeta del instalador actual: $folder" -ForegroundColor Gray
                continue
            }
            if ($folder -eq "C:\" -or $folder -eq "C:\Windows" -or $folder -eq "C:\Program Files" -or $folder -eq "C:\Program Files (x86)") {
                continue
            }
            if ($folder -eq $InstallDir) {
                Write-Host "    [=] Omitiendo eliminacion del directorio de destino final: $folder (se actualizara de forma limpia)" -ForegroundColor Gray
                continue
            }
            
            try {
                Write-Host "    [-] Eliminando directorio antiguo: $folder" -ForegroundColor Gray
                Remove-Item -Path $folder -Recurse -Force -ErrorAction Stop
                Write-Host "    [✓] Eliminado con exito: $folder" -ForegroundColor Green
            } catch {
                Write-Host "    [!] Error al eliminar de forma directa: $($_.Exception.Message). Reintentando limpieza interna..." -ForegroundColor Yellow
                try {
                    Get-ChildItem -Path $folder -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                    Remove-Item -Path $folder -Force -ErrorAction SilentlyContinue
                } catch {}
            }
        }
    }

    # Limpiar exclusiones antiguas de Defender
    Write-Host "  [..] Removiendo exclusiones antiguas de Defender..." -ForegroundColor Yellow
    try {
        Remove-MpPreference -ExclusionPath "C:\ProgramData\EndpointIQ" -ErrorAction SilentlyContinue
        foreach ($folder in $uniqueFolders) {
            if ($folder -and $folder -ne $InstallDir) {
                Remove-MpPreference -ExclusionPath $folder -ErrorAction SilentlyContinue
            }
        }
        Write-Host "    [✓] Exclusiones de Defender antiguas limpiadas" -ForegroundColor Green
    } catch {}

    Write-Host "  [✓] Barrido de desinstalacion completado exitosamente." -ForegroundColor Green
    Write-Host ""
    exit 0
}
$TASK_NAME = "Onyx-Agent"

Write-Host ""
Write-Host "  +==================================================+"
Write-Host "  |       Onyx Agent - Desinstalador           |"
Write-Host "  +==================================================+"
Write-Host ""

# Verificar admin
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "  [ERROR] Se requieren permisos de Administrador." -ForegroundColor Red
    Read-Host "  Presione Enter para salir"
    exit 1
}

# 1. Eliminar tarea programada
Write-Host "  [..] Eliminando tarea programada..." -ForegroundColor Yellow
$task = Get-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
if ($task) {
    Stop-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false
    Write-Host "  [OK] Tarea eliminada: $TASK_NAME" -ForegroundColor Green
} else {
    Write-Host "  [--] Tarea no encontrada" -ForegroundColor Gray
}

# 2. Remover exclusion de Windows Defender
Write-Host "  [..] Removiendo exclusion de Windows Defender..." -ForegroundColor Yellow
try {
    Remove-MpPreference -ExclusionPath $InstallDir -ErrorAction SilentlyContinue
    Write-Host "  [OK] Exclusion removida" -ForegroundColor Green
} catch {
    Write-Host "  [--] No se encontro exclusion" -ForegroundColor Gray
}

# 3. Eliminar directorio
Write-Host "  [..] Eliminando archivos..." -ForegroundColor Yellow
if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force
    Write-Host "  [OK] Directorio eliminado: $InstallDir" -ForegroundColor Green
} else {
    Write-Host "  [--] Directorio no encontrado" -ForegroundColor Gray
}

Write-Host ""
Write-Host "  +==================================================+" -ForegroundColor Green
Write-Host "  |     DESINSTALACION COMPLETADA                    |" -ForegroundColor Green
Write-Host "  |     Onyx Agent ha sido removido.           |" -ForegroundColor Green
Write-Host "  +==================================================+" -ForegroundColor Green
Write-Host ""
Read-Host "  Presione Enter para cerrar"
