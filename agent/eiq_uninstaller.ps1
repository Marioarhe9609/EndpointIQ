<#
.SYNOPSIS
    Onyx Agent - Desinstalador v2.1
.DESCRIPTION
    Detiene y elimina el servicio Windows de Onyx Agent.
.NOTES
    Ejecutar como Administrador
#>

param([string]$InstallDir = "C:\ProgramData\OnyxAgent", [string]$ServiceName = "OnyxAgent")

$NSSM_EXE = "$InstallDir\nssm\nssm.exe"

Write-Host ""
Write-Host "  +====================================================+" -ForegroundColor Yellow
Write-Host "  |        ONYX Agent - Desinstalador v2.1            |" -ForegroundColor Yellow
Write-Host "  +====================================================+" -ForegroundColor Yellow
Write-Host ""

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "  [ERROR] Se requieren permisos de Administrador." -ForegroundColor Red
    Read-Host "Presione Enter para salir"; exit 1
}

# Detener y eliminar servicio Windows
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "  [..] Deteniendo servicio $ServiceName..." -ForegroundColor Yellow
    if (Test-Path $NSSM_EXE) {
        & $NSSM_EXE stop $ServiceName confirm 2>$null | Out-Null
        Start-Sleep -Seconds 2
        & $NSSM_EXE remove $ServiceName confirm 2>$null | Out-Null
    } else {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName | Out-Null
    }
    Write-Host "  [OK] Servicio eliminado" -ForegroundColor Green
} else {
    Write-Host "  [!!] Servicio no encontrado (ya desinstalado?)" -ForegroundColor Yellow
}

# Eliminar tarea programada anterior (por si acaso)
$oldTask = Get-ScheduledTask -TaskName "EndpointIQ-Agent" -ErrorAction SilentlyContinue
if ($oldTask) {
    Unregister-ScheduledTask -TaskName "EndpointIQ-Agent" -Confirm:$false
    Write-Host "  [OK] Tarea programada anterior eliminada" -ForegroundColor Green
}
$oldTask2 = Get-ScheduledTask -TaskName "OnyxAgent" -ErrorAction SilentlyContinue
if ($oldTask2) {
    Unregister-ScheduledTask -TaskName "OnyxAgent" -Confirm:$false
    Write-Host "  [OK] Tarea programada eliminada" -ForegroundColor Green
}

# Eliminar exclusion de Defender
try {
    Remove-MpPreference -ExclusionPath $InstallDir -ErrorAction SilentlyContinue
    Write-Host "  [OK] Exclusion de Defender eliminada" -ForegroundColor Green
} catch { }

# Eliminar directorio
if (Test-Path $InstallDir) {
    Write-Host "  [..] Eliminando archivos en $InstallDir..." -ForegroundColor Yellow
    Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "  [OK] Directorio eliminado" -ForegroundColor Green
} else {
    Write-Host "  [!!] Directorio no encontrado" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  +====================================================+" -ForegroundColor Green
Write-Host "  |      DESINSTALACION COMPLETADA                    |" -ForegroundColor Green
Write-Host "  |      Onyx Agent eliminado de este equipo          |" -ForegroundColor Green
Write-Host "  +====================================================+" -ForegroundColor Green
Write-Host ""
Read-Host "  Presione Enter para cerrar"
