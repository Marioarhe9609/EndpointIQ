<#
.SYNOPSIS
    Onyx Agent - Desinstalador para Windows
.DESCRIPTION
    Elimina completamente el agente Onyx.
.NOTES
    Ejecutar como Administrador
#>

param(
    [string]$InstallDir = "C:\ProgramData\Onyx"
)

$ErrorActionPreference = "SilentlyContinue"
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
