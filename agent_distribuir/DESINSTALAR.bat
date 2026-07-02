@echo off
setlocal
chcp 65001 >nul 2>&1
title Onyx Agent — Desinstalador v3.0

:: Auto-elevacion
net session >nul 2>&1
if %errorlevel% neq 0 (
    set "ELEVATE_VBS=%TEMP%\onyx_elevate.vbs"
    echo Set UAC = CreateObject^("Shell.Application"^) > "%ELEVATE_VBS%"
    echo UAC.ShellExecute "%~f0", "", "%~dp0", "runas", 1 >> "%ELEVATE_VBS%"
    cscript //nologo "%ELEVATE_VBS%"
    del "%ELEVATE_VBS%" >nul 2>&1
    exit /b
)

cd /d "%~dp0"
cls
color 0C

echo.
echo   ╔══════════════════════════════════════════════════════════╗
echo   ║                                                          ║
echo   ║    ONYX — Desinstalador del Agente v3.0                  ║
echo   ║    By Agentica                                           ║
echo   ║                                                          ║
echo   ╚══════════════════════════════════════════════════════════╝
echo.
echo   ⚠  Esta accion eliminara el agente de monitoreo de este
echo      equipo. Los datos ya enviados NO se eliminaran.
echo.
echo   ──────────────────────────────────────────────────────────
echo.

set /p CONFIRM="   ¿Desea continuar? (S/N): "
if /i not "%CONFIRM%"=="S" (
    echo.
    echo   Operacion cancelada.
    goto :FIN
)

echo.
echo   [1/4] Eliminando tarea programada...
schtasks /delete /tn "Onyx-Agent" /f >nul 2>&1
echo         ✓ Tarea Onyx-Agent eliminada
echo.

echo   [2/4] Eliminando exclusion de Defender...
powershell -NoProfile -Command "try { Remove-MpPreference -ExclusionPath 'C:\ProgramData\Onyx' -ErrorAction Stop } catch {}" 2>nul
echo         ✓ Exclusion removida
echo.

echo   [3/4] Eliminando archivos del agente...
set "INSTALL_DIR=C:\ProgramData\Onyx"
if exist "%INSTALL_DIR%" (
    rmdir /s /q "%INSTALL_DIR%" >nul 2>&1
    echo         ✓ Directorio %INSTALL_DIR% eliminado
) else (
    echo         = Directorio no encontrado (ya eliminado)
)
echo.

echo   [4/4] Limpieza completada
echo.

echo   ╔══════════════════════════════════════════════════════════╗
echo   ║                                                          ║
echo   ║    ✅  DESINSTALACION COMPLETADA                         ║
echo   ║                                                          ║
echo   ║    El agente ha sido removido de %COMPUTERNAME%          
echo   ║    Los datos historicos permanecen en la nube.           ║
echo   ║                                                          ║
echo   ╚══════════════════════════════════════════════════════════╝
echo.

:FIN
echo.
echo   Presione cualquier tecla para cerrar...
pause >nul
