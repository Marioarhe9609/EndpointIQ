@echo off
title Onyx Agent - Instalador
echo.
echo  +==================================================+
echo  ^|       Onyx Agent - Instalador v1.0         ^|
echo  ^|       Monitoreo Inteligente de Endpoints         ^|
echo  +==================================================+
echo.

:: Verificar permisos de administrador
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!!] Se requieren permisos de Administrador.
    echo  Cerrando y reabriendo como Administrador...
    echo.
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo  [OK] Permisos de Administrador verificados
echo.

:: Ejecutar el instalador PowerShell con politica de ejecucion correcta
echo  [..] Iniciando instalacion...
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0onyx_installer.ps1"

if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] Hubo un problema durante la instalacion.
    echo  Revise los mensajes anteriores.
    echo.
)

pause
