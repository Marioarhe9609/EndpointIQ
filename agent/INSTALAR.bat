@echo off
title Onyx Agent - Instalador Windows Service
echo.
echo  +====================================================+
echo  ^|         ONYX Agent - Instalador v2.1              ^|
echo  ^|         Instalando como Windows Service           ^|
echo  +====================================================+
echo.

:: Verificar permisos de administrador
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!!] Se requieren permisos de Administrador.
    echo  Reabriendo como Administrador...
    echo.
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo  [OK] Permisos verificados
echo.
echo  [..] Iniciando instalacion como Windows Service...
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0eiq_installer.ps1"

if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] Hubo un problema durante la instalacion.
    echo.
)

pause
