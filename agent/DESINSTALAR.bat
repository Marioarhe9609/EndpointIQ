@echo off
title Onyx Agent - Desinstalador
echo.
echo  +==================================================+
echo  ^|       Onyx Agent - Desinstalador           ^|
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
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0onyx_uninstaller.ps1"
echo.
pause
