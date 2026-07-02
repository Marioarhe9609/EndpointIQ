@echo off
REM ============================================
REM  Onyx Monitor — Desinstalador de Servicio
REM  Ejecutar como Administrador
REM ============================================
echo.
echo  Onyx Monitor — Desinstalador de Servicio
echo  =========================================
echo.

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Este script necesita ejecutarse como Administrador.
    pause
    exit /b 1
)

cd /d "%~dp0"

echo [1/3] Deteniendo servicio OnyxMonitor...
net stop OnyxMonitor >nul 2>&1
timeout /t 3 /nobreak >nul

echo [2/3] Eliminando servicio...
python onyx_service.py remove
if %errorLevel% neq 0 (
    echo        Intentando con sc delete...
    sc delete OnyxMonitor >nul 2>&1
)

echo [3/3] Limpieza...
if exist onyx_heartbeat.txt del onyx_heartbeat.txt

echo.
echo  ✓ Servicio desinstalado exitosamente.
echo.
pause
