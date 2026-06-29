@echo off
chcp 65001 >nul
title Onyx - Diagnostico de Agente
color 0B
echo ═══════════════════════════════════════════════════════
echo    Onyx - Diagnostico y Reparacion de Agente
echo ═══════════════════════════════════════════════════════
echo.

:: 1. Verificar Python
echo [1/6] Verificando Python...
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo    ❌ Python NO encontrado. Instale Python 3.10+ desde python.org
    goto :fin
) else (
    for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo    ✅ %%v encontrado
)
echo.

:: 2. Verificar dependencias
echo [2/6] Verificando dependencias Python...
python -c "import psutil; print('   ✅ psutil:', psutil.__version__)" 2>nul || echo    ❌ psutil NO instalado. Ejecute: pip install psutil
python -c "import requests; print('   ✅ requests:', requests.__version__)" 2>nul || echo    ❌ requests NO instalado. Ejecute: pip install requests
echo.

:: 3. Verificar tarea programada
echo [3/6] Verificando tarea programada...
schtasks /query /tn "Onyx-Agent" /fo LIST 2>nul
if %errorlevel% neq 0 (
    schtasks /query /tn "Onyx_Monitor" /fo LIST 2>nul
    if %errorlevel% neq 0 (
        echo    ❌ Tarea programada NO encontrada
        echo    Para crearla ejecute INSTALAR.bat en la carpeta agent_distribuir
    ) else (
        echo    ✅ Tarea Onyx_Monitor encontrada
    )
) else (
    echo    ✅ Tarea Onyx-Agent encontrada
)
echo.

:: 4. Verificar si el agente está corriendo
echo [4/6] Verificando proceso del agente...
tasklist /fi "imagename eq pythonw.exe" 2>nul | find /i "pythonw" >nul
if %errorlevel% equ 0 (
    echo    ✅ pythonw.exe esta corriendo
    tasklist /fi "imagename eq pythonw.exe" /fo table
) else (
    echo    ⚠️ pythonw.exe NO esta corriendo
    echo    Intentando verificar con python.exe...
    tasklist /fi "imagename eq python.exe" 2>nul | find /i "python" >nul
    if %errorlevel% equ 0 (
        echo    ✅ python.exe esta corriendo
    ) else (
        echo    ❌ Ningun proceso Python activo
    )
)
echo.

:: 5. Verificar archivo de configuracion
echo [5/6] Verificando configuracion del agente...
set "AGENT_DIR=%~dp0"
if exist "%AGENT_DIR%onyx_config.json" (
    echo    ✅ onyx_config.json encontrado
    type "%AGENT_DIR%onyx_config.json"
) else (
    echo    Buscando en ubicaciones comunes...
    if exist "C:\Users\%USERNAME%\.gemini\antigravity-ide\scratch\Onyx\agent\onyx_config.json" (
        echo    ✅ Encontrado en carpeta del proyecto
        type "C:\Users\%USERNAME%\.gemini\antigravity-ide\scratch\Onyx\agent\onyx_config.json"
    ) else (
        echo    ❌ onyx_config.json NO encontrado
    )
)
echo.

:: 6. Verificar log del agente
echo [6/6] Revisando log del agente (ultimas 20 lineas)...
if exist "%AGENT_DIR%onyx_agent.log" (
    echo    ✅ Log encontrado:
    echo    --- Ultimas lineas ---
    powershell -Command "Get-Content '%AGENT_DIR%onyx_agent.log' -Tail 20"
) else (
    if exist "C:\Users\%USERNAME%\.gemini\antigravity-ide\scratch\Onyx\agent\onyx_agent.log" (
        echo    ✅ Log encontrado en carpeta del proyecto
        powershell -Command "Get-Content 'C:\Users\%USERNAME%\.gemini\antigravity-ide\scratch\Onyx\agent\onyx_agent.log' -Tail 20"
    ) else (
        echo    ⚠️ Log NO encontrado (el agente puede no haberse ejecutado nunca)
    )
)
echo.

:: 7. Conectividad
echo [EXTRA] Verificando conectividad al servidor...
python -c "import urllib.request; r=urllib.request.urlopen('https://proy-anla-poc-175647544738.us-central1.run.app/api/status',timeout=10); print('   ✅ Servidor accesible:', r.read().decode()[:100])" 2>nul || echo    ❌ No se puede conectar al servidor

echo.
echo ═══════════════════════════════════════════════════════
echo    Diagnostico completado
echo ═══════════════════════════════════════════════════════

:fin
echo.
pause
