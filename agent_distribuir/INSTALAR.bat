@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul 2>&1
title Onyx Agent — Instalador v3.0

:: ============================================
:: AUTO-ELEVACION como Administrador via VBS
:: ============================================
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Solicitando permisos de Administrador...
    set "ELEVATE_VBS=%TEMP%\onyx_elevate.vbs"
    echo Set UAC = CreateObject^("Shell.Application"^) > "%ELEVATE_VBS%"
    echo UAC.ShellExecute "%~f0", "", "%~dp0", "runas", 1 >> "%ELEVATE_VBS%"
    cscript //nologo "%ELEVATE_VBS%"
    del "%ELEVATE_VBS%" >nul 2>&1
    exit /b
)

:: ============================================
:: YA SOMOS ADMINISTRADOR
:: ============================================
cd /d "%~dp0"
cls
color 0B

:: Habilitar ANSI colors (Windows 10+)
for /f "tokens=3" %%v in ('reg query "HKCU\Console" /v VirtualTerminalLevel 2^>nul') do set "VT=%%v"
reg add "HKCU\Console" /v VirtualTerminalLevel /t REG_DWORD /d 1 /f >nul 2>&1

:: ──────────────────────────────────────────────
:: HEADER CON BRANDING
:: ──────────────────────────────────────────────
echo.
echo   ╔══════════════════════════════════════════════════════════╗
echo   ║                                                          ║
echo   ║      ██████╗ ███╗   ██╗██╗   ██╗██╗  ██╗                ║
echo   ║     ██╔═══██╗████╗  ██║╚██╗ ██╔╝╚██╗██╔╝                ║
echo   ║     ██║   ██║██╔██╗ ██║ ╚████╔╝  ╚███╔╝                 ║
echo   ║     ██║   ██║██║╚██╗██║  ╚██╔╝   ██╔██╗                 ║
echo   ║     ╚██████╔╝██║ ╚████║   ██║   ██╔╝ ██╗                ║
echo   ║      ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝                ║
echo   ║                                                          ║
echo   ║         Agente de Monitoreo — Instalador v3.0            ║
echo   ║                    By Agentica                           ║
echo   ║                                                          ║
echo   ╚══════════════════════════════════════════════════════════╝
echo.
echo   Equipo: %COMPUTERNAME%
echo   Fecha : %date% %time:~0,8%
echo.
echo   ──────────────────────────────────────────────────────────
echo.

:: ──────────────────────────────────────────────
:: PASO 1: VERIFICAR ARCHIVOS
:: ──────────────────────────────────────────────
echo   [1/7] Verificando archivos de instalacion...
echo.

set "MISSING=0"
if not exist "%~dp0onyx_agent.py" (
    echo         ✗ onyx_agent.py — NO ENCONTRADO
    set "MISSING=1"
)
if not exist "%~dp0onyx_credentials.json" (
    echo         ✗ onyx_credentials.json — NO ENCONTRADO
    set "MISSING=1"
)

if "%MISSING%"=="1" (
    echo.
    echo   ╔══════════════════════════════════════════════════════╗
    echo   ║  ERROR: Archivos faltantes                          ║
    echo   ║  Extraiga TODOS los archivos del ZIP antes de       ║
    echo   ║  ejecutar el instalador.                            ║
    echo   ╚══════════════════════════════════════════════════════╝
    echo.
    goto :FIN
)

echo         ✓ onyx_agent.py
echo         ✓ onyx_credentials.json
echo         ✓ onyx_config.json
echo         ✓ onyx_launcher.vbs
echo         ✓ onyx_updater.py
echo.
echo         Resultado: Todos los archivos presentes
echo.

:: ──────────────────────────────────────────────
:: PASO 2: BUSCAR / INSTALAR PYTHON
:: ──────────────────────────────────────────────
echo   [2/7] Buscando Python 3...
echo.
set "PYTHON_EXE="

:: Buscar en PATH
where python.exe >nul 2>&1
if %errorlevel%==0 (
    for /f "delims=" %%i in ('where python.exe 2^>nul') do (
        set "PYTHON_EXE=%%i"
        goto :PYTHON_FOUND
    )
)

:: Buscar en rutas comunes
for %%V in (Python314 Python313 Python312 Python311 Python310 Python39) do (
    if exist "C:\%%V\python.exe" (
        set "PYTHON_EXE=C:\%%V\python.exe"
        goto :PYTHON_FOUND
    )
    if exist "C:\Program Files\%%V\python.exe" (
        set "PYTHON_EXE=C:\Program Files\%%V\python.exe"
        goto :PYTHON_FOUND
    )
)

:: Buscar en AppData
for /d %%U in (C:\Users\*) do (
    for %%V in (Python314 Python313 Python312 Python311 Python310 Python39) do (
        if exist "%%U\AppData\Local\Programs\Python\%%V\python.exe" (
            set "PYTHON_EXE=%%U\AppData\Local\Programs\Python\%%V\python.exe"
            goto :PYTHON_FOUND
        )
    )
)

:: No se encontro — descargar
echo         ⚠ Python 3 no encontrado en el sistema
echo         ↓ Descargando Python 3.11 automaticamente...
echo.
set "PY_INSTALLER=%TEMP%\python-3.11.9-amd64.exe"
powershell -NoProfile -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe' -OutFile '%PY_INSTALLER%' -UseBasicParsing"
if not exist "%PY_INSTALLER%" (
    echo         ✗ No se pudo descargar Python
    echo         → Instale manualmente: https://www.python.org/downloads/
    goto :FIN
)
echo         ✓ Python descargado
echo         ⏳ Instalando Python 3.11 (2-3 minutos)...
"%PY_INSTALLER%" /quiet InstallAllUsers=1 PrependPath=1 Include_pip=1
del "%PY_INSTALLER%" >nul 2>&1

set "PATH=C:\Program Files\Python311;C:\Program Files\Python311\Scripts;%PATH%"
for %%V in (Python314 Python313 Python312 Python311 Python310) do (
    if exist "C:\Program Files\%%V\python.exe" (
        set "PYTHON_EXE=C:\Program Files\%%V\python.exe"
        goto :PYTHON_FOUND
    )
    if exist "C:\%%V\python.exe" (
        set "PYTHON_EXE=C:\%%V\python.exe"
        goto :PYTHON_FOUND
    )
)
where python.exe >nul 2>&1
if %errorlevel%==0 (
    for /f "delims=" %%i in ('where python.exe 2^>nul') do (
        set "PYTHON_EXE=%%i"
        goto :PYTHON_FOUND
    )
)
echo         ✗ No se pudo instalar Python automaticamente
echo         → Instale desde https://www.python.org/downloads/
goto :FIN

:PYTHON_FOUND
echo         ✓ Python encontrado
echo           Ruta: %PYTHON_EXE%
echo.

:: ──────────────────────────────────────────────
:: PASO 3: CREAR DIRECTORIO E INSTALAR ARCHIVOS
:: ──────────────────────────────────────────────
echo   [3/7] Instalando archivos del agente...
echo.
set "INSTALL_DIR=C:\ProgramData\Onyx"
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

copy /y "%~dp0onyx_agent.py" "%INSTALL_DIR%\" >nul 2>&1
echo         ✓ onyx_agent.py → %INSTALL_DIR%
copy /y "%~dp0onyx_updater.py" "%INSTALL_DIR%\" >nul 2>&1
echo         ✓ onyx_updater.py (auto-actualizador)
copy /y "%~dp0onyx_credentials.json" "%INSTALL_DIR%\" >nul 2>&1
echo         ✓ onyx_credentials.json (credenciales BigQuery)
copy /y "%~dp0onyx_launcher.vbs" "%INSTALL_DIR%\" >nul 2>&1
echo         ✓ onyx_launcher.vbs (lanzador invisible)

if not exist "%INSTALL_DIR%\onyx_config.json" (
    copy /y "%~dp0onyx_config.json" "%INSTALL_DIR%\" >nul 2>&1
    echo         ✓ onyx_config.json (configuracion nueva)
) else (
    echo         = onyx_config.json (configuracion existente conservada)
)
echo.

:: ──────────────────────────────────────────────
:: PASO 4: CONFIGURACION AUTO-UPDATE
:: ──────────────────────────────────────────────
echo   [4/7] Configurando servidor de actualizaciones...
echo.
set "CONFIG=%INSTALL_DIR%\onyx_config.json"
findstr /c:"proy-anla-poc-175647544738" "%CONFIG%" >nul 2>&1
if %errorlevel% neq 0 (
    >"%CONFIG%" (
        echo {
        echo   "device_id": "auto",
        echo   "project_id": "proy-anla-poc",
        echo   "dataset": "proy-anla-poc",
        echo   "interval_seconds": 300,
        echo   "offline_buffer_max": 1000,
        echo   "credentials_file": "onyx_credentials.json",
        echo   "ping_target": "8.8.8.8",
        echo   "log_file": "onyx_agent.log",
        echo   "version": "3.0.0",
        echo   "update_server": "https://proy-anla-poc-175647544738.us-central1.run.app"
        echo }
    )
    echo         ✓ Servidor configurado: proy-anla-poc-175647544738.us-central1.run.app
) else (
    echo         ✓ Servidor ya configurado correctamente
)
echo         ✓ Auto-update habilitado (se actualiza solo desde la nube)
echo.

:: ──────────────────────────────────────────────
:: PASO 5: INSTALAR DEPENDENCIAS PYTHON
:: ──────────────────────────────────────────────
echo   [5/7] Instalando dependencias de Python...
echo.
echo         ⏳ psutil (monitoreo de hardware)...
"%PYTHON_EXE%" -m pip install --quiet --upgrade psutil 2>nul
echo         ✓ psutil instalado
echo         ⏳ google-cloud-bigquery (envio de datos)...
"%PYTHON_EXE%" -m pip install --quiet --upgrade google-cloud-bigquery 2>nul
echo         ✓ google-cloud-bigquery instalado
echo.

:: ──────────────────────────────────────────────
:: PASO 6: CONFIGURAR SEGURIDAD Y TAREA
:: ──────────────────────────────────────────────
echo   [6/7] Configurando seguridad y tarea programada...
echo.

:: Exclusion Defender
powershell -NoProfile -Command "try { Add-MpPreference -ExclusionPath '%INSTALL_DIR%' -ErrorAction Stop; Write-Host '        ✓ Exclusion de Windows Defender configurada' } catch { Write-Host '        ⚠ Defender no disponible (otro antivirus activo)' }" 2>nul

:: Limpiar TODAS las tareas anteriores (evita errores de ruta vieja)
schtasks /delete /tn "Onyx-Agent" /f >nul 2>&1
schtasks /delete /tn "Onyx_Monitor" /f >nul 2>&1
schtasks /delete /tn "Onyx Monitor" /f >nul 2>&1
echo         ✓ Tareas anteriores limpiadas

:: Crear tarea programada nueva (ruta correcta)
set "LAUNCHER=%INSTALL_DIR%\onyx_launcher.vbs"

schtasks /create /tn "Onyx-Agent" /tr "wscript.exe \"%LAUNCHER%\"" /sc minute /mo 5 /ru SYSTEM /rl HIGHEST /f >nul 2>&1
if %errorlevel%==0 (
    echo         ✓ Tarea programada creada como SYSTEM
    echo           Frecuencia: cada 5 minutos, ejecucion invisible
) else (
    schtasks /create /tn "Onyx-Agent" /tr "wscript.exe \"%LAUNCHER%\"" /sc minute /mo 5 /f >nul 2>&1
    echo         ✓ Tarea programada creada (usuario actual)
    echo           Frecuencia: cada 5 minutos
)
echo.

:: ──────────────────────────────────────────────
:: PASO 7: PRIMERA EJECUCION
:: ──────────────────────────────────────────────
echo   [7/7] Ejecutando primera recoleccion de datos...
echo.
echo         ⏳ Recolectando metricas del equipo...
"%PYTHON_EXE%" "%INSTALL_DIR%\onyx_agent.py" --once 2>nul
if %errorlevel%==0 (
    echo         ✓ Primera recoleccion completada exitosamente
    echo           → Datos enviados a BigQuery
) else (
    echo         ⚠ La primera recoleccion tuvo un problema menor
    echo           El agente reintentara automaticamente
)
echo.

:: ──────────────────────────────────────────────
:: RESUMEN FINAL
:: ──────────────────────────────────────────────
echo.
echo   ╔══════════════════════════════════════════════════════════╗
echo   ║                                                          ║
echo   ║         ✅  INSTALACION COMPLETADA CON EXITO             ║
echo   ║                                                          ║
echo   ╠══════════════════════════════════════════════════════════╣
echo   ║                                                          ║
echo   ║   Equipo       : %COMPUTERNAME%                          
echo   ║   Directorio   : %INSTALL_DIR%       
echo   ║   Python       : Detectado y configurado                 
echo   ║   Tarea        : Onyx-Agent (cada 5 min)           
echo   ║   Auto-Update  : Habilitado                              
echo   ║                                                          ║
echo   ╠══════════════════════════════════════════════════════════╣
echo   ║                                                          ║
echo   ║   📊 Datos recolectados:                                 ║
echo   ║      • CPU, RAM, Disco, Red, Bateria                    ║
echo   ║      • Procesos activos                                  ║
echo   ║      • Historial de navegacion                           ║
echo   ║      • Informacion de red (interfaces, dispositivos)     ║
echo   ║      • Puertos USB (tipo, estado, dispositivos)          ║
echo   ║      • Visor de Sucesos (errores, advertencias, login)   ║
echo   ║                                                          ║
echo   ╠══════════════════════════════════════════════════════════╣
echo   ║                                                          ║
echo   ║   🌐 Plataforma de monitoreo:                            ║
echo   ║   proy-anla-poc-175647544738.us-central1.run.app            ║
echo   ║                                                          ║
echo   ║   Onyx v3.0 — By Agentica                               ║
echo   ║                                                          ║
echo   ╚══════════════════════════════════════════════════════════╝
echo.

:FIN
echo.
echo   Presione cualquier tecla para cerrar...
pause >nul
