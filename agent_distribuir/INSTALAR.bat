@echo off
setlocal
title EndpointIQ - Instalador v2.0

:: ============================================
:: AUTO-ELEVACION como Administrador via VBS
:: (Metodo mas confiable para cualquier Windows)
:: ============================================
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Solicitando permisos de Administrador...
    set "ELEVATE_VBS=%TEMP%\eiq_elevate.vbs"
    echo Set UAC = CreateObject^("Shell.Application"^) > "%ELEVATE_VBS%"
    echo UAC.ShellExecute "%~f0", "", "%~dp0", "runas", 1 >> "%ELEVATE_VBS%"
    cscript //nologo "%ELEVATE_VBS%"
    del "%ELEVATE_VBS%" >nul 2>&1
    exit /b
)

:: ============================================
:: YA SOMOS ADMINISTRADOR - Ejecutar instalacion
:: ============================================
cd /d "%~dp0"
cls
echo.
echo  ==================================================
echo   EndpointIQ Agent - Instalador v2.0
echo   Monitoreo Inteligente + Auto-Update
echo  ==================================================
echo.

:: Verificar archivos
if not exist "%~dp0eiq_agent.py" (
    echo  [ERROR] No se encontro eiq_agent.py
    echo  Extraiga TODOS los archivos del ZIP antes de instalar.
    echo.
    goto :FIN
)
if not exist "%~dp0eiq_credentials.json" (
    echo  [ERROR] No se encontro eiq_credentials.json
    echo  Extraiga TODOS los archivos del ZIP antes de instalar.
    echo.
    goto :FIN
)
echo  [OK] Archivos verificados
echo.

:: ============================================
:: BUSCAR PYTHON
:: ============================================
echo  [..] Buscando Python 3...
set "PYTHON_EXE="

:: Buscar en PATH
where python.exe >nul 2>&1
if %errorlevel%==0 (
    for /f "delims=" %%i in ('where python.exe 2^>nul') do (
        set "PYTHON_EXE=%%i"
        goto :PYTHON_CHECK
    )
)

:: Buscar en rutas comunes
for %%V in (Python314 Python313 Python312 Python311 Python310 Python39) do (
    if exist "C:\%%V\python.exe" (
        set "PYTHON_EXE=C:\%%V\python.exe"
        goto :PYTHON_CHECK
    )
    if exist "C:\Program Files\%%V\python.exe" (
        set "PYTHON_EXE=C:\Program Files\%%V\python.exe"
        goto :PYTHON_CHECK
    )
)

:: Buscar en AppData de todos los usuarios
for /d %%U in (C:\Users\*) do (
    for %%V in (Python314 Python313 Python312 Python311 Python310 Python39) do (
        if exist "%%U\AppData\Local\Programs\Python\%%V\python.exe" (
            set "PYTHON_EXE=%%U\AppData\Local\Programs\Python\%%V\python.exe"
            goto :PYTHON_CHECK
        )
    )
)

:: No se encontro Python - descargar e instalar
echo  [!!] Python 3 no encontrado. Descargando...
echo.
set "PY_INSTALLER=%TEMP%\python-3.11.9-amd64.exe"
echo  Descargando Python 3.11 (esto tarda 1-2 min)...
powershell -NoProfile -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe' -OutFile '%PY_INSTALLER%' -UseBasicParsing"
if not exist "%PY_INSTALLER%" (
    echo  [ERROR] No se pudo descargar Python.
    echo  Instale manualmente: https://www.python.org/downloads/
    goto :FIN
)
echo  [OK] Python descargado
echo  Instalando Python 3.11 (esto tarda 2-3 min)...
"%PY_INSTALLER%" /quiet InstallAllUsers=1 PrependPath=1 Include_pip=1
del "%PY_INSTALLER%" >nul 2>&1

:: Refrescar PATH
set "PATH=C:\Program Files\Python311;C:\Program Files\Python311\Scripts;%PATH%"
for %%V in (Python314 Python313 Python312 Python311 Python310) do (
    if exist "C:\Program Files\%%V\python.exe" (
        set "PYTHON_EXE=C:\Program Files\%%V\python.exe"
        goto :PYTHON_CHECK
    )
    if exist "C:\%%V\python.exe" (
        set "PYTHON_EXE=C:\%%V\python.exe"
        goto :PYTHON_CHECK
    )
)
:: Ultimo intento
where python.exe >nul 2>&1
if %errorlevel%==0 (
    for /f "delims=" %%i in ('where python.exe 2^>nul') do (
        set "PYTHON_EXE=%%i"
        goto :PYTHON_CHECK
    )
)
echo  [ERROR] No se pudo instalar Python automaticamente.
echo  Instale Python manualmente desde https://www.python.org/downloads/
goto :FIN

:PYTHON_CHECK
echo  [OK] Python encontrado: %PYTHON_EXE%
echo.

:: ============================================
:: CREAR DIRECTORIO
:: ============================================
set "INSTALL_DIR=C:\ProgramData\EndpointIQ"
echo  [..] Creando directorio de instalacion...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
echo  [OK] Directorio: %INSTALL_DIR%

:: ============================================
:: COPIAR ARCHIVOS
:: ============================================
echo  [..] Copiando archivos del agente...
copy /y "%~dp0eiq_agent.py" "%INSTALL_DIR%\" >nul 2>&1
echo     [+] eiq_agent.py
copy /y "%~dp0eiq_config.json" "%INSTALL_DIR%\" >nul 2>&1
echo     [+] eiq_config.json
copy /y "%~dp0eiq_credentials.json" "%INSTALL_DIR%\" >nul 2>&1
echo     [+] eiq_credentials.json
copy /y "%~dp0eiq_launcher.vbs" "%INSTALL_DIR%\" >nul 2>&1
echo     [+] eiq_launcher.vbs
echo  [OK] Archivos copiados
echo.

:: ============================================
:: CONFIGURAR AUTO-UPDATE
:: ============================================
echo  [..] Configurando auto-update...
set "CONFIG=%INSTALL_DIR%\eiq_config.json"
>"%CONFIG%" (
    echo {
    echo   "update_server": "https://endpointiq-175647544738.us-central1.run.app",
    echo   "check_interval_seconds": 300,
    echo   "bq_project": "endpointiq",
    echo   "bq_dataset": "endpointiq"
    echo }
)
echo  [OK] Auto-update configurado
echo.

:: ============================================
:: INSTALAR DEPENDENCIAS
:: ============================================
echo  [..] Instalando dependencias de Python...
echo     [+] psutil...
"%PYTHON_EXE%" -m pip install --quiet --upgrade psutil 2>nul
echo     [+] google-cloud-bigquery...
"%PYTHON_EXE%" -m pip install --quiet --upgrade google-cloud-bigquery 2>nul
echo  [OK] Dependencias instaladas
echo.

:: ============================================
:: EXCLUSION DEFENDER
:: ============================================
echo  [..] Configurando exclusiones de seguridad...
powershell -NoProfile -Command "try { Add-MpPreference -ExclusionPath '%INSTALL_DIR%' -ErrorAction Stop; Write-Host '  [OK] Exclusion Defender agregada' } catch { Write-Host '  [!!] No critico - otro antivirus activo' }" 2>nul
echo.

:: ============================================
:: TAREA PROGRAMADA (invisible)
:: ============================================
echo  [..] Configurando tarea programada...

:: Eliminar tarea anterior si existe
schtasks /delete /tn "EndpointIQ-Agent" /f >nul 2>&1

:: Buscar pythonw.exe (version sin ventana)
set "PYTHONW_EXE=%PYTHON_EXE:python.exe=pythonw.exe%"
if not exist "%PYTHONW_EXE%" set "PYTHONW_EXE=%PYTHON_EXE%"

:: Crear tarea con schtasks (funciona en CUALQUIER Windows)
schtasks /create /tn "EndpointIQ-Agent" /tr "\"%PYTHONW_EXE%\" \"%INSTALL_DIR%\eiq_agent.py\" --once" /sc minute /mo 2 /ru SYSTEM /rl HIGHEST /f >nul 2>&1
if %errorlevel%==0 (
    echo  [OK] Tarea programada creada (cada 2 min, invisible)
) else (
    :: Fallback: crear como usuario actual
    schtasks /create /tn "EndpointIQ-Agent" /tr "\"%PYTHONW_EXE%\" \"%INSTALL_DIR%\eiq_agent.py\" --once" /sc minute /mo 2 /f >nul 2>&1
    echo  [OK] Tarea programada creada (cada 2 min)
)
echo.

:: ============================================
:: PRIMERA EJECUCION DE PRUEBA
:: ============================================
echo  [..] Ejecutando primera recoleccion de prueba...
"%PYTHON_EXE%" "%INSTALL_DIR%\eiq_agent.py" --once 2>nul
if %errorlevel%==0 (
    echo  [OK] Primera recoleccion completada exitosamente
) else (
    echo  [!!] La primera recoleccion tuvo un problema menor
    echo       El agente se reintentara automaticamente
)
echo.

:: ============================================
:: RESUMEN FINAL
:: ============================================
echo  ==================================================
echo   INSTALACION COMPLETADA CON EXITO
echo  --------------------------------------------------
echo   Directorio  : %INSTALL_DIR%
echo   Python      : %PYTHON_EXE%
echo   Tarea       : EndpointIQ-Agent (cada 2 min)
echo   Equipo      : %COMPUTERNAME%
echo   Auto-Update : Habilitado
echo  --------------------------------------------------
echo   El agente reporta metricas automaticamente.
echo   Plataforma: endpointiq-175647544738.us-central1.run.app
echo  ==================================================
echo.

:FIN
echo.
echo  Presione cualquier tecla para cerrar...
pause >nul
