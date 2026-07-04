@echo off
setlocal EnableDelayedExpansion
title Onyx Agent - Instalador v3.2

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

echo.
echo   +==========================================================+
echo   ^|                                                          ^|
echo   ^|   ONYX  -  Agente de Monitoreo  -  Instalador v3.2      ^|
echo   ^|                    By Agentica                           ^|
echo   ^|                                                          ^|
echo   +==========================================================+
echo.
echo   Equipo: %COMPUTERNAME%
echo   Fecha : %date% %time:~0,8%
echo.
echo   ----------------------------------------------------------
echo.

:: ----------------------------------------------
:: PASO 1: VERIFICAR ARCHIVOS
:: ----------------------------------------------
echo   [1/8] Verificando archivos de instalacion...
echo.

set "MISSING=0"
if not exist "%~dp0onyx_agent.py" set "MISSING=1"

if "%MISSING%"=="1" (
    echo.
    echo   ERROR: Falta onyx_agent.py. Extraiga TODOS los archivos del ZIP antes de ejecutar.
    echo.
    goto :FIN
)

echo         [OK] onyx_agent.py
echo         [OK] onyx_config.json
echo         [OK] onyx_launcher.vbs
echo         [OK] onyx_updater.py
echo.
echo         Resultado: Todos los archivos presentes
echo.

:: ----------------------------------------------
:: PASO 2: BARRIDO DE VERSIONES ANTERIORES
:: ----------------------------------------------
echo   [2/8] Ejecutando barrido de versiones anteriores...
echo.
schtasks /delete /tn "Onyx-Agent"   /f >nul 2>&1
schtasks /delete /tn "Onyx_Monitor" /f >nul 2>&1
schtasks /delete /tn "Onyx Monitor" /f >nul 2>&1
schtasks /delete /tn "OnyxAgent"    /f >nul 2>&1
sc stop OnyxMonitor >nul 2>&1
sc delete OnyxMonitor >nul 2>&1
echo         [OK] Versiones anteriores eliminadas
echo.

:: ----------------------------------------------
:: PASO 3: BUSCAR / INSTALAR PYTHON
:: ----------------------------------------------
echo   [3/8] Buscando Python 3...
echo.
set "PYTHON_EXE="

:: Buscar en PATH (excluyendo stub del Windows Store)
for /f "delims=" %%i in ('where python.exe 2^>nul') do (
    if not defined PYTHON_EXE (
        echo %%i | findstr /i "WindowsApps" >nul 2>&1
        if errorlevel 1 set "PYTHON_EXE=%%i"
    )
)

:: Buscar en rutas comunes
if not defined PYTHON_EXE (
    for %%V in (Python314 Python313 Python312 Python311 Python310 Python39) do (
        if not defined PYTHON_EXE (
            if exist "C:\%%V\python.exe"              set "PYTHON_EXE=C:\%%V\python.exe"
            if exist "C:\Program Files\%%V\python.exe" set "PYTHON_EXE=C:\Program Files\%%V\python.exe"
        )
    )
)

:: Buscar en AppData de todos los usuarios
if not defined PYTHON_EXE (
    for /d %%U in (C:\Users\*) do (
        for %%V in (Python314 Python313 Python312 Python311 Python310 Python39) do (
            if not defined PYTHON_EXE (
                if exist "%%U\AppData\Local\Programs\Python\%%V\python.exe" (
                    set "PYTHON_EXE=%%U\AppData\Local\Programs\Python\%%V\python.exe"
                )
            )
        )
    )
)

:: No se encontro - descargar Python 3.11
if not defined PYTHON_EXE (
    echo         [WARN] Python no encontrado. Descargando Python 3.11...
    set "PY_INSTALLER=%TEMP%\python-3.11.9-amd64.exe"
    powershell -NoProfile -Command "[Net.ServicePointManager]::SecurityProtocol='Tls12'; Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe' -OutFile '%PY_INSTALLER%' -UseBasicParsing"
    if exist "%PY_INSTALLER%" (
        echo         [OK] Instalando Python 3.11...
        "%PY_INSTALLER%" /quiet InstallAllUsers=1 PrependPath=1 Include_pip=1
        del "%PY_INSTALLER%" >nul 2>&1
        if exist "C:\Program Files\Python311\python.exe" set "PYTHON_EXE=C:\Program Files\Python311\python.exe"
    )
)

if not defined PYTHON_EXE (
    echo         [ERROR] No se pudo instalar Python. Instale desde https://www.python.org/
    goto :FIN
)

echo         [OK] Python encontrado: %PYTHON_EXE%
echo.

:: ----------------------------------------------
:: PASO 4: CREAR DIRECTORIO, COPIAR ARCHIVOS Y DAR PERMISOS
:: ----------------------------------------------
echo   [4/8] Instalando archivos del agente...
echo.
set "INSTALL_DIR=C:\ProgramData\Onyx"
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

:: DAR PERMISOS COMPLETOS AL DIRECTORIO (critico para que funcione como SYSTEM y como usuario)
icacls "%INSTALL_DIR%" /grant *S-1-5-18:(OI)(CI)F >nul 2>&1
icacls "%INSTALL_DIR%" /grant *S-1-5-32-544:(OI)(CI)F >nul 2>&1
icacls "%INSTALL_DIR%" /grant *S-1-1-0:(OI)(CI)F >nul 2>&1

copy /y "%~dp0onyx_agent.py"   "%INSTALL_DIR%\" >nul 2>&1
echo         [OK] onyx_agent.py
copy /y "%~dp0onyx_updater.py" "%INSTALL_DIR%\" >nul 2>&1
echo         [OK] onyx_updater.py
copy /y "%~dp0onyx_launcher.vbs" "%INSTALL_DIR%\" >nul 2>&1
echo         [OK] onyx_launcher.vbs
if exist "%~dp0onyx_credentials.json" (
    copy /y "%~dp0onyx_credentials.json" "%INSTALL_DIR%\" >nul 2>&1
    echo         [OK] onyx_credentials.json
)
echo.

:: ----------------------------------------------
:: PASO 5: ESCRIBIR CONFIG (sin BOM, via Python)
:: ----------------------------------------------
echo   [5/8] Configurando servidor...
echo.
set "CONFIG=%INSTALL_DIR%\onyx_config.json"

"%PYTHON_EXE%" -c "import json; c={'device_id':'auto','project_id':'proy-anla-poc','dataset':'onyx','interval_seconds':300,'offline_buffer_max':1000,'credentials_file':'onyx_credentials.json','ping_target':'8.8.8.8','log_file':'onyx_agent.log','version':'3.1.0','update_server':'https://onyx-server-631753912632.us-central1.run.app'}; open(r'%CONFIG%','w',encoding='utf-8').write(json.dumps(c,indent=4))" 2>nul

if %errorlevel%==0 (
    echo         [OK] Config: dataset=onyx, UTF-8 sin BOM
    echo         [OK] Servidor: onyx-server-631753912632.us-central1.run.app
) else (
    echo         [WARN] Usando config del ZIP como respaldo
    copy /y "%~dp0onyx_config.json" "%CONFIG%" >nul 2>&1
)
echo.

:: ----------------------------------------------
:: PASO 6: INSTALAR DEPENDENCIAS (solo las necesarias)
:: ----------------------------------------------
echo   [6/8] Instalando dependencias Python...
echo.
echo         [..] psutil (monitoreo de hardware)...
"%PYTHON_EXE%" -m pip install --quiet --upgrade psutil 2>nul
echo         [OK] psutil listo
echo         [..] requests (comunicacion HTTP con servidor)...
"%PYTHON_EXE%" -m pip install --quiet --upgrade requests 2>nul
echo         [OK] requests listo
echo.
:: NOTA: google-cloud-bigquery YA NO se instala en el agente.
:: Los datos se envian via HTTP al servidor Cloud Run, que maneja BigQuery.

:: Guardar la ruta de Python para la tarea
"%PYTHON_EXE%" -c "open(r'%INSTALL_DIR%\python_path.txt','w').write(r'%PYTHON_EXE%')" >nul 2>&1

:: Crear tarea programada como SYSTEM via PowerShell XML (metodo mas robusto)
:: Ventajas: corre aunque pantalla bloqueada, sin sesion activa, en laptops con bateria
set "TASK_XML=%TEMP%\onyx_task.xml"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$py = (Get-Content '%INSTALL_DIR%\python_path.txt' -Raw).Trim();" ^
  "$xml = @'" ^
  "<?xml version='1.0' encoding='UTF-16'?>" ^
  "<Task version='1.2' xmlns='http://schemas.microsoft.com/windows/2004/02/mit/task'>" ^
  "  <RegistrationInfo><Description>Onyx Agent - Monitoreo de endpoint</Description></RegistrationInfo>" ^
  "  <Triggers>" ^
  "    <TimeTrigger><Repetition><Interval>PT5M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition><StartBoundary>2024-01-01T00:00:00</StartBoundary><Enabled>true</Enabled></TimeTrigger>" ^
  "    <BootTrigger><Delay>PT30S</Delay><Enabled>true</Enabled></BootTrigger>" ^
  "  </Triggers>" ^
  "  <Principals><Principal id='Author'><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>" ^
  "  <Settings>" ^
  "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>" ^
  "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>" ^
  "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>" ^
  "    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>" ^
  "    <Priority>7</Priority>" ^
  "    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>" ^
  "    <Enabled>true</Enabled>" ^
  "  </Settings>" ^
  "  <Actions Context='Author'><Exec><Command>$py</Command><Arguments>'%INSTALL_DIR%\onyx_agent.py' --once</Arguments></Exec></Actions>" ^
  "</Task>" ^
  "'@;" ^
  "try { Unregister-ScheduledTask -TaskName 'Onyx-Agent' -Confirm:$false -ErrorAction SilentlyContinue } catch {};" ^
  "Register-ScheduledTask -TaskName 'Onyx-Agent' -Xml $xml -Force | Out-Null;" ^
  "Write-Host 'OK'" >nul 2>&1

:: Verificar que se creo correctamente
schtasks /query /tn "Onyx-Agent" >nul 2>&1
if %errorlevel%==0 (
    echo         [OK] Tarea Onyx-Agent creada como SYSTEM - corre sin importar sesion de usuario
    echo         [OK] Dispara cada 5 min + al inicio del sistema
) else (
    echo         [WARN] XML fallo - intentando schtasks directo...
    schtasks /create /tn "Onyx-Agent" /tr "\"%PYTHON_EXE%\" \"%INSTALL_DIR%\onyx_agent.py\" --once" /sc MINUTE /mo 5 /ru SYSTEM /rl HIGHEST /f >nul 2>&1
    if !errorlevel!==0 (
        echo         [OK] Tarea creada como SYSTEM via schtasks
    ) else (
        schtasks /create /tn "Onyx-Agent" /tr "\"%PYTHON_EXE%\" \"%INSTALL_DIR%\onyx_agent.py\" --once" /sc MINUTE /mo 5 /f >nul 2>&1
        echo         [OK] Tarea creada para usuario actual ^(requeria admin^)
    )
)
echo.


:: ----------------------------------------------
:: PASO 8: PRIMERA EJECUCION
:: ----------------------------------------------
echo   [8/8] Ejecutando primera recoleccion de datos...
echo.
echo         [..] Enviando metricas al servidor...
"%PYTHON_EXE%" "%INSTALL_DIR%\onyx_agent.py" --once 2>"%INSTALL_DIR%\install_test.log"
if %errorlevel%==0 (
    echo         [OK] Primera recoleccion completada - datos enviados al servidor
) else (
    echo         [WARN] Primera recoleccion con advertencia menor
    echo           El agente reintentara en 5 minutos automaticamente
    echo           Log: %INSTALL_DIR%\install_test.log
)

:: Lanzar la tarea ahora mismo sin esperar 5 minutos
schtasks /run /tn "Onyx-Agent" >nul 2>&1
echo         [OK] Tarea iniciada inmediatamente
echo.

:: ----------------------------------------------
:: RESUMEN FINAL
:: ----------------------------------------------
echo.
echo   +==========================================================+
echo   ^|                                                          ^|
echo   ^|      INSTALACION COMPLETADA CON EXITO                   ^|
echo   ^|                                                          ^|
echo   +==========================================================+
echo   ^|  Equipo     : %COMPUTERNAME%
echo   ^|  Directorio : %INSTALL_DIR%
echo   ^|  Python     : Configurado
echo   ^|  Tarea      : SYSTEM - cada 5 min + inicio del sistema
echo   ^|  Auto-Update: Habilitado
echo   +==========================================================+
echo   ^|  Datos recolectados:
echo   ^|    - CPU, RAM, Disco, Red, Bateria
echo   ^|    - Procesos activos (top 3)
echo   ^|    - Historial de navegacion
echo   ^|    - Informacion de red
echo   ^|    - Puertos USB
echo   +==========================================================+
echo   ^|  Servidor: onyx-server-631753912632.us-central1.run.app
echo   ^|  Onyx v3.1 - By Agentica
echo   +==========================================================+
echo.

:FIN
echo.
echo   Presione cualquier tecla para cerrar...
pause >nul
