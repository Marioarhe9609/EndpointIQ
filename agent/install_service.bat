@echo off
REM ============================================
REM  Onyx Monitor — Instalador de Servicio
REM  Ejecutar como Administrador
REM ============================================
echo.
echo  ╔══════════════════════════════════════════╗
echo  ║   Onyx Monitor — Instalador de Servicio  ║
echo  ║   By Agentica                             ║
echo  ╚══════════════════════════════════════════╝
echo.

REM Verificar permisos de administrador
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Este script necesita ejecutarse como Administrador.
    echo         Click derecho → "Ejecutar como administrador"
    pause
    exit /b 1
)

cd /d "%~dp0"
echo [INFO] Directorio: %cd%

REM 1. Buscar Python
echo [1/6] Buscando Python...
where python >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Python no encontrado en PATH.
    echo         Instala Python desde https://python.org
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version 2^>^&1') do echo        %%i encontrado

REM 2. Instalar dependencias
echo [2/6] Verificando dependencias...
python -c "import psutil" >nul 2>&1
if %errorLevel% neq 0 (
    echo        Instalando psutil...
    pip install psutil --quiet
)

python -c "import win32serviceutil" >nul 2>&1
if %errorLevel% neq 0 (
    echo        Instalando pywin32...
    pip install pywin32 --quiet
    echo        Ejecutando post-install de pywin32...
    python -c "import win32serviceutil" >nul 2>&1
    if %errorLevel% neq 0 (
        echo [WARN] Ejecutando script de post-instalación...
        for /f "tokens=*" %%i in ('python -c "import sys; print(sys.prefix)"') do (
            if exist "%%i\Scripts\pywin32_postinstall.py" (
                python "%%i\Scripts\pywin32_postinstall.py" -install
            )
        )
    )
)

python -c "from google.cloud import bigquery" >nul 2>&1
if %errorLevel% neq 0 (
    echo        Instalando google-cloud-bigquery...
    pip install google-cloud-bigquery --quiet
)

REM 3. Detener servicio existente (si existe)
echo [3/6] Deteniendo servicio existente (si existe)...
sc query OnyxMonitor >nul 2>&1
if %errorLevel% equ 0 (
    echo        Servicio existente encontrado. Deteniendo...
    net stop OnyxMonitor >nul 2>&1
    timeout /t 2 /nobreak >nul
    python onyx_service.py remove >nul 2>&1
    timeout /t 2 /nobreak >nul
)

REM 4. Desactivar Tarea Programada vieja (si existe)
echo [4/6] Desactivando tarea programada anterior...
schtasks /Query /TN "Onyx Agent" >nul 2>&1
if %errorLevel% equ 0 (
    echo        Tarea "Onyx Agent" encontrada. Desactivando...
    schtasks /Change /TN "Onyx Agent" /Disable >nul 2>&1
    echo        Tarea desactivada (no eliminada, por seguridad).
) else (
    echo        No se encontro tarea programada anterior.
)

REM 5. Instalar el servicio
echo [5/6] Instalando servicio OnyxMonitor...
python onyx_service.py install
if %errorLevel% neq 0 (
    echo [ERROR] Fallo al instalar el servicio.
    pause
    exit /b 1
)

REM Configurar recovery: reiniciar tras 60 segundos en caso de fallo
echo        Configurando auto-recovery...
sc failure OnyxMonitor reset= 86400 actions= restart/60000/restart/60000/restart/120000 >nul 2>&1

REM Configurar inicio automático con delay
sc config OnyxMonitor start= delayed-auto >nul 2>&1

REM Configurar descripción
sc description OnyxMonitor "Agente de monitoreo Onyx - Recolecta metricas de hardware y las envia a BigQuery. By Agentica." >nul 2>&1

REM 6. Iniciar el servicio
echo [6/6] Iniciando servicio...
net start OnyxMonitor
if %errorLevel% neq 0 (
    echo [WARN] No se pudo iniciar. Intentando con sc start...
    sc start OnyxMonitor
)

echo.
echo  ╔══════════════════════════════════════════╗
echo  ║  ✓ Servicio instalado exitosamente!       ║
echo  ║                                            ║
echo  ║  Nombre: OnyxMonitor                       ║
echo  ║  Inicio: Automatico (delayed)              ║
echo  ║  Recovery: Auto-restart tras 60s            ║
echo  ║                                            ║
echo  ║  Verificar: services.msc                    ║
echo  ║  Logs: onyx_service.log                      ║
echo  ╚══════════════════════════════════════════╝
echo.
pause
