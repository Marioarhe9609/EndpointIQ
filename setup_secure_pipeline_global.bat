@echo off
chcp 65001 >nul
echo.
echo =======================================================================
echo   INSTALADOR DEL PROTOCOLO DE DESARROLLO SEGURO MULTI-AGENTE (GLOBAL)
echo   Gemini 3.7 + Claude Code + Blindaje Anti-Regresion
echo =======================================================================
echo.

set "TARGET_DIR=%USERPROFILE%\.gemini\config"
set "RULES_DIR=%TARGET_DIR%\rules"
set "SKILLS_DIR=%TARGET_DIR%\skills\claude-secure-pipeline"
set "SCRIPTS_DIR=%SKILLS_DIR%\scripts"

echo [1/3] Creando directorios globales en %TARGET_DIR%...
if not exist "%RULES_DIR%" mkdir "%RULES_DIR%"
if not exist "%SCRIPTS_DIR%" mkdir "%SCRIPTS_DIR%"

echo [2/3] Copiando Reglas y Skills...
copy /y "%~dp0.gemini\rules\secure_dev_pipeline.md" "%RULES_DIR%\" >nul
copy /y "%~dp0.gemini\skills\claude-secure-pipeline\SKILL.md" "%SKILLS_DIR%\" >nul
copy /y "%~dp0.gemini\skills\claude-secure-pipeline\scripts\claude_gate.py" "%SCRIPTS_DIR%\" >nul

echo [3/3] Verificando dependencias locales...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [AVISO] Python no esta en el PATH. Asegurate de instalar Python 3.10+
) else (
    echo [OK] Python detectado.
)

where claude >nul 2>&1
if %errorlevel% neq 0 (
    echo [AVISO] Claude CLI no encontrado en PATH. Ejecuta: npm install -g @anthropic-ai/claude-code
) else (
    echo [OK] Claude Code CLI detectado.
)

echo.
echo =======================================================================
echo   INSTALACION GLOBAL COMPLETADA CON EXITO
echo   A partir de ahora, Antigravity aplicara este protocolo seguro en
echo   CUALQUIER proyecto nuevo o existente en esta maquina.
echo =======================================================================
echo.
pause
