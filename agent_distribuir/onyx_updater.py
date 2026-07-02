"""
Onyx - Actualizador Autonomo v1.0
========================================
Script independiente que verifica y descarga la ultima version
del agente desde el servidor central. Diseñado para ejecutarse
ANTES del agente principal, garantizando que siempre se use
la version mas reciente.

Uso: pythonw onyx_updater.py  (silencioso, sin ventana)
     python  onyx_updater.py  (con output en consola)
"""

import os
import sys
import json
import hashlib
import datetime
import logging
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.resolve()
AGENT_FILE = SCRIPT_DIR / "onyx_agent.py"
CONFIG_FILE = SCRIPT_DIR / "onyx_config.json"
LOG_FILE = SCRIPT_DIR / "onyx_updater.log"

# Default server - se puede sobrescribir desde onyx_config.json
DEFAULT_SERVER = "https://proy-anla-poc-175647544738.us-central1.run.app"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [UPDATER] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
    ]
)
log = logging.getLogger("EIQ-UPDATER")


def get_server_url():
    """Lee el update_server desde onyx_config.json o usa el default."""
    try:
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            server = cfg.get("update_server", DEFAULT_SERVER)
            # Ignorar localhost (config corrupto)
            if "localhost" in server or "127.0.0.1" in server:
                return DEFAULT_SERVER
            return server
    except Exception:
        pass
    return DEFAULT_SERVER


def get_local_hash():
    """Calcula el hash MD5 del agente local."""
    if not AGENT_FILE.exists():
        return None
    with open(AGENT_FILE, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


def check_and_update():
    """Verifica si hay una version nueva y la descarga."""
    import urllib.request
    import urllib.error

    server = get_server_url()
    log.info("Verificando actualizaciones en %s ...", server)

    # 1. Obtener hash del servidor
    try:
        version_url = server + "/api/agent-version"
        req = urllib.request.Request(version_url, headers={"User-Agent": "EIQ-Updater/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            version_data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as e:
        log.info("Servidor no alcanzable (modo offline): %s", e)
        return False
    except Exception as e:
        log.info("Error al verificar version: %s", e)
        return False

    server_hash = version_data.get("hash", "")
    server_version = version_data.get("version", "?")

    if not server_hash:
        log.info("Servidor no reporto hash. Saltando actualizacion.")
        return False

    # 2. Comparar con hash local
    local_hash = get_local_hash()
    if local_hash == server_hash:
        log.info("Agente actualizado (v%s, hash: %s)", server_version, local_hash[:8])
        return False

    log.info("NUEVA VERSION! Servidor: v%s (hash:%s) vs Local: (hash:%s)",
             server_version, server_hash[:8], (local_hash or "N/A")[:8])

    # 3. Descargar nueva version
    try:
        download_url = server + "/api/agent-download"
        req2 = urllib.request.Request(download_url, headers={"User-Agent": "EIQ-Updater/1.0"})
        with urllib.request.urlopen(req2, timeout=30) as resp2:
            new_content = resp2.read()
    except Exception as e:
        log.warning("Error al descargar agente: %s", e)
        return False

    # 4. Verificar integridad
    new_hash = hashlib.md5(new_content).hexdigest()
    if new_hash != server_hash:
        log.warning("Hash de descarga no coincide! Esperado:%s Obtenido:%s. Abortando.",
                     server_hash[:8], new_hash[:8])
        return False

    # 5. Backup del agente actual
    if AGENT_FILE.exists():
        backup = AGENT_FILE.with_suffix(".py.bak")
        try:
            import shutil
            shutil.copy2(str(AGENT_FILE), str(backup))
            log.info("Backup guardado: %s", backup.name)
        except Exception as e:
            log.warning("No se pudo hacer backup: %s", e)

    # 6. Escribir nuevo agente
    try:
        with open(AGENT_FILE, "wb") as f:
            f.write(new_content)
        log.info("ACTUALIZADO a v%s (%d bytes). Efectivo en la proxima ejecucion.",
                 server_version, len(new_content))
    except Exception as e:
        log.error("Error critico al escribir agente: %s", e)
        # Intentar restaurar backup
        backup = AGENT_FILE.with_suffix(".py.bak")
        if backup.exists():
            try:
                import shutil
                shutil.copy2(str(backup), str(AGENT_FILE))
                log.info("Backup restaurado exitosamente.")
            except Exception:
                pass
        return False

    # 7. Actualizar version en config
    try:
        cfg = {}
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        cfg["version"] = server_version
        # Asegurar que update_server apunte a produccion
        if "localhost" in cfg.get("update_server", "") or "127.0.0.1" in cfg.get("update_server", ""):
            cfg["update_server"] = DEFAULT_SERVER
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=4)
    except Exception:
        pass

    return True


def update_support_files(server):
    """Descarga las versiones mas recientes del launcher y verifica el config."""
    import urllib.request
    import urllib.error

    # Actualizar launcher.vbs
    launcher_file = SCRIPT_DIR / "onyx_launcher.vbs"
    try:
        launcher_url = server + "/api/launcher-download"
        req = urllib.request.Request(launcher_url, headers={"User-Agent": "EIQ-Updater/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            new_launcher = resp.read()
        if len(new_launcher) > 100:  # Sanity check
            # Compare with existing
            current = b""
            if launcher_file.exists():
                current = launcher_file.read_bytes()
            if current != new_launcher:
                launcher_file.write_bytes(new_launcher)
                log.info("Launcher actualizado (%d bytes)", len(new_launcher))
    except Exception as e:
        log.info("No se pudo actualizar launcher: %s", e)

    # Asegurar config tiene update_server correcto
    try:
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            changed = False
            if "localhost" in cfg.get("update_server", "") or "127.0.0.1" in cfg.get("update_server", ""):
                cfg["update_server"] = DEFAULT_SERVER
                changed = True
            if changed:
                with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, indent=4)
                log.info("Config corregido: update_server -> produccion")
    except Exception:
        pass


if __name__ == "__main__":
    try:
        server = get_server_url()
        updated = check_and_update()
        if updated:
            log.info("Actualizacion del agente completada exitosamente.")
        # Siempre intentar sincronizar archivos de soporte
        update_support_files(server)
        # Limpiar log si es muy grande (>1MB)
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > 1024 * 1024:
            lines = LOG_FILE.read_text(encoding="utf-8").splitlines()
            LOG_FILE.write_text("\n".join(lines[-200:]) + "\n", encoding="utf-8")
    except Exception as e:
        log.error("Error inesperado: %s", e)
