"""
Onyx Monitor — Windows Service v1.0
====================================
Servicio de Windows que ejecuta el agente de monitoreo Onyx de forma
persistente, con heartbeat, auto-recovery y logging al Event Log.

Instalación:
  python onyx_service.py install
  python onyx_service.py start

Desinstalación:
  python onyx_service.py stop
  python onyx_service.py remove
"""

import os
import sys
import time
import json
import socket
import logging
import datetime
import threading
import traceback
from pathlib import Path

# Agregar el directorio del script al path
SCRIPT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(SCRIPT_DIR))

# Importar pywin32
try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
except ImportError:
    print("ERROR: pywin32 no instalado. Ejecuta: pip install pywin32")
    print("       Luego: python Scripts/pywin32_postinstall.py -install")
    sys.exit(1)

# ===========================================================================
# Service Configuration
# ===========================================================================
SERVICE_NAME = "OnyxMonitor"
SERVICE_DISPLAY_NAME = "Onyx Monitor Agent"
SERVICE_DESCRIPTION = "Agente de monitoreo Onyx - Recolecta métricas de hardware y las envía a BigQuery. By Agentica."

def load_service_config():
    """Carga la configuración del agente."""
    config_path = SCRIPT_DIR / "onyx_config.json"
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"interval_seconds": 120, "version": "1.0"}


class OnyxMonitorService(win32serviceutil.ServiceFramework):
    """Windows Service que ejecuta el agente Onyx de forma persistente."""

    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY_NAME
    _svc_description_ = SERVICE_DESCRIPTION

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.is_running = True
        self.config = load_service_config()

        # Setup file logging
        log_path = SCRIPT_DIR / "onyx_service.log"
        self.logger = logging.getLogger("OnyxService")
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler(str(log_path), encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s [SERVICE] %(message)s"))
        self.logger.addHandler(handler)

    def SvcStop(self):
        """Llamado cuando el servicio recibe señal de detención."""
        self.logger.info("Servicio detenido por el usuario/sistema.")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.is_running = False
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        """Punto de entrada principal del servicio."""
        try:
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, "")
            )
            self.logger.info("=" * 60)
            self.logger.info("Onyx Monitor Service v%s iniciado", self.config.get("version", "1.0"))
            self.logger.info("Directorio: %s", SCRIPT_DIR)
            self.logger.info("Intervalo: %ds", self.config.get("interval_seconds", 120))
            self.logger.info("=" * 60)

            self.main_loop()

        except Exception as e:
            self.logger.error("Error fatal en el servicio: %s", e, exc_info=True)
            servicemanager.LogErrorMsg(f"Onyx Monitor error fatal: {e}")

    def main_loop(self):
        """Loop principal del servicio."""
        interval = self.config.get("interval_seconds", 120)
        consecutive_failures = 0
        max_failures = 5

        # Iniciar thread de heartbeat
        heartbeat_thread = threading.Thread(target=self.heartbeat_loop, daemon=True)
        heartbeat_thread.start()
        self.logger.info("Heartbeat thread iniciado.")

        while self.is_running:
            try:
                # Ejecutar un ciclo de recolección
                self.run_agent_cycle()
                consecutive_failures = 0

            except Exception as e:
                consecutive_failures += 1
                self.logger.error(
                    "Error en ciclo #%d/%d: %s",
                    consecutive_failures, max_failures, e, exc_info=True
                )

                if consecutive_failures >= max_failures:
                    self.logger.warning(
                        "%d fallos consecutivos. Reiniciando cliente BigQuery...",
                        max_failures
                    )
                    try:
                        import onyx_agent
                        onyx_agent.get_bq_client(force_reset=True)
                    except Exception:
                        pass
                    consecutive_failures = 0

            # Esperar el intervalo, pero responder a stop_event inmediatamente
            wait_result = win32event.WaitForSingleObject(
                self.stop_event, interval * 1000
            )
            if wait_result == win32event.WAIT_OBJECT_0:
                break

        self.logger.info("Loop principal terminado. Servicio detenido.")

    def run_agent_cycle(self):
        """Ejecuta un ciclo completo de recolección y envío."""
        try:
            # Importar el agente (lazy import para que use su propia config)
            import importlib
            if 'onyx_agent' in sys.modules:
                importlib.reload(sys.modules['onyx_agent'])
            import onyx_agent

            # Ejecutar ciclo
            onyx_agent.run_once()
            self.logger.info(
                "Ciclo completado. Device: %s",
                onyx_agent.DEVICE_ID
            )

        except Exception as e:
            self.logger.error("Error ejecutando agente: %s", e, exc_info=True)
            raise

    def heartbeat_loop(self):
        """Thread que escribe heartbeat cada 30 segundos."""
        heartbeat_file = SCRIPT_DIR / "onyx_heartbeat.txt"

        while self.is_running:
            try:
                now = datetime.datetime.now(datetime.timezone.utc)
                data = {
                    "timestamp": now.isoformat(),
                    "service": SERVICE_NAME,
                    "status": "alive",
                    "pid": os.getpid()
                }
                with open(heartbeat_file, "w", encoding="utf-8") as f:
                    json.dump(data, f)

                # También intentar enviar heartbeat al servidor
                self._send_server_heartbeat(now)

            except Exception as e:
                self.logger.debug("Heartbeat error: %s", e)

            # Esperar 30 segundos
            time.sleep(30)

    def _send_server_heartbeat(self, now):
        """Envía heartbeat HTTP al servidor central."""
        try:
            import urllib.request
            server = self.config.get(
                "update_server",
                "https://proy-anla-poc-175647544738.us-central1.run.app"
            )
            # Obtener device_id
            try:
                import onyx_agent
                device_id = onyx_agent.DEVICE_ID
            except Exception:
                import hashlib
                hostname = socket.gethostname().lower().replace(" ", "-")
                h = hashlib.md5(hostname.encode()).hexdigest()[:6]
                device_id = "eiq-" + hostname + "-" + h

            payload = json.dumps({
                "device_id": device_id,
                "timestamp": now.isoformat(),
                "status": "alive",
                "service_mode": "windows_service"
            }).encode("utf-8")

            req = urllib.request.Request(
                server + "/api/heartbeat",
                data=payload,
                headers={"Content-Type": "application/json",
                         "User-Agent": "OnyxService/1.0"},
                method="POST"
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass  # Heartbeat silencioso — no importa si falla


# ===========================================================================
# Entry Point
# ===========================================================================
if __name__ == "__main__":
    if len(sys.argv) == 1:
        # Si se ejecuta sin argumentos, intentar como servicio
        try:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(OnyxMonitorService)
            servicemanager.StartServiceCtrlDispatcher()
        except Exception as e:
            print(f"Error iniciando servicio: {e}")
            print("Uso: python onyx_service.py [install|start|stop|remove|debug]")
    else:
        # Manejar argumentos de línea de comandos
        win32serviceutil.HandleCommandLine(OnyxMonitorService)
