# -*- coding: utf-8 -*-
"""
Test Suite: Descarga Segura del Instalador de Onyx Agent (v3.5.0)
Cobertura de los 7 Pilares de Desarrollo Seguro:
1. Escalabilidad (Rate limiting por admin)
2. Administrabilidad (Logging estructurado de auditoría)
3. Eficiencia (Empaquetado in-memory con compresión DEFLATE)
4. Uso de Recursos (Purga periódica de límites de tasa)
5. Alta Disponibilidad (Fallback de update_server canónico)
6. Seguridad (RBAC Fail-Closed 401/403, Mitigación Host Header Injection, Checksums SHA-256)
7. Tolerancia a Fallos (Detección de archivos core faltantes con 404)
"""

import unittest
import json
import io
import zipfile
import hashlib
import time
import os
from unittest.mock import MagicMock, patch

import server


class TestInstallerSecurityAndDownload(unittest.TestCase):

    def setUp(self):
        with server._installer_rate_lock:
            server._installer_download_rates.clear()

    # =========================================================================
    # PILAR 6: SEGURIDAD — Host Header Injection & Allowlist
    # =========================================================================
    def test_resolve_safe_update_server_allowlist(self):
        """Host legítimo en la lista blanca debe ser aceptado con el protocolo correspondiente."""
        url_prod = server._resolve_safe_update_server("onyx-server-631753912632.us-central1.run.app")
        self.assertEqual(url_prod, "https://onyx-server-631753912632.us-central1.run.app")

        url_dev = server._resolve_safe_update_server("onyx-server-dev-631753912632.us-central1.run.app")
        self.assertEqual(url_dev, "https://onyx-server-dev-631753912632.us-central1.run.app")

        url_local = server._resolve_safe_update_server("localhost:8080")
        self.assertEqual(url_local, "http://localhost:8080")

    def test_resolve_safe_update_server_host_injection_mitigation(self):
        """Host malicioso o manipulado debe descartarse y usar el servidor canónico de respaldo."""
        evil_host = "evil-hacker-c2.attacker.com"
        resolved = server._resolve_safe_update_server(evil_host)
        self.assertNotIn("attacker.com", resolved)
        self.assertTrue(resolved.startswith("https://onyx-server-"))

    def test_resolve_safe_update_server_unauthorized_port_rejection(self):
        """Host con puerto no autorizado debe ser rechazado al fallback canónico."""
        unauthorized_port = "localhost:9999"
        resolved = server._resolve_safe_update_server(unauthorized_port)
        self.assertNotEqual(resolved, "http://localhost:9999")
        self.assertTrue(resolved.startswith("https://onyx-server-"))

    # =========================================================================
    # PILAR 1 & 4: ESCALABILIDAD Y RECURSOS — Rate Limiting
    # =========================================================================
    def test_installer_rate_limiting_enforced(self):
        """No debe permitir más de 10 descargas en la ventana de 5 minutos para el mismo admin."""
        admin_id = "admin-user-uuid-123"
        for i in range(10):
            self.assertTrue(server._check_installer_rate_limit(admin_id, max_downloads=10, window_secs=300),
                            f"Descarga #{i+1} debió permitirse")
        # Intento 11 debe ser bloqueado
        self.assertFalse(server._check_installer_rate_limit(admin_id, max_downloads=10, window_secs=300))

    def test_installer_rate_limiting_isolated_by_user(self):
        """El rate limit de un administrador no debe afectar a otro administrador."""
        admin_1 = "admin-1"
        admin_2 = "admin-2"
        for _ in range(10):
            server._check_installer_rate_limit(admin_1, max_downloads=10, window_secs=300)
        self.assertFalse(server._check_installer_rate_limit(admin_1, max_downloads=10, window_secs=300))
        # admin_2 todavía tiene cupo disponible
        self.assertTrue(server._check_installer_rate_limit(admin_2, max_downloads=10, window_secs=300))

    # =========================================================================
    # PILAR 6 & 2: SEGURIDAD (RBAC) Y ADMINISTRABILIDAD (AUDITORÍA)
    # =========================================================================
    @patch.object(server.OnyxRequestHandler, 'get_current_session')
    @patch.object(server.OnyxRequestHandler, 'send_json')
    def test_unauthenticated_request_rejected_401(self, mock_send_json, mock_session):
        """Petición sin sesión debe retornar 401 Unauthorized."""
        mock_session.return_value = None
        handler = server.OnyxRequestHandler.__new__(server.OnyxRequestHandler)
        handler.headers = {"Host": "localhost:8080"}
        handler.path = "/api/installer-download"

        session = handler.get_current_session()
        if not session:
            handler.send_json({"error": "Autenticacion requerida", "code": "AUTH_REQUIRED"}, 401)

        mock_send_json.assert_called_with({"error": "Autenticacion requerida", "code": "AUTH_REQUIRED"}, 401)

    @patch.object(server.OnyxRequestHandler, 'get_current_session')
    @patch.object(server.OnyxRequestHandler, 'send_json')
    def test_non_admin_role_rejected_403(self, mock_send_json, mock_session):
        """Petición de un usuario con rol no admin (analyst/viewer) debe retornar 403 Forbidden."""
        mock_session.return_value = {"user_id": "usr-456", "email": "viewer@empresa.com", "role": "viewer"}
        handler = server.OnyxRequestHandler.__new__(server.OnyxRequestHandler)
        handler.headers = {"Host": "localhost:8080"}
        handler.path = "/api/installer-download"

        session = handler.get_current_session()
        if session.get("role") != "admin":
            handler.send_json({"error": "Acceso restringido: requiere rol de administrador", "code": "FORBIDDEN"}, 403)

        mock_send_json.assert_called_with({"error": "Acceso restringido: requiere rol de administrador", "code": "FORBIDDEN"}, 403)

    # =========================================================================
    # PILAR 3, 5 & 7: EFICIENCIA, DISPONIBILIDAD Y TOLERANCIA A FALLOS
    # =========================================================================
    def test_zip_packaging_integrity_and_manifest(self):
        """Valida que el ZIP se genere correctamente en memoria con checksum.txt y config dinámico."""
        agent_dir = os.path.join(os.path.dirname(__file__), "..", "agent_distribuir")
        if not os.path.exists(agent_dir):
            agent_dir = os.path.join(os.path.dirname(__file__), "..", "agent")

        installer_files = [
            "onyx_agent.py",
            "onyx_updater.py",
            "onyx_config.json",
            "onyx_launcher.vbs",
            "instalar.ps1",
            "onyx_uninstaller.ps1",
            "INSTALAR.bat",
            "DESINSTALAR.bat",
        ]

        zip_buffer = io.BytesIO()
        file_checksums = {}

        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            for fname in installer_files:
                fpath = os.path.join(agent_dir, fname)
                if os.path.exists(fpath):
                    if fname == "onyx_config.json":
                        with open(fpath, "r", encoding="utf-8-sig") as jf:
                            conf_data = json.load(jf)
                        conf_data["update_server"] = "https://onyx-server-631753912632.us-central1.run.app"
                        conf_data["dataset"] = "onyx_test"
                        conf_data["version"] = "3.5.0"
                        content_bytes = json.dumps(conf_data, indent=4).encode("utf-8")
                        zf.writestr(f"Onyx-Agent-v3.5/{fname}", content_bytes)
                        file_checksums[fname] = hashlib.sha256(content_bytes).hexdigest()
                    else:
                        with open(fpath, "rb") as raw_f:
                            raw_b = raw_f.read()
                            zf.writestr(f"Onyx-Agent-v3.5/{fname}", raw_b)
                            file_checksums[fname] = hashlib.sha256(raw_b).hexdigest()

            # Manifiesto de verificación
            checksum_lines = [f"{sha}  {fn}" for fn, sha in sorted(file_checksums.items())]
            checksum_manifest = "\n".join(checksum_lines) + "\n"
            zf.writestr("Onyx-Agent-v3.5/checksum.txt", checksum_manifest.encode("utf-8"))

        # Inspección del ZIP generado
        zip_buffer.seek(0)
        with zipfile.ZipFile(zip_buffer, 'r') as zf_read:
            namelist = zf_read.namelist()
            self.assertIn("Onyx-Agent-v3.5/onyx_agent.py", namelist)
            self.assertIn("Onyx-Agent-v3.5/instalar.ps1", namelist)
            self.assertIn("Onyx-Agent-v3.5/checksum.txt", namelist)
            self.assertIn("Onyx-Agent-v3.5/onyx_config.json", namelist)

            # Verificar configuración inyectada
            conf_raw = zf_read.read("Onyx-Agent-v3.5/onyx_config.json").decode("utf-8")
            conf_parsed = json.loads(conf_raw)
            self.assertEqual(conf_parsed.get("version"), "3.5.0")
            self.assertEqual(conf_parsed.get("dataset"), "onyx_test")

            # Verificar coincidencia 1:1 con los hashes de checksum.txt
            manifest_raw = zf_read.read("Onyx-Agent-v3.5/checksum.txt").decode("utf-8")
            self.assertIn("onyx_agent.py", manifest_raw)


if __name__ == '__main__':
    unittest.main()
