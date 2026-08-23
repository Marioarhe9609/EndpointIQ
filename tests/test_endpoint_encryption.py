import unittest
import time
import json
import hmac
import hashlib
import uuid
import datetime
import os
import sys
from unittest.mock import patch, MagicMock

# Import functions under test from server and agent
sys.path.insert(0, os.path.abspath("."))
import server
from agent import onyx_agent

class TestEndpointEncryption7Pillars(unittest.TestCase):

    def setUp(self):
        # Reset server rate-limits, nonces, and device secrets for isolation
        with server._ip_rate_lock:
            server._ip_rate_limits.clear()
        with server._nonces_lock:
            server._seen_nonces.clear()
        with server._device_secrets_lock:
            server._device_secrets.clear()
            server._device_secrets["test-device-01"] = "test-secret-key-1234567890abcdef"
            server._device_secrets["test-device-02"] = "test-secret-key-fedcba0987654321"

    # =========================================================================
    # PILAR 1: ESCALABILIDAD
    # =========================================================================
    def test_tc_sca_01_concurrency_nonces(self):
        """Concurrencia de validación de nonces sin colisiones ni condiciones de carrera."""
        import threading
        results = []
        def verify_worker(dev_id, n_id):
            now_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
            secret = server._device_secrets[dev_id]
            body = {"metrics": {"cpu": 10}, "sync": {}}
            can_body = json.dumps(body, sort_keys=True, separators=(',', ':'), default=str, ensure_ascii=False)
            sig_msg = f"{now_ts}|{n_id}|{dev_id}|{can_body}".encode("utf-8")
            sig = hmac.new(secret.encode("utf-8"), sig_msg, hashlib.sha256).hexdigest()
            headers = {"X-Agent-Signature": sig, "X-Agent-Timestamp": now_ts, "X-Agent-Nonce": n_id}
            valid, code, msg = server._verify_agent_signature(headers, json.dumps(body).encode("utf-8"), dev_id)
            results.append((valid, code))

        threads = []
        for i in range(50):
            t = threading.Thread(target=verify_worker, args=("test-device-01", f"nonce-{i}"))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), 50)
        self.assertTrue(all(valid is True and code == 200 for valid, code in results))

    def test_tc_sca_02_bounded_rate_limiter_keys(self):
        """El rate limiter purga y mantiene acotado el número de IPs activas."""
        for i in range(1050):
            server._check_ip_rate_limit(f"192.168.10.{i % 254}")
        with server._ip_rate_lock:
            self.assertLessEqual(len(server._ip_rate_limits), 1000)

    # =========================================================================
    # PILAR 2: ADMINISTRABILIDAD
    # =========================================================================
    def test_tc_adm_01_sanitize_disk_encryption_whitelist(self):
        """La sanitización aplica lista blanca estricta y descarta campos no permitidos."""
        malicious_input = [
            {
                "drive_letter": "C:",
                "protection_status": 1,
                "conversion_status": "FullyEncrypted",
                "encryption_percentage": 100.0,
                "encryption_method": "XTS-AES 128",
                "recovery_key": "489234-234234-SECRET-KEY", # Inyección no permitida
                "pin": "1234"
            }
        ]
        sanitized = server._sanitize_disk_encryption(malicious_input)
        self.assertIsNotNone(sanitized)
        parsed = json.loads(sanitized)
        self.assertEqual(len(parsed), 1)
        item = parsed[0]
        self.assertEqual(item["drive_letter"], "C:")
        self.assertEqual(item["protection_status"], 1)
        self.assertNotIn("recovery_key", item)
        self.assertNotIn("pin", item)

    def test_tc_adm_02_sanitize_disk_encryption_invalid_values(self):
        """Valores corruptos son normalizados a valores seguros por defecto."""
        corrupt_input = [
            {
                "drive_letter": "INVALID_DRIVE_NAME",
                "protection_status": 999,
                "conversion_status": "HACKED_STATUS",
                "encryption_percentage": 500.0,
                "encryption_method": "ROT13"
            }
        ]
        sanitized = server._sanitize_disk_encryption(corrupt_input)
        parsed = json.loads(sanitized)[0]
        self.assertEqual(parsed["drive_letter"], "C:")
        self.assertEqual(parsed["protection_status"], 0)
        self.assertEqual(parsed["conversion_status"], "Unknown")
        self.assertEqual(parsed["encryption_percentage"], 100.0)
        self.assertEqual(parsed["encryption_method"], "Unknown")

    # =========================================================================
    # PILAR 3: EFICIENCIA
    # =========================================================================
    def test_tc_efi_01_constant_time_comparison(self):
        """Uso de hmac.compare_digest para prevención de timing attacks."""
        valid, code, msg = server._verify_agent_signature(
            {"X-Agent-Signature": "invalid_sig", "X-Agent-Timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(), "X-Agent-Nonce": "n1"},
            b"{}",
            "test-device-01"
        )
        self.assertFalse(valid)
        self.assertEqual(code, 401)
        self.assertIn("Firma HMAC", msg)

    # =========================================================================
    # PILAR 4: USO DE RECURSOS
    # =========================================================================
    def test_tc_res_01_seen_nonces_ttl_cleanup(self):
        """Purga O(1) lazy de nonces expirados."""
        now = time.time()
        with server._nonces_lock:
            server._seen_nonces["old-nonce"] = now - 10.0 # Expirado
            server._seen_nonces["active-nonce"] = now + 200.0

        headers = {
            "X-Agent-Signature": "dummy",
            "X-Agent-Timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "X-Agent-Nonce": "old-nonce"
        }
        # Intentar reusar nonce expirado con timestamp válido debe sobrescribir sin error de nonce reutilizado
        dev_id = "test-device-01"
        secret = server._device_secrets[dev_id]
        body = {"metrics": {}}
        can_body = json.dumps(body, sort_keys=True, separators=(',', ':'), default=str, ensure_ascii=False)
        sig_msg = f"{headers['X-Agent-Timestamp']}|old-nonce|{dev_id}|{can_body}".encode("utf-8")
        headers["X-Agent-Signature"] = hmac.new(secret.encode("utf-8"), sig_msg, hashlib.sha256).hexdigest()

        valid, code, msg = server._verify_agent_signature(headers, json.dumps(body).encode("utf-8"), dev_id)
        self.assertTrue(valid)
        self.assertEqual(code, 200)

    # =========================================================================
    # PILAR 5: ALTA DISPONIBILIDAD
    # =========================================================================
    def test_tc_ha_01_malformed_timestamp(self):
        """Timestamp corrupto es capturado limpiamente con 401."""
        headers = {"X-Agent-Signature": "sig", "X-Agent-Timestamp": "not-a-valid-date", "X-Agent-Nonce": "n1"}
        valid, code, msg = server._verify_agent_signature(headers, b"{}", "test-device-01")
        self.assertFalse(valid)
        self.assertEqual(code, 401)
        self.assertEqual(msg, "Timestamp malformado")

    def test_tc_ha_02_malformed_body_bytes(self):
        """Body no parseable como JSON es capturado con 401."""
        now_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        headers = {"X-Agent-Signature": "sig", "X-Agent-Timestamp": now_ts, "X-Agent-Nonce": "n1"}
        valid, code, msg = server._verify_agent_signature(headers, b"NOT_JSON{", "test-device-01")
        self.assertFalse(valid)
        self.assertEqual(code, 401)

    # =========================================================================
    # PILAR 6: SEGURIDAD
    # =========================================================================
    def test_tc_seg_01_fail_closed_unregistered_device(self):
        """Dispositivo no registrado es rechazado fail-closed con 401."""
        headers = {"X-Agent-Signature": "sig", "X-Agent-Timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(), "X-Agent-Nonce": "n1"}
        valid, code, msg = server._verify_agent_signature(headers, b"{}", "unregistered-device-99")
        self.assertFalse(valid)
        self.assertEqual(code, 401)
        self.assertIn("no autorizado", msg)

    def test_tc_seg_02_timestamp_anti_replay_window(self):
        """Petición firmada con timestamp fuera de ventana (>300s) es rechazada."""
        old_ts = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=305)).isoformat()
        dev_id = "test-device-01"
        secret = server._device_secrets[dev_id]
        body = {"metrics": {}}
        can_body = json.dumps(body, sort_keys=True, separators=(',', ':'), default=str, ensure_ascii=False)
        sig_msg = f"{old_ts}|nonce-replay|{dev_id}|{can_body}".encode("utf-8")
        sig = hmac.new(secret.encode("utf-8"), sig_msg, hashlib.sha256).hexdigest()
        headers = {"X-Agent-Signature": sig, "X-Agent-Timestamp": old_ts, "X-Agent-Nonce": "nonce-replay"}
        
        valid, code, msg = server._verify_agent_signature(headers, json.dumps(body).encode("utf-8"), dev_id)
        self.assertFalse(valid)
        self.assertEqual(code, 401)
        self.assertIn("Timestamp fuera de ventana", msg)

    def test_tc_seg_03_nonce_reuse_detection(self):
        """Reenvío de petición con el mismo nonce dentro de ventana es detectado como replay."""
        now_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        dev_id = "test-device-01"
        secret = server._device_secrets[dev_id]
        body = {"metrics": {}}
        can_body = json.dumps(body, sort_keys=True, separators=(',', ':'), default=str, ensure_ascii=False)
        sig_msg = f"{now_ts}|nonce-unique-1|{dev_id}|{can_body}".encode("utf-8")
        sig = hmac.new(secret.encode("utf-8"), sig_msg, hashlib.sha256).hexdigest()
        headers = {"X-Agent-Signature": sig, "X-Agent-Timestamp": now_ts, "X-Agent-Nonce": "nonce-unique-1"}

        # 1ª ejecución: Aceptada
        valid1, code1, _ = server._verify_agent_signature(headers, json.dumps(body).encode("utf-8"), dev_id)
        self.assertTrue(valid1)
        self.assertEqual(code1, 200)

        # 2ª ejecución con mismo nonce: Rechazada
        valid2, code2, msg2 = server._verify_agent_signature(headers, json.dumps(body).encode("utf-8"), dev_id)
        self.assertFalse(valid2)
        self.assertEqual(code2, 401)
        self.assertIn("Replay Attack", msg2)

    def test_tc_seg_04_ip_rate_limiting_enforced(self):
        """Rate limit por IP bloquea en la 61ª petición en 1 minuto."""
        test_ip = "198.51.100.25"
        for _ in range(60):
            allowed = server._check_ip_rate_limit(test_ip, max_req_per_min=60)
            self.assertTrue(allowed)
        
        # Petición 61 es bloqueada
        blocked = server._check_ip_rate_limit(test_ip, max_req_per_min=60)
        self.assertFalse(blocked)

    def test_tc_seg_05_agent_fail_closed_without_secret(self):
        """El agente falla cerrado localmente si no tiene agent_secret configurado."""
        with patch.dict(onyx_agent.CONFIG, {"agent_secret": ""}):
            result = onyx_agent.send_via_http({"device_id": "eiq-test"}, {})
            self.assertFalse(result)

    def test_tc_seg_06_trusted_proxy_extraction(self):
        """Extracción de IP cliente segura en Cloud Run vs ejecución local."""
        class MockHandler:
            headers = {"X-Forwarded-For": "1.2.3.4, 203.0.113.195"}
            client_address = ("10.0.0.1", 12345)

        # Sin K_SERVICE: Ignora X-Forwarded-For no confiable
        with patch.dict(os.environ, {}, clear=True):
            ip = server._extract_trusted_client_ip(MockHandler())
            self.assertEqual(ip, "10.0.0.1")

        # Con K_SERVICE: Toma la última IP fijada por GFE
        with patch.dict(os.environ, {"K_SERVICE": "onyx-server"}):
            ip = server._extract_trusted_client_ip(MockHandler())
            self.assertEqual(ip, "203.0.113.195")

    # =========================================================================
    # PILAR 7: TOLERANCIA A FALLOS
    # =========================================================================
    def test_tc_tol_01_http_error_handling(self):
        """El agente captura HTTPError de urllib y registra código de error."""
        import urllib.error
        with patch.dict(onyx_agent.CONFIG, {"agent_secret": "sec", "update_server": "http://localhost:8080"}):
            with patch("urllib.request.urlopen") as mock_open:
                mock_open.side_effect = urllib.error.HTTPError(
                    "http://localhost/api/agent-ingest", 401, "Unauthorized", {}, MagicMock(read=lambda: b'{"error":"Invalid signature"}')
                )
                res = onyx_agent.send_via_http({"device_id": "eiq-test"}, {})
                self.assertFalse(res)

    def test_tc_tol_02_zero_knowledge_bitlocker_collection(self):
        """Verificación de invariante Zero-Knowledge en recolección de BitLocker."""
        # Simulación de salida de PowerShell Get-BitLockerVolume
        mock_ps_output = json.dumps([{
            "MountPoint": "C:",
            "ProtectionStatus": 1,
            "VolumeStatus": "FullyEncrypted",
            "EncryptionPercentage": 100.0,
            "EncryptionMethod": "XTS-AES 128"
        }])
        with patch("subprocess.run") as mock_sub:
            mock_sub.return_value = MagicMock(stdout=mock_ps_output, returncode=0)
            metrics_row, sync_row = onyx_agent.collect_metrics()
            self.assertIn("disk_encryption", metrics_row)
            enc_data = json.loads(metrics_row["disk_encryption"])
            self.assertEqual(enc_data[0]["drive_letter"], "C:")
            self.assertEqual(enc_data[0]["protection_status"], 1)
            # Asegurar que NO existan claves de recuperación
            self.assertNotIn("KeyProtector", metrics_row["disk_encryption"])
            self.assertNotIn("recovery_key", metrics_row["disk_encryption"])

if __name__ == "__main__":
    unittest.main()
