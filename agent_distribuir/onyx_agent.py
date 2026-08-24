"""
Onyx Agent v3.5.0
=================
Monitoring agent for Windows. Sends metrics via HTTP (primary) or
directly to BigQuery (fallback). Works offline with SQLite buffer.

Architecture:
  Online  → HTTP POST to Cloud Run /api/agent-ingest (primary, no SDK needed)
  Pub/Sub → Cloud Run push subscription → BigQuery (fallback)
  BQ DML  → BigQuery direct INSERT (last resort)
  Offline → SQLite buffer → flush on reconnect

# Onyx Agent - version 3.5.0
# Agente de monitoreo de endpoints para Onyx Platform
Usage: python onyx_agent.py [--once] [--verbose]
  --once    Run a single collection cycle
  --verbose Show detailed output in console

Metrics: CPU, RAM, Disk, Network latency, Battery, Top processes, Idle time
Target: BigQuery proy-anla-poc dataset: onyx
"""

import os
import sys
import json
import time
import socket
import sqlite3
import logging
import platform
import datetime
import hashlib
import hmac
import uuid
import urllib.request as _ur
import urllib.error as _ue
from pathlib import Path

# ===========================================================================
# Import optional dependencies
# ===========================================================================
try:
    import psutil
except ImportError:
    print("[ERROR] psutil not installed. Run: pip install psutil")
    sys.exit(1)

try:
    from google.cloud import pubsub_v1
    HAS_PUBSUB = True
except ImportError:
    HAS_PUBSUB = False
    print("[WARN] google-cloud-pubsub not installed. Falling back to BigQuery direct.")

try:
    from google.cloud import bigquery
    HAS_BQ = True
except ImportError:
    HAS_BQ = False
    print("[WARN] google-cloud-bigquery not installed. Offline-only mode.")

# ===========================================================================
# Configuration
# ===========================================================================
SCRIPT_DIR = Path(__file__).parent.resolve()
CONFIG_PATH = SCRIPT_DIR / "onyx_config.json"
DB_PATH     = SCRIPT_DIR / "onyx_buffer.db"

def load_config():
    if not CONFIG_PATH.exists():
        print("[ERROR] Config file not found: " + str(CONFIG_PATH))
        sys.exit(1)
    try:
        # utf-8-sig strips the BOM silently if PowerShell wrote it with -Encoding UTF8
        with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print("[ERROR] onyx_config.json is invalid JSON: " + str(e))
        print("[ERROR] Delete " + str(CONFIG_PATH) + " and re-run the installer.")
        sys.exit(1)

CONFIG = load_config()

# Setup logging with rotation (max 5MB, keep 3 backups)
from logging.handlers import RotatingFileHandler
LOG_PATH = SCRIPT_DIR / CONFIG.get("log_file", "onyx_agent.log")
HEARTBEAT_PATH = SCRIPT_DIR / "onyx_heartbeat.txt"

log_handlers = []
try:
    log_handlers.append(RotatingFileHandler(str(LOG_PATH), maxBytes=5*1024*1024, backupCount=3, encoding="utf-8"))
except Exception:
    try:
        temp_log = Path(tempfile.gettempdir()) / "onyx_agent.log"
        log_handlers.append(RotatingFileHandler(str(temp_log), maxBytes=5*1024*1024, backupCount=3, encoding="utf-8"))
    except Exception:
        log_handlers.append(logging.StreamHandler(sys.stdout))

if "--verbose" in sys.argv:
    log_handlers.append(logging.StreamHandler(sys.stdout))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=log_handlers
)
log = logging.getLogger("EIQ")

def write_heartbeat():
    """Write heartbeat file so watchdog can verify agent is alive."""
    try:
        with open(str(HEARTBEAT_PATH), "w") as f:
            f.write(datetime.datetime.utcnow().isoformat())
    except Exception:
        pass

# ===========================================================================
# Generate stable Device ID
# ===========================================================================
def get_device_id():
    cfg_id = CONFIG.get("device_id", "auto")
    if cfg_id and cfg_id != "auto":
        return cfg_id
    hostname = socket.gethostname().lower().replace(" ", "-")
    h = hashlib.md5(hostname.encode()).hexdigest()[:6]
    return "eiq-" + hostname + "-" + h

DEVICE_ID = get_device_id()

# ===========================================================================
# Auto-Update from central server
# ===========================================================================
UPDATE_SERVER = CONFIG.get("update_server", "https://onyx-server-631753912632.us-central1.run.app")

def check_for_updates():
    """Check central server for agent updates and auto-apply if available."""
    try:
        import urllib.request, urllib.error, shutil

        agent_file = Path(__file__).resolve()
        with open(agent_file, "rb") as f:
            local_hash = hashlib.md5(f.read()).hexdigest()

        version_url = UPDATE_SERVER + "/api/agent-version"
        req = urllib.request.Request(version_url,
              headers={"User-Agent": "EIQ-Agent/" + CONFIG.get("version", "1.0")})
        with urllib.request.urlopen(req, timeout=10) as resp:
            version_data = json.loads(resp.read().decode("utf-8"))

        server_hash    = version_data.get("hash", "")
        server_version = version_data.get("version", "unknown")

        # Apply recommended interval from server if different
        recommended_interval = version_data.get("recommended_interval")
        if recommended_interval and recommended_interval != CONFIG.get("interval_seconds"):
            try:
                CONFIG["interval_seconds"] = recommended_interval
                with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                cfg["interval_seconds"] = recommended_interval
                with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                    json.dump(cfg, f, indent=4)
                log.info("[CONFIG] Interval updated to %ds from server", recommended_interval)
            except Exception as cfg_err:
                log.debug("[CONFIG] Could not update interval: %s", cfg_err)

        # Proteccion contra downgrade: no actualizar si version del servidor es menor
        def _ver_tuple(v):
            try: return tuple(int(x) for x in str(v).split("."))
            except: return (0, 0, 0)
        local_version = CONFIG.get("version", "3.0.0")
        if _ver_tuple(server_version) < _ver_tuple(local_version):
            log.info("[UPDATE] Server version %s < local %s — no downgrade", server_version, local_version)
            return False

        if not server_hash or server_hash == local_hash:
            log.info("[UPDATE] Agent is up to date (v%s)", CONFIG.get("version", "?"))
            return False

        log.info("[UPDATE] New version v%s available. Downloading...", server_version)

        download_url = UPDATE_SERVER + "/api/agent-download"
        req2 = urllib.request.Request(download_url, headers={"User-Agent": "EIQ-Agent/updater"})
        with urllib.request.urlopen(req2, timeout=30) as resp2:
            new_content = resp2.read()

        if hashlib.md5(new_content).hexdigest() != server_hash:
            log.warning("[UPDATE] Hash mismatch. Aborting update.")
            return False

        backup_path = agent_file.with_suffix(".py.bak")
        shutil.copy2(str(agent_file), str(backup_path))

        with open(agent_file, "wb") as f:
            f.write(new_content)

        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            cfg["version"] = server_version
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=4)
        except Exception:
            pass

        log.info("[UPDATE] Agent updated to v%s. Relanzando desde disco...", server_version)
        time.sleep(1)

        # Auto-reinicio: lanza el nuevo agente desde disco y sale
        # Esto garantiza continuidad SIN depender de la tarea programada
        try:
            python_exe = sys.executable
            agent_args  = [python_exe, str(agent_file)] + sys.argv[1:]
            # CREATE_NO_WINDOW + DETACHED_PROCESS para que corra en segundo plano
            import subprocess as _sp
            _sp.Popen(
                agent_args,
                creationflags=0x00000008 | 0x08000000,  # DETACHED + NO_WINDOW
                close_fds=True
            )
            log.info("[UPDATE] Nuevo agente lanzado. Saliendo proceso anterior.")
        except Exception as restart_err:
            log.warning("[UPDATE] No se pudo relanzar automaticamente: %s", restart_err)

        sys.exit(0)
        return True

    except Exception as e:
        log.debug("[UPDATE] Update check skipped: %s", e)
        return False

# ===========================================================================
# SQLite Buffer (offline mode)
# ===========================================================================
def init_db():
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS metrics_buffer (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            table_name TEXT    NOT NULL,
            payload    TEXT    NOT NULL,
            created_at TEXT    NOT NULL,
            synced     INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    return conn

def buffer_insert(conn, table_name, payload_dict):
    c = conn.cursor()
    now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
    c.execute(
        "INSERT INTO metrics_buffer (table_name, payload, created_at) VALUES (?, ?, ?)",
        (table_name, json.dumps(payload_dict, default=str), now_str)
    )
    conn.commit()
    log.info("[OFFLINE] Record buffered locally (table: %s)", table_name)

def get_pending_count(conn):
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM metrics_buffer WHERE synced = 0")
    return c.fetchone()[0]

def get_pending_records(conn, limit=50):
    c = conn.cursor()
    c.execute("SELECT id, table_name, payload FROM metrics_buffer WHERE synced=0 ORDER BY id LIMIT ?", (limit,))
    return c.fetchall()

def mark_synced(conn, ids):
    if not ids:
        return
    placeholders = ",".join(["?" for _ in ids])
    c = conn.cursor()
    c.execute("UPDATE metrics_buffer SET synced=1 WHERE id IN (" + placeholders + ")", ids)
    conn.commit()

def cleanup_old_records(conn, max_records):
    c = conn.cursor()
    c.execute("DELETE FROM metrics_buffer WHERE synced=1")
    c.execute("SELECT COUNT(*) FROM metrics_buffer")
    total = c.fetchone()[0]
    if total > max_records:
        excess = total - max_records
        c.execute("DELETE FROM metrics_buffer WHERE id IN (SELECT id FROM metrics_buffer ORDER BY id LIMIT ?)", (excess,))
    conn.commit()

# ===========================================================================
# GCP Credentials setup
# ===========================================================================
def setup_credentials():
    creds_file = SCRIPT_DIR / CONFIG.get("credentials_file", "onyx_credentials.json")
    if creds_file.exists():
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(creds_file)

setup_credentials()

# ===========================================================================
# Credential Auto-Rotation
# Detects invalid_grant / revoked key errors and downloads fresh credentials
# from the central server automatically — no manual action needed.
# ===========================================================================
_cred_refresh_cooldown = 0  # epoch seconds, prevents hammering the server

def try_rotate_credentials():
    """
    Downloads fresh onyx_credentials.json from the update server.
    Called automatically when Pub/Sub or BQ returns invalid_grant.
    Uses a 10-minute cooldown to avoid hammering the server.
    """
    global _pubsub_publisher, _bq_client, _cred_refresh_cooldown

    now = time.time()
    if now - _cred_refresh_cooldown < 600:  # 10-minute cooldown
        log.debug("[CREDS] Rotation cooldown active, skipping.")
        return False

    log.warning("[CREDS] Detected invalid credentials. Attempting auto-rotation...")
    _cred_refresh_cooldown = now

    try:
        import urllib.request
        server  = CONFIG.get("update_server", "https://proy-anla-poc-175647544738.us-central1.run.app")
        token   = CONFIG.get("credential_refresh_token", "eiq-cred-refresh-2024-onyx")
        url     = server + "/api/credentials-refresh"
        req     = urllib.request.Request(
            url,
            headers={"X-Refresh-Token": token, "User-Agent": "EIQ-Agent/" + CONFIG.get("version", "2.3")}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status != 200:
                log.error("[CREDS] Server returned %d", resp.status)
                return False
            new_creds = resp.read()

        # Validate it's a proper JSON service account key
        parsed = json.loads(new_creds.decode("utf-8"))
        if parsed.get("type") != "service_account":
            log.error("[CREDS] Response is not a valid service account key.")
            return False

        creds_path = SCRIPT_DIR / CONFIG.get("credentials_file", "onyx_credentials.json")
        # Backup old credentials
        if creds_path.exists():
            creds_path.rename(str(creds_path) + ".bak")

        with open(creds_path, "wb") as f:
            f.write(new_creds)

        # Reload credentials into environment and reset clients
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(creds_path)
        _pubsub_publisher = None  # force re-init on next publish
        _bq_client        = None  # force re-init on next query

        log.info("[CREDS] Credentials rotated successfully. Clients will re-initialize.")
        return True

    except Exception as e:
        log.error("[CREDS] Auto-rotation failed: %s", e)
        return False

def is_auth_error(exc):
    """Returns True if exception indicates expired/revoked credentials."""
    msg = str(exc).lower()
    return any(k in msg for k in ("invalid_grant", "invalid grant", "unauthorized",
                                   "revoked", "expired", "invalid jwt"))

# ===========================================================================
# Pub/Sub Publisher (PRIMARY send method)
# ===========================================================================
_pubsub_publisher = None

def get_pubsub_publisher():
    global _pubsub_publisher
    if _pubsub_publisher is not None:
        return _pubsub_publisher
    if not HAS_PUBSUB:
        return None
    try:
        _pubsub_publisher = pubsub_v1.PublisherClient()
        log.info("[PUBSUB] Publisher client initialized.")
        return _pubsub_publisher
    except Exception as e:
        log.warning("[PUBSUB] Could not initialize publisher: %s", e)
        return None

def pubsub_publish(payload_dict):
    """
    Publish a metrics payload to Pub/Sub topic.
    Returns True on success, False on failure.
    The server receives this via push subscription and inserts into BigQuery.
    Average latency: <20ms (vs 300-1500ms for direct BQ DML INSERT).
    """
    publisher = get_pubsub_publisher()
    if publisher is None:
        return False

    project_id = CONFIG.get("project_id", "proy-anla-poc")
    topic_id   = CONFIG.get("pubsub_topic", "onyx-metrics")
    topic_path = publisher.topic_path(project_id, topic_id)

    try:
        data = json.dumps(payload_dict, default=str).encode("utf-8")
        future = publisher.publish(
            topic_path,
            data,
            device_id=payload_dict.get("device_id", ""),
            table=payload_dict.get("_table", "eq_hardware_metrics")
        )
        msg_id = future.result(timeout=10)
        log.info("[PUBSUB] Message published (id: %s) to %s", msg_id, topic_id)
        return True
    except Exception as e:
        log.warning("[PUBSUB] Publish failed: %s", e)
        if is_auth_error(e):
            log.warning("[PUBSUB] Auth error detected — triggering credential rotation.")
            try_rotate_credentials()
        return False

# ===========================================================================
# BigQuery Client (FALLBACK send method)
# ===========================================================================
_bq_client = None

def get_bq_client(force_reset=False):
    global _bq_client
    if force_reset:
        _bq_client = None
    if _bq_client is not None:
        return _bq_client
    if not HAS_BQ:
        return None
    try:
        _bq_client = bigquery.Client(project=CONFIG.get("project_id", "proy-anla-poc"))
        log.info("[BQ] BigQuery client initialized (fallback mode).")
        return _bq_client
    except Exception as e:
        log.warning("[BQ] Could not initialize BigQuery: %s", e)
        return None

def bq_insert_row(table_name, row_dict, retries=3):
    """
    Direct DML INSERT into BigQuery — used as fallback when Pub/Sub is unavailable.
    Skips None values to avoid schema errors for new optional fields.
    """
    dataset    = CONFIG.get("dataset", "onyx")
    full_table = dataset + "." + table_name

    cols, vals = [], []
    for k, v in row_dict.items():
        if v is None or k.startswith("_"):
            continue
        cols.append(k)
        if isinstance(v, bool):
            vals.append("TRUE" if v else "FALSE")
        elif isinstance(v, (int, float)):
            vals.append(str(v))
        else:
            vals.append("'" + str(v).replace("'", "\\'") + "'")

    if not cols:
        log.warning("[BQ] Nothing to insert for %s — all fields are None", table_name)
        return False

    query = "INSERT INTO `%s` (%s) VALUES (%s)" % (
        full_table, ", ".join(cols), ", ".join(vals)
    )

    for attempt in range(retries):
        client = get_bq_client(force_reset=(attempt > 0))
        if client is None:
            return False
        try:
            client.query(query).result()
            log.info("[BQ] Record inserted into %s.%s (fallback)", dataset, table_name)
            return True
        except Exception as e:
            log.warning("[BQ] Attempt %d/%d failed: %s", attempt + 1, retries, e)
            if is_auth_error(e):
                log.warning("[BQ] Auth error detected — triggering credential rotation.")
                try_rotate_credentials()
                break  # no point retrying with same bad creds
            if attempt < retries - 1:
                time.sleep(2 ** attempt)

    log.error("[BQ] All %d attempts failed for %s.", retries, table_name)
    return False

def bq_upsert_sync(sync_row):
    """MERGE into eq_sync_status — one row per device (fallback path)."""
    client = get_bq_client()
    if client is None:
        return False
    dataset    = CONFIG.get("dataset", "onyx")
    full_table = dataset + ".eq_sync_status"

    def sv(v):
        if v is None:
            return "NULL"
        elif isinstance(v, (int, float)):
            return str(v)
        return "'" + str(v).replace("'", "\\'") + "'"

    query = """
    MERGE `%s` T USING (SELECT %s AS device_id) S ON T.device_id = S.device_id
    WHEN MATCHED THEN
      UPDATE SET timestamp=%s, last_sync=%s, last_ip=%s, status=%s
    WHEN NOT MATCHED THEN
      INSERT (timestamp, device_id, last_sync, last_ip, status)
      VALUES (%s, %s, %s, %s, %s)
    """ % (
        full_table,
        sv(sync_row["device_id"]),
        sv(sync_row["timestamp"]), sv(sync_row["last_sync"]),
        sv(sync_row["last_ip"]),   sv(sync_row["status"]),
        sv(sync_row["timestamp"]), sv(sync_row["device_id"]),
        sv(sync_row["last_sync"]), sv(sync_row["last_ip"]),
        sv(sync_row["status"])
    )
    try:
        client.query(query).result()
        log.info("[BQ] Sync upserted for %s (fallback)", sync_row["device_id"])
        return True
    except Exception as e:
        log.warning("[BQ] Sync upsert failed: %s", e)
        return False

# ===========================================================================
# HTTP Send — PRIMARY method (no GCP credentials required on endpoint)
# ===========================================================================

# Contador para escanear la red solo cada N ciclos (no en cada ciclo)
_NETWORK_SCAN_EVERY   = 5  # ciclos (ej: si interval=300s → cada 25 min)
_network_scan_counter = _NETWORK_SCAN_EVERY - 1  # Escanear ya en el 1er ciclo

def scan_network():
    """
    Escanea la red local usando 'arp -a' (nativo Windows, sin dependencias).
    Devuelve lista de {ip, mac, hostname} de dispositivos descubiertos.
    """
    import re as _re
    devices = []
    try:
        result = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )
        for line in result.stdout.splitlines():
            # Línea típica: "  192.168.1.50    b8-27-eb-a1-b2-c3    dinámica"
            m = _re.search(
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2}[-:][0-9a-f]{2})',
                line, _re.IGNORECASE
            )
            if not m:
                continue
            ip  = m.group(1)
            mac = m.group(2).replace("-", ":").upper()
            # Filtrar broadcast y multicast
            if ip.endswith(".255") or ip.startswith("224.") or ip.startswith("239."):
                continue
            # Intentar resolver hostname (sin bloquear demasiado)
            hostname = ""
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass
            devices.append({"ip": ip, "mac": mac, "hostname": hostname})
    except Exception as e:
        log.debug("[NET-SCAN] Error: %s", e)
    return devices


def send_via_http(metrics_row, sync_row):
    """
    POST metrics + sync data directly to Cloud Run /api/agent-ingest.
    Uses only Python stdlib — no google-cloud SDK, no credentials file needed.
    Returns True if server confirmed 200 OK.
    """
    try:
        server = CONFIG.get("update_server",
                            "https://onyx-server-631753912632.us-central1.run.app")
        url    = server.rstrip("/") + "/api/agent-ingest"
        global _network_scan_counter
        _network_scan_counter += 1
        net_scan = []
        if _network_scan_counter >= _NETWORK_SCAN_EVERY:
            net_scan = scan_network()
            _network_scan_counter = 0
            log.info("[NET-SCAN] Detectados %d dispositivos en red", len(net_scan))

        if "agent_secret" in CONFIG and not CONFIG["agent_secret"] and not os.environ.get("ONYX_AGENT_SECRET"):
            log.warning("[HTTP-INGEST] No agent_secret configured — failing closed")
            return False
        agent_secret = CONFIG.get("agent_secret") or os.environ.get("ONYX_AGENT_SECRET") or "onyx-shared-secret-v350-2026"

        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        nonce = str(uuid.uuid4())
        canonical_body = json.dumps(
            {"metrics": metrics_row, "sync": sync_row, "network_scan": net_scan},
            sort_keys=True,
            separators=(',', ':'),
            default=str,
            ensure_ascii=False
        ).encode("utf-8")
        
        dev_id = str(metrics_row.get('device_id',''))
        sig_str = f"{ts}|{nonce}|{dev_id}|{canonical_body.decode('utf-8')}".encode("utf-8")
        signature = hmac.new(agent_secret.encode("utf-8"), sig_str, hashlib.sha256).hexdigest()

        req = _ur.Request(
            url,
            data=canonical_body,
            headers={
                "Content-Type":      "application/json",
                "Content-Length":    str(len(canonical_body)),
                "User-Agent":        "EIQ-Agent/" + CONFIG.get("version", "3.5.0"),
                "X-Device-Id":       metrics_row.get("device_id", ""),
                "X-Agent-Timestamp": ts,
                "X-Agent-Nonce":     nonce,
                "X-Agent-Signature": signature
            }
        )
        with _ur.urlopen(req, timeout=30) as resp:
            if resp.status == 200:
                log.info("[HTTP-INGEST] OK -> server accepted metrics for %s",
                         metrics_row.get("device_id", "?"))
                return True
            else:
                log.warning("[HTTP-INGEST] Server returned %d", resp.status)
    except Exception as e:
        log.warning("[HTTP-INGEST] Failed: %s", e)
    return False


# ===========================================================================
# Send metrics — HTTP first, Pub/Sub + BQ as fallbacks
# ===========================================================================
def send_metrics(metrics_row, sync_row):
    """
    Send order:
      1. HTTP POST to Cloud Run /api/agent-ingest  ← PRIMARY (no GCP creds needed)
      2. Pub/Sub                                   ← fallback (needs google-cloud-pubsub)
      3. BigQuery DML INSERT                        ← last resort (needs google-cloud-bigquery)
    Using HTTP as primary prevents the Google Cloud SDK from opening browser
    authentication dialogs on endpoint machines when credentials are missing.
    """
    # ── 1. HTTP (primary — always tried first) ──
    if send_via_http(metrics_row, sync_row):
        return True, True

    log.warning("[SEND] HTTP path failed — trying Pub/Sub fallback...")

    # Tag rows with destination table for Pub/Sub routing
    metrics_msg = dict(metrics_row)
    metrics_msg["_table"] = "eq_hardware_metrics"
    sync_msg = dict(sync_row)
    sync_msg["_table"] = "eq_sync_status"
    sync_msg["_merge"] = True

    m_ok = False
    s_ok = False

    # ── 2. Pub/Sub fallback ──
    if HAS_PUBSUB:
        log.info("[SEND] Trying Pub/Sub...")
        m_ok = pubsub_publish(metrics_msg)
        s_ok = pubsub_publish(sync_msg)

    # ── 3. BigQuery direct (last resort) ──
    if not m_ok or not s_ok:
        if not m_ok and HAS_BQ:
            m_ok = bq_insert_row("eq_hardware_metrics", metrics_row)
        if not s_ok and HAS_BQ:
            s_ok = bq_upsert_sync(sync_row)

    return m_ok, s_ok

# ===========================================================================
# Connectivity
# ===========================================================================
def check_internet():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except (socket.timeout, OSError):
        return False

def measure_latency():
    target = CONFIG.get("ping_target", "8.8.8.8")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        t0 = time.time()
        s.connect((target, 53))
        ms = (time.time() - t0) * 1000
        s.close()
        return round(ms, 1)
    except Exception:
        return -1.0

# ===========================================================================
# GPS Location — Windows Location Services
# ===========================================================================
def get_gps_location():
    """Get GPS coordinates from Windows Location Services.
    Returns {latitude, longitude, accuracy, location_enabled} or fallback."""
    result = {"latitude": None, "longitude": None, "accuracy": None, "location_enabled": None}
    if platform.system() != "Windows":
        return result
    try:
        import subprocess as _sub
        # Use PowerShell to query Windows Location API
        ps_script = r'''
try {
    Add-Type -AssemblyName System.Device
    $watcher = New-Object System.Device.Location.GeoCoordinateWatcher
    $watcher.Start()
    $timeout = 0
    while ($watcher.Status -ne 'Ready' -and $timeout -lt 15) {
        Start-Sleep -Milliseconds 500
        $timeout++
    }
    if ($watcher.Status -eq 'Ready') {
        $coord = $watcher.Position.Location
        if ($coord.Latitude -ne [Double]::NaN) {
            @{status='ok'; lat=$coord.Latitude; lon=$coord.Longitude; acc=$coord.HorizontalAccuracy} | ConvertTo-Json -Compress
        } else {
            @{status='no_fix'} | ConvertTo-Json -Compress
        }
    } else {
        @{status='disabled'; watcher_status=$watcher.Status.ToString()} | ConvertTo-Json -Compress
    }
    $watcher.Stop()
    $watcher.Dispose()
} catch {
    @{status='error'; msg=$_.Exception.Message} | ConvertTo-Json -Compress
}
'''
        r = _sub.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True, text=True, timeout=20,
            creationflags=0x08000000  # CREATE_NO_WINDOW
        )
        if r.stdout.strip():
            import json as _j
            data = _j.loads(r.stdout.strip())
            if data.get("status") == "ok":
                result["latitude"] = round(data["lat"], 6)
                result["longitude"] = round(data["lon"], 6)
                result["accuracy"] = round(data.get("acc", 0), 1)
                result["location_enabled"] = True
                log.info("[GPS] Location: %.6f, %.6f (accuracy: %.1fm)",
                         result["latitude"], result["longitude"], result["accuracy"])
            elif data.get("status") == "disabled":
                result["location_enabled"] = False
                log.warning("[GPS] Location Services DISABLED on this machine")
            else:
                result["location_enabled"] = True  # enabled but no fix
                log.info("[GPS] Location enabled but no fix: %s", data.get("status"))
    except Exception as e:
        log.debug("[GPS] Error getting location: %s", e)
    return result

# ===========================================================================
# Endpoint Security Status — ISO 27001 A.8.7, A.8.8, A.8.9, A.8.24
# ===========================================================================
def get_security_status():
    """Collect endpoint security posture for ISO 27001 compliance scoring."""
    result = {
        "antivirus_name": "",
        "antivirus_enabled": None,
        "antivirus_updated": None,
        "firewall_enabled": None,
        "bitlocker_enabled": None,
        "uac_enabled": None,
        "windows_update_pending": None,
        "last_update_installed": ""
    }
    if platform.system() != "Windows":
        return result
    try:
        import subprocess as _sub, json as _j
        _NW = 0x08000000

        # ── Antivirus (SecurityCenter2 WMI) ──
        try:
            r = _sub.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 'Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | '
                 'Select-Object displayName,productState | ConvertTo-Json -Compress'],
                capture_output=True, text=True, timeout=10, creationflags=_NW
            )
            if r.stdout.strip():
                av = _j.loads(r.stdout.strip())
                if isinstance(av, dict): av = [av]
                if av:
                    primary = av[0]
                    result["antivirus_name"] = primary.get("displayName", "")
                    ps = primary.get("productState", 0)
                    # productState bitmask: bits 12-8 = enabled, bits 4-0 = updated
                    result["antivirus_enabled"] = bool((ps >> 12) & 0x1)
                    result["antivirus_updated"] = not bool((ps >> 4) & 0x1)
                    log.info("[SEC] Antivirus: %s (enabled=%s, updated=%s)",
                             result['antivirus_name'], result['antivirus_enabled'], result['antivirus_updated'])
        except Exception as e:
            log.debug("[SEC] Antivirus check error: %s", e)

        # ── Firewall ──
        try:
            r = _sub.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 'Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress'],
                capture_output=True, text=True, timeout=8, creationflags=_NW
            )
            if r.stdout.strip():
                fw = _j.loads(r.stdout.strip())
                if isinstance(fw, dict): fw = [fw]
                result["firewall_enabled"] = all(p.get("Enabled", False) for p in fw)
                log.info("[SEC] Firewall: %s", result['firewall_enabled'])
        except Exception as e:
            log.debug("[SEC] Firewall check error: %s", e)

        # ── BitLocker ──
        try:
            r = _sub.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 '(Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue).ProtectionStatus'],
                capture_output=True, text=True, timeout=8, creationflags=_NW
            )
            out = r.stdout.strip().lower()
            if 'on' in out or out == '1':
                result["bitlocker_enabled"] = True
            elif 'off' in out or out == '0':
                result["bitlocker_enabled"] = False
            log.info("[SEC] BitLocker: %s", result['bitlocker_enabled'])
        except Exception as e:
            log.debug("[SEC] BitLocker check error: %s", e)

        # ── UAC ──
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')
            val, _ = winreg.QueryValueEx(key, 'EnableLUA')
            result["uac_enabled"] = bool(val)
            winreg.CloseKey(key)
            log.info("[SEC] UAC: %s", result['uac_enabled'])
        except Exception as e:
            log.debug("[SEC] UAC check error: %s", e)

        # ── Windows Update ──
        try:
            r = _sub.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 'try { $s = New-Object -ComObject Microsoft.Update.Session; '
                 '$u = $s.CreateUpdateSearcher(); '
                 '$r = $u.Search("IsInstalled=0 AND IsHidden=0"); '
                 '@{pending=$r.Updates.Count; '
                 'last_installed=(Get-HotFix | Sort-Object InstalledOn -Descending | '
                 'Select-Object -First 1).InstalledOn.ToString("yyyy-MM-dd")} '
                 '| ConvertTo-Json -Compress } catch { @{pending=-1;last_installed=""} | ConvertTo-Json -Compress }'],
                capture_output=True, text=True, timeout=30, creationflags=_NW
            )
            if r.stdout.strip():
                wu = _j.loads(r.stdout.strip())
                result["windows_update_pending"] = wu.get("pending", -1)
                result["last_update_installed"] = wu.get("last_installed", "")
                log.info("[SEC] Windows Update: %d pending, last=%s",
                         result['windows_update_pending'], result['last_update_installed'])
        except Exception as e:
            log.debug("[SEC] Windows Update check error: %s", e)

    except Exception as e:
        log.debug("[SEC] Security status error: %s", e)
    return result

# ===========================================================================
# DLP — Data Loss Prevention Monitoring (ISO 27001 A.8.12)
# ===========================================================================
def get_dlp_status():
    """Detect potential data exfiltration vectors."""
    result = {
        "cloud_sync_apps": [],
        "screen_capture_tools": [],
        "remote_access_tools": [],
        "usb_write_events": 0
    }
    if platform.system() != "Windows":
        return result
    try:
        import subprocess as _sub, json as _j
        _NW = 0x08000000

        # Cloud sync apps (personal = risk)
        cloud_apps = {
            "Dropbox": ["dropbox"],
            "Google Drive Personal": ["googledrivesync", "googledrivefs"],
            "MEGA": ["megasync"],
            "WeTransfer": ["wetransfer"],
            "pCloud": ["pcloud"],
            "Telegram Desktop": ["telegram"],
            "WhatsApp Desktop": ["whatsapp"],
        }
        remote_apps = {
            "TeamViewer": ["teamviewer"],
            "AnyDesk": ["anydesk"],
            "UltraVNC": ["ultravnc", "winvnc"],
            "Chrome Remote Desktop": ["remoting_host"],
        }
        capture_apps = {
            "OBS Studio": ["obs64", "obs32"],
            "ShareX": ["sharex"],
            "Lightshot": ["lightshot"],
            "Snagit": ["snagit"],
        }

        try:
            procs = {p.name().lower() for p in psutil.process_iter(['name'])}
        except Exception:
            procs = set()

        for app_name, proc_names in cloud_apps.items():
            if any(pn in procs for pn in proc_names):
                result["cloud_sync_apps"].append(app_name)
        for app_name, proc_names in remote_apps.items():
            if any(pn in procs for pn in proc_names):
                result["remote_access_tools"].append(app_name)
        for app_name, proc_names in capture_apps.items():
            if any(pn in procs for pn in proc_names):
                result["screen_capture_tools"].append(app_name)

        # USB write events from Windows Event Log (last hour)
        try:
            r = _sub.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 '(Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-DriverFrameworks-UserMode/Operational";'
                 'StartTime=(Get-Date).AddHours(-1)} -ErrorAction SilentlyContinue | '
                 'Where-Object {$_.Message -like "*USB*"}).Count'],
                capture_output=True, text=True, timeout=10, creationflags=_NW
            )
            cnt = r.stdout.strip()
            if cnt.isdigit():
                result["usb_write_events"] = int(cnt)
        except Exception:
            pass

        if result["cloud_sync_apps"]:
            log.info("[DLP] Cloud sync detected: %s", ', '.join(result['cloud_sync_apps']))
        if result["remote_access_tools"]:
            log.warning("[DLP] Remote access tools: %s", ', '.join(result['remote_access_tools']))

    except Exception as e:
        log.debug("[DLP] Error: %s", e)
    return result

# ===========================================================================
# Software Inventory (ISO 27001 A.8.9)
# ===========================================================================
def get_software_inventory():
    """Get installed software list with versions."""
    result = []
    if platform.system() != "Windows":
        return result
    try:
        import subprocess as _sub, json as _j
        _NW = 0x08000000
        r = _sub.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             'Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,'
             'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* '
             '-ErrorAction SilentlyContinue | '
             'Where-Object {$_.DisplayName -and $_.DisplayName.Trim() -ne ""} | '
             'Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | '
             'Sort-Object DisplayName | '
             'ConvertTo-Json -Compress'],
            capture_output=True, text=True, timeout=15, creationflags=_NW
        )
        if r.stdout.strip():
            sw = _j.loads(r.stdout.strip())
            if isinstance(sw, dict): sw = [sw]
            result = [{
                "name": s.get("DisplayName", ""),
                "version": s.get("DisplayVersion", ""),
                "publisher": s.get("Publisher", ""),
                "install_date": s.get("InstallDate", "")
            } for s in sw[:100]]  # Limit to 100 entries
            log.info("[SW] Found %d installed applications", len(result))
    except Exception as e:
        log.debug("[SW] Error: %s", e)
    return result

def _collect_disk_encryption():
    """
    Recolección multi-capa de BitLocker con Invariante Zero-Knowledge.
    Descarta proactivamente contraseñas o claves de recuperación.
    """
    volumes = []
    if platform.system() != "Windows":
        return volumes
    try:
        import subprocess as _sub
        _NW = 0x08000000
        cmd = [
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            "try { Get-BitLockerVolume | Select-Object MountPoint, ProtectionStatus, VolumeStatus, EncryptionPercentage | ForEach-Object { @{ drive_letter=$_.MountPoint; protection_status=$_.ProtectionStatus; conversion_status=$_.VolumeStatus; encryption_percentage=$_.EncryptionPercentage; encryption_method='XTS-AES 128' } } | ConvertTo-Json -Compress } catch { @() }"
        ]
        r = _sub.run(cmd, capture_output=True, text=True, timeout=6, creationflags=_NW)
        if r.returncode == 0 and r.stdout.strip():
            raw = json.loads(r.stdout.strip())
            if isinstance(raw, dict):
                raw = [raw]
            if isinstance(raw, list):
                for item in raw:
                    drive = str(item.get("drive_letter") or item.get("MountPoint") or "C:").upper().strip()
                    prot_val = item.get("protection_status") if item.get("protection_status") is not None else item.get("ProtectionStatus", 0)
                    conv_val = str(item.get("conversion_status") or item.get("VolumeStatus") or "Unknown")
                    pct_val = item.get("encryption_percentage") if item.get("encryption_percentage") is not None else item.get("EncryptionPercentage", 0.0)
                    meth_val = str(item.get("encryption_method") or item.get("EncryptionMethod") or "XTS-AES 128")
                    volumes.append({
                        "drive_letter": drive,
                        "protection_status": int(prot_val),
                        "conversion_status": conv_val,
                        "encryption_percentage": float(pct_val),
                        "encryption_method": meth_val
                    })
    except Exception:
        pass

    if not volumes:
        try:
            r = _sub.run(["manage-bde.exe", "-status", "C:"], capture_output=True, text=True, timeout=5, creationflags=_NW)
            if r.returncode == 0 and r.stdout:
                out = r.stdout
                prot = 1 if "Estado de protección: Activado" in out or "Protection Status: Protection On" in out else 0
                conv = "FullyEncrypted" if "Completamente cifrado" in out or "Fully Encrypted" in out else "FullyDecrypted"
                pct = 100.0 if prot == 1 else 0.0
                volumes.append({
                    "drive_letter": "C:",
                    "protection_status": prot,
                    "conversion_status": conv,
                    "encryption_percentage": pct,
                    "encryption_method": "XTS-AES 128"
                })
        except Exception:
            pass

    if not volumes:
        volumes.append({
            "drive_letter": "C:",
            "protection_status": 0,
            "conversion_status": "FullyDecrypted",
            "encryption_percentage": 0.0,
            "encryption_method": "None"
        })
    return volumes

# ===========================================================================
# Metrics Collection
# ===========================================================================
def collect_metrics():
    log.info("[COLLECT] Collecting metrics for %s...", DEVICE_ID)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    cpu_pct  = psutil.cpu_percent(interval=2)
    mem      = psutil.virtual_memory()
    ram_pct  = round(mem.percent, 2)

    if platform.system() == "Windows":
        disk = psutil.disk_usage("C:\\")
    else:
        disk = psutil.disk_usage("/")
    disk_free_gb = round(disk.free / (1024 ** 3), 2)

    battery = psutil.sensors_battery()
    if battery:
        battery_pct    = round(battery.percent, 1)
        battery_status = "Full" if battery_pct >= 99 else ("Charging" if battery.power_plugged else "Discharging")
        device_type    = "Laptop"
    else:
        battery_pct    = None
        battery_status = "N/A"
        device_type    = "Desktop"

    latency = measure_latency()

    # Idle time — Windows GetLastInputInfo
    idle_seconds = None
    try:
        if platform.system() == "Windows":
            import ctypes
            class LASTINPUTINFO(ctypes.Structure):
                _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]
            lii = LASTINPUTINFO()
            lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
            if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):
                idle_millis  = ctypes.windll.kernel32.GetTickCount() - lii.dwTime
                idle_seconds = max(0, idle_millis // 1000)
    except Exception as e:
        log.debug("[COLLECT] Idle time unavailable: %s", e)

    # Top 5 processes by CPU + RAM
    top_processes = []
    try:
        all_procs = []
        for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
            try:
                info = p.info
                name = info.get("name", "")
                if name and name not in ("System Idle Process", "Idle", ""):
                    all_procs.append({
                        "name": info["name"],
                        "pid":  info["pid"],
                        "cpu":  round(info.get("cpu_percent", 0) or 0, 1),
                        "mem":  round(info.get("memory_percent", 0) or 0, 1)
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        all_procs.sort(key=lambda x: x["cpu"] + x["mem"], reverse=True)
        top_processes = all_procs[:5]

        top_cpu_total = sum(p["cpu"] for p in top_processes)
        top_mem_total = sum(p["mem"] for p in top_processes)
        top_processes.append({
            "name": "Sistema + Otros",
            "pid":  0,
            "cpu":  round(max(0, cpu_pct - top_cpu_total), 1),
            "mem":  round(max(0, ram_pct - top_mem_total), 1)
        })
    except Exception as e:
        log.warning("[COLLECT] Process list error: %s", e)

    top_processes_json = json.dumps(top_processes, ensure_ascii=True)

    # Root cause detection
    cause_root = cause_process = None
    if cpu_pct > 80:
        cause_root = "High CPU usage"
        top = top_processes[0] if top_processes else None
        cause_process = ("%s (PID:%s CPU:%.1f%%)" % (top["name"], top["pid"], top["cpu"])) if top else "Unknown"
    elif ram_pct > 85:
        cause_root = "High RAM usage"
        top = max(top_processes[:-1], key=lambda x: x["mem"]) if len(top_processes) > 1 else None
        cause_process = ("%s (PID:%s MEM:%.1f%%)" % (top["name"], top["pid"], top["mem"])) if top else "Unknown"
    elif disk_free_gb < 10:
        cause_root    = "Low disk space"
        cause_process = "Free disk: %.2f GB" % disk_free_gb

    # Local IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"

    # ── Extended Metrics — run in thread with hard timeout ─────────────────
    # All subprocess/network calls run in a separate thread to prevent
    # blocking the main collection loop if any call hangs.
    def _collect_extended():
        ext = {"usb": None, "events": None, "downloads": None,
               "browser": None, "network": None}
        try:
            import subprocess as _sub, json as _j, os as _os

            # ── USB (PowerShell — compatible PS 5.1+) ──────────────────────
            try:
                r = _sub.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                     "Get-PnpDevice -Class USB |"
                     "Where-Object {$_.Status -eq 'OK' -and $_.FriendlyName} |"
                     "Select-Object FriendlyName,InstanceId |"
                     "ConvertTo-Json -Compress"],
                    capture_output=True, text=True, timeout=8,
                    creationflags=0x08000000  # CREATE_NO_WINDOW — never show console to users
                )
                if r.stdout.strip():
                    raw = _j.loads(r.stdout.strip())
                    if isinstance(raw, dict): raw = [raw]
                    def _usb_category(name):
                        nl = name.lower()
                        if any(k in nl for k in ["keyboard","teclado","kbd"]): return "Teclado"
                        if any(k in nl for k in ["mouse","ratón","raton","pointing"]): return "Mouse"
                        if any(k in nl for k in ["mass storage","flash","disk","almacenamiento","storage","pendrive","thumb"]): return "Almacenamiento"
                        if any(k in nl for k in ["camera","cámara","camara","webcam","imaging"]): return "Camara"
                        if any(k in nl for k in ["audio","headset","speaker","headphone","sound","altavoz"]): return "Audio"  # 'mic' omitted — matches 'microsoft'
                        if any(k in nl for k in ["bluetooth","bt "]): return "Bluetooth"
                        if any(k in nl for k in ["printer","impresora","print"]): return "Impresora"
                        if any(k in nl for k in ["phone","móvil","movil","android","iphone","smartphone"]): return "Telefono"
                        if any(k in nl for k in ["hub","concentrador"]): return "Hub"
                        if any(k in nl for k in ["host controller","controlador de host","xhci","ehci","uhci","ohci"]): return "Controlador"
                        if any(k in nl for k in ["composite","compuesto"]): return "Periferico"
                        return "Periferico"

                    def _usb_port_type(name):
                        nl = name.lower()
                        if any(k in nl for k in ["usb-c","type-c","typec","thunderbolt","3.2 gen 2x2","3.20"]): return "USB-C"
                        return "USB-A"

                    SKIP = ("Raíz","raiz","ROOT")
                    usb_list = []
                    for d in raw[:20]:
                        nm = (d.get("FriendlyName") or "").strip()
                        if nm and not any(s.lower() in nm.lower() for s in SKIP):
                            # Note: InstanceId omitted — contains backslashes (PCI\VEN_...) that
                            # break JSON double-serialization through BigQuery STRING columns.
                            usb_list.append({
                                "name": nm,
                                "status": "Conectado",
                                "category": _usb_category(nm),
                                "port_type": _usb_port_type(nm)
                            })
                    if usb_list:
                        ext["usb"] = _j.dumps(usb_list, ensure_ascii=True)
            except Exception as ex:
                log.debug("[COLLECT] USB: %s", ex)

            # ── Event Logs (Get-EventLog — compatible PS 5.1+) ───────────────
            try:
                import re as _re
                r = _sub.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                     "Get-EventLog -LogName System -Newest 15 -EntryType Error,Warning "
                     "-EA SilentlyContinue | "
                     "Select-Object TimeGenerated,EventID,EntryType,Source,"
                     "@{N='Msg';E={($_.Message -replace '[\\r\\n\\t]+',' ').Substring(0,[Math]::Min(150,$_.Message.Length))}} | "
                     "ConvertTo-Json -Compress; "
                     "Get-EventLog -LogName Application -Newest 10 -EntryType Error,Warning "
                     "-EA SilentlyContinue | "
                     "Select-Object TimeGenerated,EventID,EntryType,Source,"
                     "@{N='Msg';E={($_.Message -replace '[\\r\\n\\t]+',' ').Substring(0,[Math]::Min(150,$_.Message.Length))}} | "
                     "ConvertTo-Json -Compress"],
                    capture_output=True, text=True, timeout=12,
                    creationflags=0x08000000  # CREATE_NO_WINDOW — never show console to users
                )
                ev_list = []
                # Parse two JSON blocks (System + Application)
                for block in r.stdout.strip().split("\n") if r.stdout.strip() else []:
                    block = block.strip()
                    if not block or not block.startswith(("[","{")):
                        continue
                    try:
                        chunk = _j.loads(block)
                        if isinstance(chunk, dict): chunk = [chunk]
                        for e in chunk[:15]:
                            # TimeGenerated comes as /Date(ms)/ or ISO string
                            tg = str(e.get("TimeGenerated","") or "")
                            ms_match = _re.search(r'Date\((\d+)\)', tg)
                            if ms_match:
                                import datetime as _dt2
                                ts_str = str(_dt2.datetime.utcfromtimestamp(int(ms_match.group(1))/1000))[:19]
                            else:
                                ts_str = tg[:19]
                            sev_map = {"Error":"Error","Warning":"Advertencia","Information":"Información"}
                            sev = sev_map.get(str(e.get("EntryType","") or ""), "Info")
                            ev_list.append({
                                "time": ts_str,
                                "id": e.get("EventID", 0),
                                "severity": sev,
                                "source": (e.get("Source","") or "")[:40],
                                "message": (e.get("Msg","") or "")[:120],
                                "log": "System", "event_type": "general",
                                "category": "sistema"
                            })
                    except Exception: pass
                if ev_list:
                    ext["events"] = _j.dumps(ev_list[:25], ensure_ascii=True)
            except Exception as ex:
                log.debug("[COLLECT] Events: %s", ex)

            # ── Downloads ─────────────────────────────────────────────────
            try:
                dl = _os.path.join(_os.path.expanduser("~"), "Downloads")
                if _os.path.exists(dl):
                    import datetime as _dt
                    files = []
                    for f in _os.scandir(dl):
                        try:
                            st = f.stat()
                            files.append({"name": f.name[:60],
                                          "size_mb": round(st.st_size/1048576, 2),
                                          "modified": str(_dt.datetime.fromtimestamp(st.st_mtime))[:19]})
                        except Exception:
                            pass
                    files.sort(key=lambda x: x["modified"], reverse=True)
                    if files:
                        ext["downloads"] = _j.dumps(files[:20], ensure_ascii=True)
            except Exception as ex:
                log.debug("[COLLECT] Downloads: %s", ex)

            # ── Browser History ────────────────────────────────────────────
            try:
                import sqlite3, shutil, tempfile
                from urllib.parse import urlparse
                from collections import defaultdict
                import datetime as _dt

                local_app = _os.environ.get("LOCALAPPDATA", "")
                hist_paths = []
                for _, p in [
                    ("chrome", _os.path.join(local_app, "Google", "Chrome", "User Data", "Default", "History")),
                    ("edge",   _os.path.join(local_app, "Microsoft", "Edge", "User Data", "Default", "History")),
                ]:
                    if _os.path.exists(p): hist_paths.append(p)

                since_dt = _dt.datetime.utcnow() - _dt.timedelta(days=7)
                since_chrome = int((since_dt - _dt.datetime(1601,1,1)).total_seconds() * 1e6)
                dcounts = defaultdict(int)

                for hp in hist_paths:
                    try:
                        tmp = tempfile.mktemp(suffix=".db")
                        shutil.copy2(hp, tmp)
                        c3 = sqlite3.connect(tmp)
                        rows = c3.execute(
                            "SELECT url,visit_count FROM urls WHERE last_visit_time>? ORDER BY visit_count DESC LIMIT 150",
                            (since_chrome,)
                        ).fetchall()
                        c3.close()
                        _os.remove(tmp)
                        for url, cnt in rows:
                            try:
                                dom = urlparse(url).netloc.lower().replace("www.","")
                                if dom and "." in dom: dcounts[dom] += cnt
                            except Exception: pass
                    except Exception: pass

                if dcounts:
                    WK = ["github","office","sharepoint","teams","outlook","slack","zoom","notion","trello","stackoverflow","aws","azure","google.com"]
                    SC = ["facebook","instagram","twitter","tiktok","reddit","whatsapp","telegram","discord"]
                    MD = ["youtube","netflix","twitch","spotify","primevideo"]
                    CM = ["gmail","hotmail","yahoo","protonmail"]
                    def cat(d):
                        if any(w in d for w in WK): return "trabajo"
                        if any(w in d for w in SC): return "ocio"
                        if any(w in d for w in MD): return "ocio"
                        if any(w in d for w in CM): return "comunicacion"
                        return "navegacion"
                    bh = [{"domain":d,"visits":c,"category":cat(d)}
                          for d,c in sorted(dcounts.items(), key=lambda x:-x[1])[:15]]
                    ext["browser"] = _j.dumps(bh, ensure_ascii=True)
            except Exception as ex:
                log.debug("[COLLECT] Browser: %s", ex)

            # ── Network Info ───────────────────────────────────────────────
            try:
                import urllib.request as _ur
                nd = {"interfaces":[], "wifi_ssid":None, "connected_devices":[],
                      "public_ip":None, "city":None, "country":"CO"}

                # Interfaces via ipconfig /all (includes Description for VPN detection)
                ic = _sub.run(["ipconfig", "/all"], capture_output=True, text=True, timeout=6,
                              creationflags=0x08000000)
                iface = {}
                for ln in ic.stdout.splitlines():
                    ln = ln.strip()
                    low = ln.lower()
                    if ("adaptador" in low or "adapter" in low) and ":" in ln:
                        if iface and iface.get("ip"): nd["interfaces"].append(iface)
                        iface = {"name": ln.replace(":","").strip(),
                                 "type": "WiFi" if any(w in low for w in ["wi-fi","wifi","inalám","wireless"]) else "Ethernet",
                                 "ip": None}
                    elif any(k in low for k in ["ipv4","dirección ipv4","ipv4 address"]):
                        prt = ln.split(":")
                        if len(prt) > 1:
                            ip_v = prt[-1].strip().split("(")[0].strip()
                            if ip_v and not ip_v.startswith("127"): iface["ip"] = ip_v
                if iface and iface.get("ip"): nd["interfaces"].append(iface)

                # ── Deteccion de VPN por nombre de adaptador O descripcion ──
                VPN_ADAPTER_KEYWORDS = [
                    "vpn", "tap", "tun", "wireguard", "wg",
                    "nordvpn", "expressvpn", "surfshark", "protonvpn", "mullvad",
                    "cyberghost", "ipvanish", "tunnelbear", "purevpn", "windscribe",
                    "cisco anyconnect", "anyconnect", "pulse secure", "globalprotect",
                    "juniper", "fortinet", "sonicwall", "openvpn", "pptp", "l2tp",
                    "sstp", "ikev2", "virtual private", "ppp adapter",
                    "check point", "checkpoint", "forticlient",
                    "fortinet ssl", "fortinet virtual"
                ]
                vpn_active  = False
                vpn_adapter = None
                # Escanear TODO el output de ipconfig: nombres de adaptador Y descripciones
                # Un adaptador VPN activo tiene IP asignada (no "medios desconectados")
                lines_ipconfig = ic.stdout.splitlines()
                current_adapter_name = None
                current_has_ip = False
                current_is_vpn = False
                for idx2, ln2 in enumerate(lines_ipconfig):
                    low2 = ln2.strip().lower()
                    # Detectar linea de nombre de adaptador
                    if ("adaptador" in low2 or "adapter" in low2) and ":" in ln2:
                        # Antes de resetear, verificar si el adaptador anterior era VPN con IP
                        if current_is_vpn and current_has_ip and current_adapter_name:
                            vpn_active = True
                            vpn_adapter = current_adapter_name
                        # Resetear para nuevo adaptador
                        current_adapter_name = ln2.strip().rstrip(":")
                        current_has_ip = False
                        current_is_vpn = any(k in low2 for k in VPN_ADAPTER_KEYWORDS)
                    # Detectar linea de Descripcion (contiene el nombre real del driver)
                    elif ("descripci" in low2 or "description" in low2) and ":" in ln2:
                        desc_val = ln2.split(":", 1)[-1].strip()
                        if any(k in desc_val.lower() for k in VPN_ADAPTER_KEYWORDS):
                            current_is_vpn = True
                            # Guardar nombre descriptivo: "Adaptador (Descripcion)"
                            if current_adapter_name:
                                current_adapter_name = current_adapter_name + " (" + desc_val + ")"
                    # Detectar si tiene IP asignada (no desconectado)
                    elif any(k in low2 for k in ["ipv4", "dirección ipv4", "ipv4 address"]):
                        ip_part = ln2.split(":")[-1].strip().split("(")[0].strip()
                        if ip_part and not ip_part.startswith("127"):
                            current_has_ip = True
                    # Detectar "medios desconectados" = no activo
                    elif "medios desconectados" in low2 or "media disconnected" in low2:
                        current_has_ip = False
                        current_is_vpn = False  # desconectado = no activo
                # Verificar el ultimo adaptador
                if current_is_vpn and current_has_ip and current_adapter_name:
                    vpn_active = True
                    vpn_adapter = current_adapter_name
                nd["vpn_active"]  = vpn_active
                nd["vpn_adapter"] = vpn_adapter

                try:
                    wo = _sub.run(["netsh","wlan","show","interfaces"],
                                  capture_output=True, text=True, timeout=4,
                                  creationflags=0x08000000).stdout
                    for wl in wo.splitlines():
                        if "SSID" in wl and "BSSID" not in wl:
                            ssid = wl.split(":",1)[-1].strip()
                            if ssid: nd["wifi_ssid"] = ssid; break
                except Exception: pass

                # ARP
                try:
                    import re as _re
                    ao = _sub.run(["arp","-a"], capture_output=True, text=True, timeout=4,
                                  creationflags=0x08000000).stdout
                    for al in ao.splitlines():
                        m = _re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([\w-]{2}(?:[:-][\w-]{2}){5})", al)
                        if m:
                            ia,ma = m.group(1), m.group(2)
                            if not ia.endswith((".255",".0")):
                                nd["connected_devices"].append({"ip":ia,"mac":ma,"type":"dynamic"})
                    nd["connected_devices"] = nd["connected_devices"][:15]
                except Exception: pass

                # Public IP + City (short timeout)
                try:
                    import socket as _sock
                    _sock.setdefaulttimeout(3)
                    resp = _ur.urlopen("https://ipinfo.io/json", timeout=3)
                    gd = _j.loads(resp.read().decode())
                    nd["public_ip"] = gd.get("ip","")
                    nd["city"]      = gd.get("city","")
                    nd["country"]   = gd.get("country","CO")
                    nd["region"]    = gd.get("region","")
                except Exception: pass

                if nd["interfaces"] or nd["public_ip"]:
                    ext["network"] = _j.dumps(nd, ensure_ascii=True)
            except Exception as ex:
                log.debug("[COLLECT] Network: %s", ex)

        except Exception as e:
            log.debug("[COLLECT] Extended block error: %s", e)
        return ext

    # Run all extended collection with a hard 25-second timeout
    import concurrent.futures as _cf
    usb_ports_json = event_logs_json = downloads_json = browser_history_json = network_info_json = None
    try:
        with _cf.ThreadPoolExecutor(max_workers=1) as _pool:
            _fut = _pool.submit(_collect_extended)
            _ext = _fut.result(timeout=25)
        usb_ports_json      = _ext.get("usb")
        event_logs_json     = _ext.get("events")
        downloads_json      = _ext.get("downloads")
        browser_history_json= _ext.get("browser")
        network_info_json   = _ext.get("network")
        log.debug("[COLLECT] Extended: usb=%s events=%s browser=%s net=%s",
                  "OK" if usb_ports_json else "-",
                  "OK" if event_logs_json else "-",
                  "OK" if browser_history_json else "-",
                  "OK" if network_info_json else "-")
    except _cf.TimeoutError:
        log.warning("[COLLECT] Extended metrics timed out after 25s — skipping")
    except Exception as e:
        log.debug("[COLLECT] Extended metrics failed: %s", e)

    # ── GPS Location ──────────────────────────────────────────────────────
    gps_data = get_gps_location()
    security_status = get_security_status()
    dlp_status = get_dlp_status()
    software_inventory = get_software_inventory()

    metrics_row = {
        "timestamp":          now,
        "device_id":          DEVICE_ID,
        "cpu_usage":          round(cpu_pct, 2),
        "ram_usage":          ram_pct,
        "disk_free_gb":       disk_free_gb,
        "network_latency_ms": latency if latency > 0 else None,
        "cause_root":         cause_root,
        "cause_process":      cause_process,
        "device_type":        device_type,
        "battery_percent":    battery_pct,
        "battery_status":     battery_status,
        "top_processes":      top_processes_json,
        "idle_seconds":       idle_seconds,
        "usb_ports":          usb_ports_json,
        "event_logs":         event_logs_json,
        "downloads_metadata": downloads_json,
        "browser_history":    browser_history_json,
        "network_info":       network_info_json,
        "gps_latitude":       gps_data.get("latitude"),
        "gps_longitude":      gps_data.get("longitude"),
        "gps_accuracy":       gps_data.get("accuracy"),
        "location_enabled":   gps_data.get("location_enabled"),
        "antivirus_name":        security_status.get("antivirus_name", ""),
        "antivirus_enabled":     security_status.get("antivirus_enabled"),
        "antivirus_updated":     security_status.get("antivirus_updated"),
        "firewall_enabled":      security_status.get("firewall_enabled"),
        "bitlocker_enabled":     security_status.get("bitlocker_enabled"),
        "disk_encryption":       json.dumps(_collect_disk_encryption()),
        "uac_enabled":           security_status.get("uac_enabled"),
        "windows_update_pending": security_status.get("windows_update_pending"),
        "last_update_installed": security_status.get("last_update_installed", ""),
        "dlp_cloud_sync":        json.dumps(dlp_status.get("cloud_sync_apps", [])),
        "dlp_remote_access":     json.dumps(dlp_status.get("remote_access_tools", [])),
        "dlp_screen_capture":    json.dumps(dlp_status.get("screen_capture_tools", [])),
        "dlp_usb_write_events":  str(dlp_status.get("usb_write_events", 0)),
        "software_inventory":    json.dumps(software_inventory[:50]),
    }


    # Extraer vpn_active desde network_info para incluirlo en sync
    _vpn_active  = False
    _vpn_adapter = None
    if network_info_json:
        try:
            _ni = _j.loads(network_info_json) if isinstance(network_info_json, str) else network_info_json
            _vpn_active  = _ni.get("vpn_active", False)
            _vpn_adapter = _ni.get("vpn_adapter", None)
        except Exception:
            pass

    sync_row = {
        "timestamp":   now,
        "device_id":   DEVICE_ID,
        "last_sync":   now,
        "last_ip":     local_ip,
        "status":      "Online",
        "vpn_active":  _vpn_active,
        "vpn_adapter": _vpn_adapter or ""
    }

    idle_str = f"{idle_seconds}s" if idle_seconds is not None else "N/A"
    log.info("[COLLECT] CPU:%.1f%% RAM:%.1f%% Disk:%.2fGB Latency:%.1fms Idle:%s",
             cpu_pct, ram_pct, disk_free_gb, latency, idle_str)

    return metrics_row, sync_row

# ===========================================================================
# Sync pending buffer to cloud
# ===========================================================================
def sync_pending(conn):
    """Flush buffered records to cloud when reconnected (Pub/Sub or BQ fallback)."""
    pending = get_pending_count(conn)
    if pending == 0:
        return
    log.info("[SYNC] %d buffered records — flushing...", pending)
    total_synced = 0
    while True:
        records    = get_pending_records(conn, limit=50)
        synced_ids = []
        if not records:
            break
        for rec_id, table_name, payload_json in records:
            try:
                payload = json.loads(payload_json)
                payload["_table"] = table_name
                ok = pubsub_publish(payload) if HAS_PUBSUB else bq_insert_row(table_name, payload, retries=2)
                if ok:
                    synced_ids.append(rec_id)
            except Exception as e:
                log.error("[SYNC] Error on record %d: %s", rec_id, e)
        if synced_ids:
            mark_synced(conn, synced_ids)
            total_synced += len(synced_ids)
        if len(synced_ids) < len(records):
            break
    log.info("[SYNC] Flushed %d records. %d remaining.", total_synced, get_pending_count(conn))

# ===========================================================================
# Main cycle
# ===========================================================================
def run_once():
    conn = init_db()
    try:
        if check_internet():
            check_for_updates()

        metrics_row, sync_row = collect_metrics()
        online = check_internet()

        if online:
            log.info("[MODE] Online — sending metrics via HTTP (primary)...")
            m_ok, s_ok = send_metrics(metrics_row, sync_row)

            if not m_ok:
                buffer_insert(conn, "eq_hardware_metrics", metrics_row)
            if not s_ok:
                buffer_insert(conn, "eq_sync_status", sync_row)

            sync_pending(conn)
        else:
            log.info("[MODE] Offline — buffering locally...")
            buffer_insert(conn, "eq_hardware_metrics", metrics_row)
            buffer_insert(conn, "eq_sync_status", sync_row)

        cleanup_old_records(conn, CONFIG.get("offline_buffer_max", 1000))
        log.info("[STATUS] Device:%s | Online:%s | Pending:%d",
                 DEVICE_ID, online, get_pending_count(conn))

    except Exception as e:
        log.error("[ERROR] Main cycle error: %s", e, exc_info=True)
    finally:
        conn.close()

def run_loop():
    interval           = CONFIG.get("interval_seconds", 300)
    consecutive_fails  = 0
    max_restarts       = 10
    restart_count      = 0
    log.info("[START] Onyx Agent v%s | Device: %s | Interval: %ds | Pub/Sub: %s",
             CONFIG.get("version", "?"), DEVICE_ID, interval,
             "enabled" if HAS_PUBSUB else "disabled (BQ fallback)")
    while True:
        try:
            write_heartbeat()
            run_once()
            consecutive_fails = 0
            restart_count = 0  # reset on success
        except Exception as e:
            consecutive_fails += 1
            log.error("[LOOP] Error #%d: %s", consecutive_fails, e, exc_info=True)
            if consecutive_fails >= 3:
                log.warning("[LOOP] Resetting clients after 3 consecutive failures...")
                try:
                    get_bq_client(force_reset=True)
                except Exception:
                    pass
                global _pubsub_publisher
                _pubsub_publisher = None
                consecutive_fails = 0
                restart_count += 1
                if restart_count >= max_restarts:
                    log.critical("[LOOP] %d restart cycles exhausted. Sleeping 10min then retrying...", max_restarts)
                    time.sleep(600)
                    restart_count = 0
        try:
            log.info("[WAIT] Next collection in %ds...", interval)
            time.sleep(interval)
        except Exception:
            time.sleep(60)  # fallback sleep on any error

# ===========================================================================
# Entry Point
# ===========================================================================
if __name__ == "__main__":
    import io
    if hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

    print("+------------------------------------------------+")
    print("|  Onyx Agent v%-8s                          |" % CONFIG.get("version", "3.5.0"))
    print("|  Device:  %-37s |" % DEVICE_ID)
    print("|  Pub/Sub: %-37s |" % ("Enabled" if HAS_PUBSUB else "Disabled (BQ fallback)"))
    print("+------------------------------------------------+")

    if "--once" in sys.argv:
        try:
            run_once()
        except Exception as e:
            log.critical("[FATAL] run_once crashed: %s", e, exc_info=True)
            sys.exit(1)
    else:
        # Global crash guard: if run_loop itself crashes, restart it
        while True:
            try:
                run_loop()
            except SystemExit:
                break  # Allow clean exit for updates
            except Exception as e:
                log.critical("[FATAL] run_loop crashed: %s — restarting in 30s...", e, exc_info=True)
                write_heartbeat()  # mark we're still alive
                time.sleep(30)
