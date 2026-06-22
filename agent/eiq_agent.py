"""
Onyx Agent v2.3.0
=================
Monitoring agent for Windows. Sends metrics via Pub/Sub (primary) or
directly to BigQuery (fallback). Works offline with SQLite buffer.

Architecture:
  Online  → Pub/Sub Topic → Cloud Run /api/internal/ingest → BigQuery
  Fallback → BigQuery DML INSERT (direct, if Pub/Sub unavailable)
  Offline  → SQLite buffer → flush on reconnect

Usage: python eiq_agent.py [--once] [--verbose]
  --once    Run a single collection cycle
  --verbose Show detailed output in console

Metrics: CPU, RAM, Disk, Network latency, Battery, Top processes, Idle time
Target: Pub/Sub topic onyx-metrics → BigQuery endpointiq dataset
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
CONFIG_PATH = SCRIPT_DIR / "eiq_config.json"
DB_PATH     = SCRIPT_DIR / "eiq_buffer.db"

def load_config():
    if not CONFIG_PATH.exists():
        print("[ERROR] Config file not found: " + str(CONFIG_PATH))
        sys.exit(1)
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

CONFIG = load_config()

# Setup logging
LOG_PATH = SCRIPT_DIR / CONFIG.get("log_file", "eiq_agent.log")
log_handlers = [logging.FileHandler(LOG_PATH, encoding="utf-8")]
if "--verbose" in sys.argv:
    log_handlers.append(logging.StreamHandler(sys.stdout))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=log_handlers
)
log = logging.getLogger("EIQ")

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
UPDATE_SERVER = CONFIG.get("update_server", "https://endpointiq-175647544738.us-central1.run.app")

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

        log.info("[UPDATE] Agent updated to v%s. Restart to apply.", server_version)
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
    creds_file = SCRIPT_DIR / CONFIG.get("credentials_file", "eiq_credentials.json")
    if creds_file.exists():
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(creds_file)

setup_credentials()

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

    project_id = CONFIG.get("project_id", "endpointiq")
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
        _bq_client = bigquery.Client(project=CONFIG.get("project_id", "endpointiq"))
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
    dataset    = CONFIG.get("dataset", "endpointiq")
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
            if attempt < retries - 1:
                time.sleep(2 ** attempt)

    log.error("[BQ] All %d attempts failed for %s.", retries, table_name)
    return False

def bq_upsert_sync(sync_row):
    """MERGE into eq_sync_status — one row per device (fallback path)."""
    client = get_bq_client()
    if client is None:
        return False
    dataset    = CONFIG.get("dataset", "endpointiq")
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
# Send metrics — tries Pub/Sub first, falls back to BQ direct
# ===========================================================================
def send_metrics(metrics_row, sync_row):
    """
    Primary path: Pub/Sub (fast, decoupled, scalable to 100K+ devices)
    Fallback:     Direct BigQuery DML INSERT
    Returns:      (metrics_ok, sync_ok)
    """
    # Tag rows with destination table for Pub/Sub routing
    metrics_msg = dict(metrics_row)
    metrics_msg["_table"] = "eq_hardware_metrics"

    sync_msg = dict(sync_row)
    sync_msg["_table"] = "eq_sync_status"
    sync_msg["_merge"] = True   # tells the server to MERGE instead of INSERT

    m_ok = False
    s_ok = False

    if HAS_PUBSUB:
        log.info("[SEND] Trying Pub/Sub (primary)...")
        m_ok = pubsub_publish(metrics_msg)
        s_ok = pubsub_publish(sync_msg)

    if not m_ok or not s_ok:
        if HAS_PUBSUB:
            log.warning("[SEND] Pub/Sub failed — falling back to BigQuery direct.")
        else:
            log.info("[SEND] Pub/Sub unavailable — using BigQuery direct (fallback).")

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
        "idle_seconds":       idle_seconds
    }

    sync_row = {
        "timestamp":  now,
        "device_id":  DEVICE_ID,
        "last_sync":  now,
        "last_ip":    local_ip,
        "status":     "Online"
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

        if online and (HAS_PUBSUB or HAS_BQ):
            log.info("[MODE] Online — sending metrics...")
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
    log.info("[START] Onyx Agent v%s | Device: %s | Interval: %ds | Pub/Sub: %s",
             CONFIG.get("version", "?"), DEVICE_ID, interval,
             "enabled" if HAS_PUBSUB else "disabled (BQ fallback)")
    while True:
        try:
            run_once()
            consecutive_fails = 0
        except Exception as e:
            consecutive_fails += 1
            log.error("[LOOP] Error #%d: %s", consecutive_fails, e, exc_info=True)
            if consecutive_fails >= 3:
                log.warning("[LOOP] Resetting clients after 3 consecutive failures...")
                get_bq_client(force_reset=True)
                global _pubsub_publisher
                _pubsub_publisher = None
                consecutive_fails = 0
        log.info("[WAIT] Next collection in %ds...", interval)
        time.sleep(interval)

# ===========================================================================
# Entry Point
# ===========================================================================
if __name__ == "__main__":
    import io
    if hasattr(sys.stdout, "buffer"):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

    print("+------------------------------------------------+")
    print("|  Onyx Agent v%-8s                          |" % CONFIG.get("version", "2.3.0"))
    print("|  Device:  %-37s |" % DEVICE_ID)
    print("|  Pub/Sub: %-37s |" % ("Enabled" if HAS_PUBSUB else "Disabled (BQ fallback)"))
    print("+------------------------------------------------+")

    if "--once" in sys.argv:
        run_once()
    else:
        run_loop()
