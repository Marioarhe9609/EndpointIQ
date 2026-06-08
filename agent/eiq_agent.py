"""
EndpointIQ Agent v1.0.0
=======================
Monitoring agent for Windows that collects hardware metrics
and sends them to BigQuery. Works online and offline with SQLite buffer.

Usage: python eiq_agent.py [--once] [--verbose]
  --once    Run a single collection cycle (for Scheduled Task)
  --verbose Show detailed output in console

Metrics: CPU, RAM, Disk, Network, Battery, Top processes
Target: BigQuery dataset endpointiq (tables eq_hardware_metrics, eq_sync_status)
Offline: Local SQLite buffer in eiq_buffer.db
"""

import os
import sys
import json
import time
import socket
import sqlite3
import logging
import platform
import subprocess
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
DB_PATH = SCRIPT_DIR / "eiq_buffer.db"

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
        import urllib.request
        import urllib.error

        # Get current local file hash
        agent_file = Path(__file__).resolve()
        with open(agent_file, "rb") as f:
            local_hash = hashlib.md5(f.read()).hexdigest()

        # Check server version
        version_url = UPDATE_SERVER + "/api/agent-version"
        req = urllib.request.Request(version_url, headers={"User-Agent": "EIQ-Agent/" + CONFIG.get("version", "1.0")})
        with urllib.request.urlopen(req, timeout=10) as resp:
            version_data = json.loads(resp.read().decode("utf-8"))

        server_hash = version_data.get("hash", "")
        server_version = version_data.get("version", "unknown")

        if not server_hash or server_hash == local_hash:
            log.info("[UPDATE] Agent is up to date (v%s, hash: %s)", CONFIG.get("version", "?"), local_hash[:8])
            return False

        log.info("[UPDATE] New version available! Server: v%s (hash: %s), Local: v%s (hash: %s)",
                 server_version, server_hash[:8], CONFIG.get("version", "?"), local_hash[:8])

        # Download new agent
        download_url = UPDATE_SERVER + "/api/agent-download"
        req2 = urllib.request.Request(download_url, headers={"User-Agent": "EIQ-Agent/updater"})
        with urllib.request.urlopen(req2, timeout=30) as resp2:
            new_content = resp2.read()

        # Verify download integrity
        new_hash = hashlib.md5(new_content).hexdigest()
        if new_hash != server_hash:
            log.warning("[UPDATE] Download hash mismatch. Aborting update.")
            return False

        # Backup current agent
        backup_path = agent_file.with_suffix(".py.bak")
        try:
            import shutil
            shutil.copy2(str(agent_file), str(backup_path))
            log.info("[UPDATE] Backup saved: %s", backup_path)
        except Exception as e:
            log.warning("[UPDATE] Backup failed: %s", e)

        # Write new agent
        with open(agent_file, "wb") as f:
            f.write(new_content)

        # Update config version
        try:
            config_data = {}
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                config_data = json.load(f)
            config_data["version"] = server_version
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(config_data, f, indent=4)
        except Exception:
            pass

        log.info("[UPDATE] Agent updated to v%s. Changes take effect on next run.", server_version)
        return True

    except urllib.error.URLError as e:
        log.info("[UPDATE] Server unreachable (offline mode): %s", e.reason if hasattr(e, 'reason') else e)
        return False
    except Exception as e:
        log.info("[UPDATE] Update check skipped: %s", e)
        return False

# ===========================================================================
# SQLite Buffer (offline mode)
# ===========================================================================
def init_db():
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS metrics_buffer (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            table_name TEXT NOT NULL,
            payload TEXT NOT NULL,
            created_at TEXT NOT NULL,
            synced INTEGER DEFAULT 0
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
    log.info("[OFFLINE] Record saved to local buffer (table: %s)", table_name)

def get_pending_count(conn):
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM metrics_buffer WHERE synced = 0")
    return c.fetchone()[0]

def get_pending_records(conn, limit=50):
    c = conn.cursor()
    c.execute("SELECT id, table_name, payload FROM metrics_buffer WHERE synced = 0 ORDER BY id LIMIT ?", (limit,))
    return c.fetchall()

def mark_synced(conn, ids):
    if not ids:
        return
    placeholders = ",".join(["?" for _ in ids])
    c = conn.cursor()
    c.execute("UPDATE metrics_buffer SET synced = 1 WHERE id IN (" + placeholders + ")", ids)
    conn.commit()

def cleanup_old_records(conn, max_records):
    c = conn.cursor()
    c.execute("DELETE FROM metrics_buffer WHERE synced = 1")
    c.execute("SELECT COUNT(*) FROM metrics_buffer")
    total = c.fetchone()[0]
    if total > max_records:
        excess = total - max_records
        c.execute("DELETE FROM metrics_buffer WHERE id IN (SELECT id FROM metrics_buffer ORDER BY id LIMIT ?)", (excess,))
    conn.commit()

# ===========================================================================
# BigQuery Client
# ===========================================================================
_bq_client = None

def get_bq_client():
    global _bq_client
    if _bq_client is not None:
        return _bq_client
    if not HAS_BQ:
        return None
    creds_file = SCRIPT_DIR / CONFIG.get("credentials_file", "eiq_credentials.json")
    if creds_file.exists():
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(creds_file)
    try:
        _bq_client = bigquery.Client(project=CONFIG.get("project_id", "endpointiq"))
        log.info("[BQ] BigQuery client initialized.")
        return _bq_client
    except Exception as e:
        log.warning("[BQ] Could not initialize BigQuery: %s", e)
        return None

def bq_insert_row(table_name, row_dict):
    client = get_bq_client()
    if client is None:
        return False
    dataset = CONFIG.get("dataset", "endpointiq")
    full_table = dataset + "." + table_name

    # Build column names and values for DML INSERT
    cols = []
    vals = []
    for k, v in row_dict.items():
        cols.append(k)
        if v is None:
            vals.append("NULL")
        elif isinstance(v, (int, float)):
            vals.append(str(v))
        else:
            safe_v = str(v).replace("'", "\\'")
            vals.append("'" + safe_v + "'")

    col_str = ", ".join(cols)
    val_str = ", ".join(vals)
    query = "INSERT INTO `%s` (%s) VALUES (%s)" % (full_table, col_str, val_str)

    try:
        job = client.query(query)
        job.result()  # Wait for completion
        log.info("[BQ] Record sent to %s.%s", dataset, table_name)
        return True
    except Exception as e:
        log.warning("[BQ] Failed to send to %s: %s", table_name, e)
        return False

def bq_upsert_sync(sync_row):
    """MERGE (upsert) into eq_sync_status to keep only 1 row per device."""
    client = get_bq_client()
    if client is None:
        return False
    dataset = CONFIG.get("dataset", "endpointiq")
    full_table = dataset + ".eq_sync_status"

    def safe_val(v):
        if v is None:
            return "NULL"
        elif isinstance(v, (int, float)):
            return str(v)
        else:
            return "'" + str(v).replace("'", "\\'") + "'"

    query = """
    MERGE `%s` T
    USING (SELECT %s AS device_id) S
    ON T.device_id = S.device_id
    WHEN MATCHED THEN
      UPDATE SET timestamp = %s, last_sync = %s, last_ip = %s, status = %s
    WHEN NOT MATCHED THEN
      INSERT (timestamp, device_id, last_sync, last_ip, status)
      VALUES (%s, %s, %s, %s, %s)
    """ % (
        full_table,
        safe_val(sync_row['device_id']),
        safe_val(sync_row['timestamp']),
        safe_val(sync_row['last_sync']),
        safe_val(sync_row['last_ip']),
        safe_val(sync_row['status']),
        safe_val(sync_row['timestamp']),
        safe_val(sync_row['device_id']),
        safe_val(sync_row['last_sync']),
        safe_val(sync_row['last_ip']),
        safe_val(sync_row['status'])
    )

    try:
        job = client.query(query)
        job.result()
        log.info("[BQ] Sync status upserted for %s", sync_row['device_id'])
        return True
    except Exception as e:
        log.warning("[BQ] Failed to upsert sync status: %s", e)
        return False

# ===========================================================================
# Connectivity Test
# ===========================================================================
def check_internet():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except (socket.timeout, OSError):
        return False

def measure_latency():
    """Mide latencia usando TCP socket puro - 0 ventanas, 0 subprocess."""
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
    log.info("[COLLECT] Collecting metrics for device %s...", DEVICE_ID)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # CPU
    cpu_pct = psutil.cpu_percent(interval=2)

    # RAM
    mem = psutil.virtual_memory()
    ram_pct = round(mem.percent, 2)

    # Disk
    if platform.system() == "Windows":
        disk = psutil.disk_usage("C:\\")
    else:
        disk = psutil.disk_usage("/")
    disk_free_gb = round(disk.free / (1024 ** 3), 2)

    # Battery
    battery = psutil.sensors_battery()
    if battery:
        battery_pct = round(battery.percent, 1)
        if battery.power_plugged:
            battery_status = "Full" if battery_pct >= 99 else "Charging"
        else:
            battery_status = "Discharging"
        device_type = "Laptop"
    else:
        battery_pct = None
        battery_status = "N/A"
        device_type = "Desktop"

    # Latency
    latency = measure_latency()

    # Top processes collection (top 5 by CPU + RAM)
    top_processes = []
    try:
        # Get fresh CPU percent for all processes
        all_procs = []
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                info = p.info
                name = info.get('name', '')
                if name and name not in ('System Idle Process', 'Idle', ''):
                    all_procs.append({
                        'name': info['name'],
                        'pid': info['pid'],
                        'cpu': round(info.get('cpu_percent', 0) or 0, 1),
                        'mem': round(info.get('memory_percent', 0) or 0, 1)
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # Sort by combined CPU + RAM score and take top 5
        all_procs.sort(key=lambda x: x['cpu'] + x['mem'], reverse=True)
        top_processes = all_procs[:5]

        # Calculate system/services/other usage
        top_cpu_total = sum(p['cpu'] for p in top_processes)
        top_mem_total = sum(p['mem'] for p in top_processes)
        remaining_cpu = max(0, cpu_pct - top_cpu_total)
        remaining_mem = max(0, ram_pct - top_mem_total)

        top_processes.append({
            'name': 'Sistema + Otros',
            'pid': 0,
            'cpu': round(remaining_cpu, 1),
            'mem': round(remaining_mem, 1)
        })
    except Exception as e:
        log.warning("[COLLECT] Error collecting processes: %s", e)
        top_processes = []

    top_processes_json = json.dumps(top_processes, ensure_ascii=True)

    # Root cause detection
    cause_root = None
    cause_process = None

    if cpu_pct > 80:
        cause_root = "High CPU usage"
        if top_processes and len(top_processes) > 1:
            top = top_processes[0]
            cause_process = "%s (PID:%s CPU:%.1f%%)" % (
                top['name'], top['pid'], top['cpu']
            )
        else:
            cause_process = "Unknown"
    elif ram_pct > 85:
        cause_root = "High RAM usage"
        if top_processes and len(top_processes) > 1:
            top = max(top_processes[:-1], key=lambda x: x['mem'])
            cause_process = "%s (PID:%s MEM:%.1f%%)" % (
                top['name'], top['pid'], top['mem']
            )
        else:
            cause_process = "Unknown"
    elif disk_free_gb < 10:
        cause_root = "Low disk space"
        cause_process = "Free disk: %.2f GB" % disk_free_gb

    # Local IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"

    # Build payloads
    metrics_row = {
        "timestamp": now,
        "device_id": DEVICE_ID,
        "cpu_usage": round(cpu_pct, 2),
        "ram_usage": ram_pct,
        "disk_free_gb": disk_free_gb,
        "network_latency_ms": latency if latency > 0 else None,
        "cause_root": cause_root,
        "cause_process": cause_process,
        "device_type": device_type,
        "battery_percent": battery_pct,
        "battery_status": battery_status,
        "top_processes": top_processes_json
    }

    sync_row = {
        "timestamp": now,
        "device_id": DEVICE_ID,
        "last_sync": now,
        "last_ip": local_ip,
        "status": "Online"
    }

    log.info("[COLLECT] CPU:%.1f%% RAM:%.1f%% Disk:%.2fGB Latency:%.1fms Battery:%s%%",
             cpu_pct, ram_pct, disk_free_gb, latency, battery_pct)
    log.info("[COLLECT] Top processes: %s", ", ".join(p['name'] for p in top_processes[:3]))

    return metrics_row, sync_row

# ===========================================================================
# Sync pending buffer
# ===========================================================================
def sync_pending(conn):
    pending = get_pending_count(conn)
    if pending == 0:
        return
    log.info("[SYNC] %d pending records in buffer. Syncing...", pending)
    records = get_pending_records(conn, limit=50)
    synced_ids = []
    for rec_id, table_name, payload_json in records:
        try:
            payload = json.loads(payload_json)
            success = bq_insert_row(table_name, payload)
            if success:
                synced_ids.append(rec_id)
        except Exception as e:
            log.error("[SYNC] Error syncing record %d: %s", rec_id, e)
    if synced_ids:
        mark_synced(conn, synced_ids)
        log.info("[SYNC] %d/%d records synced successfully.", len(synced_ids), len(records))

# ===========================================================================
# Main cycle
# ===========================================================================
def run_once():
    conn = init_db()
    try:
        # Check for auto-updates first (only when online)
        if check_internet():
            check_for_updates()

        metrics_row, sync_row = collect_metrics()
        online = check_internet()

        if online and HAS_BQ:
            log.info("[MODE] Online - Sending to BigQuery...")
            m_ok = bq_insert_row("eq_hardware_metrics", metrics_row)
            s_ok = bq_upsert_sync(sync_row)
            if not m_ok:
                buffer_insert(conn, "eq_hardware_metrics", metrics_row)
            if not s_ok:
                buffer_insert(conn, "eq_sync_status", sync_row)
            sync_pending(conn)
        else:
            log.info("[MODE] Offline - Saving to local buffer...")
            buffer_insert(conn, "eq_hardware_metrics", metrics_row)
            buffer_insert(conn, "eq_sync_status", sync_row)

        max_buf = CONFIG.get("offline_buffer_max", 1000)
        cleanup_old_records(conn, max_buf)

        pending = get_pending_count(conn)
        log.info("[STATUS] Device: %s | Online: %s | Pending: %d", DEVICE_ID, online, pending)

    except Exception as e:
        log.error("[ERROR] Main cycle error: %s", e, exc_info=True)
    finally:
        conn.close()

def run_loop():
    interval = CONFIG.get("interval_seconds", 300)
    log.info("[START] EndpointIQ Agent v%s started (interval: %ds)", CONFIG.get('version', '1.0'), interval)
    log.info("[START] Device ID: %s", DEVICE_ID)
    while True:
        try:
            run_once()
        except Exception as e:
            log.error("[LOOP] Error: %s", e, exc_info=True)
        log.info("[WAIT] Next collection in %d seconds...", interval)
        time.sleep(interval)

# ===========================================================================
# Entry Point
# ===========================================================================
if __name__ == "__main__":
    import io
    if hasattr(sys.stdout, 'buffer'):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

    print("+----------------------------------------------+")
    print("|  EndpointIQ Agent v%-8s                 |" % CONFIG.get('version', '1.0.0'))
    print("|  Device: %-35s |" % DEVICE_ID)
    bq_label = "Available" if HAS_BQ else "Not available"
    print("|  BigQuery: %-33s |" % bq_label)
    print("+----------------------------------------------+")

    if "--once" in sys.argv:
        run_once()
    else:
        run_loop()
