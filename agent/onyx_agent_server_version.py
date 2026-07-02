"""
Onyx Agent v2.1.0
=================
Monitoring agent for Windows that collects hardware metrics
and sends them to BigQuery. Works online and offline with SQLite buffer.
Includes automatic reconnection with exponential backoff.

Usage: python onyx_agent.py [--once] [--verbose]
  --once    Run a single collection cycle (for Scheduled Task)
  --verbose Show detailed output in console
Monitoring agent for Windows that collects hardware metrics
and sends them to BigQuery. Works online and offline with SQLite buffer.

Usage: python onyx_agent.py [--once] [--verbose]
  --once    Run a single collection cycle (for Scheduled Task)
  --verbose Show detailed output in console

Metrics: CPU, RAM, Disk, Network, Battery, Top processes
Target: BigQuery dataset proy-anla-poc (tables eq_hardware_metrics, eq_sync_status)
Offline: Local SQLite buffer in onyx_buffer.db
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
CONFIG_PATH = SCRIPT_DIR / "onyx_config.json"
DB_PATH = SCRIPT_DIR / "onyx_buffer.db"

def load_config():
    if not CONFIG_PATH.exists():
        print("[ERROR] Config file not found: " + str(CONFIG_PATH))
        sys.exit(1)
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

CONFIG = load_config()

# Setup logging
LOG_PATH = SCRIPT_DIR / CONFIG.get("log_file", "onyx_agent.log")
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
UPDATE_SERVER = CONFIG.get("update_server", "https://proy-anla-poc-175647544738.us-central1.run.app")

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

def get_bq_client(force_reset=False):
    global _bq_client
    if force_reset:
        _bq_client = None
    if _bq_client is not None:
        return _bq_client
    if not HAS_BQ:
        return None
    creds_file = SCRIPT_DIR / CONFIG.get("credentials_file", "onyx_credentials.json")
    if creds_file.exists():
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(creds_file)
    try:
        _bq_client = bigquery.Client(project=CONFIG.get("project_id", "proy-anla-poc"))
        log.info("[BQ] BigQuery client initialized.")
        return _bq_client
    except Exception as e:
        log.warning("[BQ] Could not initialize BigQuery: %s", e)
        return None

def bq_insert_row(table_name, row_dict, retries=3):
    """Insert a row into BigQuery with retry and client reset on failure."""
    dataset = CONFIG.get("dataset", "proy-anla-poc")
    full_table = dataset + "." + table_name

    # Build column names and values for DML INSERT
    # Skip None values entirely — avoids errors for new/optional fields not yet in BQ schema
    cols = []
    vals = []
    for k, v in row_dict.items():
        if v is None:
            continue  # omit None fields — BQ will use column default (NULL)
        cols.append(k)
        if isinstance(v, (int, float)):
            vals.append(str(v))
        elif isinstance(v, bool):
            vals.append("TRUE" if v else "FALSE")
        else:
            safe_v = str(v).replace("'", "\\'")
            vals.append("'" + safe_v + "'")

    if not cols:
        log.warning("[BQ] Nothing to insert for %s — all fields are None", table_name)
        return False

    col_str = ", ".join(cols)
    val_str = ", ".join(vals)
    query = "INSERT INTO `%s` (%s) VALUES (%s)" % (full_table, col_str, val_str)

    for attempt in range(retries):
        client = get_bq_client(force_reset=(attempt > 0))  # reset client on retry
        if client is None:
            return False
        try:
            job = client.query(query)
            job.result()  # Wait for completion
            log.info("[BQ] Record sent to %s.%s", dataset, table_name)
            return True
        except Exception as e:
            log.warning("[BQ] Attempt %d/%d failed for %s: %s", attempt+1, retries, table_name, e)
            if attempt < retries - 1:
                wait = 2 ** attempt  # exponential backoff: 1s, 2s, 4s
                log.info("[BQ] Retrying in %ds...", wait)
                time.sleep(wait)
    log.error("[BQ] All %d attempts failed for %s. Saving to buffer.", retries, table_name)
    return False

def bq_upsert_sync(sync_row):
    """MERGE (upsert) into eq_sync_status to keep only 1 row per device."""
    client = get_bq_client()
    if client is None:
        return False
    dataset = CONFIG.get("dataset", "proy-anla-poc")
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
# USB Ports Collection
# ===========================================================================
def collect_usb_ports():
    """Detect connected USB devices via WMI/PowerShell with USB-C detection."""
    if not CONFIG.get("modules", {}).get("usb_monitoring", True): return []
    usb_devices = []
    try:
        if platform.system() != "Windows": return []
        import tempfile, os as _os

        # Step 1: Detect USB Type-C via UCSI and USB 3.20 controller mapping
        usbc_ids = set()
        try:
            # Write PS1 script for reliable execution (avoids subprocess quoting issues)
            ucm_script = (
                '$parents = @()\n'
                '$ucm = Get-PnpDevice -Class UCM -Status OK -ErrorAction SilentlyContinue\n'
                'if ($ucm) {\n'
                '  foreach ($u in $ucm) {\n'
                '    $p = (Get-PnpDeviceProperty -InstanceId $u.InstanceId -KeyName DEVPKEY_Device_Parent -ErrorAction SilentlyContinue).Data\n'
                '    if ($p) { $parents += $p }\n'
                '  }\n'
                '}\n'
                '# Check if UCSI device exists\n'
                '$ucsi = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -like "ACPI\\USBC*" }\n'
                'if ($ucsi) {\n'
                '  # Find USB 3.20 controllers and their root hubs\n'
                '  $ctrls = Get-CimInstance Win32_PnPEntity -Filter "PNPClass=\'USB\'" | Where-Object { $_.Name -match "USB 3\\.2" }\n'
                '  foreach ($c in $ctrls) {\n'
                '    $parents += $c.PNPDeviceID\n'
                '    $ch = (Get-PnpDeviceProperty -InstanceId $c.PNPDeviceID -KeyName DEVPKEY_Device_Children -ErrorAction SilentlyContinue).Data\n'
                '    if ($ch) { $parents += $ch }\n'
                '  }\n'
                '}\n'
                'if ($parents.Count -gt 0) { $parents | ConvertTo-Json -Compress } else { Write-Output "[]" }\n'
            )
            ps1_path = _os.path.join(tempfile.gettempdir(), "onyx_ucm.ps1")
            with open(ps1_path, "w") as f:
                f.write(ucm_script)
            ucm_r = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ps1_path],
                capture_output=True, text=True, timeout=12,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
            )
            if ucm_r.returncode == 0 and ucm_r.stdout.strip():
                ucm_list = json.loads(ucm_r.stdout.strip())
                if isinstance(ucm_list, str): ucm_list = [ucm_list]
                for pid in ucm_list:
                    if pid: usbc_ids.add(pid.upper())
                log.info("[USB] USB-C identifiers: %d found", len(usbc_ids))
            try: _os.remove(ps1_path)
            except: pass
        except Exception as e:
            log.debug("[USB] USB-C detection skipped: %s", e)

        # Step 2: Collect USB devices with parent + bus-reported description
        dev_script = (
            '$devs = Get-CimInstance Win32_PnPEntity -Filter "PNPClass=\'USB\'" | Select-Object Name, Manufacturer, Status, PNPDeviceID\n'
            '$result = @()\n'
            'foreach ($d in $devs) {\n'
            '  $busDesc = ""\n'
            '  try { $busDesc = (Get-PnpDeviceProperty -InstanceId $d.PNPDeviceID -KeyName DEVPKEY_Device_BusReportedDeviceDesc -ErrorAction SilentlyContinue).Data } catch {}\n'
            '  $parent = ""\n'
            '  try { $parent = (Get-PnpDeviceProperty -InstanceId $d.PNPDeviceID -KeyName DEVPKEY_Device_Parent -ErrorAction SilentlyContinue).Data } catch {}\n'
            '  $result += [PSCustomObject]@{\n'
            '    Name=$d.Name; Manufacturer=$d.Manufacturer; Status=$d.Status;\n'
            '    PNPDeviceID=$d.PNPDeviceID; BusDesc=$busDesc; Parent=$parent\n'
            '  }\n'
            '}\n'
            '$result | ConvertTo-Json -Compress\n'
        )
        ps1_dev = _os.path.join(tempfile.gettempdir(), "onyx_usb_devs.ps1")
        with open(ps1_dev, "w") as f:
            f.write(dev_script)
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ps1_dev],
            capture_output=True, text=True, timeout=15,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        )
        try: _os.remove(ps1_dev)
        except: pass

        if result.returncode == 0 and result.stdout.strip():
            parsed = json.loads(result.stdout.strip())
            if isinstance(parsed, dict): parsed = [parsed]

            def is_on_usbc_bus(pnp_id, parent_id):
                """Check if device is connected through a USB-C controller."""
                pnp_up = (pnp_id or "").upper()
                parent_up = (parent_id or "").upper()
                for ucid in usbc_ids:
                    if ucid == pnp_up or ucid == parent_up:
                        return True
                    if ucid in parent_up or ucid in pnp_up:
                        return True
                return False

            def classify_usb(name, pnp_id="", parent_id="", bus_desc=""):
                nl = (name or "").lower()
                bl = (bus_desc or "").lower()
                combined = nl + " " + bl

                # Determine category
                if any(k in combined for k in ["keyboard", "teclado"]): cat = "Teclado"
                elif any(k in combined for k in ["mouse", "pointing", "2.4g mouse"]): cat = "Mouse"
                elif any(k in combined for k in ["storage", "mass storage", "disk", "flash", "pendrive"]): cat = "Almacenamiento"
                elif any(k in combined for k in ["camera", "webcam", "integrated camera"]): cat = "Camara"
                elif any(k in combined for k in ["audio", "speaker", "headset", "microphone"]): cat = "Audio"
                elif "bluetooth" in combined: cat = "Bluetooth"
                elif any(k in combined for k in ["print", "impresora"]): cat = "Impresora"
                elif any(k in combined for k in ["phone", "android", "iphone", "samsung"]): cat = "Telefono"
                elif any(k in combined for k in ["hub", "concentrador", "root hub", "root_hub"]): cat = "Hub"
                elif any(k in combined for k in ["controller", "controlador", "host controller", "xhci"]): cat = "Controlador"
                else: cat = "Periferico"

                # Determine port type
                if any(k in combined for k in ["usb-c", "type-c", "type c", "thunderbolt", "ucsi"]):
                    return cat, "USB-C"
                if cat == "Telefono":
                    return cat, "USB-C"
                if is_on_usbc_bus(pnp_id, parent_id):
                    return cat, "USB-C"
                return cat, "USB-A"

            for dev in parsed:
                dn = dev.get("Name", "USB desconocido")
                pnp_id = dev.get("PNPDeviceID", "")
                parent_id = dev.get("Parent", "")
                bus_desc = dev.get("BusDesc", "")
                display_name = bus_desc if bus_desc and len(bus_desc) > 2 else dn
                cat, pt = classify_usb(dn, pnp_id, parent_id, bus_desc)
                sr = dev.get("Status", "OK")
                st = "Conectado" if sr == "OK" else ("Bloqueado" if sr in ("Error","Degraded") else "Desconectado")
                usb_devices.append({
                    "name": display_name, "port_type": pt, "category": cat,
                    "status": st, "manufacturer": dev.get("Manufacturer", "Desconocido")
                })
        log.info("[USB] Detected %d USB devices", len(usb_devices))
    except subprocess.TimeoutExpired: log.warning("[USB] Timed out")
    except Exception as e: log.warning("[USB] Failed: %s", e)
    return usb_devices

# ===========================================================================
# Downloads Metadata Collection
# ===========================================================================
_HR = {".exe",".msi",".bat",".ps1",".cmd",".vbs",".js",".scr",".com",".pif",".reg"}
_MR = {".zip",".rar",".7z",".tar",".gz",".iso",".img",".dll",".sys",".jar"}
_TM = {".pdf":"documento",".doc":"documento",".docx":"documento",".xls":"documento",".xlsx":"documento",
    ".ppt":"documento",".pptx":"documento",".txt":"documento",".csv":"documento",
    ".jpg":"imagen",".jpeg":"imagen",".png":"imagen",".gif":"imagen",".svg":"imagen",".webp":"imagen",
    ".mp4":"multimedia",".avi":"multimedia",".mkv":"multimedia",".mp3":"multimedia",".wav":"multimedia",
    ".exe":"ejecutable",".msi":"ejecutable",".bat":"ejecutable",
    ".zip":"comprimido",".rar":"comprimido",".7z":"comprimido",
    ".iso":"imagen_disco",".img":"imagen_disco"}

def collect_downloads_metadata():
    """Scan Downloads folder for recent files (last 24h)."""
    if not CONFIG.get("modules", {}).get("downloads_monitoring", True): return []
    downloads = []
    try:
        dd = Path(os.path.expanduser("~")) / "Downloads"
        if not dd.exists(): return []
        now = datetime.datetime.now()
        cutoff = now - datetime.timedelta(hours=24)
        ff = []
        for f in dd.iterdir():
            if not f.is_file(): continue
            try:
                s = f.stat(); mt = datetime.datetime.fromtimestamp(s.st_mtime); ct = datetime.datetime.fromtimestamp(s.st_ctime)
                if max(mt, ct) >= cutoff: ff.append((f, s, mt, ct))
            except: continue
        ff.sort(key=lambda x: max(x[2], x[3]), reverse=True)
        for f, s, mt, ct in ff[:20]:
            ext = f.suffix.lower()
            r = "high" if ext in _HR else ("medium" if ext in _MR else "low")
            downloads.append({"name": f.name, "ext": ext, "size_bytes": s.st_size, "type": _TM.get(ext, "otro"), "risk": r,
                "created": ct.strftime("%Y-%m-%dT%H:%M:%S"), "modified": mt.strftime("%Y-%m-%dT%H:%M:%S")})
        log.info("[DOWNLOADS] Found %d recent files (last 24h)", len(downloads))
    except Exception as e: log.warning("[DOWNLOADS] Failed: %s", e)
    return downloads

# ===========================================================================
# Windows Event Viewer Collection (Microsoft Services)
# ===========================================================================
def collect_event_logs():
    """Collect recent critical/error/warning events from Windows Event Viewer."""
    if not CONFIG.get("modules", {}).get("event_logs", True): return []
    event_logs_data = []
    try:
        if platform.system() != "Windows": return []
        ps_event_cmd = """
$events = @()
$logNames = @('System','Application','Security')
foreach ($logName in $logNames) {
    try {
        $evts = Get-WinEvent -FilterHashtable @{LogName=$logName; Level=1,2,3; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 10 -ErrorAction SilentlyContinue
        if ($evts) {
            foreach ($e in $evts) {
                $msg = if ($e.Message) { $e.Message.Substring(0, [Math]::Min(200, $e.Message.Length)) } else { '' }
                $events += [PSCustomObject]@{
                    log = $logName
                    id = $e.Id
                    level = $e.Level
                    levelName = $e.LevelDisplayName
                    source = $e.ProviderName
                    message = $msg
                    time = $e.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss')
                }
            }
        }
    } catch {}
}
$events | ConvertTo-Json -Compress
"""
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_event_cmd],
            capture_output=True, text=True, timeout=15,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        )
        if result.returncode == 0 and result.stdout.strip():
            raw_events = result.stdout.strip()
            if raw_events:
                parsed = json.loads(raw_events)
                if isinstance(parsed, dict): parsed = [parsed]
                for ev in parsed:
                    level_num = ev.get("level", 4)
                    severity = "Info"
                    if level_num == 1: severity = "Critico"
                    elif level_num == 2: severity = "Error"
                    elif level_num == 3: severity = "Advertencia"
                    event_id = ev.get("id", 0)
                    log_name = ev.get("log", "")
                    category = "sistema"
                    if log_name == "Security": category = "seguridad"
                    elif log_name == "Application": category = "aplicacion"
                    event_type = "general"
                    if event_id in (4624, 4625, 4634, 4648): event_type = "inicio_sesion"
                    elif event_id in (4720, 4722, 4723, 4724, 4725, 4726): event_type = "gestion_cuenta"
                    elif event_id in (7036, 7045, 7040): event_type = "servicio"
                    elif event_id in (6008, 6006, 6005, 1074): event_type = "apagado"
                    elif event_id in (1000, 1001, 1002): event_type = "error_app"
                    elif event_id in (11, 51, 7, 15): event_type = "disco"
                    elif event_id in (41, 109): event_type = "energia"
                    event_logs_data.append({
                        "log": log_name, "id": event_id, "severity": severity,
                        "source": ev.get("source", ""), "message": ev.get("message", "")[:200],
                        "time": ev.get("time", ""), "category": category, "event_type": event_type
                    })
        log.info("[EVENTS] Captured %d Windows events", len(event_logs_data))
    except subprocess.TimeoutExpired: log.warning("[EVENTS] Timed out")
    except Exception as e: log.warning("[EVENTS] Failed: %s", e)
    return event_logs_data

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

    # Idle time (tiempo sin movimiento de mouse/teclado) — solo Windows
    idle_seconds = None
    try:
        if platform.system() == "Windows":
            import ctypes
            class LASTINPUTINFO(ctypes.Structure):
                _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]
            lii = LASTINPUTINFO()
            lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
            if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):
                millis_since_boot = ctypes.windll.kernel32.GetTickCount()
                idle_millis = millis_since_boot - lii.dwTime
                idle_seconds = max(0, idle_millis // 1000)
    except Exception as e:
        log.debug("[COLLECT] Could not get idle time: %s", e)

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

    # ── Modular Collections: USB + Downloads + Event Viewer ──
    usb_ports_data = collect_usb_ports()
    usb_ports_json = json.dumps(usb_ports_data, ensure_ascii=True) if usb_ports_data else None
    downloads_data = collect_downloads_metadata()
    downloads_json = json.dumps(downloads_data, ensure_ascii=True) if downloads_data else None
    event_logs_data = collect_event_logs()
    event_logs_json = json.dumps(event_logs_data, ensure_ascii=True) if event_logs_data else None

    # Build payloads
    metrics_row = {
        "timestamp": now, "device_id": DEVICE_ID,
        "cpu_usage": round(cpu_pct, 2), "ram_usage": ram_pct,
        "disk_free_gb": disk_free_gb,
        "network_latency_ms": latency if latency > 0 else None,
        "cause_root": cause_root, "cause_process": cause_process,
        "device_type": device_type,
        "battery_percent": battery_pct, "battery_status": battery_status,
        "top_processes": top_processes_json, "idle_seconds": idle_seconds,
        "usb_ports": usb_ports_json, "downloads_metadata": downloads_json,
        "event_logs": event_logs_json
    }

    sync_row = {
        "timestamp": now, "device_id": DEVICE_ID,
        "last_sync": now, "last_ip": local_ip, "status": "Online"
    }

    idle_str = f"{idle_seconds}s" if idle_seconds is not None else "N/A"
    uc = len(usb_ports_data) if usb_ports_data else 0
    dc = len(downloads_data) if downloads_data else 0
    ec = len(event_logs_data) if event_logs_data else 0
    log.info("[COLLECT] CPU:%.1f%% RAM:%.1f%% Disk:%.2fGB Latency:%.1fms Battery:%s%% Idle:%s USB:%d Downloads:%d Events:%d",
             cpu_pct, ram_pct, disk_free_gb, latency, battery_pct, idle_str, uc, dc, ec)
    log.info("[COLLECT] Top processes: %s", ", ".join(p['name'] for p in top_processes[:3]))

    return metrics_row, sync_row

# ===========================================================================
# Sync pending buffer
# ===========================================================================
def sync_pending(conn):
    """Sync all pending buffered records to BigQuery when reconnected."""
    pending = get_pending_count(conn)
    if pending == 0:
        return
    log.info("[SYNC] %d pending records in buffer. Flushing to BigQuery...", pending)
    # Flush all in batches of 50
    total_synced = 0
    while True:
        records = get_pending_records(conn, limit=50)
        if not records:
            break
        synced_ids = []
        for rec_id, table_name, payload_json in records:
            try:
                payload = json.loads(payload_json)
                success = bq_insert_row(table_name, payload, retries=2)
                if success:
                    synced_ids.append(rec_id)
            except Exception as e:
                log.error("[SYNC] Error syncing record %d: %s", rec_id, e)
        if synced_ids:
            mark_synced(conn, synced_ids)
            total_synced += len(synced_ids)
        # If we couldn't sync any in this batch, stop trying
        if len(synced_ids) < len(records):
            break
    remaining = get_pending_count(conn)
    log.info("[SYNC] Flushed %d records. %d remaining in buffer.", total_synced, remaining)

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
    log.info("[START] Onyx Agent v%s started (interval: %ds)", CONFIG.get('version', '1.0'), interval)
    log.info("[START] Device ID: %s", DEVICE_ID)
    consecutive_failures = 0
    while True:
        try:
            run_once()
            consecutive_failures = 0  # reset on success
        except Exception as e:
            consecutive_failures += 1
            log.error("[LOOP] Error (failure #%d): %s", consecutive_failures, e, exc_info=True)
            # After 3 consecutive failures, reset BQ client to force reconnect
            if consecutive_failures >= 3:
                log.warning("[LOOP] 3 consecutive failures — resetting BigQuery client for reconnect...")
                get_bq_client(force_reset=True)
                consecutive_failures = 0
        wait = interval
        log.info("[WAIT] Next collection in %d seconds...", wait)
        time.sleep(wait)

# ===========================================================================
# Entry Point
# ===========================================================================
if __name__ == "__main__":
    import io
    if hasattr(sys.stdout, 'buffer'):
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

    print("+----------------------------------------------+")
    print("|  Onyx Agent v%-8s                      |" % CONFIG.get('version', '1.0.0'))
    print("|  Device: %-35s |" % DEVICE_ID)
    bq_label = "Available" if HAS_BQ else "Not available"
    print("|  BigQuery: %-33s |" % bq_label)
    print("+----------------------------------------------+")

    if "--once" in sys.argv:
        run_once()
    else:
        run_loop()
