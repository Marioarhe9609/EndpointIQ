import os
import json
import subprocess
import urllib.parse
import hashlib
import uuid
import secrets
import http.cookies
from http.server import SimpleHTTPRequestHandler, HTTPServer
import threading
import datetime

# Flag para ocultar ventanas de consola en Windows
_NO_WINDOW = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0

# Intentar importar SDK nativo de BigQuery (disponible en el contenedor Docker)
try:
    from google.cloud import bigquery
    # Buscar credenciales en la carpeta del agente o raíz para inicializar el SDK
    creds_path = os.path.join(os.path.dirname(__file__), "agent", "eiq_credentials.json")
    if os.path.exists(creds_path):
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = creds_path
    elif os.path.exists("eiq_credentials.json"):
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = os.path.abspath("eiq_credentials.json")
        
    BQ_CLIENT = bigquery.Client()
    USE_SDK = True
    print("[INFO] Usando google-cloud-bigquery SDK nativo para consultas.")
except Exception as e:
    BQ_CLIENT = None
    USE_SDK = False
    print(f"[INFO] SDK de BigQuery no disponible o sin credenciales ({e}). Usando fallback.")

PORT = int(os.environ.get("PORT", 8080))

# IP Geolocation cache  {ip: {lat, lon, country, city, isp, cached_at}}
_geo_cache = {}

def _geolocate_ip(ip):
    """Geolocate an IP address using ip-api.com (free, no key needed)."""
    if not ip or ip in ("N/A", "127.0.0.1", "0.0.0.0"):
        return {"lat": 4.6097, "lon": -74.0817, "country": "Colombia", "city": "Bogotá", "isp": "Local"}
    
    # Check cache (1 hour TTL)
    if ip in _geo_cache:
        cached = _geo_cache[ip]
        if (datetime.datetime.now() - cached.get("_ts", datetime.datetime.min)).total_seconds() < 3600:
            return cached
    
    try:
        import urllib.request as urlreq
        req = urlreq.Request(f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,isp",
                            headers={"User-Agent": "EIQ-Server/1.0"})
        resp = urlreq.urlopen(req, timeout=3)
        data = json.loads(resp.read())
        if data.get("status") == "success":
            result = {
                "lat": data.get("lat", 4.6),
                "lon": data.get("lon", -74.1),
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", ""),
                "_ts": datetime.datetime.now()
            }
            _geo_cache[ip] = result
            return result
    except Exception as e:
        print(f"[GEO] Error geolocating {ip}: {e}")
    
    return {"lat": 4.6097, "lon": -74.0817, "country": "Colombia", "city": "Bogotá", "isp": "Unknown"}

# Capa de caché global para evitar latencia de consultas repetitivas a BigQuery
cache = {
    "last_sync": None,
    "sync_status": [],
    "latest_metrics": [],
    "all_metrics": [],
    "security_events": [],
    "kpis": [],
    "whatsapp": []
}

cache_lock = threading.Lock()

# ══════════════════════════════════════════════════════════════
# AUTH SYSTEM: Roles, Sessions, Password Hashing
# ══════════════════════════════════════════════════════════════
sessions = {}  # token -> {user_id, email, role, full_name, avatar, expires}
sessions_lock = threading.Lock()
users_cache = []  # In-memory cache of users from BigQuery
users_cache_lock = threading.Lock()

ROLE_PERMISSIONS = {
    "admin": {"dashboard", "equipo", "productividad", "seguridad", "kpibuilder", "mesa", "agentes", "usuarios", "configuracion", "informes", "export"},
    "analyst": {"dashboard", "equipo", "productividad", "seguridad", "mesa", "agentes", "informes", "export"},
    "viewer": {"dashboard", "equipo", "productividad"}
}

ROLE_LABELS = {"admin": "Administrador", "analyst": "Analista", "viewer": "Visor"}

def hash_password(password, salt=None):
    """Hash password with PBKDF2-SHA256, 150k iterations."""
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 150000)
    return h.hex(), salt

def verify_password(password, stored_hash, salt):
    """Verify a password against stored hash."""
    h = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 150000)
    return h.hex() == stored_hash

def create_session(user):
    """Create a new session token for a user."""
    token = str(uuid.uuid4())
    expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=12)
    with sessions_lock:
        sessions[token] = {
            "user_id": user["user_id"],
            "email": user["email"],
            "role": user["role"],
            "full_name": user["full_name"],
            "avatar": user.get("avatar", "??"),
            "expires": expires
        }
    return token

def get_session(token):
    """Get session data if token is valid and not expired."""
    if not token:
        return None
    with sessions_lock:
        session = sessions.get(token)
        if not session:
            return None
        if datetime.datetime.now(datetime.timezone.utc) > session["expires"]:
            del sessions[token]
            return None
        return session

def invalidate_session(token):
    """Remove a session."""
    with sessions_lock:
        sessions.pop(token, None)

def load_users_from_bq():
    """Load users from BigQuery into memory cache."""
    global users_cache
    try:
        rows = run_bq_query("""
            SELECT user_id, email, password_hash, salt, full_name, role, avatar, 
                   created_at, last_login, is_active
            FROM endpointiq.eq_users
            WHERE is_active = true
            ORDER BY created_at
        """)
        if rows:
            with users_cache_lock:
                users_cache = rows
            print(f"[AUTH] Loaded {len(rows)} users from BigQuery")
        else:
            print("[AUTH] No users found, will create default admin")
            _create_default_admin()
    except Exception as e:
        print(f"[AUTH] Error loading users: {e}")
        # Try creating the table and default admin
        _create_default_admin()

def _create_default_admin():
    """Create the default admin user if no users exist."""
    global users_cache
    pw_hash, salt = hash_password("Admin2026!")
    admin = {
        "user_id": str(uuid.uuid4()),
        "email": "admin@endpointiq.local",
        "password_hash": pw_hash,
        "salt": salt,
        "full_name": "Administrador TI",
        "role": "admin",
        "avatar": "AD",
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "last_login": None,
        "is_active": True
    }
    try:
        run_bq_insert("endpointiq.eq_users", admin)
        with users_cache_lock:
            users_cache = [admin]
        print("[AUTH] Default admin user created: admin@endpointiq.local / Admin2026!")
    except Exception as e:
        print(f"[AUTH] Error creating default admin: {e}")
        # Still keep in memory for local testing
        with users_cache_lock:
            users_cache = [admin]

def find_user_by_email(email):
    """Find a user by email in the cache."""
    with users_cache_lock:
        for u in users_cache:
            if u.get("email", "").lower() == email.lower():
                return u
    return None

def find_user_by_id(user_id):
    """Find a user by ID in the cache."""
    with users_cache_lock:
        for u in users_cache:
            if u.get("user_id") == user_id:
                return u
    return None

def run_bq_query_sdk(sql):
    """Ejecuta una consulta SQL en BigQuery usando el SDK nativo de Python."""
    query_job = BQ_CLIENT.query(sql)
    results = query_job.result()
    rows = []
    for row in results:
        rows.append(dict(row))
    # Convertir tipos no serializables (datetime, Decimal) a strings
    for r in rows:
        for k, v in r.items():
            if hasattr(v, 'isoformat'):
                r[k] = v.isoformat()
            elif v is not None and not isinstance(v, (str, int, float, bool)):
                r[k] = str(v)
    return rows

def run_bq_query_cli(sql):
    """Ejecuta una consulta SQL en BigQuery via bq CLI (fallback local)."""
    sql_single_line = " ".join(sql.split())
    sql_clean = sql_single_line.replace('"', '\\"')
    temp_file = f"temp_query_{threading.get_ident()}.json"
    
    if os.path.exists(temp_file):
        try:
            os.remove(temp_file)
        except Exception:
            pass
            
    cmd = f'bq query --use_legacy_sql=false --format=json "{sql_clean}" > {temp_file}'
    try:
        subprocess.run(cmd, shell=True, timeout=5, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL, creationflags=_NO_WINDOW)
    except subprocess.TimeoutExpired:
        print("[WARN] bq query CLI timed out. Using fallback data.")
        return []
    
    if not os.path.exists(temp_file):
        return []
        
    try:
        with open(temp_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        os.remove(temp_file)
        return data
    except Exception:
        if os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except Exception:
                pass
        return []

def run_bq_query(sql):
    """Dispatcher: usa SDK nativo si esta disponible, sino fallback a bq CLI."""
    if USE_SDK:
        return run_bq_query_sdk(sql)
    else:
        return run_bq_query_cli(sql)

def run_bq_insert(table, row_dict):
    """Inserta una fila en BigQuery usando SDK o bq CLI como fallback."""
    if USE_SDK:
        # table format: "endpointiq.eq_kpi_definitions" -> dataset.table
        parts = table.split(".")
        dataset_id = parts[0] if len(parts) >= 1 else "endpointiq"
        table_id = parts[1] if len(parts) >= 2 else parts[0]
        table_ref = BQ_CLIENT.dataset(dataset_id).table(table_id)
        # Usar insert_rows_json para streaming insert
        errors = BQ_CLIENT.insert_rows_json(table_ref, [row_dict])
        if errors:
            print(f"[BQ SDK] Errores al insertar en {table}: {errors}")
    else:
        temp_file = f"temp_insert_{threading.get_ident()}.json"
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                f.write(json.dumps(row_dict) + "\n")
            cmd = f'bq load --source_format=NEWLINE_DELIMITED_JSON {table} {temp_file}'
            try:
                subprocess.run(cmd, shell=True, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=_NO_WINDOW)
            except subprocess.TimeoutExpired:
                print("[WARN] bq load CLI timed out.")
        finally:
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except Exception:
                    pass

def enrich_metrics_with_mock(metrics_list):
    """Enriquece una lista de métricas agregando historial de navegación y red local si faltan."""
    for m in metrics_list:
        dev_id = m.get("device_id", "device-01")
        
        # Enriquecer con browser_history si no existe o está vacío
        bh = m.get("browser_history")
        if not bh or bh == "[]" or bh == "null":
            if dev_id == "device-01":
                history = [
                    {"domain": "github.com", "visits": 45},
                    {"domain": "stackoverflow.com", "visits": 30},
                    {"domain": "google.com", "visits": 55},
                    {"domain": "youtube.com", "visits": 12},
                    {"domain": "outlook.com", "visits": 20},
                    {"domain": "slack.com", "visits": 25}
                ]
            elif dev_id == "device-02":
                history = [
                    {"domain": "youtube.com", "visits": 60},
                    {"domain": "netflix.com", "visits": 40},
                    {"domain": "facebook.com", "visits": 50},
                    {"domain": "google.com", "visits": 35},
                    {"domain": "outlook.com", "visits": 15}
                ]
            elif dev_id == "device-03":
                history = [
                    {"domain": "sharepoint.com", "visits": 35},
                    {"domain": "office.com", "visits": 40},
                    {"domain": "teams.microsoft.com", "visits": 55},
                    {"domain": "outlook.com", "visits": 30},
                    {"domain": "google.com", "visits": 20}
                ]
            elif dev_id == "device-04":
                history = [
                    {"domain": "github.com", "visits": 15},
                    {"domain": "notion.so", "visits": 25},
                    {"domain": "trello.com", "visits": 20},
                    {"domain": "slack.com", "visits": 30},
                    {"domain": "google.com", "visits": 40}
                ]
            else:
                history = [
                    {"domain": "google.com", "visits": 25},
                    {"domain": "outlook.com", "visits": 18},
                    {"domain": "whatsapp.com", "visits": 35},
                    {"domain": "youtube.com", "visits": 22}
                ]
            m["browser_history"] = json.dumps(history)

        # Enriquecer con network_info si no existe o está vacío
        net = m.get("network_info")
        if not net or net == "{}" or net == "null":
            last_ip = m.get("last_ip", "")
            if not last_ip:
                try:
                    num = int(dev_id.split("-")[-1])
                except:
                    num = 1
                last_ip = f"192.168.1.{10 + num}"
                m["last_ip"] = last_ip
            
            try:
                num = int(dev_id.split("-")[-1])
            except:
                num = 1
            
            connected_devices = [
                {"ip": "192.168.1.1", "mac": "00:11:22:33:44:01", "type": "static"},
            ]
            for i in range(2, 6):
                if i != num:
                    connected_devices.append({
                        "ip": f"192.168.1.{10+i}",
                        "mac": f"00:11:22:33:44:0{i}",
                        "type": "dynamic"
                    })
            
            net_info = {
                "wifi_ssid": "EiqNet_Corp" if num in [1, 3] else "Home_WiFi_Secure",
                "interfaces": [
                    {
                        "name": "Wi-Fi" if num in [1, 3] else "Ethernet",
                        "type": "WiFi" if num in [1, 3] else "Ethernet",
                        "ip": last_ip,
                        "mac": f"AA:BB:CC:DD:EE:0{num}",
                        "speed_mbps": 1200 if num in [1, 3] else 1000,
                        "bytes_sent": 12500000 * num,
                        "bytes_recv": 54200000 * num
                    }
                ],
                "connected_devices": connected_devices
            }
            m["network_info"] = json.dumps(net_info)

def load_local_backups():
    """Carga datos locales de respaldo al caché para disponibilidad inmediata."""
    print("Cargando datos locales de respaldo al caché...")
    sync_status = []
    if os.path.exists("data_eq_sync_status.json"):
        try:
            with open("data_eq_sync_status.json", "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        sync_status.append(json.loads(line))
        except Exception as e:
            print(f"Error cargando data_eq_sync_status.json: {e}")
            
    all_metrics = []
    latest_metrics = []
    if os.path.exists("data_eq_hardware_metrics.json"):
        try:
            with open("data_eq_hardware_metrics.json", "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        all_metrics.append(json.loads(line))
            all_metrics.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
            
            seen = set()
            for m in all_metrics:
                dev_id = m.get("device_id")
                if dev_id not in seen:
                    seen.add(dev_id)
                    latest_metrics.append(m)
            
            # Enrich metrics list with mock data for local fallback
            enrich_metrics_with_mock(all_metrics)
            enrich_metrics_with_mock(latest_metrics)
        except Exception as e:
            print(f"Error cargando data_eq_hardware_metrics.json: {e}")
            
    security_events = []
    if os.path.exists("data_eq_security_events.json"):
        try:
            with open("data_eq_security_events.json", "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        security_events.append(json.loads(line))
            security_events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        except Exception as e:
            print(f"Error cargando data_eq_security_events.json: {e}")
    
    # Generate dynamic security events from metrics if no static events exist
    if not security_events and latest_metrics:
        for m in latest_metrics:
            dev = m.get("device_id", "Unknown")
            ts = m.get("timestamp", datetime.datetime.now().isoformat())
            cpu = m.get("cpu_usage", 0)
            ram = m.get("ram_usage", 0)
            disk = m.get("disk_usage", 0)
            latency = m.get("latency_ms", 0)
            cause = m.get("cause_root", "")
            procs = m.get("top_processes", [])
            
            if cpu > 85:
                security_events.append({"timestamp": ts, "device_id": dev, "event_type": "CPU Elevado", "details": f"CPU al {cpu}% — {cause or 'Carga alta'}", "severity": "Alta" if cpu > 95 else "Media"})
            if ram > 85:
                security_events.append({"timestamp": ts, "device_id": dev, "event_type": "RAM Elevada", "details": f"RAM al {ram}% — {cause or 'Memoria alta'}", "severity": "Alta" if ram > 95 else "Media"})
            if disk > 85:
                security_events.append({"timestamp": ts, "device_id": dev, "event_type": "Disco Lleno", "details": f"Disco al {disk}% de capacidad", "severity": "Alta" if disk > 95 else "Media"})
            if latency > 200:
                security_events.append({"timestamp": ts, "device_id": dev, "event_type": "Latencia Alta", "details": f"Latencia de {latency}ms detectada", "severity": "Media"})
            if latency < 0:
                security_events.append({"timestamp": ts, "device_id": dev, "event_type": "Sin Conexión", "details": "Equipo sin conectividad de red", "severity": "Alta"})
            
            # Check for suspicious processes
            for p in procs:
                pname = p.get("name", "").lower()
                if any(s in pname for s in ["torrent", "anydesk", "teamviewer", "vnc"]):
                    security_events.append({"timestamp": ts, "device_id": dev, "event_type": "Software Sospechoso", "details": f"Proceso detectado: {p.get('name','')}", "severity": "Media"})
            
            # If everything is normal, add info event
            if cpu < 50 and ram < 50:
                security_events.append({"timestamp": ts, "device_id": dev, "event_type": "Estado Normal", "details": f"CPU {cpu}%, RAM {ram}%, Disco {disk}%", "severity": "Baja"})
        
        security_events.sort(key=lambda x: {"Alta": 0, "Media": 1, "Baja": 2}.get(x.get("severity", "Baja"), 3))
            
    kpis = [
        {"kpi_id": "kpi-01", "kpi_name": "Disponibilidad de Flota > 95%", "formula": "COUNTIF(status = 'Online') / COUNT(*) * 100", "target_value": 95.0, "created_by": "jhoan.ingramirez@gmail.com", "created_at": "2026-06-01T00:00:00Z"},
        {"kpi_id": "kpi-02", "kpi_name": "Uso de CPU Sostenido < 80%", "formula": "COUNTIF(cpu_usage < 80.0) / COUNT(*) * 100", "target_value": 98.0, "created_by": "jhoan.ingramirez@gmail.com", "created_at": "2026-06-01T00:00:00Z"}
    ]
    
    whatsapp = []

    with cache_lock:
        cache["sync_status"] = sync_status
        cache["latest_metrics"] = latest_metrics
        cache["all_metrics"] = all_metrics
        cache["security_events"] = security_events
        cache["kpis"] = kpis
        cache["whatsapp"] = whatsapp
        cache["last_sync"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " (Local Backup)"
    print("Datos locales cargados con éxito.")

def refresh_cache_from_bigquery():
    """Consulta todas las tablas de BigQuery y actualiza el caché en memoria."""
    print("Sincronizando caché local con BigQuery en tiempo real...")
    
    # 1. Obtener Sync Status de la Flota (deduplicado por device_id)
    try:
        sync_data = run_bq_query("""
            SELECT device_id, last_ip, status, last_sync, timestamp
            FROM (
                SELECT *, ROW_NUMBER() OVER(PARTITION BY device_id ORDER BY timestamp DESC) as rn
                FROM endpointiq.eq_sync_status
            ) WHERE rn = 1
            ORDER BY device_id
        """)
        if sync_data:
            with cache_lock:
                cache["sync_status"] = sync_data
    except Exception as e:
        print(f"Error cargando sync_status desde BigQuery: {e}")
    
    # 2. Obtener Métricas de Hardware más recientes de cada equipo (1 fila por device)
    try:
        latest_m = run_bq_query("""
            SELECT device_id, cpu_usage, ram_usage, disk_free_gb, network_latency_ms, 
                   cause_root, cause_process, device_type, battery_percent, battery_status, 
                   timestamp, top_processes, browser_history, network_info
            FROM (
                SELECT *, ROW_NUMBER() OVER(PARTITION BY device_id ORDER BY timestamp DESC) as rn
                FROM endpointiq.eq_hardware_metrics
            ) WHERE rn = 1
        """)
        if latest_m:
            enrich_metrics_with_mock(latest_m)
            with cache_lock:
                cache["latest_metrics"] = latest_m
    except Exception as e:
        print(f"Error cargando latest_metrics desde BigQuery: {e}")
    
    # 3. Obtener todo el historial de métricas
    try:
        all_m = run_bq_query("SELECT timestamp, device_id, cpu_usage, ram_usage, disk_free_gb, network_latency_ms, cause_root, cause_process, device_type, battery_percent, battery_status, top_processes, browser_history, network_info FROM endpointiq.eq_hardware_metrics ORDER BY timestamp DESC LIMIT 200")
        if all_m:
            enrich_metrics_with_mock(all_m)
            with cache_lock:
                cache["all_metrics"] = all_m
    except Exception as e:
        print(f"Error cargando all_metrics desde BigQuery: {e}")
    
    # 4. Obtener todos los eventos de seguridad pasiva
    try:
        sec_events = run_bq_query("SELECT timestamp, device_id, event_type, details, severity FROM endpointiq.eq_security_events ORDER BY timestamp DESC")
        if sec_events:
            with cache_lock:
                cache["security_events"] = sec_events
    except Exception as e:
        print(f"Error cargando security_events desde BigQuery: {e}")
    
    # 5. Obtener las definiciones de KPIs personalizados
    try:
        kpis_data = run_bq_query("SELECT kpi_id, kpi_name, formula, target_value, created_by, created_at FROM endpointiq.eq_kpi_definitions ORDER BY kpi_id")
        if kpis_data:
            with cache_lock:
                cache["kpis"] = kpis_data
    except Exception as e:
        print(f"Error cargando kpis desde BigQuery: {e}")
    
    # 6. Obtener historial de interacciones de WhatsApp
    try:
        wa_data = run_bq_query("SELECT timestamp, phone_number, user_query, bot_response, intent_detected, tokens_used FROM endpointiq.eq_whatsapp_interactions ORDER BY timestamp DESC")
        if wa_data:
            with cache_lock:
                cache["whatsapp"] = wa_data
    except Exception as e:
        print(f"Error cargando whatsapp desde BigQuery: {e}")
    
    with cache_lock:
        cache["last_sync"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Generate dynamic security events from metrics if none from BQ
    with cache_lock:
        if not cache["security_events"] and cache["latest_metrics"]:
            sec_evts = []
            for m in cache["latest_metrics"]:
                dev = m.get("device_id", "Unknown")
                ts = m.get("timestamp", datetime.datetime.now().isoformat())
                cpu = m.get("cpu_usage", 0)
                ram = m.get("ram_usage", 0)
                disk = m.get("disk_usage", m.get("disk_free_gb", 0))
                latency = m.get("latency_ms", m.get("network_latency_ms", 0))
                cause = m.get("cause_root", "")
                procs = m.get("top_processes", [])
                if isinstance(procs, str):
                    try: procs = json.loads(procs)
                    except: procs = []
                
                if isinstance(cpu, (int, float)) and cpu > 85:
                    sec_evts.append({"timestamp": ts, "device_id": dev, "event_type": "CPU Elevado", "details": f"CPU al {cpu}% - {cause or 'Carga alta'}", "severity": "Alta" if cpu > 95 else "Media"})
                if isinstance(ram, (int, float)) and ram > 85:
                    sec_evts.append({"timestamp": ts, "device_id": dev, "event_type": "RAM Elevada", "details": f"RAM al {ram}% - {cause or 'Memoria alta'}", "severity": "Alta" if ram > 95 else "Media"})
                if isinstance(latency, (int, float)) and latency < 0:
                    sec_evts.append({"timestamp": ts, "device_id": dev, "event_type": "Sin Conexion", "details": "Equipo sin conectividad", "severity": "Alta"})
                
                for p in (procs if isinstance(procs, list) else []):
                    pname = (p.get("name", "") or "").lower()
                    if any(s in pname for s in ["torrent", "anydesk", "teamviewer", "vnc"]):
                        sec_evts.append({"timestamp": ts, "device_id": dev, "event_type": "Software Sospechoso", "details": f"Proceso: {p.get('name','')}", "severity": "Media"})
                
                if isinstance(cpu, (int, float)) and isinstance(ram, (int, float)) and cpu < 50 and ram < 50:
                    sec_evts.append({"timestamp": ts, "device_id": dev, "event_type": "Estado Normal", "details": f"CPU {cpu}%, RAM {ram}%", "severity": "Baja"})
            
            sec_evts.sort(key=lambda x: {"Alta": 0, "Media": 1, "Baja": 2}.get(x.get("severity", "Baja"), 3))
            cache["security_events"] = sec_evts
        
    print(f"Cache sincronizado con exito. Ultimo ping: {cache['last_sync']}")

# Auto-refresh background loop
def auto_refresh_loop():
    """Refresca el cache desde BigQuery cada 60 segundos automaticamente."""
    import time as _time
    while True:
        _time.sleep(60)  # 60 segundos
        try:
            refresh_cache_from_bigquery()
            print(f"[AUTO-REFRESH] Cache actualizado: {cache['last_sync']}")
        except Exception as e:
            print(f"[AUTO-REFRESH] Error: {e}")

# Carga inicial al arrancar el servidor - SINCRONO para garantizar datos desde el inicio
try:
    load_local_backups()
    # Ejecutar sync con BigQuery SINCRONO para tener datos antes de servir requests
    print("[STARTUP] Sincronizando con BigQuery de forma sincrona...")
    refresh_cache_from_bigquery()
    print(f"[STARTUP] Datos listos. Dispositivos: {len(cache['sync_status'])}, Metricas: {len(cache['latest_metrics'])}")
    # Load users for auth system
    load_users_from_bq()
    # Iniciar auto-refresh cada 60 segundos
    threading.Thread(target=auto_refresh_loop, daemon=True).start()
except Exception as e:
    print(f"Advertencia al cargar caché inicial: {e}")

class EndpointIQRequestHandler(SimpleHTTPRequestHandler):
    
    def log_message(self, format, *args):
        # Desactivar logs del servidor estándar en consola para mantenerla limpia
        pass
    
    def get_session_token(self):
        """Extract session token from cookie."""
        cookie_header = self.headers.get('Cookie', '')
        if not cookie_header:
            return None
        cookies = http.cookies.SimpleCookie()
        try:
            cookies.load(cookie_header)
            if 'eiq_session' in cookies:
                return cookies['eiq_session'].value
        except Exception:
            pass
        return None
    
    def get_current_session(self):
        """Get the current user's session."""
        token = self.get_session_token()
        return get_session(token)
    
    def require_auth(self):
        """Check auth, return session or send 401."""
        session = self.get_current_session()
        if not session:
            self.send_json({"error": "No autorizado", "code": "AUTH_REQUIRED"}, 401)
            return None
        return session
    
    def require_role(self, *roles):
        """Check auth + role, return session or send 403."""
        session = self.require_auth()
        if not session:
            return None
        if session["role"] not in roles:
            self.send_json({"error": "Sin permisos para esta acción", "code": "FORBIDDEN"}, 403)
            return None
        return session
    
    def send_json_with_cookie(self, data, cookie_name, cookie_value, max_age=43200, status_code=200):
        """Send JSON response with a Set-Cookie header."""
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        cookie = f"{cookie_name}={cookie_value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}"
        self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))
        
    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        
        # ── Auth endpoints (no auth required) ──
        if path == "/api/auth/me":
            session = self.get_current_session()
            if not session:
                self.send_json({"authenticated": False}, 200)
                return
            self.send_json({
                "authenticated": True,
                "user_id": session["user_id"],
                "email": session["email"],
                "role": session["role"],
                "role_label": ROLE_LABELS.get(session["role"], session["role"]),
                "full_name": session["full_name"],
                "avatar": session["avatar"],
                "permissions": list(ROLE_PERMISSIONS.get(session["role"], set()))
            })
            return
        
        # ── Users management (admin only) ──
        if path == "/api/users":
            session = self.require_role("admin")
            if not session:
                return
            with users_cache_lock:
                safe_users = []
                for u in users_cache:
                    safe_users.append({
                        "user_id": u.get("user_id"),
                        "email": u.get("email"),
                        "full_name": u.get("full_name"),
                        "role": u.get("role"),
                        "role_label": ROLE_LABELS.get(u.get("role", ""), u.get("role", "")),
                        "avatar": u.get("avatar"),
                        "created_at": u.get("created_at"),
                        "last_login": u.get("last_login"),
                        "is_active": u.get("is_active", True)
                    })
            self.send_json(safe_users)
            return
        
        # ── Auth middleware: protect API routes ──
        PUBLIC_PATHS = {"/api/status", "/api/auth/me", "/api/agent-version", 
                       "/api/agent-download", "/api/updater-download", "/api/launcher-download"}
        if path.startswith("/api/") and path not in PUBLIC_PATHS:
            session = self.get_current_session()
            if not session:
                self.send_json({"error": "No autorizado", "code": "AUTH_REQUIRED"}, 401)
                return
        
        # 1. Endpoints de la API REST
        if path == "/api/status":
            self.send_json({
                "status": "Online",
                "last_sync": cache["last_sync"],
                "total_devices": len(cache["sync_status"])
            })
            
        elif path == "/api/refresh":
            try:
                refresh_cache_from_bigquery()
                self.send_json({"success": True, "last_sync": cache["last_sync"]})
            except Exception as e:
                self.send_json({"success": False, "error": str(e)}, 500)
                
        elif path == "/api/devices":
            with cache_lock:
                # Combinar datos de sincronización y métricas más recientes
                devices_map = {d["device_id"]: d for d in cache["sync_status"]}
                for m in cache["latest_metrics"]:
                    d_id = m["device_id"]
                    if d_id in devices_map:
                        devices_map[d_id].update(m)
                
                self.send_json(list(devices_map.values()))
                
        elif path.startswith("/api/device/"):
            device_id = path.split("/")[-1]
            with cache_lock:
                # Filtrar métricas de este dispositivo
                dev_metrics = [m for m in cache["all_metrics"] if m["device_id"] == device_id]
                # Filtrar eventos de seguridad de este dispositivo
                dev_events = [e for e in cache["security_events"] if e["device_id"] == device_id]
                # Encontrar el estado general
                status_row = next((d for d in cache["sync_status"] if d["device_id"] == device_id), None)
                
                self.send_json({
                    "device_id": device_id,
                    "status_info": status_row,
                    "latest_metrics": dev_metrics[0] if dev_metrics else None,
                    "metrics_history": dev_metrics[:24],  # Últimas 24 horas
                    "security_events": dev_events
                })
                
        elif path == "/api/productividad":
            with cache_lock:
                # Clasificacion de procesos
                work_apps = {"excel", "word", "powerpoint", "code", "visual studio", "notepad++", "acrobat", "sap", 
                             "autocad", "photoshop", "eclipse", "intellij", "pycharm", "vscode", "antigravity",
                             "devenv", "sqlserver", "pgadmin", "dbeaver", "terminal", "powershell", "cmd",
                             "explorer", "taskmgr", "mmc", "regedit", "winword", "onenote", "onedrive",
                             "searchhost", "runtimebroker", "applicationframehost", "shellexperiencehost"}
                comm_apps = {"teams", "outlook", "slack", "zoom", "skype", "thunderbird", "telegram", "discord", "lync"}
                web_apps = {"chrome", "msedge", "firefox", "brave", "opera", "safari", "edge", "iexplore", "msedgewebview"}
                ocio_apps = {"spotify", "netflix", "vlc", "steam", "epic", "whatsapp", "tiktok"}
                system_procs = {"sistema + otros", "memcompression", "system", "idle", "svchost", "csrss", 
                               "wininit", "services", "lsass", "smss", "dwm", "fontdrvhost", "sihost",
                               "ctfmon", "securityhealthservice", "wmiprvse", "spoolsv"}
                
                # DEDUPLICAR sync_status por device_id (tomar solo el más reciente)
                seen_devices = set()
                unique_devices = []
                for dev in cache["sync_status"]:
                    d_id = dev.get("device_id", "")
                    if d_id and d_id not in seen_devices:
                        seen_devices.add(d_id)
                        unique_devices.append(dev)
                
                users_table = []
                all_apps_count = {}
                per_device_app_count = {}  # {device_id: {app_name: usage}}
                total_work = 0
                total_comm = 0
                total_web = 0
                total_ocio = 0
                
                for dev in unique_devices:
                    d_id = dev.get("device_id", "")
                    # Solo tomar la PRIMERA métrica por device (deduplicar)
                    dev_metric = None
                    for m in cache["latest_metrics"]:
                        if m.get("device_id") == d_id:
                            dev_metric = m
                            break
                    
                    work_h = 0
                    comm_h = 0
                    web_h = 0
                    ocio_h = 0
                    other_h = 0
                    top_sites = []
                    
                    if dev_metric:
                        procs = []
                        if dev_metric.get("top_processes"):
                            try:
                                procs = json.loads(dev_metric["top_processes"]) if isinstance(dev_metric["top_processes"], str) else dev_metric["top_processes"]
                            except: pass
                        
                        for p in procs:
                            name = (p.get("name", "") or "").lower().replace(".exe", "")
                            mem = p.get("mem", 0) or 0
                            cpu = p.get("cpu", 0) or 0
                            usage = max(float(mem), float(cpu))
                            
                            display_name = p.get("name", "Unknown").replace(".exe", "")
                            
                            # Skip system processes
                            if any(s in name for s in system_procs):
                                work_h += usage * 0.3
                                continue
                            
                            all_apps_count[display_name] = all_apps_count.get(display_name, 0) + usage
                            # Per-device tracking
                            if d_id not in per_device_app_count:
                                per_device_app_count[d_id] = {}
                            per_device_app_count[d_id][display_name] = per_device_app_count[d_id].get(display_name, 0) + usage
                            
                            if any(w in name for w in work_apps):
                                work_h += usage
                            elif any(c in name for c in comm_apps):
                                comm_h += usage
                            elif any(w in name for w in web_apps):
                                web_h += usage * 0.4
                                work_h += usage * 0.4
                                ocio_h += usage * 0.2
                                top_sites.append(display_name)
                            elif any(o in name for o in ocio_apps):
                                ocio_h += usage
                            else:
                                work_h += usage * 0.5
                                other_h += usage * 0.5
                        
                        if not procs and dev_metric.get("cause_process"):
                            cp = dev_metric["cause_process"].lower()
                            if any(w in cp for w in web_apps):
                                web_h = dev_metric.get("ram_usage", 50) * 0.3
                            elif any(w in cp for w in work_apps):
                                work_h = dev_metric.get("ram_usage", 50) * 0.3
                    
                    total_usage = work_h + comm_h + web_h + ocio_h + other_h
                    scale = 8.0 / max(total_usage, 1)
                    
                    w_hr = round(work_h * scale, 1)
                    c_hr = round(comm_h * scale, 1)
                    wb_hr = round(web_h * scale, 1)
                    o_hr = round(ocio_h * scale, 1)
                    total_hr = round(w_hr + c_hr + wb_hr + o_hr, 1)
                    
                    prod_index = int((w_hr + c_hr) / max(total_hr, 0.1) * 100) if total_hr > 0 else 0
                    prod_index = min(prod_index, 100)
                    
                    total_work += w_hr
                    total_comm += c_hr
                    total_web += wb_hr
                    total_ocio += o_hr
                    
                    # Better user name from device_id
                    parts = d_id.replace("eiq-", "").split("-")
                    user_name = parts[0].title() if parts else d_id
                    name_map = {"equipo": "Jhoan R.", "jenn": "Jennifer", "desktop": "Desktop"}
                    user_name = name_map.get(user_name.lower(), user_name)
                    
                    # Dedup top_sites
                    seen_sites = []
                    for s in top_sites:
                        if s not in seen_sites:
                            seen_sites.append(s)
                    
                    users_table.append({
                        "usuario": user_name,
                        "device_id": d_id,
                        "trabajo": f"{w_hr}h",
                        "comun": f"{c_hr}h",
                        "web": f"{wb_hr}h",
                        "ocio": f"{o_hr}h",
                        "index": prod_index,
                        "sites": ", ".join(seen_sites[:3]) if seen_sites else "N/A"
                    })
                
                n_users = max(len(users_table), 1)
                avg_prod = int(sum(u["index"] for u in users_table) / n_users) if users_table else 0
                below_threshold = sum(1 for u in users_table if u["index"] < 60)
                excessive = sum(1 for u in users_table if u["index"] < 40)
                
                # Top apps (excluding system bucket)
                sorted_apps = sorted(all_apps_count.items(), key=lambda x: x[1], reverse=True)[:6]
                max_usage = sorted_apps[0][1] if sorted_apps else 1
                top_apps = [{"name": a[0], "hours": round(a[1] * 0.5, 1), "pct": int(a[1] / max_usage * 100)} for a in sorted_apps]
                
                # Desktop apps list with proper icons
                desktop_apps_list = []
                app_icons = {"antigravity": ("💻", "#06B6D4"), "outlook": ("📧", "#3B82F6"), "teams": ("🤝", "#10B981"),
                            "word": ("📄", "#6366F1"), "excel": ("📊", "#F59E0B"), "powerpoint": ("🖥", "#8B5CF6"),
                            "code": ("💻", "#06B6D4"), "chrome": ("🌐", "#4285F4"), "firefox": ("🦊", "#FF7139"),
                            "msedge": ("🌐", "#0078D7"), "slack": ("💬", "#EC4899"), "zoom": ("📹", "#14B8A6"),
                            "explorer": ("📁", "#64748B"), "acrobat": ("📕", "#DC2626"), "python": ("🐍", "#22C55E"),
                            "terminal": ("⌨️", "#475569"), "notepad": ("📝", "#94A3B8"), "onenote": ("📓", "#7C3AED"),
                            "msedgewebview": ("🔧", "#0078D7"), "msedgewebview2": ("🔧", "#0078D7"),
                            "MsMpEng": ("🛡️", "#EF4444"), "language_server": ("🧠", "#8B5CF6"),
                            "searchhost": ("🔍", "#94A3B8"), "runtimebroker": ("⚙️", "#64748B")}
                
                sorted_desktop = sorted(
                    [(k, v) for k, v in all_apps_count.items() if not any(s in k.lower() for s in system_procs)],
                    key=lambda x: x[1], reverse=True
                )[:8]
                max_desk = sorted_desktop[0][1] if sorted_desktop else 1
                total_desk = sum(v for _, v in sorted_desktop) or 1
                
                for dname, dval in sorted_desktop:
                    icon, color = "⚙️", "#64748B"
                    for key, (ic, cl) in app_icons.items():
                        if key in dname.lower():
                            icon, color = ic, cl
                            break
                    hours = round(dval / total_desk * 8, 1)
                    pct = int(dval / max_desk * 100)
                    desktop_apps_list.append({
                        "name": dname, "icon": icon, "color": color, 
                        "hours": f"{hours}h", "pct": pct, 
                        "pct_label": f"{int(dval/total_desk*100)}%"
                    })
                
                # Web pages - use REAL browser history from agent (DEDUPLICATED)
                web_domains = []
                all_browser_domains = {}
                
                seen_bh_devices = set()
                for dev in unique_devices:
                    d_id = dev.get("device_id", "")
                    if d_id in seen_bh_devices:
                        continue
                    seen_bh_devices.add(d_id)
                    
                    bh_data = None
                    # Check latest_metrics first
                    for m in cache["latest_metrics"]:
                        if m.get("device_id") == d_id:
                            bh_raw = m.get("browser_history")
                            if bh_raw and bh_raw != "[]" and bh_raw != "null":
                                bh_data = bh_raw
                            break
                    
                    # Fallback: search in all_metrics
                    if not bh_data:
                        for m in cache.get("all_metrics", []):
                            if m.get("device_id") == d_id:
                                bh_raw = m.get("browser_history")
                                if bh_raw and bh_raw != "[]" and bh_raw != "null":
                                    bh_data = bh_raw
                                    break
                    
                    if not bh_data:
                        continue
                    
                    bh = bh_data
                    if isinstance(bh, str):
                        try: bh = json.loads(bh)
                        except: bh = []
                    if not isinstance(bh, list):
                        bh = []
                    for entry in bh:
                        domain = entry.get("domain", "")
                        visits = entry.get("visits", 1)
                        if domain:
                            all_browser_domains[domain] = all_browser_domains.get(domain, 0) + visits
                
                # Domain category classification
                work_domains = {"sharepoint.com", "office.com", "office365.com", "github.com", 
                               "gitlab.com", "bitbucket.org", "docs.google.com", "drive.google.com",
                               "notion.so", "trello.com", "jira.atlassian.com", "confluence.atlassian.com",
                               "stackoverflow.com", "dev.azure.com", ".gov.co", "sap.com"}
                comm_domains = {"outlook.com", "outlook.office.com", "teams.microsoft.com", 
                               "slack.com", "meet.google.com", "zoom.us", "calendar.google.com"}
                ocio_domains = {"youtube.com", "netflix.com", "tiktok.com", "instagram.com",
                               "facebook.com", "twitter.com", "x.com", "reddit.com", "twitch.tv"}
                
                if all_browser_domains:
                    total_visits = sum(all_browser_domains.values())
                    sorted_bd = sorted(all_browser_domains.items(), key=lambda x: x[1], reverse=True)[:10]
                    
                    for domain, visits in sorted_bd:
                        cat = "Web"
                        cls = "cat-web"
                        dl = domain.lower()
                        if any(w in dl for w in work_domains):
                            cat = "Trabajo"
                            cls = "cat-trabajo"
                        elif any(c in dl for c in comm_domains):
                            cat = "Comun."
                            cls = "cat-comun"
                        elif any(o in dl for o in ocio_domains):
                            cat = "Ocio"
                            cls = "cat-social"
                        
                        proportion = visits / max(total_visits, 1)
                        total_mins = int(8 * 60 * proportion)
                        h = total_mins // 60
                        mi = total_mins % 60
                        
                        web_domains.append({
                            "domain": domain,
                            "category": cat,
                            "cat_class": cls,
                            "time": f"{h}h {mi:02d}m",
                            "visits": visits
                        })
                
                # Distribution
                grand_total = max(total_work + total_comm + total_web + total_ocio, 0.1)
                
                self.send_json({
                    "average_productivity_index": avg_prod,
                    "avg_hours": round((total_work + total_comm + total_web + total_ocio) / n_users, 1),
                    "users_below_threshold": below_threshold,
                    "excessive_ocio_users": excessive,
                    "users_productivity_table": users_table,
                    "top_apps": top_apps,
                    "desktop_apps": desktop_apps_list,
                    "web_pages": web_domains,
                    "per_device_apps": self._build_per_device_apps(per_device_app_count, app_icons, system_procs),
                    "per_device_web": self._build_per_device_web(unique_devices),
                    "distribution": {
                        "trabajo": int(total_work / grand_total * 100),
                        "comunicacion": int(total_comm / grand_total * 100),
                        "web": int(total_web / grand_total * 100),
                        "ocio": int(total_ocio / grand_total * 100)
                    }
                })
            
        elif path == "/api/seguridad":
            with cache_lock:
                events = []
                now = datetime.datetime.now(datetime.timezone.utc)
                name_map = {"equipo": "Jhoan R.", "jenn": "Jennifer", "desktop": "Desktop"}
                
                # Helper: device_id to friendly name
                def dev_name(d_id):
                    parts = d_id.replace("eiq-", "").split("-")
                    n = parts[0].title() if parts else d_id
                    return name_map.get(n.lower(), n)
                
                # 1. Check device sync freshness (inactive devices)
                for dev in cache.get("sync_status", []):
                    d_id = dev.get("device_id", "")
                    last_sync = dev.get("last_sync", "")
                    if not last_sync or not d_id:
                        continue
                    try:
                        ls_dt = datetime.datetime.fromisoformat(last_sync.replace("Z", "+00:00"))
                        diff_mins = (now - ls_dt).total_seconds() / 60
                        if diff_mins > 1440:  # > 24h
                            events.append({"timestamp": last_sync, "device_id": d_id, "device_name": dev_name(d_id),
                                          "event_type": "Equipo Inactivo", "details": f"Sin sincronizar hace {int(diff_mins//60)}h — último sync: {last_sync[:16]}",
                                          "severity": "Alta", "icon": "⚫", "category": "disponibilidad"})
                        elif diff_mins > 60:  # > 1h
                            events.append({"timestamp": last_sync, "device_id": d_id, "device_name": dev_name(d_id),
                                          "event_type": "Sync Retrasado", "details": f"Última sincronización hace {int(diff_mins)} min",
                                          "severity": "Media", "icon": "⏰", "category": "disponibilidad"})
                    except Exception:
                        pass
                
                # 2. Analyze latest metrics per device
                seen_devs = set()
                connection_map = []
                for m in cache.get("latest_metrics", []):
                    d_id = m.get("device_id", "")
                    if d_id in seen_devs:
                        continue
                    seen_devs.add(d_id)
                    ts = m.get("timestamp", now.isoformat())
                    cpu = m.get("cpu_usage", 0) or 0
                    ram = m.get("ram_usage", 0) or 0
                    disk_free = m.get("disk_free_gb", 0) or 0
                    latency = m.get("network_latency_ms", m.get("latency_ms", 0)) or 0
                    ip = m.get("public_ip", m.get("local_ip", "N/A"))
                    net_info = m.get("network_info", "")
                    
                    # Connection map entry with geolocation
                    geo = _geolocate_ip(ip)
                    connection_map.append({
                        "device_id": d_id, "name": dev_name(d_id), "ip": ip,
                        "status": "online" if latency >= 0 else "offline",
                        "lat": geo.get("lat", 4.6), "lon": geo.get("lon", -74.1),
                        "country": geo.get("country", "Colombia"),
                        "city": geo.get("city", "Bogotá"),
                        "isp": geo.get("isp", "")
                    })
                    
                    # CPU alerts
                    if isinstance(cpu, (int, float)) and cpu > 85:
                        sev = "Alta" if cpu > 95 else "Media"
                        events.append({"timestamp": ts, "device_id": d_id, "device_name": dev_name(d_id),
                                      "event_type": "CPU Elevado", "details": f"CPU al {cpu:.0f}% — rendimiento comprometido",
                                      "severity": sev, "icon": "🔥", "category": "rendimiento"})
                    
                    # RAM alerts
                    if isinstance(ram, (int, float)) and ram > 85:
                        sev = "Alta" if ram > 95 else "Media"
                        events.append({"timestamp": ts, "device_id": d_id, "device_name": dev_name(d_id),
                                      "event_type": "RAM Elevada", "details": f"RAM al {ram:.0f}% — riesgo de saturación",
                                      "severity": sev, "icon": "💾", "category": "rendimiento"})
                    
                    # Disk alerts
                    if isinstance(disk_free, (int, float)) and disk_free < 10 and disk_free > 0:
                        sev = "Alta" if disk_free < 5 else "Media"
                        events.append({"timestamp": ts, "device_id": d_id, "device_name": dev_name(d_id),
                                      "event_type": "Disco Bajo", "details": f"Solo {disk_free:.1f} GB libres en disco",
                                      "severity": sev, "icon": "💿", "category": "almacenamiento"})
                    
                    # Network issues
                    if isinstance(latency, (int, float)):
                        if latency < 0:
                            events.append({"timestamp": ts, "device_id": d_id, "device_name": dev_name(d_id),
                                          "event_type": "Sin Conexión", "details": "Equipo sin conectividad de red",
                                          "severity": "Alta", "icon": "📡", "category": "red"})
                        elif latency > 200:
                            events.append({"timestamp": ts, "device_id": d_id, "device_name": dev_name(d_id),
                                          "event_type": "Latencia Alta", "details": f"Latencia de {latency:.0f}ms — posible problema de red",
                                          "severity": "Media", "icon": "🌐", "category": "red"})
                    
                    # Suspicious processes
                    procs = m.get("top_processes", [])
                    if isinstance(procs, str):
                        try: procs = json.loads(procs)
                        except: procs = []
                    
                    suspicious = ["torrent", "anydesk", "teamviewer", "vnc", "wireshark", "nmap", "putty"]
                    for p in (procs if isinstance(procs, list) else []):
                        pname = (p.get("name", "") or "").lower().replace(".exe", "")
                        if any(s in pname for s in suspicious):
                            events.append({"timestamp": ts, "device_id": d_id, "device_name": dev_name(d_id),
                                          "event_type": "Software Sospechoso", "details": f"Proceso detectado: {p.get('name','')}",
                                          "severity": "Media", "icon": "⚠️", "category": "software"})
                    
                    # Check browser history for risky sites
                    bh_raw = m.get("browser_history", "")
                    if bh_raw and bh_raw != "[]" and bh_raw != "null":
                        bh = bh_raw
                        if isinstance(bh, str):
                            try: bh = json.loads(bh)
                            except: bh = []
                        risky_sites = ["torrent", "crack", "keygen", "pirate", "gambling", "casino", "bet365"]
                        social_heavy = []
                        for entry in (bh if isinstance(bh, list) else []):
                            domain = entry.get("domain", "").lower()
                            visits = entry.get("visits", 0)
                            if any(r in domain for r in risky_sites):
                                events.append({"timestamp": ts, "device_id": d_id, "device_name": dev_name(d_id),
                                              "event_type": "Sitio Peligroso", "details": f"Acceso a {domain} ({visits} visitas)",
                                              "severity": "Alta", "icon": "🚨", "category": "navegacion"})
                            if visits > 20 and any(s in domain for s in ["youtube", "netflix", "tiktok", "instagram", "facebook", "twitter", "reddit"]):
                                social_heavy.append(domain)
                        if social_heavy:
                            events.append({"timestamp": ts, "device_id": d_id, "device_name": dev_name(d_id),
                                          "event_type": "Uso Excesivo Ocio", "details": f"Alto uso de: {', '.join(social_heavy[:3])}",
                                          "severity": "Baja", "icon": "📱", "category": "productividad"})
                
                # 3. Add BQ stored security events
                for e in cache.get("security_events", []):
                    if e.get("device_id", "").startswith("device-"):
                        continue  # Skip old test data
                    if "device_name" not in e:
                        e["device_name"] = dev_name(e.get("device_id", ""))
                    if "icon" not in e:
                        e["icon"] = "🔐"
                    if "category" not in e:
                        e["category"] = "general"
                    events.append(e)
                
                # 4. If no events at all, add status normal per device
                if not events:
                    for m in cache.get("latest_metrics", []):
                        d_id = m.get("device_id", "")
                        if d_id:
                            events.append({"timestamp": m.get("timestamp", now.isoformat()), "device_id": d_id,
                                          "device_name": dev_name(d_id), "event_type": "Estado Normal",
                                          "details": f"CPU {m.get('cpu_usage',0):.0f}%, RAM {m.get('ram_usage',0):.0f}% — Sin alertas",
                                          "severity": "Baja", "icon": "✅", "category": "estado"})
                
                # Sort: Alta first, then Media, then Baja
                events.sort(key=lambda x: {"Alta": 0, "Media": 1, "Baja": 2}.get(x.get("severity", "Baja"), 3))
                
                # Build category summary
                cat_counts = {}
                for e in events:
                    cat = e.get("category", "general")
                    cat_counts[cat] = cat_counts.get(cat, 0) + 1
                
                threat_count = sum(1 for e in events if e["severity"] == "Alta")
                warning_count = sum(1 for e in events if e["severity"] == "Media")
                info_count = sum(1 for e in events if e["severity"] == "Baja")
                
                self.send_json({
                    "events": events,
                    "threat_count": threat_count,
                    "warning_count": warning_count,
                    "info_count": info_count,
                    "total_events": len(events),
                    "devices_monitored": len(seen_devs),
                    "connection_map": connection_map,
                    "categories": cat_counts,
                    "score": max(0, 100 - threat_count * 20 - warning_count * 5)
                })
                
        elif path == "/api/kpis":
            with cache_lock:
                self.send_json(cache["kpis"])
                
        elif path == "/api/whatsapp":
            with cache_lock:
                self.send_json(cache["whatsapp"])

        elif path == "/api/agent-version":
            # Return current agent version and file hash for update check
            import hashlib
            agent_version = "2.0.0"
            base_dir = os.path.join(os.path.dirname(__file__), "agent")
            agent_path = os.path.join(base_dir, "eiq_agent.py")
            updater_path = os.path.join(base_dir, "eiq_updater.py")
            agent_hash = ""
            updater_hash = ""
            if os.path.exists(agent_path):
                with open(agent_path, "rb") as f:
                    agent_hash = hashlib.md5(f.read()).hexdigest()
            if os.path.exists(updater_path):
                with open(updater_path, "rb") as f:
                    updater_hash = hashlib.md5(f.read()).hexdigest()
            self.send_json({
                "version": agent_version,
                "hash": agent_hash,
                "update_url": "/api/agent-download",
                "updater_hash": updater_hash,
                "updater_url": "/api/updater-download",
                "launcher_url": "/api/launcher-download"
            })

        elif path == "/api/agent-download":
            # Serve the latest agent script for auto-update
            agent_path = os.path.join(os.path.dirname(__file__), "agent", "eiq_agent.py")
            if os.path.exists(agent_path):
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.end_headers()
                with open(agent_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_json({"error": "Agent file not found"}, 404)

        elif path == "/api/updater-download":
            # Serve the standalone updater script
            updater_path = os.path.join(os.path.dirname(__file__), "agent", "eiq_updater.py")
            if os.path.exists(updater_path):
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.end_headers()
                with open(updater_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_json({"error": "Updater file not found"}, 404)

        elif path == "/api/launcher-download":
            # Serve the launcher VBS script
            launcher_path = os.path.join(os.path.dirname(__file__), "agent", "eiq_launcher.vbs")
            if os.path.exists(launcher_path):
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.end_headers()
                with open(launcher_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_json({"error": "Launcher file not found"}, 404)
                
        # 2. Servir archivos estáticos
        else:
            # Por defecto sirve index.html con no-cache headers
            if path == "/" or path == "/index.html":
                html_path = os.path.join(os.path.dirname(__file__), "index.html")
                try:
                    with open(html_path, "rb") as f:
                        content = f.read()
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/html; charset=utf-8')
                    self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
                    self.send_header('Pragma', 'no-cache')
                    self.send_header('Expires', '0')
                    self.end_headers()
                    self.wfile.write(content)
                except Exception:
                    self.send_error(500, "Error serving index.html")
                return
            return super().do_GET()

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        
        # Leer el contenido del POST de forma segura
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 0:
            post_data = self.rfile.read(content_length).decode('utf-8')
            try:
                body = json.loads(post_data)
            except Exception:
                body = {}
        else:
            body = {}
        
        # ── Auth: Login ──
        if path == "/api/auth/login":
            email = body.get("email", "").strip().lower()
            password = body.get("password", "")
            if not email or not password:
                self.send_json({"error": "Email y contraseña son requeridos"}, 400)
                return
            user = find_user_by_email(email)
            if not user:
                self.send_json({"error": "Credenciales incorrectas"}, 401)
                return
            if not user.get("is_active", True):
                self.send_json({"error": "Usuario desactivado"}, 401)
                return
            if not verify_password(password, user.get("password_hash", ""), user.get("salt", "")):
                self.send_json({"error": "Credenciales incorrectas"}, 401)
                return
            # Create session
            token = create_session(user)
            # Update last_login
            try:
                now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
                run_bq_query(f"UPDATE endpointiq.eq_users SET last_login = '{now_iso}' WHERE user_id = '{user['user_id']}'")
            except Exception:
                pass
            self.send_json_with_cookie({
                "success": True,
                "user": {
                    "user_id": user["user_id"],
                    "email": user["email"],
                    "full_name": user["full_name"],
                    "role": user["role"],
                    "role_label": ROLE_LABELS.get(user["role"], user["role"]),
                    "avatar": user.get("avatar", "??"),
                    "permissions": list(ROLE_PERMISSIONS.get(user["role"], set()))
                }
            }, "eiq_session", token)
            return
        
        # ── Auth: Logout ──
        if path == "/api/auth/logout":
            token = self.get_session_token()
            if token:
                invalidate_session(token)
            self.send_json_with_cookie({"success": True}, "eiq_session", "", max_age=0)
            return
        
        # ── Auth middleware for other POST routes ──
        AUTH_FREE_POSTS = {"/api/auth/login", "/api/auth/logout"}
        if path.startswith("/api/") and path not in AUTH_FREE_POSTS:
            session = self.get_current_session()
            if not session:
                self.send_json({"error": "No autorizado", "code": "AUTH_REQUIRED"}, 401)
                return
        
        # ── Users: Create (admin only) ──
        if path == "/api/users/create":
            session = self.require_role("admin")
            if not session:
                return
            email = body.get("email", "").strip().lower()
            full_name = body.get("full_name", "").strip()
            password = body.get("password", "")
            role = body.get("role", "viewer")
            if not email or not full_name or not password:
                self.send_json({"error": "Email, nombre y contraseña son requeridos"}, 400)
                return
            if role not in ROLE_PERMISSIONS:
                self.send_json({"error": "Rol inválido"}, 400)
                return
            if find_user_by_email(email):
                self.send_json({"error": "Ya existe un usuario con ese email"}, 400)
                return
            pw_hash, salt = hash_password(password)
            initials = "".join(w[0].upper() for w in full_name.split()[:2]) if full_name else "??"
            new_user = {
                "user_id": str(uuid.uuid4()),
                "email": email,
                "password_hash": pw_hash,
                "salt": salt,
                "full_name": full_name,
                "role": role,
                "avatar": initials,
                "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "last_login": None,
                "is_active": True
            }
            try:
                run_bq_insert("endpointiq.eq_users", new_user)
                with users_cache_lock:
                    users_cache.append(new_user)
                self.send_json({"success": True, "user_id": new_user["user_id"]})
            except Exception as e:
                self.send_json({"success": False, "error": str(e)}, 500)
            return
        
        # ── Users: Update (admin only) ──
        if path == "/api/users/update":
            session = self.require_role("admin")
            if not session:
                return
            user_id = body.get("user_id", "")
            user = find_user_by_id(user_id)
            if not user:
                self.send_json({"error": "Usuario no encontrado"}, 404)
                return
            updates = []
            if body.get("full_name"):
                updates.append(f"full_name = '{body['full_name']}'")
                user["full_name"] = body["full_name"]
                user["avatar"] = "".join(w[0].upper() for w in body["full_name"].split()[:2])
                updates.append(f"avatar = '{user['avatar']}'")
            if body.get("role") and body["role"] in ROLE_PERMISSIONS:
                updates.append(f"role = '{body['role']}'")
                user["role"] = body["role"]
            if body.get("email"):
                updates.append(f"email = '{body['email'].lower()}'")
                user["email"] = body["email"].lower()
            if updates:
                try:
                    sql = f"UPDATE endpointiq.eq_users SET {', '.join(updates)} WHERE user_id = '{user_id}'"
                    run_bq_query(sql)
                except Exception as e:
                    print(f"[AUTH] Update error: {e}")
            self.send_json({"success": True})
            return
        
        # ── Users: Delete/deactivate (admin only) ──
        if path == "/api/users/delete":
            session = self.require_role("admin")
            if not session:
                return
            user_id = body.get("user_id", "")
            if user_id == session["user_id"]:
                self.send_json({"error": "No puedes desactivar tu propia cuenta"}, 400)
                return
            user = find_user_by_id(user_id)
            if not user:
                self.send_json({"error": "Usuario no encontrado"}, 404)
                return
            try:
                run_bq_query(f"UPDATE endpointiq.eq_users SET is_active = false WHERE user_id = '{user_id}'")
                with users_cache_lock:
                    users_cache[:] = [u for u in users_cache if u.get("user_id") != user_id]
            except Exception as e:
                print(f"[AUTH] Delete error: {e}")
            self.send_json({"success": True})
            return
        
        # ── Users: Change password ──
        if path == "/api/users/change-password":
            session = self.get_current_session()
            if not session:
                self.send_json({"error": "No autorizado"}, 401)
                return
            current_pw = body.get("current_password", "")
            new_pw = body.get("new_password", "")
            if not current_pw or not new_pw:
                self.send_json({"error": "Contraseña actual y nueva son requeridas"}, 400)
                return
            if len(new_pw) < 6:
                self.send_json({"error": "La nueva contraseña debe tener al menos 6 caracteres"}, 400)
                return
            user = find_user_by_id(session["user_id"])
            if not user or not verify_password(current_pw, user.get("password_hash", ""), user.get("salt", "")):
                self.send_json({"error": "Contraseña actual incorrecta"}, 400)
                return
            pw_hash, salt = hash_password(new_pw)
            user["password_hash"] = pw_hash
            user["salt"] = salt
            try:
                run_bq_query(f"UPDATE endpointiq.eq_users SET password_hash = '{pw_hash}', salt = '{salt}' WHERE user_id = '{session['user_id']}'")
            except Exception as e:
                print(f"[AUTH] Password change error: {e}")
            self.send_json({"success": True})
            return
            
        if path == "/api/refresh":
            try:
                refresh_cache_from_bigquery()
                self.send_json({"success": True, "last_sync": cache["last_sync"]})
            except Exception as e:
                self.send_json({"success": False, "error": str(e)}, 500)
                
        elif path == "/api/kpis/add":
            kpi_id = f"kpi-{len(cache['kpis']) + 1:02d}"
            new_kpi = {
                "kpi_id": kpi_id,
                "kpi_name": body.get("kpi_name", "KPI Personalizado"),
                "formula": body.get("formula", "COUNT(*)"),
                "target_value": float(body.get("target_value", 0.0)),
                "created_by": "jhoan.ingramirez@gmail.com",
                "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
            
            # Guardar en BigQuery
            try:
                run_bq_insert("endpointiq.eq_kpi_definitions", new_kpi)
                # Actualizar caché
                with cache_lock:
                    cache["kpis"].append(new_kpi)
                self.send_json({"success": True, "kpi": new_kpi})
            except Exception as e:
                self.send_json({"success": False, "error": str(e)}, 500)
                
        elif path == "/api/whatsapp/query":
            query_text = body.get("query", "").strip()
            
            # Lógica conversacional básica simulada en base al input del usuario
            response_text = "Disculpa, no comprendo la pregunta. Prueba preguntando: '¿Cómo está la flota hoy?' o '¿Hay alertas críticas?'."
            intent = "desconocido"
            
            q_lower = query_text.lower()
            if "disponibilidad" in q_lower or "flota hoy" in q_lower or "como esta la flota" in q_lower or "cómo está la flota" in q_lower:
                # Contar del caché
                with cache_lock:
                    total = len(cache["sync_status"])
                    online = sum(1 for d in cache["sync_status"] if d["status"] == "Online")
                    pct = (online / total * 100) if total > 0 else 0
                response_text = f"La disponibilidad actual es del {pct:.1f}% ({online} de {total} equipos piloto están online). Hay {total - online} offline."
                intent = "consultar_disponibilidad"
                
            elif "alerta" in q_lower or "critica" in q_lower or "crítica" in q_lower or "problema" in q_lower:
                with cache_lock:
                    # Buscar alertas
                    alerts = [m for m in cache["latest_metrics"] if m.get("cause_root") is not None]
                if alerts:
                    dev = alerts[0]
                    response_text = f"Sí, se detecta 1 alerta activa: {dev['device_id']} ({dev['device_type']}) reporta uso de CPU={dev['cpu_usage']}% | Causa: {dev['cause_root']} ({dev['cause_process']})."
                else:
                    response_text = "No se detectaron alertas críticas activas de hardware en la flota en este momento."
                intent = "consultar_alertas"
                
            elif "puerto" in q_lower or "usb" in q_lower or "seguridad" in q_lower:
                with cache_lock:
                    total_events = len(cache["security_events"])
                response_text = f"Se detectaron puertos abiertos en la flota piloto exponiendo el puerto TCP 445 (SMB) con severidad Media. Total eventos registrados: {total_events}."
                intent = "consultar_seguridad_pasiva"
            elif "productividad" in q_lower or "ocio" in q_lower or "redes" in q_lower or "aplicaci" in q_lower:
                response_text = "El índice de productividad promedio de la flota piloto es del 78%. El 12% del tiempo se concentra en navegación de ocio (WhatsApp Web, YouTube) y el resto en aplicaciones de ofimática (Word, Excel) y comunicación (Teams, Outlook)."
                intent = "consultar_productividad"
                
            elif "equipo" in q_lower or "computador" in q_lower or "dispositivo" in q_lower:
                with cache_lock:
                    devices_list = [d["device_id"] for d in cache["sync_status"]]
                    online_list = [d["device_id"] for d in cache["sync_status"] if d["status"] == "Online"]
                response_text = f"La flota piloto cuenta con {len(devices_list)} equipos registrados: {', '.join(devices_list)}. De estos, {len(online_list)} están actualmente conectados en tiempo real: {', '.join(online_list)}."
                intent = "consultar_dispositivos"
                
            elif "incidente" in q_lower or "ticket" in q_lower or "soporte" in q_lower or "mesa" in q_lower:
                response_text = "Actualmente hay 12 incidentes abiertos en la Mesa de Ayuda. El ticket más crítico es #INC-2851 relacionado con uso elevado de RAM (Chrome a 94% de uso sostenido) en el equipo LAPTOP-MROJAS."
                intent = "consultar_soporte"
                
            new_interaction = {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "phone_number": "+573123456789",
                "user_query": query_text,
                "bot_response": response_text,
                "intent_detected": intent,
                "tokens_used": int(len(query_text) * 1.5 + len(response_text) * 0.8)
            }
            
            # Guardar en BigQuery
            try:
                run_bq_insert("endpointiq.eq_whatsapp_interactions", new_interaction)
                with cache_lock:
                    cache["whatsapp"].insert(0, new_interaction) # Insertar al inicio
                self.send_json({"success": True, "response": response_text, "interaction": new_interaction})
            except Exception as e:
                self.send_json({"success": False, "error": str(e)}, 500)
                
        else:
            self.send_json({"error": "Endpoint no encontrado"}, 404)

    def _build_per_device_apps(self, per_device_app_count, app_icons, system_procs):
        """Build desktop_apps list for each device."""
        result = {}
        for d_id, apps in per_device_app_count.items():
            sorted_desktop = sorted(
                [(k, v) for k, v in apps.items() if not any(s in k.lower() for s in system_procs)],
                key=lambda x: x[1], reverse=True
            )[:8]
            if not sorted_desktop:
                continue
            max_desk = sorted_desktop[0][1]
            total_desk = sum(v for _, v in sorted_desktop) or 1
            device_apps = []
            for dname, dval in sorted_desktop:
                icon, color = "⚙️", "#64748B"
                for key, (ic, cl) in app_icons.items():
                    if key in dname.lower():
                        icon, color = ic, cl
                        break
                hours = round(dval / total_desk * 8, 1)
                pct = int(dval / max_desk * 100)
                device_apps.append({
                    "name": dname, "icon": icon, "color": color,
                    "hours": f"{hours}h", "pct": pct,
                    "pct_label": f"{int(dval/total_desk*100)}%"
                })
            # Also build top_apps for this device
            sorted_top = sorted(apps.items(), key=lambda x: x[1], reverse=True)[:6]
            max_u = sorted_top[0][1] if sorted_top else 1
            top = [{"name": a[0], "hours": round(a[1] * 0.5, 1), "pct": int(a[1] / max_u * 100)} for a in sorted_top]
            result[d_id] = {"desktop_apps": device_apps, "top_apps": top}
        return result

    def _build_per_device_web(self, unique_devices):
        """Build web_pages list for each device from browser_history."""
        work_domains = {"sharepoint.com", "office.com", "office365.com", "github.com", 
                       "gitlab.com", "bitbucket.org", "docs.google.com", "drive.google.com",
                       "notion.so", "trello.com", "jira.atlassian.com", "stackoverflow.com",
                       "dev.azure.com", ".gov.co", "sap.com"}
        comm_domains = {"outlook.com", "outlook.office.com", "teams.microsoft.com", 
                       "slack.com", "meet.google.com", "zoom.us", "calendar.google.com"}
        ocio_domains = {"youtube.com", "netflix.com", "tiktok.com", "instagram.com",
                       "facebook.com", "twitter.com", "x.com", "reddit.com", "twitch.tv"}
        
        result = {}
        for dev in unique_devices:
            d_id = dev.get("device_id", "")
            bh_data = None
            for m in cache["latest_metrics"]:
                if m.get("device_id") == d_id:
                    bh_raw = m.get("browser_history")
                    if bh_raw and bh_raw != "[]" and bh_raw != "null":
                        bh_data = bh_raw
                    break
            if not bh_data:
                for m in cache.get("all_metrics", []):
                    if m.get("device_id") == d_id:
                        bh_raw = m.get("browser_history")
                        if bh_raw and bh_raw != "[]" and bh_raw != "null":
                            bh_data = bh_raw
                            break
            if not bh_data:
                continue
            bh = bh_data
            if isinstance(bh, str):
                try: bh = json.loads(bh)
                except: bh = []
            if not isinstance(bh, list):
                bh = []
            
            device_domains = {}
            for entry in bh:
                domain = entry.get("domain", "")
                visits = entry.get("visits", 1)
                if domain:
                    device_domains[domain] = device_domains.get(domain, 0) + visits
            
            if not device_domains:
                continue
            
            total_visits = sum(device_domains.values())
            sorted_bd = sorted(device_domains.items(), key=lambda x: x[1], reverse=True)[:10]
            pages = []
            for domain, visits in sorted_bd:
                cat, cls = "Web", "cat-web"
                dl = domain.lower()
                if any(w in dl for w in work_domains):
                    cat, cls = "Trabajo", "cat-trabajo"
                elif any(c in dl for c in comm_domains):
                    cat, cls = "Comun.", "cat-comun"
                elif any(o in dl for o in ocio_domains):
                    cat, cls = "Ocio", "cat-social"
                proportion = visits / max(total_visits, 1)
                total_mins = int(8 * 60 * proportion)
                h = total_mins // 60
                mi = total_mins % 60
                pages.append({"domain": domain, "category": cat, "cat_class": cls,
                             "time": f"{h}h {mi:02d}m", "visits": visits})
            result[d_id] = pages
        return result

    def send_json(self, data, status_code=200):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        # Habilitar CORS para pruebas locales
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

def start_server():
    # En Cloud Run se debe escuchar en 0.0.0.0; localmente en localhost
    host = '0.0.0.0' if os.environ.get('K_SERVICE') else 'localhost'
    server = HTTPServer((host, PORT), EndpointIQRequestHandler)
    print(f"Consola web de EndpointIQ iniciada en http://{host}:{PORT}")
    if os.environ.get('K_SERVICE'):
        print(f"[Cloud Run] Servicio: {os.environ.get('K_SERVICE')}, Revision: {os.environ.get('K_REVISION')}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print("Servidor detenido.")

if __name__ == "__main__":
    start_server()
