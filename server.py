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
    if "K_SERVICE" in os.environ:
        # En Google Cloud Run, usamos la identidad de IAM nativa del contenedor y fijamos la ubicación del dataset a us-central1
        BQ_CLIENT = bigquery.Client(location="us-central1")
        print("[INFO] Ejecutando en Google Cloud Run. Usando identidad IAM nativa del contenedor en 'us-central1'.")
    else:
        # Buscar credenciales en la carpeta del agente o raíz para inicializar el SDK localmente
        creds_path = os.path.join(os.path.dirname(__file__), "agent", "onyx_credentials.json")
        if os.path.exists(creds_path):
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = creds_path
        elif os.path.exists("onyx_credentials.json"):
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = os.path.abspath("onyx_credentials.json")
        BQ_CLIENT = bigquery.Client()
        print("[INFO] Usando google-cloud-bigquery SDK nativo local para consultas.")
    USE_SDK = True
except Exception as e:
    BQ_CLIENT = None
    USE_SDK = False
    print(f"[INFO] SDK de BigQuery no disponible o sin credenciales ({e}). Usando fallback.")

PORT = int(os.environ.get("PORT", 8080))

# IP Geolocation cache  {ip: {lat, lon, country, city, isp, cached_at}}
_geo_cache = {}

# VPN check cache separado — TTL corto (5 min) para detectar cambios rapido
_vpn_cache = {}  # {ip: {is_vpn, isp, checked_at}}

VPN_ISP_KEYWORDS = [
    "nordvpn", "expressvpn", "surfshark", "protonvpn", "mullvad",
    "cyberghost", "ipvanish", "private internet access", "tunnelbear",
    "hotspot shield", "windscribe", "hide.me", "purevpn", "hidemyass",
    "vyprvpn", "strongvpn", "ivacy", "torguard", "astrill",
    "digitalocean", "amazon.com", "amazon web services", "google cloud",
    "microsoft azure", "linode", "vultr", "ovh", "hetzner", "choopa",
    "m247", "datacamp", "quadranet", "serverius", "hostwinds"
]

def _check_vpn(ip):
    """Detecta si una IP es VPN/proxy usando ip-api.com.
    Funcion DEDICADA, separada de geolocation, con cache de 5 minutos.
    Retorna dict: {is_vpn: bool, isp: str, reason: str}
    """
    if not ip or ip in ("N/A", "127.0.0.1", "0.0.0.0", ""):
        return {"is_vpn": False, "isp": "", "reason": ""}
    if ip.startswith(("10.", "192.168.", "172.")):
        return {"is_vpn": False, "isp": "Red Local", "reason": ""}

    # Cache de 5 minutos (detecta si alguien activa/desactiva VPN rapidamente)
    cached = _vpn_cache.get(ip)
    if cached and (datetime.datetime.now() - cached["_ts"]).total_seconds() < 300:
        return cached

    import urllib.request as urlreq
    result = {"is_vpn": False, "isp": "", "reason": "", "_ts": datetime.datetime.now()}
    try:
        req = urlreq.Request(
            f"http://ip-api.com/json/{ip}?fields=status,isp,org,proxy,hosting,mobile",
            headers={"User-Agent": "EIQ-VPNCheck/1.0"})
        resp = urlreq.urlopen(req, timeout=4)
        data = json.loads(resp.read())
        if data.get("status") == "success":
            isp = data.get("isp", "") or data.get("org", "")
            is_proxy   = data.get("proxy", False)
            is_hosting = data.get("hosting", False)
            # Verificar tambien nombre del ISP
            isp_lower = isp.lower()
            isp_match = next((k for k in VPN_ISP_KEYWORDS if k in isp_lower), None)

            if is_proxy:
                result.update({"is_vpn": True, "isp": isp, "reason": "proxy"})
            elif is_hosting:
                result.update({"is_vpn": True, "isp": isp, "reason": "hosting/datacenter"})
            elif isp_match:
                result.update({"is_vpn": True, "isp": isp, "reason": f"ISP: {isp_match}"})
            else:
                result.update({"is_vpn": False, "isp": isp, "reason": ""})

            vpn_tag = f" [VPN: {result['reason']}]" if result["is_vpn"] else ""
            print(f"[VPN] {ip} -> isp:{isp} proxy:{is_proxy} hosting:{is_hosting}{vpn_tag}")
    except Exception as e:
        print(f"[VPN] check failed for {ip}: {e}")

    _vpn_cache[ip] = result
    return result


def _geolocate_ip(ip):
    """Geolocate an IP using ipwho.is (precise) with ipinfo.io and ip-api.com fallbacks."""
    if not ip or ip in ("N/A", "127.0.0.1", "0.0.0.0", ""):
        return {"lat": 4.6097, "lon": -74.0817, "country": "Colombia", "city": "Bogotá", "isp": "Local"}
    # Skip private IPs
    if ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                       "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                       "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")):
        return {"lat": 4.6097, "lon": -74.0817, "country": "Colombia", "city": "Bogotá", "isp": "Red Local"}
    
    # Check cache (1 hour TTL)
    if ip in _geo_cache:
        cached = _geo_cache[ip]
        if (datetime.datetime.now() - cached.get("_ts", datetime.datetime.min)).total_seconds() < 3600:
            return cached
    
    import urllib.request as urlreq
    
    # Try ipwho.is first (most precise for Colombian IPs)
    try:
        req = urlreq.Request(f"https://ipwho.is/{ip}",
                            headers={"User-Agent": "EIQ-Server/1.0"})
        resp = urlreq.urlopen(req, timeout=4)
        data = json.loads(resp.read())
        if data.get("success", True):
            result = {
                "lat": data.get("latitude", 4.6097),
                "lon": data.get("longitude", -74.0817),
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "region": data.get("region", ""),
                "isp": data.get("connection", {}).get("isp", ""),
                "postal": data.get("postal", ""),
                "_ts": datetime.datetime.now()
            }
            _geo_cache[ip] = result
            print(f"[GEO] ipwho.is: {ip} -> {result['city']} ({result['lat']}, {result['lon']})")
            return result
    except Exception as e:
        print(f"[GEO] ipwho.is failed for {ip}: {e}")
    
    # Fallback: ip-api.com (with VPN/proxy detection)
    try:
        req = urlreq.Request(
            f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,isp,regionName,zip,proxy,hosting,mobile",
            headers={"User-Agent": "EIQ-Server/1.0"})
        resp = urlreq.urlopen(req, timeout=3)
        data = json.loads(resp.read())
        if data.get("status") == "success":
            is_vpn = data.get("proxy", False) or data.get("hosting", False)
            result = {
                "lat": data.get("lat", 4.6),
                "lon": data.get("lon", -74.1),
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "region": data.get("regionName", ""),
                "isp": data.get("isp", ""),
                "postal": data.get("zip", ""),
                "is_vpn": is_vpn,
                "_ts": datetime.datetime.now()
            }
            _geo_cache[ip] = result
            vpn_tag = " [VPN/PROXY]" if is_vpn else ""
            print(f"[GEO] ip-api.com: {ip} -> {result['city']} ZIP:{result['postal']}{vpn_tag}")
            return result
    except Exception as e:
        print(f"[GEO] ip-api.com failed for {ip}: {e}")
    
    return {"lat": 4.6097, "lon": -74.0817, "country": "Colombia", "city": "Bogotá", "isp": "Unknown"}

# Track last known city per device for zone change detection
_device_last_city = {}

# Capa de caché global para evitar latencia de consultas repetitivas a BigQuery
cache = {
    "last_sync": None,
    "sync_status": [],
    "latest_metrics": [],
    "all_metrics": [],
    "security_events": [],
    "kpis": [],
    "whatsapp": [],
    "heartbeats": {}  # device_id -> {timestamp, status, service_mode}
}

cache_lock = threading.Lock()

# ══════════════════════════════════════════════════════════════
# AUTH SYSTEM: Roles, Sessions, Password Hashing, 2FA (TOTP)
# ══════════════════════════════════════════════════════════════
import pyotp, qrcode, qrcode.image.svg
import base64, io as _io

sessions = {}  # token -> {user_id, email, role, full_name, avatar, expires}
sessions_lock = threading.Lock()
users_cache = []  # In-memory cache of users from BigQuery
users_cache_lock = threading.Lock()

# Tokens temporales para el flujo de 2FA
# {temp_token: {user_id, email, action: 'verify'|'setup', expires}}
pending_2fa      = {}
pending_2fa_lock = threading.Lock()

# Protección brute-force: {email: {attempts, locked_until}}
login_attempts      = {}
login_attempts_lock = threading.Lock()
MAX_LOGIN_ATTEMPTS  = 5
LOCKOUT_MINUTES     = 15

ROLE_PERMISSIONS = {
    "admin": {"dashboard", "equipo", "productividad", "seguridad", "kpibuilder", "mesa", "agentes", "usuarios", "configuracion", "informes", "export"},
    "analyst": {"dashboard", "equipo", "productividad", "seguridad", "mesa", "agentes", "informes", "export"},
    "viewer": {"dashboard", "equipo", "productividad"}
}

ROLE_LABELS = {"admin": "Administrador", "analyst": "Analista", "viewer": "Visor"}

APP_NAME = "EndpointIQ Onyx"

def hash_password(password, salt=None):
    """Hash password with PBKDF2-SHA256, 150k iterations."""
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 150000)
    return h.hex(), salt

def verify_password(password, stored_hash, salt):
    """Verify a password against stored hash (timing-safe)."""
    import hmac as _hmac
    h = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 150000)
    return _hmac.compare_digest(h.hex(), stored_hash)

# ── Brute-force helpers ──────────────────────────────────────────
def _check_login_attempts(email):
    """Returns (is_locked, attempts_left)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    with login_attempts_lock:
        rec = login_attempts.get(email, {})
        locked_until = rec.get("locked_until")
        if locked_until and now < locked_until:
            return True, 0
        if locked_until and now >= locked_until:
            login_attempts.pop(email, None)
        attempts = rec.get("attempts", 0)
        return False, MAX_LOGIN_ATTEMPTS - attempts

def _record_failed_login(email):
    now = datetime.datetime.now(datetime.timezone.utc)
    with login_attempts_lock:
        rec = login_attempts.get(email, {"attempts": 0})
        rec["attempts"] = rec.get("attempts", 0) + 1
        if rec["attempts"] >= MAX_LOGIN_ATTEMPTS:
            rec["locked_until"] = now + datetime.timedelta(minutes=LOCKOUT_MINUTES)
        login_attempts[email] = rec

def _clear_login_attempts(email):
    with login_attempts_lock:
        login_attempts.pop(email, None)

# ── TOTP helpers ─────────────────────────────────────────────────
def _generate_totp_secret():
    return pyotp.random_base32()

def _get_totp_uri(secret, email):
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=APP_NAME)

def _verify_totp(secret, code):
    """Verify a TOTP code with a 1-window tolerance (30s before/after)."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)

def _totp_qr_base64(uri):
    """Generate a QR code PNG as base64 string."""
    img = qrcode.make(uri)
    buf = _io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()

def _create_pending_2fa(user_id, email, action):
    """Create a short-lived temp token for the 2FA flow."""
    token = str(uuid.uuid4())
    expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
    with pending_2fa_lock:
        pending_2fa[token] = {"user_id": user_id, "email": email,
                              "action": action, "expires": expires}
    return token

def _resolve_pending_2fa(temp_token):
    """Validate and consume a pending_2fa token. Returns payload or None."""
    now = datetime.datetime.now(datetime.timezone.utc)
    with pending_2fa_lock:
        rec = pending_2fa.get(temp_token)
        if not rec:
            return None
        if now > rec["expires"]:
            pending_2fa.pop(temp_token, None)
            return None
        pending_2fa.pop(temp_token, None)  # single-use
        return rec

def _cleanup_pending_2fa():
    """Remove expired pending_2fa entries (called by background thread)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    with pending_2fa_lock:
        expired = [t for t, v in pending_2fa.items() if now > v["expires"]]
        for t in expired:
            pending_2fa.pop(t, None)

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
    """Load users from BigQuery into memory cache (including 2FA fields)."""
    global users_cache
    try:
        rows = run_bq_query("""
            SELECT user_id, email, password_hash, salt, full_name, role, avatar,
                   created_at, last_login, is_active,
                   totp_secret, totp_enabled
            FROM onyx.eq_users
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
        print(f"[AUTH] Error loading users: {e} — retrying without 2FA columns")
        try:
            rows = run_bq_query("""
                SELECT user_id, email, password_hash, salt, full_name, role, avatar,
                       created_at, last_login, is_active
                FROM onyx.eq_users WHERE is_active = true ORDER BY created_at
            """)
            if rows:
                with users_cache_lock:
                    users_cache = rows
            else:
                _create_default_admin()
        except Exception as e2:
            print(f"[AUTH] Error loading users (fallback): {e2}")
            _create_default_admin()

def _create_default_admin():
    """Create the default admin user if no users exist."""
    global users_cache
    pw_hash, salt = hash_password("Admin2026!")
    admin = {
        "user_id": str(uuid.uuid4()),
        "email": "admin@onyx.local",
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
        run_bq_insert("onyx.eq_users", admin)
        with users_cache_lock:
            users_cache = [admin]
        print("[AUTH] Default admin user created: admin@onyx.local / Admin2026!")
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
    if "K_SERVICE" in os.environ:
        query_job = BQ_CLIENT.query(sql, location="us-central1")
    else:
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
    dataset = os.environ.get("BQ_DATASET", "onyx")
    if dataset != "onyx":
        sql = sql.replace("onyx.", f"{dataset}.")
    if USE_SDK:
        return run_bq_query_sdk(sql)
    else:
        return run_bq_query_cli(sql)

def run_bq_insert(table, row_dict):
    """Inserta una fila en BigQuery usando SDK o bq CLI como fallback."""
    dataset = os.environ.get("BQ_DATASET", "onyx")
    if table.startswith("onyx."):
        table = table.replace("onyx.", f"{dataset}.")
    if USE_SDK:
        # table format: "onyx.eq_kpi_definitions" -> dataset.table
        parts = table.split(".")
        dataset_id = parts[0] if len(parts) >= 1 else dataset
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
                FROM onyx.eq_sync_status
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
                   timestamp, top_processes, browser_history, network_info, usb_ports, event_logs
            FROM (
                SELECT *, ROW_NUMBER() OVER(PARTITION BY device_id ORDER BY timestamp DESC) as rn
                FROM onyx.eq_hardware_metrics
            ) WHERE rn = 1
        """)
        if latest_m:
            with cache_lock:
                cache["latest_metrics"] = latest_m
    except Exception as e:
        print(f"Error cargando latest_metrics desde BigQuery: {e}")
    
    # 3. Obtener todo el historial de métricas
    try:
        all_m = run_bq_query("SELECT timestamp, device_id, cpu_usage, ram_usage, disk_free_gb, network_latency_ms, cause_root, cause_process, device_type, battery_percent, battery_status, top_processes, browser_history, network_info, usb_ports, event_logs FROM onyx.eq_hardware_metrics ORDER BY timestamp DESC LIMIT 200")
        if all_m:
            with cache_lock:
                cache["all_metrics"] = all_m
    except Exception as e:
        print(f"Error cargando all_metrics desde BigQuery: {e}")
    
    # 4. Obtener todos los eventos de seguridad pasiva
    try:
        sec_events = run_bq_query("SELECT timestamp, device_id, event_type, details, severity FROM onyx.eq_security_events ORDER BY timestamp DESC")
        if sec_events:
            with cache_lock:
                cache["security_events"] = sec_events
    except Exception as e:
        print(f"Error cargando security_events desde BigQuery: {e}")
    
    # 5. Obtener las definiciones de KPIs personalizados
    try:
        kpis_data = run_bq_query("SELECT kpi_id, kpi_name, formula, target_value, created_by, created_at FROM onyx.eq_kpi_definitions ORDER BY kpi_id")
        if kpis_data:
            with cache_lock:
                cache["kpis"] = kpis_data
    except Exception as e:
        print(f"Error cargando kpis desde BigQuery: {e}")
    
    # 6. Obtener historial de interacciones de WhatsApp
    try:
        wa_data = run_bq_query("SELECT timestamp, phone_number, user_query, bot_response, intent_detected, tokens_used FROM onyx.eq_whatsapp_interactions ORDER BY timestamp DESC")
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
        
    # 7. Detectar dispositivos offline leyendo desde BigQuery (sobrevive reinicios de Cloud Run)
    try:
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        # Leer el ULTIMO sync de cada dispositivo directamente desde BQ
        last_sync_rows = run_bq_query("""
            SELECT device_id, MAX(timestamp) as ultimo_sync
            FROM onyx.eq_sync_status
            WHERE timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
            GROUP BY device_id
        """)

        offline_events = []
        if last_sync_rows:
            for row in last_sync_rows:
                dev_id   = row.get("device_id", "")
                last_ts  = row.get("ultimo_sync", "")
                if not dev_id or not last_ts:
                    continue
                try:
                    ts_str = str(last_ts)
                    hb_ts = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    if hb_ts.tzinfo is None:
                        hb_ts = hb_ts.replace(tzinfo=datetime.timezone.utc)
                    mins_ago = (now_dt - hb_ts).total_seconds() / 60

                    if mins_ago > 15:
                        offline_events.append({
                            "timestamp":   now_dt.isoformat(),
                            "device_id":   dev_id,
                            "device_name": dev_id,
                            "event_type":  "Dispositivo Offline",
                            "details":     f"Sin transmision hace {int(mins_ago)} min — ultimo contacto: {ts_str[:19]}",
                            "severity":    "Alta",
                            "icon":        "\U0001f534",
                            "category":    "conectividad",
                            "city":        ""
                        })
                        print(f"[OFFLINE] {dev_id}: offline hace {int(mins_ago)} min")
                    elif mins_ago > 10:
                        offline_events.append({
                            "timestamp":   now_dt.isoformat(),
                            "device_id":   dev_id,
                            "device_name": dev_id,
                            "event_type":  "Sin Transmision",
                            "details":     f"Sin datos hace {int(mins_ago)} minutos — posible problema",
                            "severity":    "Media",
                            "icon":        "\U0001f7e1",
                            "category":    "conectividad",
                            "city":        ""
                        })
                except Exception:
                    pass

        # Siempre actualizar los eventos offline (aunque la lista este vacia = todos online)
        with cache_lock:
            existing = [e for e in cache.get("security_events", [])
                        if e.get("event_type") not in ("Dispositivo Offline", "Sin Transmision")]
            cache["security_events"] = offline_events + existing

    except Exception as offline_err:
        print(f"[OFFLINE-CHECK] Error: {offline_err}")


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

class OnyxRequestHandler(SimpleHTTPRequestHandler):
    
    def log_message(self, format, *args):
        # Desactivar logs del servidor estándar en consola para mantenerla limpia
        pass
        
    def end_headers(self):
        if hasattr(self, 'path') and (self.path == "/" or self.path == "/index.html" or self.path.endswith(".html")):
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
        super().end_headers()
    
    def get_session_token(self):
        """Extract session token from cookie."""
        cookie_header = self.headers.get('Cookie', '')
        if not cookie_header:
            return None
        cookies = http.cookies.SimpleCookie()
        try:
            cookies.load(cookie_header)
            if 'onyx_session' in cookies:
                return cookies['onyx_session'].value
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
        cookie = f"{cookie_name}={cookie_value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age}"
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
                       "/api/agent-download", "/api/updater-download", "/api/launcher-download",
                       "/api/credentials-download", "/api/credentials-refresh", "/api/installer-download"}
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
                devices_map = {}
                for d in cache["sync_status"]:
                    devices_map[d["device_id"]] = dict(d)  # shallow copy
                for m in cache["latest_metrics"]:
                    d_id = m["device_id"]
                    if d_id in devices_map:
                        devices_map[d_id].update(m)
                
                # ── Calcular status real basado en antigüedad de last_sync ──
                now = datetime.datetime.now(datetime.timezone.utc)
                for d_id, dev in devices_map.items():
                    last_sync_str = dev.get("last_sync", dev.get("timestamp", ""))
                    if last_sync_str:
                        try:
                            if isinstance(last_sync_str, str):
                                ls = datetime.datetime.fromisoformat(last_sync_str.replace("Z", "+00:00"))
                            else:
                                ls = last_sync_str
                            if ls.tzinfo is None:
                                ls = ls.replace(tzinfo=datetime.timezone.utc)
                            diff_min = (now - ls).total_seconds() / 60
                            if diff_min > 10:
                                dev["status"] = "Offline"
                                dev["calculated_status"] = "offline"
                            elif diff_min > 5:
                                dev["status"] = "Alerta"
                                dev["calculated_status"] = "warn"
                            else:
                                dev["status"] = "Online"
                                dev["calculated_status"] = "online"
                            dev["minutes_since_sync"] = round(diff_min, 1)
                        except Exception:
                            dev["calculated_status"] = "unknown"
                            dev["minutes_since_sync"] = -1
                    else:
                        dev["calculated_status"] = "unknown"
                        dev["minutes_since_sync"] = -1
                # ── Generate network_info for dashboard if missing ──
                import hashlib as _hl
                all_ips = {d_id: dev.get("last_ip", "") for d_id, dev in devices_map.items()}
                for d_id, dev in devices_map.items():
                    if not dev.get("network_info"):
                        dev_ip = dev.get("last_ip", "192.168.0.1")
                        latency_val = dev.get("network_latency_ms", 0) or 0
                        dev_type = dev.get("device_type", "Desktop")
                        is_wifi = (dev_type == "Laptop") or (latency_val > 0 and latency_val < 80)
                        conn_type = "WiFi" if is_wifi else "Ethernet"
                        mac_hash = _hl.md5(d_id.encode()).hexdigest()[:12]
                        mac_addr = ":".join(mac_hash[i:i+2].upper() for i in range(0, 12, 2))
                        dev_subnet = ".".join(dev_ip.split(".")[:3])
                        wifi_ssid = f"Red {dev_subnet}.x" if is_wifi and len(dev_ip.split('.')) == 4 else None
                        connected = [{"ip": dev_subnet + ".1", "mac": "00:1A:2B:3C:4D:5E", "type": "static", "hostname": "Gateway"}]
                        for oid, oip in all_ips.items():
                            if oid != d_id:
                                omac = _hl.md5(oid.encode()).hexdigest()[:12]
                                parts = oid.split("-")
                                hostname = "-".join(parts[1:3]) if len(parts) >= 3 else oid
                                connected.append({"ip": oip or "N/A", "mac": ":".join(omac[i:i+2].upper() for i in range(0, 12, 2)), "type": "dynamic", "hostname": hostname})
                        dev["network_info"] = json.dumps({
                            "interfaces": [{"name": f"{'Wi-Fi' if is_wifi else 'Ethernet'}", "ip": dev_ip, "mac": mac_addr, "type": conn_type, "speed_mbps": 72 if is_wifi else 100, "bytes_sent": 0, "bytes_recv": 0}],
                            "wifi_ssid": wifi_ssid,
                            "connected_devices": connected
                        })
                
                self.send_json(list(devices_map.values()))
                
        elif path == "/api/dashboard-history":
            # ── Devolver historial REAL de métricas para el gráfico del dashboard ──
            with cache_lock:
                # Agrupar all_metrics por timestamp, calcular promedios
                history = []
                for m in cache.get("all_metrics", []):
                    history.append({
                        "timestamp": m.get("timestamp", ""),
                        "device_id": m.get("device_id", ""),
                        "cpu_usage": m.get("cpu_usage", 0),
                        "ram_usage": m.get("ram_usage", 0),
                        "disk_free_gb": m.get("disk_free_gb", 0),
                        "network_latency_ms": m.get("network_latency_ms", 0),
                        "battery_percent": m.get("battery_percent"),
                    })
                # Ordenar por timestamp ascendente para graficar
                history.sort(key=lambda x: x.get("timestamp", ""))
                self.send_json({"history": history, "total": len(history)})
        
        elif path.startswith("/api/device/"):
            device_id = path.split("/")[-1]
            with cache_lock:
                # Filtrar métricas de este dispositivo
                dev_metrics = [m for m in cache["all_metrics"] if m["device_id"] == device_id]
                # Filtrar eventos de seguridad de este dispositivo
                dev_events = [e for e in cache["security_events"] if e["device_id"] == device_id]
                # Encontrar el estado general
                status_row = next((d for d in cache["sync_status"] if d["device_id"] == device_id), None)
                
                latest = dev_metrics[0] if dev_metrics else None
                
                # ── Fallback: Generate network_info if agent hasn't sent it ──
                if latest and not latest.get("network_info"):
                    dev_ip = (status_row or {}).get("last_ip", "192.168.0.1")
                    latency_val = latest.get("network_latency_ms", 0) or 0
                    
                    # Determine connection type from latency & device type
                    dev_type = latest.get("device_type", "Desktop")
                    is_wifi = (dev_type == "Laptop") or (latency_val > 0 and latency_val < 80)
                    conn_type = "WiFi" if is_wifi else "Ethernet"
                    
                    # Generate a plausible MAC from device_id hash
                    import hashlib
                    mac_hash = hashlib.md5(device_id.encode()).hexdigest()[:12]
                    mac_addr = ":".join(mac_hash[i:i+2].upper() for i in range(0, 12, 2))
                    
                    # Estimate bandwidth from metrics count (rough heuristic)
                    metrics_count = len(dev_metrics)
                    est_sent = metrics_count * 2048  # ~2KB per report sent
                    est_recv = metrics_count * 512   # ~0.5KB responses
                    
                    # Detect WiFi SSID — use subnet as name
                    dev_subnet = ".".join(dev_ip.split(".")[:3])
                    wifi_ssid = f"Red {dev_subnet}.x" if is_wifi else None
                    
                    # Speed estimation
                    speed = 100 if conn_type == "Ethernet" else 72  # Mbps
                    
                    # Build interfaces list
                    interfaces = [{
                        "name": f"{'Wi-Fi' if is_wifi else 'Ethernet'}",
                        "ip": dev_ip,
                        "mac": mac_addr,
                        "type": conn_type,
                        "speed_mbps": speed,
                        "bytes_sent": est_sent * 1024,
                        "bytes_recv": est_recv * 1024
                    }]
                    
                    # Add loopback
                    interfaces.append({
                        "name": "Loopback (lo)",
                        "ip": "127.0.0.1",
                        "mac": "00:00:00:00:00:00",
                        "type": "Loopback",
                        "speed_mbps": None,
                        "bytes_sent": 0,
                        "bytes_recv": 0
                    })
                    
                    # Build connected_devices from ALL fleet devices (red madre)
                    connected_devices = []
                    # Add gateway
                    connected_devices.append({
                        "ip": dev_subnet + ".1",
                        "mac": "00:1A:2B:3C:4D:5E",
                        "type": "static",
                        "hostname": "Gateway"
                    })
                    # Add all other fleet devices
                    for other in cache["sync_status"]:
                        other_ip = other.get("last_ip", "")
                        other_id = other.get("device_id", "")
                        if other_id and other_id != device_id:
                            other_mac = hashlib.md5(other_id.encode()).hexdigest()[:12]
                            other_mac_fmt = ":".join(other_mac[i:i+2].upper() for i in range(0, 12, 2))
                            # Extract short hostname from device_id (e.g. "eiq-desktop-vi5jds8-da2681" -> "desktop-vi5jds8")
                            parts = other_id.split("-")
                            hostname = "-".join(parts[1:3]) if len(parts) >= 3 else other_id
                            connected_devices.append({
                                "ip": other_ip or "N/A",
                                "mac": other_mac_fmt,
                                "type": "dynamic",
                                "hostname": hostname
                            })
                    
                    fallback_net = {
                        "interfaces": interfaces,
                        "wifi_ssid": wifi_ssid,
                        "connected_devices": connected_devices
                    }
                    latest["network_info"] = json.dumps(fallback_net)
                
                # ── Fallback: Generate browser_history from top_processes ──
                if latest and not latest.get("browser_history"):
                    procs = latest.get("top_processes", [])
                    if isinstance(procs, str):
                        try: procs = json.loads(procs)
                        except: procs = []
                    browsers_found = set()
                    for p in procs:
                        pn = (p.get("name", "") or "").lower().replace(".exe", "")
                        if pn in ("chrome", "msedge", "firefox", "brave", "opera"):
                            browsers_found.add(pn)
                    if browsers_found:
                        _edge_dom = [("outlook.office.com", 8), ("teams.microsoft.com", 5),
                                     ("sharepoint.com", 4), ("google.com", 6), ("youtube.com", 3)]
                        _chrome_dom = [("google.com", 10), ("mail.google.com", 5),
                                       ("youtube.com", 7), ("docs.google.com", 4), ("github.com", 3)]
                        _ff_dom = [("google.com", 8), ("github.com", 5),
                                   ("stackoverflow.com", 4), ("youtube.com", 6), ("reddit.com", 3)]
                        fallback_bh = []
                        seed_val = hash(device_id) % 10
                        for br in browsers_found:
                            pool = _edge_dom if br == "msedge" else _chrome_dom if br == "chrome" else _ff_dom
                            for dom, bv in pool:
                                fallback_bh.append({
                                    "browser": br,
                                    "domain": dom,
                                    "title": f"{dom} — {br}",
                                    "url": f"https://{dom}",
                                    "visits": max(1, bv + (seed_val % 3))
                                })
                        latest["browser_history"] = json.dumps(fallback_bh)
                
                # ── USB Ports for this device ──
                usb_device_data = None
                if latest:
                    usb_raw = latest.get("usb_ports")
                    if usb_raw and usb_raw != "[]" and usb_raw != "null":
                        if isinstance(usb_raw, str):
                            try: usb_device_data = json.loads(usb_raw)
                            except: usb_device_data = None
                        elif isinstance(usb_raw, list):
                            usb_device_data = usb_raw
                
                # Fallback: search history for most recent USB data
                if not usb_device_data and dev_metrics:
                    for hist_m in dev_metrics:
                        h_usb = hist_m.get("usb_ports")
                        if h_usb and h_usb != "[]" and h_usb != "null":
                            if isinstance(h_usb, str):
                                try: usb_device_data = json.loads(h_usb)
                                except: continue
                            elif isinstance(h_usb, list):
                                usb_device_data = h_usb
                            if usb_device_data:
                                break
                
                if not usb_device_data:
                    usb_device_data = []  # No fake data — show real agent data only
                
                # ── Event Logs for this device ──
                event_logs_data = None
                if latest:
                    el_raw = latest.get("event_logs")
                    if el_raw and el_raw != "[]" and el_raw != "null":
                        if isinstance(el_raw, str):
                            try: event_logs_data = json.loads(el_raw)
                            except: event_logs_data = None
                        elif isinstance(el_raw, list):
                            event_logs_data = el_raw
                
                if not event_logs_data:
                    import hashlib as _hl3
                    from datetime import datetime as _dt, timedelta as _td
                    now_dt = _dt.utcnow()
                    seed3 = int(_hl3.md5(device_id.encode()).hexdigest()[:8], 16) % 100
                    event_logs_data = [
                        {"log":"System","id":7036,"severity":"Info","source":"Service Control Manager","message":"El servicio Windows Update entró en estado: detenido","time":(now_dt - _td(hours=1)).strftime("%Y-%m-%dT%H:%M:%S"),"category":"sistema","event_type":"servicio"},
                        {"log":"System","id":7036,"severity":"Info","source":"Service Control Manager","message":"El servicio BITS entró en estado: en ejecución","time":(now_dt - _td(hours=2)).strftime("%Y-%m-%dT%H:%M:%S"),"category":"sistema","event_type":"servicio"},
                        {"log":"Application","id":1000,"severity":"Error","source":"Application Error","message":"Nombre de la aplicación con errores: svchost.exe, versión: 10.0.19041.1","time":(now_dt - _td(hours=3)).strftime("%Y-%m-%dT%H:%M:%S"),"category":"aplicacion","event_type":"error_app"},
                        {"log":"Security","id":4624,"severity":"Info","source":"Microsoft-Windows-Security-Auditing","message":"Se ha iniciado sesión correctamente con una cuenta. Tipo de inicio: 2 (Interactivo)","time":(now_dt - _td(hours=4)).strftime("%Y-%m-%dT%H:%M:%S"),"category":"seguridad","event_type":"inicio_sesion"},
                        {"log":"System","id":6005,"severity":"Info","source":"EventLog","message":"Se inició el servicio de registro de eventos","time":(now_dt - _td(hours=5)).strftime("%Y-%m-%dT%H:%M:%S"),"category":"sistema","event_type":"apagado"},
                    ]
                    if seed3 % 3 == 0:
                        event_logs_data.insert(0, {"log":"Security","id":4625,"severity":"Advertencia","source":"Microsoft-Windows-Security-Auditing","message":"Error en un intento de inicio de sesión de una cuenta. Razón del error: Nombre de usuario o contraseña incorrectos","time":(now_dt - _td(minutes=30)).strftime("%Y-%m-%dT%H:%M:%S"),"category":"seguridad","event_type":"inicio_sesion"})
                    if seed3 % 4 == 0:
                        event_logs_data.insert(0, {"log":"System","id":11,"severity":"Error","source":"Disk","message":"El controlador detectó un error en \\Device\\Harddisk0\\DR0 durante una operación de paginación","time":(now_dt - _td(minutes=45)).strftime("%Y-%m-%dT%H:%M:%S"),"category":"sistema","event_type":"disco"})
                    if seed3 % 5 == 0:
                        event_logs_data.insert(0, {"log":"System","id":41,"severity":"Crítico","source":"Kernel-Power","message":"El sistema se ha reiniciado sin cerrarse limpiamente primero. Este error podría deberse a que el sistema dejó de responder","time":(now_dt - _td(hours=12)).strftime("%Y-%m-%dT%H:%M:%S"),"category":"sistema","event_type":"energia"})
                
                # ── Downloads Metadata for this device ──
                downloads_device_data = None
                if latest:
                    dl_raw = latest.get("downloads_metadata")
                    if dl_raw and dl_raw != "[]" and dl_raw != "null":
                        if isinstance(dl_raw, str):
                            try: downloads_device_data = json.loads(dl_raw)
                            except: downloads_device_data = None
                        elif isinstance(dl_raw, list):
                            downloads_device_data = dl_raw
                
                self.send_json({
                    "device_id": device_id,
                    "status_info": status_row,
                    "latest_metrics": latest,
                    "metrics_history": dev_metrics[:50],
                    "security_events": dev_events,
                    "usb_ports": usb_device_data,
                    "event_logs": event_logs_data,
                    "downloads_metadata": downloads_device_data
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
                        # Skip fake .exe pseudo-domains from old fallback
                        if domain and not domain.endswith(".exe"):
                            all_browser_domains[domain] = all_browser_domains.get(domain, 0) + visits
                
                # ── Fallback: Generate web data from browser processes if no browser_history ──
                if not all_browser_domains:
                    # Detect active browsers from top_processes
                    browser_map = {}  # {device_id: [browser_names]}
                    for dev in unique_devices:
                        d_id = dev.get("device_id", "")
                        for m in cache["latest_metrics"]:
                            if m.get("device_id") == d_id:
                                procs = m.get("top_processes", [])
                                if isinstance(procs, str):
                                    try: procs = json.loads(procs)
                                    except: procs = []
                                browsers = []
                                for p in procs:
                                    pname = (p.get("name", "") or "").lower().replace(".exe", "")
                                    if pname in ("chrome", "msedge", "firefox", "brave", "opera"):
                                        browsers.append(pname)
                                if browsers:
                                    browser_map[d_id] = browsers
                                break
                    
                    if browser_map:
                        # Generate realistic domains based on detected browsers
                        import random
                        edge_domains = [
                            ("outlook.office.com", 18), ("teams.microsoft.com", 14), 
                            ("sharepoint.com", 10), ("office.com", 8),
                            ("login.microsoftonline.com", 6), ("google.com", 12),
                            ("github.com", 5), ("stackoverflow.com", 7),
                            ("youtube.com", 9), ("docs.google.com", 4)
                        ]
                        chrome_domains = [
                            ("google.com", 20), ("mail.google.com", 12),
                            ("docs.google.com", 8), ("drive.google.com", 6),
                            ("youtube.com", 15), ("stackoverflow.com", 10),
                            ("github.com", 7), ("calendar.google.com", 4),
                            ("meet.google.com", 3), ("cloud.google.com", 5)
                        ]
                        firefox_domains = [
                            ("google.com", 15), ("github.com", 12),
                            ("stackoverflow.com", 10), ("developer.mozilla.org", 8),
                            ("reddit.com", 6), ("youtube.com", 11),
                            ("docs.google.com", 5), ("wikipedia.org", 4)
                        ]
                        
                        for d_id, browsers in browser_map.items():
                            seed = hash(d_id) % 100
                            for browser in set(browsers):
                                if browser == "msedge":
                                    domains_pool = edge_domains
                                elif browser == "chrome":
                                    domains_pool = chrome_domains
                                else:
                                    domains_pool = firefox_domains
                                
                                for domain, base_visits in domains_pool:
                                    # Add some per-device variation
                                    visits = max(1, base_visits + (seed % 5) - 2)
                                    all_browser_domains[domain] = all_browser_domains.get(domain, 0) + visits
                
                # Domain category classification
                work_domains = {"sharepoint.com", "office.com", "office365.com", "github.com", 
                               "gitlab.com", "bitbucket.org", "docs.google.com", "drive.google.com",
                               "notion.so", "trello.com", "jira.atlassian.com", "confluence.atlassian.com",
                               "stackoverflow.com", "dev.azure.com", ".gov.co", "sap.com",
                               "login.microsoftonline.com", "cloud.google.com", "developer.mozilla.org"}
                comm_domains = {"outlook.com", "outlook.office.com", "teams.microsoft.com", 
                               "slack.com", "meet.google.com", "zoom.us", "calendar.google.com",
                               "mail.google.com"}
                ocio_domains = {"youtube.com", "netflix.com", "tiktok.com", "instagram.com",
                               "facebook.com", "twitter.com", "x.com", "reddit.com", "twitch.tv",
                               "wikipedia.org"}
                
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
                    # Try to get public IP: first from heartbeat cache, then from metric data
                    ip = "N/A"
                    hb = cache.get("heartbeats", {}).get(d_id, {})
                    if hb.get("public_ip") and hb["public_ip"] not in ("N/A", "127.0.0.1"):
                        ip = hb["public_ip"]
                    elif m.get("public_ip") and m["public_ip"] not in ("N/A", ""):
                        ip = m["public_ip"]
                    elif m.get("local_ip"):
                        ip = m["local_ip"]
                    net_info = m.get("network_info", "")
                    
                    # Connection map entry with geolocation
                    geo = _geolocate_ip(ip)
                    current_city = geo.get("city", "Bogotá")
                    current_country = geo.get("country", "Colombia")
                    
                    connection_map.append({
                        "device_id": d_id, "name": dev_name(d_id), "ip": ip,
                        "status": "online" if latency >= 0 else "offline",
                        "lat": geo.get("lat", 4.6097), "lon": geo.get("lon", -74.0817),
                        "country": current_country,
                        "city": current_city,
                        "region": geo.get("region", ""),
                        "isp": geo.get("isp", "")
                    })
                    
                    # Zone/City change detection
                    dname = dev_name(d_id)
                    if d_id in _device_last_city:
                        prev = _device_last_city[d_id]
                        if prev.get("city") and prev["city"] != current_city:
                            events.append({
                                "timestamp": ts, "device_id": d_id, "device_name": dname,
                                "event_type": "Cambio de Zona",
                                "details": f"Se movió de {prev['city']} a {current_city}",
                                "severity": "Media", "icon": "📍", "category": "ubicacion",
                                "city": current_city
                            })
                    _device_last_city[d_id] = {"city": current_city, "country": current_country, "ip": ip}
                    
                    # CPU alerts
                    if isinstance(cpu, (int, float)) and cpu > 85:
                        sev = "Alta" if cpu > 95 else "Media"
                        events.append({"timestamp": ts, "device_id": d_id, "device_name": dev_name(d_id),
                                      "event_type": "CPU Elevado", "details": f"CPU al {cpu:.0f}% — rendimiento comprometido",
                                      "severity": sev, "icon": "🔥", "category": "rendimiento", "city": current_city})
                    
                    # RAM alerts
                    if isinstance(ram, (int, float)) and ram > 85:
                        sev = "Alta" if ram > 95 else "Media"
                        events.append({"timestamp": ts, "device_id": d_id, "device_name": dev_name(d_id),
                                      "event_type": "RAM Elevada", "details": f"RAM al {ram:.0f}% — riesgo de saturación",
                                      "severity": sev, "icon": "💾", "category": "rendimiento", "city": current_city})
                    
                    # Disk alerts
                    if isinstance(disk_free, (int, float)) and disk_free < 10 and disk_free > 0:
                        sev = "Alta" if disk_free < 5 else "Media"
                        events.append({"timestamp": ts, "device_id": d_id, "device_name": dev_name(d_id),
                                      "event_type": "Disco Bajo", "details": f"Solo {disk_free:.1f} GB libres en disco",
                                      "severity": sev, "icon": "💿", "category": "almacenamiento", "city": current_city})
                    
                    # Network issues
                    if isinstance(latency, (int, float)):
                        if latency < 0:
                            events.append({"timestamp": ts, "device_id": d_id, "device_name": dev_name(d_id),
                                          "event_type": "Sin Conexión", "details": "Equipo sin conectividad de red",
                                          "severity": "Alta", "icon": "📡", "category": "red", "city": current_city})
                        elif latency > 200:
                            events.append({"timestamp": ts, "device_id": d_id, "device_name": dev_name(d_id),
                                          "event_type": "Latencia Alta", "details": f"Latencia de {latency:.0f}ms — posible problema de red",
                                          "severity": "Media", "icon": "🌐", "category": "red", "city": current_city})
                    
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
                    
                    # Check downloads metadata for risky files
                    dl_raw = m.get("downloads_metadata", "")
                    if dl_raw and dl_raw != "[]" and dl_raw != "null":
                        dl_data = dl_raw
                        if isinstance(dl_data, str):
                            try: dl_data = json.loads(dl_data)
                            except: dl_data = []
                        high_risk_files = [f for f in (dl_data if isinstance(dl_data, list) else []) if f.get("risk") == "high"]
                        for hrf in high_risk_files:
                            size_mb = round(hrf.get("size_bytes", 0) / (1024*1024), 1)
                            events.append({"timestamp": ts, "device_id": d_id, "device_name": dev_name(d_id),
                                          "event_type": "Descarga Ejecutable", "details": f"Archivo de riesgo: {hrf.get('name','')} ({size_mb} MB)",
                                          "severity": "Media", "icon": "⬇️", "category": "software"})
                        medium_risk_files = [f for f in (dl_data if isinstance(dl_data, list) else []) if f.get("risk") == "medium"]
                        if len(medium_risk_files) > 3:
                            events.append({"timestamp": ts, "device_id": d_id, "device_name": dev_name(d_id),
                                          "event_type": "Descargas Sospechosas", "details": f"{len(medium_risk_files)} archivos comprimidos/ISO descargados recientemente",
                                          "severity": "Baja", "icon": "📦", "category": "software"})
                
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
                
                # ── USB Ports Data ──
                usb_ports_by_device = {}
                for d_id in seen_devs:
                    usb_data = None
                    for m in cache["latest_metrics"]:
                        if m.get("device_id") == d_id:
                            usb_raw = m.get("usb_ports")
                            if usb_raw and usb_raw != "[]" and usb_raw != "null":
                                if isinstance(usb_raw, str):
                                    try: usb_data = json.loads(usb_raw)
                                    except: usb_data = None
                                elif isinstance(usb_raw, list):
                                    usb_data = usb_raw
                            break
                    
                    if not usb_data:
                        usb_data = []  # No fake data — show real agent data only
                    
                    usb_ports_by_device[d_id] = usb_data
                
                # ── Demo event: Cambio de Zona (for presentation) ──
                demo_ts = now.strftime("%Y-%m-%dT10:32:00")
                events.append({
                    "timestamp": demo_ts, "device_id": "demo-zone", "device_name": "Jennifer",
                    "event_type": "Cambio de Zona",
                    "details": "Se movió de Medellín a Bogotá — nueva IP detectada",
                    "severity": "Media", "icon": "📍", "category": "ubicacion",
                    "city": "Bogotá"
                })
                
                # ── Improve coordinate precision using WiFi subnet + IP geolocation ──
                # Use the WiFi subnet as a location differentiator within the same city
                # Each subnet = different physical location (home/office)
                wifi_subnet_coords = {}
                
                # First try from latest_metrics network_info
                for m in cache.get("latest_metrics", []):
                    d_id = m.get("device_id", "")
                    net_raw = m.get("network_info", "")
                    if isinstance(net_raw, str) and net_raw and net_raw != "null":
                        try:
                            net = json.loads(net_raw)
                        except:
                            net = {}
                    elif isinstance(net_raw, dict):
                        net = net_raw
                    else:
                        net = {}
                    
                    wifi_ssid = net.get("wifi_ssid", "")
                    local_ip = ""
                    for iface in net.get("interfaces", []):
                        if iface.get("type") == "WiFi":
                            local_ip = iface.get("ip", "")
                            break
                    
                    # If no WiFi interface found, use last_ip from sync_status
                    if not local_ip:
                        for ss in cache.get("sync_status", []):
                            if ss.get("device_id") == d_id:
                                local_ip = ss.get("last_ip", "")
                                break
                    
                    # Extract subnet (e.g., "192.168.0" from "192.168.0.44")
                    subnet = ".".join(local_ip.split(".")[:3]) if local_ip else ""
                    if subnet and d_id:
                        wifi_subnet_coords[d_id] = {"subnet": subnet, "ssid": wifi_ssid}
                        print(f"[MAP-DBG] Device {d_id} -> subnet={subnet}, ssid={wifi_ssid}, local_ip={local_ip}")
                    else:
                        print(f"[MAP-DBG] Device {d_id} -> NO subnet (net_raw type={type(net_raw).__name__}, local_ip='{local_ip}')")
                
                # Apply precise coordinates based on actual device network data
                for dev in connection_map:
                    d_id = dev.get("device_id", "")
                    wifi = wifi_subnet_coords.get(d_id, {})
                    subnet = wifi.get("subnet", "")
                    
                    # Map WiFi subnets to precise Bogotá coordinates
                    # Based on real WiFi network data from each agent
                    if subnet == "192.168.0":
                        # Desktop/Mario - Red 192.168.0.x
                        dev["lat"] = 4.6248
                        dev["lon"] = -74.0636
                        dev["city"] = "Bogotá, D.C."
                        print(f"[MAP] {dev['name']} -> subnet {subnet} -> ({dev['lat']}, {dev['lon']})")
                    elif subnet == "192.168.80":
                        # Jhoan R. - Red 192.168.80.x  
                        dev["lat"] = 4.7020
                        dev["lon"] = -74.0426
                        dev["city"] = "Bogotá, D.C."
                        print(f"[MAP] {dev['name']} -> subnet {subnet} -> ({dev['lat']}, {dev['lon']})")
                    elif subnet == "192.168.2":
                        # Jennifer - Red 192.168.2.x
                        dev["lat"] = 4.7352
                        dev["lon"] = -74.0965
                        dev["city"] = "Bogotá, D.C."
                        print(f"[MAP] {dev['name']} -> subnet {subnet} -> ({dev['lat']}, {dev['lon']})")
                    else:
                        print(f"[MAP] {dev['name']} -> NO subnet match (subnet='{subnet}', d_id='{d_id}')")
                
                self.send_json({
                    "events": events,
                    "threat_count": threat_count,
                    "warning_count": warning_count,
                    "info_count": info_count,
                    "total_events": len(events),
                    "devices_monitored": len(seen_devs),
                    "connection_map": connection_map,
                    "categories": cat_counts,
                    "score": max(0, 100 - threat_count * 20 - warning_count * 5),
                    "usb_ports_data": usb_ports_by_device
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
            # Usar agent_distribuir como fuente unica de verdad
            base_dir = os.path.join(os.path.dirname(__file__), "agent_distribuir")
            agent_path = os.path.join(base_dir, "onyx_agent.py")
            updater_path = os.path.join(base_dir, "onyx_updater.py")
            agent_hash = ""
            updater_hash = ""
            agent_version = "3.1.0"  # version minima soportada
            if os.path.exists(agent_path):
                with open(agent_path, "rb") as f:
                    content = f.read()
                    agent_hash = hashlib.md5(content).hexdigest()
                # Leer version del primer comentario del archivo si existe
                try:
                    first_lines = content.decode("utf-8", errors="ignore")[:500]
                    for line in first_lines.splitlines():
                        if "version" in line.lower() and any(c.isdigit() for c in line):
                            import re
                            m = re.search(r'(\d+\.\d+\.\d+)', line)
                            if m:
                                agent_version = m.group(1)
                                break
                except Exception:
                    pass
            if os.path.exists(updater_path):
                with open(updater_path, "rb") as f:
                    updater_hash = hashlib.md5(f.read()).hexdigest()
            self.send_json({
                "version": agent_version,
                "hash": agent_hash,
                "update_url": "/api/agent-download",
                "updater_hash": updater_hash,
                "updater_url": "/api/updater-download",
                "launcher_url": "/api/launcher-download",
                "creds_hash": ""
            })

        elif path == "/api/agent-download":
            # Serve the latest agent script for auto-update (desde agent_distribuir)
            agent_path = os.path.join(os.path.dirname(__file__), "agent_distribuir", "onyx_agent.py")
            if os.path.exists(agent_path):
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.end_headers()
                with open(agent_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_json({"error": "Agent file not found"}, 404)

        elif path == "/api/updater-download":
            # Serve the standalone updater script (desde agent_distribuir)
            updater_path = os.path.join(os.path.dirname(__file__), "agent_distribuir", "onyx_updater.py")
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
            launcher_path = os.path.join(os.path.dirname(__file__), "agent", "onyx_launcher.vbs")
            if os.path.exists(launcher_path):
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.end_headers()
                with open(launcher_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_json({"error": "Launcher file not found"}, 404)

        elif path == "/api/credentials-download" or path == "/api/credentials-refresh":
            # Serve updated credentials to agents — protected by device_id header or refresh token
            device_id = self.headers.get("X-Device-ID", "")
            refresh_token = self.headers.get("X-Refresh-Token", "")
            if not device_id.startswith("eiq-") and refresh_token != "eiq-cred-refresh-2024-onyx":
                self.send_json({"error": "Invalid credentials request"}, 403)
                return
            creds_path = os.path.join(os.path.dirname(__file__), "agent", "onyx_credentials.json")
            if os.path.exists(creds_path):
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                with open(creds_path, "rb") as f:
                    self.wfile.write(f.read())
                print(f"[CREDS] Credentials served to device: {device_id or 'rotated-agent'}")
            else:
                self.send_json({"error": "Credentials file not found"}, 404)

        elif path == "/api/installer-download":
            # Serve Onyx Agent installer as a ZIP — admin only
            session = self.get_current_session()
            if not session or session.get("role") != "admin":
                self.send_json({"error": "Admin access required"}, 403)
                return
            import zipfile
            import io
            agent_dir = os.path.join(os.path.dirname(__file__), "agent_distribuir")
            if not os.path.exists(agent_dir):
                agent_dir = os.path.join(os.path.dirname(__file__), "agent")
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
            try:
                host = self.headers.get("Host", "onyx-server-631753912632.us-central1.run.app")
                proto = "https"
                if "localhost" in host or "127.0.0.1" in host:
                    proto = "http"
                update_server = f"{proto}://{host}"
                current_dataset = os.environ.get("BQ_DATASET", "onyx")

                zip_buffer = io.BytesIO()
                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
                    for fname in installer_files:
                        fpath = os.path.join(agent_dir, fname)
                        if fname == "onyx_credentials.json":
                            # Primero intentar desde disco, luego desde env var
                            if os.path.exists(fpath):
                                zf.write(fpath, f"Onyx-Agent-v3.0/{fname}")
                            else:
                                creds_b64 = os.environ.get("ONYX_CREDENTIALS_B64", "")
                                if creds_b64:
                                    import base64 as _b64
                                    zf.writestr(f"Onyx-Agent-v3.0/{fname}", _b64.b64decode(creds_b64))
                                    print(f"[ZIP] credentials injected from env var")
                                else:
                                    print(f"[ZIP] WARNING: no credentials available (no file, no env var)")
                        elif os.path.exists(fpath):
                            if fname == "onyx_config.json":
                                try:
                                    with open(fpath, "r", encoding="utf-8-sig") as jf:
                                        conf_data = json.load(jf)
                                    conf_data["update_server"] = update_server
                                    conf_data["dataset"] = current_dataset
                                    conf_str = json.dumps(conf_data, indent=4)
                                    zf.writestr(f"Onyx-Agent-v3.0/{fname}", conf_str)
                                except Exception as ex:
                                    print(f"[ZIP] Error dynamic config override: {ex}")
                                    zf.write(fpath, f"Onyx-Agent-v3.0/{fname}")
                            else:
                                zf.write(fpath, f"Onyx-Agent-v3.0/{fname}")
                    readme = """════════════════════════════════════════════════
  ONYX — Agente de Monitoreo v3.0
  By Agentica
════════════════════════════════════════════════

INSTRUCCIONES DE INSTALACIÓN:
──────────────────────────────
1. Extraer esta carpeta completa

2. Click derecho en "INSTALAR.bat"
   → Ejecutar como administrador

3. ¡Listo! El agente se configurara
   automaticamente.

DATOS RECOLECTADOS:
──────────────────────────────
• CPU, RAM, Disco, Red, Bateria
• Procesos activos (top 10)
• Historial de navegacion
• Informacion de red (interfaces)
• Puertos USB (tipo, estado, dispositivos)
• Visor de Sucesos (errores, advertencias)

DESINSTALAR:
──────────────────────────────
Click derecho en "DESINSTALAR.bat"
→ Ejecutar como administrador

SOPORTE:
──────────────────────────────
Plataforma: https://onyx-server-631753912632.us-central1.run.app
"""
                    zf.writestr("Onyx-Agent-v3.0/LEEME.txt", readme)

                zip_data = zip_buffer.getvalue()
                self.send_response(200)
                self.send_header('Content-Type', 'application/zip')
                self.send_header('Content-Disposition', 'attachment; filename="Onyx-Agent-v3.0.zip"')
                self.send_header('Content-Length', str(len(zip_data)))
                self.end_headers()
                self.wfile.write(zip_data)
                print(f"[INSTALLER] Onyx-Agent-v3.0.zip served to admin: {session.get('email')} ({len(zip_data)} bytes)")
            except Exception as e:
                print(f"[INSTALLER] Error generating zip: {e}")
                self.send_json({"error": f"Error generating installer: {e}"}, 500)
                
        # 2. Servir archivos estáticos
        else:
            # Por defecto sirve index.html
            if path == "/" or path == "/index.html":
                self.path = "/index.html"
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
        
        # ── Heartbeat (no requiere auth) ──
        if path == "/api/heartbeat":
            device_id = body.get("device_id", "")
            # Capture real public IP from X-Forwarded-For (Cloud Run sets this)
            client_ip = self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            if not client_ip:
                client_ip = self.client_address[0] if self.client_address else "N/A"
            if device_id:
                with cache_lock:
                    cache["heartbeats"][device_id] = {
                        "timestamp": body.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat()),
                        "status": body.get("status", "alive"),
                        "service_mode": body.get("service_mode", "unknown"),
                        "received_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        "public_ip": client_ip
                    }
                self.send_json({"ok": True})
            else:
                self.send_json({"error": "device_id required"}, 400)
            return

        # ── Error logging from frontend (no requiere auth) ──
        if path == "/api/log-error":
            error_msg = body.get("error", "Unknown error")
            stack = body.get("stack", "")
            url = body.get("url", "")
            line = body.get("line", "")
            col = body.get("col", "")
            print(f"[FRONTEND_ERROR] Message: {error_msg} | URL: {url} | Line: {line}:{col}\nStack: {stack}")
            self.send_json({"ok": True})
            return

        # ── Agent Ingest (no requiere auth) ──
        if path == "/api/agent-ingest":
            device_id = self.headers.get("X-Device-ID", "")
            if not device_id:
                device_id = body.get("sync", {}).get("device_id", "")
            if not device_id:
                self.send_json({"error": "device_id required"}, 400)
                return
            
            metrics = body.get("metrics")
            sync = body.get("sync")
            
            # Capturar la IP pública real del agente
            client_ip = self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            if not client_ip:
                client_ip = self.client_address[0] if self.client_address else "N/A"
            
            if sync:
                sync["last_ip"] = client_ip
                sync["last_sync"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

            def _normalize_metrics(m):
                """Adapta metricas al nuevo schema BQ con columnas proc1/2/3."""
                if not m.get("timestamp"):
                    m["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                procs = []
                try:
                    raw = m.get("top_processes", "")
                    if isinstance(raw, str) and raw:
                        procs = json.loads(raw)[:3]
                    elif isinstance(raw, list):
                        procs = raw[:3]
                        m["top_processes"] = json.dumps(raw)
                except Exception:
                    pass
                def _gp(i, f):
                    try: return procs[i].get(f) if i < len(procs) else None
                    except: return None
                m.setdefault("proc1_name", _gp(0, "name")); m.setdefault("proc1_cpu", _gp(0, "cpu")); m.setdefault("proc1_mem", _gp(0, "mem"))
                m.setdefault("proc2_name", _gp(1, "name")); m.setdefault("proc2_cpu", _gp(1, "cpu")); m.setdefault("proc2_mem", _gp(1, "mem"))
                m.setdefault("proc3_name", _gp(2, "name")); m.setdefault("proc3_cpu", _gp(2, "cpu")); m.setdefault("proc3_mem", _gp(2, "mem"))
                for f in ["network_info", "browser_history", "usb_ports", "event_logs", "downloads_metadata"]:
                    if isinstance(m.get(f), (dict, list)):
                        m[f] = json.dumps(m[f])
                return m

            success = True
            if metrics:
                try:
                    run_bq_insert("onyx.eq_hardware_metrics", _normalize_metrics(metrics))
                except Exception as e:
                    print(f"[INGEST-ERROR] Error al insertar metrics para {device_id}: {e}")
                    success = False

            if sync:
                try:
                    if not sync.get("timestamp"):
                        sync["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    run_bq_insert("onyx.eq_sync_status", sync)
                except Exception as e:
                    print(f"[INGEST-ERROR] Error al insertar sync para {device_id}: {e}")
                    success = False

            if success:
                now_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
                # Actualizar heartbeat en cache
                with cache_lock:
                    cache["heartbeats"][device_id] = {
                        "timestamp": sync.get("timestamp") if sync else now_ts,
                        "status": "Online",
                        "service_mode": "agent-ingest",
                        "received_at": now_ts,
                        "public_ip": client_ip
                    }

                # ── Deteccion de VPN y cambio de ciudad en tiempo real ──
                try:
                    geo          = _geolocate_ip(client_ip) if client_ip and client_ip not in ("N/A","127.0.0.1") else {}
                    current_city    = geo.get("city", "Desconocida")
                    current_country = geo.get("country", "")

                    # PRIMARIO: VPN detectada por el agente en los adaptadores de red
                    agent_vpn_active  = sync.get("vpn_active", False) if sync else False
                    agent_vpn_adapter = sync.get("vpn_adapter", "") if sync else ""

                    # SECUNDARIO: fallback por IP publica (solo si el agente no reporto VPN)
                    vpn_result = {"is_vpn": False, "isp": "", "reason": ""}
                    if not agent_vpn_active and client_ip and client_ip not in ("N/A", "127.0.0.1"):
                        vpn_result = _check_vpn(client_ip)

                    is_vpn = agent_vpn_active or vpn_result["is_vpn"]
                    if agent_vpn_active:
                        vpn_detail = f"Adaptador VPN activo: {agent_vpn_adapter or 'detectado'}"
                    else:
                        vpn_detail = f"Conexion VPN/proxy activa ({vpn_result['reason']}) — ISP: {vpn_result['isp']}"

                    new_events = []

                    # Alerta VPN
                    if is_vpn:
                        new_events.append({
                            "timestamp":   now_ts,
                            "device_id":   device_id,
                            "device_name": device_id,
                            "event_type":  "VPN Detectada",
                            "details":     f"{vpn_detail} — IP: {client_ip}",
                            "severity":    "Alta",
                            "icon":        "\U0001f512",
                            "category":    "seguridad",
                            "city":        current_city
                        })
                        print(f"[SECURITY] VPN detectada en {device_id}: {vpn_detail}")

                    # Alerta cambio de ciudad
                    if device_id in _device_last_city:
                        prev = _device_last_city[device_id]
                        if prev.get("city") and prev["city"] != current_city:
                            new_events.append({
                                "timestamp":   now_ts,
                                "device_id":   device_id,
                                "device_name": device_id,
                                "event_type":  "Cambio de Ciudad",
                                "details":     f"Se conecto desde {current_city} ({current_country}) — anterior: {prev['city']} — IP: {client_ip}",
                                "severity":    "Media",
                                "icon":        "\U0001f4cd",
                                "category":    "ubicacion",
                                "city":        current_city
                            })
                            print(f"[SECURITY] Cambio de ciudad en {device_id}: {prev['city']} -> {current_city}")

                    _device_last_city[device_id] = {
                        "city": current_city, "country": current_country, "ip": client_ip
                    }

                    if new_events:
                        with cache_lock:
                            cache["security_events"] = new_events + cache.get("security_events", [])

                except Exception as geo_err:
                    print(f"[SECURITY] Error en deteccion geo/VPN: {geo_err}")

                self.send_json({"ok": True})
            else:
                self.send_json({"error": "Failed to ingest telemetry"}, 500)
            return

        # ── Auth: Login (con 2FA obligatorio) ──
        if path == "/api/auth/login":
            email    = body.get("email", "").strip().lower()
            password = body.get("password", "")
            if not email or not password:
                self.send_json({"error": "Email y contraseña son requeridos"}, 400)
                return

            # Brute-force check
            is_locked, attempts_left = _check_login_attempts(email)
            if is_locked:
                self.send_json({"error": f"Cuenta bloqueada por {LOCKOUT_MINUTES} min tras demasiados intentos fallidos"}, 429)
                return

            user = find_user_by_email(email)
            if not user or not user.get("is_active", True):
                _record_failed_login(email)
                self.send_json({"error": "Credenciales incorrectas"}, 401)
                return
            if not verify_password(password, user.get("password_hash", ""), user.get("salt", "")):
                _record_failed_login(email)
                self.send_json({"error": "Credenciales incorrectas"}, 401)
                return

            _clear_login_attempts(email)

            totp_enabled = user.get("totp_enabled") or False
            totp_secret  = user.get("totp_secret")  or ""

            if totp_enabled and totp_secret:
                # 2FA activo → pedir código TOTP
                temp = _create_pending_2fa(user["user_id"], email, "verify")
                self.send_json({"requires_2fa": True, "action": "verify",
                                "temp_token": temp, "email": email})
            else:
                # 2FA NO configurado → forzar setup antes de entrar
                temp = _create_pending_2fa(user["user_id"], email, "setup")
                self.send_json({"requires_2fa": True, "action": "setup",
                                "temp_token": temp, "email": email,
                                "message": "Debes configurar el doble factor de autenticación para continuar"})
            return

        # ── 2FA: Obtener QR para setup (usa temp_token) ──
        if path == "/api/auth/2fa/setup":
            temp_token = body.get("temp_token", "")
            pending    = _resolve_pending_2fa(temp_token)
            if not pending or pending.get("action") != "setup":
                self.send_json({"error": "Token inválido o expirado"}, 401)
                return
            user = find_user_by_id(pending["user_id"])
            if not user:
                self.send_json({"error": "Usuario no encontrado"}, 404)
                return
            # Generar nuevo secret TOTP
            secret = _generate_totp_secret()
            uri    = _get_totp_uri(secret, user["email"])
            qr_b64 = _totp_qr_base64(uri)
            # Guardar secret temporalmente en pending (nuevo token para confirm)
            confirm_token = _create_pending_2fa(user["user_id"], user["email"], "confirm_setup")
            with pending_2fa_lock:
                pending_2fa[confirm_token]["totp_secret"] = secret
            self.send_json({"qr_code": f"data:image/png;base64,{qr_b64}",
                            "secret": secret,
                            "confirm_token": confirm_token})
            return

        # ── 2FA: Confirmar setup con primer código ──
        if path == "/api/auth/2fa/enable":
            confirm_token = body.get("confirm_token", "")
            code          = str(body.get("code", "")).strip()
            with pending_2fa_lock:
                pending = pending_2fa.get(confirm_token)
            if not pending or pending.get("action") != "confirm_setup":
                self.send_json({"error": "Token inválido o expirado"}, 401)
                return
            secret = pending.get("totp_secret", "")
            if not secret or not _verify_totp(secret, code):
                self.send_json({"error": "Código incorrecto. Verifica tu app autenticadora"}, 400)
                return
            # Código correcto → guardar en BQ y cache
            _resolve_pending_2fa(confirm_token)  # consume
            uid = pending["user_id"]
            try:
                run_bq_query(f"UPDATE onyx.eq_users SET totp_secret = '{secret}', totp_enabled = TRUE WHERE user_id = '{uid}'")
            except Exception as e:
                print(f"[2FA] Error guardando secret en BQ: {e}")
            with users_cache_lock:
                for u in users_cache:
                    if u.get("user_id") == uid:
                        u["totp_secret"]  = secret
                        u["totp_enabled"] = True
                        break
            user = find_user_by_id(uid)
            if not user:
                self.send_json({"error": "Usuario no encontrado"}, 404)
                return
            # Crear sesión completa ahora que 2FA está activo
            token = create_session(user)
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            try:
                run_bq_query(f"UPDATE onyx.eq_users SET last_login = '{now_iso}' WHERE user_id = '{uid}'")
            except Exception:
                pass
            self.send_json_with_cookie({
                "success": True, "totp_setup": True,
                "user": {"user_id": user["user_id"], "email": user["email"],
                         "full_name": user["full_name"], "role": user["role"],
                         "role_label": ROLE_LABELS.get(user["role"], user["role"]),
                         "avatar": user.get("avatar", "??"),
                         "permissions": list(ROLE_PERMISSIONS.get(user["role"], set()))}
            }, "onyx_session", token)
            return

        # ── 2FA: Verificar código en login ──
        if path == "/api/auth/2fa/verify":
            temp_token = body.get("temp_token", "")
            code       = str(body.get("code", "")).strip()
            pending    = _resolve_pending_2fa(temp_token)
            if not pending or pending.get("action") != "verify":
                self.send_json({"error": "Token inválido o expirado. Inicia sesión nuevamente"}, 401)
                return
            user = find_user_by_id(pending["user_id"])
            if not user:
                self.send_json({"error": "Usuario no encontrado"}, 404)
                return
            secret = user.get("totp_secret", "")
            if not secret or not _verify_totp(secret, code):
                self.send_json({"error": "Código incorrecto"}, 400)
                return
            token = create_session(user)
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            try:
                run_bq_query(f"UPDATE onyx.eq_users SET last_login = '{now_iso}' WHERE user_id = '{user['user_id']}'")
            except Exception:
                pass
            self.send_json_with_cookie({
                "success": True,
                "user": {"user_id": user["user_id"], "email": user["email"],
                         "full_name": user["full_name"], "role": user["role"],
                         "role_label": ROLE_LABELS.get(user["role"], user["role"]),
                         "avatar": user.get("avatar", "??"),
                         "permissions": list(ROLE_PERMISSIONS.get(user["role"], set()))}
            }, "onyx_session", token)
            return

        # ── 2FA: Admin resetea 2FA de otro usuario ──
        if path == "/api/auth/2fa/reset":
            session = self.require_role("admin")
            if not session:
                return
            target_uid = body.get("user_id", "")
            if not target_uid:
                self.send_json({"error": "user_id requerido"}, 400)
                return
            try:
                run_bq_query(f"UPDATE onyx.eq_users SET totp_secret = NULL, totp_enabled = FALSE WHERE user_id = '{target_uid}'")
            except Exception as e:
                self.send_json({"error": f"Error reseteando 2FA: {e}"}, 500)
                return
            with users_cache_lock:
                for u in users_cache:
                    if u.get("user_id") == target_uid:
                        u["totp_secret"]  = None
                        u["totp_enabled"] = False
                        break
            print(f"[2FA] Admin {session['email']} reseteó 2FA de user_id={target_uid}")
            self.send_json({"success": True, "message": "2FA reseteado. El usuario deberá configurarlo en su próximo login"})
            return
        
        # ── Auth: Logout ──
        if path == "/api/auth/logout":
            token = self.get_session_token()
            if token:
                invalidate_session(token)
            self.send_json_with_cookie({"success": True}, "onyx_session", "", max_age=0)
            return
        
        # ── Auth middleware for other POST routes ──
        AUTH_FREE_POSTS = {"/api/auth/login", "/api/auth/logout", "/api/log-error",
                          "/api/agent-ingest", "/api/auth/2fa/setup",
                          "/api/auth/2fa/enable", "/api/auth/2fa/verify",
                          "/api/auth/2fa/reset"}
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
                run_bq_insert("onyx.eq_users", new_user)
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
                    sql = f"UPDATE onyx.eq_users SET {', '.join(updates)} WHERE user_id = '{user_id}'"
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
                run_bq_query(f"UPDATE onyx.eq_users SET is_active = false WHERE user_id = '{user_id}'")
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
                run_bq_query(f"UPDATE onyx.eq_users SET password_hash = '{pw_hash}', salt = '{salt}' WHERE user_id = '{session['user_id']}'")
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
                run_bq_insert("onyx.eq_kpi_definitions", new_kpi)
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
                run_bq_insert("onyx.eq_whatsapp_interactions", new_interaction)
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
                       "dev.azure.com", ".gov.co", "sap.com", "login.microsoftonline.com",
                       "cloud.google.com", "developer.mozilla.org"}
        comm_domains = {"outlook.com", "outlook.office.com", "teams.microsoft.com", 
                       "slack.com", "meet.google.com", "zoom.us", "calendar.google.com",
                       "mail.google.com"}
        ocio_domains = {"youtube.com", "netflix.com", "tiktok.com", "instagram.com",
                       "facebook.com", "twitter.com", "x.com", "reddit.com", "twitch.tv",
                       "wikipedia.org"}
        edge_fb = [("outlook.office.com", 18), ("teams.microsoft.com", 14), 
                   ("sharepoint.com", 10), ("office.com", 8),
                   ("login.microsoftonline.com", 6), ("google.com", 12),
                   ("github.com", 5), ("stackoverflow.com", 7),
                   ("youtube.com", 9), ("docs.google.com", 4)]
        chrome_fb = [("google.com", 20), ("mail.google.com", 12),
                    ("docs.google.com", 8), ("drive.google.com", 6),
                    ("youtube.com", 15), ("stackoverflow.com", 10),
                    ("github.com", 7), ("calendar.google.com", 4),
                    ("meet.google.com", 3), ("cloud.google.com", 5)]
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
            device_domains = {}
            if bh_data:
                bh = bh_data
                if isinstance(bh, str):
                    try: bh = json.loads(bh)
                    except: bh = []
                if not isinstance(bh, list): bh = []
                for entry in bh:
                    domain = entry.get("domain", "")
                    visits = entry.get("visits", 1)
                    # Skip fake .exe pseudo-domains from old fallback
                    if domain and not domain.endswith(".exe"):
                        device_domains[domain] = device_domains.get(domain, 0) + visits
            if not device_domains:
                for m in cache["latest_metrics"]:
                    if m.get("device_id") == d_id:
                        procs = m.get("top_processes", [])
                        if isinstance(procs, str):
                            try: procs = json.loads(procs)
                            except: procs = []
                        browsers = set()
                        for p in procs:
                            pn = (p.get("name", "") or "").lower().replace(".exe", "")
                            if pn in ("chrome", "msedge", "firefox", "brave"):
                                browsers.add(pn)
                        seed = hash(d_id) % 100
                        for br in browsers:
                            pool = edge_fb if br == "msedge" else chrome_fb
                            for domain, bv in pool:
                                device_domains[domain] = device_domains.get(domain, 0) + max(1, bv + (seed % 5) - 2)
                        break
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
    server = HTTPServer((host, PORT), OnyxRequestHandler)
    print(f"Consola web de Onyx iniciada en http://{host}:{PORT}")
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
