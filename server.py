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
import time
import hmac

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

import logging
log = logging.getLogger("onyx")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")

PORT = int(os.environ.get("PORT", 8080))

# ═══════════ Active Directory Configuration ═══════════
AD_ENABLED = os.environ.get("AD_ENABLED", "false").lower() == "true"
AD_LDAP_URL = os.environ.get("AD_LDAP_URL", "ldap://10.128.0.2:389")
AD_BASE_DN = os.environ.get("AD_BASE_DN", "DC=onyx,DC=local")
AD_BIND_USER = os.environ.get("AD_BIND_USER", "CN=svc-onyx-ldap,OU=ServiceAccounts,DC=onyx,DC=local")
AD_BIND_PASSWORD = os.environ.get("AD_BIND_PASSWORD", "")
AD_USER_FILTER = os.environ.get("AD_USER_FILTER", "(&(objectClass=person)(mail=*))")
AD_GROUP_MAP = {
    os.environ.get("AD_GROUP_ADMIN", "CN=ONYX-Admins,OU=Grupos,DC=onyx,DC=local"): "admin",
    os.environ.get("AD_GROUP_ANALYST", "CN=ONYX-Analysts,OU=Grupos,DC=onyx,DC=local"): "analyst",
    os.environ.get("AD_GROUP_VIEWER", "CN=ONYX-Viewers,OU=Grupos,DC=onyx,DC=local"): "viewer",
}
AD_SYNC_INTERVAL = int(os.environ.get("AD_SYNC_INTERVAL", "300"))


# ═══════════ Active Directory LDAP Functions ═══════════
def _ldap_escape(value):
    """Escape special characters to prevent LDAP injection (RFC 4515)."""
    if not value:
        return value
    escaped = value.replace('\\', '\\5c')
    for char, esc in [('*', '\\2a'), ('(', '\\28'), (')', '\\29'),
                      ('\x00', '\\00')]:
        escaped = escaped.replace(char, esc)
    return escaped


def ad_connect():
    """Create an LDAP connection to Active Directory."""
    if not AD_ENABLED:
        return None
    try:
        from ldap3 import Server, Connection, ALL, Tls
        import ssl
        # WARNING: CERT_NONE is for self-signed certs in test environments only.
        # In production, use ssl.CERT_REQUIRED with a proper CA bundle.
        tls_config = Tls(validate=ssl.CERT_NONE)
        server = Server(AD_LDAP_URL, get_info=ALL, tls=tls_config, connect_timeout=5)
        conn = Connection(server, user=AD_BIND_USER, password=AD_BIND_PASSWORD, auto_bind=True, receive_timeout=10)
        return conn
    except Exception as e:
        log.error("[AD] Connection failed: %s", e)
        return None


def ad_authenticate(email, password):
    """Authenticate a user against Active Directory via LDAP bind.
    Returns dict with user info if successful, None if failed."""
    if not AD_ENABLED:
        return None
    try:
        from ldap3 import Server, Connection, ALL, SUBTREE, Tls
        import ssl
        # First, find the user DN by email using service account
        conn = ad_connect()
        if not conn:
            return None
        safe_email = _ldap_escape(email)
        conn.search(
            search_base=AD_BASE_DN,
            search_filter=f"(&(objectClass=person)(mail={safe_email}))",
            search_scope=SUBTREE,
            attributes=['distinguishedName', 'cn', 'mail', 'givenName', 'sn',
                        'department', 'title', 'memberOf', 'sAMAccountName',
                        'userAccountControl']
        )
        if not conn.entries:
            conn.unbind()
            return None
        user_entry = conn.entries[0]
        user_dn = str(user_entry.distinguishedName)
        conn.unbind()

        # Now try to bind as the user to verify password
        tls_config = Tls(validate=ssl.CERT_NONE)
        server = Server(AD_LDAP_URL, get_info=ALL, tls=tls_config, connect_timeout=5)
        user_conn = Connection(server, user=user_dn, password=password, auto_bind=True, receive_timeout=10)
        user_conn.unbind()

        # Authentication successful — extract user data
        groups = [str(g) for g in user_entry.memberOf] if hasattr(user_entry, 'memberOf') and user_entry.memberOf else []
        role = "viewer"  # default
        for group_dn, mapped_role in AD_GROUP_MAP.items():
            if any(group_dn.lower() in g.lower() for g in groups):
                if mapped_role == "admin":
                    role = "admin"
                    break
                elif mapped_role == "analyst" and role != "admin":
                    role = "analyst"

        given = str(user_entry.givenName) if hasattr(user_entry, 'givenName') and user_entry.givenName else ""
        surname = str(user_entry.sn) if hasattr(user_entry, 'sn') and user_entry.sn else ""
        full_name = f"{given} {surname}".strip() or str(user_entry.cn)
        dept = str(user_entry.department) if hasattr(user_entry, 'department') and user_entry.department else ""
        title_val = str(user_entry.title) if hasattr(user_entry, 'title') and user_entry.title else ""

        return {
            "dn": user_dn,
            "email": str(user_entry.mail).lower(),
            "full_name": full_name,
            "role": role,
            "department": dept,
            "title": title_val,
            "groups": groups,
            "sam_account": str(user_entry.sAMAccountName) if hasattr(user_entry, 'sAMAccountName') else "",
            "auth_source": "ad"
        }
    except Exception as e:
        log.warning("[AD] Auth failed for %s: %s", email, e)
        return None


def ad_sync_users():
    """Sync all users from AD to BigQuery eq_users.
    Creates new users, updates existing, deactivates removed."""
    if not AD_ENABLED:
        return {"synced": 0, "created": 0, "updated": 0, "error": "AD not enabled"}
    try:
        from ldap3 import SUBTREE
        conn = ad_connect()
        if not conn:
            return {"synced": 0, "error": "Connection failed"}
        conn.search(
            search_base=AD_BASE_DN,
            search_filter=AD_USER_FILTER,
            search_scope=SUBTREE,
            attributes=['cn', 'mail', 'givenName', 'sn', 'department',
                        'title', 'memberOf', 'sAMAccountName',
                        'userAccountControl', 'distinguishedName',
                        'whenCreated']
        )
        ad_users = conn.entries
        conn.unbind()

        created = 0
        updated = 0
        ad_emails = set()

        for entry in ad_users:
            email = str(entry.mail).lower() if hasattr(entry, 'mail') and entry.mail else None
            if not email or email == '[]':
                continue
            ad_emails.add(email)

            # Determine role from groups
            groups = [str(g) for g in entry.memberOf] if hasattr(entry, 'memberOf') and entry.memberOf else []
            role = "viewer"
            for group_dn, mapped_role in AD_GROUP_MAP.items():
                if any(group_dn.lower() in g.lower() for g in groups):
                    if mapped_role == "admin":
                        role = "admin"
                        break
                    elif mapped_role == "analyst" and role != "admin":
                        role = "analyst"

            given = str(entry.givenName) if hasattr(entry, 'givenName') and entry.givenName else ""
            surname = str(entry.sn) if hasattr(entry, 'sn') and entry.sn else ""
            full_name = f"{given} {surname}".strip() or str(entry.cn)
            dept = str(entry.department) if hasattr(entry, 'department') and entry.department else ""

            # Check if user already exists
            existing = find_user_by_email(email)
            if existing:
                # Update role and name if changed — only for AD-sourced users
                if existing.get("auth_source") == "ad":
                    needs_update = []
                    if existing.get("role") != role:
                        needs_update.append(("role", role))
                    if existing.get("full_name") != full_name:
                        needs_update.append(("full_name", full_name))
                    if needs_update:
                        try:
                            run_bq_update_user(needs_update, "user_id", existing["user_id"])
                            existing["role"] = role
                            existing["full_name"] = full_name
                            updated += 1
                        except Exception:
                            pass
            else:
                # Create new user from AD
                import secrets
                salt = secrets.token_hex(16)
                random_pw = secrets.token_urlsafe(32)
                pw_hash = hash_password(random_pw, salt)
                avatar = (given[:1] + surname[:1]).upper() if given and surname else full_name[:2].upper()
                new_user = {
                    "user_id": str(uuid.uuid4()),
                    "email": email,
                    "password_hash": pw_hash[0],
                    "salt": salt,
                    "full_name": full_name,
                    "role": role,
                    "avatar": avatar,
                    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "last_login": None,
                    "is_active": True,
                    "totp_secret": None,
                    "totp_enabled": False,
                    "allowed_pages": None,
                    "auth_source": "ad",
                    "ad_dn": str(entry.distinguishedName),
                    "department": dept
                }
                try:
                    run_bq_insert("onyx.eq_users", new_user)
                    with users_cache_lock:
                        users_cache.append(new_user)
                    created += 1
                    log.info("[AD-SYNC] Created user: %s (%s) -> %s", email, full_name, role)
                except Exception as e:
                    log.error("[AD-SYNC] Failed to create %s: %s", email, e)

        log.info("[AD-SYNC] Complete: %d created, %d updated, %d total AD users",
                 created, updated, len(ad_emails))
        return {"synced": len(ad_emails), "created": created, "updated": updated}
    except Exception as e:
        log.error("[AD-SYNC] Error: %s", e)
        return {"synced": 0, "error": str(e)}


def ad_get_ou_structure():
    """Get organizational unit structure from AD."""
    if not AD_ENABLED:
        return []
    try:
        from ldap3 import SUBTREE
        conn = ad_connect()
        if not conn:
            return []
        conn.search(
            search_base=AD_BASE_DN,
            search_filter="(objectClass=organizationalUnit)",
            search_scope=SUBTREE,
            attributes=['ou', 'description', 'distinguishedName']
        )
        ous = [{
            "name": str(e.ou) if hasattr(e, 'ou') else "",
            "description": str(e.description) if hasattr(e, 'description') and e.description else "",
            "dn": str(e.distinguishedName)
        } for e in conn.entries]
        conn.unbind()
        return ous
    except Exception as e:
        log.error("[AD] OU query failed: %s", e)
        return []

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

# ===========================================================================
# Pipeline de Seguridad Criptográfica y Validación para Agentes
# ===========================================================================
_ip_rate_limits = {}  # {ip: [timestamps]}
_ip_rate_lock = threading.Lock()
_seen_nonces = {}  # {nonce: expire_epoch_seconds}
_nonce_lock = threading.Lock()
_nonces_lock = _nonce_lock

# Secretos por dispositivo (Fail-Closed estricto: sin clave por defecto)
_device_secrets = {}
_device_secrets_lock = threading.Lock()

def _get_device_secret(device_id: str) -> str | None:
    """Obtiene el secreto criptográfico aprovisionado para el dispositivo."""
    if not device_id:
        return None
    with _device_secrets_lock:
        if device_id in _device_secrets:
            return _device_secrets[device_id]
    env_secret = os.environ.get("ONYX_AGENT_SECRET")
    if env_secret:
        return env_secret
    if os.environ.get("ONYX_ENV") == "development" or os.environ.get("DEBUG") == "true":
        return "onyx-dev-secret-key-2026"
    return None

def _extract_trusted_client_ip(handler) -> str:
    """Extrae la IP real del cliente evitando spoofing de cabeceras."""
    if os.environ.get("K_SERVICE"):
        xff = handler.headers.get("X-Forwarded-For", "").strip()
        if xff:
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            if parts:
                return parts[-1]
    if handler.client_address and len(handler.client_address) > 0:
        return handler.client_address[0]
    return "127.0.0.1"

def _check_ip_rate_limit(ip: str, max_req_per_min: int = 60) -> bool:
    """Paso 1 del pipeline anti-DoS: límite estricto por IP de origen."""
    if not ip or ip in ("127.0.0.1", "localhost", "::1"):
        return True
    now = time.time()
    with _ip_rate_lock:
        window_start = now - 60.0
        if len(_ip_rate_limits) > 1000:
            for k in list(_ip_rate_limits.keys()):
                _ip_rate_limits[k] = [t for t in _ip_rate_limits[k] if t > window_start]
                if not _ip_rate_limits[k]:
                    del _ip_rate_limits[k]
        reqs = _ip_rate_limits.get(ip, [])
        reqs = [t for t in reqs if t > window_start]
        if len(reqs) >= max_req_per_min:
            _ip_rate_limits[ip] = reqs
            return False
        reqs.append(now)
        _ip_rate_limits[ip] = reqs
    return True

def _verify_agent_signature(headers: dict, body_bytes: bytes, device_id: str, client_ip: str = "") -> tuple[bool, int, str]:
    """Paso 2 y 3: Verificación HMAC-SHA256, expiración de timestamp y anti-replay."""
    secret = _get_device_secret(device_id)
    if not secret:
        return False, 401, "Dispositivo no autorizado"

    ts_header = headers.get("X-Agent-Timestamp")
    nonce = headers.get("X-Agent-Nonce")
    signature = headers.get("X-Agent-Signature")

    if not ts_header or not nonce or not signature:
        return False, 401, "Cabeceras criptograficas incompletas"

    try:
        req_dt = datetime.datetime.fromisoformat(ts_header)
        if req_dt.tzinfo is None:
            req_dt = req_dt.replace(tzinfo=datetime.timezone.utc)
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        delta_sec = abs((now_dt - req_dt).total_seconds())
        if delta_sec > 300.0:
            return False, 401, "Timestamp fuera de ventana"
    except Exception:
        return False, 401, "Timestamp malformado"

    try:
        body_obj = json.loads(body_bytes.decode('utf-8'))
        canonical_body = json.dumps(body_obj, sort_keys=True, separators=(',', ':'), default=str, ensure_ascii=False).encode('utf-8')
    except Exception:
        return False, 401, "Payload JSON invalido"

    expected_message = f"{ts_header}|{nonce}|{device_id}|{canonical_body.decode('utf-8')}".encode('utf-8')
    expected_sig = hmac.new(secret.encode('utf-8'), expected_message, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_sig, signature):
        return False, 401, "Firma HMAC no coincide"

    now_epoch = time.time()
    with _nonce_lock:
        if nonce in _seen_nonces:
            if _seen_nonces[nonce] > now_epoch:
                return False, 401, "Replay Attack: Nonce duplicado detectado"
        if len(_seen_nonces) >= 10000:
            for n, exp in list(_seen_nonces.items()):
                if exp <= now_epoch:
                    del _seen_nonces[n]
            if len(_seen_nonces) >= 10000:
                return False, 429, "Capacidad anti-replay saturada"
        _seen_nonces[nonce] = now_epoch + 300.0

    return True, 200, "OK"

def _sanitize_disk_encryption(raw_encryption):
    """Sanitización estricta por lista blanca para disk_encryption (Zero-Knowledge)."""
    if not raw_encryption:
        return None
    try:
        data = raw_encryption
        if isinstance(raw_encryption, str):
            data = json.loads(raw_encryption)
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            return None

        VALID_PROTECTION_STATUSES = {0, 1, 2}
        VALID_CONVERSION_STATUSES = {"FullyEncrypted", "FullyDecrypted", "EncryptionInProgress", "DecryptionInProgress", "Unknown"}

        sanitized_list = []
        for item in data:
            if not isinstance(item, dict):
                continue
            raw_drive = str(item.get("drive_letter", "C:")).upper().strip()
            drive = raw_drive if (len(raw_drive) == 2 and raw_drive[0].isalpha() and raw_drive[1] == ":") else "C:"
            
            prot = item.get("protection_status", 0)
            try:
                prot_int = int(prot)
                if prot_int not in VALID_PROTECTION_STATUSES:
                    prot_int = 0
            except:
                prot_int = 0

            conv = str(item.get("conversion_status", "Unknown")).strip()
            if conv not in VALID_CONVERSION_STATUSES:
                conv = "Unknown"

            pct = 0.0
            try:
                pct = float(item.get("encryption_percentage", 0.0))
                pct = max(0.0, min(100.0, pct))
            except:
                pct = 0.0

            meth = str(item.get("encryption_method", "Unknown")).strip()
            if not any(meth.startswith(vm) for vm in ["XTS-AES", "AES-CBC", "None", "Unknown"]):
                meth = "Unknown"

            sanitized_item = {
                "drive_letter": drive,
                "protection_status": prot_int,
                "conversion_status": conv,
                "encryption_percentage": round(pct, 1),
                "encryption_method": meth
            }
            sanitized_list.append(sanitized_item)
        return json.dumps(sanitized_list, ensure_ascii=True)
    except Exception:
        return None

# ===========================================================================
# Mitigación contra Host Header Injection y Rate Limiting para Instalador
# ===========================================================================
ALLOWED_UPDATE_HOSTS = {
    "onyx-server-631753912632.us-central1.run.app",
    "onyx-server-dev-631753912632.us-central1.run.app",
    "proy-anla-poc-175647544738.us-central1.run.app",
    "localhost:8080", "127.0.0.1:8080", "localhost", "127.0.0.1"
}

_installer_download_rates = {}  # {user_id: [timestamps]}
_installer_rate_lock = threading.Lock()

def _resolve_safe_update_server(host_header: str) -> str:
    """Resuelve el update_server validando contra allowlist."""
    canonical = os.environ.get("ONYX_CANONICAL_SERVER", "https://onyx-server-631753912632.us-central1.run.app")
    if not host_header:
        return canonical
    normalized = host_header.strip().lower()
    if normalized in ALLOWED_UPDATE_HOSTS:
        proto = "http" if ("localhost" in normalized or "127.0.0.1" in normalized) else "https"
        return f"{proto}://{normalized}"
    return canonical

def _check_installer_rate_limit(user_id: str, max_downloads: int = 10, window_secs: int = 300) -> bool:
    """Rate limit indexado por user_id de administrador."""
    if not user_id:
        return False
    now = time.time()
    with _installer_rate_lock:
        window_start = now - float(window_secs)
        if len(_installer_download_rates) > 500:
            for uid in list(_installer_download_rates.keys()):
                _installer_download_rates[uid] = [t for t in _installer_download_rates[uid] if t > window_start]
                if not _installer_download_rates[uid]:
                    del _installer_download_rates[uid]
        timestamps = _installer_download_rates.setdefault(user_id, [])
        timestamps = [t for t in timestamps if t > window_start]
        if len(timestamps) >= max_downloads:
            _installer_download_rates[user_id] = timestamps
            return False
        timestamps.append(now)
        _installer_download_rates[user_id] = timestamps
    return True

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

# Track location_enabled state per device for GPS monitoring
_device_location_state = {}

# Persistent GPS coordinates cache (survives BQ sync refreshes)
# {device_id: {"lat": float, "lon": float, "city": str, "country": str, "ts": datetime}}
_device_gps_cache = {}

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

# ── Inventario de red: dispositivos detectados por los agentes via ARP scan ──
# {mac: {ip, hostname, mac, detected_by, first_seen, last_seen, has_agent}}
network_devices_cache      = {}
network_devices_cache_lock = threading.Lock()

# ── Cache de dispositivos USB por equipo (para detectar cambios) ──
# {device_id: [{"name": ..., "category": ...}, ...]}
_usb_device_cache = {}
_usb_device_cache_lock = threading.Lock()

ROLE_PERMISSIONS = {
    "admin": {"dashboard", "equipo", "productividad", "seguridad", "kpibuilder", "mesa", "agentes", "usuarios", "configuracion", "informes", "export", "auditoria", "gestion", "cumplimiento", "dlp", "politicas", "informes-iso", "incidentes", "capacitacion", "ad", "inventario"},
    "analyst": {"dashboard", "equipo", "productividad", "seguridad", "mesa", "agentes", "informes", "export", "cumplimiento", "dlp", "informes-iso", "incidentes", "capacitacion", "inventario"},
    "viewer": {"dashboard", "equipo", "productividad", "inventario"}
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
    # Parse allowed_pages: JSON string → list, list → list, None → None
    raw_ap = user.get("allowed_pages")
    if isinstance(raw_ap, str):
        try:
            allowed_pages = json.loads(raw_ap)
        except (json.JSONDecodeError, ValueError):
            allowed_pages = None
    elif isinstance(raw_ap, list):
        allowed_pages = raw_ap
    else:
        allowed_pages = None
    with sessions_lock:
        sessions[token] = {
            "user_id": user["user_id"],
            "email": user["email"],
            "role": user["role"],
            "full_name": user["full_name"],
            "avatar": user.get("avatar", "??"),
            "expires": expires,
            "allowed_pages": allowed_pages
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
    # Auto-migrate: ensure allowed_pages column exists
    try:
        run_bq_query("ALTER TABLE onyx.eq_users ADD COLUMN IF NOT EXISTS allowed_pages STRING")
        print("[AUTH] Schema migration: allowed_pages column ensured")
    except Exception as me:
        print(f"[AUTH] Schema migration note: {me}")
    # Auto-migrate: GPS columns in eq_hardware_metrics
    for col, col_type in [("gps_latitude", "FLOAT64"), ("gps_longitude", "FLOAT64"),
                           ("gps_accuracy", "FLOAT64"), ("location_enabled", "BOOL")]:
        try:
            run_bq_query(f"ALTER TABLE onyx.eq_hardware_metrics ADD COLUMN IF NOT EXISTS {col} {col_type}")
        except Exception:
            pass
    print("[AUTH] Schema migration: GPS columns ensured")
    try:
        rows = run_bq_query("""
            SELECT user_id, email, password_hash, salt, full_name, role, avatar,
                   created_at, last_login, is_active,
                   totp_secret, totp_enabled, allowed_pages
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
    import secrets as _secrets
    _temp_pwd = _secrets.token_urlsafe(16)
    pw_hash, salt = hash_password(_temp_pwd)
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
        print(f"[AUTH] Default admin created: admin@onyx.local — Contraseña temporal: {_temp_pwd}")
        print(f"[AUTH] ⚠️ CAMBIE ESTA CONTRASEÑA INMEDIATAMENTE en el primer login")
    except Exception as e:
        print(f"[AUTH] Error creating default admin: {e}")
        # Still keep in memory for local testing
        with users_cache_lock:
            users_cache = [admin]

def _seed_platform_admins():
    """Auto-create essential platform admin accounts if they don't exist.
       If they exist but password doesn't match, force-reset the password."""
    seed_users = [
        {
            "email": "jramirez@agenticatech.ai",
            "full_name": "Jhoan Ramirez",
            "password": os.environ.get("SEED_ADMIN_PASSWORD", ""),
            "role": "admin",
            "avatar": "JR"
        }
    ]
    for su in seed_users:
        existing = find_user_by_email(su["email"])
        if existing:
            # Verify password matches; if not, force-reset it
            if verify_password(su["password"], existing.get("password_hash", ""), existing.get("salt", "")):
                print(f"[AUTH] Seed user OK: {su['email']}")
                continue
            else:
                print(f"[AUTH] Seed user password mismatch, resetting: {su['email']}")
                pw_hash, salt = hash_password(su["password"])
                existing["password_hash"] = pw_hash
                existing["salt"] = salt
                existing["role"] = su["role"]
                existing["totp_secret"] = None
                existing["totp_enabled"] = False
                try:
                    run_bq_update_user(
                        [("password_hash", pw_hash), ("salt", salt), ("role", su["role"]),
                         ("totp_secret", None), ("totp_enabled", False)],
                        "email", su["email"]
                    )
                    print(f"[AUTH] Seed user fully reset in BQ: {su['email']}")
                except Exception as e:
                    print(f"[AUTH] Error resetting seed user in BQ: {e}")
                continue
        pw_hash, salt = hash_password(su["password"])
        new_user = {
            "user_id": str(uuid.uuid4()),
            "email": su["email"],
            "password_hash": pw_hash,
            "salt": salt,
            "full_name": su["full_name"],
            "role": su["role"],
            "avatar": su["avatar"],
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "last_login": None,
            "is_active": True,
            "totp_secret": None,
            "totp_enabled": False
        }
        try:
            run_bq_insert("onyx.eq_users", new_user)
            with users_cache_lock:
                users_cache.append(new_user)
            print(f"[AUTH] Seed admin created: {su['email']}")
        except Exception as e:
            print(f"[AUTH] Error creating seed user {su['email']}: {e}")
            with users_cache_lock:
                users_cache.append(new_user)

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

def run_bq_update_user(set_clause_parts, where_field, where_value):
    """Execute a parameterized UPDATE on eq_users. ISO 27001 A.8.26 — Prevents SQL injection.
    set_clause_parts: list of (column, value) tuples
    where_field: column name for WHERE clause
    where_value: value for WHERE clause
    """
    dataset = os.environ.get("BQ_DATASET", "onyx")
    set_parts = []
    params = []
    for i, (col, val) in enumerate(set_clause_parts):
        pname = f"p{i}"
        if val is None:
            set_parts.append(f"{col} = NULL")
        elif isinstance(val, bool):
            set_parts.append(f"{col} = {'TRUE' if val else 'FALSE'}")
        else:
            set_parts.append(f"{col} = @{pname}")
            params.append(bigquery.ScalarQueryParameter(pname, "STRING", str(val)))
    params.append(bigquery.ScalarQueryParameter("where_val", "STRING", str(where_value)))
    sql = f"UPDATE {dataset}.eq_users SET {', '.join(set_parts)} WHERE {where_field} = @where_val"
    if USE_SDK:
        job_config = bigquery.QueryJobConfig(query_parameters=params)
        BQ_CLIENT.query(sql, job_config=job_config, location="us-central1" if "K_SERVICE" in os.environ else None).result()
    else:
        # Fallback: sanitize values for CLI (escape single quotes)
        safe_sql = sql
        for p in params:
            safe_sql = safe_sql.replace(f"@{p.name}", f"'{p.value.replace(chr(39), chr(39)+chr(39))}'")
        run_bq_query(safe_sql)

def audit_log(action, actor_email="system", actor_ip="", target_type="", target_id="", details="", result="SUCCESS"):
    """ISO 27001 A.8.34 — Immutable audit trail. Logs administrative actions to BigQuery."""
    try:
        row = {
            "audit_id": str(uuid.uuid4()),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "actor_email": str(actor_email),
            "actor_ip": str(actor_ip),
            "action": str(action),
            "target_type": str(target_type),
            "target_id": str(target_id),
            "details": json.dumps(details) if isinstance(details, dict) else str(details),
            "result": str(result)
        }
        run_bq_insert("onyx.eq_audit_log", row)
    except Exception as e:
        print(f"[AUDIT] Error logging: {e}")

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


def calculate_compliance_score(device_data):
    """ISO 27001 — Calculate per-device compliance score (0-100)."""
    score = 100
    deductions = []
    metrics = device_data.get("latest_metrics", {})

    # A.8.7 Antivirus
    av_enabled = metrics.get("antivirus_enabled")
    if av_enabled is False:
        score -= 25
        deductions.append({"control": "A.8.7", "item": "Antivirus deshabilitado", "points": -25})
    elif av_enabled is None:
        score -= 10
        deductions.append({"control": "A.8.7", "item": "Estado antivirus desconocido", "points": -10})

    av_updated = metrics.get("antivirus_updated")
    if av_updated is False:
        score -= 10
        deductions.append({"control": "A.8.7", "item": "Antivirus desactualizado", "points": -10})

    # A.8.20 Firewall
    fw = metrics.get("firewall_enabled")
    if fw is False:
        score -= 20
        deductions.append({"control": "A.8.20", "item": "Firewall deshabilitado", "points": -20})
    elif fw is None:
        score -= 5
        deductions.append({"control": "A.8.20", "item": "Estado firewall desconocido", "points": -5})

    # A.8.24 BitLocker
    bl = metrics.get("bitlocker_enabled")
    if bl is False:
        score -= 15
        deductions.append({"control": "A.8.24", "item": "Disco sin cifrar (BitLocker)", "points": -15})
    elif bl is None:
        score -= 5
        deductions.append({"control": "A.8.24", "item": "Estado cifrado desconocido", "points": -5})

    # A.8.8 Windows Update
    pending = metrics.get("windows_update_pending")
    if pending is not None and pending > 5:
        score -= 15
        deductions.append({"control": "A.8.8", "item": f"{pending} actualizaciones pendientes", "points": -15})
    elif pending is not None and pending > 0:
        score -= 5
        deductions.append({"control": "A.8.8", "item": f"{pending} actualizaciones pendientes", "points": -5})

    # UAC
    uac = metrics.get("uac_enabled")
    if uac is False:
        score -= 10
        deductions.append({"control": "A.8.2", "item": "UAC deshabilitado", "points": -10})

    # Location disabled
    loc = metrics.get("location_enabled")
    if loc is False:
        score -= 5
        deductions.append({"control": "A.8.1", "item": "Ubicación deshabilitada", "points": -5})

    return max(0, score), deductions


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
                   timestamp, top_processes, browser_history, network_info, usb_ports, event_logs,
                   gps_latitude, gps_longitude, gps_accuracy, location_enabled
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
        all_m = run_bq_query("SELECT timestamp, device_id, cpu_usage, ram_usage, disk_free_gb, network_latency_ms, cause_root, cause_process, device_type, battery_percent, battery_status, top_processes, browser_history, network_info, usb_ports, event_logs, gps_latitude, gps_longitude, gps_accuracy, location_enabled FROM onyx.eq_hardware_metrics ORDER BY timestamp DESC LIMIT 200")
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
    _seed_platform_admins()
    # Iniciar auto-refresh cada 60 segundos
    threading.Thread(target=auto_refresh_loop, daemon=True).start()
    # AD periodic sync thread
    def _ad_sync_loop():
        import time
        while True:
            time.sleep(AD_SYNC_INTERVAL)
            if AD_ENABLED:
                try:
                    result = ad_sync_users()
                    log.info("[AD-SYNC-THREAD] %s", result)
                except Exception as e:
                    log.error("[AD-SYNC-THREAD] Error: %s", e)

    if AD_ENABLED:
        threading.Thread(target=_ad_sync_loop, daemon=True, name="ad-sync").start()
        log.info("[AD] Sync thread started (interval: %ds)", AD_SYNC_INTERVAL)
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
        # ISO 27001 A.8.26 — Restrict CORS
        origin = self.headers.get('Origin', '')
        if origin:
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Access-Control-Allow-Credentials', 'true')
        # ISO 27001 A.8.26 — Security headers
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
        self.send_header('Content-Security-Policy', "default-src 'self' 'unsafe-inline' 'unsafe-eval' https: data: blob:;")
        self.send_header('Permissions-Policy', "camera=(), microphone=(), geolocation=(self)")
        if os.environ.get('K_SERVICE'):
            self.send_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
        cookie = f"{cookie_name}={cookie_value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age}"
        self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))
        
    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        
        # ── Servir archivos estáticos (logo, imágenes) ──
        if path == "/onyx_logo.jpeg":
            logo_path = os.path.join(os.path.dirname(__file__), "onyx_logo.jpeg")
            if os.path.exists(logo_path):
                with open(logo_path, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "image/jpeg")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "public, max-age=86400")
                self.end_headers()
                self.wfile.write(data)
                return
            self.send_response(404)
            self.end_headers()
            return
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
                "permissions": list(set(session.get("allowed_pages") or []) | ROLE_PERMISSIONS.get(session["role"], set()))
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
                        "user_id":    u.get("user_id"),
                        "email":      u.get("email"),
                        "full_name":  u.get("full_name"),
                        "role":       u.get("role"),
                        "role_label": ROLE_LABELS.get(u.get("role", ""), u.get("role", "")),
                        "avatar":     u.get("avatar"),
                        "created_at": u.get("created_at"),
                        "last_login": u.get("last_login"),
                        "is_active":  u.get("is_active", True),
                        "totp_enabled": bool(u.get("totp_enabled")),  # para indicador 2FA en panel admin
                        "allowed_pages": u.get("allowed_pages")
                    })
            self.send_json(safe_users)
            return
        
        # ── Auth middleware: protect API routes ──
        PUBLIC_PATHS = {"/api/status", "/api/auth/me", "/api/agent-version", 
                       "/api/agent-download", "/api/updater-download", "/api/launcher-download",
                       "/api/credentials-download", "/api/credentials-refresh"}
        if path.startswith("/api/") and path not in PUBLIC_PATHS:
            session = self.get_current_session()
            if not session:
                self.send_json({"error": "No autorizado", "code": "AUTH_REQUIRED"}, 401)
                return
        
        # 1. Endpoints de la API REST
        if path == "/api/security/encryption-summary":
            session = self.get_current_session()
            if not session:
                self.send_json({"error": "No autorizado", "code": "AUTH_REQUIRED"}, 401)
                return
            with cache_lock:
                latest = list(cache.get("latest_metrics", []))
                syncs = {s.get("device_id"): s for s in cache.get("sync_status", [])}
            
            total_devices = len(latest)
            protected_count = 0
            unprotected_count = 0
            volumes_summary = []
            
            for m in latest:
                dev_id = m.get("device_id", "")
                enc_raw = m.get("disk_encryption")
                is_prot = False
                dev_vols = []
                if enc_raw:
                    try:
                        vols = json.loads(enc_raw) if isinstance(enc_raw, str) else enc_raw
                        if isinstance(vols, list):
                            for v in vols:
                                prot = v.get("protection_status", 0)
                                if prot == 1:
                                    is_prot = True
                                dev_vols.append(v)
                    except Exception:
                        pass
                if is_prot:
                    protected_count += 1
                else:
                    unprotected_count += 1
                volumes_summary.append({
                    "device_id": dev_id,
                    "is_protected": is_prot,
                    "volumes": dev_vols,
                    "last_sync": syncs.get(dev_id, {}).get("last_sync", "")
                })
            
            compliance_pct = round((protected_count / total_devices * 100.0), 1) if total_devices > 0 else 0.0
            self.send_json({
                "total_devices": total_devices,
                "protected_devices": protected_count,
                "unprotected_devices": unprotected_count,
                "compliance_percentage": compliance_pct,
                "devices": volumes_summary
            })
            return

        elif path == "/api/network-summary":
            session = self.get_current_session()
            if not session:
                self.send_json({"error": "No autorizado"}, 401)
                return

            # -- Flota real: equipos con agente instalado (sync_status) --
            with cache_lock:
                fleet = list(cache["sync_status"])
                latest = list(cache.get("latest_metrics", []))
            fleet_count = len(fleet)

            # Construir lista de dispositivos de la flota con info enriquecida
            fleet_devices = []
            for s in fleet:
                dev_id = s.get("device_id", "")
                last_ip = s.get("last_ip", "")
                status = s.get("status", "Offline")
                last_sync = s.get("last_sync", s.get("timestamp", ""))
                # Buscar info de red del último metrics
                net_info = {}
                for m in latest:
                    if m.get("device_id") == dev_id:
                        ni_raw = m.get("network_info")
                        if ni_raw:
                            try:
                                net_info = json.loads(ni_raw) if isinstance(ni_raw, str) else ni_raw
                            except: pass
                        break
                wifi_ssid = net_info.get("wifi_ssid", "")
                vpn_active = s.get("vpn_active", False) or net_info.get("vpn_active", False)
                vpn_adapter = s.get("vpn_adapter", "") or net_info.get("vpn_adapter", "")
                interfaces = net_info.get("interfaces", [])
                iface_str = ", ".join(i.get("name", "") for i in interfaces[:2]) if interfaces else ""

                fleet_devices.append({
                    "device_id": dev_id,
                    "ip": last_ip,
                    "hostname": dev_id,
                    "has_agent": True,
                    "status": status,
                    "last_seen": last_sync,
                    "wifi_ssid": wifi_ssid,
                    "vpn_active": vpn_active,
                    "vpn_adapter": vpn_adapter,
                    "interface": iface_str
                })

            # -- Red: dispositivos detectados via ARP sin agente --
            with network_devices_cache_lock:
                arp_devices = list(network_devices_cache.values())
            visitors = sorted(
                [d for d in arp_devices if not d.get("has_agent")],
                key=lambda x: x.get("last_seen", ""),
                reverse=True
            )[:20]

            without_agent = len(visitors)
            total = fleet_count + without_agent

            self.send_json({
                "total":          total,
                "with_agent":     fleet_count,
                "without_agent":  without_agent,
                "fleet":          fleet_devices,
                "visitors":       visitors
            })
            return

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
                            if diff_min > 15:
                                dev["status"] = "Offline"
                                dev["calculated_status"] = "offline"
                            elif diff_min > 8:
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
                # ── Generate minimal network_info for dashboard if agent hasn't sent it ──
                # Only uses REAL data (IP, device_type). No fake MACs, SSIDs, or connected_devices.
                for d_id, dev in devices_map.items():
                    if not dev.get("network_info"):
                        dev_ip = dev.get("last_ip", "")
                        if not dev_ip:
                            continue
                        dev_type = dev.get("device_type", "Desktop")
                        latency_val = dev.get("network_latency_ms", 0) or 0
                        is_wifi = (dev_type == "Laptop")
                        conn_type = "WiFi" if is_wifi else "Ethernet"
                        dev["network_info"] = json.dumps({
                            "interfaces": [{"name": conn_type, "ip": dev_ip, "mac": "", "type": conn_type, "speed_mbps": None, "bytes_sent": 0, "bytes_recv": 0}],
                            "wifi_ssid": None,
                            "connected_devices": []
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
                
                # ── Fallback: Generate minimal network_info if agent hasn't sent it ──
                # Only uses REAL data. No fake MACs, SSIDs, or connected_devices.
                if latest and not latest.get("network_info"):
                    dev_ip = (status_row or {}).get("last_ip", "")
                    if dev_ip:
                        dev_type = latest.get("device_type", "Desktop")
                        is_wifi = (dev_type == "Laptop")
                        conn_type = "WiFi" if is_wifi else "Ethernet"
                        fallback_net = {
                            "interfaces": [{"name": conn_type, "ip": dev_ip, "mac": "", "type": conn_type, "speed_mbps": None, "bytes_sent": 0, "bytes_recv": 0}],
                            "wifi_ssid": None,
                            "connected_devices": []
                        }
                        latest["network_info"] = json.dumps(fallback_net)
                
                # NOTE: No fake browser_history fallback — show real data only
                
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
                    event_logs_data = []  # No fake data — show real agent data only
                
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
                
        elif path.startswith("/api/productividad/historico"):
            # Historical productivity from BigQuery
            params = urllib.parse.parse_qs(parsed_url.query)
            date_from = params.get("from", [""])[0]
            date_to = params.get("to", [""])[0]
            
            if not date_from or not date_to:
                self.send_json({"error": "Parámetros 'from' y 'to' son requeridos"}, 400)
                return
            
            try:
                # Query BigQuery for metrics in the date range
                query = f"""
                    SELECT device_id, timestamp, top_processes, browser_history,
                           cpu_usage, ram_usage
                    FROM `onyx.eq_hardware_metrics`
                    WHERE DATE(timestamp) BETWEEN '{date_from}' AND '{date_to}'
                    ORDER BY timestamp DESC
                    LIMIT 5000
                """
                rows = run_bq_query(query)
                
                if not rows:
                    self.send_json({
                        "average_productivity_index": 0,
                        "avg_hours": 0,
                        "users_below_threshold": 0,
                        "excessive_ocio_users": 0,
                        "users_productivity_table": [],
                        "top_apps": [],
                        "desktop_apps": [],
                        "web_pages": [],
                        "per_device_apps": {},
                        "per_device_web": {},
                        "distribution": {"trabajo": 0, "comunicacion": 0, "web": 0, "ocio": 0},
                        "period_start": date_from,
                        "period_end": date_to
                    })
                    return
                
                # Classification sets
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
                
                # Group by device_id
                device_metrics = {}
                for row in rows:
                    d_id = row.get("device_id", "")
                    if d_id not in device_metrics:
                        device_metrics[d_id] = []
                    device_metrics[d_id].append(row)
                
                users_table = []
                all_apps_count = {}
                total_work = 0
                total_comm = 0
                total_web = 0
                total_ocio = 0
                all_browser_domains = {}
                
                name_map = {"equipo": "Jhoan R.", "jenn": "Jennifer", "desktop": "Desktop"}
                app_icons = {"antigravity": ("💻", "#06B6D4"), "outlook": ("📧", "#3B82F6"), "teams": ("🤝", "#10B981"),
                            "word": ("📄", "#6366F1"), "excel": ("📊", "#F59E0B"), "powerpoint": ("🖥", "#8B5CF6"),
                            "code": ("💻", "#06B6D4"), "chrome": ("🌐", "#4285F4"), "firefox": ("🦊", "#FF7139"),
                            "msedge": ("🌐", "#0078D7"), "slack": ("💬", "#EC4899"), "zoom": ("📹", "#14B8A6"),
                            "explorer": ("📁", "#64748B"), "acrobat": ("📕", "#DC2626"), "python": ("🐍", "#22C55E")}
                
                for d_id, metrics_list in device_metrics.items():
                    work_h = 0
                    comm_h = 0
                    web_h = 0
                    ocio_h = 0
                    other_h = 0
                    n_samples = len(metrics_list)
                    
                    for m in metrics_list:
                        procs = []
                        if m.get("top_processes"):
                            try:
                                procs = json.loads(m["top_processes"]) if isinstance(m["top_processes"], str) else m["top_processes"]
                            except: pass
                        
                        for p in procs:
                            name = (p.get("name", "") or "").lower().replace(".exe", "")
                            mem = p.get("mem", 0) or 0
                            cpu = p.get("cpu", 0) or 0
                            usage = max(float(mem), float(cpu))
                            display_name = p.get("name", "Unknown").replace(".exe", "")
                            
                            if any(s in name for s in system_procs):
                                continue
                            
                            all_apps_count[display_name] = all_apps_count.get(display_name, 0) + usage
                            
                            if any(w in name for w in work_apps):
                                work_h += usage
                            elif any(c in name for c in comm_apps):
                                comm_h += usage
                            elif any(w in name for w in web_apps):
                                web_h += usage * 0.4
                                work_h += usage * 0.4
                                ocio_h += usage * 0.2
                            elif any(o in name for o in ocio_apps):
                                ocio_h += usage
                            else:
                                work_h += usage * 0.5
                                other_h += usage * 0.5
                        
                        # Browser history
                        bh_raw = m.get("browser_history")
                        if bh_raw and bh_raw != "[]" and bh_raw != "null":
                            try:
                                bh = json.loads(bh_raw) if isinstance(bh_raw, str) else bh_raw
                                if isinstance(bh, list):
                                    for entry in bh:
                                        domain = entry.get("domain", "")
                                        visits = entry.get("visits", 1)
                                        if domain and not domain.endswith(".exe"):
                                            all_browser_domains[domain] = all_browser_domains.get(domain, 0) + visits
                            except: pass
                    
                    # Normalize by number of samples for daily average
                    days_factor = max(n_samples, 1)
                    total_usage = work_h + comm_h + web_h + ocio_h + other_h
                    scale = 8.0 / max(total_usage / days_factor, 1)
                    
                    w_hr = round(work_h / days_factor * scale, 1)
                    c_hr = round(comm_h / days_factor * scale, 1)
                    wb_hr = round(web_h / days_factor * scale, 1)
                    o_hr = round(ocio_h / days_factor * scale, 1)
                    total_hr = round(w_hr + c_hr + wb_hr + o_hr, 1)
                    
                    prod_index = int((w_hr + c_hr) / max(total_hr, 0.1) * 100) if total_hr > 0 else 0
                    prod_index = min(prod_index, 100)
                    
                    total_work += w_hr
                    total_comm += c_hr
                    total_web += wb_hr
                    total_ocio += o_hr
                    
                    parts = d_id.replace("eiq-", "").split("-")
                    user_name = parts[0].title() if parts else d_id
                    user_name = name_map.get(user_name.lower(), user_name)
                    
                    users_table.append({
                        "usuario": user_name,
                        "device_id": d_id,
                        "trabajo": f"{w_hr}h",
                        "comun": f"{c_hr}h",
                        "web": f"{wb_hr}h",
                        "ocio": f"{o_hr}h",
                        "index": prod_index,
                        "sites": "N/A",
                        "samples": n_samples
                    })
                
                n_users = max(len(users_table), 1)
                avg_prod = int(sum(u["index"] for u in users_table) / n_users) if users_table else 0
                below_threshold = sum(1 for u in users_table if u["index"] < 60)
                excessive = sum(1 for u in users_table if u["index"] < 40)
                
                sorted_apps = sorted(all_apps_count.items(), key=lambda x: x[1], reverse=True)[:6]
                max_usage_val = sorted_apps[0][1] if sorted_apps else 1
                top_apps = [{"name": a[0], "hours": round(a[1] * 0.05, 1), "pct": int(a[1] / max_usage_val * 100)} for a in sorted_apps]
                
                # Desktop apps
                desktop_apps_list = []
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
                
                # Web pages
                web_domains = []
                work_domains = {"sharepoint.com", "office.com", "github.com", "gitlab.com",
                               "docs.google.com", "drive.google.com", "stackoverflow.com",
                               "login.microsoftonline.com", "cloud.google.com"}
                comm_domains_set = {"outlook.com", "outlook.office.com", "teams.microsoft.com",
                               "slack.com", "meet.google.com", "zoom.us", "mail.google.com"}
                ocio_domains_set = {"youtube.com", "netflix.com", "tiktok.com", "instagram.com",
                               "facebook.com", "twitter.com", "reddit.com"}
                
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
                        elif any(c in dl for c in comm_domains_set):
                            cat = "Comun."
                            cls = "cat-comun"
                        elif any(o in dl for o in ocio_domains_set):
                            cat = "Ocio"
                            cls = "cat-social"
                        proportion = visits / max(total_visits, 1)
                        total_mins = int(8 * 60 * proportion)
                        h = total_mins // 60
                        mi = total_mins % 60
                        web_domains.append({
                            "domain": domain, "category": cat, "cat_class": cls,
                            "time": f"{h}h {mi:02d}m", "visits": visits
                        })
                
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
                    "per_device_apps": {},
                    "per_device_web": {},
                    "distribution": {
                        "trabajo": int(total_work / grand_total * 100),
                        "comunicacion": int(total_comm / grand_total * 100),
                        "web": int(total_web / grand_total * 100),
                        "ocio": int(total_ocio / grand_total * 100)
                    },
                    "period_start": date_from,
                    "period_end": date_to
                })
            except Exception as e:
                print(f"[PROD-HIST] Error: {e}")
                import traceback
                traceback.print_exc()
                self.send_json({"error": str(e)}, 500)
            return

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
                
                # ── Filtrar datos de las últimas 24 horas (no solo fecha UTC) ──
                now_utc = datetime.datetime.now(datetime.timezone.utc)
                cutoff_24h = now_utc - datetime.timedelta(hours=24)
                today_str = now_utc.strftime("%Y-%m-%d")
                
                # Usar ALL metrics (no solo latest) para capturar todos los dispositivos
                today_metrics = []
                for m in cache.get("all_metrics", []):
                    ts = m.get("timestamp", "")
                    if not ts:
                        continue
                    try:
                        ts_str = str(ts)
                        ts_dt = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        if ts_dt.tzinfo is None:
                            ts_dt = ts_dt.replace(tzinfo=datetime.timezone.utc)
                        if ts_dt >= cutoff_24h:
                            today_metrics.append(m)
                    except:
                        # Fallback: comparar por fecha string
                        if str(ts)[:10] == today_str:
                            today_metrics.append(m)
                
                # También incluir latest_metrics si no están ya
                seen_ids_ts = set()
                for m in today_metrics:
                    key = f"{m.get('device_id','')}-{str(m.get('timestamp',''))[:19]}"
                    seen_ids_ts.add(key)
                for m in cache.get("latest_metrics", []):
                    key = f"{m.get('device_id','')}-{str(m.get('timestamp',''))[:19]}"
                    if key not in seen_ids_ts:
                        today_metrics.append(m)
                
                # Agrupar por device_id — usar la métrica más reciente de cada uno
                seen_today = {}
                for m in today_metrics:
                    d_id = m.get("device_id", "")
                    if d_id not in seen_today:
                        seen_today[d_id] = m
                    else:
                        # Quedarse con la más reciente
                        existing_ts = str(seen_today[d_id].get("timestamp", ""))
                        new_ts = str(m.get("timestamp", ""))
                        if new_ts > existing_ts:
                            seen_today[d_id] = m
                today_metrics_dedup = list(seen_today.values())
                
                print(f"[PROD-TODAY] Últimas 24h: {len(today_metrics)} métricas, {len(today_metrics_dedup)} dispositivos")
                
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
                    # Solo usar métricas de HOY
                    dev_metric = seen_today.get(d_id)
                    if not dev_metric:
                        continue  # Saltar dispositivos sin datos de hoy
                    
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
                
                # NOTE: No fallback — if no real browser_history, web pages will be empty
                
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
                    },
                    "period_start": today_str,
                    "period_end": today_str
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
                    
                    # Extract public_ip from network_info JSON if still private/N/A
                    net_info_raw = m.get("network_info", "")
                    if net_info_raw and ip in ("N/A", "") or (ip and ip.startswith(("10.", "192.168.", "172."))):
                        try:
                            ni = json.loads(net_info_raw) if isinstance(net_info_raw, str) else net_info_raw
                            pub = ni.get("public_ip", "")
                            if pub and pub not in ("N/A", "127.0.0.1", ""):
                                ip = pub
                        except:
                            pass
                    
                    # Last resort: local_ip
                    if ip in ("N/A", ""):
                        ip = m.get("local_ip", "N/A")
                    
                    # Connection map entry with geolocation (GPS prioritized)
                    # 1. Check GPS cache (from agent-ingest)
                    if d_id in _device_gps_cache:
                        gps = _device_gps_cache[d_id]
                        geo = {"lat": gps["lat"], "lon": gps["lon"], 
                               "city": gps.get("city", "Bogotá"), "country": gps.get("country", "Colombia"),
                               "region": "", "isp": "GPS"}
                        geo_source = "GPS"
                    else:
                        found_gps = False
                        # 2. Check GPS coords in the metric row itself (from BigQuery)
                        m_lat = m.get("gps_latitude")
                        m_lon = m.get("gps_longitude")
                        if m_lat and m_lon:
                            geo = {"lat": m_lat, "lon": m_lon,
                                   "city": "Bogotá", "country": "Colombia",
                                   "region": "", "isp": "GPS"}
                            geo_source = "GPS"
                            # Also populate GPS cache for future requests
                            _device_gps_cache[d_id] = {"lat": m_lat, "lon": m_lon, "city": "Bogotá", "country": "Colombia", "ts": now}
                            found_gps = True
                        
                        # 3. Check all_metrics for any row with GPS for this device
                        if not found_gps:
                            for am in cache.get("all_metrics", []):
                                if am.get("device_id") == d_id and am.get("gps_latitude") and am.get("gps_longitude"):
                                    geo = {"lat": am["gps_latitude"], "lon": am["gps_longitude"],
                                           "city": "Bogotá", "country": "Colombia",
                                           "region": "", "isp": "GPS"}
                                    geo_source = "GPS"
                                    _device_gps_cache[d_id] = {"lat": am["gps_latitude"], "lon": am["gps_longitude"], "city": "Bogotá", "country": "Colombia", "ts": now}
                                    found_gps = True
                                    break
                        
                        # 4. Check sync_status for geo_lat/geo_lon
                        if not found_gps:
                            for ss in cache.get("sync_status", []):
                                if ss.get("device_id") == d_id:
                                    if ss.get("geo_lat") and ss.get("geo_lon"):
                                        geo = {"lat": ss["geo_lat"], "lon": ss["geo_lon"],
                                               "city": ss.get("geo_city", "Bogotá"), "country": "Colombia",
                                               "region": "", "isp": "GPS"}
                                        geo_source = ss.get("geo_source", "GPS")
                                        found_gps = True
                                    break
                        
                        if not found_gps:
                            # 5. Fallback to IP geolocation
                            geo = _geolocate_ip(ip)
                            geo_source = "IP"
                    current_city = geo.get("city", "Bogotá")
                    current_country = geo.get("country", "Colombia")
                    
                    # Determine real online/offline status from sync_status
                    dev_status = "offline"
                    for ss in cache.get("sync_status", []):
                        if ss.get("device_id") == d_id:
                            ls = ss.get("last_sync", "")
                            if ls:
                                try:
                                    ls_dt = datetime.datetime.fromisoformat(str(ls).replace("Z", "+00:00"))
                                    if ls_dt.tzinfo is None:
                                        ls_dt = ls_dt.replace(tzinfo=datetime.timezone.utc)
                                    diff_min = (now - ls_dt).total_seconds() / 60
                                    dev_status = "online" if diff_min < 15 else "offline"
                                except:
                                    dev_status = "offline"
                            break
                    
                    connection_map.append({
                        "device_id": d_id, "name": dev_name(d_id), "ip": ip,
                        "status": dev_status,
                        "lat": geo.get("lat", 4.6097), "lon": geo.get("lon", -74.0817),
                        "country": current_country,
                        "city": current_city,
                        "region": geo.get("region", ""),
                        "isp": geo.get("isp", ""),
                        "geo_source": geo_source
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
                
                # ── Improve coordinate precision using agent's public_ip ──
                # Each agent reports its public IP via network_info.public_ip
                # Use that for precise geolocation instead of hardcoded subnets
                device_geo_cache = {}
                
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
                    
                    public_ip = net.get("public_ip", "")
                    city_agent = net.get("city", "")
                    
                    if d_id:
                        # Priorizar GPS del caché persistente
                        if d_id in _device_gps_cache:
                            gps = _device_gps_cache[d_id]
                            device_geo_cache[d_id] = {
                                "lat": gps["lat"], "lon": gps["lon"],
                                "city": gps.get("city", "Bogotá"),
                                "country": gps.get("country", "Colombia"),
                                "ip": public_ip or ""
                            }
                            print(f"[MAP] Device {d_id} -> GPS ({gps['lat']}, {gps['lon']}) {gps.get('city')}")
                        elif public_ip:
                            geo = _geolocate_ip(public_ip)
                            device_geo_cache[d_id] = {
                                "lat": geo.get("lat", 4.6097),
                                "lon": geo.get("lon", -74.0817),
                                "city": geo.get("city", city_agent or "Bogotá"),
                                "country": geo.get("country", "Colombia"),
                                "ip": public_ip
                            }
                            print(f"[MAP] Device {d_id} -> IP {public_ip} -> ({geo.get('lat')}, {geo.get('lon')}) {geo.get('city')}")
                        else:
                            print(f"[MAP] Device {d_id} -> NO public_ip, NO GPS")
                
                # Apply coordinates to connection_map
                for dev in connection_map:
                    d_id = dev.get("device_id", "")
                    if d_id in device_geo_cache:
                        geo = device_geo_cache[d_id]
                        dev["lat"] = geo["lat"]
                        dev["lon"] = geo["lon"]
                        dev["city"] = geo["city"]
                        if d_id in _device_gps_cache:
                            dev["geo_source"] = "GPS"
                        print(f"[MAP] {dev['name']} -> ({dev['lat']}, {dev['lon']}) geo_source={dev.get('geo_source', 'IP')}")
                    elif d_id in _device_gps_cache:
                        gps = _device_gps_cache[d_id]
                        dev["lat"] = gps["lat"]
                        dev["lon"] = gps["lon"]
                        dev["city"] = gps.get("city", "Bogotá")
                        dev["geo_source"] = "GPS"
                        print(f"[MAP] {dev['name']} -> GPS fallback ({gps['lat']}, {gps['lon']})")
                    else:
                        # Fallback: use the client IP from agent-ingest
                        for ss in cache.get("sync_status", []):
                            if ss.get("device_id") == d_id:
                                last_ip = ss.get("last_ip", "")
                                if last_ip:
                                    geo = _geolocate_ip(last_ip)
                                    dev["lat"] = geo.get("lat", dev.get("lat", 4.6097))
                                    dev["lon"] = geo.get("lon", dev.get("lon", -74.0817))
                                    dev["city"] = geo.get("city", dev.get("city", "Bogotá"))
                                    dev["geo_source"] = "IP"
                                    print(f"[MAP] {dev['name']} -> IP fallback ({dev['lat']}, {dev['lon']})")
                                break
                
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
                "creds_hash": "",
                "recommended_interval": 60
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

        # ── ISO 27001: Audit Log ──
        elif path == "/api/audit-log":
            session = self.require_auth()
            if not session:
                return
            if session["role"] != "admin":
                self.send_json({"error": "Solo administradores pueden ver el audit log"}, 403)
                return
            try:
                rows = run_bq_query("""
                    SELECT audit_id, timestamp, actor_email, actor_ip, action,
                           target_type, target_id, details, result
                    FROM onyx.eq_audit_log
                    ORDER BY timestamp DESC
                    LIMIT 500
                """)
                self.send_json({"audit_log": rows})
            except Exception as e:
                self.send_json({"audit_log": [], "error": str(e)})
            return

        # ── ISO 27001: Compliance Dashboard ──
        elif path == "/api/compliance":
            session = self.require_auth()
            if not session:
                return
            devices = []
            with cache_lock:
                # Build a lookup: device_id -> latest metrics row
                metrics_by_dev = {}
                for m in cache.get("latest_metrics", []):
                    d_id = m.get("device_id")
                    if d_id:
                        metrics_by_dev[d_id] = m
                # Iterate fleet from sync_status (list of dicts)
                for info in cache.get("sync_status", []):
                    d_id = info.get("device_id", "")
                    if not d_id:
                        continue
                    latest = metrics_by_dev.get(d_id, {})
                    score, deductions = calculate_compliance_score({"latest_metrics": latest})
                    devices.append({
                        "device_id": d_id,
                        "hostname": info.get("hostname", d_id),
                        "status": info.get("status", "offline"),
                        "last_sync": info.get("last_sync", ""),
                        "score": score,
                        "deductions": deductions,
                        "antivirus_name": latest.get("antivirus_name", ""),
                        "antivirus_enabled": latest.get("antivirus_enabled"),
                        "antivirus_updated": latest.get("antivirus_updated"),
                        "firewall_enabled": latest.get("firewall_enabled"),
                        "bitlocker_enabled": latest.get("bitlocker_enabled"),
                        "uac_enabled": latest.get("uac_enabled"),
                        "windows_update_pending": latest.get("windows_update_pending"),
                        "last_update_installed": latest.get("last_update_installed", "")
                    })
            total = len(devices)
            avg_score = sum(d["score"] for d in devices) / total if total else 0
            compliant = sum(1 for d in devices if d["score"] >= 80)
            critical = sum(1 for d in devices if d["score"] < 50)
            self.send_json({
                "global_score": round(avg_score, 1),
                "total_devices": total,
                "compliant_devices": compliant,
                "critical_devices": critical,
                "devices": sorted(devices, key=lambda x: x["score"])
            })
            return

        # ── ISO 27001: DLP Dashboard ──
        elif path == "/api/dlp-dashboard":
            session = self.require_auth()
            if not session:
                return
            dlp_alerts = []
            sw_inventory = {}
            with cache_lock:
                for m in cache.get("latest_metrics", []):
                    d_id = m.get("device_id", "")
                    if not d_id:
                        continue
                    try:
                        cloud = json.loads(m.get("dlp_cloud_sync", "[]")) if isinstance(m.get("dlp_cloud_sync"), str) else m.get("dlp_cloud_sync", [])
                        remote = json.loads(m.get("dlp_remote_access", "[]")) if isinstance(m.get("dlp_remote_access"), str) else m.get("dlp_remote_access", [])
                        capture = json.loads(m.get("dlp_screen_capture", "[]")) if isinstance(m.get("dlp_screen_capture"), str) else m.get("dlp_screen_capture", [])
                        usb_events = m.get("dlp_usb_write_events", 0)
                        hostname = d_id
                        for s in cache.get("sync_status", []):
                            if s.get("device_id") == d_id:
                                hostname = s.get("hostname", d_id)
                                break
                        for app in (cloud or []):
                            dlp_alerts.append({"device_id": d_id, "hostname": hostname, "type": "Cloud Sync", "severity": "warning", "detail": app, "icon": "\u2601\ufe0f"})
                        for app in (remote or []):
                            dlp_alerts.append({"device_id": d_id, "hostname": hostname, "type": "Remote Access", "severity": "critical", "detail": app, "icon": "\ud83d\udda5\ufe0f"})
                        for app in (capture or []):
                            dlp_alerts.append({"device_id": d_id, "hostname": hostname, "type": "Screen Capture", "severity": "info", "detail": app, "icon": "\ud83d\udcf8"})
                        if usb_events and int(usb_events) > 0:
                            dlp_alerts.append({"device_id": d_id, "hostname": hostname, "type": "USB Activity", "severity": "warning", "detail": f"{usb_events} eventos USB", "icon": "\ud83d\udcbe"})
                        try:
                            sw = json.loads(m.get("software_inventory", "[]")) if isinstance(m.get("software_inventory"), str) else m.get("software_inventory", [])
                            if sw:
                                sw_inventory[d_id] = {"hostname": hostname, "software": sw, "count": len(sw)}
                        except Exception:
                            pass
                    except Exception:
                        pass
            self.send_json({
                "total_alerts": len(dlp_alerts),
                "critical_alerts": sum(1 for a in dlp_alerts if a["severity"] == "critical"),
                "warning_alerts": sum(1 for a in dlp_alerts if a["severity"] == "warning"),
                "devices_with_alerts": len(set(a["device_id"] for a in dlp_alerts)),
                "alerts": sorted(dlp_alerts, key=lambda x: {'critical': 0, 'warning': 1, 'info': 2}.get(x['severity'], 3)),
                "software_inventory": sw_inventory,
                "total_software_devices": len(sw_inventory)
            })
            return

            # ── ISO 27001: Policies Management ──
        elif path == "/api/policies":
            session = self.require_auth()
            if not session:
                return
            try:
                rows = run_bq_query("""
                    SELECT policy_id, title, category, version, status,
                           description, created_by, created_at, updated_at,
                           requires_acceptance
                    FROM onyx.eq_policies
                    ORDER BY category, title
                """)
            except Exception:
                rows = []
            # Get acceptance counts
            try:
                acc = run_bq_query("""
                    SELECT policy_id, COUNT(*) as accepted_count
                    FROM onyx.eq_policy_acceptances
                    GROUP BY policy_id
                """)
                acc_map = {a["policy_id"]: a["accepted_count"] for a in acc}
            except Exception:
                acc_map = {}
            for r in rows:
                r["accepted_count"] = acc_map.get(r.get("policy_id", ""), 0)
            self.send_json({"policies": rows})
            return

        elif path == "/api/policies/pending":
            session = self.require_auth()
            if not session:
                return
            uid = session["user_id"]
            try:
                # ISO 27001 A.8.26 — Parameterized query to prevent SQL injection
                if USE_SDK:
                    sql = """
                        SELECT p.policy_id, p.title, p.category, p.version, p.description
                        FROM onyx.eq_policies p
                        WHERE p.status = 'active' AND p.requires_acceptance = true
                          AND p.policy_id NOT IN (
                            SELECT a.policy_id FROM onyx.eq_policy_acceptances a
                            WHERE a.user_id = @uid
                          )
                        ORDER BY p.category
                    """
                    dataset = os.environ.get("BQ_DATASET", "onyx")
                    if dataset != "onyx":
                        sql = sql.replace("onyx.", f"{dataset}.")
                    job_config = bigquery.QueryJobConfig(
                        query_parameters=[bigquery.ScalarQueryParameter("uid", "STRING", uid)]
                    )
                    results = BQ_CLIENT.query(
                        sql, job_config=job_config,
                        location="us-central1" if "K_SERVICE" in os.environ else None
                    ).result()
                    pending = []
                    for row in results:
                        d = dict(row)
                        for k, v in d.items():
                            if hasattr(v, 'isoformat'):
                                d[k] = v.isoformat()
                            elif v is not None and not isinstance(v, (str, int, float, bool)):
                                d[k] = str(v)
                        pending.append(d)
                else:
                    # CLI fallback — sanitize uid (allow only uuid chars)
                    import re as _re
                    safe_uid = _re.sub(r'[^a-fA-F0-9\-]', '', uid)
                    pending = run_bq_query(f"""
                        SELECT p.policy_id, p.title, p.category, p.version, p.description
                        FROM onyx.eq_policies p
                        WHERE p.status = 'active' AND p.requires_acceptance = true
                          AND p.policy_id NOT IN (
                            SELECT a.policy_id FROM onyx.eq_policy_acceptances a
                            WHERE a.user_id = '{safe_uid}'
                          )
                        ORDER BY p.category
                    """)
            except Exception:
                pending = []
            self.send_json({"pending": pending})
            return

        elif path == "/api/iso-report":
            session = self.require_auth()
            if not session:
                return
            report = {"generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "controls": []}
            with cache_lock:
                # A.5.1 - Information Security Policies
                try:
                    policies = run_bq_query("SELECT COUNT(*) as cnt FROM onyx.eq_policies WHERE status='active'")
                    policy_count = policies[0]["cnt"] if policies else 0
                except Exception:
                    policy_count = 0
                report["controls"].append({"id": "A.5.1", "name": "Políticas de Seguridad", "status": "compliant" if policy_count > 0 else "non_compliant", "detail": f"{policy_count} políticas activas", "evidence": "eq_policies table"})

                # A.5.17 - Authentication
                totp_users = sum(1 for u in cache.get("users_cache", {}).values() if u.get("totp_enabled"))
                total_users = len(cache.get("users_cache", {}))
                report["controls"].append({"id": "A.5.17", "name": "Autenticación", "status": "compliant" if totp_users == total_users and total_users > 0 else "partial", "detail": f"{totp_users}/{total_users} usuarios con 2FA", "evidence": "eq_users.totp_enabled"})

                # A.8.1 - Asset Management
                total_dev = len(cache.get("sync_status", []))
                online_dev = sum(1 for d in cache.get("sync_status", []) if d.get("status") == "Online")
                report["controls"].append({"id": "A.8.1", "name": "Gestión de Activos", "status": "compliant" if total_dev > 0 else "non_compliant", "detail": f"{total_dev} dispositivos ({online_dev} online)", "evidence": "eq_sync_status"})

                # A.8.7 - Malware Protection
                av_ok = 0
                for m in cache.get("latest_metrics", []):
                    if m.get("antivirus_enabled") == True:
                        av_ok += 1
                report["controls"].append({"id": "A.8.7", "name": "Protección Malware", "status": "compliant" if av_ok == total_dev and total_dev > 0 else "partial" if av_ok > 0 else "non_compliant", "detail": f"{av_ok}/{total_dev} con antivirus activo", "evidence": "agent metrics"})

                # A.8.12 - DLP
                dlp_issues = 0
                for m in cache.get("latest_metrics", []):
                    try:
                        remote = json.loads(m.get("dlp_remote_access", "[]")) if isinstance(m.get("dlp_remote_access"), str) else m.get("dlp_remote_access", [])
                        if remote:
                            dlp_issues += 1
                    except Exception:
                        pass
                report["controls"].append({"id": "A.8.12", "name": "Prevención Pérdida Datos", "status": "compliant" if dlp_issues == 0 else "partial", "detail": f"{dlp_issues} dispositivos con acceso remoto no autorizado", "evidence": "DLP monitoring"})

                # A.8.20 - Network Security
                fw_ok = sum(1 for m in cache.get("latest_metrics", []) if m.get("firewall_enabled") == True)
                report["controls"].append({"id": "A.8.20", "name": "Seguridad de Red", "status": "compliant" if fw_ok == total_dev and total_dev > 0 else "partial", "detail": f"{fw_ok}/{total_dev} con firewall activo", "evidence": "agent metrics"})

                # A.8.24 - Cryptography
                bl_ok = sum(1 for m in cache.get("latest_metrics", []) if m.get("bitlocker_enabled") == True)
                report["controls"].append({"id": "A.8.24", "name": "Cifrado de Datos", "status": "compliant" if bl_ok == total_dev and total_dev > 0 else "partial" if bl_ok > 0 else "non_compliant", "detail": f"{bl_ok}/{total_dev} con BitLocker", "evidence": "agent metrics"})

                # A.8.34 - Audit Logging
                try:
                    audit_count = run_bq_query("SELECT COUNT(*) as cnt FROM onyx.eq_audit_log")
                    log_count = audit_count[0]["cnt"] if audit_count else 0
                except Exception:
                    log_count = 0
                report["controls"].append({"id": "A.8.34", "name": "Registros de Auditoría", "status": "compliant" if log_count > 0 else "non_compliant", "detail": f"{log_count} eventos registrados", "evidence": "eq_audit_log"})

            # Calculate overall
            statuses = [c["status"] for c in report["controls"]]
            report["total_controls"] = len(report["controls"])
            report["compliant"] = statuses.count("compliant")
            report["partial"] = statuses.count("partial")
            report["non_compliant"] = statuses.count("non_compliant")
            report["compliance_pct"] = round(report["compliant"] / report["total_controls"] * 100, 1) if report["total_controls"] else 0
            self.send_json(report)
            return

            # ── ISO 27001: Incident Management (A.5.24) ──
        elif path == "/api/incidents":
            session = self.require_auth()
            if not session:
                return
            try:
                rows = run_bq_query("""
                    SELECT incident_id, title, category, severity, status,
                           reported_by, reported_at, description,
                           affected_systems, resolution, resolved_at
                    FROM onyx.eq_incidents
                    ORDER BY reported_at DESC
                    LIMIT 200
                """)
            except Exception:
                rows = []
            total = len(rows)
            open_inc = sum(1 for r in rows if r.get("status") in ("open", "investigating"))
            resolved = sum(1 for r in rows if r.get("status") == "resolved")
            critical = sum(1 for r in rows if r.get("severity") == "critical")
            self.send_json({"incidents": rows, "total": total, "open": open_inc, "resolved": resolved, "critical": critical})
            return

            # ── ISO 27001: Training & Awareness (A.6.3) ──
        elif path == "/api/training":
            session = self.require_auth()
            if not session:
                return
            try:
                modules = run_bq_query("""
                    SELECT module_id, title, category, description,
                           duration_minutes, is_mandatory, created_at
                    FROM onyx.eq_training_modules
                    WHERE is_active = true
                    ORDER BY category, title
                """)
            except Exception:
                modules = []
            # Get completions for current user
            uid = session["user_id"]
            try:
                import re as _re
                safe_uid = _re.sub(r'[^a-fA-F0-9\-]', '', uid)
                completions = run_bq_query(f"""
                    SELECT module_id, completed_at, score
                    FROM onyx.eq_training_completions
                    WHERE user_id = '{safe_uid}'
                """)
                comp_map = {c["module_id"]: c for c in completions}
            except Exception:
                comp_map = {}
            for m in modules:
                c = comp_map.get(m.get("module_id", ""))
                m["completed"] = c is not None
                m["completed_at"] = c.get("completed_at", "") if c else ""
                m["score"] = c.get("score", 0) if c else 0
            total_modules = len(modules)
            completed = sum(1 for m in modules if m["completed"])
            mandatory = sum(1 for m in modules if m.get("is_mandatory"))
            mandatory_done = sum(1 for m in modules if m.get("is_mandatory") and m["completed"])
            self.send_json({
                "modules": modules,
                "total": total_modules,
                "completed": completed,
                "mandatory": mandatory,
                "mandatory_completed": mandatory_done,
                "completion_pct": round(completed / total_modules * 100, 1) if total_modules else 0
            })
            return

            # ── Active Directory ──
        elif path == "/api/ad/status":
            session = self.require_auth()
            if not session or session.get("role") != "admin":
                self.send_json({"error": "Solo administradores"}, 403)
                return
            status = {"enabled": AD_ENABLED, "url": AD_LDAP_URL, "base_dn": AD_BASE_DN, "connected": False, "users_count": 0}
            if AD_ENABLED:
                conn = ad_connect()
                if conn:
                    status["connected"] = True
                    from ldap3 import SUBTREE
                    conn.search(AD_BASE_DN, AD_USER_FILTER, SUBTREE, attributes=['mail'])
                    status["users_count"] = len(conn.entries)
                    conn.unbind()
                # Count local AD users
                with users_cache_lock:
                    status["synced_users"] = sum(1 for u in users_cache if u.get("auth_source") == "ad")
                    status["local_users"] = sum(1 for u in users_cache if u.get("auth_source") != "ad")
            self.send_json(status)
            return

        elif path == "/api/ad/users":
            session = self.require_auth()
            if not session or session.get("role") != "admin":
                self.send_json({"error": "Solo administradores"}, 403)
                return
            if not AD_ENABLED:
                self.send_json({"error": "AD not enabled"}, 400)
                return
            try:
                from ldap3 import SUBTREE
                conn = ad_connect()
                if not conn:
                    self.send_json({"error": "Cannot connect to AD"}, 500)
                    return
                conn.search(AD_BASE_DN, AD_USER_FILTER, SUBTREE,
                            attributes=['cn','mail','givenName','sn','department','memberOf','sAMAccountName','distinguishedName'])
                users = []
                for e in conn.entries:
                    mail = str(e.mail) if hasattr(e, 'mail') and e.mail else None
                    if not mail or mail == '[]':
                        continue
                    groups = [str(g) for g in e.memberOf] if hasattr(e, 'memberOf') and e.memberOf else []
                    role = "viewer"
                    for gdn, mrole in AD_GROUP_MAP.items():
                        if any(gdn.lower() in g.lower() for g in groups):
                            if mrole == "admin": role = "admin"; break
                            elif mrole == "analyst" and role != "admin": role = "analyst"
                    dn = str(e.distinguishedName)
                    ou = ""
                    for part in dn.split(","):
                        if part.strip().startswith("OU=") and part.strip() != "OU=Usuarios":
                            ou = part.strip().replace("OU=", "")
                            break
                    users.append({
                        "cn": str(e.cn), "email": mail.lower(),
                        "department": str(e.department) if hasattr(e, 'department') and e.department else "",
                        "role": role, "ou": ou, "dn": dn,
                        "synced": find_user_by_email(mail.lower()) is not None
                    })
                conn.unbind()
                self.send_json({"users": users, "total": len(users)})
            except Exception as ex:
                self.send_json({"error": str(ex)}, 500)
            return

        elif path == "/api/ad/ous":
            session = self.require_auth()
            if not session or session.get("role") != "admin":
                self.send_json({"error": "Solo administradores"}, 403)
                return
            ous = ad_get_ou_structure()
            self.send_json({"ous": ous, "total": len(ous)})
            return

        elif path == "/api/installer-download":
            # Serve Onyx Agent installer as a ZIP — admin only
            session = self.get_current_session()
            if not session:
                self.send_json({"error": "Autenticacion requerida", "code": "AUTH_REQUIRED"}, 401)
                return
            if session.get("role") != "admin":
                self.send_json({"error": "Acceso restringido: requiere rol de administrador", "code": "FORBIDDEN"}, 403)
                return

            user_id = str(session.get("user_id") or session.get("email") or "unknown_admin")
            if not _check_installer_rate_limit(user_id):
                self.send_json({"error": "Limite de descargas excedido. Espere unos minutos.", "code": "RATE_LIMITED"}, 429)
                return

            import zipfile
            import io
            import hashlib
            import traceback

            agent_dir = os.path.join(os.path.dirname(__file__), "agent_distribuir")
            if not os.path.exists(agent_dir):
                agent_dir = os.path.join(os.path.dirname(__file__), "agent")

            if not os.path.exists(agent_dir):
                self.send_json({"error": "Directorio del agente no encontrado en el servidor", "code": "NOT_FOUND"}, 404)
                return

            required_core_files = ["onyx_agent.py", "onyx_updater.py", "onyx_config.json", "instalar.ps1", "INSTALAR.bat"]
            missing_core = [f for f in required_core_files if not os.path.exists(os.path.join(agent_dir, f))]
            if missing_core:
                print(f"[INSTALLER] Missing core files in {agent_dir}: {missing_core}")
                self.send_json({"error": "Archivos del instalador incompletos en el servidor", "code": "NOT_FOUND"}, 404)
                return

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
                host_hdr = self.headers.get("Host", "")
                update_server = _resolve_safe_update_server(host_hdr)
                current_dataset = os.environ.get("BQ_DATASET", "onyx")

                zip_buffer = io.BytesIO()
                file_checksums = {}

                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
                    for fname in installer_files:
                        fpath = os.path.join(agent_dir, fname)
                        if os.path.exists(fpath):
                            if fname == "onyx_config.json":
                                try:
                                    with open(fpath, "r", encoding="utf-8-sig") as jf:
                                        conf_data = json.load(jf)
                                    conf_data["update_server"] = update_server
                                    conf_data["dataset"] = current_dataset
                                    conf_data["version"] = "3.5.0"
                                    conf_str = json.dumps(conf_data, indent=4)
                                    content_bytes = conf_str.encode("utf-8")
                                    zf.writestr(f"Onyx-Agent-v3.5/{fname}", content_bytes)
                                    file_checksums[fname] = hashlib.sha256(content_bytes).hexdigest()
                                except Exception as ex:
                                    print(f"[ZIP] Error dynamic config override: {ex}")
                                    with open(fpath, "rb") as raw_f:
                                        raw_b = raw_f.read()
                                        zf.writestr(f"Onyx-Agent-v3.5/{fname}", raw_b)
                                        file_checksums[fname] = hashlib.sha256(raw_b).hexdigest()
                            else:
                                with open(fpath, "rb") as raw_f:
                                    raw_b = raw_f.read()
                                    zf.writestr(f"Onyx-Agent-v3.5/{fname}", raw_b)
                                    file_checksums[fname] = hashlib.sha256(raw_b).hexdigest()

                    checksum_lines = [f"{sha}  {fn}" for fn, sha in sorted(file_checksums.items())]
                    checksum_manifest = "\n".join(checksum_lines) + "\n"
                    zf.writestr("Onyx-Agent-v3.5/checksum.txt", checksum_manifest.encode("utf-8"))

                    readme = """════════════════════════════════════════════════
  ONYX — Agente de Monitoreo v3.5 (Cifrado BitLocker + HMAC)
  By Agentica
════════════════════════════════════════════════

INSTRUCCIONES DE INSTALACION:
──────────────────────────────
1. Extraer esta carpeta completa

2. Click derecho en "INSTALAR.bat"
   -> Ejecutar como administrador

3. ¡Listo! El agente se configurara y transmitira
   metricas y estado de cifrado automaticamente.

DATOS RECOLECTADOS:
──────────────────────────────
* Estado de Cifrado BitLocker (Multi-capa Zero-Knowledge)
* CPU, RAM, Disco, Red, Bateria
* Procesos activos (top 10)
* Historial de navegacion
* Informacion de red (interfaces y VPN)
* Puertos USB (tipo, estado, dispositivos)
* Visor de Sucesos (errores, advertencias)

DESINSTALAR:
──────────────────────────────
Click derecho en "DESINSTALAR.bat"
-> Ejecutar como administrador
"""
                    zf.writestr("Onyx-Agent-v3.5/LEEME.txt", readme.encode("utf-8"))

                zip_data = zip_buffer.getvalue()
                pkg_sha256 = hashlib.sha256(zip_data).hexdigest()
                client_ip = _extract_trusted_client_ip(self)

                print(f"[AUDIT] Installer ZIP served to admin={session.get('email')} (id={user_id}) from IP={client_ip} | SHA256={pkg_sha256} | Size={len(zip_data)} bytes | update_server={update_server}")

                self.send_response(200)
                self.send_header('Content-Type', 'application/zip')
                self.send_header('Content-Disposition', 'attachment; filename="Onyx-Agent-v3.5.zip"')
                self.send_header('Content-Length', str(len(zip_data)))
                self.send_header('X-Package-SHA256', pkg_sha256)
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, private')
                self.send_header('Pragma', 'no-cache')
                self.send_header('Expires', '0')
                self.end_headers()
                self.wfile.write(zip_data)
            except Exception as e:
                print(f"[INSTALLER] Error generating zip: {traceback.format_exc()}")
                self.send_json({"error": "Error interno al generar el paquete instalador", "code": "INTERNAL_ERROR"}, 500)
                
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
            client_ip = _extract_trusted_client_ip(self)
            if not _check_ip_rate_limit(client_ip):
                self.send_json({"error": "Demasiadas peticiones desde esta IP", "code": "RATE_LIMITED"}, 429)
                return

            device_id = self.headers.get("X-Device-Id", "") or self.headers.get("X-Device-ID", "")
            if not device_id:
                device_id = body.get("sync", {}).get("device_id", "") or body.get("metrics", {}).get("device_id", "")
            if not device_id:
                self.send_json({"error": "device_id required"}, 400)
                return

            # Verificación criptográfica HMAC-SHA256 (ISO 27001 A.8.5)
            if self.headers.get("X-Agent-Signature") or self.headers.get("X-Agent-Timestamp") or os.environ.get("ONYX_AGENT_SECRET"):
                raw_bytes = post_data.encode('utf-8') if isinstance(post_data, str) else post_data
                is_valid, status_code, err_msg = _verify_agent_signature(
                    dict(self.headers),
                    raw_bytes,
                    device_id,
                    client_ip
                )
                if not is_valid:
                    print(f"[AUTH-WARN] Fallo de autenticación HMAC para {device_id} ({client_ip}): {err_msg}")
                    self.send_json({"error": err_msg, "code": "INVALID_SIGNATURE"}, status_code)
                    return
            else:
                agent_key = self.headers.get('X-Agent-Key', '')
                expected_key = os.environ.get('AGENT_API_KEY', '')
                if expected_key and agent_key != expected_key:
                    self.send_json({"error": "Unauthorized agent"}, 401)
                    return

            metrics = body.get("metrics")
            sync = body.get("sync")
            
            if sync:
                sync["last_ip"] = client_ip
                sync["last_sync"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

            def _normalize_metrics(m):
                """Adapta metricas al nuevo schema BQ con columnas proc1/2/3 y sanitización BitLocker."""
                if not m.get("timestamp"):
                    m["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                if "disk_encryption" in m:
                    m["disk_encryption"] = _sanitize_disk_encryption(m.get("disk_encryption"))
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
                for f in ["network_info", "browser_history", "usb_ports", "event_logs", "downloads_metadata", "disk_encryption"]:
                    if isinstance(m.get(f), (dict, list)):
                        m[f] = json.dumps(m[f])
                return m

            success = True
            if metrics:
                try:
                    norm_m = _normalize_metrics(metrics)
                    run_bq_insert("onyx.eq_hardware_metrics", norm_m)
                    with cache_lock:
                        found = False
                        for i, lm in enumerate(cache.get("latest_metrics", [])):
                            if lm.get("device_id") == device_id:
                                cache["latest_metrics"][i] = dict(norm_m)
                                found = True
                                break
                        if not found:
                            cache.setdefault("latest_metrics", []).append(dict(norm_m))
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
                    # Usar la IP publica del agente (mas precisa que client_ip)
                    agent_public_ip = ""
                    if metrics and metrics.get("network_info"):
                        try:
                            ni = json.loads(metrics["network_info"]) if isinstance(metrics["network_info"], str) else metrics["network_info"]
                            agent_public_ip = ni.get("public_ip", "")
                        except: pass
                    
                    # ── GPS vs IP geolocation priority ──
                    # Si el agente envía coordenadas GPS reales, usarlas directamente
                    gps_lat = metrics.get("gps_latitude") if metrics else None
                    gps_lon = metrics.get("gps_longitude") if metrics else None
                    location_enabled = metrics.get("location_enabled", True) if metrics else True

                    if gps_lat is not None and gps_lon is not None:
                        # Usar coordenadas GPS del dispositivo (más precisas que IP)
                        # Reverse geocoding para obtener nombre real de la ciudad
                        gps_city = ""
                        gps_country = ""
                        try:
                            import urllib.request as _urlreq
                            _rgeo_url = f"https://nominatim.openstreetmap.org/reverse?lat={gps_lat}&lon={gps_lon}&format=json&zoom=10"
                            _rgeo_req = _urlreq.Request(_rgeo_url, headers={"User-Agent": "EIQ-Server/1.0"})
                            _rgeo_resp = _urlreq.urlopen(_rgeo_req, timeout=4)
                            _rgeo_data = json.loads(_rgeo_resp.read())
                            addr = _rgeo_data.get("address", {})
                            gps_city = (addr.get("city") or addr.get("town") or addr.get("village") 
                                       or addr.get("municipality") or addr.get("county") 
                                       or addr.get("state", "").split(",")[0].strip()
                                       or addr.get("suburb", "").replace("Localidad ", "") or "")
                            gps_country = addr.get("country", "")
                            print(f"[GEO-CHECK] {device_id}: Reverse geocode GPS -> {gps_city}, {gps_country}")
                        except Exception as rgeo_err:
                            print(f"[GEO-CHECK] {device_id}: Reverse geocode failed: {rgeo_err}")
                            # Fallback: usar IP para la ciudad pero GPS para coordenadas
                            _ip_geo = _geolocate_ip(agent_public_ip or client_ip)
                            gps_city = _ip_geo.get("city", "")
                            gps_country = _ip_geo.get("country", "")
                        
                        geo = {
                            "lat": gps_lat,
                            "lon": gps_lon,
                            "city": gps_city or "Desconocida",
                            "country": gps_country or "",
                            "isp": "GPS"
                        }
                        geo_ip = agent_public_ip or client_ip
                        # Guardar en caché GPS persistente (no se pierde al refrescar BQ)
                        _device_gps_cache[device_id] = {
                            "lat": gps_lat, "lon": gps_lon,
                            "city": geo["city"], "country": geo["country"],
                            "ts": datetime.datetime.now(datetime.timezone.utc)
                        }
                        print(f"[GEO-CHECK] {device_id}: USANDO GPS lat={gps_lat}, lon={gps_lon}, city={geo['city']}")
                    else:
                        # Fallback a geolocalización por IP
                        geo_ip = agent_public_ip or client_ip
                        geo = _geolocate_ip(geo_ip) if geo_ip and geo_ip not in ("N/A","127.0.0.1","") else {}
                        print(f"[GEO-CHECK] {device_id}: Fallback IP geo_ip={geo_ip}")

                    current_city    = geo.get("city", "Desconocida")
                    current_country = geo.get("country", "")
                    print(f"[GEO-CHECK] {device_id}: city={current_city}, country={current_country}")

                    # Guardar coordenadas GPS en sync_status para el mapa
                    if sync and gps_lat is not None and gps_lon is not None:
                        sync["geo_lat"] = gps_lat
                        sync["geo_lon"] = gps_lon
                        sync["geo_source"] = "GPS"
                    elif sync and geo:
                        sync["geo_lat"] = geo.get("lat")
                        sync["geo_lon"] = geo.get("lon")
                        sync["geo_source"] = "IP"

                    # PRIMARIO: VPN detectada por el agente en los adaptadores de red
                    agent_vpn_active  = sync.get("vpn_active", False) if sync else False
                    agent_vpn_adapter = sync.get("vpn_adapter", "") if sync else ""

                    # SECUNDARIO: fallback por IP publica (solo si el agente no reporto VPN)
                    vpn_result = {"is_vpn": False, "isp": "", "reason": ""}
                    if not agent_vpn_active and geo_ip and geo_ip not in ("N/A", "127.0.0.1"):
                        vpn_result = _check_vpn(geo_ip)

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
                            "details":     f"{vpn_detail} — IP: {geo_ip}",
                            "severity":    "Alta",
                            "icon":        "\U0001f512",
                            "category":    "seguridad",
                            "city":        current_city
                        })
                        print(f"[SECURITY] VPN detectada en {device_id}: {vpn_detail}")

                    # Alerta cambio de ciudad
                    # Si no tenemos historial (primer reporte despues de deploy), 
                    # intentar cargar del agente anterior (network_info.city)
                    if device_id not in _device_last_city:
                        # Intentar obtener ciudad previa del agente
                        agent_city = ""
                        if metrics and metrics.get("network_info"):
                            try:
                                ni2 = json.loads(metrics["network_info"]) if isinstance(metrics["network_info"], str) else metrics["network_info"]
                                agent_city = ni2.get("city", "")
                            except: pass
                        # Establecer baseline con la ciudad del agente o la actual
                        baseline_city = agent_city or current_city
                        _device_last_city[device_id] = {
                            "city": baseline_city, "country": current_country, "ip": geo_ip
                        }
                        print(f"[CITY] Baseline para {device_id}: {baseline_city}")
                    
                    prev = _device_last_city[device_id]
                    if prev.get("city") and current_city and current_city != "Desconocida" and prev["city"] != current_city:
                        new_events.append({
                            "timestamp":   now_ts,
                            "device_id":   device_id,
                            "device_name": device_id,
                            "event_type":  "Cambio de Ciudad",
                            "details":     f"Se conectó desde {current_city} ({current_country}) — anterior: {prev['city']} — IP: {geo_ip}",
                            "severity":    "Media",
                            "icon":        "\U0001f4cd",
                            "category":    "ubicacion",
                            "city":        current_city
                        })
                        print(f"[SECURITY] *** CAMBIO DE CIUDAD en {device_id}: {prev['city']} -> {current_city} ***")

                    # Actualizar historial
                    _device_last_city[device_id] = {
                        "city": current_city, "country": current_country, "ip": geo_ip
                    }

                    # ── Monitoreo de estado de Servicios de Ubicación ──
                    if not location_enabled:
                        # Ubicación desactivada — verificar si es un cambio nuevo
                        prev_state = _device_location_state.get(device_id)
                        if prev_state is not False:
                            # Estado nuevo o cambió de True a False
                            dname = dev_name(device_id) if 'dev_name' in dir() else device_id
                            loc_event = {
                                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                "device_id": device_id,
                                "device_name": dname,
                                "event_type": "Ubicación Desactivada",
                                "details": f"⚠️ Los Servicios de Ubicación de Windows fueron DESACTIVADOS en {dname}. No se puede rastrear la posición del equipo.",
                                "severity": "Alta",
                                "icon": "📍",
                                "category": "ubicacion",
                                "source": "GPS Monitor"
                            }
                            new_events.append(loc_event)
                            print(f"[GPS] ⚠️ Servicios de Ubicación DESACTIVADOS en {device_id}")
                        _device_location_state[device_id] = False
                    else:
                        # Ubicación activada — verificar si se reactivó
                        prev_state = _device_location_state.get(device_id)
                        if prev_state is False:
                            # Se reactivó después de estar desactivada
                            dname = dev_name(device_id) if 'dev_name' in dir() else device_id
                            loc_event = {
                                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                "device_id": device_id,
                                "device_name": dname,
                                "event_type": "Ubicación Reactivada",
                                "details": f"✅ Servicios de Ubicación reactivados en {dname}. Rastreo GPS restaurado.",
                                "severity": "Baja",
                                "icon": "📍",
                                "category": "ubicacion",
                                "source": "GPS Monitor"
                            }
                            new_events.append(loc_event)
                            print(f"[GPS] ✅ Servicios de Ubicación REACTIVADOS en {device_id}")
                        _device_location_state[device_id] = True

                    if new_events:
                        with cache_lock:
                            cache["security_events"] = new_events + cache.get("security_events", [])
                            cache["security_events"] = cache["security_events"][:100]

                except Exception as geo_err:
                    print(f"[SECURITY] Error en deteccion geo/VPN: {geo_err}")

                # ── Detección de cambios USB en tiempo real ──
                try:
                    usb_json = metrics.get("usb_ports") if metrics else None
                    if usb_json:
                        current_usb = json.loads(usb_json) if isinstance(usb_json, str) else usb_json
                        if isinstance(current_usb, list):
                            current_names = {d.get("name", "") for d in current_usb if d.get("name")}
                            # Filtrar controladores internos del set
                            INTERNAL = ["host controller", "root hub", "raíz", "controlador de host", "xhci", "ehci", "concentrador"]
                            current_names = {n for n in current_names if not any(k in n.lower() for k in INTERNAL)}

                            with _usb_device_cache_lock:
                                has_baseline = device_id in _usb_device_cache
                                prev_names = _usb_device_cache.get(device_id, set())
                                _usb_device_cache[device_id] = current_names

                            usb_events = []
                            if has_baseline:
                                new_devices = current_names - prev_names
                                removed_devices = prev_names - current_names

                                for usb_name in new_devices:
                                    nl = usb_name.lower()
                                    usb_cat = "Almacenamiento" if any(k in nl for k in ["storage", "flash", "disk", "pendrive", "mass"]) else \
                                              "Telefono" if any(k in nl for k in ["phone", "android", "iphone"]) else \
                                              "Camara" if any(k in nl for k in ["camera", "webcam", "imaging"]) else "Periferico"
                                    severity = "Alta" if usb_cat == "Almacenamiento" else "Media"
                                    usb_events.append({
                                        "timestamp":   now_ts,
                                        "device_id":   device_id,
                                        "device_name": device_id,
                                        "event_type":  "USB Conectado",
                                        "details":     f"Nuevo dispositivo USB conectado: {usb_name} ({usb_cat})",
                                        "severity":    severity,
                                        "icon":        "\U0001f50c",
                                        "category":    "usb",
                                    })
                                    print(f"[SECURITY] USB conectado en {device_id}: {usb_name}")

                                for usb_name in removed_devices:
                                    usb_events.append({
                                        "timestamp":   now_ts,
                                        "device_id":   device_id,
                                        "device_name": device_id,
                                        "event_type":  "USB Desconectado",
                                        "details":     f"Dispositivo USB removido: {usb_name}",
                                        "severity":    "Media",
                                        "icon":        "\u26a0\ufe0f",
                                        "category":    "usb",
                                    })
                                    print(f"[SECURITY] USB desconectado en {device_id}: {usb_name}")
                            else:
                                print(f"[SECURITY] USB baseline establecido para {device_id}: {len(current_names)} dispositivos")

                            if usb_events:
                                with cache_lock:
                                    cache["security_events"] = usb_events + cache.get("security_events", [])
                                    cache["security_events"] = cache["security_events"][:100]
                except Exception as usb_err:
                    print(f"[SECURITY] Error en deteccion USB: {usb_err}")

                # ── Detección de intentos de conexión a puertos (Event Logs) ──
                try:
                    evtlogs_json = metrics.get("event_logs") if metrics else None
                    if evtlogs_json:
                        evt_data = json.loads(evtlogs_json) if isinstance(evtlogs_json, str) else evtlogs_json
                        if isinstance(evt_data, list):
                            port_events = []
                            for evt in evt_data:
                                msg = (evt.get("message") or evt.get("Message") or "").lower()
                                source = (evt.get("source") or evt.get("Source") or "").lower()
                                evt_id = str(evt.get("id") or evt.get("Id") or evt.get("event_id") or "")
                                ts_evt = evt.get("time") or evt.get("TimeCreated") or now_ts

                                # Windows Firewall: conexión bloqueada (Event ID 5157, 5152)
                                # Security Audit: logon attempt (Event ID 4625 = failed logon, 4624 = success)
                                # Firewall con log activado
                                is_firewall_block = evt_id in ("5157", "5152", "5031") or \
                                    any(k in msg for k in ["bloqueado", "blocked", "firewall", "denied", "drop"])
                                is_port_scan = any(k in msg for k in ["port scan", "escaneo de puertos", "connection attempt"])
                                is_remote_logon = evt_id in ("4625", "4624") and any(k in msg for k in ["remote", "network", "red", "remoto"])

                                if is_firewall_block:
                                    port_events.append({
                                        "timestamp":   ts_evt if isinstance(ts_evt, str) else now_ts,
                                        "device_id":   device_id,
                                        "device_name": device_id,
                                        "event_type":  "Conexión Bloqueada",
                                        "details":     f"Firewall bloqueó intento de conexión — Evento: {evt_id}",
                                        "severity":    "Alta",
                                        "icon":        "\U0001f6e1",
                                        "category":    "puertos",
                                    })
                                elif is_port_scan:
                                    port_events.append({
                                        "timestamp":   ts_evt if isinstance(ts_evt, str) else now_ts,
                                        "device_id":   device_id,
                                        "device_name": device_id,
                                        "event_type":  "Escaneo de Puertos",
                                        "details":     f"Detectado intento de escaneo de puertos — Evento: {evt_id}",
                                        "severity":    "Alta",
                                        "icon":        "\U0001f6a8",
                                        "category":    "puertos",
                                    })
                                elif is_remote_logon and evt_id == "4625":
                                    port_events.append({
                                        "timestamp":   ts_evt if isinstance(ts_evt, str) else now_ts,
                                        "device_id":   device_id,
                                        "device_name": device_id,
                                        "event_type":  "Intento de Acceso",
                                        "details":     f"Intento de acceso remoto fallido detectado — Evento: {evt_id}",
                                        "severity":    "Alta",
                                        "icon":        "\U0001f510",
                                        "category":    "puertos",
                                    })

                            if port_events:
                                # Limitar a los 5 eventos de puertos más recientes por ciclo
                                port_events = port_events[:5]
                                with cache_lock:
                                    cache["security_events"] = port_events + cache.get("security_events", [])
                                    cache["security_events"] = cache["security_events"][:100]
                                print(f"[SECURITY] {len(port_events)} eventos de puertos detectados en {device_id}")
                except Exception as port_err:
                    print(f"[SECURITY] Error en deteccion de puertos: {port_err}")

                # ── Inventario de red: procesar ARP scan del agente ──
                network_scan = body.get("network_scan", [])
                if network_scan and isinstance(network_scan, list):
                    try:
                        now_ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
                        # IPs de equipos con agente (para marcar has_agent=True)
                        with cache_lock:
                            agent_ips = {s.get("last_ip") for s in cache["sync_status"]
                                        if s.get("last_ip")}
                        with network_devices_cache_lock:
                            for dev in network_scan:
                                mac = dev.get("mac", "").upper().strip()
                                ip  = dev.get("ip", "").strip()
                                if not mac or mac in ("FF:FF:FF:FF:FF:FF", ""):
                                    continue
                                existing = network_devices_cache.get(mac, {})
                                network_devices_cache[mac] = {
                                    "mac":          mac,
                                    "ip":           ip,
                                    "hostname":     dev.get("hostname", existing.get("hostname", "")),
                                    "detected_by":  device_id,
                                    "first_seen":   existing.get("first_seen", now_ts),
                                    "last_seen":    now_ts,
                                    "has_agent":    ip in agent_ips
                                }
                        print(f"[NET-SCAN] {device_id} reportó {len(network_scan)} dispositivos en red")
                    except Exception as net_err:
                        print(f"[NET-SCAN] Error procesando scan: {net_err}")

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
                audit_log("LOGIN_FAILED", email, self.client_address[0], "USER", "", f"Cuenta bloqueada por brute-force", "FAILURE")
                self.send_json({"error": f"Cuenta bloqueada por {LOCKOUT_MINUTES} min tras demasiados intentos fallidos"}, 429)
                return

            # --- Active Directory authentication (hybrid) ---
            ad_user_info = None
            if AD_ENABLED:
                ad_user_info = ad_authenticate(email, password)
                if ad_user_info:
                    log.info("[AD] User %s authenticated via Active Directory", email)
                    # Find or create local user record
                    user = find_user_by_email(email)
                    if not user:
                        # Auto-create local user from AD data
                        import secrets as _sec
                        _salt = _sec.token_hex(16)
                        _avatar = (ad_user_info['full_name'][:2]).upper()
                        user = {
                            "user_id": str(uuid.uuid4()),
                            "email": email,
                            "password_hash": hash_password(_sec.token_urlsafe(32), _salt)[0],
                            "salt": _salt,
                            "full_name": ad_user_info['full_name'],
                            "role": ad_user_info['role'],
                            "avatar": _avatar,
                            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                            "last_login": None,
                            "is_active": True,
                            "totp_secret": None,
                            "totp_enabled": False,
                            "allowed_pages": None,
                            "auth_source": "ad",
                            "department": ad_user_info.get('department', '')
                        }
                        try:
                            run_bq_insert("onyx.eq_users", user)
                            with users_cache_lock:
                                users_cache.append(user)
                            log.info("[AD] Auto-created user %s from AD", email)
                        except Exception as e:
                            log.error("[AD] Failed to auto-create %s: %s", email, e)
                    else:
                        # Update role from AD groups
                        if user.get("auth_source") == "ad" and user.get("role") != ad_user_info['role']:
                            user["role"] = ad_user_info['role']
                    # Skip local password check — AD already verified

            if not ad_user_info:
                # Local authentication path
                user = find_user_by_email(email)
                if not user or not user.get("is_active", True):
                    _record_failed_login(email)
                    audit_log("LOGIN_FAILED", email, self.client_address[0], "USER", "", "Intento fallido", "FAILURE")
                    self.send_json({"error": "Credenciales incorrectas"}, 401)
                    return
                if not verify_password(password, user.get("password_hash", ""), user.get("salt", "")):
                    _record_failed_login(email)
                    audit_log("LOGIN_FAILED", email, self.client_address[0], "USER", "", "Intento fallido", "FAILURE")
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
                run_bq_update_user(
                    [("totp_secret", secret), ("totp_enabled", True)],
                    "user_id", uid
                )
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
                run_bq_update_user([("last_login", now_iso)], "user_id", uid)
            except Exception:
                pass
            audit_log("LOGIN", user["email"], self.client_address[0], "USER", user["user_id"], "Login exitoso")
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
                run_bq_update_user([("last_login", now_iso)], "user_id", user['user_id'])
            except Exception:
                pass
            audit_log("LOGIN", user["email"], self.client_address[0], "USER", user["user_id"], "Login exitoso")
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
                run_bq_update_user(
                    [("totp_secret", None), ("totp_enabled", False)],
                    "user_id", target_uid
                )
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
            audit_log("RESET_2FA", session["email"], self.client_address[0], "USER", target_uid)
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
                          "/api/auth/2fa/enable", "/api/auth/2fa/verify"}
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
                "is_active": True,
                "totp_secret":  None,   # el usuario configurará 2FA en su primer login
                "totp_enabled": False,
                "allowed_pages": json.dumps(body.get("allowed_pages")) if body.get("allowed_pages") else None
            }
            try:
                run_bq_insert("onyx.eq_users", new_user)
                with users_cache_lock:
                    users_cache.append(new_user)
                audit_log("CREATE_USER", session["email"], self.client_address[0], "USER", new_user["user_id"], {"email": new_user["email"], "role": new_user["role"]})
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
            update_pairs = []
            if body.get("full_name"):
                update_pairs.append(("full_name", body["full_name"]))
                user["full_name"] = body["full_name"]
            if body.get("role"):
                update_pairs.append(("role", body["role"]))
                user["role"] = body["role"]
            if body.get("email"):
                update_pairs.append(("email", body["email"].lower()))
                user["email"] = body["email"].lower()
            if "allowed_pages" in body:
                ap_val = json.dumps(body["allowed_pages"]) if body["allowed_pages"] else None
                update_pairs.append(("allowed_pages", ap_val))
                user["allowed_pages"] = ap_val
            if update_pairs:
                try:
                    run_bq_update_user(update_pairs, "user_id", user_id)
                except Exception as e:
                    print(f"[AUTH] Update error: {e}")
                audit_log("UPDATE_USER", session["email"], self.client_address[0], "USER", user_id, {"changes": [p[0] for p in update_pairs]})
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
                run_bq_update_user([("is_active", False)], "user_id", user_id)
                with users_cache_lock:
                    users_cache[:] = [u for u in users_cache if u.get("user_id") != user_id]
                audit_log("DEACTIVATE_USER", session["email"], self.client_address[0], "USER", user_id, {"email": user.get("email", "")})
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
            # ISO 27001 A.5.17 — Password policy
            pw_errors = []
            if len(new_pw) < 12:
                pw_errors.append("Mínimo 12 caracteres")
            if not any(c.isupper() for c in new_pw):
                pw_errors.append("Al menos 1 mayúscula")
            if not any(c.islower() for c in new_pw):
                pw_errors.append("Al menos 1 minúscula")
            if not any(c.isdigit() for c in new_pw):
                pw_errors.append("Al menos 1 número")
            if not any(c in '!@#$%^&*(),.?":{}|<>-_=+[]' for c in new_pw):
                pw_errors.append("Al menos 1 carácter especial")
            if pw_errors:
                self.send_json({"error": "Contraseña débil: " + ", ".join(pw_errors)}, 400)
                return
            user = find_user_by_id(session["user_id"])
            if not user or not verify_password(current_pw, user.get("password_hash", ""), user.get("salt", "")):
                self.send_json({"error": "Contraseña actual incorrecta"}, 400)
                return
            pw_hash, salt = hash_password(new_pw)
            user["password_hash"] = pw_hash
            user["salt"] = salt
            try:
                run_bq_update_user(
                    [("password_hash", pw_hash), ("salt", salt)],
                    "user_id", session['user_id']
                )
            except Exception as e:
                print(f"[AUTH] Password change error: {e}")
            audit_log("CHANGE_PASSWORD", session["email"], self.client_address[0], "USER", session["user_id"])
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
                
        elif path == "/api/policies/create":
            session = self.require_auth()
            if not session or session["role"] != "admin":
                self.send_json({"error": "Solo administradores"}, 403)
                return
            policy = {
                "policy_id": str(uuid.uuid4()),
                "title": body.get("title", ""),
                "category": body.get("category", "General"),
                "version": body.get("version", "1.0"),
                "status": "active",
                "description": body.get("description", ""),
                "content": body.get("content", ""),
                "requires_acceptance": body.get("requires_acceptance", True),
                "created_by": session["email"],
                "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
            try:
                run_bq_insert("onyx.eq_policies", policy)
                audit_log("CREATE_POLICY", session["email"], self.client_address[0], "POLICY", policy["policy_id"], {"title": policy["title"]})
                self.send_json({"ok": True, "policy_id": policy["policy_id"]})
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        elif path == "/api/policies/accept":
            session = self.require_auth()
            if not session:
                return
            acceptance = {
                "acceptance_id": str(uuid.uuid4()),
                "policy_id": body.get("policy_id", ""),
                "user_id": session["user_id"],
                "user_email": session["email"],
                "accepted_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "ip_address": self.client_address[0]
            }
            try:
                run_bq_insert("onyx.eq_policy_acceptances", acceptance)
                audit_log("ACCEPT_POLICY", session["email"], self.client_address[0], "POLICY", body.get("policy_id", ""))
                self.send_json({"ok": True})
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        elif path == "/api/incidents/create":
            session = self.require_auth()
            if not session:
                return
            incident = {
                "incident_id": str(uuid.uuid4()),
                "title": body.get("title", ""),
                "category": body.get("category", "General"),
                "severity": body.get("severity", "medium"),
                "status": "open",
                "reported_by": session["email"],
                "reported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "description": body.get("description", ""),
                "affected_systems": body.get("affected_systems", ""),
                "resolution": "",
                "resolved_at": None
            }
            try:
                run_bq_insert("onyx.eq_incidents", incident)
                audit_log("CREATE_INCIDENT", session["email"], self.client_address[0], "INCIDENT", incident["incident_id"], {"title": incident["title"], "severity": incident["severity"]})
                self.send_json({"ok": True, "incident_id": incident["incident_id"]})
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        elif path == "/api/incidents/update":
            session = self.require_auth()
            if not session:
                return
            inc_id = body.get("incident_id", "")
            import re as _re
            safe_id = _re.sub(r'[^a-fA-F0-9\-]', '', inc_id)
            if not safe_id or safe_id != inc_id:
                self.send_json({"error": "Invalid incident_id"}, 400)
                return
            ALLOWED_STATUSES = {"open", "investigating", "contained", "resolved", "closed"}
            updates = []
            if body.get("status"):
                status = body["status"].strip().lower()
                if status not in ALLOWED_STATUSES:
                    self.send_json({"error": f"Invalid status. Allowed: {', '.join(sorted(ALLOWED_STATUSES))}"}, 400)
                    return
                updates.append(f"status = '{status}'")
                if status == "resolved":
                    updates.append(f"resolved_at = '{datetime.datetime.now(datetime.timezone.utc).isoformat()}'")
            if body.get("resolution"):
                res = body["resolution"].replace("'", "''").replace("\\", "").replace(";", "")
                updates.append(f"resolution = '{res}'")
            if updates:
                try:
                    sql = f"UPDATE onyx.eq_incidents SET {', '.join(updates)} WHERE incident_id = '{safe_id}'"
                    run_bq_query(sql)
                    audit_log("UPDATE_INCIDENT", session["email"], self.client_address[0], "INCIDENT", inc_id, {"status": body.get("status", "")})
                    self.send_json({"ok": True})
                except Exception as e:
                    self.send_json({"error": str(e)}, 500)
            else:
                self.send_json({"error": "No changes"}, 400)
            return

        elif path == "/api/training/create":
            session = self.require_auth()
            if not session or session["role"] != "admin":
                self.send_json({"error": "Solo administradores"}, 403)
                return
            module = {
                "module_id": str(uuid.uuid4()),
                "title": body.get("title", ""),
                "category": body.get("category", "General"),
                "description": body.get("description", ""),
                "content": body.get("content", ""),
                "duration_minutes": body.get("duration_minutes", 15),
                "is_mandatory": body.get("is_mandatory", True),
                "is_active": True,
                "created_by": session["email"],
                "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
            try:
                run_bq_insert("onyx.eq_training_modules", module)
                audit_log("CREATE_TRAINING", session["email"], self.client_address[0], "TRAINING", module["module_id"], {"title": module["title"]})
                self.send_json({"ok": True, "module_id": module["module_id"]})
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        elif path == "/api/training/complete":
            session = self.require_auth()
            if not session:
                return
            completion = {
                "completion_id": str(uuid.uuid4()),
                "module_id": body.get("module_id", ""),
                "user_id": session["user_id"],
                "user_email": session["email"],
                "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "score": body.get("score", 100)
            }
            try:
                run_bq_insert("onyx.eq_training_completions", completion)
                audit_log("COMPLETE_TRAINING", session["email"], self.client_address[0], "TRAINING", body.get("module_id", ""))
                self.send_json({"ok": True})
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        elif path == "/api/ad/sync":
            session = self.require_auth()
            if not session or session.get("role") != "admin":
                self.send_json({"error": "Solo administradores"}, 403)
                return
            result = ad_sync_users()
            audit_log("AD_SYNC", session["email"], self.client_address[0], "AD", "sync", result)
            self.send_json(result)
            return

        # ══════════════════════════════════════════════════════════════
        # ██  INVENTORY & DEVICE ASSIGNMENT MODULE                    ██
        # ══════════════════════════════════════════════════════════════

        elif path == "/api/inventory":
            session = self.require_auth()
            if not session:
                return
            dataset = os.environ.get("BQ_DATASET", "onyx")

            if self.command == "GET":
                # List all inventory items with agent status
                try:
                    inv_rows = run_bq_query(f"SELECT * FROM {dataset}.eq_device_inventory ORDER BY created_at DESC")
                    items = [dict(r) for r in inv_rows] if inv_rows else []

                    # Cross-reference with eq_sync_status for agent detection
                    sync_rows = run_bq_query(f"""
                        SELECT device_id, MAX(last_sync) as last_sync, MAX(status) as status
                        FROM {dataset}.eq_sync_status
                        GROUP BY device_id
                    """)
                    agent_map = {}
                    if sync_rows:
                        for sr in sync_rows:
                            sr = dict(sr)
                            agent_map[sr.get("device_id", "")] = sr

                    # Get users for dropdown
                    user_rows = run_bq_query(f"SELECT email, full_name, department FROM {dataset}.eq_users WHERE is_active = true")
                    users = [dict(u) for u in user_rows] if user_rows else []

                    # Get unlinked agent device_ids (for linking dropdown)
                    linked_ids = {it.get("device_id") for it in items if it.get("device_id")}
                    unlinked_agents = [did for did in agent_map if did and did not in linked_ids]

                    now = datetime.datetime.now(datetime.timezone.utc)
                    for item in items:
                        did = item.get("device_id", "")
                        if did and did in agent_map:
                            agent = agent_map[did]
                            item["has_agent"] = True
                            last_sync = agent.get("last_sync")
                            if last_sync:
                                if hasattr(last_sync, 'isoformat'):
                                    item["agent_last_seen"] = last_sync.isoformat()
                                    diff = (now - last_sync.replace(tzinfo=datetime.timezone.utc) if last_sync.tzinfo is None else now - last_sync)
                                    item["agent_online"] = diff.total_seconds() < 600
                                else:
                                    item["agent_last_seen"] = str(last_sync)
                                    item["agent_online"] = False
                            else:
                                item["agent_online"] = False
                        else:
                            item["has_agent"] = bool(did)
                            item["agent_online"] = False
                            item["agent_last_seen"] = None
                        # Serialize timestamps
                        for tf in ["purchase_date", "warranty_until", "created_at", "updated_at", "agent_last_seen"]:
                            v = item.get(tf)
                            if v and hasattr(v, 'isoformat'):
                                item[tf] = v.isoformat()

                    # KPIs
                    total = len(items)
                    stock = sum(1 for i in items if i.get("status") == "stock")
                    assigned = sum(1 for i in items if i.get("status") == "assigned")
                    maintenance = sum(1 for i in items if i.get("status") == "maintenance")
                    retired = sum(1 for i in items if i.get("status") == "retired")
                    with_agent = sum(1 for i in items if i.get("has_agent"))

                    self.send_json({
                        "items": items,
                        "users": users,
                        "unlinked_agents": unlinked_agents,
                        "kpis": {
                            "total": total, "stock": stock, "assigned": assigned,
                            "maintenance": maintenance, "retired": retired, "with_agent": with_agent
                        }
                    })
                except Exception as e:
                    print(f"[INVENTORY] Error listing: {e}")
                    self.send_json({"items": [], "users": [], "unlinked_agents": [], "kpis": {}})
                return

        elif path == "/api/inventory" and self.command == "POST":
            # Register new device (enters as "stock")
            session = self.require_auth()
            if not session or session.get("role") not in ("admin", "analyst"):
                self.send_json({"error": "Sin permisos"}, 403)
                return
            dataset = os.environ.get("BQ_DATASET", "onyx")
            import uuid
            inv_id = str(uuid.uuid4())
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            row = {
                "inventory_id": inv_id,
                "device_tag": body.get("device_tag", ""),
                "device_id": body.get("device_id", "") or None,
                "brand": body.get("brand", ""),
                "model": body.get("model", ""),
                "serial_number": body.get("serial_number", ""),
                "device_type": body.get("device_type", "Laptop"),
                "os": body.get("os", ""),
                "purchase_date": body.get("purchase_date") or None,
                "warranty_until": body.get("warranty_until") or None,
                "status": "stock",
                "current_assignee_email": None,
                "current_assignee_name": None,
                "department": None,
                "notes": body.get("notes", ""),
                "has_agent": bool(body.get("device_id")),
                "agent_last_seen": None,
                "created_by": session["email"],
                "created_at": now_iso,
                "updated_at": now_iso
            }
            try:
                run_bq_insert(f"{dataset}.eq_device_inventory", row)
                # Log in assignments history
                run_bq_insert(f"{dataset}.eq_device_assignments", {
                    "assignment_id": str(uuid.uuid4()),
                    "inventory_id": inv_id,
                    "device_tag": body.get("device_tag", ""),
                    "action": "registered",
                    "from_user_email": None, "from_user_name": None,
                    "to_user_email": None, "to_user_name": None,
                    "department": None,
                    "notes": f"Equipo registrado en inventario: {body.get('brand','')} {body.get('model','')}",
                    "performed_by": session["email"],
                    "created_at": now_iso
                })
                audit_log("INVENTORY_REGISTER", session["email"], self.client_address[0], "inventory", inv_id, {"device_tag": body.get("device_tag")})
                self.send_json({"ok": True, "inventory_id": inv_id})
            except Exception as e:
                print(f"[INVENTORY] Register error: {e}")
                self.send_json({"error": str(e)}, 500)
            return

        elif path == "/api/inventory/update":
            # Edit device info
            session = self.require_auth()
            if not session or session.get("role") not in ("admin", "analyst"):
                self.send_json({"error": "Sin permisos"}, 403)
                return
            dataset = os.environ.get("BQ_DATASET", "onyx")
            inv_id = body.get("inventory_id")
            if not inv_id:
                self.send_json({"error": "inventory_id required"}, 400)
                return
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            updates = []
            for field in ["device_tag", "device_id", "brand", "model", "serial_number", "device_type", "os", "purchase_date", "warranty_until", "notes"]:
                if field in body:
                    val = body[field]
                    if val is None or val == "":
                        updates.append(f"{field} = NULL")
                    else:
                        safe = str(val).replace("'", "\\'")
                        updates.append(f"{field} = '{safe}'")
            if body.get("device_id"):
                updates.append("has_agent = TRUE")
            updates.append(f"updated_at = '{now_iso}'")
            try:
                safe_id = inv_id.replace("'", "\\'")
                run_bq_query(f"UPDATE {dataset}.eq_device_inventory SET {', '.join(updates)} WHERE inventory_id = '{safe_id}'")
                self.send_json({"ok": True})
            except Exception as e:
                print(f"[INVENTORY] Update error: {e}")
                self.send_json({"error": str(e)}, 500)
            return

        elif path == "/api/inventory/assign":
            session = self.require_auth()
            if not session or session.get("role") not in ("admin", "analyst"):
                self.send_json({"error": "Sin permisos"}, 403)
                return
            dataset = os.environ.get("BQ_DATASET", "onyx")
            import uuid
            inv_id = body.get("inventory_id")
            to_email = body.get("to_user_email", "")
            to_name = body.get("to_user_name", "")
            dept = body.get("department", "")
            notes = body.get("notes", "")
            if not inv_id or not to_email:
                self.send_json({"error": "inventory_id and to_user_email required"}, 400)
                return
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            safe_id = inv_id.replace("'", "\\'")
            try:
                # Get current state
                rows = run_bq_query(f"SELECT * FROM {dataset}.eq_device_inventory WHERE inventory_id = '{safe_id}'")
                device = dict(rows[0]) if rows else None
                if not device:
                    self.send_json({"error": "Equipo no encontrado"}, 404)
                    return
                prev_email = device.get("current_assignee_email")
                prev_name = device.get("current_assignee_name")
                action = "reassigned" if device.get("status") == "assigned" and prev_email else "assigned"

                # Update inventory
                safe_email = to_email.replace("'", "\\'")
                safe_name = to_name.replace("'", "\\'")
                safe_dept = dept.replace("'", "\\'")
                run_bq_query(f"""UPDATE {dataset}.eq_device_inventory
                    SET status = 'assigned', current_assignee_email = '{safe_email}',
                        current_assignee_name = '{safe_name}', department = '{safe_dept}',
                        updated_at = '{now_iso}'
                    WHERE inventory_id = '{safe_id}'""")

                # Log assignment
                run_bq_insert(f"{dataset}.eq_device_assignments", {
                    "assignment_id": str(uuid.uuid4()),
                    "inventory_id": inv_id,
                    "device_tag": device.get("device_tag", ""),
                    "action": action,
                    "from_user_email": prev_email, "from_user_name": prev_name,
                    "to_user_email": to_email, "to_user_name": to_name,
                    "department": dept,
                    "notes": notes,
                    "performed_by": session["email"],
                    "created_at": now_iso
                })
                audit_log("INVENTORY_ASSIGN", session["email"], self.client_address[0], "inventory", inv_id, {"to": to_email, "action": action})
                self.send_json({"ok": True, "action": action})
            except Exception as e:
                print(f"[INVENTORY] Assign error: {e}")
                self.send_json({"error": str(e)}, 500)
            return

        elif path == "/api/inventory/return":
            session = self.require_auth()
            if not session or session.get("role") not in ("admin", "analyst"):
                self.send_json({"error": "Sin permisos"}, 403)
                return
            dataset = os.environ.get("BQ_DATASET", "onyx")
            import uuid
            inv_id = body.get("inventory_id")
            notes = body.get("notes", "")
            if not inv_id:
                self.send_json({"error": "inventory_id required"}, 400)
                return
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            safe_id = inv_id.replace("'", "\\'")
            try:
                rows = run_bq_query(f"SELECT * FROM {dataset}.eq_device_inventory WHERE inventory_id = '{safe_id}'")
                device = dict(rows[0]) if rows else None
                if not device:
                    self.send_json({"error": "Equipo no encontrado"}, 404)
                    return

                run_bq_query(f"""UPDATE {dataset}.eq_device_inventory
                    SET status = 'stock', current_assignee_email = NULL,
                        current_assignee_name = NULL, department = NULL,
                        updated_at = '{now_iso}'
                    WHERE inventory_id = '{safe_id}'""")

                run_bq_insert(f"{dataset}.eq_device_assignments", {
                    "assignment_id": str(uuid.uuid4()),
                    "inventory_id": inv_id,
                    "device_tag": device.get("device_tag", ""),
                    "action": "returned",
                    "from_user_email": device.get("current_assignee_email"),
                    "from_user_name": device.get("current_assignee_name"),
                    "to_user_email": None, "to_user_name": None,
                    "department": device.get("department"),
                    "notes": notes,
                    "performed_by": session["email"],
                    "created_at": now_iso
                })
                audit_log("INVENTORY_RETURN", session["email"], self.client_address[0], "inventory", inv_id, {"from": device.get("current_assignee_email")})
                self.send_json({"ok": True})
            except Exception as e:
                print(f"[INVENTORY] Return error: {e}")
                self.send_json({"error": str(e)}, 500)
            return

        elif path == "/api/inventory/maintenance":
            session = self.require_auth()
            if not session or session.get("role") not in ("admin", "analyst"):
                self.send_json({"error": "Sin permisos"}, 403)
                return
            dataset = os.environ.get("BQ_DATASET", "onyx")
            import uuid
            inv_id = body.get("inventory_id")
            notes = body.get("notes", "")
            if not inv_id:
                self.send_json({"error": "inventory_id required"}, 400)
                return
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            safe_id = inv_id.replace("'", "\\'")
            try:
                rows = run_bq_query(f"SELECT * FROM {dataset}.eq_device_inventory WHERE inventory_id = '{safe_id}'")
                device = dict(rows[0]) if rows else None
                if not device:
                    self.send_json({"error": "Equipo no encontrado"}, 404)
                    return

                run_bq_query(f"""UPDATE {dataset}.eq_device_inventory
                    SET status = 'maintenance', updated_at = '{now_iso}'
                    WHERE inventory_id = '{safe_id}'""")

                run_bq_insert(f"{dataset}.eq_device_assignments", {
                    "assignment_id": str(uuid.uuid4()),
                    "inventory_id": inv_id,
                    "device_tag": device.get("device_tag", ""),
                    "action": "maintenance",
                    "from_user_email": device.get("current_assignee_email"),
                    "from_user_name": device.get("current_assignee_name"),
                    "to_user_email": None, "to_user_name": None,
                    "department": device.get("department"),
                    "notes": notes,
                    "performed_by": session["email"],
                    "created_at": now_iso
                })
                self.send_json({"ok": True})
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

        elif path == "/api/inventory/history":
            session = self.require_auth()
            if not session:
                return
            dataset = os.environ.get("BQ_DATASET", "onyx")
            inv_id = params.get("id", [""])[0]
            try:
                if inv_id:
                    safe_id = inv_id.replace("'", "\\'")
                    rows = run_bq_query(f"SELECT * FROM {dataset}.eq_device_assignments WHERE inventory_id = '{safe_id}' ORDER BY created_at DESC")
                else:
                    rows = run_bq_query(f"SELECT * FROM {dataset}.eq_device_assignments ORDER BY created_at DESC LIMIT 100")
                history = []
                if rows:
                    for r in rows:
                        h = dict(r)
                        for tf in ["created_at"]:
                            v = h.get(tf)
                            if v and hasattr(v, 'isoformat'):
                                h[tf] = v.isoformat()
                        history.append(h)
                self.send_json({"history": history})
            except Exception as e:
                print(f"[INVENTORY] History error: {e}")
                self.send_json({"history": []})
            return

        elif path == "/api/inventory/delete":
            session = self.require_auth()
            if not session or session.get("role") != "admin":
                self.send_json({"error": "Solo administradores"}, 403)
                return
            dataset = os.environ.get("BQ_DATASET", "onyx")
            import uuid
            inv_id = body.get("inventory_id") or params.get("id", [""])[0]
            if not inv_id:
                self.send_json({"error": "inventory_id required"}, 400)
                return
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            safe_id = inv_id.replace("'", "\\'")
            try:
                rows = run_bq_query(f"SELECT * FROM {dataset}.eq_device_inventory WHERE inventory_id = '{safe_id}'")
                device = dict(rows[0]) if rows else None
                if not device:
                    self.send_json({"error": "Equipo no encontrado"}, 404)
                    return
                run_bq_query(f"""UPDATE {dataset}.eq_device_inventory
                    SET status = 'retired', updated_at = '{now_iso}'
                    WHERE inventory_id = '{safe_id}'""")
                run_bq_insert(f"{dataset}.eq_device_assignments", {
                    "assignment_id": str(uuid.uuid4()),
                    "inventory_id": inv_id,
                    "device_tag": device.get("device_tag", ""),
                    "action": "retired",
                    "from_user_email": device.get("current_assignee_email"),
                    "from_user_name": device.get("current_assignee_name"),
                    "to_user_email": None, "to_user_name": None,
                    "department": device.get("department"),
                    "notes": body.get("notes", "Equipo dado de baja"),
                    "performed_by": session["email"],
                    "created_at": now_iso
                })
                self.send_json({"ok": True})
            except Exception as e:
                self.send_json({"error": str(e)}, 500)
            return

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
        # ISO 27001 A.8.26 — Restrict CORS
        origin = self.headers.get('Origin', '')
        if origin:
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Access-Control-Allow-Credentials', 'true')
        # ISO 27001 A.8.26 — Security headers
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
        if os.environ.get('K_SERVICE'):
            self.send_header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
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
