# main.py
# ══════════════════════════════════════════════════════════════════════════════
# Panel Technamooz v1.0.0.0 stable
# پنل فوق‌حرفه‌ای و بهینه‌سازی‌شده ساخت و مدیریت کانفیگ VLESS / Trojan / XHTTP
# توسعه‌یافته توسط تیم Technamooz با مدیریت amirparsa
# ══════════════════════════════════════════════════════════════════════════════

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote
from zoneinfo import ZoneInfo

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

if __name__ == "__main__":
    sys.modules.setdefault("main", sys.modules[__name__])

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [Technamooz] %(message)s")
APP_NAME = "Panel Technamooz"
APP_VERSION = "1.0.0.0"
logger = logging.getLogger("Technamooz")
IRAN_TZ = ZoneInfo("Asia/Tehran")

app = FastAPI(title=f"{APP_NAME} v{APP_VERSION} stable", docs_url=None, redoc_url=None)

# ── Persistence ───────────────────────────────────────────────────────────────
IS_RAILWAY = bool(
    os.environ.get("RAILWAY_ENVIRONMENT")
    or os.environ.get("RAILWAY_ENVIRONMENT_NAME")
    or os.environ.get("RAILWAY_PROJECT_ID")
)
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data" if IS_RAILWAY else "./data"))
DATA_FILE = DATA_DIR / "technamooz_state.json"
SECRET_FILE = DATA_DIR / "technamooz_secret.key"
SAVE_LOCK = asyncio.Lock()


def _load_or_create_secret() -> str:
    env_secret = os.environ.get("SECRET_KEY")
    if env_secret:
        return env_secret
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if SECRET_FILE.exists():
            existing = SECRET_FILE.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        new_secret = secrets.token_urlsafe(32)
        SECRET_FILE.write_text(new_secret, encoding="utf-8")
        SECRET_FILE.chmod(0o600)
        return new_secret
    except Exception as e:
        logger.warning(f"Could not persist SECRET_KEY: {e}")
        return secrets.token_urlsafe(32)


CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": _load_or_create_secret(),
    "host": os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost"),
}

TRUST_PROXY_HEADERS = os.environ.get("TRUST_PROXY_HEADERS", "false").lower() in {"1", "true", "yes"}
ALLOWED_PUBLIC_HOSTS = {x.strip().split(":", 1)[0].lower() for x in os.environ.get("ALLOWED_PUBLIC_HOSTS", "").split(",") if x.strip()}
_cors_origins = [x.strip() for x in os.environ.get("CORS_ORIGINS", "").split(",") if x.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=bool(_cors_origins),
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type"],
)


async def load_state():
    global LINKS, AUTH, SUBS
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if DATA_FILE.exists():
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                raw = f.read()
            data = json.loads(raw)
            loaded_links = data.get("links", {})
            loaded_subs = data.get("subs", {})
            # The bot token is intentionally never persisted to disk.  Keep a
            # token supplied through the environment instead of overwriting it
            # with the redacted empty token from a previous state save.
            saved_telegram = data.get("telegram", {})
            if isinstance(saved_telegram, dict):
                for key in ("enabled", "admin_ids"):
                    if key in saved_telegram:
                        BOT_SETTINGS[key] = saved_telegram[key]
            BOT_SETTINGS["enabled"] = bool(BOT_SETTINGS.get("token")) and bool(BOT_SETTINGS.get("enabled"))

            for item in loaded_links.values():
                if item.get("protocol") == "xhttp-stream-one":
                    item["protocol"] = "xhttp-stream-up"

            LINKS.update(loaded_links)
            SUBS.update(loaded_subs)
            if "password_hash" in data:
                AUTH["password_hash"] = data["password_hash"]
            if data.get("username"):
                AUTH["username"] = str(data["username"]).strip()
            logger.info(f"Loaded state: {len(LINKS)} links, {len(SUBS)} subs")
    except Exception as e:
        logger.warning(f"Could not load state: {e}")


async def save_state():
    async with SAVE_LOCK:
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            data = {
                "links": dict(LINKS),
                "subs": dict(SUBS),
                "password_hash": AUTH["password_hash"],
                "username": AUTH["username"],
                "telegram": {**dict(BOT_SETTINGS), "token": ""},
                "saved_at": datetime.now().isoformat(),
            }
            tmp = DATA_FILE.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(json.dumps(data, ensure_ascii=False, indent=2))
            tmp.chmod(0o600)
            tmp.replace(DATA_FILE)
            DATA_FILE.chmod(0o600)
        except Exception as e:
            logger.warning(f"Could not save state: {e}")


# ── In-memory state ───────────────────────────────────────────────────────────
connections: dict = {}
stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}
error_logs: deque = deque(maxlen=60)
activity_logs: deque = deque(maxlen=250)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None

LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()
SUBS: dict = {}
SUBS_LOCK = asyncio.Lock()

PROTOCOLS = ("vless-ws", "trojan-ws", "xhttp-packet-up", "xhttp-stream-up")
DEFAULT_PROTOCOL = "vless-ws"
FINGERPRINTS = ("chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized")
DEFAULT_FINGERPRINT = "chrome"

DEFAULT_ALPN_BY_PROTOCOL = {
    "vless-ws": "http/1.1",
    "trojan-ws": "http/1.1",
    "xhttp-packet-up": "h2,http/1.1",
    "xhttp-stream-up": "h2,http/1.1",
}
DEFAULT_PORT = 443
MIN_PORT, MAX_PORT = 1, 65535
DEFAULT_SPEED_LIMIT = 0


def log_activity(kind: str, message: str, level: str = "info"):
    activity_logs.append({
        "kind": kind,
        "level": level,
        "message": message,
        "time": datetime.now().isoformat(),
    })


# ── Auth & Credentials ────────────────────────────────────────────────────────
SESSION_COOKIE = "technamooz_session"
SESSION_TTL = 60 * 60 * 24 * 365


def hash_password(pw: str) -> str:
    iterations = 310_000
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${digest.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    if not stored:
        return False
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, iterations, salt, expected = stored.split("$", 3)
            digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), int(iterations))
            return hmac.compare_digest(digest.hex(), expected)
        except (ValueError, TypeError):
            return False
    legacy = hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()
    return hmac.compare_digest(legacy, stored)


_admin_password = os.environ.get("ADMIN_PASSWORD")
if not _admin_password and IS_RAILWAY:
    raise RuntimeError("ADMIN_PASSWORD must be set in production")

AUTH = {
    "username": os.environ.get("ADMIN_USERNAME", "Amirparsa"),
    "password_hash": hash_password(_admin_password or "Technamooz"),
}

LOGIN_CAPTCHAS: dict[str, tuple[str, float]] = {}
BOT_SETTINGS = {
    "enabled": bool(os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()),
    "token": os.environ.get("TELEGRAM_BOT_TOKEN", "").strip(),
    "admin_ids": os.environ.get("TELEGRAM_ADMIN_IDS", "").strip(),
}

SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()
LOGIN_FAILURES: dict[str, list[float]] = defaultdict(list)
LOGIN_LOCK = asyncio.Lock()
LOGIN_WINDOW = 300
LOGIN_MAX_FAILURES = 8


async def login_rate_limited(ip: str) -> bool:
    now = time.time()
    async with LOGIN_LOCK:
        attempts = [t for t in LOGIN_FAILURES.get(ip, []) if now - t < LOGIN_WINDOW]
        LOGIN_FAILURES[ip] = attempts
        return len(attempts) >= LOGIN_MAX_FAILURES


async def record_login_failure(ip: str):
    async with LOGIN_LOCK:
        LOGIN_FAILURES.setdefault(ip, []).append(time.time())


async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token


async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None:
            return False
        if exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True


async def destroy_session(token: str | None):
    if not token:
        return
    async with SESSIONS_LOCK:
        SESSIONS.pop(token, None)


async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="Unauthorized")
    return token


# ── Startup & Shutdown ────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global http_client
    http_client = httpx.AsyncClient(timeout=10.0)
    await load_state()
    await ensure_default_link()

    from xhttp_siz10 import ensure_reaper
    ensure_reaper()

    if BOT_SETTINGS.get("token") and BOT_SETTINGS.get("enabled"):
        try:
            from telegram_bot import start_bot
            asyncio.create_task(start_bot())
        except Exception as e:
            logger.warning(f"Could not start Telegram Bot: {e}")


@app.on_event("shutdown")
async def shutdown():
    global http_client
    if http_client:
        await http_client.aclose()
    try:
        from telegram_bot import stop_bot
        await stop_bot()
    except Exception:
        pass


# ── Helpers ───────────────────────────────────────────────────────────────────
def get_host(request: Request | None = None) -> str:
    configured = os.environ.get("RAILWAY_PUBLIC_DOMAIN") or CONFIG["host"]
    if request is not None:
        header_name = "x-forwarded-host" if TRUST_PROXY_HEADERS else "host"
        candidate = request.headers.get(header_name, "").split(",", 1)[0].strip().split(":", 1)[0].lower()
        if candidate and (candidate == configured.lower() or candidate in ALLOWED_PUBLIC_HOSTS):
            CONFIG["host"] = candidate
            return candidate
    return configured


def generate_uuid() -> str:
    h = secrets.token_hex(16)
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def now_ir() -> datetime:
    return datetime.now(IRAN_TZ)


def generate_config_link(
    uuid: str,
    host: str,
    remark: str = "Technamooz",
    protocol: str = DEFAULT_PROTOCOL,
    fingerprint: str | None = None,
    alpn: str | None = None,
    port: int | None = None,
    clean_ip: str | None = None,
) -> str:
    fp = (fingerprint or DEFAULT_FINGERPRINT).strip() or DEFAULT_FINGERPRINT
    if fp not in FINGERPRINTS:
        fp = DEFAULT_FINGERPRINT
    alpn_val = (alpn or "").strip() or DEFAULT_ALPN_BY_PROTOCOL.get(protocol, "http/1.1")
    port_val = port or DEFAULT_PORT
    if not (MIN_PORT <= port_val <= MAX_PORT):
        port_val = DEFAULT_PORT

    server_host = (clean_ip or "").strip() or host

    if protocol == "trojan-ws":
        path = f"/ws/{uuid}"
        params = {
            "security": "tls",
            "type": "ws",
            "host": host,
            "path": path,
            "sni": host,
            "fp": fp,
            "alpn": alpn_val,
        }
        query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
        return f"trojan://{uuid}@{server_host}:{port_val}?{query}#{quote(remark)}"

    elif protocol == "vless-ws":
        path = f"/ws/{uuid}"
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "ws",
            "host": host,
            "path": path,
            "sni": host,
            "fp": fp,
            "alpn": alpn_val,
        }
        query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
        return f"vless://{uuid}@{server_host}:{port_val}?{query}#{quote(remark)}"

    else:
        # XHTTP
        mode = protocol.replace("xhttp-", "")
        path = f"/xhttp-siz10/{mode}/{uuid}"
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "xhttp",
            "mode": mode,
            "host": host,
            "path": path,
            "sni": host,
            "fp": fp,
            "alpn": alpn_val,
        }
        query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
        return f"vless://{uuid}@{server_host}:{port_val}?{query}#{quote(remark)}"


def vless_link_for_link(link: dict, uid: str, host: str) -> str:
    proto = link.get("protocol", DEFAULT_PROTOCOL)
    return generate_config_link(
        uid,
        host,
        remark=f"Technamooz-{link.get('label', '')}",
        protocol=proto,
        fingerprint=link.get("fingerprint"),
        alpn=link.get("alpn"),
        port=link.get("port"),
        clean_ip=link.get("clean_ip"),
    )


def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB":
        return int(value * 1024 ** 3)
    if unit == "MB":
        return int(value * 1024 ** 2)
    return int(value)


def parse_speed_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit in ("MBPS", "MBIT", "MB/S"):
        return int(value * 1024 * 1024 / 8)
    if unit in ("KBPS", "KBIT", "KB/S"):
        return int(value * 1024 / 8)
    return int(value)


def normalize_port(value) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return DEFAULT_PORT
    return port if MIN_PORT <= port <= MAX_PORT else DEFAULT_PORT


def parse_request_float(value, field: str, default: float = 0.0) -> float:
    try:
        result = default if value is None or value == "" else float(value)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail=f"مقدار {field} نامعتبر است")
    if result != result or result in (float("inf"), float("-inf")):
        raise HTTPException(status_code=400, detail=f"مقدار {field} نامعتبر است")
    return result


def parse_request_int(value, field: str, default: int = 0) -> int:
    try:
        return default if value is None or value == "" else int(value)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail=f"مقدار {field} نامعتبر است")


def is_link_expired(link: dict) -> bool:
    exp = link.get("expires_at")
    if not exp:
        return False
    try:
        dt = datetime.fromisoformat(exp)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=IRAN_TZ)
        return now_ir() > dt
    except Exception:
        return False


def is_link_allowed(link: dict | None) -> bool:
    if link is None or not link.get("active", True):
        return False
    if is_link_expired(link):
        return False
    lim = link.get("limit_bytes", 0)
    if lim > 0 and link.get("used_bytes", 0) >= lim:
        return False
    return True


def fmt_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    if b < 1024 ** 2:
        return f"{b/1024:.1f} KB"
    if b < 1024 ** 3:
        return f"{b/1024**2:.2f} MB"
    return f"{b/1024**3:.2f} GB"


def unique_ips_for_uuid(uuid: str) -> set:
    from speed_limit import get_active_ips_for_uuid
    conn_ips = {c.get("ip") for c in connections.values() if c.get("uuid") == uuid and c.get("ip")}
    return conn_ips.union(get_active_ips_for_uuid(uuid))


def is_ip_allowed(link: dict | None, uuid: str, ip: str) -> bool:
    from speed_limit import is_ip_within_limit
    return is_ip_within_limit(link, uuid, ip)


def client_ip(request: Request) -> str:
    if TRUST_PROXY_HEADERS:
        cf_ip = request.headers.get("cf-connecting-ip")
        if cf_ip:
            return cf_ip.strip()
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()
    return request.client.host if request.client else "نامشخص"


async def ensure_default_link():
    if not LINKS:
        uid = generate_uuid()
        LINKS[uid] = {
            "label": "پیش‌فرض Technamooz",
            "active": True,
            "created_at": datetime.now().isoformat(),
            "used_bytes": 0,
            "limit_bytes": 0,
            "expires_at": None,
            "note": "کانفیگ اولیه ساخته‌شده توسط تیم Technamooz",
            "sub_id": None,
            "protocol": "vless-ws",
            "fingerprint": "chrome",
            "alpn": "http/1.1",
            "port": 443,
            "ip_limit": 0,
            "speed_limit_bytes": 0,
            "clean_ip": "",
        }
        await save_state()


async def remove_link(uid: str) -> str | None:
    async with LINKS_LOCK:
        link = LINKS.pop(uid, None)
        if not link:
            return None
        label = link.get("label", uid[:8])
    from speed_limit import reset_bucket
    reset_bucket(uid)
    async with SUBS_LOCK:
        for sub in SUBS.values():
            if uid in sub.get("link_ids", []):
                sub["link_ids"].remove(uid)
    await save_state()
    log_activity("delete", f"کانفیگ «{label}» حذف شد", "warn")
    return label


async def create_sub_group(name: str, desc: str = "", password: str = "") -> tuple[str, dict]:
    sub_id = generate_uuid()
    uuid_key = secrets.token_urlsafe(16)
    sub = {
        "name": (name or "گروه جدید Technamooz").strip()[:60],
        "desc": (desc or "").strip()[:200],
        "password_hash": hash_password(password) if password else None,
        "uuid_key": uuid_key,
        "link_ids": [],
        "created_at": datetime.now().isoformat(),
    }
    async with SUBS_LOCK:
        SUBS[sub_id] = sub
    await save_state()
    log_activity("sub", f"گروه اشتراک «{sub['name']}» ساخته شد", "ok")
    return sub_id, sub


async def remove_sub_group(sub_id: str) -> str | None:
    async with SUBS_LOCK:
        sub = SUBS.pop(sub_id, None)
        if not sub:
            return None
    async with LINKS_LOCK:
        for link in LINKS.values():
            if link.get("sub_id") == sub_id:
                link["sub_id"] = None
    name = sub.get("name", sub_id[:8])
    await save_state()
    log_activity("sub", f"گروه اشتراک «{name}» حذف شد", "warn")
    return name


async def set_link_sub(uid: str, sub_id: str | None) -> bool:
    # Always acquire locks in the project-wide order: SUBS before LINKS.
    if sub_id is not None:
        async with SUBS_LOCK:
            if sub_id not in SUBS:
                return False
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            return False
        link["sub_id"] = sub_id
    async with SUBS_LOCK:
        for sid, s in SUBS.items():
            lids = s.setdefault("link_ids", [])
            if sid == sub_id:
                if uid not in lids:
                    lids.append(uid)
            elif uid in lids:
                lids.remove(uid)
    await save_state()
    return True


async def set_link_active(uid: str, active: bool) -> dict | None:
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link:
            return None
        link["active"] = bool(active)
        result = dict(link)
    await save_state()
    log_activity("link", f"وضعیت کانفیگ «{uid[:8]}» به {'فعال' if active else 'غیرفعال'} تغییر یافت", "ok")
    return result


# ── Subscription Formats Generators (Clash & Sing-box) ─────────────────────────
def generate_clash_meta_yaml(links_list: list[tuple[str, dict]], host: str, profile_name: str = "Technamooz") -> str:
    proxies_yaml = []
    proxy_names = []

    for uid, link in links_list:
        proto = link.get("protocol", "vless-ws")
        name = f"Technamooz - {link.get('label', 'Node')} ({proto})"
        proxy_names.append(name)
        server = (link.get("clean_ip") or "").strip() or host
        port = link.get("port") or 443
        fp = link.get("fingerprint") or "chrome"

        if proto == "trojan-ws":
            proxies_yaml.append(f"""  - name: {json.dumps(name, ensure_ascii=False)}
    type: trojan
    server: {server}
    port: {port}
    password: "{uid}"
    udp: true
    sni: {host}
    client-fingerprint: {fp}
    network: ws
    ws-opts:
      path: "/ws/{uid}"
      headers:
        Host: {host}""")
        elif proto == "vless-ws":
            proxies_yaml.append(f"""  - name: {json.dumps(name, ensure_ascii=False)}
    type: vless
    server: {server}
    port: {port}
    uuid: "{uid}"
    udp: true
    tls: true
    sni: {host}
    client-fingerprint: {fp}
    network: ws
    ws-opts:
      path: "/ws/{uid}"
      headers:
        Host: {host}""")
        else:
            # XHTTP
            mode = proto.replace("xhttp-", "")
            proxies_yaml.append(f"""  - name: {json.dumps(name, ensure_ascii=False)}
    type: vless
    server: {server}
    port: {port}
    uuid: "{uid}"
    udp: true
    tls: true
    sni: {host}
    client-fingerprint: {fp}
    network: h2
    h2-opts:
      host:
        - {host}
      path: "/xhttp-siz10/{mode}/{uid}"
""")

    proxies_str = "\n".join(proxies_yaml) if proxies_yaml else "  []"
    quoted_names = "\n".join(
        f"      - {json.dumps(n, ensure_ascii=False)}" for n in proxy_names
    )

    return f"""# Generated by Panel Technamooz v1.0.0.0 stable
# Community: https://t.me/technamooz | Website: https://technamooz.ir
port: 7890
socks-port: 7891
allow-lan: true
mode: rule
log-level: info
ipv6: false

proxies:
{proxies_str}

proxy-groups:
  - name: PROXIES
    type: select
    proxies:
      - AUTO-SELECT
      - FALLBACK
{quoted_names}

  - name: AUTO-SELECT
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    proxies:
{quoted_names}

  - name: FALLBACK
    type: fallback
    url: http://www.gstatic.com/generate_204
    interval: 300
    proxies:
{quoted_names}

rules:
  - GEOIP,IR,DIRECT
  - DOMAIN-SUFFIX,ir,DIRECT
  - MATCH,PROXIES
"""


def generate_singbox_json(links_list: list[tuple[str, dict]], host: str) -> dict:
    outbounds = []
    tags = []

    for uid, link in links_list:
        proto = link.get("protocol", "vless-ws")
        tag = f"Technamooz - {link.get('label', 'Node')} ({proto})"
        tags.append(tag)
        server = (link.get("clean_ip") or "").strip() or host
        port = link.get("port") or 443
        fp = link.get("fingerprint") or "chrome"

        if proto == "trojan-ws":
            outbounds.append({
                "type": "trojan",
                "tag": tag,
                "server": server,
                "server_port": port,
                "password": uid,
                "tls": {
                    "enabled": True,
                    "server_name": host,
                    "utls": {"enabled": True, "fingerprint": fp},
                },
                "transport": {
                    "type": "ws",
                    "path": f"/ws/{uid}",
                    "headers": {"Host": host},
                },
            })
        else:
            if proto == "vless-ws":
                transport = {
                    "type": "ws",
                    "path": f"/ws/{uid}",
                    "headers": {"Host": host},
                }
            else:
                mode = proto.replace("xhttp-", "")
                transport = {
                    "type": "http",
                    "host": [host],
                    "path": f"/xhttp-siz10/{mode}/{uid}",
                    "method": "POST",
                }
            outbounds.append({
                "type": "vless",
                "tag": tag,
                "server": server,
                "server_port": port,
                "uuid": uid,
                "tls": {
                    "enabled": True,
                    "server_name": host,
                    "utls": {"enabled": True, "fingerprint": fp},
                },
                "transport": transport,
            })

    if not tags:
        tags = ["direct"]

    return {
        "version": 1,
        "outbounds": [
            {
                "type": "selector",
                "tag": "select",
                "outbounds": ["auto"] + tags,
            },
            {
                "type": "urltest",
                "tag": "auto",
                "outbounds": tags,
                "url": "https://www.gstatic.com/generate_204",
                "interval": "3m",
            },
        ] + outbounds + [{"type": "direct", "tag": "direct"}],
        "route": {
            "rules": [
                {"geoip": ["ir"], "outbound": "direct"},
                {"geosite": ["ir"], "outbound": "direct"},
            ]
        },
    }


# ── Basic Endpoints ───────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return RedirectResponse(url="/dashboard")


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "app": APP_NAME,
        "version": APP_VERSION,
        "team": "Technamooz",
        "manager": "amirparsa",
    }


@app.get("/api/system")
async def system_info(_=Depends(require_auth)):
    try:
        import psutil
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
    except Exception:
        cpu = 0.0
        ram = 0.0

    return {
        "app_name": APP_NAME,
        "app_version": APP_VERSION,
        "status": "stable",
        "team": "Technamooz",
        "manager": "amirparsa",
        "uptime": uptime(),
        "total_traffic": fmt_bytes(stats["total_bytes"]),
        "total_requests": stats["total_requests"],
        "active_connections": len(connections),
        "total_links": len(LINKS),
        "total_subs": len(SUBS),
        "cpu": cpu,
        "ram": ram,
    }


# ── Backup / Restore ──────────────────────────────────────────────────────────
@app.get("/api/backup")
async def download_backup(_=Depends(require_auth)):
    async with LINKS_LOCK, SUBS_LOCK:
        data = {
            "version": APP_VERSION,
            "exported_at": datetime.now().isoformat(),
            "links": dict(LINKS),
            "subs": dict(SUBS),
            "telegram": {k: v for k, v in BOT_SETTINGS.items() if k != "token"},
            "author": "Technamooz (amirparsa)",
        }
    content = json.dumps(data, ensure_ascii=False, indent=2)
    filename = f"technamooz_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.post("/api/restore")
async def restore_backup(request: Request, _=Depends(require_auth)):
    body = await request.json()
    new_links = body.get("links", {})
    new_subs = body.get("subs", {})
    if not isinstance(new_links, dict) or not isinstance(new_subs, dict):
        raise HTTPException(status_code=400, detail="فرمت فایل بکاپ نامعتبر است")

    # Do not allow arbitrary objects to enter the runtime state.  Restore is an
    # admin operation, but malformed state can otherwise crash relay/subscription
    # code long after the restore request has completed.
    required_link_keys = {"active", "used_bytes", "limit_bytes", "protocol"}
    for uid, link in new_links.items():
        if not isinstance(uid, str) or not isinstance(link, dict) or not required_link_keys.issubset(link):
            raise HTTPException(status_code=400, detail="فرمت کانفیگ در بکاپ نامعتبر است")
        if link.get("protocol") not in PROTOCOLS:
            raise HTTPException(status_code=400, detail="پروتکل نامعتبر در بکاپ")
        try:
            if int(link.get("used_bytes", 0)) < 0 or int(link.get("limit_bytes", 0)) < 0:
                raise ValueError
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="مقادیر ترافیک در بکاپ نامعتبر است")
    for sid, sub in new_subs.items():
        if not isinstance(sid, str) or not isinstance(sub, dict) or not isinstance(sub.get("link_ids", []), list):
            raise HTTPException(status_code=400, detail="فرمت گروه در بکاپ نامعتبر است")
        if any(lid not in new_links for lid in sub.get("link_ids", [])):
            raise HTTPException(status_code=400, detail="گروه به کانفیگ ناموجود اشاره می‌کند")

    async with LINKS_LOCK, SUBS_LOCK:
        LINKS.clear()
        LINKS.update(new_links)
        SUBS.clear()
        SUBS.update(new_subs)
        if "telegram" in body and isinstance(body["telegram"], dict):
            imported_telegram = dict(body["telegram"])
            imported_telegram.pop("token", None)
            BOT_SETTINGS.update(imported_telegram)

    await save_state()
    log_activity("restore", f"بکاپ بازیابی شد: {len(LINKS)} کانفیگ و {len(SUBS)} گروه", "ok")
    return {"ok": True, "links_restored": len(LINKS), "subs_restored": len(SUBS)}


# ── Subscriptions ─────────────────────────────────────────────────────────────
@app.get("/sub/{uuid}")
@app.get("/sub/{uuid}/clash")
@app.get("/sub/{uuid}/singbox")
async def subscription_single(uuid: str, request: Request):
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
    if not link or not is_link_allowed(link):
        raise HTTPException(status_code=404, detail="Config not found or inactive")

    host = get_host(request)
    fmt = request.query_params.get("format", "").lower()
    if request.url.path.endswith("/clash") or fmt == "clash":
        yaml_content = generate_clash_meta_yaml([(uuid, link)], host, link.get("label", "Technamooz"))
        return Response(content=yaml_content, media_type="text/yaml")
    elif request.url.path.endswith("/singbox") or fmt == "singbox":
        sb_json = generate_singbox_json([(uuid, link)], host)
        return Response(content=json.dumps(sb_json, indent=2), media_type="application/json")

    # Standard Base64
    vless_uri = vless_link_for_link(link, uuid, host)
    b64 = base64.b64encode(vless_uri.encode()).decode()

    used = link.get("used_bytes", 0)
    total = link.get("limit_bytes", 0)
    exp_ts = 0
    if link.get("expires_at"):
        try:
            exp_ts = int(datetime.fromisoformat(link["expires_at"]).timestamp())
        except Exception:
            exp_ts = 0

    headers = {
        "profile-title": quote(link.get("label", "Technamooz")),
        "support-url": "https://t.me/technamooz",
        "profile-update-interval": "12",
        "Subscription-UserInfo": f"upload={used}; download=0; total={total}; expire={exp_ts}",
    }
    return Response(content=b64, media_type="text/plain", headers=headers)


@app.get("/sub-group/{uuid_key}")
@app.get("/sub-group/{uuid_key}/clash")
@app.get("/sub-group/{uuid_key}/singbox")
async def sub_group_subscription(uuid_key: str, request: Request):
    async with SUBS_LOCK:
        sub = next((s for s in SUBS.values() if s.get("uuid_key") == uuid_key), None)
    if not sub:
        raise HTTPException(status_code=404, detail="Group not found")

    if sub.get("password_hash"):
        pw = request.query_params.get("pw", "")
        if not verify_password(pw, sub["password_hash"]):
            raise HTTPException(status_code=403, detail="Password required or incorrect")

    host = get_host(request)
    link_ids = sub.get("link_ids", [])
    valid_links = []

    async with LINKS_LOCK:
        for lid in link_ids:
            lk = LINKS.get(lid)
            if lk and is_link_allowed(lk):
                valid_links.append((lid, lk))

    fmt = request.query_params.get("format", "").lower()
    if request.url.path.endswith("/clash") or fmt == "clash":
        yaml_content = generate_clash_meta_yaml(valid_links, host, sub.get("name", "Technamooz Group"))
        return Response(content=yaml_content, media_type="text/yaml")
    elif request.url.path.endswith("/singbox") or fmt == "singbox":
        sb_json = generate_singbox_json(valid_links, host)
        return Response(content=json.dumps(sb_json, indent=2), media_type="application/json")

    # Standard Base64
    uris = [vless_link_for_link(lk, lid, host) for lid, lk in valid_links]
    content = base64.b64encode("\n".join(uris).encode()).decode()

    headers = {
        "profile-title": quote(sub.get("name", "Technamooz Group")),
        "support-url": "https://t.me/technamooz",
        "profile-update-interval": "12",
    }
    return Response(content=content, media_type="text/plain", headers=headers)


@app.get("/sub-all")
async def subscription_all(request: Request, _=Depends(require_auth)):
    host = get_host(request)
    async with LINKS_LOCK:
        valid_links = [(uid, lk) for uid, lk in LINKS.items() if is_link_allowed(lk)]

    fmt = request.query_params.get("format", "").lower()
    if fmt == "clash":
        return Response(content=generate_clash_meta_yaml(valid_links, host, "Technamooz All"), media_type="text/yaml")
    elif fmt == "singbox":
        return Response(content=json.dumps(generate_singbox_json(valid_links, host), indent=2), media_type="application/json")

    lines = [vless_link_for_link(lk, uid, host) for uid, lk in valid_links]
    return Response(content=base64.b64encode("\n".join(lines).encode()).decode(), media_type="text/plain")


# ── Captcha & Auth Endpoints ──────────────────────────────────────────────────
@app.get("/api/captcha")
async def get_captcha():
    alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    cid = secrets.token_urlsafe(16)
    code = "".join(secrets.choice(alphabet) for _ in range(5))
    LOGIN_CAPTCHAS[cid] = (code, time.time() + 300)

    # Clean old captchas
    now = time.time()
    for k in list(LOGIN_CAPTCHAS.keys()):
        if LOGIN_CAPTCHAS[k][1] < now:
            LOGIN_CAPTCHAS.pop(k, None)

    return {"captcha_id": cid, "captcha_code": code}


@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    ip = client_ip(request)

    captcha_id = str(body.get("captcha_id", "")).strip()
    captcha_code = str(body.get("captcha_code", "")).strip().upper()
    challenge = LOGIN_CAPTCHAS.pop(captcha_id, None)

    if not challenge or challenge[1] < time.time() or not hmac.compare_digest(captcha_code, challenge[0]):
        raise HTTPException(status_code=401, detail="کد امنیتی اشتباه یا منقضی شده است / Invalid or expired captcha")

    if await login_rate_limited(ip):
        raise HTTPException(status_code=429, detail="تعداد تلاش‌های ناموفق بیش از حد مجاز است / Too many attempts")

    username = str(body.get("username", "")).strip()
    username_ok = hmac.compare_digest(username, AUTH["username"]) if username else False

    if not username_ok or not verify_password(str(body.get("password", "")), AUTH["password_hash"]):
        await record_login_failure(ip)
        log_activity("auth", f"تلاش ورود ناموفق از {ip}", "err")
        raise HTTPException(status_code=401, detail="نام کاربری یا رمز عبور اشتباه است / Invalid credentials")

    token = await create_session()
    log_activity("auth", f"ورود موفق مدیر به پنل از {ip}", "ok")
    resp = JSONResponse({"ok": True})
    resp.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_TTL,
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="lax",
        path="/",
    )
    return resp


@app.post("/api/logout")
async def api_logout(request: Request):
    await destroy_session(request.cookies.get(SESSION_COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@app.get("/api/me")
async def api_me(request: Request):
    return {
        "authenticated": await is_valid_session(request.cookies.get(SESSION_COOKIE)),
        "username": AUTH["username"],
        "app_name": APP_NAME,
        "version": APP_VERSION,
    }


@app.post("/api/change-credentials")
async def change_credentials(request: Request, token=Depends(require_auth)):
    body = await request.json()
    if not verify_password(str(body.get("current_password", "")), AUTH["password_hash"]):
        raise HTTPException(status_code=400, detail="رمز عبور فعلی نادرست است")

    username = str(body.get("username", "")).strip()
    new_password = str(body.get("new_password", ""))

    if len(username) < 3 or len(username) > 64:
        raise HTTPException(status_code=400, detail="نام کاربری باید بین ۳ تا ۶۴ کاراکتر باشد")
    if new_password and len(new_password) < 6:
        raise HTTPException(status_code=400, detail="رمز جدید باید حداقل ۶ کاراکتر باشد")

    AUTH["username"] = username
    if new_password:
        AUTH["password_hash"] = hash_password(new_password)

    async with SESSIONS_LOCK:
        SESSIONS.clear()
        SESSIONS[token] = time.time() + SESSION_TTL

    await save_state()
    log_activity("auth", "مشخصات ورود مدیر با موفقیت تغییر یافت", "ok")
    return {"ok": True, "username": username}


@app.post("/api/change-password")
async def change_password_compat(request: Request, token=Depends(require_auth)):
    """Backward-compatible endpoint used by the legacy dashboard script."""
    body = await request.json()
    if not verify_password(str(body.get("current_password", "")), AUTH["password_hash"]):
        raise HTTPException(status_code=400, detail="رمز عبور فعلی نادرست است")
    new_password = str(body.get("new_password", ""))
    if len(new_password) < 6:
        raise HTTPException(status_code=400, detail="رمز جدید باید حداقل ۶ کاراکتر باشد")
    AUTH["password_hash"] = hash_password(new_password)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        SESSIONS[token] = time.time() + SESSION_TTL
    await save_state()
    return {"ok": True}


# ── Telegram Settings Endpoints ───────────────────────────────────────────────
@app.get("/api/telegram/status")
async def telegram_status(_=Depends(require_auth)):
    try:
        from telegram_bot import get_bot_status
        return get_bot_status()
    except Exception:
        return {"configured": False, "running": False}


@app.post("/api/telegram/settings")
async def telegram_settings(request: Request, _=Depends(require_auth)):
    body = await request.json()
    token = str(body.get("token", "")).strip()
    admin_ids = str(body.get("admin_ids", "")).strip()
    BOT_SETTINGS["token"] = token
    BOT_SETTINGS["admin_ids"] = admin_ids
    BOT_SETTINGS["enabled"] = bool(body.get("enabled", bool(token))) and bool(token)
    await save_state()

    try:
        if BOT_SETTINGS["enabled"]:
            from telegram_bot import configure_bot
            await configure_bot(token, admin_ids)
        else:
            from telegram_bot import stop_bot
            await stop_bot()
    except Exception as e:
        logger.warning(f"Could not configure Telegram bot: {e}")

    log_activity("telegram", "تنظیمات ربات تلگرام به‌روزرسانی شد", "ok")
    return {"ok": True}


# ── Stats, Activity, Connections ──────────────────────────────────────────────
@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    async with LINKS_LOCK:
        total_links = len(LINKS)
        active_links = sum(1 for l in LINKS.values() if l.get("active", True) and not is_link_expired(l))
        total_traffic = sum(l.get("used_bytes", 0) for l in LINKS.values())
    async with SUBS_LOCK:
        subs_count = len(SUBS)

    server_total_bytes = max(stats["total_bytes"], total_traffic)
    total_traffic_mb = round(server_total_bytes / (1024 * 1024), 2)

    return {
        "uptime": uptime(),
        "total_bytes": server_total_bytes,
        "total_traffic_mb": total_traffic_mb,
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "active_connections": len(connections),
        "total_links": total_links,
        "links_count": total_links,
        "active_links": active_links,
        "subs_count": subs_count,
        "hourly": dict(hourly_traffic),
        "hourly_traffic": dict(hourly_traffic),
        "recent_errors": list(error_logs)[-10:],
    }


@app.get("/api/activity")
async def get_activity(_=Depends(require_auth)):
    return {"logs": list(reversed(activity_logs))}


@app.get("/api/connections")
async def get_connections(_=Depends(require_auth)):
    items = []
    async with LINKS_LOCK:
        for cid, c in connections.items():
            link = LINKS.get(c.get("uuid", ""))
            bytes_val = c.get("bytes", 0)
            items.append({
                "conn_id": cid,
                "uuid": c.get("uuid"),
                "label": link.get("label", "Unknown") if link else "Unknown",
                "ip": c.get("ip", "127.0.0.1"),
                "transport": c.get("transport", "vless-ws"),
                "connected_at": c.get("connected_at", datetime.now().isoformat()),
                "bytes": bytes_val,
                "bytes_fmt": fmt_bytes(bytes_val),
            })
    return {
        "count": len(items),
        "connections": items,
    }


# ── Links Management Endpoints ────────────────────────────────────────────────
async def make_link(
    label: str,
    limit_value: float = 0,
    limit_unit: str = "GB",
    expires_days: float = 0,
    note: str = "",
    sub_id: str | None = None,
    protocol: str = DEFAULT_PROTOCOL,
    fingerprint: str | None = None,
    alpn: str | None = None,
    port: int | None = None,
    ip_limit: int = 0,
    speed_limit_value: float = 0,
    speed_limit_unit: str = "Mbps",
    clean_ip: str = "",
    limit_bytes: int | None = None,
    expires_at: str | None = None,
    speed_limit_bytes: int | None = None,
) -> tuple[str, dict]:
    uid = generate_uuid()
    if limit_bytes is not None:
        final_limit_bytes = max(0, int(limit_bytes))
    else:
        final_limit_bytes = parse_size_to_bytes(limit_value, limit_unit) if limit_value > 0 else 0

    if expires_at is not None:
        final_expires_at = expires_at
    else:
        final_expires_at = (now_ir() + timedelta(days=expires_days)).isoformat() if expires_days > 0 else None

    if speed_limit_bytes is not None:
        final_speed_bytes = max(0, int(speed_limit_bytes))
    else:
        final_speed_bytes = parse_speed_to_bytes(speed_limit_value, speed_limit_unit) if speed_limit_value > 0 else 0

    proto = protocol if protocol in PROTOCOLS else DEFAULT_PROTOCOL
    fp = (fingerprint or DEFAULT_FINGERPRINT).strip()
    if fp not in FINGERPRINTS:
        fp = DEFAULT_FINGERPRINT
    if sub_id:
        async with SUBS_LOCK:
            if sub_id not in SUBS:
                raise HTTPException(status_code=400, detail="گروه اشتراک یافت نشد")

    link_data = {
        "label": label or "کانفیگ Technamooz",
        "active": True,
        "created_at": datetime.now().isoformat(),
        "used_bytes": 0,
        "limit_bytes": final_limit_bytes,
        "expires_at": final_expires_at,
        "note": note,
        "sub_id": sub_id,
        "protocol": proto,
        "fingerprint": fp,
        "alpn": (alpn or "").strip(),
        "port": normalize_port(port),
        "ip_limit": max(0, int(ip_limit or 0)),
        "speed_limit_bytes": final_speed_bytes,
        "clean_ip": (clean_ip or "").strip(),
    }

    async with LINKS_LOCK:
        LINKS[uid] = link_data

    if sub_id:
        async with SUBS_LOCK:
            sub = SUBS.get(sub_id)
            if sub and uid not in sub.setdefault("link_ids", []):
                sub["link_ids"].append(uid)

    await save_state()
    log_activity("create", f"کانفیگ «{label}» ({proto}) ساخته شد", "ok")
    return uid, link_data


async def reset_link_usage_helper(uid: str):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link:
            return None
        link["used_bytes"] = 0
    await save_state()
    log_activity("reset", f"مصرف کانفیگ «{link.get('label', uid[:8])}» صفر شد", "info")
    return link


async def renew_link_helper(uid: str, days: float = 30, reset_usage: bool = False):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link:
            return None
        link["active"] = True
        cur_exp = link.get("expires_at")
        base_dt = now_ir()
        if cur_exp:
            try:
                dt = datetime.fromisoformat(cur_exp)
                if dt > base_dt:
                    base_dt = dt
            except Exception:
                pass
        link["expires_at"] = (base_dt + timedelta(days=days)).isoformat()
        if reset_usage:
            link["used_bytes"] = 0
    await save_state()
    log_activity("renew", f"کانفیگ «{link.get('label', uid[:8])}» برای {int(days)} روز تمدید شد", "ok")
    return link


@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    uid, link_data = await make_link(
        label=str(body.get("label", "کانفیگ جدید")).strip(),
        limit_value=parse_request_float(body.get("limit_value", 0), "limit_value"),
        limit_unit=str(body.get("limit_unit", "GB")),
        expires_days=parse_request_float(body.get("expires_days", 0), "expires_days"),
        note=str(body.get("note", "")).strip(),
        sub_id=body.get("sub_id") or None,
        protocol=str(body.get("protocol", DEFAULT_PROTOCOL)),
        fingerprint=body.get("fingerprint"),
        alpn=body.get("alpn"),
        port=parse_request_int(body.get("port", DEFAULT_PORT), "port", DEFAULT_PORT),
        ip_limit=parse_request_int(body.get("ip_limit", 0), "ip_limit"),
        speed_limit_value=parse_request_float(body.get("speed_limit_value", 0), "speed_limit_value"),
        speed_limit_unit=str(body.get("speed_limit_unit", "Mbps")),
        clean_ip=str(body.get("clean_ip", "")).strip(),
    )
    host = get_host(request)
    return {
        "uuid": uid,
        "link": link_data,
        "vless_link": vless_link_for_link(link_data, uid, host),
        "sub_url": f"https://{host}/sub/{uid}",
        "clash_url": f"https://{host}/sub/{uid}/clash",
        "singbox_url": f"https://{host}/sub/{uid}/singbox",
    }


@app.get("/api/links")
async def list_links(request: Request, _=Depends(require_auth)):
    host = get_host(request)
    result = []
    async with LINKS_LOCK:
        for uid, lk in LINKS.items():
            item = dict(lk)
            item["uuid"] = uid
            item["expired"] = is_link_expired(lk)
            item["connected_ips"] = len(unique_ips_for_uuid(uid))
            item["vless_link"] = vless_link_for_link(lk, uid, host)
            item["sub_url"] = f"https://{host}/sub/{uid}"
            item["clash_url"] = f"https://{host}/sub/{uid}/clash"
            item["singbox_url"] = f"https://{host}/sub/{uid}/singbox"
            result.append(item)
    return {"links": result}


@app.patch("/api/links/{uid}")
async def update_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link:
            raise HTTPException(status_code=404, detail="کانفیگ یافت نشد")

        if "label" in body:
            link["label"] = str(body["label"]).strip()
        if "active" in body:
            link["active"] = bool(body["active"])
        if "note" in body:
            link["note"] = str(body["note"]).strip()
        if "clean_ip" in body:
            link["clean_ip"] = str(body["clean_ip"]).strip()
        if "reset_usage" in body and body["reset_usage"]:
            link["used_bytes"] = 0
        if "limit_value" in body:
            val = parse_request_float(body["limit_value"], "limit_value")
            unit = body.get("limit_unit", "GB")
            link["limit_bytes"] = parse_size_to_bytes(val, unit) if val > 0 else 0
        if "expires_days" in body:
            days = parse_request_float(body["expires_days"], "expires_days")
            link["expires_at"] = (now_ir() + timedelta(days=days)).isoformat() if days > 0 else None
        if "protocol" in body:
            proto = body["protocol"]
            if proto in PROTOCOLS:
                link["protocol"] = proto
        if "fingerprint" in body:
            fp = str(body["fingerprint"]).strip()
            if fp in FINGERPRINTS:
                link["fingerprint"] = fp
        if "alpn" in body:
            link["alpn"] = str(body["alpn"]).strip()
        if "port" in body:
            link["port"] = normalize_port(body["port"])
        if "ip_limit" in body:
            link["ip_limit"] = max(0, parse_request_int(body["ip_limit"], "ip_limit"))
        if "speed_limit_value" in body:
            sval = parse_request_float(body["speed_limit_value"], "speed_limit_value")
            sunit = body.get("speed_limit_unit", "Mbps")
            link["speed_limit_bytes"] = parse_speed_to_bytes(sval, sunit) if sval > 0 else 0
            from speed_limit import reset_bucket
            reset_bucket(uid)

    await save_state()
    log_activity("update", f"کانفیگ «{link.get('label', uid[:8])}» ویرایش شد", "info")
    return {"ok": True, "link": link}


@app.post("/api/links/{uid}/renew")
async def renew_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json() if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() == "application/json" else {}
    add_days = float(body.get("days", 30) or 30)
    reset_usage = bool(body.get("reset_usage", True))
    link = await renew_link_helper(uid, days=add_days, reset_usage=reset_usage)
    if not link:
        raise HTTPException(status_code=404, detail="کانفیگ یافت نشد")
    return {"ok": True, "expires_at": link["expires_at"], "used_bytes": link["used_bytes"]}


@app.post("/api/links/{uid}/reset")
async def reset_link_usage(uid: str, _=Depends(require_auth)):
    link = await reset_link_usage_helper(uid)
    if not link:
        raise HTTPException(status_code=404, detail="کانفیگ یافت نشد")
    return {"ok": True}


@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    label = await remove_link(uid)
    if not label:
        raise HTTPException(status_code=404, detail="کانفیگ یافت نشد")
    return {"ok": True}


@app.get("/api/links/export")
async def export_links(request: Request, _=Depends(require_auth)):
    host = get_host(request)
    links_out = []
    async with LINKS_LOCK:
        for uid, lk in LINKS.items():
            if lk.get("active", True) and not is_link_expired(lk):
                links_out.append(vless_link_for_link(lk, uid, host))
    return {"count": len(links_out), "links": links_out}


# ── Sub-Groups Endpoints ──────────────────────────────────────────────────────
@app.post("/api/subs")
async def create_sub(request: Request, _=Depends(require_auth)):
    body = await request.json()
    name = (body.get("name") or "گروه جدید Technamooz").strip()[:60]
    desc = (body.get("desc") or "").strip()[:200]
    password = (body.get("password") or "").strip()
    sub_id, sub = await create_sub_group(name=name, desc=desc, password=password)
    return {"ok": True, "sub_id": sub_id, "uuid_key": sub["uuid_key"]}


@app.get("/api/subs")
async def list_subs(request: Request, _=Depends(require_auth)):
    host = get_host(request)
    result = []
    async with SUBS_LOCK:
        for sid, sub in SUBS.items():
            item = dict(sub)
            item["sub_id"] = sid
            item["has_password"] = bool(sub.get("password_hash"))
            item["public_url"] = f"https://{host}/p/{sub.get('uuid_key')}"
            item["sub_url"] = f"https://{host}/sub-group/{sub.get('uuid_key')}"
            item["clash_url"] = f"https://{host}/sub-group/{sub.get('uuid_key')}/clash"
            item["singbox_url"] = f"https://{host}/sub-group/{sub.get('uuid_key')}/singbox"
            link_ids = list(sub.get("link_ids", []))
            async with LINKS_LOCK:
                group_links = [LINKS[lid] for lid in link_ids if lid in LINKS]
            item["links_count"] = len(group_links)
            item["active_count"] = sum(1 for lk in group_links if is_link_allowed(lk))
            item["total_used_fmt"] = fmt_bytes(sum(int(lk.get("used_bytes", 0) or 0) for lk in group_links))
            item.pop("password_hash", None)
            result.append(item)
    return {"subs": result}


@app.patch("/api/subs/{sub_id}")
async def patch_sub(sub_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with SUBS_LOCK:
        sub = SUBS.get(sub_id)
        if not sub:
            raise HTTPException(status_code=404, detail="گروه ساب یافت نشد")
        if "name" in body:
            sub["name"] = str(body["name"]).strip()[:60]
        if "desc" in body:
            sub["desc"] = str(body["desc"]).strip()[:200]
        if "link_ids" in body and isinstance(body["link_ids"], list):
            requested = list(dict.fromkeys(str(x) for x in body["link_ids"]))
            async with LINKS_LOCK:
                missing = [x for x in requested if x not in LINKS]
                if missing:
                    raise HTTPException(status_code=400, detail="یک یا چند کانفیگ یافت نشد")
                old_ids = set(sub.get("link_ids", []))
                new_ids = set(requested)
                for lid in old_ids - new_ids:
                    if lid in LINKS and LINKS[lid].get("sub_id") == sub_id:
                        LINKS[lid]["sub_id"] = None
                for lid in new_ids:
                    if LINKS[lid].get("sub_id") and LINKS[lid].get("sub_id") != sub_id:
                        old_sid = LINKS[lid]["sub_id"]
                        if old_sid in SUBS:
                            SUBS[old_sid]["link_ids"] = [x for x in SUBS[old_sid].get("link_ids", []) if x != lid]
                    LINKS[lid]["sub_id"] = sub_id
            sub["link_ids"] = requested
    await save_state()
    log_activity("sub", f"گروه اشتراک «{sub.get('name')}» ویرایش شد", "ok")
    safe_sub = dict(sub)
    safe_sub.pop("password_hash", None)
    return {"ok": True, "sub": safe_sub}


@app.delete("/api/subs/{sub_id}")
async def delete_sub(sub_id: str, _=Depends(require_auth)):
    ok = await remove_sub_group(sub_id)
    if not ok:
        raise HTTPException(status_code=404, detail="گروه یافت نشد")
    return {"ok": True}


@app.post("/api/subs/{sub_id}/links")
async def assign_link_to_sub(sub_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    link_id = body.get("link_id")
    action = body.get("action", "add")

    if action not in {"add", "remove"}:
        raise HTTPException(status_code=400, detail="عملیات نامعتبر است")
    if not isinstance(link_id, str):
        raise HTTPException(status_code=400, detail="شناسه کانفیگ نامعتبر است")
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="گروه یافت نشد")
    async with LINKS_LOCK:
        if link_id not in LINKS:
            raise HTTPException(status_code=404, detail="کانفیگ یافت نشد")

    # Use the canonical helper so both sides of the relationship stay in sync.
    if action == "add":
        ok = await set_link_sub(link_id, sub_id)
    else:
        async with LINKS_LOCK:
            belongs_to_group = LINKS[link_id].get("sub_id") == sub_id
        ok = await set_link_sub(link_id, None) if belongs_to_group else True
    if not ok:
        raise HTTPException(status_code=409, detail="همگام‌سازی گروه انجام نشد")
    return {"ok": True}


# ── Subscriber Public Page (/p/{uuid_key}) ────────────────────────────────────
@app.get("/p/{uuid_key}", response_class=HTMLResponse)
async def public_sub_page(uuid_key: str, request: Request):
    from pages import get_public_page_html
    return HTMLResponse(content=get_public_page_html(uuid_key))


@app.get("/api/public/sub/{uuid_key}")
async def public_sub_data(uuid_key: str, request: Request):
    pw = request.query_params.get("p", request.query_params.get("pw", ""))
    async with SUBS_LOCK:
        sub = next((s for s in SUBS.values() if s.get("uuid_key") == uuid_key), None)
    if not sub:
        raise HTTPException(status_code=404, detail="اشتراک یافت نشد")

    if sub.get("password_hash"):
        if not pw or not verify_password(pw, sub["password_hash"]):
            return {"locked": True, "name": sub.get("name")}

    host = get_host(request)
    links_out = []
    tot_used = 0
    tot_limit = 0

    async with LINKS_LOCK:
        for lid in sub.get("link_ids", []):
            lk = LINKS.get(lid)
            if not lk:
                continue
            tot_used += lk.get("used_bytes", 0)
            tot_limit += lk.get("limit_bytes", 0)
            used = int(lk.get("used_bytes", 0) or 0)
            limit = int(lk.get("limit_bytes", 0) or 0)
            links_out.append({
                "label": lk.get("label"),
                "protocol": lk.get("protocol"),
                "vless_link": vless_link_for_link(lk, lid, host),
                "sub_url": f"https://{host}/sub/{lid}",
                "active": lk.get("active", True),
                "expired": is_link_expired(lk),
                "used_bytes": used,
                "limit_bytes": limit,
                "used_fmt": fmt_bytes(used),
                "connections": sum(1 for c in connections.values() if c.get("uuid") == lid),
            })

    return {
        "locked": False,
        "name": sub.get("name"),
        "desc": sub.get("desc"),
        "links": links_out,
        "total_used": tot_used,
        "total_limit": tot_limit,
        "total_used_fmt": fmt_bytes(tot_used),
        "active_connections": sum(1 for c in connections.values() if c.get("uuid") in set(sub.get("link_ids", []))),
        "sub_url": f"https://{host}/sub-group/{uuid_key}",
        "clash_url": f"https://{host}/sub-group/{uuid_key}/clash",
        "singbox_url": f"https://{host}/sub-group/{uuid_key}/singbox",
    }


# ── HTML Views ────────────────────────────────────────────────────────────────
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/dashboard")

    from pages import LOGIN_HTML
    alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    cid = secrets.token_urlsafe(16)
    code = "".join(secrets.choice(alphabet) for _ in range(5))
    LOGIN_CAPTCHAS[cid] = (code, time.time() + 300)

    html = LOGIN_HTML.replace("__CAPTCHA_ID__", cid).replace("__CAPTCHA_CODE__", code)
    return HTMLResponse(content=html)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/login")
    from pages import DASHBOARD_HTML
    return HTMLResponse(content=DASHBOARD_HTML)


# ── WebSocket & XHTTP Route Mounting ──────────────────────────────────────────
# Import the relay lazily so importing relay_vless or xhttp_siz10 directly does
# not create a partially-initialized ``main``/``relay_vless`` circular import.
async def websocket_tunnel_entry(ws, uuid: str):
    from relay_vless import websocket_tunnel
    return await websocket_tunnel(ws, uuid)


app.add_api_websocket_route("/ws/{uuid}", websocket_tunnel_entry)
app.add_api_websocket_route("/trojan/{uuid}", websocket_tunnel_entry)

from xhttp_siz10 import router as xhttp_router
app.include_router(xhttp_router)
