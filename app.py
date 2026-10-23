# -*- coding: utf-8 -*-
"""
PortMonitor - Live Port Scanning Dashboard
Backend: Flask + flask-sock WebSocket
"""
import sys
# Force UTF-8 stdout on Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

import os, json, time, socket, hashlib, secrets, re as _re, tempfile, ipaddress, threading, errno
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, deque
from flask import Flask, request, jsonify, send_from_directory
from flask_sock import Sock
from werkzeug.security import check_password_hash, generate_password_hash

# ─── Paths ────────────────────────────────────────────────────────────────────
BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
os.makedirs(DATA, exist_ok=True)

USERS_FILE    = os.path.join(DATA, "users.json")
MACHINES_FILE = os.path.join(DATA, "machines.json")
SESSIONS_FILE = os.path.join(DATA, "sessions.json")

# ─── Flask ────────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder="public", static_url_path="")
app.secret_key = secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
sock = Sock(app)
_DATA_LOCK = threading.RLock()
_LOGIN_LOCK = threading.Lock()
_LOGIN_ATTEMPTS = defaultdict(deque)
_LOGIN_WINDOW_SECONDS = 900
_LOGIN_ATTEMPT_LIMIT = 10


def utcnow():
    return datetime.now(timezone.utc)


@contextmanager
def data_transaction():
    with _DATA_LOCK:
        yield

# ─── Helpers: persistent JSON storage ─────────────────────────────────────────
def load_json(path, default):
    with _DATA_LOCK:
        if not os.path.exists(path):
            return default
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            app.logger.exception("Unable to load JSON data from %s", path)
            raise RuntimeError(f"Unable to read data file: {os.path.basename(path)}") from exc

def save_json(path, data):
    directory = os.path.dirname(path)
    temp_path = None
    with _DATA_LOCK:
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=directory, delete=False,
                prefix=f".{os.path.basename(path)}.", suffix=".tmp"
            ) as f:
                temp_path = f.name
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, path)
        except BaseException:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except OSError:
                    app.logger.exception("Unable to remove temporary data file %s", temp_path)
            raise

# UDP probes: port → bytes to send to elicit a response
UDP_PROBES = {
    53:   b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    123:  b"\x1b" + b"\x00" * 47,   # NTP version query
    161:  b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x71\x68\x63\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    1900: b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n",
    5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00",
}

# ─── OS fingerprinting ────────────────────────────────────────────────────────
# Probes several well-known ports and reads their banners to infer OS + version.
# No hardcoded port→OS maps — detection is purely from what the host sends back.

_OS_BANNER_PATTERNS = [
    # SSH banners carry OS info: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    (_re.compile(rb"ubuntu",          _re.I), "Linux",   lambda m: "Ubuntu "  + (m.group(0).decode(errors="replace").split("Ubuntu")[-1].strip().split()[0] if m else "")),
    (_re.compile(rb"debian",          _re.I), "Linux",   lambda m: "Debian "  + (m.group(0).decode(errors="replace").split("Debian")[-1].strip().split()[0] if m else "")),
    (_re.compile(rb"centos",          _re.I), "Linux",   lambda m: "CentOS "  + (m.group(0).decode(errors="replace").split("CentOS")[-1].strip().split()[0] if m else "")),
    (_re.compile(rb"fedora",          _re.I), "Linux",   lambda m: "Fedora "  + (m.group(0).decode(errors="replace").split("Fedora")[-1].strip().split()[0] if m else "")),
    (_re.compile(rb"arch linux",      _re.I), "Linux",   lambda m: "Arch Linux"),
    (_re.compile(rb"alpine",          _re.I), "Linux",   lambda m: "Alpine Linux"),
    (_re.compile(rb"raspbian",        _re.I), "Linux",   lambda m: "Raspbian"),
    (_re.compile(rb"openssh.*linux",  _re.I), "Linux",   lambda m: "Linux (OpenSSH)"),
    (_re.compile(rb"openssh",         _re.I), "Linux",   lambda m: "Linux"),
    (_re.compile(rb"windows",         _re.I), "Windows", lambda m: "Windows"),
    (_re.compile(rb"microsoft",       _re.I), "Windows", lambda m: "Windows (Microsoft)"),
    (_re.compile(rb"IIS",             _re.I), "Windows", lambda m: "Windows (IIS)"),
    (_re.compile(rb"freebsd",         _re.I), "BSD",     lambda m: "FreeBSD"),
    (_re.compile(rb"netbsd",          _re.I), "BSD",     lambda m: "NetBSD"),
    (_re.compile(rb"openbsd",         _re.I), "BSD",     lambda m: "OpenBSD"),
    (_re.compile(rb"darwin|mac os",   _re.I), "macOS",   lambda m: "macOS"),
    (_re.compile(rb"synology",        _re.I), "Linux",   lambda m: "Synology DSM"),
    (_re.compile(rb"mikrotik",        _re.I), "RouterOS",lambda m: "MikroTik RouterOS"),
    (_re.compile(rb"cisco",           _re.I), "Cisco",   lambda m: "Cisco IOS"),
    (_re.compile(rb"junos",           _re.I), "Junos",   lambda m: "Juniper JunOS"),
    (_re.compile(rb"Android",         _re.I), "Android", lambda m: "Android"),
]

# HTTP Server header → OS hints
_HTTP_SERVER_OS = [
    (_re.compile(r"Ubuntu|Debian|CentOS|Fedora|Alpine|Raspbian", _re.I), "Linux"),
    (_re.compile(r"Win32|Win64|Windows",                          _re.I), "Windows"),
    (_re.compile(r"Darwin",                                       _re.I), "macOS"),
    (_re.compile(r"FreeBSD|OpenBSD|NetBSD",                       _re.I), "BSD"),
]

def detect_os(host: str, timeout: float = 2.0) -> dict:
    """
    Probe several ports on `host` and fingerprint the OS from live banners.
    Checks SSH (22, 2222), HTTP (80, 8080, 443, 8443), SMB (445), Telnet (23).
    Returns {"os": "Linux", "version": "Ubuntu 22.04", "method": "ssh-banner"}
    or      {"os": "Unknown", "version": "", "method": "none"}
    """
    import urllib.request

    probe_ports = [22, 2222, 80, 8080, 443, 8443, 445, 23]

    for port in probe_ports:
        try:
            raw, text = grab_banner(host, port, timeout=timeout)
            if not raw:
                continue

            # Try all OS banner patterns
            for pattern, os_name, version_fn in _OS_BANNER_PATTERNS:
                m = pattern.search(raw)
                if m:
                    version = version_fn(m).strip(" \x00\r\n")
                    return {"os": os_name, "version": version, "method": f"banner:{port}"}

            # HTTP Server header
            if port in (80, 8080, 443, 8443):
                server_match = _re.search(r"[Ss]erver:\s*([^\r\n]+)", text)
                if server_match:
                    server_val = server_match.group(1)
                    for pat, os_name in _HTTP_SERVER_OS:
                        if pat.search(server_val):
                            return {"os": os_name, "version": server_val.strip(), "method": f"http-server:{port}"}

        except Exception:
            continue

    # TTL-based fallback via ICMP (ping) — Windows=128, Linux=64
    try:
        import subprocess
        flag = "-n" if os.name == "nt" else "-c"
        out  = subprocess.check_output(["ping", flag, "1", host], timeout=3,
                                        stderr=subprocess.DEVNULL).decode(errors="replace")
        ttl_m = _re.search(r"ttl[=:](\d+)", out, _re.I)
        if ttl_m:
            ttl = int(ttl_m.group(1))
            if ttl >= 100:
                return {"os": "Windows", "version": f"TTL={ttl}", "method": "icmp-ttl"}
            elif ttl >= 50:
                return {"os": "Linux",   "version": f"TTL={ttl}", "method": "icmp-ttl"}
    except Exception:
        pass

    return {"os": "Unknown", "version": "", "method": "none"}


# ── Banner-based service fingerprints (TCP) ───────────────────────────────────
_BANNER_PATTERNS = [
    (_re.compile(rb"SSH-",                _re.I), "ssh"),
    (_re.compile(rb"220.*ftp",            _re.I), "ftp"),
    (_re.compile(rb"220.*smtp|220.*mail|ehlo", _re.I), "smtp"),
    (_re.compile(rb"\+OK",                _re.I), "pop3"),
    (_re.compile(rb"\* OK.*IMAP",         _re.I), "imap"),
    (_re.compile(rb"HTTP/",               _re.I), "http"),
    (_re.compile(rb"RFB \d",              _re.I), "vnc"),
    (_re.compile(rb"^\x16\x03",                0), "tls/ssl"),
    (_re.compile(rb"mongod",              _re.I), "mongodb"),
    (_re.compile(rb"PONG|redis_version|-ERR", _re.I), "redis"),
    (_re.compile(rb"mysql|mariadb",       _re.I), "mysql"),
    (_re.compile(rb"postgresql",          _re.I), "postgresql"),
    (_re.compile(rb"SMB|SAMBA|\xffSMB",  _re.I), "smb"),
    (_re.compile(rb"220.*telnet|telnetd", _re.I), "telnet"),
    (_re.compile(rb"rdp|msts",            _re.I), "rdp"),
    (_re.compile(rb"elastic",             _re.I), "elasticsearch"),
    (_re.compile(rb"memcache",            _re.I), "memcached"),
]

# Service-name → risk level (port-agnostic: SSH on port 2000 = "high")
_SERVICE_RISK = {
    "ssh":           "high",
    "telnet":        "critical",
    "ftp":           "critical",
    "smb":           "critical",
    "rdp":           "critical",
    "vnc":           "critical",
    "mongodb":       "critical",
    "redis":         "critical",
    "elasticsearch": "critical",
    "memcached":     "critical",
    "mysql":         "high",
    "postgresql":    "high",
    "mssql":         "high",
    "smtp":          "high",
    "http":          "high",
    "tls/ssl":       "medium",
    "pop3":          "medium",
    "imap":          "medium",
    "dns":           "medium",
    "snmp":          "medium",
    "ntp":           "low",
}


# ─── TCP banner grab ──────────────────────────────────────────────────────────
def grab_banner(host, port, timeout=1.0):
    """
    Connect to an open TCP port and read its greeting banner using a
    3-step strategy so services on non-standard ports are still identified:
      1. Passive wait  → SSH / FTP / SMTP / VNC / Redis speak first
      2. HTTP probe    → web servers on any port respond to HEAD /
      3. CRLF nudge   → MySQL, custom daemons, etc.
    Returns (raw_bytes, decoded_string).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            raw = b""

            # Step 1: passive read
            s.settimeout(timeout / 2)
            try:
                raw = s.recv(1024)
            except Exception:
                pass
            # Step 2: HTTP probe
            if not raw:
                try:
                    probe = b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n"
                    s.settimeout(timeout)
                    s.sendall(probe)
                    s.settimeout(timeout / 2)
                    raw = s.recv(1024)
                except Exception:
                    pass

            # Step 3: CRLF nudge
            if not raw:
                try:
                    s.settimeout(timeout)
                    s.sendall(b"\r\n")
                    s.settimeout(timeout / 2)
                    raw = s.recv(1024)
                except Exception:
                    pass
        return raw, raw.decode("utf-8", errors="replace").strip()
    except Exception:
        return b"", ""


def detect_service(port, banner_bytes, banner_str):
    """
    Identify the real TCP service purely from the live connection:
      1. Banner regex  — port-agnostic, detects SSH on 2000, HTTP on 9999, etc.
      2. OS services db — socket.getservbyport() reads /etc/services or Windows registry.
      3. "unknown"     — if neither method works; no static guessing by port number.
    Returns (service_name, banner_snippet).
    """
    snippet = banner_str[:120].replace("\n", " ").replace("\r", "").strip()

    # 1. Pattern-match the live banner (port-agnostic)
    for pattern, name in _BANNER_PATTERNS:
        if pattern.search(banner_bytes):
            return name, snippet

    # 2. OS-level service database (covers ~300 well-known ports)
    try:
        name = socket.getservbyport(port, "tcp")
        return name, snippet
    except Exception:
        pass

    # 3. Nothing matched — report honestly
    return "unknown", snippet


def classify_risk(service: str) -> str:
    """Return risk level for a detected service name. Unknown service = low."""
    return _SERVICE_RISK.get(service, "low") if service else "low"


# ─── Phase 1: TCP connect check (no banner) ───────────────────────────────────
def _tcp_connect(host: str, port: int, timeout: float) -> dict:
    """
    Stage 1 of the two-phase TCP scan.
    Returns open, closed (connection refused), or filtered/unconfirmed.
    Banner grabbing happens in stage 2 for open ports only.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
    except OSError as exc:
        result = exc.errno or getattr(exc, "winerror", None) or -1

    return {
        "port":    port,
        "proto":   "tcp",
        "status":  "open" if result == 0 else
                  "closed" if result in (errno.ECONNREFUSED, 10061) else "filtered",
    }


# ─── Phase 2: deep scan of a confirmed-open TCP port ─────────────────────────
def _tcp_deep_scan(host: str, port: int, timeout: float) -> dict:
    """
    Stage 2 — only runs for ports confirmed open in stage 1 and grabs a banner.
    """
    banner_bytes, banner_str = grab_banner(host, port, max(timeout, 1.0))

    service, banner_snippet = detect_service(port, banner_bytes, banner_str)
    risk = classify_risk(service)

    return {
        "port":    port,
        "proto":   "tcp",
        "status":  "open",
        "service": service,
        "banner":  banner_snippet,
        "risk":    risk,
        "exposed": None,
    }


def scan_port(host: str, port: int, timeout: float = 0.5) -> dict:
    """
    Full two-phase TCP scan; a refused connection is closed and other
    unsuccessful connection attempts are reported as filtered/unconfirmed.
    """
    probe = _tcp_connect(host, port, timeout)
    if probe["status"] != "open":
        return {
            "port":    port,
            "proto":   "tcp",
            "status":  probe["status"],
            "service": "-",
            "banner":  "",
            "risk":    "none",
            "exposed": None,
        }
    return _tcp_deep_scan(host, port, timeout)


# ─── UDP scan (single-phase local probe) ──────────────────────────────────────
def scan_udp_port(host: str, port: int, timeout: float = 1.5) -> dict:
    """
    UDP scan using ICMP port-unreachable as a closed signal.
    Sends a port-specific probe. Internet exposure is not measured locally.
    Status:
      'open'          — received a valid UDP response
      'open|filtered' — no response (could be open or silently filtered by firewall)
      'closed'        — received ICMP port-unreachable (Windows: ConnectionResetError)
    """
    probe = UDP_PROBES.get(port, b"\x00" * 4)
    banner_snippet = ""
    status = "open|filtered"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(probe, (host, port))
            try:
                data, _ = s.recvfrom(1024)
                status = "open"
                banner_snippet = data[:120].decode("utf-8", errors="replace").strip()
                banner_snippet = banner_snippet.replace("\n", " ").replace("\r", "")
            except socket.timeout:
                status = "open|filtered"
            except ConnectionResetError:
                status = "closed"
    except Exception:
        status = "open|filtered"

    # Service name from OS database — no static fallback map
    try:
        service_name = socket.getservbyport(port, "udp")
    except Exception:
        service_name = "unknown"

    is_accessible = status in ("open", "open|filtered")
    risk    = classify_risk(service_name) if is_accessible else "none"
    return {
        "port":    port,
        "proto":   "udp",
        "status":  status,
        "service": service_name,
        "banner":  banner_snippet,
        "risk":    risk,
        "exposed": None,
    }


# ─── Auth helpers ──────────────────────────────────────────────────────────────
def hash_pw(pw):
    return generate_password_hash(pw, method="scrypt")


def verify_password(stored_hash, password):
    if stored_hash.startswith(("scrypt:", "pbkdf2:")):
        return check_password_hash(stored_hash, password), False
    legacy_hash = hashlib.sha256(password.encode()).hexdigest()
    return secrets.compare_digest(stored_hash, legacy_hash), True

def create_token():
    return secrets.token_hex(32)

def token_key(token):
    return hashlib.sha256(token.encode()).hexdigest()

def _session_is_current(expiry, now=None):
    try:
        parsed = datetime.fromisoformat(expiry)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed > (now or utcnow())
    except (TypeError, ValueError):
        return False

def verify_token(token):
    if not isinstance(token, str) or not token:
        return None
    key = token_key(token)
    with data_transaction():
        sessions = load_json(SESSIONS_FILE, {})
        session_id = key if key in sessions else token
        entry = sessions.get(session_id)
        if not entry:
            return None
        try:
            expires = datetime.fromisoformat(entry["expires"])
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
        except (KeyError, TypeError, ValueError):
            app.logger.warning("Removing malformed session record")
            sessions.pop(session_id, None)
            save_json(SESSIONS_FILE, sessions)
            return None
        if expires < utcnow():
            sessions.pop(session_id, None)
            save_json(SESSIONS_FILE, sessions)
            return None
        username = entry.get("username")
        if not isinstance(username, str) or not username:
            sessions.pop(session_id, None)
            save_json(SESSIONS_FILE, sessions)
            return None
        if session_id == token:
            sessions.pop(token, None)
            sessions[key] = entry
            save_json(SESSIONS_FILE, sessions)
        return username


def json_body():
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else None


def allowed_target_networks():
    raw = os.environ.get("PORTMONITOR_ALLOWED_TARGETS", "").strip()
    if not raw:
        return []
    try:
        networks = [
            ipaddress.ip_network(value.strip(), strict=False)
            for value in raw.split(",") if value.strip()
        ]
    except ValueError as exc:
        raise RuntimeError(
            "PORTMONITOR_ALLOWED_TARGETS must contain valid IPv4 addresses or CIDRs"
        ) from exc
    if not networks or any(network.version != 4 for network in networks):
        raise RuntimeError(
            "PORTMONITOR_ALLOWED_TARGETS must contain valid IPv4 addresses or CIDRs"
        )
    return networks


def validate_host(host):
    if not isinstance(host, str):
        raise ValueError("host must be a hostname or IPv4 address")
    host = host.strip()
    if not host or len(host) > 253 or any(char.isspace() for char in host):
        raise ValueError("enter a valid hostname or IPv4 address")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.version != 4:
            raise ValueError("IPv6 targets are not supported")
        resolved = {ip}
    else:
        labels = host.rstrip(".").split(".")
        if not all(
            label and len(label) <= 63 and
            _re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
            for label in labels
        ):
            raise ValueError("enter a valid hostname or IPv4 address")
        try:
            resolved = {
                ipaddress.ip_address(result[4][0])
                for result in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
            }
        except socket.gaierror as exc:
            raise ValueError("hostname could not be resolved to IPv4") from exc
    networks = allowed_target_networks()
    if networks:
        if any(not any(address in network for network in networks) for address in resolved):
            raise ValueError("target is not in PORTMONITOR_ALLOWED_TARGETS")
    return host


def resolve_target(host):
    validate_host(host)
    try:
        address = ipaddress.ip_address(host)
        return str(address)
    except ValueError:
        pass
    try:
        addresses = {
            ipaddress.ip_address(result[4][0])
            for result in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        }
    except socket.gaierror as exc:
        raise ValueError("hostname could not be resolved to IPv4") from exc
    networks = allowed_target_networks()
    if networks and any(not any(address in network for network in networks) for address in addresses):
        raise ValueError("target is not in PORTMONITOR_ALLOWED_TARGETS")
    if not addresses:
        raise ValueError("hostname could not be resolved to IPv4")
    return str(sorted(addresses)[0])


def _allow_login_attempt(remote_addr):
    now = time.monotonic()
    with _LOGIN_LOCK:
        attempts = _LOGIN_ATTEMPTS[remote_addr]
        while attempts and now - attempts[0] >= _LOGIN_WINDOW_SECONDS:
            attempts.popleft()
        if len(attempts) >= _LOGIN_ATTEMPT_LIMIT:
            return False, max(1, int(_LOGIN_WINDOW_SECONDS - (now - attempts[0])))
        return True, 0


def _record_login_failure(remote_addr):
    with _LOGIN_LOCK:
        _LOGIN_ATTEMPTS[remote_addr].append(time.monotonic())


def _clear_login_failures(remote_addr):
    with _LOGIN_LOCK:
        _LOGIN_ATTEMPTS.pop(remote_addr, None)


def validate_scan_config(payload, proto):
    if not isinstance(payload, dict):
        raise ValueError("scan configuration must be a JSON object")
    host = validate_host(payload.get("host", "127.0.0.1"))

    def integer_setting(name, default):
        value = payload.get(name, default)
        if isinstance(value, bool):
            raise ValueError(f"{name} must be a whole number")
        if isinstance(value, int):
            return value
        if isinstance(value, str) and _re.fullmatch(r"\d+", value.strip()):
            return int(value)
        raise ValueError(f"{name} must be a whole number")

    try:
        start = integer_setting("start", 1)
        end = integer_setting("end", 1024)
        timeout_value = payload.get("timeout", 0.7 if proto == "tcp" else 1.5)
        if isinstance(timeout_value, bool):
            raise ValueError("timeout must be a number")
        timeout = float(timeout_value)
        batch = integer_setting("batch", 500 if proto == "tcp" else 100)
    except (TypeError, OverflowError) as exc:
        raise ValueError("scan settings must be valid numbers") from exc
    if not 1 <= start <= end <= 65535:
        raise ValueError("port range must satisfy 1 <= start <= end <= 65535")
    if not 0.1 <= timeout <= 3.0:
        raise ValueError("timeout must be between 0.1 and 3 seconds")
    if not 1 <= batch <= 500:
        raise ValueError("batch size must be between 1 and 500")
    return host, start, end, timeout, batch

def require_auth(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.headers.get("X-Token")
        user = verify_token(token) if token else None
        if not user:
            return jsonify({"error": "unauthorized"}), 401
        request.username = user
        return fn(*args, **kwargs)
    return wrapper

# ─── Local host info ──────────────────────────────────────────────────────────
@app.route("/api/local-host")
@require_auth
def local_host():
    """Return the hostname, best local IP, and OS info of this server."""
    import platform
    hostname = socket.gethostname()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"
    # For the local machine we read the OS directly — no banner probing needed
    os_name    = platform.system()                         # "Windows", "Linux", "Darwin"
    os_version = platform.version()                        # full build string
    os_release = platform.release()                        # "10", "22.04", etc.
    if os_name == "Darwin":
        os_name = "macOS"
    version_str = os_release if os_release else os_version
    return jsonify({"hostname": hostname, "ip": local_ip,
                    "os": os_name, "version": version_str})

# ─── Auth routes ──────────────────────────────────────────────────────────────
@app.route("/api/register", methods=["POST"])
def register():
    body = json_body()
    if body is None:
        return jsonify({"error": "a JSON object is required"}), 400
    username = body.get("username")
    password = body.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"error": "username and password are required"}), 400
    username = username.strip()
    if not _re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
        return jsonify({"error": "username must be 3-32 letters, numbers, dots, underscores, or hyphens"}), 400
    if len(password) < 12 or len(password) > 128:
        return jsonify({"error": "password must be between 12 and 128 characters"}), 400
    password_hash = hash_pw(password)
    with data_transaction():
        users = load_json(USERS_FILE, {})
        if username in users:
            return jsonify({"error": "username already taken"}), 409
        users[username] = {"password": password_hash, "created": utcnow().isoformat()}
        save_json(USERS_FILE, users)
    return jsonify({"ok": True})

@app.route("/api/login", methods=["POST"])
def login():
    body = json_body()
    if body is None:
        return jsonify({"error": "a JSON object is required"}), 400
    username = body.get("username")
    password = body.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"error": "invalid credentials"}), 401
    remote_addr = request.remote_addr or "unknown"
    allowed, retry_after = _allow_login_attempt(remote_addr)
    if not allowed:
        response = jsonify({"error": "too many sign-in attempts; try again later"})
        response.status_code = 429
        response.headers["Retry-After"] = str(retry_after)
        return response
    username = username.strip()
    with data_transaction():
        users = load_json(USERS_FILE, {})
        user = users.get(username)
        if not isinstance(user, dict) or not isinstance(user.get("password"), str):
            _record_login_failure(remote_addr)
            return jsonify({"error": "invalid credentials"}), 401
        valid, legacy = verify_password(user["password"], password)
        if not valid:
            _record_login_failure(remote_addr)
            return jsonify({"error": "invalid credentials"}), 401
        _clear_login_failures(remote_addr)
        if legacy:
            user["password"] = hash_pw(password)
            save_json(USERS_FILE, users)
        token = create_token()
        sessions = load_json(SESSIONS_FILE, {})
        now = utcnow()
        sessions = {
            key: value for key, value in sessions.items()
            if isinstance(value, dict) and value.get("expires")
            and _session_is_current(value["expires"], now)
        }
        sessions[token_key(token)] = {
            "username": username,
            "expires": (now + timedelta(hours=24)).isoformat()
        }
        save_json(SESSIONS_FILE, sessions)
    return jsonify({"token": token, "username": username})

@app.route("/api/logout", methods=["POST"])
@require_auth
def logout():
    token = request.headers.get("X-Token")
    with data_transaction():
        sessions = load_json(SESSIONS_FILE, {})
        sessions.pop(token_key(token), None)
        sessions.pop(token, None)
        save_json(SESSIONS_FILE, sessions)
    return jsonify({"ok": True})

# ─── Machines routes ───────────────────────────────────────────────────────────
@app.route("/api/machines", methods=["GET"])
@require_auth
def get_machines():
    all_machines = load_json(MACHINES_FILE, {})
    user_machines = all_machines.get(request.username, [])
    return jsonify(user_machines)

@app.route("/api/machines", methods=["POST"])
@require_auth
def add_machine():
    body = json_body()
    if body is None:
        return jsonify({"error": "a JSON object is required"}), 400
    name = body.get("name")
    host = body.get("host")
    if not isinstance(name, str) or not isinstance(host, str):
        return jsonify({"error": "name and host are required"}), 400
    name = name.strip()
    try:
        host = validate_host(host)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if not name or len(name) > 80:
        return jsonify({"error": "name must be 1-80 characters"}), 400
    with data_transaction():
        all_machines = load_json(MACHINES_FILE, {})
        user_machines = all_machines.get(request.username, [])
        machine_id = secrets.token_hex(8)
        user_machines.append({
            "id": machine_id,
            "name": name,
            "host": host,
            "added": utcnow().isoformat(),
            "last_scan": None,
        })
        all_machines[request.username] = user_machines
        save_json(MACHINES_FILE, all_machines)
    return jsonify({"id": machine_id, "ok": True})

@app.route("/api/machines/<machine_id>", methods=["DELETE"])
@require_auth
def delete_machine(machine_id):
    with data_transaction():
        all_machines = load_json(MACHINES_FILE, {})
        user_machines = all_machines.get(request.username, [])
        all_machines[request.username] = [m for m in user_machines if m["id"] != machine_id]
        save_json(MACHINES_FILE, all_machines)
    return jsonify({"ok": True})

# ─── OS detect endpoint ───────────────────────────────────────────────────────
@app.route("/api/os-detect")
@require_auth
def os_detect():
    """Fingerprint the OS of an arbitrary host."""
    try:
        host = resolve_target(request.args.get("host", ""))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    result = detect_os(host)
    return jsonify(result)

# ─── Shared: run one full scan pass, streaming batches over ws ────────────────
def _run_scan_pass(ws, ports, scan_fn, batch, workers, cycle):
    """
    Scan every port in `ports` using `scan_fn`, send results in batches.
    Returns list of all results, or raises on WebSocket error.
    `cycle` is the 1-based pass number (sent to the client for display).
    """
    total   = len(ports)
    scanned = 0
    all_results = []

    for i in range(0, total, batch):
        chunk = ports[i:i + batch]
        results = []
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(scan_fn, _ws_host[ws], p, _ws_timeout[ws]): p for p in chunk}
            for fut in as_completed(futures):
                results.append(fut.result())
        results.sort(key=lambda x: x["port"])
        scanned += len(results)
        all_results.extend(results)
        ws.send(json.dumps({
            "type":    "batch",
            "results": results,
            "scanned": scanned,
            "total":   total,
            "cycle":   cycle,
        }))

    return all_results

# Per-ws metadata (host and timeout) stored so _run_scan_pass can access them
_ws_host    = {}
_ws_timeout = {}

# ─── WebSocket continuous TCP monitor ─────────────────────────────────────────
@sock.route("/ws/scan")
def ws_scan(ws):
    try:
        init = json.loads(ws.receive(timeout=10))
    except Exception:
        ws.close()
        return

    if not isinstance(init, dict):
        ws.send(json.dumps({"type": "error", "error": "scan configuration must be a JSON object"}))
        ws.close()
        return
    token = init.get("token")
    user  = verify_token(token)
    if not user:
        ws.send(json.dumps({"error": "unauthorized"}))
        ws.close()
        return

    try:
        requested_host, start, end, timeout, batch = validate_scan_config(init, "tcp")
        host = resolve_target(requested_host)
    except ValueError as exc:
        ws.send(json.dumps({"type": "error", "error": str(exc)}))
        ws.close()
        return

    _ws_host[ws]    = host
    _ws_timeout[ws] = timeout

    ports = list(range(start, min(end + 1, 65536)))
    total = len(ports)

    ws.send(json.dumps({"type": "start", "total": total, "host": host, "proto": "tcp"}))

    cycle = 0
    try:
        while True:
            cycle += 1
            ws.send(json.dumps({"type": "cycle_start", "cycle": cycle, "total": total, "proto": "tcp"}))
            _run_scan_pass(ws, ports, scan_port, batch, 250, cycle)

            # Update last_scan timestamp after every full pass
            with data_transaction():
                all_machines = load_json(MACHINES_FILE, {})
                user_machines = all_machines.get(user, [])
                for m in user_machines:
                    if m["host"] == requested_host:
                        m["last_scan"] = utcnow().isoformat()
                all_machines[user] = user_machines
                save_json(MACHINES_FILE, all_machines)

            ws.send(json.dumps({"type": "cycle_done", "cycle": cycle, "total": total, "proto": "tcp",
                                "timestamp": utcnow().isoformat(),
                                "last_refreshed": time.strftime("%H:%M:%S")}))
    except (ConnectionError, OSError):
        # WebSocket closed by client — clean up and exit silently
        pass
    finally:
        _ws_host.pop(ws, None)
        _ws_timeout.pop(ws, None)


# ─── WebSocket continuous UDP monitor ─────────────────────────────────────────
@sock.route("/ws/scan_udp")
def ws_scan_udp(ws):
    try:
        init = json.loads(ws.receive(timeout=10))
    except Exception:
        ws.close()
        return

    if not isinstance(init, dict):
        ws.send(json.dumps({"type": "error", "error": "scan configuration must be a JSON object"}))
        ws.close()
        return
    token = init.get("token")
    user  = verify_token(token)
    if not user:
        ws.send(json.dumps({"error": "unauthorized"}))
        ws.close()
        return

    try:
        requested_host, start, end, timeout, batch = validate_scan_config(init, "udp")
        host = resolve_target(requested_host)
    except ValueError as exc:
        ws.send(json.dumps({"type": "error", "error": str(exc)}))
        ws.close()
        return
    ports = list(range(start, end + 1))

    _ws_host[ws]    = host
    _ws_timeout[ws] = timeout

    total = len(ports)

    ws.send(json.dumps({"type": "start", "total": total, "host": host, "proto": "udp"}))

    cycle = 0
    try:
        while True:
            cycle += 1
            ws.send(json.dumps({"type": "cycle_start", "cycle": cycle, "total": total, "proto": "udp"}))
            _run_scan_pass(ws, ports, scan_udp_port, batch, 50, cycle)
            ws.send(json.dumps({"type": "cycle_done", "cycle": cycle, "total": total, "proto": "udp",
                                "timestamp": utcnow().isoformat(),
                                "last_refreshed": time.strftime("%H:%M:%S")}))
    except (ConnectionError, OSError):
        pass
    finally:
        _ws_host.pop(ws, None)
        _ws_timeout.pop(ws, None)


# ─── Serve SPA ────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory("public", "index.html")

# ─── CLI mode ─────────────────────────────────────────────────────────────────
def cli_mode():
    import argparse, sys
    parser = argparse.ArgumentParser(description="PortMonitor CLI")
    parser.add_argument("host", nargs="?", default="127.0.0.1", help="Target host (authorized systems only)")
    parser.add_argument("--start", type=int, default=1)
    parser.add_argument("--end", type=int, default=1024)
    parser.add_argument("--timeout", type=float, default=0.5)
    parser.add_argument("--workers", type=int, default=100)
    parser.add_argument("--filter", choices=["all","open","closed","filtered","critical"], default="open")
    parser.add_argument("--udp", action="store_true", help="Scan UDP instead of TCP")
    args = parser.parse_args()

    try:
        host = resolve_target(args.host)
    except ValueError as exc:
        parser.error(str(exc))
    if not 1 <= args.start <= args.end <= 65535:
        parser.error("port range must satisfy 1 <= start <= end <= 65535")
    if not 0.1 <= args.timeout <= 3:
        parser.error("timeout must be between 0.1 and 3 seconds")
    if not 1 <= args.workers <= 300:
        parser.error("workers must be between 1 and 300")
    ports = list(range(args.start, args.end + 1))
    total = len(ports)

    RESET="\033[0m"; BOLD="\033[1m"; RED="\033[91m"; GRN="\033[92m"
    YEL="\033[93m"; CYN="\033[96m"; DIM="\033[2m"; MAG="\033[95m"

    proto = "UDP" if args.udp else "TCP"
    print(f"\n{BOLD}{CYN}+==================================================+")
    print(f"|   PortMonitor CLI  -  {host:<20} {proto}  |")
    print(f"+==================================================+{RESET}")
    print(f"{DIM}Scanning ports {args.start}-{args.end}  ({total} ports)  workers={args.workers}{RESET}\n")

    results = []
    done = [0]

    def progress_cb(r):
        done[0] += 1
        pct = done[0] * 100 // total
        bar = "#" * (pct // 5) + "." * (20 - pct // 5)
        print(f"\r  {CYN}[{bar}]{RESET} {pct:3d}%  {done[0]}/{total}", end="", flush=True)

    scan_fn = scan_udp_port if args.udp else scan_port
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(scan_fn, host, p, args.timeout): p for p in ports}
        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)
            progress_cb(r)

    print()
    results.sort(key=lambda x: x["port"])

    open_ports     = [r for r in results if r["status"] == "open"]
    filtered_ports = [r for r in results if r["status"] in ("filtered", "open|filtered")]
    closed_ports   = [r for r in results if r["status"] == "closed"]
    critical_ports = [
        r for r in results
        if r["status"] in ("open", "open|filtered") and r["risk"] == "critical"
    ]

    print(f"\n{BOLD}  Summary ({proto}){RESET}")
    print(f"  {'Scanned':<16}: {total}")
    print(f"  {GRN}{'Open':<16}{RESET}: {len(open_ports)}")
    print(f"  {YEL}{'Open|Filtered':<16}{RESET}: {len(filtered_ports)}")
    print(f"  {DIM}{'Closed':<16}{RESET}: {len(closed_ports)}")
    print(f"  {'Exposure':<16}: not measured")
    print(f"  {RED}{'Critical':<16}{RESET}: {len(critical_ports)}")

    RISK_COLOR = {"critical": RED, "high": YEL, "medium": MAG, "low": GRN, "none": DIM}

    if args.filter == "all":       show = results
    elif args.filter == "open":    show = open_ports
    elif args.filter == "closed":  show = closed_ports
    elif args.filter == "filtered":show = filtered_ports
    elif args.filter == "critical":show = critical_ports

    if show:
        print(f"\n{BOLD}  {'PORT':<8} {'PROTO':<6} {'STATUS':<16} {'SERVICE':<20} {'RISK':<12} {'EXPOSURE'}{RESET}")
        print("  " + "─"*72)
        for r in show:
            rc = RISK_COLOR.get(r["risk"], RESET)
            sc = GRN if r["status"] == "open" else (YEL if "filtered" in r["status"] else DIM)
            print(f"  {r['port']:<8} {r['proto']:<6} {sc}{r['status']:<16}{RESET} {r['service']:<20} {rc}{r['risk']:<12}{RESET} not measured")
    print()

if __name__ == "__main__":
    import sys
    if "--cli" in sys.argv:
        sys.argv.remove("--cli")
        cli_mode()
    else:
        host = os.environ.get("PORTMONITOR_HOST", "127.0.0.1")
        port = int(os.environ.get("PORTMONITOR_PORT", "5000"))
        is_loopback = host.lower() == "localhost"
        try:
            is_loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            pass
            allowed_target_networks()
            if not is_loopback and not os.environ.get("PORTMONITOR_ALLOWED_TARGETS", "").strip():
                raise SystemExit(
                    "Non-loopback binding requires PORTMONITOR_ALLOWED_TARGETS (IPv4 addresses/CIDRs). "
                    "Use a TLS reverse proxy for remote browser access."
                )
            print(f"  PortMonitor starting -> http://{host}:{port}")
        app.run(host=host, port=port, debug=False)
