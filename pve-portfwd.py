#!/usr/bin/env python3
"""
pve-portfwd - tiny web UI to forward ports from a Proxmox host to its guests.

Zero dependencies: Python 3 standard library + iptables (both ship with Proxmox VE).

Rules live in their own iptables chains (PORTFWD_PRE / PORTFWD_POST / PORTFWD_FWD)
and are swapped atomically with iptables-restore, so nothing else on the host
(pve-firewall, your own rules) is touched.

Usage:
  pve-portfwd.py [serve]        run the web UI (default)
  pve-portfwd.py apply          (re)apply saved rules and exit
  pve-portfwd.py flush          remove all forwarding rules + chains
  pve-portfwd.py passwd         set a local password (instead of Proxmox login)
  pve-portfwd.py --dry-run ...  print iptables commands instead of running them
"""
import argparse
import base64
import getpass
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.0.0"
CONF_DIR = os.environ.get("PORTFWD_DIR", "/etc/pve-portfwd")
CH_PRE, CH_POST, CH_FWD = "PORTFWD_PRE", "PORTFWD_POST", "PORTFWD_FWD"
JUMPS = (("nat", "PREROUTING", CH_PRE), ("nat", "POSTROUTING", CH_POST), ("filter", "FORWARD", CH_FWD))

DEFAULTS = {
    "listen": "0.0.0.0",
    "port": 8099,
    # Proxmox accounts allowed to log in (checked against the local PVE API).
    "allowed_users": ["root@pam"],
    # If set (via `passwd`), use a local password instead of Proxmox login.
    "local_user": "admin",
    "pass_hash": "",
    # Empty = reuse the Proxmox web certificate automatically.
    "cert": "",
    "key": "",
    # Ports that may never be forwarded away from the host (SSH, PVE UI, spice, rpcbind, corosync).
    "protected_ports": ["22", "8006", "3128", "111", "5405-5412"],
    # Add ACCEPT rules in FORWARD for forwarded traffic (needed if FORWARD policy is DROP).
    "forward_accept": True,
    "rules": [],
}

LOCK = threading.RLock()
STATE = {"cfg": None, "last_apply": None, "last_error": None}
SESSIONS = {}  # token -> [user, expires]
FAILS = {}     # ip -> [count, first_ts]
SESSION_TTL = 8 * 3600
DRY_RUN = False


class ApiError(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.code = code


# --------------------------------------------------------------------------- config

def conf_file():
    return os.path.join(CONF_DIR, "config.json")


def load_config():
    cfg = json.loads(json.dumps(DEFAULTS))
    try:
        with open(conf_file()) as f:
            cfg.update(json.load(f))
    except FileNotFoundError:
        pass
    rules = []
    for r in cfg.get("rules", []):
        try:
            rules.append(validate_rule(r, [], cfg, r.get("id")))
        except (ApiError, ValueError) as e:
            log("skipping invalid rule %r: %s" % (r.get("name") or r.get("id"), e))
    cfg["rules"] = rules
    return cfg


def save_config(cfg):
    os.makedirs(CONF_DIR, mode=0o700, exist_ok=True)
    tmp = conf_file() + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, conf_file())


def log(msg):
    sys.stderr.write("[pve-portfwd] %s\n" % msg)
    sys.stderr.flush()


# --------------------------------------------------------------------------- validation

NAME_RE = re.compile(r"^[A-Za-z0-9 _.:/@+-]{0,40}$")
PORT_RE = re.compile(r"^(\d{1,5})(?:[-:](\d{1,5}))?$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")


def parse_ports(s):
    m = PORT_RE.match(str(s).strip())
    if not m:
        raise ApiError("invalid port '%s' (use 8080 or 8000-8010)" % s)
    a, b = int(m.group(1)), int(m.group(2) or m.group(1))
    if not 1 <= a <= b <= 65535:
        raise ApiError("port out of range: %s" % s)
    return a, b


def protos(p):
    return ["tcp", "udp"] if p == "both" else [p]


def validate_rule(data, others, cfg, rid=None):
    if not isinstance(data, dict):
        raise ApiError("rule must be an object")
    r = {"id": rid or uuid.uuid4().hex[:8]}
    if not re.match(r"^[0-9a-f]{1,16}$", r["id"]):
        raise ApiError("invalid id")

    r["name"] = str(data.get("name", "")).strip()
    if not NAME_RE.match(r["name"]):
        raise ApiError("name: max 40 chars, letters/digits/space/_.:/@+- only")

    r["enabled"] = bool(data.get("enabled", True))
    r["proto"] = str(data.get("proto", "tcp")).lower()
    if r["proto"] not in ("tcp", "udp", "both"):
        raise ApiError("protocol must be tcp, udp or both")

    ea, eb = parse_ports(data.get("ext_port", ""))
    r["ext_port"] = str(ea) if ea == eb else "%d-%d" % (ea, eb)

    try:
        ip = ipaddress.IPv4Address(str(data.get("ip", "")).strip())
    except ValueError:
        raise ApiError("destination must be an IPv4 address")
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified:
        raise ApiError("destination IP is not usable")
    r["ip"] = str(ip)

    ip_port = str(data.get("int_port", "") or "").strip()
    if ip_port:
        ia, ib = parse_ports(ip_port)
        if ia != ib:
            raise ApiError("destination port must be a single port (leave empty to keep the same ports)")
        if ea != eb:
            raise ApiError("for a port range leave the destination port empty (ports are kept as-is)")
        ip_port = str(ia)
    r["int_port"] = ip_port

    src = str(data.get("source", "") or "").strip()
    if src:
        try:
            src = str(ipaddress.IPv4Network(src, strict=False))
        except ValueError:
            raise ApiError("source must be an IPv4 address or CIDR, e.g. 203.0.113.0/24")
    r["source"] = src

    iface = str(data.get("iface", "") or "").strip()
    if iface and not IFACE_RE.match(iface):
        raise ApiError("invalid interface name")
    r["iface"] = iface
    r["masq"] = bool(data.get("masq", False))

    # never hijack ports the host itself needs
    for p in list(cfg.get("protected_ports", [])) + [str(cfg.get("port", 8099))]:
        pa, pb = parse_ports(p)
        if ea <= pb and pa <= eb:
            raise ApiError("external port %s overlaps protected host port %s" % (r["ext_port"], p))

    if r["enabled"]:
        for o in others:
            if not o["enabled"]:
                continue
            oa, ob = parse_ports(o["ext_port"])
            same_proto = set(protos(o["proto"])) & set(protos(r["proto"]))
            same_if = not o["iface"] or not r["iface"] or o["iface"] == r["iface"]
            same_src = not o["source"] or not r["source"] or o["source"] == r["source"]
            if same_proto and same_if and same_src and ea <= ob and oa <= eb:
                raise ApiError("port %s conflicts with rule '%s' (%s)" % (r["ext_port"], o["name"] or o["id"], o["ext_port"]))
    return r


# --------------------------------------------------------------------------- iptables

def run(cmd, data=None, check_only=False):
    if DRY_RUN:
        if not check_only:
            print("[dry-run] $ " + " ".join(cmd))
            if data:
                print(data)
        return 0, ""
    try:
        p = subprocess.run(cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           universal_newlines=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, str(e)
    return p.returncode, (p.stdout if p.returncode == 0 else (p.stderr or p.stdout)).strip()


def build_ruleset(cfg):
    nat = ["*nat", ":%s - [0:0]" % CH_PRE, ":%s - [0:0]" % CH_POST]
    flt = ["*filter", ":%s - [0:0]" % CH_FWD]
    for r in cfg["rules"]:
        if not r["enabled"]:
            continue
        ea, eb = parse_ports(r["ext_port"])
        dport = str(ea) if ea == eb else "%d:%d" % (ea, eb)
        to = "%s:%s" % (r["ip"], r["int_port"]) if r["int_port"] else r["ip"]
        iport = r["int_port"] or dport
        cm = '-m comment --comment "pf:%s"' % r["id"]
        for p in protos(r["proto"]):
            pre = "-A %s -p %s" % (CH_PRE, p)
            if r["iface"]:
                pre += " -i " + r["iface"]
            if r["source"]:
                pre += " -s " + r["source"]
            # only traffic addressed to the host itself - never hijack guests' outbound traffic
            pre += " -m addrtype --dst-type LOCAL -m %s --dport %s %s -j DNAT --to-destination %s" % (p, dport, cm, to)
            nat.append(pre)
            if r["masq"]:
                nat.append("-A %s -d %s/32 -p %s -m %s --dport %s -m conntrack --ctstate DNAT %s -j MASQUERADE"
                           % (CH_POST, r["ip"], p, p, iport, cm))
            if cfg.get("forward_accept", True):
                flt.append("-A %s -d %s/32 -p %s -m %s --dport %s -m conntrack --ctstate DNAT %s -j ACCEPT"
                           % (CH_FWD, r["ip"], p, p, iport, cm))
                flt.append("-A %s -s %s/32 -p %s -m %s --sport %s -m conntrack --ctstate DNAT %s -j ACCEPT"
                           % (CH_FWD, r["ip"], p, p, iport, cm))
    return "\n".join(nat + ["COMMIT"] + flt + ["COMMIT"]) + "\n"


def ensure_ip_forward():
    path = "/proc/sys/net/ipv4/ip_forward"
    if DRY_RUN or not os.path.exists(path):
        return
    with open(path) as f:
        if f.read().strip() == "1":
            return
    with open(path, "w") as f:
        f.write("1")
    log("enabled net.ipv4.ip_forward")


def apply_rules(cfg=None):
    """Atomically replace our chains. Returns error string or None."""
    with LOCK:
        cfg = cfg or STATE["cfg"]
        rc, out = run(["iptables-restore", "--noflush"], build_ruleset(cfg))
        if rc != 0:
            STATE["last_error"] = "iptables-restore failed: " + out
            return STATE["last_error"]
        for table, chain, target in JUMPS:
            if run(["iptables", "-t", table, "-C", chain, "-j", target], check_only=True)[0] != 0:
                rc, out = run(["iptables", "-t", table, "-I", chain, "1", "-j", target])
                if rc != 0:
                    STATE["last_error"] = "cannot hook %s/%s: %s" % (table, chain, out)
                    return STATE["last_error"]
        try:
            ensure_ip_forward()
        except OSError as e:
            STATE["last_error"] = "cannot enable ip_forward: %s" % e
            return STATE["last_error"]
        STATE["last_apply"] = time.time()
        STATE["last_error"] = None
        return None


def flush_rules():
    for table, chain, target in JUMPS:
        while run(["iptables", "-t", table, "-D", chain, "-j", target])[0] == 0 and not DRY_RUN:
            pass
        run(["iptables", "-t", table, "-F", target])
        run(["iptables", "-t", table, "-X", target])


def hooks_active():
    return all(run(["iptables", "-t", t, "-C", c, "-j", tg], check_only=True)[0] == 0 for t, c, tg in JUMPS)


def counters():
    res = {}
    if DRY_RUN:
        return res
    rc, out = run(["iptables-save", "-c", "-t", "nat"])
    if rc != 0:
        return res
    for line in out.splitlines():
        m = re.match(r"^\[(\d+):(\d+)\] -A %s .*pf:([0-9a-f]+)" % CH_PRE, line)
        if m:
            c = res.setdefault(m.group(3), [0, 0])
            c[0] += int(m.group(1))
            c[1] += int(m.group(2))
    return res


def ip_forward_on():
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            return f.read().strip() == "1"
    except OSError:
        return DRY_RUN


def watchdog():
    """Re-hook our chains if something (iptables -F, network restart) removed them."""
    while True:
        time.sleep(30)
        try:
            if not DRY_RUN and not hooks_active():
                log("hooks missing, re-applying rules")
                err = apply_rules()
                if err:
                    log(err)
        except Exception as e:
            log("watchdog: %s" % e)


# --------------------------------------------------------------------------- guests / interfaces

GUEST_CACHE = {"t": 0, "data": []}


def list_ifaces():
    try:
        names = sorted(os.listdir("/sys/class/net"))
    except OSError:
        return ["vmbr0", "vmbr1"] if DRY_RUN else []
    skip = ("lo", "fwbr", "fwpr", "fwln", "tap", "veth", "docker")
    return [n for n in names if not n.startswith(skip)]


def _guest_ips(g):
    vmid = str(g["vmid"])
    ips = []
    if g["type"] == "lxc":
        if g.get("status") == "running":
            rc, out = run(["lxc-info", "-n", vmid, "-iH"], check_only=True)
            if rc == 0:
                ips = out.split()
        if not ips:
            rc, out = run(["pct", "config", vmid], check_only=True)
            if rc == 0:
                ips = re.findall(r"\bip=(\d+\.\d+\.\d+\.\d+)", out)
    elif g.get("status") == "running":
        rc, out = run(["timeout", "3", "qm", "guest", "cmd", vmid, "network-get-interfaces"], check_only=True)
        if rc == 0:
            try:
                for itf in json.loads(out):
                    for a in itf.get("ip-addresses", []):
                        if a.get("ip-address-type") == "ipv4":
                            ips.append(a["ip-address"])
            except (ValueError, KeyError, TypeError):
                pass
    return [i for i in ips if re.match(r"^\d+\.\d+\.\d+\.\d+$", i) and not i.startswith("127.")]


def list_guests():
    if DRY_RUN:
        return [{"vmid": 100, "name": "web", "type": "qemu", "status": "running", "ips": ["10.10.10.10"]},
                {"vmid": 101, "name": "db", "type": "lxc", "status": "running", "ips": ["10.10.10.11"]},
                {"vmid": 102, "name": "game", "type": "qemu", "status": "stopped", "ips": []}]
    if time.time() - GUEST_CACHE["t"] < 30:
        return GUEST_CACHE["data"]
    rc, out = run(["pvesh", "get", "/cluster/resources", "--type", "vm", "--output-format", "json"], check_only=True)
    if rc != 0:
        return []
    node = socket.gethostname().split(".")[0]
    try:
        items = [g for g in json.loads(out) if g.get("node") == node and not g.get("template")]
    except ValueError:
        return []
    with ThreadPoolExecutor(8) as ex:
        ips = list(ex.map(_guest_ips, items))
    data = sorted(({"vmid": g["vmid"], "name": g.get("name", ""), "type": g["type"],
                    "status": g.get("status", ""), "ips": i} for g, i in zip(items, ips)),
                  key=lambda x: x["vmid"])
    GUEST_CACHE.update(t=time.time(), data=data)
    return data


# --------------------------------------------------------------------------- auth

def hash_password(pw, iters=200000):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iters)
    return "pbkdf2_sha256$%d$%s$%s" % (iters, base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def check_password(pw, stored):
    try:
        _, iters, salt, dk = stored.split("$")
        calc = hashlib.pbkdf2_hmac("sha256", pw.encode(), base64.b64decode(salt), int(iters))
        return hmac.compare_digest(calc, base64.b64decode(dk))
    except (ValueError, TypeError):
        return False


def pve_login(user, pw):
    """Validate credentials against the local Proxmox API. Returns canonical user or None."""
    if "@" not in user:
        user += "@pam"
    body = urllib.parse.urlencode({"username": user, "password": pw}).encode()
    ctx = ssl._create_unverified_context()  # localhost only
    try:
        with urllib.request.urlopen("https://127.0.0.1:8006/api2/json/access/ticket", body,
                                    timeout=10, context=ctx) as resp:
            d = json.load(resp).get("data") or {}
    except Exception:
        return None
    if not d.get("ticket") or d.get("NeedTFA"):
        return None
    return d.get("username")


def authenticate(user, pw):
    cfg = STATE["cfg"]
    if cfg.get("pass_hash"):
        ok = hmac.compare_digest(user, cfg.get("local_user", "admin")) and check_password(pw, cfg["pass_hash"])
        return user if ok else None
    u = pve_login(user, pw)
    return u if u and u in cfg.get("allowed_users", []) else None


# --------------------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "pve-portfwd/" + VERSION
    sys_version = ""
    timeout = 30

    def log_message(self, fmt, *args):
        log("%s %s" % (self.client_address[0], fmt % args))

    def send(self, code, body, ctype="application/json", cookies=()):
        if ctype == "application/json":
            body = json.dumps(body)
        body = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
        for c in cookies:
            self.send_header("Set-Cookie", c)
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 65536:
            raise ApiError("request too large", 413)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            raise ApiError("invalid JSON")

    def cookie(self, name):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return None

    def session_user(self):
        tok = self.cookie("pfsid")
        s = SESSIONS.get(tok) if tok else None
        if s and s[1] > time.time():
            s[1] = time.time() + SESSION_TTL
            return s[0]
        return None

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def do_PUT(self):
        self.route("PUT")

    def do_DELETE(self):
        self.route("DELETE")

    def route(self, method):
        path = urllib.parse.urlsplit(self.path).path
        try:
            if method == "GET" and path in STATIC:
                ctype, content = STATIC[path]
                return self.send(200, content, ctype)
            if not path.startswith("/api/"):
                return self.send(404, {"error": "not found"})
            # custom header can't be sent cross-site without CORS preflight -> CSRF protection
            if method != "GET" and self.headers.get("X-PF") != "1":
                return self.send(403, {"error": "missing X-PF header"})
            if path == "/api/login" and method == "POST":
                return self.login()
            user = self.session_user()
            if not user:
                return self.send(401, {"error": "login required"})
            self.api(method, path, user)
        except ApiError as e:
            self.send(e.code, {"error": str(e)})
        except Exception:
            traceback.print_exc()
            self.send(500, {"error": "internal error"})

    def login(self):
        ip = self.client_address[0]
        now = time.time()
        f = FAILS.get(ip)
        if f and now - f[1] > 300:
            FAILS.pop(ip, None)
            f = None
        if f and f[0] >= 5:
            raise ApiError("too many failed attempts, try again in a few minutes", 429)
        d = self.body()
        user = authenticate(str(d.get("username", "")), str(d.get("password", "")))
        if not user:
            FAILS.setdefault(ip, [0, now])[0] += 1
            time.sleep(1)
            raise ApiError("invalid credentials or user not allowed", 401)
        FAILS.pop(ip, None)
        for k in [k for k, v in SESSIONS.items() if v[1] < now]:
            SESSIONS.pop(k, None)
        tok = secrets.token_urlsafe(32)
        SESSIONS[tok] = [user, now + SESSION_TTL]
        secure = "; Secure" if self.server.tls else ""
        self.send(200, {"user": user}, cookies=["pfsid=%s; Path=/; HttpOnly; SameSite=Strict%s" % (tok, secure)])

    def api(self, method, path, user):
        cfg = STATE["cfg"]
        if path == "/api/logout" and method == "POST":
            SESSIONS.pop(self.cookie("pfsid"), None)
            return self.send(200, {"ok": True}, cookies=["pfsid=; Path=/; Max-Age=0"])
        if path == "/api/state" and method == "GET":
            return self.send(200, {
                "user": user, "version": VERSION, "rules": cfg["rules"], "counters": counters(),
                "ifaces": list_ifaces(), "dry_run": DRY_RUN,
                "status": {"ip_forward": ip_forward_on(), "active": DRY_RUN or hooks_active(),
                           "last_apply": STATE["last_apply"], "last_error": STATE["last_error"]},
            })
        if path == "/api/guests" and method == "GET":
            return self.send(200, {"guests": list_guests()})
        if path == "/api/apply" and method == "POST":
            err = apply_rules()
            if err:
                raise ApiError(err, 500)
            return self.send(200, {"ok": True})

        m = re.match(r"^/api/rules(?:/([0-9a-f]{1,16}))?$", path)
        if not m:
            raise ApiError("not found", 404)
        rid = m.group(1)
        with LOCK:
            rules = list(cfg["rules"])
            idx = next((i for i, r in enumerate(rules) if r["id"] == rid), None) if rid else None
            if rid and idx is None:
                raise ApiError("rule not found", 404)
            if method == "POST" and not rid:
                rule = validate_rule(self.body(), rules, cfg)
                rules.append(rule)
            elif method == "PUT" and rid:
                rule = validate_rule(self.body(), [r for r in rules if r["id"] != rid], cfg, rid)
                rules[idx] = rule
            elif method == "DELETE" and rid:
                rules.pop(idx)
            else:
                raise ApiError("method not allowed", 405)
            new = dict(cfg, rules=rules)
            err = apply_rules(new)  # atomic: on failure the old rules stay in place
            if err:
                apply_rules(cfg)
                raise ApiError(err, 500)
            save_config(new)
            STATE["cfg"] = new
            log("%s %s %s" % (user, method, rid or "new rule"))
        return self.send(200, {"ok": True, "rules": new["rules"]})


class Server(ThreadingHTTPServer):
    daemon_threads = True
    tls = False


def tls_context(cfg):
    pairs = [(cfg["cert"], cfg["key"])] if cfg.get("cert") else [
        ("/etc/pve/local/pveproxy-ssl.pem", "/etc/pve/local/pveproxy-ssl.key"),
        ("/etc/pve/local/pve-ssl.pem", "/etc/pve/local/pve-ssl.key"),
    ]
    for cert, key in pairs:
        if os.path.exists(cert) and os.path.exists(key):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(cert, key)
            return ctx, cert
    return None, None


def serve(cfg):
    err = apply_rules()
    log("rules applied" if not err else err)
    threading.Thread(target=watchdog, daemon=True).start()
    httpd = Server((cfg["listen"], int(cfg["port"])), Handler)
    ctx, cert = tls_context(cfg)
    if ctx:
        # handshake happens lazily in the worker thread, so a slow client can't block accept()
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=False)
        httpd.tls = True
    scheme = "https" if ctx else "http"
    log("listening on %s://%s:%s/%s" % (scheme, cfg["listen"], cfg["port"], " (cert %s)" % cert if cert else " (NO TLS!)"))
    log("auth: " + ("local user '%s'" % cfg["local_user"] if cfg.get("pass_hash")
                    else "Proxmox login, allowed: %s" % ", ".join(cfg["allowed_users"])))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


# --------------------------------------------------------------------------- UI

INDEX_HTML = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Port Forwarding</title><link rel="stylesheet" href="/app.css">
</head><body>
<div id="login" class="center" hidden>
  <form id="loginForm" class="card login">
    <h1>Port Forwarding</h1>
    <p class="muted">Sign in with your Proxmox account</p>
    <label>User<input name="username" autocomplete="username" value="root@pam" required></label>
    <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
    <button type="submit">Sign in</button>
    <p id="loginErr" class="err"></p>
  </form>
</div>
<div id="app" hidden>
  <header>
    <h1>Port Forwarding</h1>
    <div id="status" class="chips"></div>
    <span class="spacer"></span>
    <span id="who" class="muted"></span>
    <button id="logout" class="ghost">Sign out</button>
  </header>
  <main>
    <div class="bar">
      <button id="addBtn">+ Add rule</button>
      <button id="reapply" class="ghost" title="Re-write iptables rules from saved config">Re-apply</button>
      <span id="msg"></span>
    </div>
    <div class="card scroll">
      <table>
        <thead><tr><th>On</th><th>Name</th><th>Proto</th><th>Host port</th><th></th><th>Destination</th><th>Source</th><th>Iface</th><th class="num">Hits</th><th></th></tr></thead>
        <tbody id="rules"></tbody>
      </table>
      <p id="empty" class="muted pad" hidden>No forwarding rules yet. Click <b>+ Add rule</b>.</p>
    </div>
    <p class="muted small">Only traffic addressed to this host is forwarded. Rules are kept in iptables chains
      <code>PORTFWD_*</code> and restored automatically when the service starts.</p>
  </main>
</div>

<dialog id="dlg">
  <form id="ruleForm" class="form">
    <h2 id="dlgTitle">Add rule</h2>
    <div class="grid">
      <label class="wide">Name<input name="name" maxlength="40" placeholder="e.g. web server"></label>
      <label>Protocol<select name="proto"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="both">TCP + UDP</option></select></label>
      <label>Host port<input name="ext_port" required placeholder="8080 or 8000-8010"></label>
      <label class="wide">Guest<select name="guest"><option value="">— pick a guest to fill its IP —</option></select></label>
      <label>Destination IP<input name="ip" required placeholder="10.10.10.10"></label>
      <label>Destination port<input name="int_port" placeholder="same as host port"></label>
      <label>Allowed source<input name="source" placeholder="any (or 203.0.113.0/24)"></label>
      <label>Incoming interface<select name="iface"><option value="">any</option></select></label>
      <label class="check wide"><input type="checkbox" name="masq"> Masquerade (SNAT) &mdash; needed if the guest's gateway is not this host, or to reach it via the public IP from other guests</label>
      <label class="check wide"><input type="checkbox" name="enabled" checked> Enabled</label>
    </div>
    <p id="formErr" class="err"></p>
    <div class="actions"><button type="button" id="cancel" class="ghost">Cancel</button><button type="submit">Save</button></div>
  </form>
</dialog>
<script src="/app.js"></script>
</body></html>
"""

APP_CSS = r"""
:root{--bg:#f5f6f8;--card:#fff;--fg:#1d2330;--muted:#6b7280;--line:#e3e6eb;--accent:#e57000;--accent-fg:#fff;
--ok:#15803d;--ok-bg:#dcfce7;--bad:#b91c1c;--bad-bg:#fee2e2;--warn:#a16207;--warn-bg:#fef9c3;--input:#fff}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--card:#1d2128;--fg:#e6e8eb;--muted:#9aa3ae;--line:#2d333c;
--accent:#ff8a1f;--accent-fg:#14171c;--ok:#4ade80;--ok-bg:#14301f;--bad:#f87171;--bad-bg:#3a1717;--warn:#facc15;--warn-bg:#3a3010;--input:#14171c}}
*{box-sizing:border-box}
[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
h1{font-size:17px;margin:0}h2{font-size:16px;margin:0 0 14px}
code{font-size:12px;background:var(--line);padding:1px 4px;border-radius:4px}
header{display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding:12px 20px;background:var(--card);border-bottom:1px solid var(--line)}
main{max-width:1200px;margin:0 auto;padding:16px 20px}
.spacer{flex:1}.muted{color:var(--muted)}.small{font-size:12px}.pad{padding:16px;margin:0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px}
.scroll{overflow-x:auto}
.bar{display:flex;gap:8px;align-items:center;margin-bottom:12px;flex-wrap:wrap}
button{font:inherit;border:1px solid var(--accent);background:var(--accent);color:var(--accent-fg);padding:7px 14px;border-radius:7px;cursor:pointer;font-weight:600}
button.ghost{background:transparent;color:var(--fg);border-color:var(--line);font-weight:500}
button.ghost:hover{border-color:var(--muted)}
button.link{background:none;border:none;color:var(--muted);padding:4px 6px;font-weight:500}
button.link:hover{color:var(--fg)}button.link.del:hover{color:var(--bad)}
table{width:100%;border-collapse:collapse;white-space:nowrap}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line)}
th{font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.03em}
tbody tr:last-child td{border-bottom:none}
tr.off td:not(:first-child){opacity:.45}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
td.arrow{color:var(--muted);padding:0 2px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
.tag{display:inline-block;font-size:11px;font-weight:600;padding:1px 7px;border-radius:99px;background:var(--line);text-transform:uppercase}
.chips{display:flex;gap:6px;flex-wrap:wrap}
.chip{font-size:12px;padding:2px 9px;border-radius:99px;font-weight:600}
.chip.ok{background:var(--ok-bg);color:var(--ok)}.chip.bad{background:var(--bad-bg);color:var(--bad)}.chip.warn{background:var(--warn-bg);color:var(--warn)}
.switch{appearance:none;width:32px;height:18px;border-radius:99px;background:var(--line);position:relative;cursor:pointer;margin:0;vertical-align:middle}
.switch:after{content:"";position:absolute;top:2px;left:2px;width:14px;height:14px;border-radius:50%;background:#fff;transition:left .15s}
.switch:checked{background:var(--ok)}.switch:checked:after{left:16px}
.center{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}
.login{width:100%;max-width:340px;padding:24px;display:flex;flex-direction:column;gap:12px}
label{display:flex;flex-direction:column;gap:4px;font-size:12px;font-weight:600;color:var(--muted)}
input,select{font:inherit;color:var(--fg);background:var(--input);border:1px solid var(--line);border-radius:7px;padding:7px 9px;font-weight:400}
input:focus,select:focus{outline:2px solid var(--accent);outline-offset:-1px}
label.check{flex-direction:row;align-items:flex-start;gap:8px;font-weight:400;color:var(--fg);font-size:13px}
label.check input{margin-top:3px}
.err{color:var(--bad);margin:0;min-height:1em;font-size:13px}
#msg{font-size:13px;color:var(--muted)}
dialog{border:1px solid var(--line);border-radius:12px;background:var(--card);color:var(--fg);padding:22px;width:min(560px,calc(100vw - 32px))}
dialog::backdrop{background:rgba(0,0,0,.45)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.grid .wide{grid-column:1/-1}
.actions{display:flex;justify-content:flex-end;gap:8px;margin-top:8px}
@media (max-width:560px){.grid{grid-template-columns:1fr}header,main{padding-left:16px;padding-right:16px}}
"""

APP_JS = r"""
'use strict';
const $ = s => document.querySelector(s);
let S = {rules: [], counters: {}, ifaces: []}, guests = null, editing = null, timer = null;

async function api(method, path, body) {
  const r = await fetch(path, {method, credentials: 'same-origin',
    headers: {'Content-Type': 'application/json', 'X-PF': '1'},
    body: body === undefined ? undefined : JSON.stringify(body)});
  const j = await r.json().catch(() => ({}));
  if (r.status === 401 && path !== '/api/login') { showLogin(); throw new Error('Login required'); }
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}

function el(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) e[k] = v;
  }
  for (const k of kids) if (k != null) e.append(k);
  return e;
}

function fmtBytes(n) {
  const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n) + ' ' + u[i];
}

function flash(t, isErr) {
  const m = $('#msg'); m.textContent = t; m.style.color = isErr ? 'var(--bad)' : '';
  clearTimeout(flash.t); flash.t = setTimeout(() => m.textContent = '', isErr ? 8000 : 3000);
}

function showLogin() {
  clearInterval(timer); timer = null;
  $('#app').hidden = true; $('#login').hidden = false;
  $('#loginForm').password.focus();
}

async function load() {
  S = await api('GET', '/api/state');
  $('#login').hidden = true; $('#app').hidden = false;
  render();
  if (!timer) timer = setInterval(() => { if (!document.hidden && !$('#dlg').open) load().catch(() => {}); }, 5000);
}

function render() {
  $('#who').textContent = S.user;
  const st = $('#status'); st.replaceChildren();
  const chip = (cls, t, title) => st.append(el('span', {class: 'chip ' + cls, textContent: t, title: title || ''}));
  if (S.dry_run) chip('warn', 'DRY RUN', 'iptables commands are only printed');
  chip(S.status.active ? 'ok' : 'bad', S.status.active ? 'rules active' : 'rules not loaded');
  chip(S.status.ip_forward ? 'ok' : 'bad', S.status.ip_forward ? 'ip_forward on' : 'ip_forward off');
  if (S.status.last_error) chip('bad', 'error', S.status.last_error);

  const tb = $('#rules'); tb.replaceChildren();
  $('#empty').hidden = S.rules.length > 0;
  for (const r of S.rules) {
    const c = S.counters[r.id];
    tb.append(el('tr', {class: r.enabled ? '' : 'off'},
      el('td', {}, el('input', {type: 'checkbox', class: 'switch', checked: r.enabled, title: r.enabled ? 'Disable' : 'Enable',
        onchange: e => save(r.id, Object.assign({}, r, {enabled: e.target.checked}))})),
      el('td', {textContent: r.name || '—'}),
      el('td', {}, el('span', {class: 'tag', textContent: r.proto === 'both' ? 'tcp+udp' : r.proto})),
      el('td', {class: 'mono', textContent: r.ext_port}),
      el('td', {class: 'arrow', textContent: '→'}),
      el('td', {class: 'mono', textContent: r.ip + ':' + (r.int_port || r.ext_port) + (r.masq ? ' ⇄' : ''), title: r.masq ? 'masquerade on' : ''}),
      el('td', {class: 'mono', textContent: r.source || 'any'}),
      el('td', {class: 'mono', textContent: r.iface || 'any'}),
      el('td', {class: 'num', textContent: c ? c[0] + ' · ' + fmtBytes(c[1]) : '—', title: 'new connections · bytes'}),
      el('td', {class: 'num'},
        el('button', {class: 'link', textContent: 'Edit', onclick: () => openDlg(r)}),
        el('button', {class: 'link del', textContent: 'Delete', onclick: () => del(r)}))));
  }
}

async function save(id, data) {
  try {
    await api(id ? 'PUT' : 'POST', id ? '/api/rules/' + id : '/api/rules', data);
    flash('Saved and applied'); await load(); return true;
  } catch (e) { flash(e.message, true); await load().catch(() => {}); throw e; }
}

async function del(r) {
  if (!confirm('Delete rule "' + (r.name || r.ext_port) + '"?')) return;
  try { await api('DELETE', '/api/rules/' + r.id); flash('Deleted'); await load(); } catch (e) { flash(e.message, true); }
}

async function fillGuests() {
  const sel = $('#ruleForm').guest;
  if (!guests) {
    try { guests = (await api('GET', '/api/guests')).guests; } catch (e) { guests = []; }
    setTimeout(() => guests = null, 30000);
  }
  sel.replaceChildren(el('option', {value: '', textContent: guests.length ? '— pick a guest to fill its IP —' : '— no guests found —'}));
  for (const g of guests) {
    const label = g.vmid + ' ' + (g.name || '') + ' (' + (g.type === 'lxc' ? 'CT' : 'VM') + (g.status !== 'running' ? ', ' + g.status : '') + ')';
    if (!g.ips.length) sel.append(el('option', {value: '', disabled: true, textContent: label + ' — IP unknown'}));
    for (const ip of g.ips) sel.append(el('option', {value: ip, textContent: label + ' — ' + ip}));
  }
}

function openDlg(r) {
  editing = r ? r.id : null;
  const f = $('#ruleForm');
  $('#dlgTitle').textContent = r ? 'Edit rule' : 'Add rule';
  $('#formErr').textContent = '';
  const iface = f.iface; iface.replaceChildren(el('option', {value: '', textContent: 'any'}));
  for (const i of S.ifaces) iface.append(el('option', {value: i, textContent: i}));
  r = r || {proto: 'tcp', enabled: true};
  for (const k of ['name', 'proto', 'ext_port', 'ip', 'int_port', 'source', 'iface']) f[k].value = r[k] || '';
  if (r.iface && !S.ifaces.includes(r.iface)) iface.append(el('option', {value: r.iface, textContent: r.iface, selected: true}));
  f.masq.checked = !!r.masq; f.enabled.checked = r.enabled !== false;
  $('#dlg').showModal();
  (r.id ? f.name : f.ext_port).focus();
  fillGuests();
}

$('#ruleForm').guest.addEventListener('change', e => {
  const f = $('#ruleForm');
  if (e.target.value) {
    f.ip.value = e.target.value;
    if (!f.name.value) f.name.value = e.target.selectedOptions[0].textContent.split(' (')[0].replace(/^\d+ /, '').slice(0, 40);
  }
});

$('#ruleForm').addEventListener('submit', async e => {
  e.preventDefault();
  const f = e.target, d = {};
  for (const k of ['name', 'proto', 'ext_port', 'ip', 'int_port', 'source', 'iface']) d[k] = f[k].value.trim();
  d.masq = f.masq.checked; d.enabled = f.enabled.checked;
  try {
    await api(editing ? 'PUT' : 'POST', editing ? '/api/rules/' + editing : '/api/rules', d);
    $('#dlg').close(); flash('Saved and applied'); load();
  } catch (err) { $('#formErr').textContent = err.message; }
});

$('#cancel').onclick = () => $('#dlg').close();
$('#addBtn').onclick = () => openDlg(null);
$('#reapply').onclick = async () => {
  try { await api('POST', '/api/apply'); flash('Rules re-applied'); load(); } catch (e) { flash(e.message, true); }
};
$('#logout').onclick = async () => { await api('POST', '/api/logout').catch(() => {}); showLogin(); };

$('#loginForm').addEventListener('submit', async e => {
  e.preventDefault();
  const f = e.target, btn = f.querySelector('button');
  $('#loginErr').textContent = ''; btn.disabled = true;
  try {
    await api('POST', '/api/login', {username: f.username.value.trim(), password: f.password.value});
    f.password.value = ''; await load();
  } catch (err) { $('#loginErr').textContent = err.message; }
  btn.disabled = false;
});

load().catch(() => {});
"""

STATIC = {
    "/": ("text/html", INDEX_HTML),
    "/app.css": ("text/css", APP_CSS),
    "/app.js": ("application/javascript", APP_JS),
}


# --------------------------------------------------------------------------- main

def main():
    global DRY_RUN, CONF_DIR
    ap = argparse.ArgumentParser(description="Port forwarding web UI for Proxmox VE")
    ap.add_argument("cmd", nargs="?", default="serve", choices=["serve", "apply", "flush", "passwd", "show"])
    ap.add_argument("--dry-run", action="store_true", help="print iptables commands instead of running them")
    ap.add_argument("--config-dir", default=CONF_DIR, help="default: %(default)s")
    ap.add_argument("--port", type=int, help="override listen port")
    a = ap.parse_args()
    DRY_RUN, CONF_DIR = a.dry_run, a.config_dir

    if not DRY_RUN and hasattr(os, "geteuid") and os.geteuid() != 0 and a.cmd != "show":
        sys.exit("must run as root (needs iptables); use --dry-run to test")

    cfg = load_config()
    if a.port:
        cfg["port"] = a.port
    STATE["cfg"] = cfg

    if a.cmd == "show":
        sys.stdout.write(build_ruleset(cfg))
    elif a.cmd == "apply":
        err = apply_rules()
        sys.exit(err) if err else print("applied %d rule(s)" % sum(r["enabled"] for r in cfg["rules"]))
    elif a.cmd == "flush":
        flush_rules()
        print("forwarding rules removed (config kept in %s)" % conf_file())
    elif a.cmd == "passwd":
        user = input("Local username [%s]: " % cfg.get("local_user", "admin")).strip() or cfg.get("local_user", "admin")
        pw = getpass.getpass("New password (empty = switch back to Proxmox login): ")
        if pw and pw != getpass.getpass("Repeat: "):
            sys.exit("passwords do not match")
        cfg["local_user"], cfg["pass_hash"] = user, hash_password(pw) if pw else ""
        save_config(cfg)
        print("saved; restart the service: systemctl restart pve-portfwd")
    else:
        serve(cfg)


if __name__ == "__main__":
    main()
