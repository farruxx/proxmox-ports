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
import calendar
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
from collections import deque
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
    # Domains: nginx reverse proxy (+ optional Let's Encrypt via certbot).
    "domains": [],
    "acme_email": "",
    "nginx_conf": "/etc/nginx/conf.d/pve-portfwd.conf",
    "acme_webroot": "/var/lib/pve-portfwd/acme",
    "letsencrypt_dir": "/etc/letsencrypt/live",
    "nginx_ipv6": True,  # also listen on [::]:80/443
}

LOCK = threading.RLock()
STATE = {"cfg": None, "last_apply": None, "last_error": None}
SESSIONS = {}  # token -> [user, expires]
FAILS = {}     # ip -> [count, first_ts]
SESSION_TTL = 8 * 3600
DRY_RUN = False
MOCK = None  # dev/mock.py instance when started with --mock (simulated host for local development)


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
            log("skipping invalid rule %r: %s" % (r.get("name") or r.get("id"), e), "warn")
    cfg["rules"] = rules
    domains = []
    for d in cfg.get("domains", []):
        try:
            domains.append(validate_domain(d, domains, cfg, d.get("id"), check_rules=False))
        except (ApiError, ValueError) as e:
            log("skipping invalid domain %r: %s" % (d.get("domain") or d.get("id"), e), "warn")
    cfg["domains"] = domains
    return cfg


def save_config(cfg):
    os.makedirs(CONF_DIR, mode=0o700, exist_ok=True)
    tmp = conf_file() + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, conf_file())


LOGS = deque(maxlen=500)  # recent log lines, shown in the Debug tab
VERBOSE = False           # log every command / request (toggle: --verbose or Debug tab)


def log(msg, level="info"):
    if level == "debug" and not VERBOSE:
        return
    LOGS.append("%s %-5s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), level.upper(), msg))
    sys.stderr.write("[pve-portfwd] %s%s\n" % ("" if level == "info" else level.upper() + ": ", msg))
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
    if r["enabled"] and any(d["enabled"] for d in cfg.get("domains", [])) and "tcp" in protos(r["proto"]):
        for p in (80, 443):
            if ea <= p <= eb:
                raise ApiError("port %d is used by nginx for your domains - add a domain instead of a port rule" % p)

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

def run(cmd, data=None, check_only=False, timeout=30):
    """Run a command. check_only=True: a non-zero exit is an expected answer, not an error."""
    line = " ".join(cmd)
    if DRY_RUN and not check_only:  # read-only queries (check_only) still run for real
        log("[dry-run] $ %s%s" % (line, "\n" + data.rstrip() if data else ""))
        return 0, ""
    t = time.time()
    if MOCK:
        rc, out = MOCK.exec(cmd, data)
    else:
        try:
            p = subprocess.run(cmd, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               universal_newlines=True, timeout=timeout)
            rc, out = p.returncode, (p.stdout if p.returncode == 0 else (p.stderr or p.stdout)).strip()
        except (OSError, subprocess.TimeoutExpired) as e:
            rc, out = 1, str(e)
    if rc != 0 and not check_only:
        log("$ %s -> exit %d: %s" % (line, rc, out), "warn")
    else:
        log("$ %s -> exit %d (%dms)%s" % (line, rc, (time.time() - t) * 1000,
                                         ("\n" + data.rstrip()) if data else ""), "debug")
    return rc, out


def sh(cmd, timeout=10):
    """Read-only diagnostic command: returns (rc, combined output)."""
    if MOCK:
        return MOCK.exec(cmd)
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           universal_newlines=True, timeout=timeout)
        return p.returncode, p.stdout.rstrip() or "(no output, exit %d)" % p.returncode
    except FileNotFoundError:
        return 127, "(command not found: %s)" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "(timed out after %ss)" % timeout


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
    if MOCK and not MOCK.ip_forward:
        MOCK.ip_forward = True
        log("enabled net.ipv4.ip_forward")
    if MOCK or DRY_RUN or not os.path.exists(path):
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
            log(STATE["last_error"], "error")
            return STATE["last_error"]
        for table, chain, target in JUMPS:
            if run(["iptables", "-t", table, "-C", chain, "-j", target], check_only=True)[0] != 0:
                rc, out = run(["iptables", "-t", table, "-I", chain, "1", "-j", target])
                if rc != 0:
                    STATE["last_error"] = "cannot hook %s/%s: %s" % (table, chain, out)
                    log(STATE["last_error"], "error")
                    return STATE["last_error"]
        try:
            ensure_ip_forward()
        except OSError as e:
            STATE["last_error"] = "cannot enable ip_forward: %s" % e
            return STATE["last_error"]
        STATE["last_apply"] = time.time()
        STATE["last_error"] = None
        log("applied %d rule(s)" % sum(r["enabled"] for r in cfg["rules"]))
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
    rc, out = run(["iptables-save", "-c", "-t", "nat"], check_only=True)
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
    if MOCK:
        return MOCK.ip_forward
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            return f.read().strip() == "1"
    except OSError:
        return DRY_RUN


def watchdog():
    """Re-hook our chains if something (iptables -F, network restart) removed them."""
    while True:
        time.sleep(10 if MOCK else 30)
        try:
            if not DRY_RUN and not hooks_active():
                log("hooks missing (iptables flushed?), re-applying rules", "warn")
                apply_rules()
        except Exception as e:
            log("watchdog: %s" % e, "error")


# --------------------------------------------------------------------------- guests / interfaces

GUEST_CACHE = {"t": 0, "data": []}


def list_ifaces():
    if MOCK:
        return MOCK.ifaces()
    try:
        names = sorted(os.listdir("/sys/class/net"))
    except OSError:
        return []
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


# --------------------------------------------------------------------------- domains (nginx)

DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[a-z]{2,}$", re.I)
BODY_RE = re.compile(r"^\d{1,5}[kmg]?$")
NGINX = {"last_apply": None, "last_error": None}
CERT_JOBS = {}    # domain id -> {"state": "pending"|"ok"|"error", "msg": str, "t": ts}
CERT_CACHE = {}   # cert name -> (checked_at, info)


def _names(d):
    return [d["domain"]] + d["aliases"]


def validate_domain(data, others, cfg, did=None, check_rules=True):
    if not isinstance(data, dict):
        raise ApiError("domain must be an object")
    d = {"id": did or uuid.uuid4().hex[:8]}
    if not re.match(r"^[0-9a-f]{1,16}$", d["id"]):
        raise ApiError("invalid id")
    d["domain"] = str(data.get("domain", "")).strip().lower().rstrip(".")
    if not DOMAIN_RE.match(d["domain"]):
        raise ApiError("invalid domain name '%s' (e.g. cloud.example.com)" % d["domain"])
    aliases = data.get("aliases", [])
    if isinstance(aliases, str):
        aliases = re.split(r"[\s,]+", aliases)
    d["aliases"] = []
    for a in aliases:
        a = str(a).strip().lower().rstrip(".")
        if not a or a == d["domain"] or a in d["aliases"]:
            continue
        if not DOMAIN_RE.match(a):
            raise ApiError("invalid alias '%s'" % a)
        d["aliases"].append(a)
    if len(d["aliases"]) > 20:
        raise ApiError("max 20 aliases")
    try:
        ip = ipaddress.IPv4Address(str(data.get("ip", "")).strip())
    except ValueError:
        raise ApiError("target must be an IPv4 address")
    if ip.is_multicast or ip.is_unspecified:
        raise ApiError("target IP is not usable")
    d["ip"] = str(ip)
    try:
        d["port"] = int(data.get("port", 80))
    except (TypeError, ValueError):
        raise ApiError("target port must be a number")
    if not 1 <= d["port"] <= 65535:
        raise ApiError("target port out of range")
    d["upstream_https"] = bool(data.get("upstream_https", False))
    d["tls"] = str(data.get("tls", "none"))
    if d["tls"] not in ("none", "letsencrypt"):
        raise ApiError("tls must be 'none' or 'letsencrypt'")
    d["force_https"] = bool(data.get("force_https", True))
    d["max_body"] = str(data.get("max_body", "100m") or "100m").strip().lower()
    if not BODY_RE.match(d["max_body"]):
        raise ApiError("max upload size: number with optional k/m/g, 0 = unlimited (e.g. 100m)")
    src = data.get("source", [])
    if isinstance(src, str):
        src = re.split(r"[\s,]+", src)
    d["source"] = []
    for c in src:
        c = str(c).strip()
        if c:
            try:
                d["source"].append(str(ipaddress.ip_network(c, strict=False)))
            except ValueError:
                raise ApiError("invalid source '%s' (IP or CIDR)" % c)
    d["enabled"] = bool(data.get("enabled", True))

    taken = {n: o for o in others for n in _names(o)}
    for n in _names(d):
        if n in taken:
            raise ApiError("%s is already used by domain %s" % (n, taken[n]["domain"]))
    if check_rules and d["enabled"]:
        for r in cfg.get("rules", []):
            if r["enabled"] and "tcp" in protos(r["proto"]):
                ea, eb = parse_ports(r["ext_port"])
                for p in (80, 443):
                    if ea <= p <= eb:
                        raise ApiError("port rule '%s' (%s) forwards port %d away from nginx - disable it first"
                                       % (r["name"] or r["id"], r["ext_port"], p))
    return d


def cert_paths(cfg, d):
    base = os.path.join(cfg.get("letsencrypt_dir", "/etc/letsencrypt/live"), d["domain"])
    return os.path.join(base, "fullchain.pem"), os.path.join(base, "privkey.pem")


def cert_info(cfg, d, fresh=False):
    """{"exists": bool, "expires": ts, "days": int} for the domain's Let's Encrypt cert (cached 60s)."""
    hit = CERT_CACHE.get(d["domain"])
    if hit and not fresh and time.time() - hit[0] < 60:
        return hit[1]
    rc, out = sh(["openssl", "x509", "-noout", "-enddate", "-in", cert_paths(cfg, d)[0]])
    info = {"exists": False}
    m = re.search(r"notAfter=(.+)", out or "") if rc == 0 else None
    if m:
        try:
            exp = calendar.timegm(time.strptime(m.group(1).strip().replace("  ", " "), "%b %d %H:%M:%S %Y %Z"))
            info = {"exists": True, "expires": exp, "days": int((exp - time.time()) // 86400)}
        except ValueError:
            info = {"exists": True}
    CERT_CACHE[d["domain"]] = (time.time(), info)
    return info


def nginx_proxy_block(d):
    up = "%s://%s:%d" % ("https" if d["upstream_https"] else "http", d["ip"], d["port"])
    lines = ["    client_max_body_size %s;" % d["max_body"], "", "    location / {"]
    lines += ["        allow %s;" % c for c in d["source"]] + (["        deny all;"] if d["source"] else [])
    lines += [
        "        proxy_pass %s;" % up,
        "        proxy_http_version 1.1;",
        "        proxy_set_header Host $host;",
        "        proxy_set_header X-Real-IP $remote_addr;",
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "        proxy_set_header X-Forwarded-Proto $scheme;",
        "        proxy_set_header X-Forwarded-Host $host;",
        "        proxy_set_header Upgrade $http_upgrade;",
        "        proxy_set_header Connection $pf_connection_upgrade;",
        "        proxy_read_timeout 1h;",
        "        proxy_send_timeout 1h;",
    ]
    if d["upstream_https"]:
        lines += ["        proxy_ssl_server_name on;", "        proxy_ssl_verify off;  # guests usually have self-signed certs"]
    return lines + ["    }"]


def build_nginx(cfg):
    out = ["# Generated by pve-portfwd %s - do not edit, changes are overwritten." % VERSION,
           "# Manage domains in the pve-portfwd web UI.", "",
           "map $http_upgrade $pf_connection_upgrade {", "    default upgrade;", "    ''      close;", "}"]
    v6 = cfg.get("nginx_ipv6", True)
    acme = ["    location ^~ /.well-known/acme-challenge/ {", "        root %s;" % cfg["acme_webroot"],
            "        default_type text/plain;", "    }"]
    for d in cfg["domains"]:
        if not d["enabled"]:
            continue
        tls = d["tls"] == "letsencrypt" and cert_info(cfg, d)["exists"]
        names = " ".join(_names(d))
        out += ["", "# %s -> %s:%d  (id %s)" % (d["domain"], d["ip"], d["port"], d["id"]),
                "server {", "    listen 80;"] + (["    listen [::]:80;"] if v6 else []) + [
                "    server_name %s;" % names] + acme
        if tls and d["force_https"]:
            out += ["    location / {", "        return 301 https://$host$request_uri;", "    }"]
        else:
            out += nginx_proxy_block(d)
        out.append("}")
        if tls:
            crt, key = cert_paths(cfg, d)
            out += ["server {", "    listen 443 ssl http2;"] + (["    listen [::]:443 ssl http2;"] if v6 else []) + [
                "    server_name %s;" % names,
                "    ssl_certificate %s;" % crt,
                "    ssl_certificate_key %s;" % key,
                "    ssl_protocols TLSv1.2 TLSv1.3;",
                "    ssl_session_cache shared:pf_ssl:10m;",
                "    ssl_session_timeout 1d;"] + nginx_proxy_block(d) + ["}"]
    return "\n".join(out) + "\n"


def nginx_installed():
    return sh(["nginx", "-v"])[0] == 0


def nginx_conf_path(cfg):
    return MOCK.path_for(cfg["nginx_conf"]) if MOCK else cfg["nginx_conf"]


def apply_nginx(cfg=None):
    """Write the nginx config, validate with `nginx -t` (rolling back on failure), reload. Returns error or None."""
    with LOCK:
        cfg = cfg or STATE["cfg"]
        path = nginx_conf_path(cfg)
        active = [d for d in cfg["domains"] if d["enabled"]]
        if not active and not os.path.exists(path):
            return None  # domains never used: don't require nginx
        if not nginx_installed():
            NGINX["last_error"] = "nginx is not installed - run: apt install nginx" + (
                " certbot" if any(d["tls"] == "letsencrypt" for d in active) else "")
            return NGINX["last_error"]
        conf = build_nginx(cfg)
        if DRY_RUN:
            log("[dry-run] would write %s:\n%s" % (path, conf.rstrip()))
            return None
        try:
            with open(path) as f:
                old = f.read()
        except OSError:
            old = None
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            os.makedirs(os.path.join(MOCK.path_for(cfg["acme_webroot"]) if MOCK else cfg["acme_webroot"],
                                     ".well-known", "acme-challenge"), exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                f.write(conf)
            os.replace(tmp, path)
        except OSError as e:
            NGINX["last_error"] = "cannot write %s: %s" % (path, e)
            log(NGINX["last_error"], "error")
            return NGINX["last_error"]
        rc, out = run(["nginx", "-t"])
        if rc != 0:
            if old is None:
                os.remove(path)
            else:
                with open(path, "w") as f:
                    f.write(old)
            NGINX["last_error"] = "nginx config test failed (previous config restored): " + out
            log(NGINX["last_error"], "error")
            return NGINX["last_error"]
        rc, out = run(["systemctl", "reload-or-restart", "nginx"])
        if rc != 0:
            NGINX["last_error"] = "nginx reload failed: " + out
            log(NGINX["last_error"], "error")
            return NGINX["last_error"]
        NGINX["last_apply"], NGINX["last_error"] = time.time(), None
        log("nginx: applied %d domain(s)" % len(active))
        return None


def issue_cert(did):
    """Request/renew a Let's Encrypt certificate in the background (certbot webroot)."""
    cfg = STATE["cfg"]
    d = next((x for x in cfg["domains"] if x["id"] == did), None)
    if not d or d["tls"] != "letsencrypt" or not d["enabled"]:
        return
    if CERT_JOBS.get(did, {}).get("state") == "pending":
        return
    CERT_JOBS[did] = {"state": "pending", "msg": "requesting certificate...", "t": time.time()}

    def job():
        if sh(["certbot", "--version"])[0] != 0:
            CERT_JOBS[did] = {"state": "error", "msg": "certbot is not installed - run: apt install certbot", "t": time.time()}
            return
        cmd = ["certbot", "certonly", "--webroot", "-w", cfg["acme_webroot"], "--non-interactive", "--agree-tos",
               "--keep-until-expiring", "--expand", "--cert-name", d["domain"],
               "--deploy-hook", "systemctl reload nginx"]
        cmd += ["-m", cfg["acme_email"]] if cfg.get("acme_email") else ["--register-unsafely-without-email"]
        for n in _names(d):
            cmd += ["-d", n]
        log("certbot: requesting certificate for %s" % ", ".join(_names(d)))
        rc, out = run(cmd, timeout=300)
        if rc != 0:
            detail = [line.strip() for line in out.splitlines()
                      if re.search(r"Detail:|Domain:|Type:|error|Error|problem", line)][:6]
            CERT_JOBS[did] = {"state": "error", "msg": "\n".join(detail) or out[-500:], "t": time.time()}
            log("certbot failed for %s: %s" % (d["domain"], CERT_JOBS[did]["msg"]), "error")
            return
        cert_info(cfg, d, fresh=True)
        err = apply_nginx()
        msg = "certificate is valid, not due for renewal yet" if "no action taken" in out else "certificate installed"
        CERT_JOBS[did] = {"state": "error" if err else "ok", "msg": err or msg, "t": time.time()}
        log("certbot: %s - %s" % (d["domain"], CERT_JOBS[did]["msg"]))

    threading.Thread(target=job, daemon=True).start()


def domain_status(cfg):
    res = {}
    for d in cfg["domains"]:
        st = {"job": CERT_JOBS.get(d["id"])}
        if d["tls"] == "letsencrypt":
            st["cert"] = cert_info(cfg, d)
        res[d["id"]] = st
    return res


def resolve(name):
    if MOCK:
        return MOCK.resolve(name)
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)})
    except socket.gaierror:
        return []


def http_check(host, tls):
    """Request http(s)://127.0.0.1/ with Host: <host> through nginx. Returns (status, text)."""
    if MOCK:
        return MOCK.http_check(host, tls)
    import http.client
    try:
        if tls:
            conn = http.client.HTTPSConnection("127.0.0.1", 443, timeout=8, context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection("127.0.0.1", 80, timeout=8)
        conn.request("GET", "/", headers={"Host": host, "User-Agent": "pve-portfwd-test"})
        r = conn.getresponse()
        return r.status, "%d %s%s" % (r.status, r.reason, (" -> " + r.getheader("Location")) if r.getheader("Location") else "")
    except (OSError, http.client.HTTPException) as e:
        return 0, str(e)


def test_domain(d):
    cfg = STATE["cfg"]
    steps = []

    def add(name, status, detail=""):
        steps.append({"name": name, "status": status, "detail": detail})

    add("domain enabled", _st(d["enabled"]))
    for n in _names(d):
        ips = resolve(n)
        add("DNS %s" % n, _st(bool(ips)), ("resolves to " + ", ".join(ips) +
            " - must be this host's public IP (or your router's, forwarding 80/443 here)") if ips
            else "does not resolve - create an A record pointing to this host's public IP")
    rc, out = sh(["systemctl", "is-active", "nginx"])
    add("nginx running", _st(out.strip() == "active"), out.strip() if out else "")
    try:
        with open(nginx_conf_path(cfg)) as f:
            present = ("server_name %s" % " ".join(_names(d))) in f.read()
    except OSError:
        present = False
    add("in nginx config", _st(present or not d["enabled"]), cfg["nginx_conf"])
    res, ms = tcp_probe(d["ip"], d["port"])
    add("upstream %s:%d" % (d["ip"], d["port"]), _st(res == "ok"),
        "connected in %dms" % ms if res == "ok" else res + (" - nothing listens on that port" if res == "refused" else ""))
    tls = d["tls"] == "letsencrypt" and cert_info(cfg, d)["exists"]
    if d["tls"] == "letsencrypt":
        ci, job = cert_info(cfg, d, fresh=True), CERT_JOBS.get(d["id"])
        if ci["exists"]:
            days = ci.get("days", 0)
            add("certificate", "ok" if days >= 14 else "warn", "expires in %d days (certbot renews automatically)" % days)
        else:
            add("certificate", "warn" if job and job["state"] == "pending" else "fail",
                job["msg"] if job else "not issued yet - click Cert")
    for proto_tls in ([False, True] if tls else [False]):
        status, text = http_check(d["domain"], proto_tls)
        name = "request via nginx (%s)" % ("https" if proto_tls else "http")
        if status in (502, 504):
            add(name, "fail", text + " - nginx can't reach the upstream")
        elif status == 0:
            add(name, "fail", text)
        else:
            add(name, "ok" if status < 500 else "warn", text)
    if d["tls"] == "none":
        add("TLS", "info", "HTTP only - pick Let's Encrypt to get HTTPS")
    return steps


# --------------------------------------------------------------------------- diagnostics

def _st(ok, warn=False):
    return "ok" if ok else ("warn" if warn else "fail")


def host_listeners():
    """{(proto, port)} of sockets the host itself listens on."""
    rc, out = sh(["ss", "-Hlntu"])
    res = set()
    if rc == 0:
        for f in (line.split() for line in out.splitlines()):
            m = re.search(r":(\d+)$", f[4]) if len(f) > 4 else None
            if m:
                res.add((f[0], int(m.group(1))))
    return res


def hook_position(table, chain, target):
    """1-based position of our jump rule in a built-in chain, or None if missing."""
    rc, out = sh(["iptables", "-t", table, "-S", chain])
    if rc != 0:
        return None
    rules = [line for line in out.splitlines() if line.startswith("-A ")]
    want = "-A %s -j %s" % (chain, target)
    return rules.index(want) + 1 if want in rules else None


def loaded_rule_ids():
    """{rule id: number of DNAT entries currently in the kernel}"""
    rc, out = sh(["iptables-save", "-t", "nat"])
    ids = {}
    if rc == 0:
        for m in re.finditer(r"^-A %s .*pf:([0-9a-f]+)" % CH_PRE, out, re.M):
            ids[m.group(1)] = ids.get(m.group(1), 0) + 1
    return ids


def checks():
    cfg = STATE["cfg"]
    res = []

    def add(name, status, detail=""):
        res.append({"name": name, "status": status, "detail": detail})

    if MOCK:
        add("mock mode", "warn", "simulated host - nothing real is touched (state: %s)" % MOCK.path)
    if DRY_RUN:
        add("dry-run mode", "warn", "iptables changes are only logged, nothing is changed")
    uid = os.geteuid() if hasattr(os, "geteuid") else -1
    add("running as root", _st(MOCK or DRY_RUN or uid == 0), "mock" if MOCK else "uid %d" % uid)
    rc, out = sh(["iptables", "--version"])
    add("iptables available", "info" if rc is None else _st(rc == 0), out)
    add("net.ipv4.ip_forward", _st(ip_forward_on()), "routing between interfaces")
    for t, c, tg in JUMPS:
        name = "hook %s/%s -> %s" % (t, c, tg)
        pos = hook_position(t, c, tg)
        add(name, "fail" if pos is None else _st(pos == 1, warn=True),
            "missing - click Re-apply" if pos is None else
            "rule #1" if pos == 1 else "rule #%d: the %d rule(s) above it are evaluated first" % (pos, pos - 1))
    expected = {r["id"]: len(protos(r["proto"])) for r in cfg["rules"] if r["enabled"]}
    loaded = loaded_rule_ids()
    missing = [r["name"] or r["id"] for r in cfg["rules"] if r["enabled"] and loaded.get(r["id"]) != expected[r["id"]]]
    stale = [i for i in loaded if i not in expected]
    add("kernel rules match config", _st(not missing and not stale),
        "%d expected, %d loaded" % (sum(expected.values()), sum(loaded.values()))
        + ("; missing/incomplete: " + ", ".join(missing) if missing else "")
        + ("; stale ids: " + ", ".join(stale) if stale else ""))
    rc, out = sh(["iptables", "-S", "FORWARD"])
    if rc == 0:
        policy = out.splitlines()[0] if out else "?"
        drop = "DROP" in policy
        add("FORWARD policy", "fail" if drop and not cfg.get("forward_accept", True) else "info",
            policy + (" - forward_accept must stay enabled" if drop else ""))
    rc, out = sh(["pve-firewall", "status"])
    add("pve-firewall", "info", out)
    listeners = host_listeners()
    for r in cfg["rules"]:
        if not r["enabled"]:
            continue
        ea, eb = parse_ports(r["ext_port"])
        for p, port in sorted(listeners):
            if p in protos(r["proto"]) and ea <= port <= eb:
                add("host port %s/%d" % (p, port), "warn",
                    "a host service listens here, but incoming traffic now goes to %s (rule '%s')" % (r["ip"], r["name"] or r["id"]))
    add("last apply", _st(not STATE["last_error"]), STATE["last_error"] or (
        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(STATE["last_apply"])) if STATE["last_apply"] else "never"))

    if cfg["domains"] or os.path.exists(nginx_conf_path(cfg)):
        rc, out = sh(["nginx", "-v"])
        add("nginx installed", _st(rc == 0), out if rc == 0 else "apt install nginx")
        rc, out = sh(["systemctl", "is-active", "nginx"])
        add("nginx running", _st(out.strip() == "active"), out.strip())
        add("nginx last apply", _st(not NGINX["last_error"]), NGINX["last_error"] or (
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(NGINX["last_apply"])) if NGINX["last_apply"] else "never"))
        rc, out = sh(["ss", "-Hlntp"])
        for line in out.splitlines() if rc == 0 else []:
            m = re.search(r":(80|443)\s", line)
            if m and "nginx" not in line:
                add("port %s" % m.group(1), "warn", "used by another program, not nginx: " + line.split()[-1])
        le = [d for d in cfg["domains"] if d["tls"] == "letsencrypt" and d["enabled"]]
        if le:
            rc, out = sh(["certbot", "--version"])
            add("certbot installed", _st(rc == 0), out if rc == 0 else "apt install certbot")
        for d in le:
            ci, job = cert_info(cfg, d), CERT_JOBS.get(d["id"])
            if ci["exists"]:
                add("certificate %s" % d["domain"], _st(ci.get("days", 0) >= 14, warn=True), "expires in %s days" % ci.get("days", "?"))
            else:
                add("certificate %s" % d["domain"], "warn" if job and job["state"] == "pending" else "fail",
                    job["msg"] if job else "not issued")
    return res


def conntrack_lines(ips):
    if not ips:
        return "(no enabled rules)"
    if not MOCK and os.path.exists("/proc/net/nf_conntrack"):
        try:
            with open("/proc/net/nf_conntrack") as f:
                lines = f.read().splitlines()
        except OSError as e:
            return str(e)
    else:
        rc, out = sh(["conntrack", "-L"])
        if rc == 127:
            return "(conntrack table not readable: apt install conntrack)"
        lines = out.splitlines()
    pats = ["src=%s " % ip for ip in ips] + ["dst=%s " % ip for ip in ips]
    hits = [line for line in lines if any(p in line + " " for p in pats)]
    return "\n".join(hits[-200:]) or "(no tracked connections to forwarded guests)"


def sections():
    cfg = STATE["cfg"]

    def ours(table):
        rc, out = sh(["iptables-save", "-c", "-t", table])
        return "\n".join(line for line in out.splitlines() if "PORTFWD" in line) or "(none loaded)" if rc == 0 else out

    safe_cfg = dict(cfg, pass_hash="***" if cfg.get("pass_hash") else "")
    return [
        {"title": "Service log", "text": "\n".join(LOGS) or "(empty)", "open": True},
        {"title": "Generated ruleset (iptables-restore input)", "text": build_ruleset(cfg)},
        {"title": "Loaded rules: nat [packets:bytes]", "text": ours("nat")},
        {"title": "Loaded rules: filter [packets:bytes]", "text": ours("filter")},
        {"title": "iptables -t nat PREROUTING", "text": sh(["iptables", "-t", "nat", "-L", "PREROUTING", "-n", "-v", "--line-numbers"])[1]},
        {"title": "iptables -t nat POSTROUTING", "text": sh(["iptables", "-t", "nat", "-L", "POSTROUTING", "-n", "-v", "--line-numbers"])[1]},
        {"title": "iptables FORWARD", "text": sh(["iptables", "-L", "FORWARD", "-n", "-v", "--line-numbers"])[1]},
        {"title": "Tracked connections to forwarded guests", "text": conntrack_lines(sorted({r["ip"] for r in cfg["rules"] if r["enabled"]}))},
        {"title": "Interfaces", "text": sh(["ip", "-4", "-br", "addr"])[1]},
        {"title": "Routes", "text": sh(["ip", "-4", "route"])[1]},
        {"title": "Listening sockets on host", "text": sh(["ss", "-Hlntup"])[1]},
        {"title": "Config " + conf_file(), "text": json.dumps(safe_cfg, indent=2)},
    ] + ([
        {"title": "nginx config " + cfg["nginx_conf"], "text": _read(nginx_conf_path(cfg)) or "(not written yet)"},
        {"title": "nginx -t", "text": sh(["nginx", "-t"])[1]},
        {"title": "certbot certificates", "text": sh(["certbot", "certificates"], timeout=30)[1]},
    ] if cfg["domains"] or os.path.exists(nginx_conf_path(cfg)) else [])


def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def diagnostics():
    return {"version": VERSION, "host": socket.gethostname(), "verbose": VERBOSE, "dry_run": DRY_RUN,
            "mock": MOCK.scenarios() if MOCK else None,
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"), "checks": checks(), "sections": sections()}


def fmt_steps(steps):
    return "\n".join("[%-4s] %s%s" % (s["status"].upper(), s["name"],
                                      (" - " + s["detail"].replace("\n", "\n         ")) if s["detail"] else "")
                     for s in steps)


def report_text(d):
    out = ["pve-portfwd %s debug report | host %s | %s%s" % (
        d["version"], d["host"], d["generated"], " | DRY RUN" if d["dry_run"] else " | MOCK" if d["mock"] else ""),
        "", fmt_steps(d["checks"])]
    for s in d["sections"][1:] + d["sections"][:1]:  # log last
        out += ["", "===== %s =====" % s["title"], s["text"]]
    return "\n".join(out) + "\n"


def tcp_probe(ip, port):
    """('ok'|'refused'|'timeout'|error text, ms)"""
    if MOCK:
        return MOCK.tcp_probe(ip, port)
    s = socket.socket()
    s.settimeout(3)
    t = time.time()
    try:
        s.connect((ip, port))
        return "ok", (time.time() - t) * 1000
    except ConnectionRefusedError:
        return "refused", 0
    except socket.timeout:
        return "timeout", 0
    except OSError as e:
        return str(e), 0
    finally:
        s.close()


def test_rule(r):
    """Step-by-step reachability check for one rule, run from the host."""
    steps = []

    def add(name, status, detail=""):
        steps.append({"name": name, "status": status, "detail": detail})

    ip = r["ip"]
    ea, _ = parse_ports(r["ext_port"])
    port = int(r["int_port"] or ea)
    add("rule enabled", _st(r["enabled"]), "" if r["enabled"] else "rule is disabled - nothing is forwarded")
    n = loaded_rule_ids().get(r["id"], 0)
    add("loaded in iptables", _st(n == len(protos(r["proto"])) or not r["enabled"]),
        "%d DNAT entr%s in %s" % (n, "y" if n == 1 else "ies", CH_PRE))
    add("ip_forward", _st(ip_forward_on()))

    rc, out = sh(["ip", "route", "get", ip])
    src = re.search(r"\bsrc (\S+)", out or "")
    if rc != 0:
        add("route to guest", "fail", out)
    else:
        via = " via " in out
        add("route to guest", "warn" if via and not r["masq"] else "ok", out.splitlines()[0].strip() + (
            "" if not via else "\nguest is behind a gateway - Masquerade is on, so replies come back through this host"
            if r["masq"] else "\nguest is behind a gateway, not on a local bridge - replies may bypass this host; try Masquerade"))

    rc, out = sh(["ping", "-c", "1", "-W", "1", ip], timeout=5)
    add("ping guest", _st(rc == 0, warn=True),
        "reply received" if rc == 0 else "no reply (guest down, wrong IP, or ICMP blocked)")

    if "tcp" in protos(r["proto"]):
        name = "TCP connect %s:%d from host" % (ip, port)
        res, ms = tcp_probe(ip, port)
        if res == "ok":
            add(name, "ok", "connected in %dms - service is listening" % ms)
        elif res == "refused":
            add(name, "fail", "connection refused - guest is up but nothing listens on port %d (or its firewall rejects)" % port)
        elif res == "timeout":
            add(name, "fail", "timeout - guest down, wrong IP, or the guest's firewall drops port %d" % port)
        else:
            add(name, "fail", res)
    if "udp" in protos(r["proto"]):
        add("UDP", "info", "UDP can't be verified with a connect test - check the service on the guest")

    c = counters().get(r["id"])
    add("traffic counter", "info", "%d connection(s), %d bytes matched since rules were loaded" % tuple(c) if c and c[0] else
        "no traffic has hit this rule yet - if tests from outside fail, check that your router / ISP / "
        "cloud firewall sends port %s to this host" % r["ext_port"])
    if not r["masq"]:
        add("return path", "info", "without Masquerade the guest's default gateway must be this host%s"
            % (" (%s)" % src.group(1) if src else ""))
    return steps


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
        log("%s %s" % (self.client_address[0], fmt % args), "debug")

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
            if path == "/api/authinfo" and method == "GET":
                cfg = STATE["cfg"]
                local = bool(cfg.get("pass_hash"))
                return self.send(200, {"mode": "local" if local else "pve", "mock": bool(MOCK),
                                       "user": cfg.get("local_user", "admin") if local else "root@pam"})
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
                "ifaces": list_ifaces(), "dry_run": DRY_RUN, "mock": bool(MOCK),
                "status": {"ip_forward": ip_forward_on(), "active": DRY_RUN or hooks_active(),
                           "last_apply": STATE["last_apply"], "last_error": STATE["last_error"]},
                "domains": cfg["domains"], "domain_status": domain_status(cfg), "acme_email": cfg.get("acme_email", ""),
                "nginx": {"last_apply": NGINX["last_apply"], "last_error": NGINX["last_error"]},
            })
        if path == "/api/guests" and method == "GET":
            return self.send(200, {"guests": list_guests()})
        if path == "/api/apply" and method == "POST":
            err = apply_rules() or apply_nginx()
            if err:
                raise ApiError(err, 500)
            return self.send(200, {"ok": True})
        if path == "/api/debug" and method == "GET":
            return self.send(200, diagnostics())
        if path == "/api/debug/report" and method == "GET":
            return self.send(200, report_text(diagnostics()), "text/plain")
        if path == "/api/debug" and method == "POST":
            global VERBOSE
            VERBOSE = bool(self.body().get("verbose"))
            log("verbose logging %s by %s" % ("enabled" if VERBOSE else "disabled", user))
            return self.send(200, {"verbose": VERBOSE})
        if path == "/api/mock" and method == "POST":
            if not MOCK:
                raise ApiError("only available with --mock", 404)
            name = str(self.body().get("scenario", ""))
            try:
                desc = MOCK.scenario(name)
            except ValueError as e:
                raise ApiError(str(e))
            log("mock scenario '%s': %s" % (name, desc), "warn")
            return self.send(200, {"ok": True, "message": desc})
        m = re.match(r"^/api/domains/([0-9a-f]{1,16})/(test|cert)$", path)
        if m and method == "POST":
            dom = next((d for d in cfg["domains"] if d["id"] == m.group(1)), None)
            if not dom:
                raise ApiError("domain not found", 404)
            if m.group(2) == "test":
                return self.send(200, {"steps": test_domain(dom)})
            if dom["tls"] != "letsencrypt" or not dom["enabled"]:
                raise ApiError("domain is disabled or does not use Let's Encrypt")
            CERT_JOBS.pop(dom["id"], None)
            issue_cert(dom["id"])
            return self.send(200, {"ok": True})
        m = re.match(r"^/api/domains(?:/([0-9a-f]{1,16}))?$", path)
        if m:
            return self.domains_api(method, m.group(1), cfg, user)
        m = re.match(r"^/api/rules/([0-9a-f]{1,16})/test$", path)
        if m and method == "POST":
            rule = next((r for r in cfg["rules"] if r["id"] == m.group(1)), None)
            if not rule:
                raise ApiError("rule not found", 404)
            return self.send(200, {"steps": test_rule(rule)})

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


    def domains_api(self, method, did, cfg, user):
        with LOCK:
            domains = list(cfg["domains"])
            idx = next((i for i, d in enumerate(domains) if d["id"] == did), None) if did else None
            if did and idx is None:
                raise ApiError("domain not found", 404)
            dom, body = None, {}
            if method in ("POST", "PUT") and (method == "POST") == (not did):
                body = self.body()
                dom = validate_domain(body, [d for d in domains if d["id"] != did], cfg, did)
                if idx is None:
                    domains.append(dom)
                else:
                    domains[idx] = dom
            elif method == "DELETE" and did:
                domains.pop(idx)
            else:
                raise ApiError("method not allowed", 405)
            new = dict(cfg, domains=domains)
            email = str(body.get("acme_email", "") or "").strip()
            if email:
                if not EMAIL_RE.match(email):
                    raise ApiError("invalid Let's Encrypt email")
                new["acme_email"] = email
            err = apply_nginx(new)  # validated with nginx -t, old config restored on failure
            if err:
                raise ApiError(err, 500)
            save_config(new)
            STATE["cfg"] = new
            log("%s %s domain %s" % (user, method, dom["domain"] if dom else did))
        if dom and dom["tls"] == "letsencrypt" and dom["enabled"]:
            issue_cert(dom["id"])  # no-op for certbot if the cert already covers these names
        return self.send(200, {"ok": True})


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
            return ctx, cert, key
    return None, None, None


def cert_reloader(ctx, cert, key):
    """Pick up renewed certificates (e.g. Proxmox ACME/Let's Encrypt) without a restart."""
    def mtime():
        try:
            return os.stat(cert).st_mtime, os.stat(key).st_mtime
        except OSError:
            return None
    last = mtime()
    while True:
        time.sleep(300)
        cur = mtime()
        if cur and cur != last:
            try:
                ctx.load_cert_chain(cert, key)  # new connections use the new cert
                last = cur
                log("reloaded TLS certificate %s" % cert)
            except (OSError, ssl.SSLError) as e:
                log("certificate reload failed: %s" % e, "error")


def serve(cfg):
    apply_rules()
    apply_nginx()
    threading.Thread(target=watchdog, daemon=True).start()
    try:
        httpd = Server((cfg["listen"], int(cfg["port"])), Handler)
    except OSError as e:
        sys.exit("cannot listen on %s:%s: %s\n(is it already running? stop it, or use --port N)"
                 % (cfg["listen"], cfg["port"], e.strerror or e))
    ctx, cert, key = tls_context(cfg)
    if ctx:
        threading.Thread(target=cert_reloader, args=(ctx, cert, key), daemon=True).start()
        # handshake happens lazily in the worker thread, so a slow client can't block accept()
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=False)
        httpd.tls = True
    scheme = "https" if ctx else "http"
    log("listening on %s://%s:%s/%s" % (scheme, cfg["listen"], cfg["port"], " (cert %s)" % cert if cert else " (NO TLS!)"))
    if MOCK:
        log("MOCK MODE: simulated Proxmox host, state in %s" % MOCK.path)
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
    <p class="muted" id="loginHint">Sign in with your Proxmox account</p>
    <label>User<input name="username" autocomplete="username" value="root@pam" required></label>
    <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
    <button type="submit">Sign in</button>
    <p id="loginErr" class="err"></p>
  </form>
</div>
<div id="app" hidden>
  <header>
    <h1>Port Forwarding</h1>
    <nav class="tabs"><a href="#rules" data-view="rules">Ports</a><a href="#domains" data-view="domains">Domains</a><a href="#debug" data-view="debug">Debug</a></nav>
    <div id="status" class="chips"></div>
    <span class="spacer"></span>
    <span id="who" class="muted"></span>
    <button id="logout" class="ghost">Sign out</button>
  </header>
  <main id="view-rules">
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
  <main id="view-domains" hidden>
    <div class="bar">
      <button id="addDomBtn">+ Add domain</button>
      <span id="domMsg"></span>
    </div>
    <div id="nginxErr" class="card banner" hidden></div>
    <div class="card scroll">
      <table>
        <thead><tr><th>On</th><th>Domain</th><th></th><th>Upstream</th><th>TLS</th><th>Allowed</th><th></th></tr></thead>
        <tbody id="domains"></tbody>
      </table>
      <p id="domEmpty" class="muted pad" hidden>No domains yet. Point a DNS A record at this host, then click <b>+ Add domain</b>.</p>
    </div>
    <p class="muted small">nginx on this host answers on ports 80/443 and proxies each domain to a guest
      (<code>/etc/nginx/conf.d/pve-portfwd.conf</code>). With Let's Encrypt, certbot gets and renews certificates automatically.
      DNS must point at this host's public IP, and if the host is behind a router, the router must forward ports 80 and 443 to it.</p>
  </main>
  <main id="view-debug" hidden>
    <div class="bar">
      <button id="dbgRefresh">Refresh</button>
      <button id="dbgCopy" class="ghost">Copy report</button>
      <button id="dbgDownload" class="ghost">Download report</button>
      <label class="check inline"><input type="checkbox" id="dbgVerbose"> Verbose logging (every iptables command + request)</label>
      <span id="dbgMsg" class="muted small"></span>
    </div>
    <div id="mockBar" class="card mockbar" hidden>
      <b>Mock host</b><span class="muted small">Break the simulated host on purpose and see what the checks report:</span>
      <div id="mockBtns" class="mockbtns"></div>
    </div>
    <div class="card"><ul id="checks" class="checks"></ul></div>
    <div id="sections"></div>
    <p class="muted small">CLI on the host: <code>pve-portfwd status</code>, <code>pve-portfwd test [rule]</code>,
      <code>pve-portfwd debug</code>, <code>pve-portfwd -v serve</code>, <code>journalctl -u pve-portfwd -f</code></p>
  </main>
</div>

<dialog id="domDlg">
  <form id="domForm" class="form">
    <h2 id="domTitle">Add domain</h2>
    <div class="grid">
      <label class="wide">Domain<input name="domain" required placeholder="cloud.example.com" autocapitalize="off" spellcheck="false"></label>
      <label class="wide">Aliases<input name="aliases" placeholder="www.example.com (optional, space separated)" autocapitalize="off" spellcheck="false"></label>
      <label class="wide">Guest<select name="guest"><option value="">— pick a guest to fill its IP —</option></select></label>
      <label>Upstream IP<input name="ip" required placeholder="10.10.10.10"></label>
      <label>Upstream port<input name="port" required value="80" inputmode="numeric"></label>
      <label class="check wide"><input type="checkbox" name="upstream_https"> Upstream uses HTTPS (self-signed certificates are accepted)</label>
      <label>HTTPS<select name="tls"><option value="letsencrypt">Let's Encrypt (automatic)</option><option value="none">None (HTTP only)</option></select></label>
      <label class="le">Let's Encrypt email<input name="acme_email" type="email" placeholder="expiry notices (optional)"></label>
      <label class="check wide le"><input type="checkbox" name="force_https" checked> Redirect HTTP to HTTPS</label>
      <label>Max upload size<input name="max_body" value="100m" placeholder="100m, 2g, 0 = unlimited"></label>
      <label>Allowed sources<input name="source" placeholder="anyone (or 203.0.113.0/24 …)"></label>
      <label class="check wide"><input type="checkbox" name="enabled" checked> Enabled</label>
    </div>
    <p id="domErr" class="err"></p>
    <div class="actions"><button type="button" id="domCancel" class="ghost">Cancel</button><button type="submit">Save</button></div>
  </form>
</dialog>

<dialog id="testDlg">
  <h2 id="testTitle">Test</h2>
  <ul id="testSteps" class="checks"></ul>
  <p class="muted small">Tests run on the Proxmox host itself. They show whether the host and guest side work,
    not whether your router, ISP or DNS sends outside traffic here. Watch the port hit counters for that.</p>
  <div class="actions"><button type="button" id="testAgain" class="ghost">Run again</button><button type="button" id="testClose">Close</button></div>
</dialog>

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
.tabs{display:flex;gap:2px;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:2px}
.tabs a{padding:4px 12px;border-radius:6px;color:var(--muted);text-decoration:none;font-weight:600;font-size:13px}
.tabs a.on{background:var(--card);color:var(--fg);box-shadow:0 1px 2px rgba(0,0,0,.12)}
label.check.inline{display:inline-flex;align-items:center;margin-left:4px}label.check.inline input{margin:0}
.checks{list-style:none;margin:0;padding:4px 0}
.checks li{display:flex;gap:10px;align-items:flex-start;padding:8px 14px;border-bottom:1px solid var(--line)}
.checks li:last-child{border-bottom:none}
.checks .d{color:var(--muted);font-size:12px;white-space:pre-wrap;word-break:break-word}
.pill{flex:none;min-width:44px;text-align:center;font-size:11px;font-weight:700;padding:2px 6px;border-radius:5px;text-transform:uppercase;margin-top:1px}
.pill.ok{background:var(--ok-bg);color:var(--ok)}.pill.fail{background:var(--bad-bg);color:var(--bad)}
.pill.warn{background:var(--warn-bg);color:var(--warn)}.pill.info{background:var(--line);color:var(--muted)}
details.sec{margin-top:10px}
details.sec summary{cursor:pointer;padding:10px 14px;font-weight:600;list-style-position:inside}
details.sec pre{margin:0;padding:12px 14px;border-top:1px solid var(--line);overflow:auto;max-height:480px;
font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre}
#testDlg{width:min(640px,calc(100vw - 32px))}#testDlg .checks{border:1px solid var(--line);border-radius:8px;margin-bottom:10px}
.spin{color:var(--muted);padding:14px}
.banner{padding:10px 14px;margin-bottom:12px;color:var(--bad);border-color:var(--bad);white-space:pre-wrap;font-size:13px}
.names a{color:var(--fg);text-decoration:none;font-weight:500}.names a:hover{text-decoration:underline}
.names .alias{display:block;color:var(--muted);font-size:12px}
.mockbar{padding:12px 14px;margin-bottom:12px;display:flex;flex-direction:column;gap:6px;border-style:dashed;border-color:var(--warn)}
.mockbtns{display:flex;flex-wrap:wrap;gap:6px}.mockbtns button{padding:4px 10px;font-size:12px}
@media (max-width:560px){.grid{grid-template-columns:1fr}header,main{padding-left:16px;padding-right:16px}}
"""

APP_JS = r"""
'use strict';
const $ = s => document.querySelector(s);
let S = {rules: [], counters: {}, ifaces: []}, guests = null, editing = null, timer = null, view = 'rules', testing = null;

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
  fetch('/api/authinfo').then(r => r.json()).then(a => {
    $('#loginForm').username.value = a.user;
    $('#loginHint').textContent = a.mock ? 'Mock mode (simulated host): admin / admin'
      : a.mode === 'local' ? 'Sign in with the local pve-portfwd account' : 'Sign in with your Proxmox account';
  }).catch(() => {});
}

async function load() {
  S = await api('GET', '/api/state');
  $('#login').hidden = true; $('#app').hidden = false;
  render();
  if (!load.started) { load.started = true; setView(); }
  if (!timer) timer = setInterval(() => {
    if (!document.hidden && view !== 'debug' && !$('#dlg').open && !$('#domDlg').open && !$('#testDlg').open) load().catch(() => {});
  }, 5000);
}

function render() {
  renderDomains();
  $('#who').textContent = S.user;
  const st = $('#status'); st.replaceChildren();
  const chip = (cls, t, title) => st.append(el('span', {class: 'chip ' + cls, textContent: t, title: title || ''}));
  if (S.dry_run) chip('warn', 'DRY RUN', 'iptables commands are only printed');
  if (S.mock) chip('warn', 'MOCK', 'simulated Proxmox host - nothing real is touched');
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
        el('button', {class: 'link', textContent: 'Test', onclick: () => runTest(r)}),
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

async function fillGuests(sel = $('#ruleForm').guest) {
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

// ---- domains
function tlsCell(d) {
  const st = (S.domain_status || {})[d.id] || {}, job = st.job, cert = st.cert;
  if (d.tls !== 'letsencrypt') return el('span', {class: 'tag', textContent: 'http only'});
  if (job && job.state === 'pending') return el('span', {class: 'chip warn', textContent: 'issuing…'});
  if (cert && cert.exists) return el('span', {class: 'chip ' + (cert.days < 14 ? 'warn' : 'ok'),
    textContent: 'https · ' + cert.days + 'd', title: 'certificate expires in ' + cert.days + ' days (auto-renewed)'});
  if (job && job.state === 'error') return el('span', {class: 'chip bad', textContent: 'cert error', title: job.msg});
  return el('span', {class: 'chip bad', textContent: 'no certificate'});
}

function renderDomains() {
  const tb = $('#domains'), ds = S.domains || [];
  tb.replaceChildren();
  $('#domEmpty').hidden = ds.length > 0;
  const ne = $('#nginxErr'); ne.hidden = !(S.nginx && S.nginx.last_error); ne.textContent = ne.hidden ? '' : S.nginx.last_error;
  for (const d of ds) {
    tb.append(el('tr', {class: d.enabled ? '' : 'off'},
      el('td', {}, el('input', {type: 'checkbox', class: 'switch', checked: d.enabled, title: d.enabled ? 'Disable' : 'Enable',
        onchange: e => saveDomain(d.id, Object.assign({}, d, {enabled: e.target.checked}))})),
      el('td', {class: 'names'}, el('a', {href: (d.tls === 'letsencrypt' ? 'https://' : 'http://') + d.domain, target: '_blank', rel: 'noopener', textContent: d.domain}),
        ...d.aliases.map(a => el('span', {class: 'alias', textContent: a}))),
      el('td', {class: 'arrow', textContent: '→'}),
      el('td', {class: 'mono', textContent: (d.upstream_https ? 'https://' : 'http://') + d.ip + ':' + d.port}),
      el('td', {}, tlsCell(d)),
      el('td', {class: 'mono', textContent: d.source.length ? d.source.join(', ') : 'anyone'}),
      el('td', {class: 'num'},
        el('button', {class: 'link', textContent: 'Test', onclick: () => runTestUrl('Test: ' + d.domain + ' → ' + d.ip + ':' + d.port, '/api/domains/' + d.id + '/test')}),
        d.tls === 'letsencrypt' ? el('button', {class: 'link', textContent: 'Cert', title: 'Request / renew certificate now', onclick: () => cert(d)}) : null,
        el('button', {class: 'link', textContent: 'Edit', onclick: () => openDomDlg(d)}),
        el('button', {class: 'link del', textContent: 'Delete', onclick: () => delDomain(d)}))));
  }
}

function domFlash(t, isErr) {
  const m = $('#domMsg'); m.textContent = t; m.style.color = isErr ? 'var(--bad)' : 'var(--muted)';
  clearTimeout(domFlash.t); domFlash.t = setTimeout(() => m.textContent = '', isErr ? 10000 : 4000);
}

async function saveDomain(id, data) {
  try { await api(id ? 'PUT' : 'POST', id ? '/api/domains/' + id : '/api/domains', data); domFlash('Saved, nginx reloaded'); }
  catch (e) { domFlash(e.message, true); }
  load().catch(() => {});
}

async function delDomain(d) {
  if (!confirm('Delete domain "' + d.domain + '"? (its certificate is kept)')) return;
  try { await api('DELETE', '/api/domains/' + d.id); domFlash('Deleted'); } catch (e) { domFlash(e.message, true); }
  load().catch(() => {});
}

async function cert(d) {
  try { await api('POST', '/api/domains/' + d.id + '/cert', {}); domFlash('Requesting certificate for ' + d.domain + '…'); }
  catch (e) { domFlash(e.message, true); }
  load().catch(() => {});
}

let editingDom = null;
function openDomDlg(d) {
  editingDom = d ? d.id : null;
  const f = $('#domForm');
  $('#domTitle').textContent = d ? 'Edit domain' : 'Add domain';
  $('#domErr').textContent = '';
  d = d || {tls: 'letsencrypt', force_https: true, enabled: true, port: 80, max_body: '100m', aliases: [], source: []};
  f.domain.value = d.domain || ''; f.aliases.value = (d.aliases || []).join(' ');
  f.ip.value = d.ip || ''; f.port.value = d.port || 80; f.upstream_https.checked = !!d.upstream_https;
  f.tls.value = d.tls; f.force_https.checked = d.force_https !== false; f.max_body.value = d.max_body || '100m';
  f.source.value = (d.source || []).join(' '); f.enabled.checked = d.enabled !== false;
  f.acme_email.value = S.acme_email || '';
  toggleLe();
  $('#domDlg').showModal();
  f.domain.focus();
  fillGuests(f.guest);
}
function toggleLe() { const le = $('#domForm').tls.value === 'letsencrypt'; for (const x of document.querySelectorAll('#domForm .le')) x.hidden = !le; }
$('#domForm').tls.addEventListener('change', toggleLe);
$('#domForm').upstream_https.addEventListener('change', e => {
  const p = $('#domForm').port; if (e.target.checked && p.value === '80') p.value = '443'; else if (!e.target.checked && p.value === '443') p.value = '80';
});
$('#domForm').guest.addEventListener('change', e => { if (e.target.value) $('#domForm').ip.value = e.target.value; });
$('#domForm').addEventListener('submit', async e => {
  e.preventDefault();
  const f = e.target, d = {};
  for (const k of ['domain', 'aliases', 'ip', 'port', 'tls', 'max_body', 'source', 'acme_email']) d[k] = f[k].value.trim();
  d.upstream_https = f.upstream_https.checked; d.force_https = f.force_https.checked; d.enabled = f.enabled.checked;
  const btn = f.querySelector('button[type=submit]'); btn.disabled = true;
  try {
    await api(editingDom ? 'PUT' : 'POST', editingDom ? '/api/domains/' + editingDom : '/api/domains', d);
    $('#domDlg').close();
    domFlash(d.tls === 'letsencrypt' && d.enabled ? 'Saved - requesting certificate in the background…' : 'Saved, nginx reloaded');
    load().catch(() => {});
  } catch (err) { $('#domErr').textContent = err.message; }
  btn.disabled = false;
});
$('#domCancel').onclick = () => $('#domDlg').close();
$('#addDomBtn').onclick = () => openDomDlg(null);

// ---- checks list (debug tab + rule test)
function renderChecks(ul, items) {
  ul.replaceChildren(...items.map(c => el('li', {},
    el('span', {class: 'pill ' + c.status, textContent: c.status}),
    el('div', {}, el('div', {textContent: c.name}), c.detail ? el('div', {class: 'd', textContent: c.detail}) : null))));
}

async function runTestUrl(title, url) {
  testing = [title, url];
  $('#testTitle').textContent = title;
  $('#testSteps').replaceChildren(el('li', {class: 'spin', textContent: 'Running checks…'}));
  if (!$('#testDlg').open) $('#testDlg').showModal();
  try { renderChecks($('#testSteps'), (await api('POST', url, {})).steps); }
  catch (e) { renderChecks($('#testSteps'), [{status: 'fail', name: 'test failed', detail: e.message}]); }
}
const runTest = r => runTestUrl('Test: ' + (r.name || r.id) + '  (' + r.proto + '/' + r.ext_port + ' → ' + r.ip + ':' + (r.int_port || r.ext_port) + ')',
  '/api/rules/' + r.id + '/test');
$('#testAgain').onclick = () => testing && runTestUrl(...testing);
$('#testClose').onclick = () => $('#testDlg').close();

// ---- debug view
async function loadDebug() {
  const b = $('#dbgRefresh'); b.disabled = true; $('#dbgMsg').textContent = 'collecting…';
  load().catch(() => {});  // keep header badges current
  try {
    const d = await api('GET', '/api/debug');
    $('#dbgVerbose').checked = d.verbose;
    $('#mockBar').hidden = !d.mock;
    if (d.mock) $('#mockBtns').replaceChildren(...Object.entries(d.mock).map(([k, desc]) =>
      el('button', {class: 'ghost', textContent: k, title: desc, onclick: async () => {
        try { const r = await api('POST', '/api/mock', {scenario: k}); $('#dbgMsg').textContent = k + ': ' + r.message; }
        catch (e) { $('#dbgMsg').textContent = e.message; }
        setTimeout(loadDebug, 300);
      }})));
    renderChecks($('#checks'), d.checks);
    const open = new Set([...document.querySelectorAll('details.sec[open]')].map(x => x.dataset.t));
    $('#sections').replaceChildren(...d.sections.map(sec => {
      const det = el('details', {class: 'sec card', open: open.size ? open.has(sec.title) : !!sec.open},
        el('summary', {textContent: sec.title}), el('pre', {textContent: sec.text}));
      det.dataset.t = sec.title;
      return det;
    }));
    const log = document.querySelector('details.sec pre'); if (log) log.scrollTop = log.scrollHeight;
    const n = k => d.checks.filter(c => c.status === k).length;
    $('#dbgMsg').textContent = d.generated + ' · ' + n('fail') + ' failed, ' + n('warn') + ' warnings';
  } catch (e) { $('#dbgMsg').textContent = e.message; }
  b.disabled = false;
}

async function reportText() {
  const r = await fetch('/api/debug/report', {credentials: 'same-origin'});
  if (!r.ok) throw new Error('report failed: ' + r.status);
  return r.text();
}
$('#dbgRefresh').onclick = loadDebug;
$('#dbgCopy').onclick = async () => {
  try { await navigator.clipboard.writeText(await reportText()); $('#dbgMsg').textContent = 'Report copied to clipboard'; }
  catch (e) { $('#dbgMsg').textContent = 'Copy failed (' + e.message + '), use Download'; }
};
$('#dbgDownload').onclick = async () => {
  try {
    const url = URL.createObjectURL(new Blob([await reportText()], {type: 'text/plain'}));
    const a = el('a', {href: url, download: 'pve-portfwd-debug-' + new Date().toISOString().slice(0, 19).replace(/:/g, '') + '.txt'});
    document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (e) { $('#dbgMsg').textContent = e.message; }
};
$('#dbgVerbose').onchange = async e => {
  try { await api('POST', '/api/debug', {verbose: e.target.checked}); loadDebug(); }
  catch (err) { e.target.checked = !e.target.checked; $('#dbgMsg').textContent = err.message; }
};

function setView() {
  view = {'#debug': 'debug', '#domains': 'domains'}[location.hash] || 'rules';
  for (const a of document.querySelectorAll('.tabs a')) a.classList.toggle('on', a.dataset.view === view);
  for (const v of ['rules', 'domains', 'debug']) $('#view-' + v).hidden = view !== v;
  if ($('#app').hidden) return;
  if (view === 'debug') loadDebug(); else load().catch(() => {});
}
window.addEventListener('hashchange', setView);

load().catch(() => {});
"""

STATIC = {
    "/": ("text/html", INDEX_HTML),
    "/app.css": ("text/css", APP_CSS),
    "/app.js": ("application/javascript", APP_JS),
}


# --------------------------------------------------------------------------- main

def start_mock(here):
    global MOCK
    import importlib.util
    path = os.path.join(here, "dev", "mock.py")
    if not os.path.exists(path):
        sys.exit("--mock needs %s (it is only in the source tree, not installed on hosts)" % path)
    spec = importlib.util.spec_from_file_location("pve_portfwd_mock", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    MOCK = mod.Mock(CONF_DIR, socket.gethostname().split(".")[0])


def main():
    global DRY_RUN, CONF_DIR, VERBOSE
    ap = argparse.ArgumentParser(
        description="Port forwarding web UI for Proxmox VE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""commands:
  serve            run the web UI (default)
  status           rules, hit counters and hook status
  test [NAME...]   reachability test per rule or domain (id, name, host port or domain; default: all)
  debug            full diagnostic report (paste this when asking for help)
  show             print the generated iptables-restore payload
  apply            re-apply saved rules
  flush            remove all forwarding rules and chains (config is kept)
  passwd           set a local login instead of Proxmox accounts
  domains          list domains, upstreams and certificates
  cert DOMAIN      request / renew the Let's Encrypt certificate now
  mock SCENARIO    (--mock only) break the simulated host: %s

local development (macOS etc.):
  ./pve-portfwd.py --mock         simulated Proxmox host, http://127.0.0.1:8099, login admin / admin""" % (
            "reset, unhook, ip-forward-off, forward-drop, pvefw-first, foreign-dnat, traffic"))
    ap.add_argument("cmd", nargs="?", default="serve",
                    choices=["serve", "status", "test", "debug", "show", "apply", "flush", "passwd", "mock",
                             "domains", "cert"])
    ap.add_argument("rules", nargs="*", help=argparse.SUPPRESS)
    ap.add_argument("-v", "--verbose", action="store_true", help="log every iptables command and HTTP request")
    ap.add_argument("--dry-run", action="store_true", help="log iptables changes instead of running them")
    ap.add_argument("--mock", action="store_true", help="simulate a Proxmox host (for local development, uses dev/mock.py)")
    ap.add_argument("--config-dir", help="default: %s (with --mock: ./.dev)" % CONF_DIR)
    ap.add_argument("--port", type=int, help="override listen port")
    a = ap.parse_args()
    DRY_RUN, VERBOSE = a.dry_run and not a.mock, a.verbose
    here = os.path.dirname(os.path.abspath(__file__))
    CONF_DIR = a.config_dir or (os.path.join(here, ".dev") if a.mock else CONF_DIR)

    if a.mock:
        start_mock(here)
    elif a.cmd == "mock":
        sys.exit("the 'mock' command needs --mock")
    elif not DRY_RUN and hasattr(os, "geteuid") and os.geteuid() != 0 and a.cmd != "show":
        sys.exit("must run as root (needs iptables); use --dry-run to preview or --mock to simulate")

    fresh = not os.path.exists(conf_file())
    cfg = load_config()
    if MOCK and fresh:
        for r in MOCK.sample_rules():
            cfg["rules"].append(validate_rule(r, cfg["rules"], cfg))
        for d in MOCK.sample_domains():
            cfg["domains"].append(validate_domain(d, cfg["domains"], cfg))
        cfg["acme_email"] = "admin@example.com"
    if a.port:
        cfg["port"] = a.port
    if MOCK:
        cfg["listen"] = "127.0.0.1"
        if not cfg.get("pass_hash"):
            cfg["local_user"], cfg["pass_hash"] = "admin", hash_password("admin")
        if fresh or not os.path.exists(conf_file()):
            save_config(cfg)
    STATE["cfg"] = cfg

    if a.cmd == "show":
        sys.stdout.write(build_ruleset(cfg))
    elif a.cmd == "apply":
        sys.exit(1 if apply_rules() or apply_nginx() else 0)
    elif a.cmd == "domains":
        if not cfg["domains"]:
            print("no domains (add them in the web UI)")
        fmt = "%-9s %-3s %-40s %-28s %s"
        if cfg["domains"]:
            print(fmt % ("ID", "ON", "DOMAIN", "UPSTREAM", "TLS"))
        for d in cfg["domains"]:
            tls = "http only"
            if d["tls"] == "letsencrypt":
                ci = cert_info(cfg, d)
                tls = "LE: expires in %s days" % ci.get("days", "?") if ci["exists"] else "LE: no certificate yet"
            print(fmt % (d["id"], "yes" if d["enabled"] else "no", " ".join(_names(d)),
                         "%s://%s:%d" % ("https" if d["upstream_https"] else "http", d["ip"], d["port"]), tls))
    elif a.cmd == "cert":
        d = next((x for x in cfg["domains"] if a.rules and a.rules[0] in (x["id"], x["domain"])), None)
        if not d:
            sys.exit("usage: cert DOMAIN (one of: %s)" % ", ".join(x["domain"] for x in cfg["domains"] if x["tls"] == "letsencrypt"))
        issue_cert(d["id"])
        while CERT_JOBS.get(d["id"], {}).get("state") == "pending":
            time.sleep(0.5)
        job = CERT_JOBS.get(d["id"]) or {"state": "error", "msg": "domain is disabled or not using Let's Encrypt"}
        print("%s: %s" % (job["state"], job["msg"]))
        sys.exit(0 if job["state"] == "ok" else 1)
    elif a.cmd == "status":
        cnt = counters()
        print("hooks: %s   ip_forward: %s   rules: %d (%d enabled)%s" % (
            "active" if DRY_RUN or hooks_active() else "MISSING (run: pve-portfwd apply)",
            "on" if ip_forward_on() else "OFF", len(cfg["rules"]), sum(r["enabled"] for r in cfg["rules"]),
            "   [dry-run]" if DRY_RUN else "   [mock]" if MOCK else ""))
        if cfg["rules"]:
            fmt = "%-9s %-3s %-6s %-12s %-31s %-18s %-8s %s"
            print("\n" + fmt % ("ID", "ON", "PROTO", "HOST PORT", "DESTINATION", "SOURCE", "IFACE", "HITS"))
            for r in cfg["rules"]:
                c = cnt.get(r["id"])
                print(fmt % (r["id"], "yes" if r["enabled"] else "no", r["proto"], r["ext_port"],
                             "%s:%s%s" % (r["ip"], r["int_port"] or r["ext_port"], " (masq)" if r["masq"] else ""),
                             r["source"] or "any", r["iface"] or "any",
                             "%d pkts / %d B" % tuple(c) if c else "-") + ("   " + r["name"] if r["name"] else ""))
    elif a.cmd == "test":
        sel = [r for r in cfg["rules"] if (r["id"] in a.rules or r["name"] in a.rules or r["ext_port"] in a.rules)
               or (not a.rules and r["enabled"])]
        dsel = [d for d in cfg["domains"] if (d["id"] in a.rules or set(_names(d)) & set(a.rules))
                or (not a.rules and d["enabled"])]
        if not sel and not dsel:
            sys.exit("nothing matched" + (" (give a rule id, name, host port or domain)" if a.rules else ""))
        failed = False
        for d in dsel:
            steps = test_domain(d)
            failed |= any(s["status"] == "fail" for s in steps)
            print("== %s -> %s:%d ==" % (" ".join(_names(d)), d["ip"], d["port"]))
            print(fmt_steps(steps) + "\n")
        for r in sel:
            steps = test_rule(r)
            failed |= any(s["status"] == "fail" for s in steps)
            print("== %s  %s/%s -> %s:%s ==" % (r["name"] or r["id"], r["proto"], r["ext_port"], r["ip"], r["int_port"] or r["ext_port"]))
            print(fmt_steps(steps) + "\n")
        sys.exit(1 if failed else 0)
    elif a.cmd == "debug":
        sys.stdout.write(report_text(diagnostics()))
    elif a.cmd == "mock":
        if not a.rules:
            sys.exit("usage: --mock mock SCENARIO\n" + "\n".join("  %-15s %s" % kv for kv in MOCK.scenarios().items()))
        try:
            print(MOCK.scenario(a.rules[0]))
        except ValueError as e:
            sys.exit(str(e))
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
