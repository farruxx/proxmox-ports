"""
Simulated Proxmox host for local development (macOS, or anywhere without iptables / root).

Loaded only with `pve-gateway.py --mock`; never installed on the real host.

Fakes: iptables, iptables-restore, iptables-save, ip, ping, ss, conntrack,
pve-firewall, pvesh, qm, pct, lxc-info, plus net.ipv4.ip_forward and TCP probes.
The fake "kernel" state lives in <config-dir>/mock-state.json, so the web UI
and CLI commands (status / test / debug / flush / mock ...) all see the same thing.
"""
import json
import os
import random
import re
import threading
import time

HOST_IP, BRIDGE_IP, PUBLIC_IP = "192.168.1.50", "10.10.10.1", "203.0.113.10"

# ports = what the guest listens on; agent = QEMU guest agent installed
GUESTS = [
    {"vmid": 100, "name": "web", "type": "qemu", "status": "running", "ip": "10.10.10.10", "ports": [80, 443], "agent": True},
    {"vmid": 101, "name": "db", "type": "lxc", "status": "running", "ip": "10.10.10.11", "ports": [22, 5432]},
    {"vmid": 102, "name": "game", "type": "qemu", "status": "stopped", "ip": "10.10.10.12", "ports": [27015], "agent": True},
    {"vmid": 103, "name": "nextcloud", "type": "lxc", "status": "running", "ip": "10.10.10.13", "ports": [80]},
    {"vmid": 104, "name": "win11", "type": "qemu", "status": "running", "ip": "10.10.10.14", "ports": [3389], "agent": False,
     "no_ping": True},
    {"vmid": 105, "name": "office-gw", "type": "qemu", "status": "running", "ip": "192.168.50.20", "ports": [443], "agent": True},
]

SCENARIOS = {
    "reset": "fresh host: empty iptables, ip_forward on (rules are re-applied by the running server)",
    "unhook": "delete our jump rules, like `iptables -F PREROUTING` would (watchdog repairs it)",
    "ip-forward-off": "set net.ipv4.ip_forward = 0",
    "forward-drop": "set FORWARD policy to DROP",
    "pvefw-first": "move pve-firewall's jump above ours in FORWARD",
    "foreign-dnat": "insert someone else's DNAT rule at the top of PREROUTING",
    "traffic": "simulate a burst of incoming connections on all rules",
    "nginx-stopped": "stop nginx (domains stop answering)",
    "nginx-test-fails": "make the next `nginx -t` fail (shows the automatic rollback)",
    "cert-expiring": "make all certificates expire in 5 days",
}

# rules seeded into a fresh ./.dev config, chosen to show every test outcome
SAMPLE_RULES = [
    {"name": "web", "proto": "tcp", "ext_port": "8080", "ip": "10.10.10.10", "int_port": "80"},
    {"name": "db ssh", "proto": "tcp", "ext_port": "2222", "ip": "10.10.10.11", "int_port": "22", "source": "203.0.113.0/24"},
    {"name": "game", "proto": "both", "ext_port": "27015-27020", "ip": "10.10.10.12"},                # guest stopped
    {"name": "nextcloud tls", "proto": "tcp", "ext_port": "8443", "ip": "10.10.10.13", "int_port": "443"},  # refused
    {"name": "rdp", "proto": "tcp", "ext_port": "3389", "ip": "10.10.10.14", "iface": "vmbr0"},    # no ping, tcp ok
    {"name": "office", "proto": "tcp", "ext_port": "9443", "ip": "192.168.50.20", "int_port": "443", "masq": True},
    {"name": "old test", "proto": "udp", "ext_port": "5000", "ip": "10.10.10.10", "enabled": False},
]

# domains seeded into a fresh ./.dev config
SAMPLE_DOMAINS = [
    {"domain": "cloud.example.com", "ip": "10.10.10.13", "port": 80, "tls": "letsencrypt", "max_body": "10g"},  # cert ok
    {"domain": "app.example.com", "aliases": "www.app.example.com", "ip": "10.10.10.10", "port": 80, "tls": "none"},
    {"domain": "broken.invalid", "ip": "10.10.10.11", "port": 8080, "tls": "letsencrypt"},  # no DNS, nothing on 8080
    {"domain": "status.example.com", "ip": "10.10.10.10", "port": 80, "tls": "wildcard"},  # uses *.example.com
]

# wildcard certificates seeded into a fresh ./.dev config (token "bad" makes the mock DNS API reject it)
SAMPLE_WILDCARDS = [
    {"zone": "example.com", "provider": "cloudflare", "credentials": {"dns_cloudflare_api_token": "mock-token"}},
]

# certbot DNS plugins "installed" on the mock host (others report as missing)
DNS_PLUGINS = ["dns-cloudflare", "dns-digitalocean", "dns-rfc2136"]

TARGETS = {"ACCEPT", "DROP", "REJECT", "RETURN", "DNAT", "SNAT", "MASQUERADE", "LOG"}

SS_LINES = [
    ("tcp", "LISTEN", "0.0.0.0:22", 'users:(("sshd",pid=1021,fd=3))'),
    ("tcp", "LISTEN", "0.0.0.0:111", 'users:(("rpcbind",pid=812,fd=4))'),
    ("tcp", "LISTEN", "127.0.0.1:25", 'users:(("master",pid=1290,fd=13))'),
    ("tcp", "LISTEN", "127.0.0.1:85", 'users:(("pvedaemon",pid=1410,fd=6))'),
    ("tcp", "LISTEN", "*:3128", 'users:(("spiceproxy",pid=1502,fd=6))'),
    ("tcp", "LISTEN", "*:8006", 'users:(("pveproxy",pid=1488,fd=6))'),
    ("tcp", "LISTEN", "0.0.0.0:8099", 'users:(("python3",pid=2211,fd=3))'),
    ("tcp", "LISTEN", "0.0.0.0:9100", 'users:(("node_exporter",pid=990,fd=3))'),
    ("udp", "UNCONN", "0.0.0.0:111", 'users:(("rpcbind",pid=812,fd=5))'),
    ("udp", "UNCONN", "%s:5405" % HOST_IP, 'users:(("corosync",pid=1150,fd=27))'),
]


def default_state():
    return {
        "ip_forward": True,
        "tables": {
            "nat": {
                "policy": {"PREROUTING": "ACCEPT", "INPUT": "ACCEPT", "OUTPUT": "ACCEPT", "POSTROUTING": "ACCEPT"},
                "chains": {"PREROUTING": [], "INPUT": [], "OUTPUT": [],
                           "POSTROUTING": ["-s 10.10.10.0/24 -o vmbr0 -j MASQUERADE"]},
            },
            "filter": {
                "policy": {"INPUT": "ACCEPT", "FORWARD": "ACCEPT", "OUTPUT": "ACCEPT"},
                "chains": {"INPUT": ["-j PVEFW-INPUT"], "FORWARD": ["-j PVEFW-FORWARD"], "OUTPUT": ["-j PVEFW-OUTPUT"],
                           "PVEFW-INPUT": [], "PVEFW-OUTPUT": [],
                           "PVEFW-FORWARD": ["-m conntrack --ctstate INVALID -j DROP",
                                             "-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"]},
            },
        },
        "counters": {},  # "table|chain|rule" -> [packets, bytes]
        "nginx_active": True,
        "nginx_test_fail": False,
        "issued": {"cloud.example.com": {"names": ["cloud.example.com"], "expires": time.time() + 61 * 86400},
                   "wildcard.example.com": {"names": ["example.com", "*.example.com"], "expires": time.time() + 75 * 86400}},
    }


def _guest(ip):
    return next((g for g in GUESTS if g["ip"] == ip), None)


def _opt(rule, flag):
    m = re.search(r"(?:^| )%s (\S+)" % re.escape(flag), rule)
    return m.group(1) if m else None


class Mock:
    def __init__(self, conf_dir, node):
        self.path = os.path.join(conf_dir, "mock-state.json")
        self.root = os.path.join(conf_dir, "mock-fs")
        self.node = node
        self.lock = threading.RLock()
        os.makedirs(conf_dir, exist_ok=True)
        if not os.path.exists(self.path):
            self._save(default_state())

    # ------------------------------------------------------------------ state
    def _load(self):
        try:
            with open(self.path) as f:
                st = json.load(f)
        except (OSError, ValueError):
            return default_state()
        for k, v in default_state().items():  # state files from older versions
            st.setdefault(k, v)
        return st

    def _save(self, st):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(st, f, indent=1)
        os.replace(tmp, self.path)

    @property
    def ip_forward(self):
        return self._load()["ip_forward"]

    @ip_forward.setter
    def ip_forward(self, value):
        with self.lock:
            st = self._load()
            st["ip_forward"] = bool(value)
            self._save(st)

    def path_for(self, real_path):
        """Map a real host path (e.g. /etc/nginx/conf.d/x.conf) into the mock filesystem under .dev."""
        return os.path.join(self.root, real_path.lstrip("/"))

    def sample_wildcards(self):
        return [dict(w) for w in SAMPLE_WILDCARDS]

    def sample_domains(self):
        return [dict(d) for d in SAMPLE_DOMAINS]

    def resolve(self, name):
        return [] if name.endswith(".invalid") or name.startswith("nodns.") else [PUBLIC_IP]

    def http_check(self, host, tls):
        """Answer a request through the simulated nginx by reading the generated config."""
        if not self._load().get("nginx_active", True):
            return 0, "[Errno 111] Connection refused"
        conf = self._nginx_conf()
        for block in re.split(r"\nserver \{", conf)[1:]:
            names = re.search(r"server_name ([^;]+);", block)
            if not names or host not in names.group(1).split() or ("listen 443" in block) != tls:
                continue
            if "return 301" in block:
                return 301, "301 Moved Permanently -> https://%s/" % host
            m = re.search(r"proxy_pass https?://([\d.]+):(\d+);", block)
            res, _ = self.tcp_probe(m.group(1), int(m.group(2)))
            return (200, "200 OK") if res == "ok" else (502, "502 Bad Gateway")
        return 404, "404 Not Found - no server block for this host, nginx's default site answered"

    def _nginx_conf(self):
        d = self.path_for("/etc/nginx/conf.d")
        out = ""
        for f in sorted(os.listdir(d)) if os.path.isdir(d) else []:
            if f.endswith(".conf"):
                with open(os.path.join(d, f)) as fh:
                    out += fh.read()
        return out

    def sample_rules(self):
        return [dict(r) for r in SAMPLE_RULES]

    def scenarios(self):
        return dict(SCENARIOS)

    def ifaces(self):
        return ["enp3s0", "vmbr0", "vmbr1"]

    def tcp_probe(self, ip, port):
        """('ok'|'refused'|'timeout', ms) for a TCP connect from the host."""
        g = _guest(ip)
        if not g or g["status"] != "running":
            return "timeout", 3000
        return ("ok" if port in g["ports"] else "refused"), random.randint(1, 6)

    def scenario(self, name):
        if name not in SCENARIOS:
            raise ValueError("unknown scenario '%s' (available: %s)" % (name, ", ".join(SCENARIOS)))
        with self.lock:
            st = default_state() if name == "reset" else self._load()
            nat, flt = st["tables"]["nat"]["chains"], st["tables"]["filter"]["chains"]
            if name == "unhook":
                for chains in (nat, flt):
                    for c in ("PREROUTING", "POSTROUTING", "FORWARD"):
                        if c in chains:
                            chains[c] = [r for r in chains[c] if not r.startswith("-j PVEGW_")]
            elif name == "ip-forward-off":
                st["ip_forward"] = False
            elif name == "forward-drop":
                st["tables"]["filter"]["policy"]["FORWARD"] = "DROP"
            elif name == "pvefw-first":
                flt["FORWARD"] = ["-j PVEFW-FORWARD"] + [r for r in flt["FORWARD"] if r != "-j PVEFW-FORWARD"]
            elif name == "foreign-dnat":
                nat["PREROUTING"].insert(0, "-p tcp -m tcp --dport 8443 -j DNAT --to-destination 10.10.10.99:443")
            elif name == "traffic":
                self._bump(st, burst=True)
            elif name == "nginx-stopped":
                st["nginx_active"] = False
            elif name == "nginx-test-fails":
                st["nginx_test_fail"] = True
            elif name == "cert-expiring":
                for c in st["issued"].values():
                    c["expires"] = time.time() + 5 * 86400 + 3600
            self._save(st)
        return SCENARIOS[name]

    # ------------------------------------------------------------------ dispatch
    def exec(self, cmd, data=None):
        cmd = list(cmd)
        if cmd[:1] == ["timeout"]:
            cmd = cmd[2:]
        fn = getattr(self, "c_" + cmd[0].replace("-", "_"), None)
        if not fn:
            return 127, "(mock) command not found: %s" % cmd[0]
        with self.lock:
            st = self._load()
            rc, out, changed = fn(st, cmd[1:], data)
            if changed:
                self._save(st)
        time.sleep(0.005)
        return rc, out

    # ------------------------------------------------------------------ iptables
    def _hooked(self, st, table, chain, target):
        return ("-j " + target) in st["tables"][table]["chains"].get(chain, [])

    def _bump(self, st, burst=False):
        """Fake incoming traffic on our DNAT rules (only if they'd really be hit)."""
        if not self._hooked(st, "nat", "PREROUTING", "PVEGW_PRE"):
            return
        for rule in st["tables"]["nat"]["chains"].get("PVEGW_PRE", []):
            to = (_opt(rule, "--to-destination") or "").split(":")[0]
            g = _guest(to)
            if not g or g["status"] != "running" or (not burst and random.random() < 0.5):
                continue
            pk = random.randint(20, 80) if burst else random.randint(1, 4)
            c = st["counters"].setdefault("nat|PVEGW_PRE|" + rule, [0, 0])
            c[0] += pk
            c[1] += pk * random.randint(52, 1400)

    def c_iptables(self, st, a, data):
        if a == ["--version"]:
            return 0, "iptables v1.8.9 (nf_tables)  [mock]", False
        table = "filter"
        if a[:1] == ["-t"]:
            table, a = a[1], a[2:]
        if table not in st["tables"]:
            return 3, "iptables v1.8.9 (nf_tables): table '%s' does not exist" % table, False
        t = st["tables"][table]
        chains = t["chains"]
        op, chain = a[0], (a[1] if len(a) > 1 and not a[1].startswith("-") else None)
        if chain and chain not in chains:
            return 1, "iptables: No chain/target/match by that name.", False

        if op == "-S":
            out = []
            for c in ([chain] if chain else chains):
                out.append("-P %s %s" % (c, t["policy"][c]) if c in t["policy"] else "-N " + c)
            for c in ([chain] if chain else chains):
                out += ["-A %s %s" % (c, r) for r in chains[c]]
            return 0, "\n".join(out), False
        if op == "-L":
            return 0, self._list(st, table, chain), False
        if op in ("-C", "-D", "-I"):
            rest = a[2:]
            pos = 1
            if op == "-I" and rest and rest[0].isdigit():
                pos, rest = int(rest[0]), rest[1:]
            rule = " ".join(rest)
            target = _opt(rule, "-j")
            if target not in TARGETS and target not in chains:
                return 2, "iptables v1.8.9 (nf_tables): Chain '%s' does not exist" % target, False
            if op == "-I":
                chains[chain].insert(pos - 1, rule)
                return 0, "", True
            if rule not in chains[chain]:
                return 1, "iptables: Bad rule (does a matching rule exist in that chain?).", False
            if op == "-D":
                chains[chain].remove(rule)
                return 0, "", True
            return 0, "", False
        if op == "-F":
            chains[chain] = []
            st["counters"] = {k: v for k, v in st["counters"].items() if not k.startswith("%s|%s|" % (table, chain))}
            return 0, "", True
        if op == "-X":
            if chain in t["policy"]:
                return 1, "iptables: can't delete built-in chain", False
            if chains[chain] or any(("-j " + chain) in r for rs in chains.values() for r in rs):
                return 1, "iptables v1.8.9 (nf_tables): CHAIN_USER_DEL failed (Device or resource busy): chain %s" % chain, False
            del chains[chain]
            return 0, "", True
        return 2, "(mock) unsupported iptables call: %s" % " ".join(a), False

    def _list(self, st, table, chain):
        t = st["tables"][table]
        if chain in t["policy"]:
            head = "Chain %s (policy %s 0 packets, 0 bytes)" % (chain, t["policy"][chain])
        else:
            refs = sum(r.endswith("-j " + chain) for rs in t["chains"].values() for r in rs)
            head = "Chain %s (%d references)" % (chain, refs)
        out = [head, "num      pkts      bytes target         prot opt in     out     source               destination"]
        for i, r in enumerate(t["chains"][chain], 1):
            pk, by = st["counters"].get("%s|%s|%s" % (table, chain, r), [0, 0])
            extra = re.sub(r"(^| )(-[pjiosd]) \S+", "", r).strip()
            out.append("%-4d %9d %10d %-14s %-4s --  %-6s %-7s %-20s %-20s %s" % (
                i, pk, by, _opt(r, "-j"), _opt(r, "-p") or "all", _opt(r, "-i") or "*", _opt(r, "-o") or "*",
                _opt(r, "-s") or "0.0.0.0/0", _opt(r, "-d") or "0.0.0.0/0", extra))
        return "\n".join(out)

    def c_iptables_save(self, st, a, data):
        counts = "-c" in a
        tables = [a[a.index("-t") + 1]] if "-t" in a else list(st["tables"])
        if counts:
            self._bump(st)
        out = ["# Generated by iptables-save v1.8.9 (mock) on %s" % time.ctime()]
        for tn in tables:
            t = st["tables"][tn]
            out.append("*" + tn)
            out += [":%s %s [0:0]" % (c, t["policy"].get(c, "-")) for c in t["chains"]]
            for c, rules in t["chains"].items():
                for r in rules:
                    pk, by = st["counters"].get("%s|%s|%s" % (tn, c, r), [0, 0])
                    out.append(("[%d:%d] " % (pk, by) if counts else "") + "-A %s %s" % (c, r))
            out.append("COMMIT")
        return 0, "\n".join(out), counts

    def c_iptables_restore(self, st, a, data):
        new = json.loads(json.dumps(st))
        table = None
        for n, line in enumerate((data or "").splitlines(), 1):
            line = line.strip()
            fail = (1, "iptables-restore v1.8.9 (nf_tables): line %d failed: %s" % (n, line), False)
            if not line or line.startswith("#"):
                continue
            if line.startswith("*"):
                table = line[1:]
                if table not in new["tables"]:
                    return fail
            elif line == "COMMIT":
                table = None
            elif table is None:
                return fail
            elif line.startswith(":"):
                name = line[1:].split()[0]
                tb = new["tables"][table]
                tb["chains"][name] = []  # declared chains are flushed, even with --noflush
                new["counters"] = {k: v for k, v in new["counters"].items() if not k.startswith("%s|%s|" % (table, name))}
            else:
                m = re.match(r"^-A (\S+) (.+)$", line)
                chains = new["tables"][table]["chains"]
                if not m or m.group(1) not in chains:
                    return fail
                target = _opt(m.group(2), "-j")
                if target not in TARGETS and target not in chains:
                    return fail
                if line.count('"') % 2:
                    return fail
                chains[m.group(1)].append(m.group(2))
        if table is not None:
            return 1, "iptables-restore: COMMIT expected at line %d" % (n + 1), False
        st.clear()
        st.update(new)
        return 0, "", True

    # ------------------------------------------------------------------ network tools
    def c_ip(self, st, a, data):
        if a[:2] == ["route", "get"]:
            ip = a[2]
            if ip.startswith("10.10.10."):
                return 0, "%s dev vmbr1 src %s uid 0 \n    cache " % (ip, BRIDGE_IP), False
            if ip.startswith("192.168.50."):
                return 0, "%s via 10.10.10.254 dev vmbr1 src %s uid 0 \n    cache " % (ip, BRIDGE_IP), False
            if ip.startswith("192.168.1."):
                return 0, "%s dev vmbr0 src %s uid 0 \n    cache " % (ip, HOST_IP), False
            return 0, "%s via 192.168.1.1 dev vmbr0 src %s uid 0 \n    cache " % (ip, HOST_IP), False
        if "addr" in a:
            return 0, "\n".join([
                "lo               UNKNOWN        127.0.0.1/8",
                "enp3s0           UP             ",
                "vmbr0            UP             %s/24" % HOST_IP,
                "vmbr1            UP             %s/24" % BRIDGE_IP,
                "tap100i0         UNKNOWN        ",
                "veth101i0@if2    UP             ",
            ]), False
        if "route" in a:
            return 0, "\n".join([
                "default via 192.168.1.1 dev vmbr0 proto kernel onlink",
                "10.10.10.0/24 dev vmbr1 proto kernel scope link src %s" % BRIDGE_IP,
                "192.168.1.0/24 dev vmbr0 proto kernel scope link src %s" % HOST_IP,
                "192.168.50.0/24 via 10.10.10.254 dev vmbr1",
            ]), False
        return 1, "(mock) unsupported ip call", False

    def c_ping(self, st, a, data):
        ip = a[-1]
        g = _guest(ip)
        if g and g["status"] == "running" and not g.get("no_ping"):
            ms = random.uniform(0.15, 0.6)
            return 0, ("PING {0} ({0}) 56(84) bytes of data.\n64 bytes from {0}: icmp_seq=1 ttl=64 time={1:.3f} ms\n\n"
                       "--- {0} ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss, time 0ms").format(ip, ms), False
        return 1, ("PING {0} ({0}) 56(84) bytes of data.\n\n--- {0} ping statistics ---\n"
                   "1 packets transmitted, 0 received, 100% packet loss, time 0ms").format(ip), False

    def c_ss(self, st, a, data):
        procs = "p" in (a[0] if a else "")
        lines = list(SS_LINES)
        if st.get("nginx_active", True):
            lines += [("tcp", "LISTEN", "0.0.0.0:80", 'users:(("nginx",pid=3010,fd=6))'),
                      ("tcp", "LISTEN", "0.0.0.0:443", 'users:(("nginx",pid=3010,fd=8))')]
        return 0, "\n".join("%-5s %-6s 0      4096  %21s %21s %s" % (
            p, s, addr, "*:*" if addr.startswith("*") else "0.0.0.0:*", u if procs else "") for p, s, addr, u in lines), False

    # ------------------------------------------------------------------ nginx / certbot / systemd
    def c_nginx(self, st, a, data):
        if a == ["-v"]:
            return 0, "nginx version: nginx/1.22.1", False
        if a == ["-t"]:
            conf = self._nginx_conf()
            if st.get("nginx_test_fail"):
                st["nginx_test_fail"] = False
                return 1, ('nginx: [emerg] unknown directive "proxy_pas" in /etc/nginx/conf.d/pve-gateway.conf:42\n'
                           "nginx: configuration file /etc/nginx/nginx.conf test failed  [mock: nginx-test-fails]"), True
            if conf.count("{") != conf.count("}"):
                return 1, "nginx: [emerg] unexpected end of file, expecting \"}\" in /etc/nginx/conf.d/pve-gateway.conf", False
            for path in re.findall(r"ssl_certificate (\S+);", conf):
                if self._cert_name(path) not in st["issued"]:
                    return 1, ('nginx: [emerg] cannot load certificate "%s": BIO_new_file() failed\n'
                               "nginx: configuration file /etc/nginx/nginx.conf test failed" % path), False
            return 0, ("nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\n"
                       "nginx: configuration file /etc/nginx/nginx.conf test is successful"), False
        return 1, "(mock) unsupported nginx call", False

    def _dns01(self, a, names):
        """Simulate certbot's DNS plugin talking to the provider API. Returns error text or None."""
        auth = a[a.index("--authenticator") + 1]
        if auth not in DNS_PLUGINS:
            return "Could not choose appropriate plugin: The requested %s plugin does not appear to be installed" % auth
        cred = a[a.index("--%s-credentials" % auth) + 1]
        try:
            with open(cred) as f:
                text = f.read()
        except OSError:
            return "Error: File not found: %s" % cred
        if re.search(r"=\s*bad\s*$", text, re.M):
            return ("Encountered exception during recovery: certbot.errors.PluginError: Error determining zone_id: "
                    "6003 Invalid request headers. Please confirm that you have supplied valid Cloudflare API credentials. "
                    "(Did you copy your entire API token/key? To use Cloudflare tokens, you'll need the python package "
                    "cloudflare>=2.3.1. This certbot is running cloudflare 2.11.1)")
        zone = names[0]
        if zone.endswith(".invalid"):
            return ("Encountered exception during recovery: certbot.errors.PluginError: Unable to determine zone identifier "
                    "for %s using zone names: ['%s', 'invalid']" % (zone, zone))
        time.sleep(1)  # "Waiting 10 seconds for DNS changes to propagate"
        return None

    def c_systemctl(self, st, a, data):
        if a[-1] != "nginx":
            return 1, "(mock) only nginx is simulated", False
        if a[0] == "is-active":
            return (0, "active", False) if st.get("nginx_active", True) else (3, "inactive", False)
        if a[0] in ("reload", "reload-or-restart", "restart", "start"):
            if a[0] == "reload" and not st.get("nginx_active", True):
                return 1, "nginx.service is not active, cannot reload.", False
            st["nginx_active"] = True
            return 0, "", True
        return 1, "(mock) unsupported systemctl call", False

    def _cert_name(self, path):
        m = re.search(r"/live/([^/]+)/", path)
        return m.group(1) if m else ""

    def c_openssl(self, st, a, data):
        path = a[a.index("-in") + 1] if "-in" in a else ""
        c = st["issued"].get(self._cert_name(path))
        if not c:
            return 1, "Could not open file or uri for loading certificate from %s" % path, False
        return 0, "notAfter=" + time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(c["expires"])), False

    def c_certbot(self, st, a, data):
        if a == ["--version"]:
            return 0, "certbot 2.1.0", False
        if a[:1] == ["certificates"]:
            if not st["issued"]:
                return 0, "No certificates found.", False
            out = ["Found the following certs:"]
            for name, c in sorted(st["issued"].items()):
                days = int((c["expires"] - time.time()) // 86400)
                out += ["  Certificate Name: " + name, "    Domains: " + " ".join(c["names"]),
                        "    Expiry Date: %s (VALID: %d days)" % (time.strftime("%Y-%m-%d %H:%M:%S+00:00", time.gmtime(c["expires"])), days),
                        "    Certificate Path: /etc/letsencrypt/live/%s/fullchain.pem" % name]
            return 0, "\n".join(out), False
        if a[:1] == ["plugins"]:
            out = ["Saving debug log to /var/log/letsencrypt/letsencrypt.log", "- " * 40]
            for p in ["standalone", "webroot"] + DNS_PLUGINS:
                out += ["* " + p, "Description: (mock)", "Interfaces: Authenticator, Plugin", "- " * 40]
            return 0, "\n".join(out), False
        if a[:1] != ["certonly"]:
            return 1, "(mock) unsupported certbot call", False
        names = [a[i + 1] for i, x in enumerate(a) if x == "-d"]
        name = a[a.index("--cert-name") + 1]
        if "--authenticator" in a:
            err = self._dns01(a, names)
            if err:
                return 1, err, False
        time.sleep(2)  # ACME round trips take a moment
        bad = [n for n in names if self.resolve(n) == []]
        if bad:
            return 1, ("Saving debug log to /var/log/letsencrypt/letsencrypt.log\n"
                       "Certbot failed to authenticate some domains (authenticator: webroot). "
                       "The Certificate Authority reported these problems:\n"
                       "  Domain: %s\n  Type:   dns\n  Detail: DNS problem: NXDOMAIN looking up A for %s - "
                       "check that a DNS record exists for this domain\n\n"
                       "Hint: The Certificate Authority failed to download the temporary challenge files "
                       "created by the --webroot plugin.\nSome challenges have failed." % (bad[0], bad[0])), False
        cur = st["issued"].get(name)
        if cur and set(names) <= set(cur["names"]) and cur["expires"] - time.time() > 30 * 86400:
            return 0, "Certificate not yet due for renewal; no action taken.", False
        st["issued"][name] = {"names": names, "expires": time.time() + 90 * 86400}
        return 0, ("Successfully received certificate.\nCertificate is saved at: /etc/letsencrypt/live/%s/fullchain.pem\n"
                   "Key is saved at:         /etc/letsencrypt/live/%s/privkey.pem\n"
                   "Certbot has set up a scheduled task to automatically renew this certificate in the background." % (name, name)), True

    def c_conntrack(self, st, a, data):
        out = []
        for rule in st["tables"]["nat"]["chains"].get("PVEGW_PRE", []):
            if not st["counters"].get("nat|PVEGW_PRE|" + rule):
                continue
            proto, dport = _opt(rule, "-p"), (_opt(rule, "--dport") or "0").split(":")[0]
            to = _opt(rule, "--to-destination") or ""
            ip, _, tport = to.partition(":")
            for _ in range(random.randint(1, 3)):
                cli, sp = "203.0.113.%d" % random.randint(2, 250), random.randint(40000, 65000)
                state = "ESTABLISHED " if proto == "tcp" else ""
                out.append("%s      %d %d %ssrc=%s dst=%s sport=%d dport=%s src=%s dst=%s sport=%s dport=%d [ASSURED] mark=0 use=1"
                           % (proto, 6 if proto == "tcp" else 17, random.randint(100, 431999), state, cli, HOST_IP,
                              sp, dport, ip, cli, tport or dport, sp))
        return 0, "\n".join(out), False

    def c_pve_firewall(self, st, a, data):
        return 0, "Status: enabled/running", False

    # ------------------------------------------------------------------ proxmox tools
    def c_pvesh(self, st, a, data):
        return 0, json.dumps([{"id": "%s/%d" % (g["type"], g["vmid"]), "vmid": g["vmid"], "name": g["name"],
                               "type": g["type"], "status": g["status"], "node": self.node, "template": 0}
                              for g in GUESTS]), False

    def c_qm(self, st, a, data):
        vmid = int(a[2])
        g = next((x for x in GUESTS if x["vmid"] == vmid), None)
        if not g:
            return 2, "Configuration file 'nodes/%s/qemu-server/%d.conf' does not exist" % (self.node, vmid), False
        if g["status"] != "running":
            return 2, "VM %d is not running" % vmid, False
        if not g.get("agent"):
            return 2, "QEMU guest agent is not running", False
        return 0, json.dumps([
            {"name": "lo", "ip-addresses": [{"ip-address-type": "ipv4", "ip-address": "127.0.0.1", "prefix": 8}]},
            {"name": "eth0", "hardware-address": "bc:24:11:00:00:%02x" % (vmid % 256),
             "ip-addresses": [{"ip-address-type": "ipv4", "ip-address": g["ip"], "prefix": 24},
                              {"ip-address-type": "ipv6", "ip-address": "fe80::be24:11ff:fe00:%x" % vmid, "prefix": 64}]},
        ]), False

    def c_pct(self, st, a, data):
        g = next((x for x in GUESTS if x["vmid"] == int(a[1]) and x["type"] == "lxc"), None)
        if not g:
            return 2, "Configuration file does not exist", False
        return 0, ("arch: amd64\ncores: 2\nhostname: {name}\nmemory: 1024\n"
                   "net0: name=eth0,bridge=vmbr1,gw={gw},hwaddr=BC:24:11:00:01:{v:02X},ip={ip}/24,type=veth\n"
                   "ostype: debian\nrootfs: local-lvm:vm-{vmid}-disk-0,size=8G").format(
            name=g["name"], gw=BRIDGE_IP, v=g["vmid"] % 256, ip=g["ip"], vmid=g["vmid"]), False

    def c_lxc_info(self, st, a, data):
        g = next((x for x in GUESTS if str(x["vmid"]) == a[a.index("-n") + 1]), None)
        if not g or g["status"] != "running":
            return 1, "", False
        return 0, g["ip"], False
