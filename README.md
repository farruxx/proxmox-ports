# pve-portfwd

A small web UI that runs on a Proxmox VE host and forwards ports from the host to VMs and containers.

- **No dependencies.** It's one Python 3 file using only the standard library, and it drives `iptables`. Both already ship with Proxmox VE 7 and 8.
- **Login with your Proxmox account.** Credentials are checked against the local PVE API, and only `root@pam` is allowed by default. You can switch to a local password instead.
- **HTTPS out of the box.** It reuses the Proxmox certificate (`/etc/pve/local/pveproxy-ssl.*` or `pve-ssl.*`).
- **Safe to run next to other rules.** Everything lives in its own chains (`PORTFWD_PRE`, `PORTFWD_POST`, `PORTFWD_FWD`), which are swapped atomically with `iptables-restore`. pve-firewall and your own rules are left alone.
- **Guest picker.** It lists local VMs and CTs with their IPs (from the QEMU guest agent or the LXC config).
- Supports TCP, UDP or both, port ranges, a source IP/CIDR allow-list, an incoming interface, optional masquerade, and shows per-rule hit counters.
- **Guard rails.** It refuses to forward 22, 8006, 3128, 111, 5405-5412 or its own port. Only traffic **addressed to the host** is forwarded (`-m addrtype --dst-type LOCAL`), so guests' outgoing traffic is never hijacked.
- A watchdog re-hooks the chains if something flushes iptables, and rules are restored at boot.

## Install (on the Proxmox host, as root)

```bash
scp pve-portfwd.py pve-portfwd.service install.sh root@pve:/root/pve-portfwd/
```

```bash
cd /root/pve-portfwd && sh install.sh
```

Then open `https://<proxmox-ip>:8099` and log in as `root@pam`.

To use the **Domains** tab (reverse proxy by hostname), install nginx and certbot as well. They are the only optional dependencies, both from Debian:

```bash
sh install.sh --with-nginx
```

## Domains (nginx reverse proxy)

The **Domains** tab maps hostnames to guests: `cloud.example.com` → `10.10.10.13:80`, `git.example.com` → `https://10.10.10.10:443`, and so on. nginx on the host answers on ports 80 and 443 and proxies each request by its `Host` header, so many guests can share one public IP and the same ports.

- Everything goes into a single generated file, `/etc/nginx/conf.d/pve-portfwd.conf`. Other nginx sites are left alone. Each change is checked with `nginx -t` before reload; if the check fails, the previous file is restored and the error is shown in the UI.
- **Let's Encrypt** (optional, per domain) uses `certbot certonly --webroot`. The certificate is requested in the background right after saving, and certbot's own systemd timer renews it, reloading nginx through a deploy hook. *Cert* re-requests it on demand, and *Test* checks DNS, nginx, the upstream, the certificate and a real request through nginx.
- **Per domain options:** aliases (extra hostnames), an HTTPS upstream (self-signed certificates are accepted), redirect HTTP to HTTPS, max upload size, and allowed source IPs/CIDRs. WebSockets always work.
- **Requirements:** each domain's DNS A record must point to the host's public IP. If the host sits behind a router, the router has to forward TCP 80 and 443 to it.
- While any domain is enabled, port-forward rules can't take TCP 80 or 443, because those ports belong to nginx. The reverse is enforced too.

### Wildcard certificates (`*.example.com`)

One certificate covers `example.com` and every `*.example.com` subdomain. Let's Encrypt only issues wildcards through a **DNS-01** check, so certbot creates a TXT record through your DNS provider's API. Port 80 doesn't have to be reachable for this.

1. Install the certbot plugin for your provider (they're all Debian packages):

   ```bash
   apt install python3-certbot-dns-cloudflare
   ```

2. Go to **Domains → Wildcard certificates → + Add wildcard** and enter the zone (`example.com`), the provider and the API token. It is issued right away (~30 s).
3. For each domain, choose **HTTPS: Wildcard certificate (DNS)**. The matching certificate is picked automatically, so a new subdomain is on HTTPS immediately.

| Provider | Package | Credentials |
|---|---|---|
| Cloudflare | `python3-certbot-dns-cloudflare` | API token with *Zone / DNS / Edit* |
| DigitalOcean | `python3-certbot-dns-digitalocean` | API token |
| Linode / Akamai | `python3-certbot-dns-linode` | API token |
| DNSimple | `python3-certbot-dns-dnsimple` | API token |
| OVH | `python3-certbot-dns-ovh` | endpoint + application key/secret + consumer key |
| RFC 2136 (BIND, PowerDNS, Knot) | `python3-certbot-dns-rfc2136` | server, TSIG key name/secret/algorithm |

- **Coverage:** a wildcard covers one level only. `*.example.com` matches `a.example.com` but not `a.b.example.com`; for that you'd add a wildcard for `b.example.com`.
- **Credentials** are written to `/etc/pve-portfwd/dns/<id>.ini` (mode 0600, directory 0700). They're never returned by the API or included in the debug report. When editing, an empty field keeps the stored value.
- **Renewal:** certbot's timer renews wildcards through the same DNS plugin. A wildcard that domains still use can't be deleted or disabled.

## Typical setup

Guests sit on a private bridge (for example `vmbr1`, `10.10.10.0/24`), and the host does NAT for them. Add a rule like:

| Host port | Destination | Meaning |
|---|---|---|
| `8080` | `10.10.10.10:80` | `http://<host-ip>:8080` reaches VM 100's web server |
| `27015-27020` TCP+UDP | `10.10.10.12` | port range, same ports on the guest |

**Masquerade** is only needed if the guest's default gateway is *not* the Proxmox host, or if other guests need to reach the service through the host's public IP (hairpin NAT). Note that with masquerade on, the guest sees the host's IP instead of the real client IP.

## CLI

```
pve-portfwd serve           # web UI (what systemd runs)
pve-portfwd status          # rules, hit counters, hook status
pve-portfwd test [NAME...]  # reachability test (rule id/name/host port or domain; default: all enabled)
pve-portfwd domains         # list domains, wildcard certificates and expiry
pve-portfwd cert NAME       # request / renew now: a domain, or '*.example.com' for a wildcard
pve-portfwd debug           # full diagnostic report, paste it when asking for help
pve-portfwd show            # print the generated iptables-restore payload
pve-portfwd apply           # re-apply saved rules
pve-portfwd flush           # remove all forwarding rules/chains (config kept)
pve-portfwd passwd          # use a local user/password instead of Proxmox login
pve-portfwd -v ...          # verbose: log every iptables command and HTTP request
pve-portfwd --dry-run ...   # log iptables commands instead of running them (for testing)
```

## Debugging

**Debug tab** in the web UI:
- **Health checks:** root, iptables, `ip_forward`, whether each hook exists and where it sits in its chain, whether the kernel rules match the config, FORWARD policy, pve-firewall status, and host services listening on a forwarded port.
- **Raw output:** the generated ruleset, the loaded `PORTFWD_*` rules with packet/byte counters, the full PREROUTING/POSTROUTING/FORWARD chains, tracked connections to the guests, interfaces, routes, listening sockets, and the config (password hash hidden).
- **Service log:** the last 500 lines kept in memory, plus a *Verbose logging* switch that takes effect immediately without a restart.
- **Copy report / Download report:** gives you the same text as `pve-portfwd debug`.

**Test** button on each rule (or `pve-portfwd test`): runs from the host and checks:
- the rule is loaded
- `ip_forward` is on
- the route to the guest (and whether it goes through a gateway)
- a ping to the guest
- a TCP connect to the guest port, which tells refused (nothing listening) apart from timeout (guest down or firewalled)
- the rule's hit counter

The tests check the guest side only. If the counter stays at 0 while you test from outside, traffic never reaches the host, so check your router, ISP or cloud firewall.

Service logs: `journalctl -u pve-portfwd -f`. To keep verbose logging on permanently, change `ExecStart` in the unit to `... pve-portfwd -v serve`.

## Local development (macOS)

`--mock` runs everything against a simulated Proxmox host. It needs no root, no iptables and no Proxmox. The mock fakes `iptables`, `iptables-restore`/`-save`, `ip`, `ping`, `ss`, `conntrack`, `pve-firewall`, `pvesh`, `qm`, `pct` and `lxc-info`. The mock code lives in [`dev/mock.py`](dev/mock.py) and is never installed on a host.

```bash
./dev.sh
```

Open http://127.0.0.1:8099 and log in as **admin / admin**.

You can run any CLI command against the same simulated host. The web UI and CLI share state through `.dev/mock-state.json`:

```bash
./dev.sh status
```
```bash
./dev.sh test
```
```bash
./dev.sh debug
```

To break the host on purpose, run a scenario. They're also available as buttons on the Debug tab:

```bash
./dev.sh mock unhook
```

| Scenario | What it does |
|---|---|
| `unhook` | removes our jump rules. The checks fail, and the watchdog repairs it within 10 s |
| `ip-forward-off` | sets `net.ipv4.ip_forward = 0` |
| `forward-drop` | sets the FORWARD policy to DROP |
| `pvefw-first` | moves pve-firewall's jump above ours (warning) |
| `foreign-dnat` | puts another DNAT rule above our hook (warning) |
| `traffic` | sends a burst of hits to the counters |
| `nginx-stopped` | stops nginx, so domain tests fail |
| `nginx-test-fails` | makes the next `nginx -t` fail, showing the rollback |
| `cert-expiring` | makes every certificate expire in 5 days |
| `reset` | wipes the simulated iptables |

The simulated guests are 100 web, 101 db, 102 game (stopped), 103 nextcloud, 104 win11 (no guest agent, ignores ping) and 105 office-gw (behind a gateway). The sample rules show every test outcome. The sample domains are `cloud.example.com` (HTTPS working), `app.example.com` (HTTP only, with an alias) and `broken.invalid` (no DNS and nothing listening upstream). The sample wildcard is `*.example.com` (Cloudflare), used by `status.example.com`. The mock certbot fails for names ending in `.invalid` and succeeds after 2 s for everything else. For wildcards, the API token `bad` gets Cloudflare's "invalid credentials" error, and only the Cloudflare, DigitalOcean and RFC 2136 plugins count as installed, so OVH shows the "plugin missing" message. Generated nginx files end up under `.dev/mock-fs/`. Delete `.dev/` to start over.

`--dry-run` is different. It's meant for a **real** host: read-only commands run for real, and changes are only logged.

## Config: `/etc/pve-portfwd/config.json`

Rules are stored here too. Restart the service after editing it by hand.

```json
{
  "listen": "0.0.0.0",
  "port": 8099,
  "allowed_users": ["root@pam"],
  "protected_ports": ["22", "8006", "3128", "111", "5405-5412"],
  "forward_accept": true
}
```

- `allowed_users`: Proxmox users allowed to log in. Accounts with TFA enabled aren't supported; use `passwd` instead.
- `forward_accept`: adds narrow `ACCEPT` rules in `FORWARD` for the forwarded flows. They're inserted before `PVEFW-FORWARD`, so if the Proxmox firewall is on for a guest, a forwarded port bypasses that guest's firewall. Use the rule's *Allowed source* field to restrict access.
- `listen`: set it to a LAN IP (e.g. `192.168.1.10`) to keep the UI off the public interface.

## Trusted HTTPS (Let's Encrypt)

Out of the box Proxmox uses a self-signed certificate, so browsers show a warning on both `:8006` and `:8099`. Give Proxmox a real certificate and pve-portfwd uses it too. Renewals are picked up within 5 minutes, with no restart needed.

Here's an example for a domain on Cloudflare DNS. It uses a DNS-01 challenge, so port 80 doesn't need to be open. Create a Cloudflare API token with *Zone → DNS → Edit* for the zone, then run on the host:

```bash
pvenode acme account register default you@example.com --directory https://acme-v02.api.letsencrypt.org/directory
printf 'CF_Token=<token>\n' > /root/cf.env
pvenode acme plugin add dns cloudflare --api cf --data /root/cf.env && rm /root/cf.env
pvenode config set --acmedomain0 proxm.example.com,plugin=cloudflare
pvenode acme cert order
```

## Uninstall

```bash
sh install.sh uninstall
```
