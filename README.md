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

## Typical setup

Guests sit on a private bridge (for example `vmbr1`, `10.10.10.0/24`), and the host does NAT for them. Add a rule like:

| Host port | Destination | Meaning |
|---|---|---|
| `8080` | `10.10.10.10:80` | `http://<host-ip>:8080` reaches VM 100's web server |
| `27015-27020` TCP+UDP | `10.10.10.12` | port range, same ports on the guest |

**Masquerade** is only needed if the guest's default gateway is *not* the Proxmox host, or if other guests need to reach the service through the host's public IP (hairpin NAT). Note that with masquerade on, the guest sees the host's IP instead of the real client IP.

## CLI

```
pve-portfwd serve      # web UI (what systemd runs)
pve-portfwd apply      # re-apply saved rules
pve-portfwd show       # print the generated iptables-restore payload
pve-portfwd flush      # remove all forwarding rules/chains (config kept)
pve-portfwd passwd     # use a local user/password instead of Proxmox login
pve-portfwd --dry-run  # print iptables commands instead of running them (for testing)
```

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

## Uninstall

```bash
sh install.sh uninstall
```
