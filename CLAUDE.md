# CLAUDE.md

Guidance for AI-assisted work on **pve-gateway**: a web UI that runs on a Proxmox VE host. It forwards host ports to guests (iptables DNAT) and reverse-proxies domains to guests (nginx, with optional Let's Encrypt / wildcard certificates).

## Hard constraints

- **No third-party dependencies.** Only the Python 3 standard library, plus tools that ship with Proxmox (`iptables`, `ip`, `ss`, `pvesh`, `qm`, `pct`). nginx and certbot (and certbot DNS plugins) are the only optional system packages, installed with `apt`. Never add pip packages, npm, build steps or CDN assets.
- **Python 3.9 compatible.** PVE 7 ships 3.9 and macOS dev uses 3.9. That rules out `match`, `X | Y` types, `str.removeprefix` and other 3.10+ features.
- **One deployable file.** `pve-gateway.py` is what `install.sh` copies to `/usr/local/bin/pve-gateway`. The HTML, CSS and JS are embedded in it as `INDEX_HTML`, `APP_CSS` and `APP_JS` and served from `STATIC`. Don't split them into separate files.
- **`dev/mock.py` and `dev.sh` are dev-only** and are never installed. Production code must not import the mock except through `start_mock()` behind `--mock`.

## Layout

| Path | Purpose |
|---|---|
| `pve-gateway.py` | Everything: config, validation, iptables, nginx/certbot, diagnostics, auth, HTTP API, embedded UI, CLI |
| `dev/mock.py` | Simulated Proxmox host (iptables, ip, ss, ping, conntrack, pvesh, qm, pct, nginx, certbot, openssl, systemctl, DNS) |
| `dev.sh` | `python3 pve-gateway.py --mock "$@"` |
| `install.sh` | Installs on a PVE host (`--with-nginx`, `uninstall`) |
| `pve-gateway.service` | systemd unit |
| `README.md`, `wildcard.md` | User docs; keep them in sync with behavior changes |

`pve-gateway.py` is organised into sections marked `# ---- <name>`: config, validation, iptables, guests/interfaces, domains (nginx), diagnostics, auth, HTTP, UI, main. Keep new code in the matching section.

## Run and verify

```bash
./dev.sh                      # mock host: http://127.0.0.1:8099, admin / admin, state in ./.dev
./dev.sh status               # any CLI command against the same mock state
./dev.sh test | debug | domains | show | apply
./dev.sh mock <scenario>      # break the mock host: unhook, ip-forward-off, forward-drop, pvefw-first,
                              # foreign-dnat, traffic, nginx-stopped, nginx-test-fails, cert-expiring, reset
rm -rf .dev                   # start over with fresh sample rules/domains/wildcards
```

There is no test suite. After changes:

1. `python3 -m py_compile pve-gateway.py dev/mock.py`
2. Syntax-check the embedded JS:
   ```bash
   node -e "const s=require('fs').readFileSync('pve-gateway.py','utf8');new Function(s.split('APP_JS = r\"\"\"')[1].split('\"\"\"')[0])"
   ```
3. Exercise the change through `./dev.sh` (CLI) and the web UI. The user may already be running `./dev.sh` on port 8099; use `--port 8101 --config-dir <scratch dir>` for your own instance so you don't disturb it or its `.dev` state.

Untested on real hardware means untested: say so rather than claiming it works on Proxmox.

## Key patterns

- **All external commands go through `run()` or `sh()`.** The mock hooks in there, so the real parsing and logic paths run in mock mode too. Never call `subprocess` directly elsewhere.
  - `run(cmd, data, check_only, timeout)` handles iptables, nginx and certbot. With `--dry-run`, mutating calls are only logged, while `check_only=True` calls are read-only and still run for real.
  - `sh(cmd)` runs read-only diagnostics and returns `(rc, combined output)`.
- **When you add a command, teach the mock about it.** Add a `c_<command>` method to `dev/mock.py` that returns `(rc, out, changed)`, with realistic output and error text, so the UI and tests can show real failure messages.
- **iptables:** our rules live only in `PVEGW_PRE`, `PVEGW_POST` and `PVEGW_FWD`. They're swapped atomically with `iptables-restore --noflush` (built by `build_ruleset`) and hooked in with `-C`/`-I`. Never touch other chains. DNAT always uses `-m addrtype --dst-type LOCAL`, so guests' outbound traffic isn't hijacked.
- **nginx:** a single generated file (`build_nginx` → `apply_nginx`). It is written, checked with `nginx -t`, and the **previous file is restored** on failure, then nginx is reloaded.
- **certbot:** always runs through `run_certbot()` in a background thread, with progress in `CERT_JOBS[key]`. Certificate state is looked up by certbot cert name (`cert_info`, `cert_paths`, `domain_cert`). Wildcards are named `wildcard.<zone>`.
- **Validation:** `validate_rule`, `validate_domain` and `validate_wildcard` normalise input and raise `ApiError(msg, code)` with a user-facing message. Cross-checks: port rules vs nginx on 80/443, duplicate hostnames, wildcard coverage (one label deep). `load_config()` re-validates saved data and drops invalid entries with a warning.
- **Saving changes:** take `LOCK`, build a new cfg dict, apply it (iptables or nginx), and only on success call `save_config()` (atomic, 0600) and swap `STATE["cfg"]`.
- **Secrets:**
  - DNS provider credentials live only in `<config dir>/dns/<id>.ini` (0600, dir 0700) and must never be returned by the API, logged or included in the debug report.
  - `pass_hash` is masked in diagnostics.
- **HTTP API:** `Handler.route` / `Handler.api`.
  - Every non-GET request requires the `X-PVEGW: 1` header (CSRF), and everything except `/api/login` and `/api/authinfo` requires a session.
  - Errors are JSON `{"error": "..."}`.
- **UI:** vanilla JS with no framework.
  - Build DOM with the `el()` helper and `textContent`. Never use `innerHTML` with data.
  - The UI must work in light and dark mode and at phone width (tables scroll inside `.card.scroll`).
  - Colors are CSS variables in `:root`.
- **Diagnostics:** new features should add health checks to `checks()`, raw output to `sections()`, and, where a user can act on it, steps to `test_rule` / `test_domain`. Each check has a status of `ok`, `warn`, `fail` or `info`, plus a detail that says how to fix it.

## Conventions

- Match the surrounding style: small functions, short comments explaining *why*, user-facing messages that say how to fix the problem (e.g. `"... - run: apt install nginx"`).
- Log with `log(msg, level)`, where level is `info`, `warn`, `error` or `debug`; `debug` only shows with `-v` or the UI toggle. The log is also kept in memory for the Debug tab.
- When adding a CLI command, update the `epilog` help, `choices` and the README CLI block.
- Commits end with the `Co-Authored-By` line from the session's attribution instructions. Work goes through PRs on `farruxx/pve-gateway`; `master` is the default branch.
