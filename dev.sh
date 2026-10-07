#!/bin/sh
# Run pve-portfwd locally against a simulated Proxmox host (no root, no iptables).
#   ./dev.sh                 web UI on http://127.0.0.1:8099  (login: admin / admin)
#   ./dev.sh status          any CLI command, against the same simulated host
#   ./dev.sh test | debug | show | apply | flush
#   ./dev.sh mock unhook     break the simulated host (see: ./dev.sh mock)
#   ./dev.sh -v              verbose logging
# State lives in ./.dev (delete it to start over).
cd "$(dirname "$0")" || exit 1
exec python3 pve-portfwd.py --mock "$@"
