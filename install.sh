#!/bin/sh
# Install / uninstall pve-portfwd on a Proxmox VE host.
#   sh install.sh               install + start
#   sh install.sh --with-nginx  also install nginx + certbot (needed for the Domains tab)
#   sh install.sh uninstall     stop, remove rules, nginx config and files (keeps /etc/pve-portfwd)
set -e
cd "$(dirname "$0")"

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }

if [ "$1" = "uninstall" ]; then
    systemctl disable --now pve-portfwd 2>/dev/null || true
    [ -x /usr/local/bin/pve-portfwd ] && /usr/local/bin/pve-portfwd flush || true
    rm -f /usr/local/bin/pve-portfwd /etc/systemd/system/pve-portfwd.service /etc/sysctl.d/99-pve-portfwd.conf
    if [ -f /etc/nginx/conf.d/pve-portfwd.conf ]; then
        rm -f /etc/nginx/conf.d/pve-portfwd.conf
        systemctl reload nginx 2>/dev/null || true
        echo "removed nginx domains config (certificates in /etc/letsencrypt are kept)"
    fi
    systemctl daemon-reload
    echo "uninstalled (config left in /etc/pve-portfwd)"
    exit 0
fi

command -v python3  >/dev/null || { echo "python3 missing: apt install python3-minimal"; exit 1; }
command -v iptables >/dev/null || { echo "iptables missing: apt install iptables"; exit 1; }

if [ "$1" = "--with-nginx" ]; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx certbot
    systemctl enable --now nginx
fi

install -m 0755 pve-portfwd.py /usr/local/bin/pve-portfwd
install -m 0644 pve-portfwd.service /etc/systemd/system/pve-portfwd.service
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-pve-portfwd.conf
sysctl -q -p /etc/sysctl.d/99-pve-portfwd.conf
install -d -m 0700 /etc/pve-portfwd

systemctl daemon-reload
systemctl enable pve-portfwd >/dev/null 2>&1
systemctl restart pve-portfwd
sleep 1
systemctl --no-pager --lines=5 status pve-portfwd || true

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo
echo "Open: https://${IP:-<host-ip>}:8099  (log in with root@pam)"
