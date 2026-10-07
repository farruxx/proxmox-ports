#!/bin/sh
# Install / uninstall pve-gateway on a Proxmox VE host.
#   sh install.sh               install + start
#   sh install.sh --with-nginx  also install nginx + certbot (needed for the Domains tab)
#   sh install.sh uninstall     stop, remove rules, nginx config and files (keeps /etc/pve-gateway)
set -e
cd "$(dirname "$0")"

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }

if [ "$1" = "uninstall" ]; then
    systemctl disable --now pve-gateway 2>/dev/null || true
    [ -x /usr/local/bin/pve-gateway ] && /usr/local/bin/pve-gateway flush || true
    rm -f /usr/local/bin/pve-gateway /etc/systemd/system/pve-gateway.service /etc/sysctl.d/99-pve-gateway.conf
    if [ -f /etc/nginx/conf.d/pve-gateway.conf ]; then
        rm -f /etc/nginx/conf.d/pve-gateway.conf
        systemctl reload nginx 2>/dev/null || true
        echo "removed nginx domains config (certificates in /etc/letsencrypt are kept)"
    fi
    systemctl daemon-reload
    echo "uninstalled (config left in /etc/pve-gateway)"
    exit 0
fi

command -v python3  >/dev/null || { echo "python3 missing: apt install python3-minimal"; exit 1; }
command -v iptables >/dev/null || { echo "iptables missing: apt install iptables"; exit 1; }

if [ "$1" = "--with-nginx" ]; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx certbot
    systemctl enable --now nginx
fi

# migrate from the old name (pve-portfwd): config, credentials, ACME webroot, certbot renewal configs
if [ -e /etc/systemd/system/pve-portfwd.service ] || [ -d /etc/pve-portfwd ]; then
    echo "migrating from pve-portfwd ..."
    systemctl disable --now pve-portfwd 2>/dev/null || true
    [ -x /usr/local/bin/pve-portfwd ] && /usr/local/bin/pve-portfwd flush || true   # drop old PORTFWD_* chains
    if [ -d /etc/pve-portfwd ] && [ ! -e /etc/pve-gateway ]; then mv /etc/pve-portfwd /etc/pve-gateway; fi
    if [ -d /var/lib/pve-portfwd ] && [ ! -e /var/lib/pve-gateway ]; then mv /var/lib/pve-portfwd /var/lib/pve-gateway; fi
    if [ -d /etc/letsencrypt/renewal ]; then
        sed -i 's#/etc/pve-portfwd/#/etc/pve-gateway/#g; s#/var/lib/pve-portfwd/#/var/lib/pve-gateway/#g' /etc/letsencrypt/renewal/*.conf 2>/dev/null || true
    fi
    rm -f /etc/nginx/conf.d/pve-portfwd.conf   # regenerated as pve-gateway.conf on start
    rm -f /usr/local/bin/pve-portfwd /etc/systemd/system/pve-portfwd.service /etc/sysctl.d/99-pve-portfwd.conf
fi

install -m 0755 pve-gateway.py /usr/local/bin/pve-gateway
install -m 0644 pve-gateway.service /etc/systemd/system/pve-gateway.service
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-pve-gateway.conf
sysctl -q -p /etc/sysctl.d/99-pve-gateway.conf
install -d -m 0700 /etc/pve-gateway

systemctl daemon-reload
systemctl enable pve-gateway >/dev/null 2>&1
systemctl restart pve-gateway
sleep 1
systemctl --no-pager --lines=5 status pve-gateway || true

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo
echo "Open: https://${IP:-<host-ip>}:8099  (log in with root@pam)"
