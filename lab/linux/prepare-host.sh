#!/usr/bin/env bash
# TechDetechtives VMware lab: prepare an Ubuntu 24.04 (or Kali) VM for its role.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
#
# Usage (as a sudo-capable user, not root):
#   lab/linux/prepare-host.sh --role dfirva|honeypot|otsim|victim|attacker [--so-ip 10.10.10.10] [--so-name td-so]
#
#   dfirva    ticketing machine: Docker, Compose, firewall for the analyst network
#   honeypot  decoy machine: Docker, Compose (no host firewall: decoys must answer)
#   otsim     OT simulators: Docker, Compose
#   victim    Linux lab endpoint: tools for the Atomic tests; Elastic Agent comes from the platform
#   attacker  Kali: traffic, flood, layer 2 and OT test tools
#
# Every role adds the platform's name to /etc/hosts so the installers can find it.
# Safe to re-run.

set -euo pipefail

ROLE=""; SO_IP="10.10.10.10"; SO_NAME="td-so"; MGMT_NET="10.10.10.0/24"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --role)     ROLE="${2:?}"; shift 2 ;;
    --so-ip)    SO_IP="${2:?}"; shift 2 ;;
    --so-name)  SO_NAME="${2:?}"; shift 2 ;;
    --mgmt-net) MGMT_NET="${2:?}"; shift 2 ;;
    -h|--help)  sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
[[ "$ROLE" =~ ^(dfirva|honeypot|otsim|victim|attacker)$ ]] || { echo "--role is required (dfirva|honeypot|otsim|victim|attacker)" >&2; exit 2; }
[[ $EUID -ne 0 ]] || { echo "run as your normal user; the script uses sudo where needed" >&2; exit 2; }

log() { printf '[lab:%s] %s\n' "$ROLE" "$*"; }

apt_install() { sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"; }

hosts_entry() {
  if getent hosts "$SO_NAME" >/dev/null; then
    log "$SO_NAME already resolves to $(getent hosts "$SO_NAME" | awk '{print $1}')"
  else
    echo "$SO_IP  $SO_NAME" | sudo tee -a /etc/hosts >/dev/null
    log "added '$SO_IP  $SO_NAME' to /etc/hosts"
  fi
}

install_docker() {
  apt_install docker.io docker-compose-v2
  sudo systemctl enable --now docker
  if ! id -nG "$USER" | grep -qw docker; then
    sudo usermod -aG docker "$USER"
    log "added $USER to the docker group: log out and back in (or run 'newgrp docker') before the installers"
  fi
  docker compose version >/dev/null 2>&1 || sudo docker compose version
}

log "updating package lists"
sudo apt-get update -y
apt_install ca-certificates curl git jq openssl python3 chrony
sudo timedatectl set-timezone UTC || true
sudo systemctl enable --now chrony 2>/dev/null || sudo systemctl enable --now chronyd 2>/dev/null || true
hosts_entry

case "$ROLE" in
  dfirva)
    install_docker
    apt_install ufw
    sudo ufw allow from "$MGMT_NET" to any port 22 proto tcp
    for p in 8443 8444 8445 9443; do sudo ufw allow from "$MGMT_NET" to any port "$p" proto tcp; done
    sudo ufw --force enable
    log "ufw on: SSH and the web pages (8443 tickets, 8444 vulnerabilities, 8445 network, 9443 Greenbone) from $MGMT_NET"
    log "note: Docker-published ports bypass ufw; the router's rules are what really limit them"
    log "free memory: $(awk '/MemAvailable/ {print int($2/1024)" MB"}' /proc/meminfo) (DFIR-IRIS + Greenbone + workbench want about 16 GB)"
    ;;
  honeypot)
    install_docker
    log "no host firewall on purpose: the decoys must answer. Keep this VM on TD-IT only."
    ;;
  otsim)
    install_docker
    log "next: cd lab/ot-sim && docker compose up -d --build"
    ;;
  victim)
    apt_install curl wget netcat-openbsd
    log "next: install Elastic Agent from the platform console (Downloads) — see lab/README.md phase 6"
    ;;
  attacker)
    apt_install nmap hping3 dsniff arp-scan macchanger netcat-openbsd tcpdump python3-venv iputils-ping
    if [[ ! -x "$HOME/otvenv/bin/python" ]]; then
      python3 -m venv "$HOME/otvenv"
    fi
    "$HOME/otvenv/bin/pip" install -q --upgrade pip
    "$HOME/otvenv/bin/pip" install -q "python-snap7==1.3" "pymodbus==3.6.9"
    log "OT client tools in ~/otvenv (activate: source ~/otvenv/bin/activate)"
    log "lab/ot-sim/dnp3_cold_restart.py sends the DNP3 test frame"
    ;;
esac

log "done"
