#!/usr/bin/env bash
# TechDetechtives: prepare the network inventory on this host.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
#
# Creates the TLS certificate and the sign-in for the pages and records their
# address in config/techdetechtives.env. It starts nothing: scripts/install.sh
# network runs this and then starts the container.
#
# Usage:
#   network/setup-network.sh [--name HOSTNAME] [--ip ADDRESS] [--port 8445]
#                            [--inside NETWORKS] [--zones NAME=NETWORK,...] [--learn-hours 72]
#
#   --name         name analysts will use for this host (default: this host's name)
#   --ip           internal IP address of this host, added to the certificate
#   --port         HTTPS port of the pages (default 8445)
#   --inside       the networks that are yours, comma separated (default: all private ranges)
#   --zones        names for parts of your network, for example
#                  "Control=10.10.1.0/24,Office=172.16.0.0/16" (default: each /24 is a zone)
#   --learn-hours  how long everything seen is taken as normal (default 72)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="$ROOT/network/certs"
ENV_FILE="${TD_ENV_FILE:-$ROOT/config/techdetechtives.env}"

SERVER_NAME=""
SERVER_IP=""
PORT=""
INSIDE=""
ZONES=""
LEARN=""

log()  { printf '[techdetechtives] %s\n' "$*"; }
die()  { printf '[techdetechtives] ERROR: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)        shift; [[ $# -gt 0 ]] || die "--name needs a value"; SERVER_NAME="$1" ;;
    --ip)          shift; [[ $# -gt 0 ]] || die "--ip needs a value"; SERVER_IP="$1" ;;
    --port)        shift; [[ $# -gt 0 ]] || die "--port needs a value"; PORT="$1" ;;
    --inside)      shift; [[ $# -gt 0 ]] || die "--inside needs a value"; INSIDE="$1" ;;
    --zones)       shift; [[ $# -gt 0 ]] || die "--zones needs a value"; ZONES="$1" ;;
    --learn-hours) shift; [[ $# -gt 0 ]] || die "--learn-hours needs a value"; LEARN="$1" ;;
    -h|--help)     sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
  shift
done

set_env() {
  # set_env KEY VALUE: replace KEY (commented out or not), or append it.
  local key="$1" value="$2" tmp
  tmp="$(mktemp)"
  awk -v key="$key" -v value="$value" '
    BEGIN { done = 0 }
    {
      line = $0
      sub(/^#[ \t]*/, "", line)
      if (!done && index(line, key "=") == 1) { print key "=" value; done = 1; next }
      print $0
    }
    END { if (!done) print key "=" value }
  ' "$ENV_FILE" > "$tmp"
  cat "$tmp" > "$ENV_FILE"
  rm -f "$tmp"
}

get_env() {
  [[ -f "$ENV_FILE" ]] || return 0
  { grep -E "^$1=" "$ENV_FILE" || true; } | tail -n 1 | cut -d= -f2-
}

if [[ ! -f "$ENV_FILE" ]]; then
  cp "$ROOT/config/techdetechtives.env.example" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  log "created $ENV_FILE from the example"
fi

# Choices made on an earlier run are kept unless given again.
PORT="${PORT:-$(get_env TD_NET_PORT)}"; PORT="${PORT:-8445}"
if [[ -z "$SERVER_NAME" ]]; then
  SERVER_NAME="$(get_env TD_NET_PUBLIC_URL | sed -n 's|^https://\([^:/]*\).*|\1|p')"
  SERVER_NAME="${SERVER_NAME:-$(hostname -f 2>/dev/null || hostname)}"
fi
if [[ -z "$SERVER_IP" && -f "$CERT_DIR/.san" ]]; then
  SERVER_IP="$(tr ',' '\n' < "$CERT_DIR/.san" | sed -n 's/^IP://p' | grep -v '^127\.0\.0\.1$' | head -n 1 || true)"
fi
[[ "$SERVER_NAME" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || die "--name must be a host name (letters, digits, dots, dashes)"
# The pages are served by an account without privileges, which cannot open a port below 1024.
[[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT >= 1024 && PORT <= 65535 )) || die "--port must be a number between 1024 and 65535"
if [[ -n "$SERVER_IP" ]]; then
  [[ "$SERVER_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "--ip must be an IPv4 address"
fi
if [[ -n "$LEARN" ]]; then
  [[ "$LEARN" =~ ^[0-9]+$ ]] || die "--learn-hours must be a whole number of hours"
fi
# Networks and zones are checked by the same code that will use them.
if [[ -n "$INSIDE$ZONES" ]]; then
  command -v python3 >/dev/null 2>&1 || die "python3 is needed to check --inside and --zones"
  TD_CHECK_INSIDE="$INSIDE" TD_CHECK_ZONES="$ZONES" PYTHONPATH="$ROOT/network/app:$ROOT/ticketing/forwarder" python3 - <<'PY' || exit 1
import os, sys
import td_forwarder as fw
from td_net.sync import INSIDE_DEFAULT, Scope
try:
    Scope(os.environ["TD_CHECK_INSIDE"] or INSIDE_DEFAULT, os.environ["TD_CHECK_ZONES"])
except fw.ConfigError as error:
    text = str(error).replace("TD_NET_INSIDE", "--inside").replace("TD_NET_ZONES", "--zones")
    sys.exit(f"[techdetechtives] ERROR: {text}")
PY
fi
command -v openssl >/dev/null 2>&1 || die "openssl is not installed on this host"

# The container runs as the account that set it up first, on every later run
# too, whoever starts it: its files in the state volume belong to that account.
NET_UID="$(get_env TD_NET_UID)"; NET_GID="$(get_env TD_NET_GID)"
if [[ ! "$NET_UID" =~ ^[0-9]+$ || ! "$NET_GID" =~ ^[0-9]+$ ]]; then
  NET_UID="$(id -u)"; NET_GID="$(id -g)"
  set_env TD_NET_UID "$NET_UID"
  set_env TD_NET_GID "$NET_GID"
fi

mkdir -p "$CERT_DIR"
cert="$CERT_DIR/td-net-cert.pem"
key="$CERT_DIR/td-net-key.pem"
san="DNS:$SERVER_NAME,DNS:localhost,IP:127.0.0.1"
[[ -n "$SERVER_IP" ]] && san="$san,IP:$SERVER_IP"
expiring=0
if [[ -f "$cert" ]] && ! openssl x509 -checkend $((30 * 86400)) -noout -in "$cert" >/dev/null 2>&1; then
  expiring=1
fi
if [[ ! -f "$cert" || ! -f "$key" || $expiring -eq 1 || "$(cat "$CERT_DIR/.san" 2>/dev/null || true)" != "$san" ]]; then
  log "creating a TLS certificate for the pages ($san), valid for 13 months; re-run this to renew it"
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 397 \
    -subj "/CN=$SERVER_NAME/O=TechDetechtives" -addext "subjectAltName=$san" \
    -keyout "$key" -out "$cert" >/dev/null 2>&1 || die "openssl could not create the certificate"
  chmod 600 "$key"
  chmod 644 "$cert"
  if [[ $EUID -eq 0 && "$NET_UID" != "0" ]]; then
    chown "$NET_UID:$NET_GID" "$key" "$cert"
  fi
  printf '%s' "$san" > "$CERT_DIR/.san"
fi

if [[ -z "$(get_env TD_NET_PASSWORD)" ]]; then
  set_env TD_NET_PASSWORD "$(openssl rand -hex 16)"
  log "generated the password for the pages"
fi
[[ -n "$(get_env TD_NET_USER)" ]] || set_env TD_NET_USER "analyst"
set_env TD_NET_PORT "$PORT"
set_env TD_NET_PUBLIC_URL "https://$SERVER_NAME:$PORT"
[[ -n "$(get_env TD_NET_NAME)" ]] || set_env TD_NET_NAME "$SERVER_NAME"
[[ -z "$INSIDE" ]] || set_env TD_NET_INSIDE "$INSIDE"
[[ -z "$ZONES" ]] || set_env TD_NET_ZONES "$ZONES"
[[ -z "$LEARN" ]] || set_env TD_NET_LEARN_HOURS "$LEARN"
log "network inventory prepared: https://$SERVER_NAME:$PORT"
