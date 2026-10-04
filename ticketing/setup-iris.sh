#!/usr/bin/env bash
# TechDetechtives: install DFIR-IRIS on this (internal) host.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
#
# Fetches DFIR-IRIS at the version pinned in upstream.lock, gives it its own
# generated secrets and TLS certificate, and starts it with Docker. Nothing is
# hosted outside this machine. DFIR-IRIS is a separate project under LGPL-3.0;
# its code is fetched into ticketing/iris-web/ and is not part of this
# repository.
#
# Usage:
#   ticketing/setup-iris.sh [--name HOSTNAME] [--ip ADDRESS] [--port 8443] [--no-start]
#
#   --name   name analysts will use to open the ticketing site (default: this host's name)
#   --ip     internal IP address of this host, added to the certificate
#   --port   HTTPS port (default 8443)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IRIS_DIR="$ROOT/ticketing/iris-web"
CERT_DIR="$ROOT/ticketing/certs"
ENV_FILE="$ROOT/config/techdetechtives.env"
LOCK_FILE="$ROOT/upstream.lock"

SERVER_NAME="$(hostname -f 2>/dev/null || hostname)"
SERVER_IP=""
PORT="8443"
START=1

log()  { printf '[techdetechtives] %s\n' "$*"; }
warn() { printf '[techdetechtives] WARNING: %s\n' "$*" >&2; }
die()  { printf '[techdetechtives] ERROR: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name) shift; [[ $# -gt 0 ]] || die "--name needs a value"; SERVER_NAME="$1" ;;
    --ip)   shift; [[ $# -gt 0 ]] || die "--ip needs a value"; SERVER_IP="$1" ;;
    --port) shift; [[ $# -gt 0 ]] || die "--port needs a value"; PORT="$1" ;;
    --no-start) START=0 ;;
    -h|--help) sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
  shift
done

[[ "$SERVER_NAME" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || die "--name must be a host name (letters, digits, dots, dashes)"
[[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT >= 1 && PORT <= 65535 )) || die "--port must be a number between 1 and 65535"
if [[ -n "$SERVER_IP" ]]; then
  [[ "$SERVER_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "--ip must be an IPv4 address"
fi
for tool in git openssl docker; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is not installed on this host"
done

set_env() {
  # set_env FILE KEY VALUE: replace KEY (commented out or not), or append it.
  local file="$1" key="$2" value="$3" tmp
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
  ' "$file" > "$tmp"
  cat "$tmp" > "$file"
  rm -f "$tmp"
}

get_env() {
  [[ -f "$1" ]] || return 0
  grep -E "^$2=" "$1" | tail -n 1 | cut -d= -f2-
}

secret() { openssl rand -hex "${1:-32}"; }

# --- 1. fetch DFIR-IRIS at the pinned version -------------------------------
pin="$(grep -E '^dfir-iris\|' "$LOCK_FILE" || true)"
[[ -n "$pin" ]] || die "no dfir-iris entry in upstream.lock"
IFS='|' read -r _ iris_repo _ iris_commit iris_version _ <<< "$pin"

if [[ ! -d "$IRIS_DIR/.git" ]]; then
  log "fetching DFIR-IRIS $iris_version"
  mkdir -p "$IRIS_DIR"
  chmod 700 "$IRIS_DIR"
  git init -q "$IRIS_DIR"
  git -C "$IRIS_DIR" remote add origin "$iris_repo"
fi
if [[ "$(git -C "$IRIS_DIR" rev-parse HEAD 2>/dev/null || true)" != "$iris_commit" ]]; then
  git -C "$IRIS_DIR" fetch -q --depth 1 origin "$iris_commit"
  git -C "$IRIS_DIR" -c advice.detachedHead=false checkout -q FETCH_HEAD
fi
log "DFIR-IRIS $iris_version is in ticketing/iris-web"

# --- 2. settings and secrets (generated once, kept on re-runs) --------------
IRIS_ENV="$IRIS_DIR/.env"
if [[ ! -f "$IRIS_ENV" ]]; then
  cp "$IRIS_DIR/.env.model" "$IRIS_ENV"
  chmod 600 "$IRIS_ENV"
  set_env "$IRIS_ENV" POSTGRES_PASSWORD "$(secret 24)"
  set_env "$IRIS_ENV" POSTGRES_ADMIN_PASSWORD "$(secret 24)"
  set_env "$IRIS_ENV" IRIS_SECRET_KEY "$(secret 32)"
  set_env "$IRIS_ENV" IRIS_SECURITY_PASSWORD_SALT "$(secret 32)"
  # Meets the DFIR-IRIS password policy: 12+ characters, upper, lower, digit.
  set_env "$IRIS_ENV" IRIS_ADM_PASSWORD "Td$(secret 12)Aa1"
  set_env "$IRIS_ENV" IRIS_ADM_API_KEY "$(secret 32)"
  set_env "$IRIS_ENV" IRIS_ADM_USERNAME "administrator"
  log "generated database passwords, application secrets, the administrator password and an API key"
else
  log "keeping the existing DFIR-IRIS settings and secrets"
fi
if grep -q "__MUST_BE_CHANGED__" "$IRIS_ENV"; then
  die "$IRIS_ENV still contains a placeholder password; remove the file and re-run"
fi
set_env "$IRIS_ENV" SERVER_NAME "$SERVER_NAME"
set_env "$IRIS_ENV" INTERFACE_HTTPS_PORT "$PORT"
set_env "$IRIS_ENV" CERT_FILENAME "techdetechtives_iris_cert.pem"
set_env "$IRIS_ENV" KEY_FILENAME "techdetechtives_iris_key.pem"

# --- 3. TLS certificate (replaces the public development certificate) -------
WEB_CERTS="$IRIS_DIR/certificates/web_certificates"
cert="$WEB_CERTS/techdetechtives_iris_cert.pem"
key="$WEB_CERTS/techdetechtives_iris_key.pem"
san="DNS:$SERVER_NAME,DNS:localhost,IP:127.0.0.1"
[[ -n "$SERVER_IP" ]] && san="$san,IP:$SERVER_IP"
if [[ ! -f "$cert" || ! -f "$key" || "$(cat "$WEB_CERTS/.techdetechtives-san" 2>/dev/null || true)" != "$san" ]]; then
  log "creating a TLS certificate for $san"
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 825 \
    -subj "/CN=$SERVER_NAME/O=TechDetechtives" -addext "subjectAltName=$san" \
    -keyout "$key" -out "$cert" >/dev/null 2>&1 || die "openssl could not create the certificate"
  # The web server in the container runs unprivileged and must read the key.
  # ticketing/iris-web itself is mode 700, so other users on this host cannot reach it.
  chmod 644 "$cert" "$key"
  printf '%s' "$san" > "$WEB_CERTS/.techdetechtives-san"
fi
mkdir -p "$CERT_DIR"
cp "$cert" "$CERT_DIR/iris-cert.pem"

# --- 4. connect the forwarder ---------------------------------------------------
if [[ ! -f "$ENV_FILE" ]]; then
  cp "$ROOT/config/techdetechtives.env.example" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  log "created $ENV_FILE from the example"
fi
set_env "$ENV_FILE" TD_IRIS_URL "https://127.0.0.1:$PORT"
set_env "$ENV_FILE" TD_IRIS_API_KEY "$(get_env "$IRIS_ENV" IRIS_ADM_API_KEY)"
set_env "$ENV_FILE" TD_IRIS_CA_CERT "/iris-certs/iris-cert.pem"

# --- 5. start ---------------------------------------------------------------------
if [[ $START -eq 0 ]]; then
  log "prepared, not started (--no-start)"
  exit 0
fi
docker compose version >/dev/null 2>&1 || die "the docker compose plugin is not installed"
docker info >/dev/null 2>&1 || die "cannot reach the docker daemon (is it running, and are you in the docker group?)"
log "starting DFIR-IRIS (the first start downloads its images and can take several minutes)"
(cd "$IRIS_DIR" && docker compose pull && docker compose up -d)

log "waiting for DFIR-IRIS to answer on port $PORT"
ready=0
for _ in $(seq 1 60); do
  if curl -fsS --cacert "$cert" -o /dev/null "https://127.0.0.1:$PORT/login" 2>/dev/null; then
    ready=1
    break
  fi
  sleep 5
done
[[ $ready -eq 1 ]] || warn "DFIR-IRIS did not answer within 5 minutes; check: (cd ticketing/iris-web && docker compose logs app)"

cat <<MSG

DFIR-IRIS is installed on this host.
  Address:   https://$SERVER_NAME:$PORT   (internal network only; do not expose it to the internet)
  User:      administrator
  Password:  the IRIS_ADM_PASSWORD value in ticketing/iris-web/.env
The site uses its own certificate, so browsers show a warning until you trust
ticketing/certs/iris-cert.pem or replace it with one from your internal CA.

MSG
