#!/usr/bin/env bash
# TechDetechtives installer.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
#
# Usage:
#   sudo scripts/install.sh platform [--dry-run] [--no-salt] [--no-auto-enable] [--jupyter-url URL] [--tickets-url URL] [--vuln-url URL] [--brand-image-url URL|none]
#        Run on the Security Onion manager. Applies branding and detections, and
#        sets the platform to switch the TechDetechtives rules on when it imports them.
#   scripts/install.sh analytics
#        Run on the analytics host. Builds and starts the notebook workbench.
#   scripts/install.sh analytics-down
#        Stop the workbench (notebooks and data are kept).
#   scripts/install.sh ticketing [--name HOSTNAME] [--ip ADDRESS] [--port 8443]
#        Run on the analytics host. Installs DFIR-IRIS on this host and starts
#        the forwarder that opens a ticket for every platform alert.
#   scripts/install.sh ticketing-down
#        Stop the forwarder and DFIR-IRIS (tickets are kept).
#   scripts/install.sh vulnerability [--name HOSTNAME] [--ip ADDRESS] [--port 9443] [--dash-port 8444]
#        Run on the ticketing machine. Installs Greenbone (OpenVAS) on this host and
#        starts the connector with the vulnerability dashboard and reports pages.
#   scripts/install.sh vulnerability-down
#        Stop the connector and Greenbone (scan data is kept).
#   scripts/install.sh honeypot [--name NODE] [--ip ADDRESS] [--services LIST] [--port NAME=PORT]
#        Run on the machine that should be the decoy (the ticketing machine, or
#        better a small machine of its own). Starts OpenCanary and the shipper
#        that turns every contact into a platform alert.
#   scripts/install.sh honeypot-down
#        Stop the honeypot.
#   scripts/install.sh skills [--target DIR] [--only-techdetechtives]
#        Run where your AI assistant runs. Installs the analyst skills
#        (see skills/README.md).
#
# Security Onion itself is not installed by this script. Install it first from
# the official ISO or installer, then run the platform step.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/config/techdetechtives.env"
COMPOSE_FILE="$ROOT/analytics/docker-compose.yml"

log()  { printf '[techdetechtives] %s\n' "$*"; }
warn() { printf '[techdetechtives] WARNING: %s\n' "$*" >&2; }
die()  { printf '[techdetechtives] ERROR: %s\n' "$*" >&2; exit 1; }
usage() { sed -n '5,34p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

env_value() {
  # Read KEY from the env file without sourcing it.
  local key="$1"
  [[ -f "$ENV_FILE" ]] || return 0
  grep -E "^${key}=" "$ENV_FILE" | tail -n 1 | cut -d= -f2-
}

new_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

platform_ip() {
  # The platform's address as this host resolves it (DNS or /etc/hosts).
  # Prints nothing when TD_ES_HOST is empty; stops when the name is unknown.
  local host ip
  host="$(env_value TD_ES_HOST)"
  [[ -n "$host" ]] || return 0
  if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    printf '%s\n' "$host"
    return 0
  fi
  ip="$(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1; exit}')" || true
  if [[ -z "$ip" ]]; then
    die "this host cannot find the platform by name ($host). Add it to /etc/hosts, for example:
    echo '<platform IP>  $host' | sudo tee -a /etc/hosts
then run this command again."
  fi
  printf '%s\n' "$ip"
}

compose() {
  docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"
}

low_memory_note() {
  # $1 = what is about to start, $2 = memory it wants in MB.
  local free
  free="$(awk '/^MemAvailable:/ {print int($2 / 1024)}' /proc/meminfo 2>/dev/null)" || true
  if [[ -n "$free" && "$free" -lt "$2" ]]; then
    warn "$1 wants about $2 MB of free memory; this host has $free MB free."
    warn "It may be slow or stop. Give the machine more memory, or stop a part you are not using."
  fi
}

require_docker() {
  command -v docker >/dev/null 2>&1 || die "docker is not installed on this host"
  docker compose version >/dev/null 2>&1 || die "the docker compose plugin is not installed"
  docker info >/dev/null 2>&1 || die "cannot reach the docker daemon (is it running, and are you in the docker group?)"
}

prepare_env() {
  if [[ ! -f "$ENV_FILE" ]]; then
    cp "$ROOT/config/techdetechtives.env.example" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    log "created $ENV_FILE from the example"
  fi
  if [[ -z "$(env_value TD_JUPYTER_TOKEN)" ]]; then
    local token
    token="$(new_token)"
    sed -i "s|^TD_JUPYTER_TOKEN=.*|TD_JUPYTER_TOKEN=${token}|" "$ENV_FILE"
    log "generated a Jupyter access token and saved it in $ENV_FILE"
  fi
  local host cert
  host="$(env_value TD_ES_HOST)"
  if [[ -z "$host" ]]; then
    warn "TD_ES_HOST is empty: the workbench will start in demo mode on sample data."
    warn "Fill in TD_ES_HOST and TD_ES_API_KEY (see platform/create-readonly-key.sh) and re-run to connect it."
  else
    [[ -n "$(env_value TD_ES_API_KEY)" ]] || die "TD_ES_HOST is set but TD_ES_API_KEY is empty in $ENV_FILE"
    cert="$(env_value TD_ES_CA_CERT)"
    if [[ "$cert" == /certs/* && ! -f "$ROOT/analytics/certs/${cert#/certs/}" ]]; then
      die "CA certificate analytics/certs/${cert#/certs/} is missing. Copy /etc/pki/ca.crt from the manager to that path."
    fi
  fi
}

cmd_analytics() {
  require_docker
  prepare_env
  local platform_address
  platform_address="$(platform_ip)"
  if [[ -n "$platform_address" ]]; then
    log "platform $(env_value TD_ES_HOST) is at $platform_address"
    export TD_ES_IP="$platform_address"
  fi
  low_memory_note "the workbench" 3072
  log "building and starting the analytics workbench (the first build downloads about 1 GB)"
  compose up -d --build
  local bind port
  bind="$(env_value TD_JUPYTER_BIND)"; port="$(env_value TD_JUPYTER_PORT)"
  log "workbench started: http://${bind:-127.0.0.1}:${port:-8888}/lab"
  log "sign in with the TD_JUPYTER_TOKEN value from $ENV_FILE"
  if [[ "${bind:-127.0.0.1}" == "127.0.0.1" ]]; then
    log "it only answers on this machine. From your own computer, open a tunnel first:"
    log "  ssh -L ${port:-8888}:127.0.0.1:${port:-8888} $(id -un)@<this machine's address>"
    log "then browse to http://127.0.0.1:${port:-8888}/lab"
  fi
  log "check it with: scripts/verify.sh analytics"
}

cmd_analytics_down() {
  require_docker
  [[ -f "$ENV_FILE" ]] || die "$ENV_FILE not found; nothing to stop"
  compose down
}

forwarder_compose() {
  docker compose -f "$ROOT/ticketing/docker-compose.yml" --env-file "$ENV_FILE" "$@"
}

cmd_ticketing() {
  require_docker
  "$ROOT/ticketing/setup-iris.sh" "$@"
  if [[ -z "$(env_value TD_ES_HOST)" || -z "$(env_value TD_ES_API_KEY)" ]]; then
    warn "DFIR-IRIS is running, but the forwarder was not started: TD_ES_HOST and TD_ES_API_KEY are empty."
    warn "Fill them in $ENV_FILE (see platform/create-readonly-key.sh) and re-run this command."
    return 0
  fi
  local cert
  cert="$(env_value TD_ES_CA_CERT)"
  if [[ "$cert" == /certs/* && ! -f "$ROOT/analytics/certs/${cert#/certs/}" ]]; then
    die "CA certificate analytics/certs/${cert#/certs/} is missing. Copy /etc/pki/ca.crt from the manager to that path."
  fi
  platform_ip >/dev/null
  log "building and starting the alert-to-ticket forwarder"
  forwarder_compose up -d --build
  local minimum
  minimum="$(env_value TD_TICKET_MIN_SEVERITY)"
  log "forwarder started. Tickets are created for new alerts at severity ${minimum:-2} and above (1 low, 2 medium, 3 high, 4 critical)."
  log "check it with: scripts/verify.sh ticketing"
}

cmd_ticketing_down() {
  require_docker
  [[ -f "$ENV_FILE" ]] && forwarder_compose down
  if [[ -d "$ROOT/ticketing/iris-web/.git" ]]; then
    (cd "$ROOT/ticketing/iris-web" && docker compose down)
  fi
}

vuln_compose() {
  docker compose -f "$ROOT/vulnerability/docker-compose.yml" --env-file "$ENV_FILE" "$@"
}

cmd_vulnerability() {
  require_docker
  "$ROOT/vulnerability/setup-greenbone.sh" "$@"
  if [[ -z "$(env_value TD_ES_INGEST_API_KEY)" ]]; then
    warn "TD_ES_INGEST_API_KEY is empty: findings will show on the dashboard but will not be sent to the platform."
    warn "Create the key on the manager with platform/create-ingest-key.sh, add it to $ENV_FILE, and re-run this command."
  elif [[ -z "$(env_value TD_ES_HOST)" ]]; then
    die "TD_ES_INGEST_API_KEY is set but TD_ES_HOST is empty in $ENV_FILE"
  else
    local cert
    cert="$(env_value TD_ES_CA_CERT)"
    if [[ "$cert" == /certs/* && ! -f "$ROOT/analytics/certs/${cert#/certs/}" ]]; then
      die "CA certificate analytics/certs/${cert#/certs/} is missing. Copy /etc/pki/ca.crt from the manager to that path."
    fi
    platform_ip >/dev/null
  fi
  if [[ -z "$(env_value TD_IRIS_API_KEY)" ]]; then
    warn "DFIR-IRIS is not set up on this host: vulnerability tickets are off. Run scripts/install.sh ticketing first to enable them."
  fi
  log "building and starting the vulnerability connector"
  vuln_compose up -d --build
  log "dashboard: $(env_value TD_VULN_PUBLIC_URL)  (user $(env_value TD_VULN_USER), password = TD_VULN_PASSWORD in $ENV_FILE)"
  log "check it with: scripts/verify.sh vulnerability"
}

honeypot_compose() {
  docker compose -f "$ROOT/honeypot/docker-compose.yml" -f "$ROOT/honeypot/ports.yaml" --env-file "$ENV_FILE" "$@"
}

cmd_honeypot() {
  require_docker
  "$ROOT/honeypot/setup-honeypot.sh" "$@"
  log "building and starting the honeypot (the first build downloads about 1 GB)"
  honeypot_compose up -d --build td-honeypot
  if [[ -z "$(env_value TD_ES_HOST)" || -z "$(env_value TD_HONEYPOT_API_KEY)" ]]; then
    warn "The decoys are up, but nothing is sent to the platform yet: TD_ES_HOST or TD_HONEYPOT_API_KEY is empty."
    warn "On the platform run: sudo platform/create-ingest-key.sh --for honeypot --allow-ip <this machine>"
    warn "Put the printed line and TD_ES_HOST in $ENV_FILE, copy the platform's CA certificate"
    warn "to analytics/certs/so-ca.crt, and re-run this command. Contacts are kept until then."
    return 0
  fi
  local cert
  cert="$(env_value TD_ES_CA_CERT)"
  if [[ "$cert" == /certs/* && ! -f "$ROOT/analytics/certs/${cert#/certs/}" ]]; then
    die "CA certificate analytics/certs/${cert#/certs/} is missing. Copy /etc/pki/ca.crt from the manager to that path."
  fi
  platform_ip >/dev/null
  honeypot_compose up -d --build td-honeypot-shipper
  log "honeypot started. Every contact with a decoy becomes a platform alert; medium and above become tickets."
  log "check it with: scripts/verify.sh honeypot"
  local address
  address="$(env_value TD_HONEYPOT_IP)"
  log "try it from another machine: honeypot/README.md, \"Try it\" (for example: curl http://${address:-<this machine>}/index.html)"
}

cmd_honeypot_down() {
  require_docker
  [[ -f "$ENV_FILE" && -f "$ROOT/honeypot/ports.yaml" ]] || die "the honeypot is not set up on this machine; nothing to stop"
  honeypot_compose down
}

cmd_vulnerability_down() {
  require_docker
  [[ -f "$ENV_FILE" ]] && vuln_compose down
  if [[ -f "$ROOT/vulnerability/greenbone/compose.yaml" ]]; then
    docker compose -p techdetechtives-greenbone -f "$ROOT/vulnerability/greenbone/compose.yaml" \
      -f "$ROOT/vulnerability/greenbone/override.yaml" down
  fi
}

case "${1:-}" in
  platform)       shift; exec "$ROOT/platform/apply-overlay.sh" apply "$@" ;;
  analytics)      cmd_analytics ;;
  analytics-down) cmd_analytics_down ;;
  ticketing)      shift; cmd_ticketing "$@" ;;
  ticketing-down) cmd_ticketing_down ;;
  vulnerability)      shift; cmd_vulnerability "$@" ;;
  vulnerability-down) cmd_vulnerability_down ;;
  honeypot)       shift; cmd_honeypot "$@" ;;
  honeypot-down)  cmd_honeypot_down ;;
  skills)         shift; exec "$ROOT/skills/install-skills.sh" "$@" ;;
  -h|--help)      usage ;;
  *)              usage >&2; exit 2 ;;
esac
