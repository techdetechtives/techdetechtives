#!/usr/bin/env bash
# TechDetechtives installer.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
#
# Usage:
#   sudo scripts/install.sh platform [--dry-run] [--no-salt] [--jupyter-url URL]
#        Run on the Security Onion manager. Applies branding and detections.
#   scripts/install.sh analytics
#        Run on the analytics host. Builds and starts the notebook workbench.
#   scripts/install.sh analytics-down
#        Stop the workbench (notebooks and data are kept).
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
usage() { sed -n '5,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

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

compose() {
  docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" "$@"
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
  log "building and starting the analytics workbench"
  compose up -d --build
  local bind port
  bind="$(env_value TD_JUPYTER_BIND)"; port="$(env_value TD_JUPYTER_PORT)"
  log "workbench started: http://${bind:-127.0.0.1}:${port:-8888}/lab"
  log "sign in with the TD_JUPYTER_TOKEN value from $ENV_FILE"
  log "check it with: scripts/verify.sh analytics"
}

cmd_analytics_down() {
  require_docker
  [[ -f "$ENV_FILE" ]] || die "$ENV_FILE not found; nothing to stop"
  compose down
}

case "${1:-}" in
  platform)       shift; exec "$ROOT/platform/apply-overlay.sh" apply "$@" ;;
  analytics)      cmd_analytics ;;
  analytics-down) cmd_analytics_down ;;
  -h|--help)      usage ;;
  *)              usage >&2; exit 2 ;;
esac
