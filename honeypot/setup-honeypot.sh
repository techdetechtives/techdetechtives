#!/usr/bin/env bash
# TechDetechtives: prepare the honeypot on this host.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
#
# Writes the settings for OpenCanary (the decoy services to offer and the ports
# they use on this host) and records them in config/techdetechtives.env.
# scripts/install.sh honeypot runs this and then starts the containers.
# OpenCanary is a separate project (Thinkst Applied Research, BSD 3-Clause); it
# is fetched at the commit pinned in upstream.lock when its image is built and
# is not part of this repository.
#
# Usage:
#   honeypot/setup-honeypot.sh [--name NODE] [--ip ADDRESS] [--services LIST]
#                              [--port NAME=PORT ...] [--bind ADDRESS]
#   honeypot/setup-honeypot.sh --list
#
#   --name      name shown on alerts for this honeypot (default: this host's name)
#   --ip        this host's address, shown as the destination on alerts
#   --services  decoys to offer, comma separated
#               (default: ftp,http,telnet,mysql,mssql,rdp,vnc,redis)
#   --port      use another port on this host for one decoy, for example
#               --port ssh=2222 when this host's own SSH uses port 22
#   --bind      address the decoys listen on (default 0.0.0.0, every address)
#   --list      show the available decoys and stop

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HP_DIR="$ROOT/honeypot"
ENV_FILE="$ROOT/config/techdetechtives.env"
LOCK_FILE="$ROOT/upstream.lock"

NODE="$(hostname -s 2>/dev/null || hostname)"
ADDRESS=""
SERVICES=""
BIND="0.0.0.0"
PORTS=()

log()  { printf '[techdetechtives] %s\n' "$*"; }
warn() { printf '[techdetechtives] WARNING: %s\n' "$*" >&2; }
die()  { printf '[techdetechtives] ERROR: %s\n' "$*" >&2; exit 1; }

command -v python3 >/dev/null 2>&1 || die "python3 is not installed on this host"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)     shift; [[ $# -gt 0 ]] || die "--name needs a value"; NODE="$1" ;;
    --ip)       shift; [[ $# -gt 0 ]] || die "--ip needs a value"; ADDRESS="$1" ;;
    --services) shift; [[ $# -gt 0 ]] || die "--services needs a value"; SERVICES="$1" ;;
    --port)     shift; [[ $# -gt 0 ]] || die "--port needs a value such as ssh=2222"; PORTS+=("$1") ;;
    --bind)     shift; [[ $# -gt 0 ]] || die "--bind needs a value"; BIND="$1" ;;
    --list)     exec python3 "$HP_DIR/make_config.py" --name x --list ;;
    -h|--help)  sed -n '2,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
  shift
done

if [[ -n "$ADDRESS" ]]; then
  [[ "$ADDRESS" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "--ip must be an IPv4 address"
fi

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

# --- 1. the pinned OpenCanary version ------------------------------------------
pin="$(grep -E '^opencanary\|' "$LOCK_FILE" || true)"
[[ -n "$pin" ]] || die "no opencanary entry in upstream.lock"
IFS='|' read -r _ _ _ oc_commit oc_version _ <<< "$pin"
[[ "$oc_commit" =~ ^[0-9a-f]{40}$ ]] || die "the opencanary commit in upstream.lock is not a full commit id"
oc_tag="${oc_version%% *}"

# --- 2. settings file ----------------------------------------------------------
if [[ ! -f "$ENV_FILE" ]]; then
  cp "$ROOT/config/techdetechtives.env.example" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  log "created $ENV_FILE from the example"
fi
# Re-running without --services keeps the earlier choice.
[[ -n "$SERVICES" ]] || SERVICES="$(get_env "$ENV_FILE" TD_HONEYPOT_SERVICES)"
[[ -n "$SERVICES" ]] || SERVICES="ftp,http,telnet,mysql,mssql,rdp,vnc,redis"
[[ -n "$ADDRESS" ]] || ADDRESS="$(get_env "$ENV_FILE" TD_HONEYPOT_IP)"
if [[ ${#PORTS[@]} -eq 0 ]]; then
  saved="$(get_env "$ENV_FILE" TD_HONEYPOT_PORTS)"
  [[ -z "$saved" ]] || IFS=',' read -r -a PORTS <<< "$saved"
fi

# --- 3. OpenCanary settings and the port list -----------------------------------
args=(--name "$NODE" --services "$SERVICES" --bind "$BIND" --out-dir "$HP_DIR")
for pair in "${PORTS[@]+"${PORTS[@]}"}"; do args+=(--port "$pair"); done
summary="$(python3 "$HP_DIR/make_config.py" "${args[@]}")" || exit 1
chmod 644 "$HP_DIR/opencanary.conf" "$HP_DIR/ports.yaml"
services="$(sed -n 's/^SERVICES=//p' <<< "$summary")"
host_ports="$(sed -n 's/^HOST_PORTS=//p' <<< "$summary")"
port_map="$(sed -n 's/^PORT_MAP=//p' <<< "$summary")"

# --- 4. are those ports free on this host? --------------------------------------
# A port our own honeypot container already holds is fine (this is a re-run).
ours=""
if command -v docker >/dev/null 2>&1; then
  ours="$(docker port td-honeypot 2>/dev/null | sed -n 's/.*:\([0-9][0-9]*\)$/\1/p' | sort -u | tr '\n' ' ' || true)"
fi
if command -v ss >/dev/null 2>&1; then
  busy=()
  for port in $host_ports; do
    [[ " $ours " == *" $port "* ]] && continue
    if [[ -n "$(ss -Hltn "sport = :$port" 2>/dev/null)" ]]; then busy+=("$port"); fi
  done
  if [[ ${#busy[@]} -gt 0 ]]; then
    hint="Give that decoy another port (for example --port ssh=2222) or leave it out of --services."
    [[ " ${busy[*]} " == *" 22 "* ]] && hint="Port 22 is this host's own SSH. Use --port ssh=2222 for the decoy, or move the real SSH first."
    die "something on this host already listens on port ${busy[*]}. $hint"
  fi
else
  warn "the ss tool is not installed, so the ports could not be checked for conflicts"
fi

# --- 5. record the choices ------------------------------------------------------
set_env "$ENV_FILE" TD_HONEYPOT_NAME "$NODE"
set_env "$ENV_FILE" TD_HONEYPOT_SERVICES "$services"
set_env "$ENV_FILE" TD_HONEYPOT_PORT_MAP "$port_map"
set_env "$ENV_FILE" TD_HONEYPOT_BIND "$BIND"
set_env "$ENV_FILE" TD_HONEYPOT_PORTS "$(IFS=,; echo "${PORTS[*]+"${PORTS[*]}"}")"
[[ -z "$ADDRESS" ]] || set_env "$ENV_FILE" TD_HONEYPOT_IP "$ADDRESS"
set_env "$ENV_FILE" TD_OPENCANARY_COMMIT "$oc_commit"
set_env "$ENV_FILE" TD_OPENCANARY_VERSION "$oc_tag"

log "honeypot '$NODE' prepared: OpenCanary $oc_tag"
log "decoys: $services"
log "ports on this host: $host_ports"
[[ -n "$ADDRESS" ]] || warn "no --ip given: alerts will show the container's own address as the destination"
