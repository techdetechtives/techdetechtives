#!/usr/bin/env bash
# TechDetechtives: create an Elasticsearch API key that can only add one kind
# of data to the platform.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
#
# Run on the Security Onion manager as root.
#
# Usage:
#   sudo ./create-ingest-key.sh [--for vulnerability|honeypot] [--expiration 365d] [--allow-ip ADDRESS]
#
#   --for vulnerability   (default) key for the vulnerability connector: it can
#                         append to the logs-greenbone.results-* data stream
#   --for honeypot        key for the honeypot shipper: it can append to the
#                         logs-opencanary.* data streams
#   --allow-ip            also let that machine reach the platform on port 9200
#                         (needed when it is not already allowed)
#
# Each key can append documents to its own data stream and nothing else. It
# cannot read, change or delete any data, so a machine that holds one (the
# honeypot in particular) gives an intruder no view into the platform.

set -euo pipefail

PURPOSE="vulnerability"
EXPIRATION="365d"
ALLOW_IP=""

die() { printf '[techdetechtives] ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '[techdetechtives] %s\n' "$*"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --for)        shift; [[ $# -gt 0 ]] || die "--for needs a value"; PURPOSE="$1" ;;
    --expiration) shift; [[ $# -gt 0 ]] || die "--expiration needs a value"; EXPIRATION="$1" ;;
    --allow-ip)   shift; [[ $# -gt 0 ]] || die "--allow-ip needs a value"; ALLOW_IP="$1" ;;
    -h|--help)    sed -n '2,21p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
  shift
done

case "$PURPOSE" in
  vulnerability)
    KEY_NAME="techdetechtives-vulnerability-ingest"
    INDEX_PATTERN="logs-greenbone.results-*"
    SETTING="TD_ES_INGEST_API_KEY"
    MACHINE="the ticketing machine"
    NEXT="scripts/install.sh vulnerability"
    ;;
  honeypot)
    KEY_NAME="techdetechtives-honeypot-ingest"
    INDEX_PATTERN="logs-opencanary.*"
    SETTING="TD_HONEYPOT_API_KEY"
    MACHINE="the honeypot machine"
    NEXT="scripts/install.sh honeypot"
    ;;
  *) die "--for must be vulnerability or honeypot" ;;
esac

[[ $EUID -eq 0 || "${TD_SKIP_ROOT_CHECK:-0}" == "1" ]] || die "run this as root on the Security Onion manager"
command -v so-elasticsearch-query >/dev/null 2>&1 || die "so-elasticsearch-query not found; run this on the manager node"
command -v jq >/dev/null 2>&1 || die "jq not found"
if [[ -n "$ALLOW_IP" ]]; then
  [[ "$ALLOW_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] || die "--allow-ip must be an IPv4 address or CIDR block"
fi

body="$(jq -n --arg name "$KEY_NAME" --arg exp "$EXPIRATION" --arg pattern "$INDEX_PATTERN" --arg app "techdetechtives-$PURPOSE" '{
  name: $name,
  expiration: $exp,
  role_descriptors: {
    techdetechtives_ingest: {
      cluster: ["monitor"],
      indices: [
        { names: [$pattern], privileges: ["auto_configure", "create_doc"] }
      ]
    }
  },
  metadata: { application: $app }
}')"

response="$(so-elasticsearch-query _security/api_key -XPOST -d "$body")"
encoded="$(jq -r '.encoded // empty' <<< "$response")"
[[ -n "$encoded" ]] || die "Elasticsearch did not return a key. Response: $response"

if [[ -n "$ALLOW_IP" ]]; then
  log "allowing $ALLOW_IP to reach Elasticsearch (port 9200)"
  so-firewall includehost elasticsearch_rest "$ALLOW_IP"
  so-firewall apply
fi

cat <<EOF2

Ingest key "$KEY_NAME" created (expires in $EXPIRATION).
It can only append to $INDEX_PATTERN.
It is shown once. Add this line to config/techdetechtives.env on $MACHINE:

$SETTING=$encoded

Then re-run:  $NEXT

That machine also needs the platform's name in TD_ES_HOST, this manager's CA
certificate (/etc/pki/ca.crt) saved as analytics/certs/so-ca.crt, and firewall
access to port 9200 (--allow-ip, or platform/create-readonly-key.sh --allow-ip).

EOF2
log "to revoke the key later: so-elasticsearch-query _security/api_key -XDELETE -d '{\"name\":\"$KEY_NAME\"}'"
