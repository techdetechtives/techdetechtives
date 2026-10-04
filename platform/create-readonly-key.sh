#!/usr/bin/env bash
# TechDetechtives: create a read-only Elasticsearch API key for the analytics
# workbench, and optionally allow the analytics host through the firewall.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
#
# Run on the Security Onion manager as root.
#
# Usage:
#   sudo ./create-readonly-key.sh [--expiration 90d] [--allow-ip 10.0.0.25]
#
# The key can search the logs-* and so-* indices and nothing else. It cannot
# write, delete, or change settings.

set -euo pipefail

KEY_NAME="techdetechtives-analytics-ro"
EXPIRATION="90d"
ALLOW_IP=""

die() { printf '[techdetechtives] ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '[techdetechtives] %s\n' "$*"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --expiration) shift; [[ $# -gt 0 ]] || die "--expiration needs a value"; EXPIRATION="$1" ;;
    --allow-ip)   shift; [[ $# -gt 0 ]] || die "--allow-ip needs a value"; ALLOW_IP="$1" ;;
    -h|--help)    sed -n '2,13p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
  shift
done

[[ $EUID -eq 0 ]] || die "run this as root on the Security Onion manager"
command -v so-elasticsearch-query >/dev/null 2>&1 || die "so-elasticsearch-query not found; run this on the manager node"
command -v jq >/dev/null 2>&1 || die "jq not found"

if [[ -n "$ALLOW_IP" ]]; then
  [[ "$ALLOW_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] || die "--allow-ip must be an IPv4 address or CIDR block"
fi

body="$(jq -n --arg name "$KEY_NAME" --arg exp "$EXPIRATION" '{
  name: $name,
  expiration: $exp,
  role_descriptors: {
    techdetechtives_read: {
      cluster: ["monitor"],
      indices: [
        { names: ["logs-*", "so-*"], privileges: ["read", "view_index_metadata"] }
      ]
    }
  },
  metadata: { application: "techdetechtives-analytics" }
}')"

response="$(so-elasticsearch-query _security/api_key -XPOST -d "$body")"
encoded="$(jq -r '.encoded // empty' <<< "$response")"
[[ -n "$encoded" ]] || die "Elasticsearch did not return a key. Response: $response"

if [[ -n "$ALLOW_IP" ]]; then
  log "allowing $ALLOW_IP to reach Elasticsearch (port 9200)"
  so-firewall includehost elasticsearch_rest "$ALLOW_IP"
  so-firewall apply
fi

cat <<EOF

Read-only key "$KEY_NAME" created (expires in $EXPIRATION).
It is shown once. Put these lines in config/techdetechtives.env on the analytics host:

TD_ES_HOST=$(hostname -f 2>/dev/null || hostname)
TD_ES_API_KEY=$encoded

Then copy this manager's CA certificate to the analytics host:

  scp /etc/pki/ca.crt ANALYTICS-HOST:/path/to/techdetechtives/analytics/certs/so-ca.crt

EOF
if [[ -z "$ALLOW_IP" ]]; then
  cat <<EOF
The analytics host also needs firewall access to port 9200. Either re-run with
--allow-ip <analytics host IP>, or run:

  so-firewall includehost elasticsearch_rest <analytics host IP>
  so-firewall apply

EOF
fi
log "to revoke the key later: so-elasticsearch-query _security/api_key -XDELETE -d '{\"name\":\"$KEY_NAME\"}'"
