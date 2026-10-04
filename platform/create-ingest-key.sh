#!/usr/bin/env bash
# TechDetechtives: create an Elasticsearch API key that can only add
# vulnerability scan results to the platform.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
#
# Run on the Security Onion manager as root.
#
# Usage:
#   sudo ./create-ingest-key.sh [--expiration 365d]
#
# The key can append documents to the logs-greenbone.results-* data stream and
# nothing else. It cannot read, change or delete any data.

set -euo pipefail

KEY_NAME="techdetechtives-vulnerability-ingest"
EXPIRATION="365d"

die() { printf '[techdetechtives] ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '[techdetechtives] %s\n' "$*"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --expiration) shift; [[ $# -gt 0 ]] || die "--expiration needs a value"; EXPIRATION="$1" ;;
    -h|--help)    sed -n '2,13p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
  shift
done

[[ $EUID -eq 0 ]] || die "run this as root on the Security Onion manager"
command -v so-elasticsearch-query >/dev/null 2>&1 || die "so-elasticsearch-query not found; run this on the manager node"
command -v jq >/dev/null 2>&1 || die "jq not found"

body="$(jq -n --arg name "$KEY_NAME" --arg exp "$EXPIRATION" '{
  name: $name,
  expiration: $exp,
  role_descriptors: {
    techdetechtives_vulnerability_ingest: {
      cluster: ["monitor"],
      indices: [
        { names: ["logs-greenbone.results-*"], privileges: ["auto_configure", "create_doc"] }
      ]
    }
  },
  metadata: { application: "techdetechtives-vulnerability" }
}')"

response="$(so-elasticsearch-query _security/api_key -XPOST -d "$body")"
encoded="$(jq -r '.encoded // empty' <<< "$response")"
[[ -n "$encoded" ]] || die "Elasticsearch did not return a key. Response: $response"

cat <<EOF2

Ingest key "$KEY_NAME" created (expires in $EXPIRATION).
It is shown once. Add this line to config/techdetechtives.env on the ticketing machine:

TD_ES_INGEST_API_KEY=$encoded

Then re-run:  scripts/install.sh vulnerability

The machine also needs the platform connection from platform/create-readonly-key.sh
(TD_ES_HOST, the CA certificate, and firewall access to port 9200).

EOF2
log "to revoke the key later: so-elasticsearch-query _security/api_key -XDELETE -d '{\"name\":\"$KEY_NAME\"}'"
