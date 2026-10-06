#!/usr/bin/env bash
# TechDetechtives OT IDS. Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
#
# Gather the detection content into one folder laid out like the product's
# ~/Malcolm directory. Used by build-iso.sh (into the ISO) and by
# make-update-bundle.sh (into an offline update). Needs no network.
#
#   collect-content.sh <destination folder> [folder written by fetch_sources.py]
#
# What goes in:
#   suricata/rules/   the shared TechDetechtives rules (platform/detections/suricata),
#                     the OT IDS rules (ot-ids/detections/suricata), external rule sets
#   yara/rules/       the shared and the OT IDS YARA rules
#   zeek/intel/       your own indicators (ot-ids/iocs) and external threat feeds

set -euo pipefail

[[ $# -ge 1 ]] || { echo "Usage: $0 <destination folder> [fetched sources folder]" >&2; exit 2; }
DEST="$1"
FETCHED="${2:-}"
KIT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SHARED="${SHARED_DETECTIONS_DIR:-$KIT/../platform/detections}"

mkdir -p "$DEST/suricata/rules" "$DEST/yara/rules"

copied=0
for folder in "$SHARED/suricata" "$KIT/detections/suricata"; do
  [[ -d "$folder" ]] || continue
  for file in "$folder"/*.rules; do
    [[ -f "$file" ]] || continue
    cp "$file" "$DEST/suricata/rules/"; copied=$((copied + 1))
  done
done
for folder in "$SHARED/yara" "$KIT/detections/yara"; do
  [[ -d "$folder" ]] || continue
  for file in "$folder"/*.yar "$folder"/*.yara; do
    [[ -f "$file" ]] || continue
    cp "$file" "$DEST/yara/rules/"; copied=$((copied + 1))
  done
done
[[ -d "$SHARED/suricata" ]] || echo "[content] note: shared rules folder $SHARED not found; only the OT IDS rules were collected" >&2

# Your own indicators: every .txt or .csv in ot-ids/iocs/ with at least one entry.
inputs=()
for file in "$KIT"/iocs/*.txt "$KIT"/iocs/*.csv; do
  [[ -f "$file" ]] && grep -Eqv '^\s*(#|$)' "$file" && inputs+=("$file")
done
if [[ "${#inputs[@]}" -gt 0 ]]; then
  mkdir -p "$DEST/zeek/intel/custom"
  python3 "$KIT/tools/ioc2intel.py" --source "TechDetechtives custom" --desc "ot-ids/iocs" \
    -o "$DEST/zeek/intel/custom/custom.intel" "${inputs[@]}"
fi

if [[ -n "$FETCHED" && -d "$FETCHED" ]]; then
  [[ -d "$FETCHED/suricata/rules" ]] && cp -a "$FETCHED/suricata/rules/." "$DEST/suricata/rules/"
  [[ -d "$FETCHED/zeek/intel" ]] && { mkdir -p "$DEST/zeek/intel"; cp -a "$FETCHED/zeek/intel/." "$DEST/zeek/intel/"; }
  [[ -f "$FETCHED/SOURCES.txt" ]] && cp "$FETCHED/SOURCES.txt" "$DEST/EXTERNAL-SOURCES.txt"
fi

echo "[content] $(find "$DEST/suricata/rules" -name '*.rules' | wc -l) rule files, $(find "$DEST/yara/rules" -type f | wc -l) YARA files, $(find "$DEST/zeek/intel" -name '*.intel' 2>/dev/null | wc -l) indicator files in $DEST" >&2
