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
#   yara/rules/       the shared and the OT IDS YARA rules, and in a folder each the
#                     external YARA rule sets (among them the ones the product's own
#                     image was built with: see tools/yara_sources.py for why)
#   zeek/intel/       your own indicators (ot-ids/iocs) and external threat feeds
#   attack-ics/       the MITRE ATT&CK for ICS technique reference, to read offline
#
# Each rule that ot-ids/attack/ maps to an ATT&CK for ICS technique gets that
# technique written into its metadata here, in the copy; the rule files in the
# repository stay as they are. Set ATTACK_ICS_TAGS=false to leave the copies untouched.

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
own_yara=()
for folder in "$SHARED/yara" "$KIT/detections/yara"; do
  [[ -d "$folder" ]] || continue
  for file in "$folder"/*.yar "$folder"/*.yara; do
    [[ -f "$file" ]] || continue
    cp "$file" "$DEST/yara/rules/"; copied=$((copied + 1))
    own_yara+=("$DEST/yara/rules/$(basename "$file")")
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

# The product's file scanner compiles its YARA rules from the files in
# ./yara/rules alone as soon as that folder holds one (tools/yara_sources.py).
# So YARA rules go in together or not at all: the TechDetechtives rules and the
# external rule sets (among them the ones the product itself was built with)
# only when every YARA source that is switched on was fetched. With one
# missing, the installed system would scan with a part of the rules instead of
# all of them, and nothing would say so. YARA_ALONE=true puts in whatever there is.
rm -rf "$DEST"/yara/rules/yara-*/          # what an earlier run put here; a source switched off since must not stay
yara_status="${FETCHED:+$FETCHED/yara-sources.txt}"
yara_missing=""
if [[ -z "$yara_status" || ! -s "$yara_status" ]]; then
  yara_missing="no YARA source was fetched"
elif grep -qv ' ok$' "$yara_status"; then
  yara_missing="not fetched: $(grep -v ' ok$' "$yara_status" | cut -d' ' -f1 | tr '\n' ' ')"
fi
if [[ -z "$yara_missing" || "${YARA_ALONE:-false}" == "true" ]]; then
  [[ -n "$FETCHED" && -d "$FETCHED/yara" ]] && cp -a "$FETCHED/yara/." "$DEST/yara/rules/"
  [[ -z "$yara_missing" ]] || echo "[content] WARNING: YARA_ALONE is set: the YARA rules go in although ${yara_missing% }. The installed system scans with these alone." >&2
else
  [[ "${#own_yara[@]}" -eq 0 ]] || rm -f "${own_yara[@]}"
  echo "[content] NOTE: no YARA rules are added (${yara_missing% }). Added in part they would replace the rule sets the" >&2
  echo "[content]       product is built with; left out, the product keeps the set it has." >&2
  others="$(find "$DEST/yara/rules" -type f \( -name '*.yar' -o -name '*.yara' -o -name '*.rule' \) 2>/dev/null | wc -l)"
  [[ "$others" -eq 0 ]] || echo "[content] WARNING: $others YARA rule file(s) of your own are in the folder. On the installed system they will be the only YARA rules." >&2
fi

command -v python3 >/dev/null 2>&1 || { echo "[content] python3 is required" >&2; exit 1; }
if [[ "${ATTACK_ICS_TAGS:-true}" == "true" ]]; then
  python3 "$KIT/tools/attack_ics.py" tag "$DEST"
fi
mkdir -p "$DEST/attack-ics"
python3 "$KIT/tools/attack_ics.py" reference -o "$DEST/attack-ics/attack-ics-techniques.md"

echo "[content] $(find "$DEST/suricata/rules" -name '*.rules' | wc -l) rule files, $(find "$DEST/yara/rules" -type f \( -name '*.yar' -o -name '*.yara' \) | wc -l) YARA files, $(find "$DEST/zeek/intel" -name '*.intel' 2>/dev/null | wc -l) indicator files in $DEST" >&2
