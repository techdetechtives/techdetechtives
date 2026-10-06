#!/usr/bin/env bash
# TechDetechtives OT IDS. Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
#
# Build an offline update for installed systems: current rules, YARA rules and
# threat indicators in one archive, with a checksum beside it.
#
# Run in a checkout of this repository on a machine with Internet access:
#
#   ot-ids/tools/make-update-bundle.sh [output folder]
#
# Carry both files (the .tar.gz and the .sha256) to the appliance on removable
# media and run there:   td-apply-update /path/to/td-update-YYYYMMDD.tar.gz
#
# The checksum shows the archive arrived intact. It does not prove who made it:
# keep the media under your own control, or sign the archive with your own key.

set -euo pipefail

KIT="$(cd -P "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$PWD}"
STAMP="$(date -u +%Y%m%d)"
NAME="td-update-$STAMP"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
command -v git >/dev/null 2>&1 || { echo "git is required" >&2; exit 1; }

echo "[bundle] fetching external sources ..." >&2
python3 "$KIT/tools/fetch_sources.py" --config "$KIT/sources.conf" --out "$WORK/fetched" || \
  echo "[bundle] WARNING: at least one source could not be fetched; the bundle is built from the rest" >&2
# YARA rule sets go in together or not at all (tools/collect-content.sh says why). A bundle
# made while one could not be fetched would take the YARA rules of the last update away.
if [[ "${YARA_ALONE:-false}" != "true" && -s "$WORK/fetched/yara-sources.txt" ]] && grep -qv ' ok$' "$WORK/fetched/yara-sources.txt"; then
  echo "[bundle] ERROR: a YARA rule source could not be fetched ($(grep -v ' ok$' "$WORK/fetched/yara-sources.txt" | cut -d' ' -f1 | tr '\n' ' ')). No bundle was written; try again when it can be reached." >&2
  exit 1
fi

mkdir -p "$WORK/$NAME"
"$KIT/tools/collect-content.sh" "$WORK/$NAME" "$WORK/fetched"
{
  echo "TechDetechtives OT IDS update, built $(date -u '+%Y-%m-%d %H:%M UTC')"
  echo "Repository commit: $(git -C "$KIT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  echo
  (cd "$WORK/$NAME" && find . -type f ! -name MANIFEST.txt | sort | xargs sha256sum)
} > "$WORK/$NAME/MANIFEST.txt"

mkdir -p "$OUT_DIR"
tar -C "$WORK" --owner=0 --group=0 --numeric-owner -czf "$OUT_DIR/$NAME.tar.gz" "$NAME"
(cd "$OUT_DIR" && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256")
echo "[bundle] wrote $OUT_DIR/$NAME.tar.gz and its .sha256" >&2
