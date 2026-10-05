#!/usr/bin/env bash
# TechDetechtives: refresh the community skills from the pinned upstream commit.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
#
# For maintainers. Copies the skills named in skills/selection.txt from the
# community library (commit pinned in upstream.lock) into skills/community/,
# unchanged, and rewrites skills/MANIFEST.sha256.
#
# Copied per skill: SKILL.md, LICENSE, references/ and assets/.
# Not copied: scripts/ (helper programs that were not reviewed and are not
# needed to read the guidance) and translations.
#
# Usage: skills/sync-skills.sh [--source DIR]
#   --source DIR   use an existing checkout of the library instead of fetching it

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
NAME="cybersecurity-skills"
SOURCE=""

die() { printf '[techdetechtives] ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '[techdetechtives] %s\n' "$*"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source) shift; [[ $# -gt 0 ]] || die "--source needs a folder"; SOURCE="$1" ;;
    -h|--help) sed -n '5,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
  shift
done

pinned="$(awk -F'|' -v n="$NAME" '$1 == n {print $4}' "$ROOT/upstream.lock")"
[[ -n "$pinned" ]] || die "$NAME is not listed in upstream.lock"

if [[ -z "$SOURCE" ]]; then
  "$ROOT/scripts/fetch-upstream.sh" "$NAME"
  SOURCE="$ROOT/upstream/$NAME"
fi
[[ -d "$SOURCE/skills" ]] || die "$SOURCE does not look like the skills library"
actual="$(git -C "$SOURCE" rev-parse HEAD 2>/dev/null || true)"
[[ "$actual" == "$pinned" ]] || die "$SOURCE is at ${actual:-an unknown commit}, but upstream.lock pins $pinned"

dest="$HERE/community"
rm -rf "$dest"
mkdir -p "$dest"
count=0
while IFS= read -r skill; do
  skill="${skill%%#*}"; skill="${skill//[[:space:]]/}"
  [[ -n "$skill" ]] || continue
  [[ "$skill" =~ ^[a-z0-9-]+$ ]] || die "not a skill name: $skill"
  src="$SOURCE/skills/$skill"
  [[ -f "$src/SKILL.md" ]] || die "upstream has no skill named $skill"
  mkdir -p "$dest/$skill"
  cp "$src/SKILL.md" "$dest/$skill/"
  [[ -f "$src/LICENSE" ]] && cp "$src/LICENSE" "$dest/$skill/"
  for part in references assets; do
    [[ -d "$src/$part" ]] && cp -r "$src/$part" "$dest/$skill/"
  done
  count=$((count + 1))
done < "$HERE/selection.txt"

# Text documents only: stop if anything else came along.
unexpected="$(find "$dest" -type f ! -name '*.md' ! -name 'LICENSE' -print -o -type l -print)"
[[ -z "$unexpected" ]] || die "unexpected files in the copied skills:
$unexpected"

(
  cd "$HERE"
  printf '# Community skills as copied from %s\n# sha256  path\n' "$pinned"
  find community -type f | LC_ALL=C sort | xargs sha256sum
) > "$HERE/MANIFEST.sha256"
log "copied $count skills from $NAME at ${pinned:0:12}; manifest written"
