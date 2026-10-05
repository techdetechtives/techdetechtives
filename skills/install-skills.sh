#!/usr/bin/env bash
# TechDetechtives: install the analyst skills for an AI assistant.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
#
# Copies the skills in this folder (the TechDetechtives ones and the reviewed
# community selection) into the folder your assistant reads skills from. Run
# it as the person who uses the assistant, on the machine where it runs.
#
# Usage:
#   skills/install-skills.sh [--target DIR] [--only-techdetechtives]
#   skills/install-skills.sh --list
#   skills/install-skills.sh --remove [--target DIR]
#
#   --target DIR   where to install (default: ~/.claude/skills, which Claude
#                  Code reads; use <project>/.claude/skills for one project, or
#                  your assistant's own skills folder)
#   --only-techdetechtives   leave the community skills out
#   --list         show the skills and stop
#   --remove       remove the skills this script installed from the target

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${HOME}/.claude/skills"
ACTION="install"
WITH_COMMUNITY=1
MARK=".techdetechtives-skill"      # dropped in each installed folder, so --remove only touches ours

die() { printf '[techdetechtives] ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '[techdetechtives] %s\n' "$*"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) shift; [[ $# -gt 0 ]] || die "--target needs a folder"; TARGET="$1" ;;
    --only-techdetechtives) WITH_COMMUNITY=0 ;;
    --list) ACTION="list" ;;
    --remove) ACTION="remove" ;;
    -h|--help) sed -n '5,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
  shift
done

groups=(techdetechtives)
[[ $WITH_COMMUNITY -eq 1 ]] && groups+=(community)

skill_dirs() {
  local group dir
  for group in "${groups[@]}"; do
    for dir in "$HERE/$group"/*/; do
      [[ -f "$dir/SKILL.md" ]] && printf '%s\n' "${dir%/}"
    done
  done
}

case "$ACTION" in
  list)
    while IFS= read -r dir; do
      printf '%-16s %s\n' "$(basename "$(dirname "$dir")")" "$(basename "$dir")"
    done < <(skill_dirs)
    ;;
  install)
    mkdir -p "$TARGET"
    installed=0; skipped=0
    while IFS= read -r dir; do
      name="$(basename "$dir")"
      dest="$TARGET/$name"
      if [[ -e "$dest" && ! -f "$dest/$MARK" ]]; then
        log "skipped $name: $dest already exists and was not installed by this script"
        skipped=$((skipped + 1))
        continue
      fi
      rm -rf "$dest"
      cp -r "$dir" "$dest"
      basename "$(dirname "$dir")" > "$dest/$MARK"
      installed=$((installed + 1))
    done < <(skill_dirs)
    log "installed $installed skills into $TARGET ($skipped skipped)"
    log "start a new assistant session to pick them up"
    ;;
  remove)
    removed=0
    if [[ -d "$TARGET" ]]; then
      for dest in "$TARGET"/*/; do
        [[ -f "$dest/$MARK" ]] || continue
        rm -rf "$dest"
        removed=$((removed + 1))
      done
    fi
    log "removed $removed skills from $TARGET"
    ;;
esac
