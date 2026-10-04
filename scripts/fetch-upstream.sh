#!/usr/bin/env bash
# TechDetechtives: fetch the upstream projects at the commits in upstream.lock.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
#
# The copies land in upstream/ (git-ignored) for reference and for comparing
# against new upstream releases. They are not part of this repository and keep
# their own licences.
#
# Usage: scripts/fetch-upstream.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$ROOT/upstream"

while IFS='|' read -r name repo branch commit version licence; do
  [[ -z "$name" || "$name" == \#* ]] && continue
  dest="$ROOT/upstream/$name"
  if [[ ! -d "$dest/.git" ]]; then
    git init -q "$dest"
    git -C "$dest" remote add origin "$repo"
  fi
  git -C "$dest" fetch -q --depth 1 origin "$commit"
  git -C "$dest" -c advice.detachedHead=false checkout -q FETCH_HEAD
  printf '%s %s (%s, %s) at %s\n' "$name" "$version" "$branch" "$licence" "$(git -C "$dest" rev-parse --short HEAD)"
done < "$ROOT/upstream.lock"
