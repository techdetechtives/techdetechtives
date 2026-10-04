#!/usr/bin/env bash
# TechDetechtives platform overlay.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
#
# Applies TechDetechtives branding and detections to an installed Security
# Onion manager, using only the customization points Security Onion provides:
#   - the console's login banner and overview page (local Salt file overrides)
#   - the local Sigma / Suricata / YARA rule repositories
# It does not change Security Onion code, its licence notices, its logo or its
# licence-key features.
#
# Usage:
#   sudo ./apply-overlay.sh apply  [--dry-run] [--no-salt] [--jupyter-url URL]
#   sudo ./apply-overlay.sh revert [--dry-run] [--no-salt]
#   sudo ./apply-overlay.sh status

set -euo pipefail

TESTED_SO_VERSION="3.3.0"

# Paths on a Security Onion manager. Overridable for testing.
SO_VERSION_FILE="${TD_SO_VERSION_FILE:-/etc/soversion}"
SO_LOCAL="${TD_SO_LOCAL:-/opt/so/saltstack/local}"
RULE_REPOS="${TD_RULE_REPOS:-/nsm/rules/custom-local-repos}"
BACKUP_ROOT="${TD_BACKUP_ROOT:-/nsm/backup/techdetechtives}"
SO_USER="${TD_SO_USER:-socore}"

SOC_FILES="$SO_LOCAL/salt/soc/files/soc"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BRANDING_FILES=(banner.md motd.md)
# engine : source folder : file glob : local repo name
RULE_SETS=(
  "sigma:detections/sigma:*.yml:local-sigma"
  "suricata:detections/suricata:*.rules:local-suricata"
  "yara:detections/yara:*.yar:local-yara"
)

COMMAND=""
DRY_RUN=0
RUN_SALT=1
JUPYTER_URL="${TD_JUPYTER_URL:-https://ANALYTICS-HOST:8888 (ask your administrator)}"

log()  { printf '[techdetechtives] %s\n' "$*"; }
warn() { printf '[techdetechtives] WARNING: %s\n' "$*" >&2; }
die()  { printf '[techdetechtives] ERROR: %s\n' "$*" >&2; exit 1; }

usage() { sed -n '12,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

run() {
  # Run a command, or only print it in dry-run mode.
  if [[ $DRY_RUN -eq 1 ]]; then
    printf '[dry-run] %s\n' "$*"
  else
    "$@"
  fi
}

have_so_user() { id "$SO_USER" >/dev/null 2>&1; }

own() {
  # Hand a file to the Security Onion service user when running as root.
  if [[ $EUID -eq 0 ]] && have_so_user; then
    run chown "$SO_USER:$SO_USER" "$@"
  fi
}

repo_git() {
  # git inside a local rule repository, as the repository's owner.
  local repo="$1"; shift
  local base=(git -C "$repo" -c "safe.directory=$repo"
              -c user.name="TechDetechtives overlay"
              -c user.email="overlay@techdetechtives.invalid")
  if [[ $EUID -eq 0 ]] && have_so_user; then
    sudo -u "$SO_USER" "${base[@]}" "$@"
  else
    "${base[@]}" "$@"
  fi
}

preflight() {
  if [[ $EUID -ne 0 && "${TD_SKIP_ROOT_CHECK:-0}" != "1" ]]; then
    die "run this as root on the Security Onion manager (sudo $0 $COMMAND)"
  fi
  [[ -f "$SO_VERSION_FILE" ]] || die "$SO_VERSION_FILE not found. Install Security Onion first; this overlay does not install it."
  [[ -d "$SO_LOCAL" ]] || die "$SO_LOCAL not found. Run this on the manager node."
  local version
  version="$(tr -d '[:space:]' < "$SO_VERSION_FILE")"
  log "Security Onion version: $version (overlay tested against $TESTED_SO_VERSION)"
  if [[ "${version%%.*}" != "${TESTED_SO_VERSION%%.*}" ]]; then
    warn "major version differs from the tested one; check MODIFICATIONS.md before continuing"
  fi
}

latest_backup() {
  [[ -d "$BACKUP_ROOT" ]] || return 0
  find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1
}

overlay_pages_installed() {
  local f
  for f in "${BRANDING_FILES[@]}"; do
    if [[ -f "$SOC_FILES/$f" ]] && grep -q "TechDetechtives" "$SOC_FILES/$f"; then
      return 0
    fi
  done
  return 1
}

backup_branding() {
  local stamp dest f
  # Re-applying over our own pages must not replace the backup of the
  # original ones, or revert would restore TechDetechtives pages.
  if overlay_pages_installed && [[ -n "$(latest_backup)" ]]; then
    log "overlay pages already installed; keeping the existing backup"
    return 0
  fi
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  dest="$BACKUP_ROOT/$stamp"
  run mkdir -p "$dest"
  for f in "${BRANDING_FILES[@]}"; do
    if [[ -f "$SOC_FILES/$f" ]]; then
      run cp -p "$SOC_FILES/$f" "$dest/$f"
    else
      # Remember that there was no local override, so revert removes ours.
      run touch "$dest/$f.absent"
    fi
  done
  log "previous console pages saved to $dest"
}

install_branding() {
  local f tmp
  run mkdir -p "$SOC_FILES"
  own "$SOC_FILES"
  for f in "${BRANDING_FILES[@]}"; do
    [[ -f "$HERE/branding/$f" ]] || die "missing $HERE/branding/$f"
    if [[ $DRY_RUN -eq 1 ]]; then
      printf '[dry-run] install %s -> %s\n' "branding/$f" "$SOC_FILES/$f"
      continue
    fi
    tmp="$(mktemp)"
    # Only substitution in the files: where the analytics workbench lives.
    sed "s|@@TD_JUPYTER_URL@@|${JUPYTER_URL//|/\\|}|g" "$HERE/branding/$f" > "$tmp"
    install -m 0644 "$tmp" "$SOC_FILES/$f"
    rm -f "$tmp"
    own "$SOC_FILES/$f"
    log "installed $SOC_FILES/$f"
  done
}

each_rule_set() {
  # Calls: $1 <engine> <source dir> <glob> <repo dir>
  local fn="$1" entry engine src glob repo
  for entry in "${RULE_SETS[@]}"; do
    IFS=: read -r engine src glob repo <<< "$entry"
    "$fn" "$engine" "$HERE/$src" "$glob" "$RULE_REPOS/$repo"
  done
}

install_rules() {
  local engine="$1" src="$2" glob="$3" repo="$4" f name changed=0
  if [[ ! -d "$repo/.git" ]]; then
    warn "$repo is not a git repository; skipping $engine rules"
    return 0
  fi
  shopt -s nullglob
  local files=("$src"/$glob)
  shopt -u nullglob
  [[ ${#files[@]} -gt 0 ]] || { log "no $engine rules to install"; return 0; }
  for f in "${files[@]}"; do
    name="$(basename "$f")"
    if [[ $DRY_RUN -eq 1 ]]; then
      printf '[dry-run] install %s rule %s -> %s\n' "$engine" "$name" "$repo/"
      continue
    fi
    install -m 0644 "$f" "$repo/$name"
    own "$repo/$name"
    repo_git "$repo" add -- "$name"
  done
  [[ $DRY_RUN -eq 1 ]] && return 0
  if ! repo_git "$repo" diff --cached --quiet; then
    repo_git "$repo" commit -q -m "TechDetechtives $engine rules ($(cat "$HERE/../VERSION" 2>/dev/null || echo dev))"
    changed=1
  fi
  if [[ $changed -eq 1 ]]; then
    log "$engine: committed ${#files[@]} rule file(s) to $repo"
  else
    log "$engine: already up to date"
  fi
}

remove_rules() {
  local engine="$1" src="$2" glob="$3" repo="$4" f name
  [[ -d "$repo/.git" ]] || return 0
  shopt -s nullglob
  local files=("$src"/$glob)
  shopt -u nullglob
  for f in "${files[@]}"; do
    name="$(basename "$f")"
    if [[ -f "$repo/$name" ]]; then
      if [[ $DRY_RUN -eq 1 ]]; then
        printf '[dry-run] remove %s rule %s from %s\n' "$engine" "$name" "$repo/"
      else
        repo_git "$repo" rm -q -f -- "$name"
      fi
    fi
  done
  [[ $DRY_RUN -eq 1 ]] && return 0
  if ! repo_git "$repo" diff --cached --quiet; then
    repo_git "$repo" commit -q -m "Remove TechDetechtives $engine rules"
    log "$engine: rules removed from $repo"
  fi
}

status_rules() {
  local engine="$1" src="$2" glob="$3" repo="$4" f name present=0 total=0
  shopt -s nullglob
  local files=("$src"/$glob)
  shopt -u nullglob
  for f in "${files[@]}"; do
    name="$(basename "$f")"
    total=$((total + 1))
    if [[ -f "$repo/$name" ]] && cmp -s "$f" "$repo/$name"; then
      present=$((present + 1))
    fi
  done
  log "$engine rules installed: $present of $total"
  [[ $present -eq $total ]]
}

apply_salt() {
  if [[ $RUN_SALT -eq 0 ]]; then
    log "skipping Salt (--no-salt); the console picks the pages up on its next scheduled sync"
    return 0
  fi
  command -v salt-call >/dev/null 2>&1 || { warn "salt-call not found; skipping state apply"; return 0; }
  log "applying the console state (this can take a minute)"
  run salt-call state.apply soc queue=True
}

cmd_apply() {
  preflight
  backup_branding
  install_branding
  each_rule_set install_rules
  apply_salt
  log "done. New rules load at the next rule sync, or immediately from"
  log "Detections -> Options -> (engine) -> Full Update in the console."
}

cmd_revert() {
  preflight
  local backup f
  backup="$(latest_backup)"
  [[ -n "$backup" ]] || die "no backup found under $BACKUP_ROOT; nothing to revert"
  log "restoring console pages from $backup"
  for f in "${BRANDING_FILES[@]}"; do
    if [[ -f "$backup/$f" ]]; then
      run cp -p "$backup/$f" "$SOC_FILES/$f"
    elif [[ -f "$backup/$f.absent" ]]; then
      run rm -f "$SOC_FILES/$f"
    fi
  done
  each_rule_set remove_rules
  apply_salt
  log "reverted. The backup was left in place at $backup"
}

cmd_status() {
  preflight
  local ok=0 f
  for f in "${BRANDING_FILES[@]}"; do
    if [[ -f "$SOC_FILES/$f" ]] && grep -q "TechDetechtives" "$SOC_FILES/$f"; then
      log "console page $f: installed"
    else
      log "console page $f: not installed"
      ok=1
    fi
  done
  each_rule_set status_rules || ok=1
  return $ok
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    apply|revert|status) COMMAND="$1" ;;
    --dry-run) DRY_RUN=1 ;;
    --no-salt) RUN_SALT=0 ;;
    --jupyter-url) shift; [[ $# -gt 0 ]] || die "--jupyter-url needs a value"; JUPYTER_URL="$1" ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
  shift
done

case "$COMMAND" in
  apply)  cmd_apply ;;
  revert) cmd_revert ;;
  status) cmd_status ;;
  *) usage >&2; exit 2 ;;
esac
