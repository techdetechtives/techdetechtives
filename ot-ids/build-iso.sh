#!/usr/bin/env bash
# TechDetechtives OT IDS installer ISO build.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
#
# Builds two bootable installer ISOs from a pinned Malcolm release
# (https://github.com/idaholab/Malcolm, Apache 2.0):
#   - the central server  (Zeek + ICSNPP + ACID, Suricata, OpenSearch Dashboards, Arkime, NetBox)
#   - the capture sensor  (Malcolm's "hedgehog" profile)
# with the product name and logo on the boot menu, desktop and web applications,
# the TechDetechtives detection content and external rule sets and threat
# indicators preloaded, extra hardening, and (optionally) all container images
# embedded so the ISO installs with no Internet connection.
#
# Usage:   ./build-iso.sh [prepare|sources|images|iso|all]        (default: all)
# Config:  edit build.conf next to this script.
#
# Run it on an x86-64 Linux build host that HAS Internet access.

set -euo pipefail

KIT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
[[ -f "$KIT_DIR/build.conf" ]] && source "$KIT_DIR/build.conf"

BRAND_NAME="${BRAND_NAME:-TechDetechtives}"        # shown on boot menu; letters, digits, space . _ -
MALCOLM_REPO="${MALCOLM_REPO:-https://github.com/idaholab/Malcolm.git}"
MALCOLM_REF="${MALCOLM_REF:-v26.09.0}"             # pinned release tag
MALCOLM_COMMIT="${MALCOLM_COMMIT-b09a0adaee18421bcc24f3c5608d2135a6ee84bb}"   # what that tag must point at; empty = do not check
FLAVORS="${FLAVORS:-malcolm hedgehog}"             # malcolm = server, hedgehog = sensor
INCLUDE_IMAGES="${INCLUDE_IMAGES:-true}"           # true = air-gap ready ISO (much larger)
BRAND_WEB="${BRAND_WEB:-true}"                     # true = logo and name in the web applications too
BUILD_MODE="${BUILD_MODE:-auto}"                   # auto | vagrant | native (native = Debian 13 host)
FETCH_SOURCES="${FETCH_SOURCES:-true}"             # true = download the sources enabled in sources.conf
HARDENING="${HARDENING:-true}"                     # true = add the files under hardening/ to the ISO
HARDEN_SHELL_TIMEOUT="${HARDEN_SHELL_TIMEOUT:-900}"        # seconds before an idle SSH/console shell closes; 0 = never
HARDEN_USB_STORAGE_OFF="${HARDEN_USB_STORAGE_OFF:-false}"  # true = block USB sticks (also blocks updates by USB)
WORK_DIR="${WORK_DIR:-$KIT_DIR/work}"
OUT_DIR="${OUT_DIR:-$KIT_DIR/out}"
OVERLAY_DIR="${OVERLAY_DIR:-$KIT_DIR/overlay}"
FETCHED_DIR="$WORK_DIR/sources-out"

SRC_DIR="$WORK_DIR/Malcolm"
ISO_DIR="$SRC_DIR/malcolm-iso"
SKEL_DEST="$ISO_DIR/config/includes.chroot/etc/skel/Malcolm"

log()  { printf '\033[1;32m[kit]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m[kit] WARNING:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[kit] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not installed. $2"; }

[[ "$BRAND_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9\ ._-]{0,39}$ ]] || \
  die "BRAND_NAME may only contain letters, digits, space, dot, underscore and dash (max 40 chars)."
[[ "$HARDEN_SHELL_TIMEOUT" =~ ^[0-9]+$ ]] || die "HARDEN_SHELL_TIMEOUT must be a number of seconds."
BRAND_SLUG="$(printf '%s' "$BRAND_NAME" | tr '[:upper:] ' '[:lower:]-')"

for F in $FLAVORS; do
  [[ "$F" == "malcolm" || "$F" == "hedgehog" ]] || die "FLAVORS may only contain 'malcolm' and/or 'hedgehog' (got '$F')."
done

flavor_label() { [[ "$1" == "hedgehog" ]] && echo "${BRAND_SLUG}-sensor" || echo "${BRAND_SLUG}-server"; }
images_file()  { echo "$WORK_DIR/${BRAND_SLUG}_${1}_images.tar.xz"; }

# ---------------------------------------------------------------------------
preflight() {
  [[ "$(uname -s)" == "Linux" ]]  || die "Run this on a Linux build host."
  [[ "$(uname -m)" == "x86_64" ]] || die "The ISO is amd64 only; build on an x86-64 host."
  need git   "Install git."
  mkdir -p "$WORK_DIR" "$OUT_DIR"
  local free_gb
  free_gb="$(df -BG --output=avail "$WORK_DIR" | tail -1 | tr -dc '0-9')"
  [[ "${free_gb:-0}" -ge 80 ]] || warn "Only ${free_gb:-?} GB free under $WORK_DIR; 80 GB or more is recommended when embedding images."
}

resolve_build_mode() {
  [[ "$BUILD_MODE" != "auto" ]] && return 0
  if command -v lb >/dev/null 2>&1 && grep -qs 'VERSION_CODENAME=trixie' /etc/os-release; then
    BUILD_MODE=native
  else
    BUILD_MODE=vagrant
  fi
  log "Build mode: $BUILD_MODE"
}

# ---------------------------------------------------------------------------
# prepare: fetch the pinned source, apply branding, drop in the overlay content
cmd_prepare() {
  preflight
  if [[ ! -d "$SRC_DIR/.git" ]]; then
    log "Cloning Malcolm $MALCOLM_REF ..."
    git -c advice.detachedHead=false clone -q --depth 1 --branch "$MALCOLM_REF" "$MALCOLM_REPO" "$SRC_DIR"
    echo "$MALCOLM_REF" > "$WORK_DIR/.malcolm_ref"
    if [[ -n "$MALCOLM_COMMIT" && "$(git -C "$SRC_DIR" rev-parse HEAD)" != "$MALCOLM_COMMIT" ]]; then
      rm -rf "$SRC_DIR"
      die "The tag $MALCOLM_REF no longer points at commit $MALCOLM_COMMIT. Check the release before changing MALCOLM_COMMIT in build.conf."
    fi
  else
    [[ "$(cat "$WORK_DIR/.malcolm_ref" 2>/dev/null)" == "$MALCOLM_REF" ]] || \
      die "$SRC_DIR holds a different release than MALCOLM_REF=$MALCOLM_REF. Delete $WORK_DIR and run again."
    log "Reusing source in $SRC_DIR (resetting earlier kit changes) ..."
    git -C "$SRC_DIR" checkout -q -- .
    git -C "$SRC_DIR" clean -fdq -- malcolm-iso/config/includes.chroot malcolm-iso/shared
  fi

  local build_sh="$ISO_DIR/build.sh"
  [[ -f "$build_sh" ]] || die "malcolm-iso/build.sh not found; is MALCOLM_REF a release that has it?"

  # --- branding: boot menu text ------------------------------------------------
  # build.sh derives the menu text from the flavor name ("Malcolm"/"Hedgehog").
  # Teach it a BRAND_LABEL instead. Verified against v26.09.0; the check below
  # stops the build if a future release changes those lines.
  sed -i \
    -e "0,/^set -e\$/s||set -e\n# Modified by the ${BRAND_NAME} ISO build kit: brand label for boot menus\n[[ \"\$IMAGE_NAME\" == \"hedgehog\" ]] \&\& BRAND_LABEL=\"${BRAND_NAME} Sensor\" \|\| BRAND_LABEL=\"${BRAND_NAME}\"|" \
    -e 's|\${IMAGE_NAME^} \$IMAGE_VERSION \$(date|${BRAND_LABEL} $IMAGE_VERSION $(date|' \
    -e 's|Install \${IMAGE_NAME^}@g|Install ${BRAND_LABEL}@g|' \
    "$build_sh"
  [[ "$(grep -o 'BRAND_LABEL' "$build_sh" | wc -l)" -eq 5 ]] || \
    die "Could not apply the boot-menu branding to malcolm-iso/build.sh (layout changed in $MALCOLM_REF?)."
  bash -n "$build_sh" || die "Patched build.sh no longer parses."

  # --- branding: images (all optional) ------------------------------------------
  local b="$OVERLAY_DIR/branding"
  if [[ -f "$b/splash.png" ]]; then       # 640x480 PNG, UEFI boot menu background
    cp "$b/splash.png" "$ISO_DIR/config/bootloaders/grub-pc/splash-malcolm.png"
    cp "$b/splash.png" "$ISO_DIR/config/bootloaders/grub-pc/splash-hedgehog.png"
    log "Applied branding/splash.png"
  fi
  if [[ -f "$b/splash.svg" ]]; then       # legacy BIOS boot menu background
    cp "$b/splash.svg" "$ISO_DIR/config/bootloaders/syslinux_common/splash-malcolm.svg"
    cp "$b/splash.svg" "$ISO_DIR/config/bootloaders/syslinux_common/splash-hedgehog.svg"
    log "Applied branding/splash.svg"
  fi
  if [[ -f "$b/wallpaper.png" ]]; then    # 1920x1080 PNG, desktop wallpaper
    cp "$b/wallpaper.png" "$SRC_DIR/docs/images/logo/Malcolm_background.png"
    cp "$b/wallpaper.png" "$SRC_DIR/docs/images/hedgehog/logo/hedgehog-wallpaper.png"
    log "Applied branding/wallpaper.png"
  fi

  # --- branding: web applications ---------------------------------------------------
  # Swap the logo files and the product name in the source tree. The desktop
  # icons are taken from here by the ISO build; the web applications get them
  # through the thin image layers built in the 'images' stage.
  if [[ "$BRAND_WEB" == "true" && -d "$b/web" ]]; then
    cp "$b"/web/favicon/* "$SRC_DIR/docs/images/favicon/"
    cp "$b"/web/icon/*    "$SRC_DIR/docs/images/icon/"
    cp "$b"/web/logo/*    "$SRC_DIR/docs/images/logo/"
    local rel='<a href="https://github.com/idaholab/Malcolm/releases">Malcolm MALCOLM_VERSION_REPLACER</a>'
    local lp="$SRC_DIR/nginx/landingpage"
    sed -i "s|<title>Malcolm</title>|<title>${BRAND_NAME}</title>|" "$lp/index.html"
    sed -i "s|${rel}|${BRAND_NAME}, built on &|" "$lp/index.html" "$lp/404.html" "$lp/502.html"
    sed -i "s|Malcolm has encountered an error|${BRAND_NAME} has encountered an error|" "$lp/502.html"
    sed -i "s|alt=\"Malcolm\"|alt=\"${BRAND_NAME}\"|" "$SRC_DIR/file-upload/site/index.html"
    sed -i "s|applicationTitle: \"Malcolm Dashboards\"|applicationTitle: \"${BRAND_NAME} Dashboards\"|" \
      "$SRC_DIR/dashboards/opensearch_dashboards.yml"
    grep -q "<title>${BRAND_NAME}</title>" "$lp/index.html" && \
      grep -q "${BRAND_NAME}, built on <a" "$lp/index.html" && \
      grep -q "${BRAND_NAME}, built on <a" "$lp/404.html" && \
      grep -q "${BRAND_NAME}, built on <a" "$lp/502.html" && \
      grep -q "${BRAND_NAME} has encountered an error" "$lp/502.html" && \
      grep -q "alt=\"${BRAND_NAME}\"" "$SRC_DIR/file-upload/site/index.html" && \
      grep -q "applicationTitle: \"${BRAND_NAME} Dashboards\"" "$SRC_DIR/dashboards/opensearch_dashboards.yml" || \
      die "Could not apply the web branding text (page layout changed in $MALCOLM_REF?)."
    log "Applied web branding (icons, banners, page titles)"
  fi

  # --- content overlay ------------------------------------------------------------
  # Everything under overlay/malcolm/ lands in ~/Malcolm on the installed system
  # (e.g. overlay/malcolm/suricata/rules/*.rules -> ~/Malcolm/suricata/rules/).
  # It can ADD files; files the Malcolm build itself writes keep their content.
  mkdir -p "$SKEL_DEST"
  if [[ -d "$OVERLAY_DIR/malcolm" ]]; then
    cp -a "$OVERLAY_DIR/malcolm/." "$SKEL_DEST/"
    find "$SKEL_DEST" -name '.gitkeep' -delete
    log "Overlay files added: $(find "$SKEL_DEST" -type f | wc -l)"
  fi

  # --- detection content ------------------------------------------------------
  # Shared TechDetechtives rules, the OT IDS rules, your own indicators, and
  # whatever an earlier 'sources' stage downloaded.
  "$KIT_DIR/tools/collect-content.sh" "$SKEL_DEST" "$FETCHED_DIR"

  apply_hardening

  cat > "$SKEL_DEST/${BRAND_SLUG}-NOTICE.txt" <<EOF
${BRAND_NAME} is built on Malcolm ${MALCOLM_REF} (https://github.com/idaholab/Malcolm),
Copyright Battelle Energy Alliance, LLC, licensed under the Apache License 2.0.
Malcolm's LICENSE.txt and NOTICE.txt apply to that code and must stay with any
copy you distribute. Changes made by the ${BRAND_NAME} build: boot menu,
desktop and web interface branding (logo, name, icons); additional detection
rules, anomaly detectors, alert monitors and threat indicators (this
directory; EXTERNAL-SOURCES.txt lists third-party content and its licences);
and additional operating-system hardening (sysctl, module and SSH settings,
login banner, idle-session timeout).
EOF
  log "Source prepared in $SRC_DIR"
}

# ---------------------------------------------------------------------------
# Extra hardening on top of the base system's (which already has a default-deny
# firewall, key-only SSH without root login, audit rules, strong password rules
# and a CIS/STIG-derived baseline). Everything here is a plain settings file.
apply_hardening() {
  [[ "$HARDENING" == "true" ]] || { log "HARDENING is off; only the base system's hardening applies."; return 0; }
  local root="$ISO_DIR/config/includes.chroot" file
  cp -a "$KIT_DIR/hardening/rootfs/." "$root/"
  chmod 755 "$root/usr/local/bin/td-hardening-check" "$root/usr/local/bin/td-apply-update"

  for file in "$root/etc/issue" "$root/etc/issue.net"; do
    cat > "$file" <<EOF
${BRAND_NAME} OT IDS

Authorised use only. Activity on this system is monitored and recorded.
Disconnect now if you are not an authorised user.

EOF
  done

  if [[ "$HARDEN_SHELL_TIMEOUT" -gt 0 ]]; then
    mkdir -p "$root/etc/profile.d"
    cat > "$root/etc/profile.d/ot-ids-session-timeout.sh" <<EOF
# ${BRAND_NAME} OT IDS: close an SSH or console login shell left idle at its
# prompt. A running command (a log view, an editor) is not interrupted. TMOUT
# is deliberately not exported: exported, it would also time out the questions
# asked by setup scripts. The desktop has its own screen lock.
if [ -z "\${TMOUT:-}" ]; then
  TMOUT=${HARDEN_SHELL_TIMEOUT}
  readonly TMOUT
fi
EOF
  fi

  if [[ "$HARDEN_USB_STORAGE_OFF" == "true" ]]; then
    cat >> "$root/etc/modprobe.d/ot-ids-hardening.conf" <<'EOF'

# USB mass storage (set by HARDEN_USB_STORAGE_OFF=true in build.conf).
install usb-storage /bin/false
install uas /bin/false
EOF
  fi

  grep -q '^Banner' "$root/etc/ssh/sshd_config" || die "The base SSH configuration changed in $MALCOLM_REF; review apply_hardening."
  cat >> "$root/etc/ssh/sshd_config" <<EOF

# Added by the ${BRAND_NAME} OT IDS build
MaxSessions 4
MaxStartups 10:30:60
AllowAgentForwarding no
AllowTcpForwarding no
EOF
  log "Applied extra hardening (kernel settings, blocked modules, SSH limits, login banner$([[ "$HARDEN_SHELL_TIMEOUT" -gt 0 ]] && echo ", ${HARDEN_SHELL_TIMEOUT} s shell timeout")$([[ "$HARDEN_USB_STORAGE_OFF" == "true" ]] && echo ", USB storage blocked"))"
}

# ---------------------------------------------------------------------------
# sources: download the external rule sets and threat indicators enabled in
# sources.conf, convert them, and add them to the prepared source.
cmd_sources() {
  [[ -d "$SRC_DIR/.git" && -d "$SKEL_DEST" ]] || die "Run './build-iso.sh prepare' first."
  if [[ "$FETCH_SOURCES" != "true" ]]; then
    log "FETCH_SOURCES is off; no external rule sets or threat feeds are added."
    return 0
  fi
  need python3 "Install python3."
  log "Fetching the sources enabled in sources.conf ..."
  python3 "$KIT_DIR/tools/fetch_sources.py" --config "$KIT_DIR/sources.conf" --out "$FETCHED_DIR" || \
    warn "At least one source could not be fetched (see the lines marked FAILED above). The build continues without it."
  "$KIT_DIR/tools/collect-content.sh" "$SKEL_DEST" "$FETCHED_DIR"
  mkdir -p "$OUT_DIR"
  cp "$FETCHED_DIR/SOURCES.txt" "$OUT_DIR/external-sources.txt"
}

# ---------------------------------------------------------------------------
# list container images used by a profile (malcolm | hedgehog)
list_images() {
  local profile="$1" compose="$SRC_DIR/docker-compose.yml"
  if command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' >/dev/null 2>&1; then
    python3 - "$compose" "$profile" <<'PY'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
print("\n".join(sorted({s["image"] for s in doc["services"].values()
                        if sys.argv[2] in (s.get("profiles") or [])})))
PY
  else
    # no PyYAML: fall back to every image in the file (a superset, still correct)
    grep -E '^[[:space:]]*image:' "$compose" | awk '{print $2}' | sort -u
  fi
}

# Check every rule file with the product's own Suricata, and comment out the
# rules it refuses (most often a few from an imported Snort set), so the files
# that go into the ISO load cleanly. Never stops the build.
check_rules_with_engine() {
  local rules_dir="$SKEL_DEST/suricata/rules" report="$OUT_DIR/rule-check.txt" img file round pruned status total
  compgen -G "$rules_dir/*.rules" >/dev/null || return 0
  mkdir -p "$OUT_DIR"
  if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    warn "Docker is not available, so the rules were NOT checked by the engine."
    echo "Not checked: Docker was not available on the build host." > "$report"
    return 0
  fi
  img="$(list_images malcolm | grep '/suricata:' | head -1 || true)"
  if [[ -z "$img" ]] || ! { docker image inspect "$img" >/dev/null 2>&1 || docker pull "$img" >/dev/null 2>&1; }; then
    warn "The Suricata image could not be obtained, so the rules were NOT checked by the engine."
    echo "Not checked: the Suricata image could not be obtained." > "$report"
    return 0
  fi
  echo "Rule check with $img, $(date -u '+%Y-%m-%d %H:%M UTC')" > "$report"
  for file in "$rules_dir"/*.rules; do
    total=0
    status=0
    for round in 1 2 3 4 5 6 7 8 9 10; do
      status=0
      docker run --rm --entrypoint /usr/bin/suricata-offline -v "$rules_dir":/opt/suricata/rules:ro "$img" \
        -T -c /etc/suricata/suricata.yaml -S "/opt/suricata/rules/$(basename "$file")" -l /tmp \
        --set app-layer.protocols.modbus.enabled=yes \
        --set app-layer.protocols.dnp3.enabled=yes \
        --set app-layer.protocols.enip.enabled=yes > "$WORK_DIR/suricata-test.log" 2>&1 || status=$?
      pruned="$(python3 "$KIT_DIR/tools/prune_rules.py" --rules "$file" --log "$WORK_DIR/suricata-test.log")"
      [[ "$pruned" -gt 0 ]] || break
      total=$((total + pruned))
      grep -E 'at line [0-9]+' "$WORK_DIR/suricata-test.log" | sed "s|^|  $(basename "$file"): |" >> "$report" || true
    done
    if [[ "$status" -eq 0 ]]; then
      echo "OK      $(basename "$file"): $(grep -c '^alert ' "$file") rules load, $total commented out" >> "$report"
      [[ "$total" -eq 0 ]] && log "Rules OK: $(basename "$file")" || warn "$(basename "$file"): the engine refused $total rule(s); they are commented out (#PRUNED). See $report"
    else
      echo "PROBLEM $(basename "$file"): the engine reported an error that is not tied to a rule line:" >> "$report"
      tail -15 "$WORK_DIR/suricata-test.log" | sed 's/^/    /' >> "$report"
      warn "$(basename "$file"): the engine check did not pass. See $report"
    fi
  done
}

# List which CVEs the rules going into the ISO can recognise: the rule set
# bundled in the Suricata image (ET Open) plus everything this kit adds.
coverage_report() {
  local rules_dir="$SKEL_DEST/suricata/rules" bundled="$WORK_DIR/bundled-ruleset.rules" img inputs=() kev=()
  compgen -G "$rules_dir/*.rules" >/dev/null || return 0
  mkdir -p "$OUT_DIR"
  rm -f "$bundled"
  img="$(list_images malcolm | grep '/suricata:' | head -1 || true)"
  if [[ -n "$img" ]] && command -v docker >/dev/null 2>&1 && docker image inspect "$img" >/dev/null 2>&1; then
    docker run --rm --entrypoint cat "$img" /var/lib/suricata/rules/suricata.rules > "$bundled" 2>/dev/null || rm -f "$bundled"
  fi
  if [[ -s "$bundled" ]]; then
    inputs+=("$bundled")
  else
    warn "The rule set bundled in the Suricata image could not be read; the coverage report lists only the rules this kit adds."
  fi
  [[ -s "$FETCHED_DIR/kev/known_exploited_vulnerabilities.json" ]] && kev=(--kev "$FETCHED_DIR/kev/known_exploited_vulnerabilities.json")
  python3 "$KIT_DIR/tools/cve_index.py" --rules "${inputs[@]}" "$rules_dir" "${kev[@]}" \
    -o "$OUT_DIR/vulnerability-coverage.csv" --summary "$OUT_DIR/vulnerability-coverage.md" 2>&1 | sed 's/^/[kit] coverage: /' >&2
  cp "$OUT_DIR/vulnerability-coverage.csv" "$OUT_DIR/vulnerability-coverage.md" "$SKEL_DEST/"
}

# Add one thin layer of files on top of an official image and give the result
# the official image's name, so docker-compose.yml needs no change.
#   layer_one <image short name> <build context dir>
layer_one() {
  local name="$1" ctx="$2" img upstream
  img="$(printf '%s\n' "${IMAGES[@]}" | grep -E "/${name}:" | head -1 || true)"
  [[ -n "$img" ]] || return 0                      # image not part of this flavor
  upstream="kit-upstream/${name}:${img##*:}"
  docker tag "$img" "$upstream"
  { echo "FROM $upstream"; cat "$ctx/Dockerfile.body"; } > "$ctx/Dockerfile"
  log "Adding the ${BRAND_NAME} layer to $img ..."
  docker build -q -t "$img" "$ctx" >/dev/null || die "The added layer for '$name' failed to build."
}

# Rebrand the web applications. Every destination path below is where the
# upstream Dockerfile (Dockerfiles/<name>.Dockerfile in v26.09.0) puts the file
# being replaced.
brand_web_images() {
  [[ "$BRAND_WEB" == "true" ]] || return 0
  local web="$OVERLAY_DIR/branding/web" ctx="$WORK_DIR/brand-ctx"
  if [[ ! -d "$web" ]]; then
    warn "BRAND_WEB is true but $web does not exist; web applications keep the upstream look."
    return 0
  fi
  grep -q "applicationTitle: \"${BRAND_NAME} Dashboards\"" "$SRC_DIR/dashboards/opensearch_dashboards.yml" || \
    die "Source is not prepared for web branding; run './build-iso.sh prepare' first."
  rm -rf "$ctx"
  mkdir -p "$ctx/nginx-proxy/img" "$ctx/nginx-proxy/html" "$ctx/dashboards" "$ctx/file-upload" "$ctx/htadmin" "$ctx/filescan"

  # landing page, shared logo/icon files (also used by the dashboards header), error pages
  cp "$web"/favicon/*.png "$web"/icon/*.png "$web"/logo/*.png "$web"/brand-*.png "$ctx/nginx-proxy/img/"
  cp "$web/masthead.png"     "$ctx/nginx-proxy/img/Malcolm_background.png"
  cp "$web/icon/favicon.ico" "$ctx/nginx-proxy/favicon.ico"
  cp "$SRC_DIR/nginx/landingpage/index.html" "$SRC_DIR/nginx/landingpage/404.html" \
     "$SRC_DIR/nginx/landingpage/502.html" "$ctx/nginx-proxy/html/"
  cat > "$ctx/nginx-proxy/Dockerfile.body" <<'EOF'
COPY --chmod=644 img/*.png /usr/share/nginx/html/assets/img/
COPY --chmod=644 favicon.ico /usr/share/nginx/html/assets/favicon.ico
COPY --chmod=644 favicon.ico /usr/share/nginx/html/favicon.ico
COPY --chmod=644 html/*.html /usr/share/nginx/html/
EOF

  # dashboards: application title (its logo files are served by nginx-proxy)
  cp "$SRC_DIR/dashboards/opensearch_dashboards.yml" "$ctx/dashboards/"
  cat > "$ctx/dashboards/Dockerfile.body" <<'EOF'
COPY --chmod=644 opensearch_dashboards.yml /usr/share/opensearch-dashboards/config/opensearch_dashboards.orig.yml
EOF

  # upload page banner
  cp "$web/logo/Malcolm_banner.png" "$SRC_DIR/file-upload/site/index.html" "$ctx/file-upload/"
  cat > "$ctx/file-upload/Dockerfile.body" <<'EOF'
COPY --chmod=644 Malcolm_banner.png /var/www/upload/Malcolm_banner.png
COPY --chmod=644 index.html /var/www/upload/index.html
EOF

  # account management page tab icon
  cp "$web/icon/favicon.ico" "$ctx/htadmin/"
  cat > "$ctx/htadmin/Dockerfile.body" <<'EOF'
COPY --chmod=644 favicon.ico /var/www/htadmin/favicon.ico
EOF

  # extracted-files browser (server and sensor)
  cp "$web/masthead.png"     "$ctx/filescan/bg-masthead.png"
  cp "$web/icon/favicon.ico" "$ctx/filescan/"
  cat > "$ctx/filescan/Dockerfile.body" <<'EOF'
COPY --chmod=644 bg-masthead.png /opt/assets/assets/img/bg-masthead.png
COPY --chmod=644 favicon.ico /opt/assets/favicon.ico
EOF

  local name
  for name in nginx-proxy dashboards file-upload htadmin filescan; do
    layer_one "$name" "$ctx/$name"
  done

  # one real check that a layer landed: read a file back out of the landing page image
  local img cid tmp
  img="$(printf '%s\n' "${IMAGES[@]}" | grep -E '/nginx-proxy:' | head -1 || true)"
  if [[ -n "$img" ]]; then
    tmp="$(mktemp -d)"
    cid="$(docker create "$img")"
    docker cp "$cid:/usr/share/nginx/html/assets/img/icon.png" "$tmp/icon.png" >/dev/null 2>&1 || true
    docker rm -v "$cid" >/dev/null 2>&1 || true
    if cmp -s "$tmp/icon.png" "$web/icon/icon.png"; then
      log "Verified: the branded logo is inside $img"
    else
      warn "Could not confirm the branded logo inside $img; check the web interface after installing."
    fi
    rm -rf "$tmp"
  fi
}

# Put the OT anomaly detectors and alert monitors where the product imports
# them from at first start (upstream Dockerfiles/dashboards-helper.Dockerfile:
# /opt/anomaly_detectors and /opt/alerting/monitors).
add_platform_content() {
  local src="$KIT_DIR/detections" ctx="$WORK_DIR/content-ctx/dashboards-helper"
  compgen -G "$src/anomaly_detectors/*.json" >/dev/null || compgen -G "$src/monitors/*.json" >/dev/null || return 0
  rm -rf "$ctx"
  mkdir -p "$ctx/anomaly_detectors" "$ctx/monitors"
  : > "$ctx/Dockerfile.body"
  if compgen -G "$src/anomaly_detectors/*.json" >/dev/null; then
    cp "$src"/anomaly_detectors/*.json "$ctx/anomaly_detectors/"
    echo 'COPY --chmod=644 anomaly_detectors/*.json /opt/anomaly_detectors/' >> "$ctx/Dockerfile.body"
  fi
  if compgen -G "$src/monitors/*.json" >/dev/null; then
    cp "$src"/monitors/*.json "$ctx/monitors/"
    echo 'COPY --chmod=644 monitors/*.json /opt/alerting/monitors/' >> "$ctx/Dockerfile.body"
  fi
  layer_one dashboards-helper "$ctx"
}

# images: pull the release's container images and pack them for the ISO
cmd_images() {
  [[ -d "$SRC_DIR/.git" ]] || die "Run './build-iso.sh prepare' first."
  if [[ "$INCLUDE_IMAGES" != "true" ]]; then
    log "INCLUDE_IMAGES is not 'true'; the ISO will need Internet at first start to pull images."
    warn "Web branding, anomaly detectors and alert monitors travel inside the embedded images, so with INCLUDE_IMAGES=false the installed system will not have them."
    check_rules_with_engine
    coverage_report
    return 0
  fi
  need docker "Install Docker Engine (https://docs.docker.com/engine/install/)."
  need xz     "Install xz-utils."
  docker info >/dev/null 2>&1 || die "Cannot talk to the Docker daemon (is it running, and is your user in the 'docker' group?)."

  local flavor out
  for flavor in $FLAVORS; do
    out="$(images_file "$flavor")"
    if [[ -s "$out" ]]; then
      log "Reusing $out (delete it to rebuild)."
      continue
    fi
    mapfile -t IMAGES < <(list_images "$flavor")
    [[ "${#IMAGES[@]}" -gt 0 ]] || die "No images found for profile '$flavor' in docker-compose.yml."
    log "Pulling ${#IMAGES[@]} images for the $flavor profile ..."
    local img
    for img in "${IMAGES[@]}"; do docker pull "$img"; done
    brand_web_images
    add_platform_content
    log "Packing images to $out (this takes a while) ..."
    docker save "${IMAGES[@]}" | xz -1 > "$out.partial"
    mv "$out.partial" "$out"
  done
  check_rules_with_engine
  coverage_report
}

# ---------------------------------------------------------------------------
build_one_vagrant() {
  local flavor="$1" img_arg=() force=()
  [[ -s "$(images_file "$flavor")" ]] && img_arg=(-d "$(images_file "$flavor")")
  [[ "$FIRST_BUILD" == "1" ]] && force=(-f)       # fresh build VM for the first flavor only
  (cd "$SRC_DIR" && ./malcolm-iso/build_via_vagrant.sh "${force[@]}" -i "$flavor" "${img_arg[@]}")
}

build_one_native() {
  local flavor="$1" img_arg=()
  [[ -s "$(images_file "$flavor")" ]] && img_arg=(-d "$(images_file "$flavor")")
  mkdir -p "$ISO_DIR/shared"
  echo "VCS_REVISION=$(git -C "$SRC_DIR" rev-parse --short HEAD 2>/dev/null || echo main)" > "$ISO_DIR/shared/environment.chroot"
  (cd "$ISO_DIR" && sudo bash ./build.sh -i "$flavor" "${img_arg[@]}")
  rm -rf "$ISO_DIR/shared"
  sudo chown "$(id -u):$(id -g)" "$ISO_DIR"/"$flavor"-*.* 2>/dev/null || true
}

# iso: run the live-build and collect the results
cmd_iso() {
  [[ -d "$SRC_DIR/.git" ]] || die "Run './build-iso.sh prepare' first."
  grep -q 'BRAND_LABEL' "$ISO_DIR/build.sh" || die "Source is not prepared; run './build-iso.sh prepare' first."
  resolve_build_mode
  need rsync "Install rsync (the upstream build scripts use it)."
  case "$BUILD_MODE" in
    vagrant)
      need vagrant "Install Vagrant plus one provider (VirtualBox, VMware or libvirt). See README."
      ;;
    native)
      grep -qs 'VERSION_CODENAME=trixie' /etc/os-release || warn "Native mode is only known to work on Debian 13 (trixie)."
      need lb         "apt-get install live-build"
      need xmlstarlet "apt-get install xmlstarlet"
      need xorriso    "apt-get install xorriso"
      need docker     "Install Docker Engine; build.sh uses it for one helper package."
      ;;
    *) die "BUILD_MODE must be auto, vagrant or native." ;;
  esac

  mkdir -p "$OUT_DIR"
  FIRST_BUILD=1
  local flavor label iso
  for flavor in $FLAVORS; do
    if [[ "$INCLUDE_IMAGES" == "true" && ! -s "$(images_file "$flavor")" ]]; then
      die "No image bundle for '$flavor'. Run './build-iso.sh images' first, or set INCLUDE_IMAGES=false."
    fi
    log "Building the $flavor ISO ($BUILD_MODE mode); expect 30+ minutes ..."
    rm -f "$ISO_DIR"/"$flavor"-*.iso "$ISO_DIR"/"$flavor"-*-build.log
    "build_one_$BUILD_MODE" "$flavor"
    FIRST_BUILD=0

    iso="$(ls -1 "$ISO_DIR"/"$flavor"-*.iso 2>/dev/null | head -1 || true)"
    [[ -n "$iso" ]] || die "The $flavor build produced no ISO. Check $ISO_DIR/${flavor}-*-build.log"
    label="$(flavor_label "$flavor")-${MALCOLM_REF#v}"
    mv "$iso" "$OUT_DIR/$label.iso"
    mv "$ISO_DIR"/"$flavor"-*-build.log "$OUT_DIR/$label-build.log" 2>/dev/null || true
    (cd "$OUT_DIR" && sha256sum "$label.iso" > "$label.iso.sha256")
    log "Created $OUT_DIR/$label.iso"
  done
  log "Done. Results:"
  ls -lh "$OUT_DIR"/*.iso "$OUT_DIR"/*.sha256 >&2
}

# ---------------------------------------------------------------------------
case "${1:-all}" in
  prepare) cmd_prepare ;;
  sources) cmd_sources ;;
  images)  cmd_images ;;
  iso)     cmd_iso ;;
  all)     cmd_prepare; cmd_sources; cmd_images; cmd_iso ;;
  *)       die "Usage: $0 [prepare|sources|images|iso|all]" ;;
esac
