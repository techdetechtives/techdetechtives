#!/usr/bin/env bash
# TechDetechtives: overlay test against a mock platform tree. No Security Onion needed.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
#
# Builds a throwaway copy of the folders the overlay touches, then checks
# apply, re-apply, status, rules and revert. Needs bash, git, jq, python3 + yaml.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OVERLAY="$HERE/../apply-overlay.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fails=0
check() { # check "name" command...
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then printf '  ok    %s\n' "$name"; else printf '  FAIL  %s\n' "$name"; fails=$((fails + 1)); fi
}

mkdir -p "$WORK"/{local/pillar/soc,local/salt/soc/files/soc,default/salt/soc,rules,backup,bin}
cat > "$WORK/default/salt/soc/defaults.yaml" <<'YAML'
soc:
  config:
    server:
      modules:
        elastalertengine:
          enabledSigmaRules:
            default: |
              - ruleset: ["core"]
                level: ["critical", "high"]
            so-eval: |
              - ruleset: ["core"]
                level: ["critical"]
        strelkaengine:
          autoEnabledYaraRules:
            - securityonion-yara
YAML
printf 'soc:\n  config:\n    server:\n      keep: me\n' > "$WORK/local/pillar/soc/soc_soc.sls"
cp "$WORK/local/pillar/soc/soc_soc.sls" "$WORK/settings.before"
echo "ORIGINAL PAGE" > "$WORK/local/salt/soc/files/soc/motd.md"
echo "2.4.211" > "$WORK/soversion"
for repo in local-sigma local-suricata local-yara; do
  git init -q "$WORK/rules/$repo"
  git -C "$WORK/rules/$repo" -c user.name=t -c user.email=t@t.invalid commit -q --allow-empty -m init
done
# Stand-in for the platform's query tool: prints the file named by STUB_JSON.
printf '#!/bin/bash\ncat "$STUB_JSON"\n' > "$WORK/bin/so-elasticsearch-query"
chmod +x "$WORK/bin/so-elasticsearch-query"
doc() { printf '{"_source":{"so_detection":{"title":"%s","engine":"%s","isEnabled":%s,"ruleset":"%s"}}}' "$@"; }
printf '{"hits":{"hits":[%s,%s]}}' "$(doc A elastalert false local-sigma)" "$(doc B suricata true local-suricata)" > "$WORK/mixed.json"
printf '{"hits":{"hits":[%s]}}' "$(doc A strelka true local-yara)" > "$WORK/on.json"

export PATH="$WORK/bin:$PATH" STUB_JSON="$WORK/on.json"
export TD_SO_VERSION_FILE="$WORK/soversion" TD_SO_LOCAL="$WORK/local" TD_SO_DEFAULT="$WORK/default"
export TD_RULE_REPOS="$WORK/rules" TD_BACKUP_ROOT="$WORK/backup" TD_SKIP_ROOT_CHECK=1
overlay() { bash "$OVERLAY" "$@"; }
settings="$WORK/local/pillar/soc/soc_soc.sls"
page="$WORK/local/salt/soc/files/soc/motd.md"

echo "overlay against a mock platform:"
overlay apply --dry-run --no-salt > "$WORK/dry.out" 2>&1
check "dry run changes nothing" cmp -s "$settings" "$WORK/settings.before"
check "dry run leaves the page" grep -q "ORIGINAL PAGE" "$page"
check "status fails before apply" bash -c '! bash "$0" status' "$OVERLAY"

overlay apply --no-salt > "$WORK/apply.out" 2>&1
check "pages installed" grep -q "TechDetechtives" "$page"
check "sigma rules committed" bash -c '[[ $(git -C "$0/rules/local-sigma" ls-files | wc -l) -ge 4 ]]' "$WORK"
check "yara rule committed" bash -c '[[ $(git -C "$0/rules/local-yara" ls-files | wc -l) -ge 1 ]]' "$WORK"
check "sigma enabled on import (every role)" bash -c '[[ $(grep -c "local-sigma" "$0") -eq 2 ]]' "$settings"
check "yara enabled on import" grep -q "local-yara" "$settings"
check "other settings kept" grep -q "keep: me" "$settings"
check "settings backed up" bash -c 'ls "$0"/backup/settings/soc_soc.sls.* ' "$WORK"
check "status passes after apply" overlay status

overlay apply --no-salt > "$WORK/again.out" 2>&1
check "second apply changes no settings" grep -q "no change needed" "$WORK/again.out"
check "second apply keeps the first backup" bash -c '[[ $(find "$0/backup" -mindepth 1 -maxdepth 1 -name "[0-9]*Z" | wc -l) -eq 1 ]]' "$WORK"

STUB_JSON="$WORK/mixed.json" overlay rules > "$WORK/rules.out" 2>&1 || true
check "rules lists switched-off rules" grep -q "disabled  elastalert  A" "$WORK/rules.out"
check "status fails while a rule is off" bash -c '! STUB_JSON="$1" bash "$0" status' "$OVERLAY" "$WORK/mixed.json"

overlay revert --no-salt > "$WORK/revert.out" 2>&1
check "revert restores the page" grep -q "ORIGINAL PAGE" "$page"
check "revert restores the settings" bash -c '! grep -q "local-sigma\|local-yara" "$0" && grep -q "keep: me" "$0"' "$settings"
check "revert removes the rules" bash -c '[[ $(git -C "$0/rules/local-sigma" ls-files | wc -l) -eq 0 ]]' "$WORK"

overlay apply --no-salt --no-auto-enable > /dev/null 2>&1
check "--no-auto-enable leaves settings alone" bash -c '! grep -q "local-sigma" "$0"' "$settings"

if [[ $fails -gt 0 ]]; then echo "$fails check(s) failed"; exit 1; fi
echo "all overlay checks passed"
