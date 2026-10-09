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

mkdir -p "$WORK"/{local/pillar/soc,local/pillar/zeek,local/salt/soc/files/soc,default/salt/soc,default/salt/zeek,rules,backup,bin}
printf 'zeek:\n  enabled: False\n  config:\n    local:\n      load:\n        - misc/loaded-scripts\n        - oui-logging\n      redef:\n        - LogAscii::use_json = T;\n' > "$WORK/default/salt/zeek/defaults.yaml"
: > "$WORK/local/pillar/zeek/soc_zeek.sls"
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

# The layer 2 watch: never part of apply, switched on only when Zeek is up and can read the script.
zeek_settings="$WORK/local/pillar/zeek/soc_zeek.sls"
zeek_copy="$WORK/local/salt/zeek/policy/custom/techdetechtives"
export TD_ZEEK_STARTUP_FILE="$WORK/local.zeek" TD_ZEEK_WAIT_TRIES=2 TD_ZEEK_WAIT_SECONDS=0
# Stand-in for the platform's state tool: writes Zeek's start-up file from the
# settings, as the platform does, and can be told that Zeek fails to come back.
cat > "$WORK/bin/salt-call" <<'STUB'
#!/bin/bash
echo "salt-call $*" >> "$SALT_LOG"
if grep -q "custom/techdetechtives" "$TD_SO_LOCAL/pillar/zeek/soc_zeek.sls" 2>/dev/null; then
  echo "@load custom/techdetechtives" > "$TD_ZEEK_STARTUP_FILE"
  [[ -f "$BREAK_ZEEK" ]] && touch "$ZEEK_DOWN"
else
  : > "$TD_ZEEK_STARTUP_FILE"
  rm -f "$ZEEK_DOWN"
fi
exit 0
STUB
chmod +x "$WORK/bin/salt-call"
export SALT_LOG="$WORK/salt.log" BREAK_ZEEK="$WORK/break-zeek" ZEEK_DOWN="$WORK/zeek-down"
export TD_ZEEK_RUNNING_CMD="test ! -f $WORK/zeek-down" TD_ZEEK_CHECK_CMD=true
check "apply leaves Zeek alone" bash -c '[[ ! -e "$0" ]] && ! grep -q techdetechtives "$1"' "$zeek_copy" "$zeek_settings"
check "layer2 status says off" bash -c '! bash "$0" layer2 status' "$OVERLAY"
check "layer2 on refused while Zeek is down" bash -c '! TD_ZEEK_RUNNING_CMD=false bash "$0" layer2 on' "$OVERLAY"
check "layer2 on refused when Zeek cannot read the script" bash -c '! TD_ZEEK_CHECK_CMD=false bash "$0" layer2 on' "$OVERLAY"
check "a refused layer2 on changes nothing" bash -c '[[ ! -e "$0" ]] && ! grep -q techdetechtives "$1" && [[ ! -e "$2" ]]' "$zeek_copy" "$zeek_settings" "$SALT_LOG"
check "layer2 on --dry-run changes nothing" bash -c 'bash "$0" layer2 on --dry-run >/dev/null && [[ ! -e "$1" ]] && ! grep -q techdetechtives "$2"' "$OVERLAY" "$zeek_copy" "$zeek_settings"

# Settings that cannot be read: the script must not be left behind.
printf 'zeek: [broken\n' > "$zeek_settings"
check "layer2 on stops at unreadable settings" bash -c '! bash "$0" layer2 on' "$OVERLAY"
check "and leaves no script behind" bash -c '[[ ! -e "$0" ]]' "$zeek_copy"
: > "$zeek_settings"

# Zeek does not come back with the watch loaded: everything is put back.
touch "$BREAK_ZEEK"
overlay layer2 on > "$WORK/l2broken.out" 2>&1 || true
check "a Zeek that does not come back is noticed" grep -q "did not come back" "$WORK/l2broken.out"
check "the watch is switched off again" bash -c '! grep -q techdetechtives "$0" && [[ ! -e "$1" ]]' "$zeek_settings" "$zeek_copy"
check "and the Zeek state was applied again" bash -c '[[ $(grep -c "state.apply zeek" "$0") -eq 2 ]] && [[ ! -f "$1" ]]' "$SALT_LOG" "$ZEEK_DOWN"
rm -f "$BREAK_ZEEK"

overlay layer2 on --no-salt > "$WORK/l2on.out" 2>&1
check "layer2 on copies the script" test -f "$zeek_copy/l2-watch.zeek"
check "layer2 on adds the script to the list" grep -q "custom/techdetechtives" "$zeek_settings"
check "layer2 on keeps the default list" bash -c 'grep -q "misc/loaded-scripts" "$0" && grep -q "oui-logging" "$0"' "$zeek_settings"
check "status waits for the platform to write the start-up file" bash -c '! bash "$0" layer2 status' "$OVERLAY"
echo "@load custom/techdetechtives" > "$TD_ZEEK_STARTUP_FILE"
check "status waits for Zeek to restart" bash -c '! TD_ZEEK_STARTED_AT=1000 bash "$0" layer2 status' "$OVERLAY"
check "status passes once Zeek started after the change" bash -c 'TD_ZEEK_STARTED_AT=$(( $(date +%s) + 60 )) bash "$0" layer2 status' "$OVERLAY"
check "status fails when Zeek has stopped" bash -c '! TD_ZEEK_RUNNING_CMD=false TD_ZEEK_STARTED_AT=$(( $(date +%s) + 60 )) bash "$0" layer2 status' "$OVERLAY"
# The real check, against a stand-in for docker that, like docker, is still
# writing its listing after the line being looked for. A search that stops at
# its first match breaks the pipe, and with pipefail that once read as "Zeek
# is not running" on a platform where it was.
mkdir -p "$WORK/dockerbin"
cat > "$WORK/dockerbin/docker" <<'STUB'
#!/bin/bash
case "$1" in
  ps)  [[ "$FAKE_ZEEK" == "absent" ]] || echo "so-zeek"; sleep 0.2; echo "so-soc"; echo "so-nginx" ;;
  top) echo "UID PID CMD"; echo "root 1 /bin/bash /usr/local/bin/zeek.sh"
       [[ "$FAKE_ZEEK" == "idle" ]] || echo "zeek 2 /opt/zeek/bin/zeek -i bond0 -U .status"
       sleep 0.2; echo "zeek 3 /usr/bin/bash /opt/zeek/share/zeekctl/scripts/run-zeek" ;;
esac
STUB
chmod +x "$WORK/dockerbin/docker"
real_check() { env -u TD_ZEEK_RUNNING_CMD PATH="$WORK/dockerbin:$PATH" FAKE_ZEEK="$1" TD_ZEEK_STARTED_AT=$(( $(date +%s) + 60 )) bash "$OVERLAY" layer2 status; }
check "Zeek is found running while docker is still listing" real_check up
not() { ! "$@"; }
check "a Zeek container with no Zeek process is not running" not real_check idle
check "no Zeek container is not running" not real_check absent
# A platform upgrade changes the default list while the watch is on: "off" must still hand the list back to the platform.
sed -i 's/        - oui-logging/        - oui-logging\n        - added-by-upgrade/' "$WORK/default/salt/zeek/defaults.yaml"
overlay layer2 off --no-salt > /dev/null 2>&1
check "layer2 off hands the list back to the platform" bash -c '! grep -q "load" "$0"' "$zeek_settings"
check "layer2 off removes the script" bash -c '[[ ! -e "$0" ]]' "$zeek_copy"
overlay layer2 on > "$WORK/l2on2.out" 2>&1
check "layer2 on with the platform's tool finishes and Zeek is running" grep -q "Zeek is running" "$WORK/l2on2.out"
check "the upgraded default list is carried" grep -q "added-by-upgrade" "$zeek_settings"

overlay revert --no-salt > "$WORK/revert.out" 2>&1
check "revert switches the watch off" bash -c '! grep -q techdetechtives "$0"' "$zeek_settings"
check "revert removes the Zeek script" bash -c '[[ ! -e "$0" ]]' "$zeek_copy"
check "revert restores the page" grep -q "ORIGINAL PAGE" "$page"
check "revert restores the settings" bash -c '! grep -q "local-sigma\|local-yara" "$0" && grep -q "keep: me" "$0"' "$settings"
check "revert removes the rules" bash -c '[[ $(git -C "$0/rules/local-sigma" ls-files | wc -l) -eq 0 ]]' "$WORK"

overlay apply --no-salt --no-auto-enable > /dev/null 2>&1
check "--no-auto-enable leaves settings alone" bash -c '! grep -q "local-sigma" "$0"' "$settings"

if [[ $fails -gt 0 ]]; then echo "$fails check(s) failed"; exit 1; fi
echo "all overlay checks passed"
