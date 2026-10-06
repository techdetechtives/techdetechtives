#!/usr/bin/env bash
# TechDetechtives checks.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
#
# Usage:
#   scripts/verify.sh repo        Static checks of this repository (runs anywhere).
#   sudo scripts/verify.sh platform   On the manager: is the overlay installed?
#   scripts/verify.sh analytics   On the analytics host: is the workbench healthy?
#   scripts/verify.sh ticketing   On the analytics host: are DFIR-IRIS and the forwarder working?
#   scripts/verify.sh vulnerability   On the ticketing machine: are Greenbone and its connector working?
#   scripts/verify.sh honeypot    On the honeypot machine: are the decoys and the shipper working?
#   scripts/verify.sh network     On the ticketing machine: is the network inventory reading from the platform?

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/config/techdetechtives.env"
COMPOSE_FILE="$ROOT/analytics/docker-compose.yml"
FAILED=0

pass() { printf '[ ok ] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*"; FAILED=1; }
usage() { sed -n '5,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

cmd_repo() {
  local f
  for f in LICENSE NOTICE.md MODIFICATIONS.md licenses/Elastic-License-2.0.txt licenses/GPL-3.0.txt licenses/Apache-2.0.txt licenses/BSD-3-Clause-OpenCanary.txt analytics/LICENSE upstream.lock skills/MANIFEST.sha256; do
    if [[ -s "$ROOT/$f" ]]; then pass "present: $f"; else fail "missing: $f"; fi
  done
  while IFS= read -r f; do
    if bash -n "$f" 2>/dev/null; then pass "shell syntax: ${f#"$ROOT"/}"; else fail "shell syntax: ${f#"$ROOT"/}"; fi
  done < <(find "$ROOT" -name '*.sh' -not -path '*/upstream/*' | sort)
  if command -v python3 >/dev/null 2>&1; then
    if python3 - "$ROOT" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
problems = []
for path in sorted((root / "analytics/notebooks").glob("*.ipynb")):
    book = json.loads(path.read_text())
    if book.get("nbformat") != 4:
        problems.append(f"{path.name}: not nbformat 4")
    if any(cell.get("outputs") for cell in book["cells"] if cell["cell_type"] == "code"):
        problems.append(f"{path.name}: contains saved outputs (clear them before committing)")
    if "derived from the HELK notebook" not in "".join(book["cells"][0]["source"]):
        problems.append(f"{path.name}: missing the HELK attribution header")
for path in sorted((root / "analytics/td_hunt/sample_data").glob("*.jsonl")):
    for number, line in enumerate(path.read_text().splitlines(), 1):
        try:
            json.loads(line)
        except ValueError:
            problems.append(f"{path.name}:{number}: invalid JSON")
try:
    import yaml
except ImportError:
    yaml = None
if yaml:
    files = list((root / "platform/detections/sigma").glob("*.yml")) + [
        root / "analytics/docker-compose.yml", root / "ticketing/docker-compose.yml",
        root / "vulnerability/docker-compose.yml", root / "honeypot/docker-compose.yml",
        root / "network/docker-compose.yml"]
    ids = set()
    for path in files:
        try:
            doc = yaml.safe_load(path.read_text())
        except yaml.YAMLError as error:
            problems.append(f"{path.name}: {error}")
            continue
        if path.suffix == ".yml" and "sigma" in path.parts:
            missing = [k for k in ("title", "id", "logsource", "detection", "level") if k not in doc]
            if missing:
                problems.append(f"{path.name}: missing {missing}")
            if doc.get("id") in ids:
                problems.append(f"{path.name}: duplicate rule id")
            ids.add(doc.get("id"))
    # Every Sigma rule is paired with a test that should make it fire.
    guid = __import__("re").compile(r"^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
    try:
        pairing = yaml.safe_load((root / "platform/detections/validation.yml").read_text())
        paired = {}
        for check in pairing["checks"]:
            paired[check["rule"]] = check
            rule_path = root / "platform/detections" / check["rule"]
            if not rule_path.is_file():
                problems.append(f"validation.yml: no such rule file {check['rule']}")
                continue
            if yaml.safe_load(rule_path.read_text()).get("title") != check.get("title"):
                problems.append(f"validation.yml: title does not match {check['rule']}")
            tests = check.get("tests") or []
            if not any(test.get("expect") == "alert" for test in tests):
                problems.append(f"validation.yml: {check['rule']} has no test that expects an alert")
            for test in tests:
                if test.get("kind") == "atomic" and not guid.match(str(test.get("guid", ""))):
                    problems.append(f"validation.yml: {check['rule']}: atomic test without a valid guid")
                if test.get("kind") not in ("atomic", "manual") or test.get("expect") not in ("alert", "none"):
                    problems.append(f"validation.yml: {check['rule']}: test needs kind atomic|manual and expect alert|none")
        for path in (root / "platform/detections/sigma").glob("*.yml"):
            if f"sigma/{path.name}" not in paired:
                problems.append(f"{path.name}: no entry in platform/detections/validation.yml")
    except (OSError, KeyError, TypeError, yaml.YAMLError) as error:
        problems.append(f"validation.yml: {type(error).__name__}: {error}")
    # Images built from the repository root only receive what .dockerignore lets through.
    allowed = [line[1:] for line in (root / ".dockerignore").read_text().split() if line.startswith("!")]
    for dockerfile in sorted(root.glob("*/*/Dockerfile")):
        for line in dockerfile.read_text().splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[0] == "COPY" and "/" in parts[1] and (root / parts[1]).exists():
                if parts[1] not in allowed:
                    problems.append(f"{dockerfile.relative_to(root)}: copies {parts[1]}, which .dockerignore keeps out of the build")
    # Skills: readable front matter, name matching the folder, usable description.
    for path in sorted((root / "skills").glob("*/*/SKILL.md")):
        label = f"skills/{path.parent.parent.name}/{path.parent.name}"
        text = path.read_text(encoding="utf-8")
        parts = text.split("\n---", 1)
        if not text.startswith("---\n") or len(parts) != 2:
            problems.append(f"{label}: SKILL.md has no front matter")
            continue
        try:
            meta = yaml.safe_load(parts[0][4:])
        except yaml.YAMLError as error:
            problems.append(f"{label}: front matter: {error}")
            continue
        if not isinstance(meta, dict) or meta.get("name") != path.parent.name:
            problems.append(f"{label}: name in SKILL.md does not match the folder")
        description = str((meta or {}).get("description") or "").strip() if isinstance(meta, dict) else ""
        if not 20 <= len(description) <= 1024:
            problems.append(f"{label}: description must be 20 to 1024 characters")
    selected = {line.split("#")[0].strip() for line in (root / "skills/selection.txt").read_text().splitlines()} - {""}
    present = {p.name for p in (root / "skills/community").iterdir() if p.is_dir()}
    if selected != present:
        problems.append(f"skills/community does not match skills/selection.txt: {sorted(selected ^ present)}")
sids = []
for path in (root / "platform/detections/suricata").glob("*.rules"):
    for line in path.read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            sid = [p.strip() for p in line.split(";") if p.strip().startswith("sid:")]
            if not sid:
                problems.append(f"{path.name}: rule without sid")
            sids += sid
if len(sids) != len(set(sids)):
    problems.append("duplicate Suricata sid")
for problem in problems:
    print("   ", problem)
sys.exit(1 if problems else 0)
PY
    then pass "notebooks, sample data, rules, rule tests and skills are consistent"; else fail "notebooks, sample data, rules, rule tests or skills have problems (listed above)"; fi
    if (cd "$ROOT/skills" && sha256sum --quiet -c MANIFEST.sha256 >/dev/null 2>&1) \
       && [[ "$(find "$ROOT/skills/community" -type f | wc -l)" -eq "$(grep -vc '^#' "$ROOT/skills/MANIFEST.sha256")" ]]; then
      pass "community skills match their manifest"
    else
      fail "community skills differ from skills/MANIFEST.sha256 (run: cd skills && sha256sum -c MANIFEST.sha256)"
    fi
    if python3 -m unittest discover -s "$ROOT/platform/tests" >/dev/null 2>&1; then
      skipped=""
      command -v yara >/dev/null 2>&1 || skipped="; YARA rules skipped, yara is not installed"
      command -v zeek >/dev/null 2>&1 || skipped="$skipped; layer 2 script skipped, zeek is not installed"
      pass "platform tests (rule and Zeek settings; Sigma, Suricata, YARA rules and the layer 2 script against samples$skipped)"
    else
      fail "platform tests (run: python3 -m unittest discover -s platform/tests -v)"
    fi
    if bash "$ROOT/platform/tests/test_overlay.sh" >/dev/null 2>&1; then
      pass "overlay test against a mock platform"
    else
      fail "overlay test (run: platform/tests/test_overlay.sh)"
    fi
    if python3 -m unittest discover -s "$ROOT/ticketing/tests" >/dev/null 2>&1; then
      pass "forwarder tests"
    else
      fail "forwarder tests (run: python3 -m unittest discover -s ticketing/tests -v)"
    fi
    if python3 -m unittest discover -s "$ROOT/honeypot/tests" >/dev/null 2>&1; then
      pass "honeypot tests"
    else
      fail "honeypot tests (run: python3 -m unittest discover -s honeypot/tests -v)"
    fi
    if python3 -m unittest discover -s "$ROOT/network/tests" >/dev/null 2>&1; then
      pass "network inventory tests"
    else
      fail "network inventory tests (run: python3 -m unittest discover -s network/tests -v)"
    fi
    if python3 -m unittest discover -s "$ROOT/ot-ids/tests" >/dev/null 2>&1; then
      skipped=""
      command -v yara >/dev/null 2>&1 || skipped="; YARA rules skipped, yara is not installed"
      pass "OT IDS tests (rules against sample packets, Snort conversion, indicators, vulnerability index, ATT&CK for ICS mapping, baseline program, traffic profile, YARA sources, hardening files$skipped)"
    else
      fail "OT IDS tests (run: python3 -m unittest discover -s ot-ids/tests -v)"
    fi
    if python3 -m unittest discover -s "$ROOT/vulnerability/tests" >/dev/null 2>&1; then
      pass "vulnerability connector tests"
    else
      fail "vulnerability connector tests (run: python3 -m unittest discover -s vulnerability/tests -v)"
    fi
  else
    printf '[skip] python3 not found; content checks skipped\n'
  fi
}

cmd_platform() {
  if "$ROOT/platform/apply-overlay.sh" status; then pass "platform overlay installed"; else fail "platform overlay not fully installed"; fi
}

cmd_analytics() {
  command -v docker >/dev/null 2>&1 || { fail "docker is not installed"; return; }
  [[ -f "$ENV_FILE" ]] || { fail "$ENV_FILE not found; run scripts/install.sh analytics first"; return; }
  local compose=(docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE")
  if [[ -n "$("${compose[@]}" ps --status running -q td-jupyter 2>/dev/null)" ]]; then
    pass "td-jupyter container is running"
  else
    fail "td-jupyter container is not running (docker logs td-jupyter)"
    return
  fi
  if "${compose[@]}" exec -T td-jupyter python -m td_hunt.selftest; then
    pass "workbench self-test"
  else
    fail "workbench self-test"
  fi
}

cmd_ticketing() {
  command -v docker >/dev/null 2>&1 || { fail "docker is not installed"; return; }
  [[ -f "$ENV_FILE" ]] || { fail "$ENV_FILE not found; run scripts/install.sh ticketing first"; return; }
  if [[ -d "$ROOT/ticketing/iris-web/.git" ]]; then
    local running
    running="$(cd "$ROOT/ticketing/iris-web" && docker compose ps --status running --services 2>/dev/null | wc -l)"
    if [[ "$running" -ge 5 ]]; then pass "DFIR-IRIS: $running of 5 services running"; else fail "DFIR-IRIS: only $running of 5 services running"; fi
  else
    printf '[skip] DFIR-IRIS is not installed from this repository (external instance assumed)\n'
  fi
  local compose=(docker compose -f "$ROOT/ticketing/docker-compose.yml" --env-file "$ENV_FILE")
  if [[ -n "$("${compose[@]}" ps --status running -q td-forwarder 2>/dev/null)" ]]; then
    pass "td-forwarder container is running"
  else
    fail "td-forwarder container is not running (docker logs td-forwarder)"
    return
  fi
  if "${compose[@]}" exec -T td-forwarder python /opt/techdetechtives/td_forwarder.py --check; then
    pass "forwarder can reach the platform and DFIR-IRIS"
  else
    fail "forwarder connection check"
  fi
}

cmd_vulnerability() {
  command -v docker >/dev/null 2>&1 || { fail "docker is not installed"; return; }
  [[ -f "$ENV_FILE" ]] || { fail "$ENV_FILE not found; run scripts/install.sh vulnerability first"; return; }
  if [[ -f "$ROOT/vulnerability/greenbone/compose.yaml" ]]; then
    local gb=(docker compose -p techdetechtives-greenbone -f "$ROOT/vulnerability/greenbone/compose.yaml" -f "$ROOT/vulnerability/greenbone/override.yaml")
    local service
    for service in gvmd gsad nginx ospd-openvas pg-gvm redis-server; do
      if [[ -n "$("${gb[@]}" ps --status running -q "$service" 2>/dev/null)" ]]; then
        pass "Greenbone service $service is running"
      else
        fail "Greenbone service $service is not running"
      fi
    done
  else
    fail "Greenbone is not installed from this repository (run scripts/install.sh vulnerability)"
  fi
  local compose=(docker compose -f "$ROOT/vulnerability/docker-compose.yml" --env-file "$ENV_FILE")
  if [[ -n "$("${compose[@]}" ps --status running -q td-vuln 2>/dev/null)" ]]; then
    pass "td-vuln container is running"
  else
    fail "td-vuln container is not running (docker logs td-vuln)"
    return
  fi
  if "${compose[@]}" exec -T td-vuln python -m td_vuln.main --check; then
    pass "connector can reach Greenbone and its configured outputs"
  else
    fail "connector connection check"
  fi
}

cmd_network() {
  command -v docker >/dev/null 2>&1 || { fail "docker is not installed"; return; }
  [[ -f "$ENV_FILE" ]] || { fail "$ENV_FILE not found; run scripts/install.sh network first"; return; }
  local compose=(docker compose -f "$ROOT/network/docker-compose.yml" --env-file "$ENV_FILE")
  if [[ -n "$("${compose[@]}" ps --status running -q td-netmap 2>/dev/null)" ]]; then
    pass "td-netmap container is running"
  else
    fail "td-netmap container is not running (docker logs td-netmap)"
    return
  fi
  if docker exec td-netmap python -m td_net.main --check; then
    pass "network inventory can read the platform, and the platform has connection records"
  else
    fail "network inventory connection check"
  fi
  if docker exec td-netmap python -m td_net.main --status; then
    pass "the platform's records have been read"
  else
    fail "no finished read of the platform yet (docker logs td-netmap); the first one takes a minute or two"
  fi
}

cmd_honeypot() {
  command -v docker >/dev/null 2>&1 || { fail "docker is not installed"; return; }
  [[ -f "$ENV_FILE" && -f "$ROOT/honeypot/ports.yaml" ]] || { fail "the honeypot is not set up; run scripts/install.sh honeypot first"; return; }
  local compose=(docker compose -f "$ROOT/honeypot/docker-compose.yml" -f "$ROOT/honeypot/ports.yaml" --env-file "$ENV_FILE")
  if [[ -n "$("${compose[@]}" ps --status running -q td-honeypot 2>/dev/null)" ]]; then
    pass "td-honeypot container is running"
  else
    fail "td-honeypot container is not running (docker logs td-honeypot)"
    return
  fi
  # Each decoy should answer on its port. Opening and closing a connection is
  # not a sign-in attempt and raises no alert, except on the SSH decoy, which
  # reports every connection: that one is left alone.
  local pair port address open=0 closed=""
  address="$(grep -E "^TD_HONEYPOT_BIND=" "$ENV_FILE" | tail -n 1 | cut -d= -f2-)"
  [[ -n "$address" && "$address" != "0.0.0.0" ]] || address="127.0.0.1"
  for pair in $(grep -E "^TD_HONEYPOT_PORT_MAP=" "$ENV_FILE" | tail -n 1 | cut -d= -f2- | tr ',' ' '); do
    [[ "${pair%%=*}" == "22" ]] && continue
    port="${pair##*=}"
    if (exec 3<>"/dev/tcp/$address/$port") 2>/dev/null; then open=$((open + 1)); else closed="$closed $port"; fi
  done
  if [[ -z "$closed" ]]; then pass "$open decoy ports answer on $address"; else fail "decoy ports not answering on $address:$closed"; fi
  if [[ -n "$("${compose[@]}" ps --status running -q td-honeypot-shipper 2>/dev/null)" ]]; then
    pass "td-honeypot-shipper container is running"
  else
    fail "td-honeypot-shipper container is not running (docker logs td-honeypot-shipper; it needs TD_ES_HOST and TD_HONEYPOT_API_KEY)"
    return
  fi
  if "${compose[@]}" exec -T td-honeypot-shipper python /opt/techdetechtives/td_honeypot.py --check; then
    pass "shipper can read the honeypot log and reach the platform"
  else
    fail "shipper check"
  fi
}

case "${1:-}" in
  repo)      cmd_repo ;;
  platform)  cmd_platform ;;
  analytics) cmd_analytics ;;
  ticketing) cmd_ticketing ;;
  vulnerability) cmd_vulnerability ;;
  honeypot)  cmd_honeypot ;;
  network)   cmd_network ;;
  -h|--help) usage; exit 0 ;;
  *)         usage >&2; exit 2 ;;
esac
exit "$FAILED"
