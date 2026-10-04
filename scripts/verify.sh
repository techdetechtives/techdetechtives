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

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/config/techdetechtives.env"
COMPOSE_FILE="$ROOT/analytics/docker-compose.yml"
FAILED=0

pass() { printf '[ ok ] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*"; FAILED=1; }
usage() { sed -n '5,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

cmd_repo() {
  local f
  for f in LICENSE NOTICE.md MODIFICATIONS.md licenses/Elastic-License-2.0.txt licenses/GPL-3.0.txt analytics/LICENSE upstream.lock; do
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
    files = list((root / "platform/detections/sigma").glob("*.yml")) + [root / "analytics/docker-compose.yml"]
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
    then pass "notebooks, sample data and rules parse"; else fail "notebooks, sample data or rules have problems (listed above)"; fi
    if python3 -m unittest discover -s "$ROOT/ticketing/tests" >/dev/null 2>&1; then
      pass "forwarder tests"
    else
      fail "forwarder tests (run: python3 -m unittest discover -s ticketing/tests -v)"
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

case "${1:-}" in
  repo)      cmd_repo ;;
  platform)  cmd_platform ;;
  analytics) cmd_analytics ;;
  ticketing) cmd_ticketing ;;
  vulnerability) cmd_vulnerability ;;
  -h|--help) usage; exit 0 ;;
  *)         usage >&2; exit 2 ;;
esac
exit "$FAILED"
