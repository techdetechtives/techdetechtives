#!/usr/bin/env bash
# TechDetechtives checks.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
#
# Usage:
#   scripts/verify.sh repo        Static checks of this repository (runs anywhere).
#   sudo scripts/verify.sh platform   On the manager: is the overlay installed?
#   scripts/verify.sh analytics   On the analytics host: is the workbench healthy?

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/config/techdetechtives.env"
COMPOSE_FILE="$ROOT/analytics/docker-compose.yml"
FAILED=0

pass() { printf '[ ok ] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*"; FAILED=1; }
usage() { sed -n '5,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

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

case "${1:-}" in
  repo)      cmd_repo ;;
  platform)  cmd_platform ;;
  analytics) cmd_analytics ;;
  -h|--help) usage; exit 0 ;;
  *)         usage >&2; exit 2 ;;
esac
exit "$FAILED"
