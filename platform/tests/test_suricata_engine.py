# TechDetechtives: Suricata rules against real traffic, in Suricata itself.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Run with:  python3 -m unittest discover -s platform/tests -v

Every request in platform/detections/cases/*.json ("suricata" lists) is written
into a packet capture (pcap.py) and replayed through Suricata with all of the
TechDetechtives rules loaded, so every rule must also load without an error. Each request must raise exactly the rules it
lists, and none of the other rules its case file covers ("covers": the SIDs
that file is the test for).

Needs Suricata: a `suricata` program, or Docker with TD_SURICATA_IMAGE set
(for example jasonish/suricata:7.0.11). Skipped when neither is available.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from pcap import write_http_pcap

DETECTIONS = Path(__file__).resolve().parents[1] / "detections"
CASES = [json.loads(path.read_text()) for path in sorted((DETECTIONS / "cases").glob("*.json"))]
# (case, the SIDs its case file covers)
REQUESTS = [(case, set(data.get("covers", []))) for data in CASES for case in data.get("suricata", [])]
# Rule files whose every rule must have a request that raises it: the web
# rules and every file the rule factory writes.
COVERED_FILES = ["techdetechtives-web.rules"] + sorted(p.name for p in (DETECTIONS / "suricata").glob("techdetechtives-cve-*.rules"))
IMAGE = os.environ.get("TD_SURICATA_IMAGE", "").strip()
# Security Onion switches on the industrial protocol decoders that stock
# Suricata leaves off (salt/suricata/defaults.yaml); the OT rules need them.
PLATFORM_SETTINGS = [option for name in ("modbus", "dnp3", "enip")
                     for option in ("--set", f"app-layer.protocols.{name}.enabled=yes")]


def _sids(path: Path) -> set[int]:
    if not path.exists():
        return set()
    return {int(m) for m in re.findall(r"\bsid:(\d+);", path.read_text())}


COVERED_SIDS = set().union(*(_sids(DETECTIONS / "suricata" / name) for name in COVERED_FILES))


def _engine():
    if shutil.which("suricata"):
        return "local"
    if IMAGE and shutil.which("docker"):
        return "docker"
    return None


def run_suricata(folder: Path) -> list[dict]:
    rules = folder / "all.rules"
    rules.write_text("\n".join(path.read_text() for path in sorted((DETECTIONS / "suricata").glob("*.rules"))))
    out = folder / "out"
    out.mkdir()
    os.chmod(folder, 0o777)
    os.chmod(out, 0o777)
    args = ["-r", "traffic.pcap", "-S", "all.rules", "-k", "none", "-l", "out", "--runmode", "single", *PLATFORM_SETTINGS]
    if _engine() == "local":
        command = ["suricata", *args]
        cwd = folder
    else:
        command = ["docker", "run", "--rm", "-v", f"{folder}:/work", "-w", "/work", "--entrypoint", "suricata", IMAGE, *args]
        cwd = None
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        raise AssertionError(f"Suricata failed ({result.returncode}):\n{result.stdout[-2000:]}\n{result.stderr[-2000:]}")
    errors = [line for line in (result.stdout + result.stderr).splitlines() if "rule" in line.lower() and "error" in line.lower()]
    if errors:
        raise AssertionError("Suricata could not load some rules:\n" + "\n".join(errors[:20]))
    events = []
    eve = out / "eve.json"
    if eve.exists():
        for line in eve.read_text().splitlines():
            event = json.loads(line)
            if event.get("event_type") == "alert":
                events.append(event)
    return events


@unittest.skipUnless(_engine(), "Suricata is not available (install it, or set TD_SURICATA_IMAGE and have Docker)")
class SuricataEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = Path(tempfile.mkdtemp())
        cls.ports = write_http_pcap(cls.folder / "traffic.pcap", [case["request"] for case, _ in REQUESTS])
        cls.alerts: dict[int, set[int]] = {}
        for event in run_suricata(cls.folder):
            port = event.get("src_port") if event.get("src_ip") == "203.0.113.50" else event.get("dest_port")
            cls.alerts.setdefault(int(port), set()).add(int(event["alert"]["signature_id"]))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.folder, ignore_errors=True)

    def test_each_request_raises_exactly_its_rules(self):
        for (case, covers), port in zip(REQUESTS, self.ports):
            raised = self.alerts.get(port, set()) & covers
            self.assertEqual(raised, set(case["alerts"]), f"{case['name']}: raised {sorted(raised)}, expected {sorted(case['alerts'])}")

    def test_every_rule_is_proven_by_a_request(self):
        proven = {sid for case, _ in REQUESTS for sid in case["alerts"]}
        self.assertEqual(COVERED_SIDS - proven, set(), "rules with no request that raises them")


class CaseFiles(unittest.TestCase):
    def test_cases_name_known_rules(self):
        for case, covers in REQUESTS:
            self.assertIn("request", case, case.get("name"))
            self.assertTrue(covers, f"{case.get('name')}: its case file has no 'covers' list")
            self.assertLessEqual(covers, COVERED_SIDS, f"'covers' names SIDs not in {COVERED_FILES}")
            for sid in case["alerts"]:
                self.assertIn(sid, covers, f"{case['name']}: sid {sid} is not in its file's 'covers'")


if __name__ == "__main__":
    unittest.main()
