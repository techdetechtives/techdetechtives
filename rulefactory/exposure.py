# TechDetechtives rule factory: are we exposed? Runs inside your network.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Matches recently exploited remote-code-execution CVEs (CISA KEV) against
the vulnerability scanner's findings already on the platform, and raises one
DFIR-IRIS alert per CVE that is present, naming the hosts and saying which
detection rules are in place. Nothing about your hosts leaves your network:
the only outside requests are for the public KEV and NVD feeds.

Reads the platform with the read-only key (TD_ES_*), writes to DFIR-IRIS with
TD_IRIS_* - the same settings as the ticket forwarder (config/techdetechtives.env).
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Optional

from . import feeds
from .common import REPO, log
from .factory import own_rules

sys.path.insert(0, str(REPO / "ticketing" / "forwarder"))
import td_forwarder as fw  # noqa: E402  (shared HTTP, TLS and settings handling)

INDEX = "logs-greenbone.results-*"
PR_SEARCH = "https://github.com/techdetechtives/techdetechtives/pulls?q=is%3Apr+{cve}"


def findings(platform: "fw.Platform", cves: list[str]) -> dict[str, dict]:
    """CVE -> {"hosts": [...], "names": [...]} for the CVEs the scanner has seen."""
    found: dict[str, dict] = {}
    for start in range(0, len(cves), 500):
        chunk = cves[start:start + 500]
        body = {"size": 0, "query": {"bool": {"filter": [{"terms": {"vulnerability.id": chunk}}]}},
                "aggs": {"cve": {"terms": {"field": "vulnerability.id", "size": 1000, "include": chunk},
                                 "aggs": {"hosts": {"terms": {"field": "host.ip", "size": 200}},
                                          "names": {"terms": {"field": "host.name", "size": 200}}}}}}
        index = fw.urllib.parse.quote(INDEX, safe="*,-_.")
        data = fw.http_json("POST", f"{platform.config.es_url}/{index}/_search?ignore_unavailable=true&allow_no_indices=true",
                            platform.headers, body, context=platform.context)
        for bucket in data.get("aggregations", {}).get("cve", {}).get("buckets", []):
            found[bucket["key"]] = {"hosts": sorted(b["key"] for b in bucket["hosts"]["buckets"]),
                                    "names": sorted(b["key"] for b in bucket["names"]["buckets"])}
    return found


def alert_payload(vuln: feeds.Vulnerability, seen: dict, iris: "fw.Iris") -> dict:
    rules = own_rules(vuln.cve)
    hosts = seen["hosts"]
    critical = (vuln.cvss or 0) >= 9 or vuln.ransomware.lower() == "known"
    severity = iris.severity_ids.get("Critical" if critical else "High") or iris.severity_ids.get("High") or 1
    lines = [f"{vuln.cve} ({vuln.name or vuln.title}) is being exploited in the wild (CISA KEV, added {vuln.date_added or 'recently'}) "
             f"and the vulnerability scanner finds it on {len(hosts)} host(s).", "",
             "Hosts: " + ", ".join(hosts[:50]) + (" ..." if len(hosts) > 50 else ""), ""]
    if rules:
        lines.append("TechDetechtives detection rules for it are in place: " + ", ".join(rules))
    else:
        lines.append("No TechDetechtives rule names it yet. The rule factory drafts one when a public exploit exists: "
                     + PR_SEARCH.format(cve=vuln.cve))
    lines += ["", "Patch or isolate these hosts first; then search back in Hunt for exploitation before the patch."]
    return {
        "alert_title": f"[Rule factory] Actively exploited {vuln.cve} found on {len(hosts)} host(s)"[:480],
        "alert_description": "\n".join(lines),
        "alert_source": "TechDetechtives rule factory",
        "alert_source_ref": f"exposure-{vuln.cve}-{hashlib.sha1(','.join(hosts).encode()).hexdigest()[:12]}",
        "alert_source_link": f"https://nvd.nist.gov/vuln/detail/{vuln.cve}",
        "alert_source_content": {"cve": vuln.cve, "hosts": hosts, "host_names": seen["names"], "rules": rules,
                                 "kev_date_added": vuln.date_added, "cvss": vuln.cvss, "cwes": vuln.cwes},
        "alert_source_event_time": fw.datetime.now(fw.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f"),
        "alert_severity_id": severity,
        "alert_status_id": iris.status_new,
        "alert_customer_id": iris.customer_id,
        "alert_context": {"CVE": vuln.cve, "Hosts": str(len(hosts)), "Detection rules": "yes" if rules else "not yet"},
        "alert_note": "",
        "alert_tags": ",".join(["techdetechtives", "rulefactory", "vulnerability", vuln.cve.lower()]),
    }


def run(days: int, state_path: Optional[Path] = None, dry_run: bool = False) -> int:
    config = fw.Config()
    platform, iris = fw.Platform(config), fw.Iris(config)
    state_path = state_path or Path(os.environ.get("TD_RF_STATE", "/state/rulefactory-exposure.json"))
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    candidates = {v.cve: v for v in feeds.recent_rce(days, [])}
    if not candidates:
        log.info("no remote-code-execution CVEs added to KEV in the last %d days", days)
        return 0
    seen = findings(platform, sorted(candidates))
    log.info("%d recent exploited RCE CVEs; %d found by the scanner", len(candidates), len(seen))
    if not iris.resolved and not dry_run:
        iris.resolve_ids()
    raised = 0
    for cve, hosts in sorted(seen.items()):
        payload = alert_payload(candidates[cve], hosts, iris) if not dry_run else None
        key = hashlib.sha1(",".join(hosts["hosts"]).encode()).hexdigest()
        if state.get(cve) == key:
            continue                                      # already raised for this same set of hosts
        if dry_run:
            print(f"{cve}: {len(hosts['hosts'])} host(s): {', '.join(hosts['hosts'][:10])}")
            continue
        alert_id = iris.create_alert(payload)
        log.info("DFIR-IRIS alert %s: %s on %d host(s)", alert_id, cve, len(hosts["hosts"]))
        state[cve] = key
        raised += 1
    if not dry_run:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(state, indent=1))
    return raised
