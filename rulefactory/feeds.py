# TechDetechtives rule factory: which vulnerabilities to act on.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""CISA's Known Exploited Vulnerabilities (KEV) list says what attackers are
using now; NVD adds the score, weakness type and description. A CVE is acted
on when it is in KEV and lets an attacker run code or commands."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Optional

from .common import check_cve, fetch_json, log

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"

# Weaknesses that end in running the attacker's code or commands.
RCE_CWES = {"CWE-77", "CWE-78", "CWE-94", "CWE-95", "CWE-96", "CWE-98", "CWE-434", "CWE-502", "CWE-917", "CWE-1336",
            "CWE-88", "CWE-74"}
RCE_WORDS = re.compile(r"remote code execution|execute arbitrary (code|commands?)|arbitrary code execution|"
                       r"command injection|code injection|os command|deserializ|template injection|"
                       r"execute (system )?commands|run arbitrary (code|commands)|argument injection|unrestricted (file )?upload",
                       re.I)


@dataclass
class Vulnerability:
    cve: str
    vendor: str = ""
    product: str = ""
    name: str = ""
    description: str = ""
    date_added: str = ""
    ransomware: str = ""
    cwes: list[str] = field(default_factory=list)
    cvss: Optional[float] = None
    severity: str = ""
    references: list[str] = field(default_factory=list)
    in_kev: bool = False

    @property
    def is_rce(self) -> bool:
        return bool(set(self.cwes) & RCE_CWES) or bool(RCE_WORDS.search(f"{self.name} {self.description}"))

    @property
    def title(self) -> str:
        return " ".join(part for part in (self.vendor, self.product) if part) or self.cve


def kev() -> list[dict]:
    data = fetch_json(KEV_URL, "kev.json", max_age_hours=3)
    return data.get("vulnerabilities", [])


def from_kev(entry: dict) -> Vulnerability:
    return Vulnerability(
        cve=check_cve(entry["cveID"]), vendor=entry.get("vendorProject", ""), product=entry.get("product", ""),
        name=entry.get("vulnerabilityName", ""), description=entry.get("shortDescription", ""),
        date_added=entry.get("dateAdded", ""), ransomware=entry.get("knownRansomwareCampaignUse", ""),
        cwes=list(entry.get("cwes") or []), in_kev=True,
        references=[part.strip() for part in re.split(r"[ ;]+", entry.get("notes", "")) if part.startswith("http")])


def nvd(cve: str) -> dict:
    headers = {"apiKey": os.environ["TD_RF_NVD_API_KEY"]} if os.environ.get("TD_RF_NVD_API_KEY") else None
    try:
        data = fetch_json(NVD_URL.format(cve=cve), f"nvd-{cve}.json", max_age_hours=24, headers=headers)
    except Exception as error:  # noqa: BLE001  NVD is extra detail; KEV alone is enough to go on
        log.warning("NVD lookup for %s failed: %s", cve, error)
        return {}
    items = data.get("vulnerabilities") or []
    return items[0].get("cve", {}) if items else {}


def enrich(vuln: Vulnerability) -> Vulnerability:
    record = nvd(vuln.cve)
    if not record:
        return vuln
    if not vuln.description:
        vuln.description = next((d["value"] for d in record.get("descriptions", []) if d.get("lang") == "en"), "")
    for weakness in record.get("weaknesses", []):
        for item in weakness.get("description", []):
            if item.get("value", "").startswith("CWE-") and item["value"] not in vuln.cwes:
                vuln.cwes.append(item["value"])
    metrics = record.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            data = metrics[key][0].get("cvssData", {})
            vuln.cvss = data.get("baseScore")
            vuln.severity = data.get("baseSeverity", "")
            break
    for ref in record.get("references", [])[:12]:
        if ref.get("url") and ref["url"] not in vuln.references:
            vuln.references.append(ref["url"])
    return vuln


def lookup(cve: str) -> Vulnerability:
    """One CVE, from KEV when it is listed there, enriched from NVD."""
    cve = check_cve(cve)
    entry = next((e for e in kev() if e.get("cveID", "").upper() == cve), None)
    vuln = from_kev(entry) if entry else Vulnerability(cve=cve)
    return enrich(vuln)


def recent_rce(days: int, watch: list[str]) -> list[Vulnerability]:
    """KEV entries added in the last `days` days that allow code execution.
    `watch`, when given, keeps only those whose vendor or product contains
    one of its words."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).date()
    picked = []
    for entry in kev():
        try:
            added = date.fromisoformat(entry.get("dateAdded", "1970-01-01"))
        except ValueError:
            continue
        if added < since:
            continue
        vuln = from_kev(entry)
        haystack = f"{vuln.vendor} {vuln.product}".lower()
        if watch and not any(word.lower() in haystack for word in watch):
            continue
        if not vuln.is_rce:
            vuln = enrich(vuln)          # KEV's own text may not say; NVD's weakness type will
        if vuln.is_rce:
            picked.append(vuln)
    return sorted(picked, key=lambda v: v.date_added, reverse=True)
