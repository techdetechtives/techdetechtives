# TechDetechtives rule factory: rules other people have already written.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Searches public rule sets for a CVE before anything is drafted:

  ET Open (Suricata)      Security Onion already loads it; a hit means the
                          exploit request is covered once the sensor sees it
  SigmaHQ                 Security Onion imports these Sigma rules; a hit
                          means the rule only needs to be switched on
  YARA Forge              curated public YARA rules; reported with their
                          licence, never copied in
  Nuclei templates        not detection rules, but the exact request the
                          exploit sends: the source for drafting and testing

Each source is downloaded into the cache folder and refreshed once a day; a
failed refresh falls back to the last copy. Nothing about your network is sent.
"""
from __future__ import annotations

import io
import re
import subprocess
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .common import cache_dir, fetch_cached, log

ET_OPEN_URL = "https://rules.emergingthreats.net/open/suricata-7.0/emerging-all.rules"
YARA_FORGE_URL = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip"
SIGMA_REPO = "https://github.com/SigmaHQ/sigma.git"
NUCLEI_REPO = "https://github.com/projectdiscovery/nuclei-templates.git"


@dataclass
class Found:
    source: str
    name: str
    where: str = ""
    note: str = ""


@dataclass
class Coverage:
    et_open: list[Found] = field(default_factory=list)
    sigma: list[Found] = field(default_factory=list)
    yara: list[Found] = field(default_factory=list)
    nuclei: Optional[Path] = None
    errors: list[str] = field(default_factory=list)

    @property
    def any_rule(self) -> bool:
        return bool(self.et_open or self.sigma or self.yara)


def _sparse_repo(url: str, folder: str, paths: list[str]) -> Path:
    """A shallow, partial clone kept in the cache and pulled once a day."""
    target = cache_dir() / folder
    stamp = target / ".td-updated"
    if (target / ".git").exists():
        if stamp.exists() and time.time() - stamp.stat().st_mtime < 24 * 3600:
            return target
        try:
            subprocess.run(["git", "-C", str(target), "pull", "-q", "--depth", "1"], check=True, capture_output=True, timeout=600)
            stamp.touch()
        except (subprocess.SubprocessError, OSError) as error:
            log.warning("could not update %s (%s); using the copy in the cache", url, error)
        return target
    subprocess.run(["git", "clone", "-q", "--depth", "1", "--filter=blob:none", "--sparse", url, str(target)],
                   check=True, capture_output=True, timeout=900)
    subprocess.run(["git", "-C", str(target), "sparse-checkout", "set", *paths], check=True, capture_output=True, timeout=900)
    stamp.touch()
    return target


def _cve_pattern(cve: str) -> re.Pattern:
    year, number = cve.split("-")[1:]
    # CVE-2024-4577, cve.2024-4577 (Sigma tags), cve,2024-4577 (Suricata references)
    return re.compile(rf"cve[-_.,]{year}[-_]{number}(?!\d)", re.I)


def et_open(cve: str) -> list[Found]:
    text = fetch_cached(ET_OPEN_URL, "et-open-emerging-all.rules", 24).decode("utf-8", "replace")
    pattern = _cve_pattern(cve)
    found = []
    for line in text.splitlines():
        if line.startswith("alert") and pattern.search(line):
            msg = re.search(r'msg:"([^"]+)"', line)
            sid = re.search(r"\bsid:(\d+);", line)
            found.append(Found("ET Open", msg.group(1) if msg else "?", f"sid {sid.group(1) if sid else '?'}"))
    return found


def sigma(cve: str) -> list[Found]:
    root = _sparse_repo(SIGMA_REPO, "sigmahq", ["rules", "rules-emerging-threats", "rules-threat-hunting"])
    pattern = _cve_pattern(cve)
    found = []
    for path in sorted(root.glob("rules*/**/*.yml")):
        text = path.read_text(errors="replace")
        if pattern.search(path.name) or pattern.search(text):
            title = re.search(r"^title:\s*(.+)$", text, re.M)
            found.append(Found("SigmaHQ", title.group(1).strip() if title else path.stem, str(path.relative_to(root)),
                               "Detection Rule License 1.1"))
    return found


def yara_forge(cve: str) -> list[Found]:
    data = fetch_cached(YARA_FORGE_URL, "yara-forge-full.zip", 24)
    pattern = _cve_pattern(cve)
    found = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for member in archive.namelist():
            if not member.endswith(".yar"):
                continue
            text = archive.read(member).decode("utf-8", "replace")
            for match in re.finditer(r"^rule\s+(\w+)[^{]*\{(.*?)^\}", text, re.M | re.S):
                if pattern.search(match.group(0)):
                    licence = re.search(r'license\s*=\s*"([^"]+)"', match.group(2))
                    found.append(Found("YARA Forge", match.group(1), member, licence.group(1) if licence else "see the rule"))
    return found


def nuclei(cve: str) -> Optional[Path]:
    root = _sparse_repo(NUCLEI_REPO, "nuclei-templates", ["http/cves", "network/cves"])
    year = cve.split("-")[1]
    for candidate in (root / "http" / "cves" / year / f"{cve}.yaml", root / "network" / "cves" / year / f"{cve}.yaml"):
        if candidate.exists():
            return candidate
    hits = list(root.glob(f"**/{cve}.yaml"))
    return hits[0] if hits else None


def search(cve: str, offline_nuclei: Optional[Path] = None) -> Coverage:
    coverage = Coverage()
    for label, finder, slot in (("ET Open", et_open, "et_open"), ("SigmaHQ", sigma, "sigma"), ("YARA Forge", yara_forge, "yara")):
        try:
            setattr(coverage, slot, finder(cve))
        except Exception as error:  # noqa: BLE001  one unreachable source must not stop the others
            coverage.errors.append(f"{label}: {error}")
            log.warning("%s search failed: %s", label, error)
    if offline_nuclei:
        coverage.nuclei = offline_nuclei
    else:
        try:
            coverage.nuclei = nuclei(cve)
        except Exception as error:  # noqa: BLE001
            coverage.errors.append(f"Nuclei templates: {error}")
            log.warning("Nuclei template search failed: %s", error)
    return coverage
