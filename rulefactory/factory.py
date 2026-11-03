# TechDetechtives rule factory: from a CVE to a pull request.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import community, draft, feeds, nuclei
from .common import DETECTIONS, REPO, check_cve, log

REPORTS = REPO / "rulefactory" / "reports"


@dataclass
class Result:
    vuln: feeds.Vulnerability
    coverage: community.Coverage
    template: Optional[nuclei.Template]
    drafts: list[draft.Draft] = field(default_factory=list)
    already: list[str] = field(default_factory=list)      # our own rule files that already name the CVE
    files: list[Path] = field(default_factory=list)
    tests: str = ""
    passed: Optional[bool] = None
    engine_tested: bool = False
    yara_tested: bool = False

    @property
    def branch(self) -> str:
        return f"rulefactory/{self.vuln.cve.lower()}"


def own_rules(cve: str) -> list[str]:
    year, number = cve.split("-")[1:]
    pattern = re.compile(rf"cve[-_.,]{year}[-_]{number}(?!\d)", re.I)
    files = [p for folder in ("sigma", "suricata", "yara") for p in sorted((DETECTIONS / folder).glob("*"))]
    return [str(path.relative_to(REPO)) for path in files
            if path.suffix in (".yml", ".rules", ".yar") and pattern.search(path.read_text(errors="replace"))]


def build(cve: str, *, nuclei_path: Optional[Path] = None, offline: bool = False,
          vuln: Optional[feeds.Vulnerability] = None) -> Result:
    cve = check_cve(cve)
    vuln = vuln or (feeds.Vulnerability(cve=cve) if offline else feeds.lookup(cve))
    if offline:
        coverage = community.Coverage(nuclei=nuclei_path, errors=["ET Open, SigmaHQ and YARA Forge (running offline)"])
    else:
        coverage = community.search(cve, nuclei_path)
    template = nuclei.load(coverage.nuclei) if coverage.nuclei else None
    result = Result(vuln, coverage, template, already=own_rules(cve))
    if result.already:
        log.info("%s: TechDetechtives rules already name it (%s); nothing drafted", cve, ", ".join(result.already))
        return result
    result.drafts = draft.all_drafts(vuln, template)
    return result


def write(result: Result) -> list[Path]:
    """Rule files, the case file with their tests, and the report."""
    cve = result.vuln.cve
    cases: dict = {"about": f"Tests for the rules the rule factory drafted for {cve}. Made by rulefactory; edit freely.",
                   "covers": [], "suricata": [], "sigma": {}, "yara": {}, "validation": []}
    for item in result.drafts:
        item.path.parent.mkdir(parents=True, exist_ok=True)
        item.path.write_text(item.text)
        result.files.append(item.path)
        cases["covers"] += item.cases.get("covers", [])
        cases["suricata"] += item.cases.get("suricata", [])
        cases["sigma"].update(item.cases.get("sigma", {}))
        cases["yara"].update(item.cases.get("yara", {}))
        cases["validation"] += item.validation
    if result.drafts:
        case_path = DETECTIONS / "cases" / f"{cve.lower()}.json"
        case_path.write_text(json.dumps({k: v for k, v in cases.items() if v}, indent=1, ensure_ascii=False) + "\n")
        result.files.append(case_path)
    REPORTS.mkdir(parents=True, exist_ok=True)
    report = REPORTS / f"{cve}.md"
    report.write_text(render_report(result))
    result.files.append(report)
    return result.files


def validate(result: Result) -> bool:
    """The repository's own rule tests, which now include the drafts' cases."""
    env = dict(os.environ)
    run = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "platform/tests", "-p", "test_*rule*.py", "-v"],
                         cwd=REPO, capture_output=True, text=True, env=env, timeout=1800)
    engine = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "platform/tests", "-p", "test_suricata_engine.py", "-v"],
                            cwd=REPO, capture_output=True, text=True, env=env, timeout=1800)
    verify = subprocess.run(["bash", "scripts/verify.sh", "repo"], cwd=REPO, capture_output=True, text=True, timeout=1800)
    output = run.stderr + engine.stderr
    line = next((l for l in engine.stderr.splitlines() if l.startswith("test_each_request_raises_exactly_its_rules")), "")
    result.engine_tested = bool(line) and "skipped" not in line
    result.yara_tested = "the yara program is not installed" not in run.stderr
    failed_verify = [line for line in verify.stdout.splitlines() if line.startswith("[FAIL]")]
    result.passed = run.returncode == 0 and engine.returncode == 0 and not failed_verify
    result.tests = output[-6000:] + ("\n" + "\n".join(failed_verify) if failed_verify else "")
    return result.passed


def render_report(result: Result) -> str:
    v, c = result.vuln, result.coverage
    lines = [f"# {v.cve}: {v.name or v.title}", "",
             f"Made by the TechDetechtives rule factory on {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC from public information only.", "",
             "## The vulnerability", "",
             f"- **Product:** {v.title}",
             f"- **Known exploited (CISA KEV):** {'yes, added ' + v.date_added if v.in_kev else 'no'}"
             + (f"; used in ransomware campaigns: {v.ransomware}" if v.ransomware else ""),
             f"- **Severity:** {v.severity or 'unknown'}" + (f" (CVSS {v.cvss})" if v.cvss else ""),
             f"- **Weakness:** {', '.join(v.cwes) or 'not given'}",
             f"- **Details:** https://nvd.nist.gov/vuln/detail/{v.cve}", ""]
    if v.description:
        lines += [f"> {v.description.strip()[:900]}", ""]
    lines += ["## Rules that already exist", ""]
    if result.already:
        lines += [f"- TechDetechtives: `{path}`" for path in result.already]
    for found in c.et_open:
        lines.append(f"- ET Open: {found.name} ({found.where}). Security Onion loads ET Open, so this is on once its rules update.")
    for found in c.sigma:
        lines.append(f"- SigmaHQ: {found.name} (`{found.where}`, {found.note}). Security Onion imports SigmaHQ rules; check it is enabled.")
    for found in c.yara:
        lines.append(f"- YARA Forge: `{found.name}` ({found.where}, licence: {found.note}). Not copied; import it if its licence suits.")
    if not (result.already or c.et_open or c.sigma or c.yara or c.errors):
        lines.append("- None found in ET Open, SigmaHQ or YARA Forge.")
    for error in c.errors:
        lines.append(f"- Not searched: {error}")
    lines += ["", "## Drafted here", ""]
    if result.template:
        lines.append(f"Exploit request from the Nuclei template `{result.template.id}` (ProjectDiscovery, MIT licence), "
                     f"{len(result.template.requests)} variant(s).")
        lines.append("")
    if result.drafts:
        lines += [f"- {item.summary}: `{item.path.relative_to(REPO)}`" for item in result.drafts]
        lines.append(f"- Tests: `platform/detections/cases/{v.cve.lower()}.json` (the exploit requests and events it must alert on, and look-alikes it must not)")
    else:
        reasons = []
        if not result.template:
            reasons.append("no public exploit request (Nuclei template) to draft a network rule from")
        if not draft.product_entry(v):
            reasons.append("the product is not in rulefactory/products.yml, so no host rule was drafted")
        reasons.append("the exploit uploads no script file, so YARA has nothing to match" if result.template else "")
        lines.append("Nothing drafted: " + "; ".join(r for r in reasons if r) + ".")
    lines += ["", "## Tests", ""]
    if result.passed is None:
        lines.append("Not run yet.")
    else:
        lines.append(f"- Rule tests (Sigma logic, Suricata structure, YARA samples, repository checks): **{'passed' if result.passed else 'FAILED'}**")
        lines.append(f"- Suricata replayed the exploit requests and look-alikes: **{'yes' if result.engine_tested else 'no, Suricata was not available'}**")
        lines.append(f"- YARA compiled and ran its samples: **{'yes' if result.yara_tested else 'no, yara was not installed'}**")
    lines += ["", "## Before approving", "",
              "1. Read each rule: does it match the attack, and only the attack?",
              "2. Check it against your own traffic if you can: Hunt for the same URI or process in the last 30 days.",
              "3. Approve and merge; `sudo scripts/install.sh platform` on the manager loads the rules (Detections, Full Update to load them at once).",
              "4. Search back: the platform keeps weeks of data, and exploitation often starts before a CVE is published.", ""]
    return "\n".join(lines)


# ------------------------------------------------------------------ publishing
def _git(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=REPO, capture_output=True, text=True, check=check, timeout=300)


def remote_branch_exists(branch: str) -> bool:
    return bool(_git("ls-remote", "--heads", "origin", branch, check=False).stdout.strip())


def processed(cve: str) -> bool:
    return (REPORTS / f"{cve}.md").exists() or remote_branch_exists(f"rulefactory/{cve.lower()}")


def publish(result: Result, repo: str, token: str, base: str = "main") -> str:
    """Commit to a branch of its own, push, and open a pull request. Returns its URL."""
    branch = result.branch
    _git("checkout", "-q", "-B", branch)
    _git("add", "--", *[str(p.relative_to(REPO)) for p in result.files])
    title = f"Rule factory: {result.vuln.cve} {result.vuln.title}"[:200]
    _git("commit", "-q", "-m", f"{title}\n\nDrafted from public information by rulefactory. Needs an analyst's review.")
    _git("push", "-q", "-u", "origin", branch, "--force-with-lease")
    _git("checkout", "-q", base)
    body = (render_report(result) + "\n<details><summary>Test output</summary>\n\n```\n" + (result.tests or "not run")[-4000:]
            + "\n```\n</details>\n")
    request = urllib.request.Request(f"https://api.github.com/repos/{repo}/pulls", method="POST",
                                     data=json.dumps({"title": title, "head": branch, "base": base, "body": body,
                                                      "draft": not bool(result.passed)}).encode(),
                                     headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                                              "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "td-rulefactory"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read())["html_url"]
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"GitHub refused the pull request: HTTP {error.code} {error.read()[:300]!r}") from None
