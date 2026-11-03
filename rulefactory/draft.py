# TechDetechtives rule factory: draft rules and their tests.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Drafts are made only from public information about the vulnerability, and
each one comes with the test cases that prove it: the requests it must alert
on and look-alikes it must not. Nothing goes live without an analyst approving
the pull request.

  Suricata  from the exploit request (Nuclei template): the distinctive parts
            every variant of the request shares
  Sigma     from the product (products.yml): its server process starting a
            shell, which is where the exploit leads
  YARA      only when the exploit uploads a script file: that file's content
"""
from __future__ import annotations

import hashlib
import re
import urllib.parse
import uuid
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Optional

import yaml

from .common import DETECTIONS, slug, suricata_text
from .feeds import Vulnerability
from .nuclei import HOST, OAST, VARIABLE, Request, Template

SID_FIRST, SID_LAST = 1900501, 1900899
SPLIT = re.compile(r"[/?&=+\s,;\"'()#<>{}\[\]|*!]+")
STOP = {"index.php", "test.php", "index.html", "index.jsp", "default.aspx", "admin", "login", "input", "hello",
        "test.hello", "localhost", "true", "false", "null", "undefined", "application", "mozilla", "text/html",
        "charset", "utf-8", "content-type", "x-www-form-urlencoded", "multipart", "form-data", "boundary"}
SIGNAL = re.compile(r"exec|runtime|jndi|include|prepend|eval|system|cmd|shell|ognl|class|upload|invoke|getruntime|"
                    r"process|script|payload|serial|template|expression|passwd|whoami|\.\./", re.I)
LINUX_SHELLS = ["/sh", "/bash", "/dash", "/zsh", "/nc", "/ncat", "/socat", "/whoami", "/id", "/curl", "/wget", "/perl"]
WINDOWS_SHELLS = ["\\cmd.exe", "\\powershell.exe", "\\pwsh.exe", "\\wscript.exe", "\\cscript.exe", "\\mshta.exe",
                  "\\rundll32.exe", "\\certutil.exe", "\\whoami.exe", "\\net.exe", "\\net1.exe"]
SCRIPT_MARKERS = re.compile(r"<\?php|<%|<jsp:|#!/bin/|<script", re.I)


@dataclass
class Draft:
    kind: str                 # suricata | sigma | yara
    path: Path                # where the rule file goes, under platform/detections
    text: str
    summary: str
    cases: dict = field(default_factory=dict)       # merged into cases/<cve>.json
    validation: list = field(default_factory=list)  # Sigma pairing entries for verify.sh


# ------------------------------------------------------------------ helpers
def _decode(uri: str) -> str:
    """What Suricata's http.uri buffer holds: percent-decoded, '+' kept."""
    return urllib.parse.unquote(uri, errors="surrogateescape")


def _usable(token: str) -> bool:
    low = token.lower()
    return (len(token) >= 5 and re.search(r"[a-z]", low) is not None and low not in STOP
            and VARIABLE.lower() not in low and OAST not in low and HOST not in token
            and not re.match(r"cve[-_]?\d{4}", low) and "nuclei" not in low and "interact" not in low)


def _score(token: str) -> float:
    return len(token) + 4 * len(re.findall(r"[._@:$%\\-]", token)) + (15 if SIGNAL.search(token) else 0)


def pick_tokens(texts: list[str], limit: int = 3) -> list[str]:
    """Distinctive pieces of the first text that every other text also has."""
    if not texts:
        return []
    candidates = {t for t in SPLIT.split(texts[0]) if _usable(t)}
    shared = [t for t in candidates if all(t.lower() in other.lower() for other in texts[1:])]
    chosen: list[str] = []
    for token in sorted(shared, key=lambda t: (-_score(t), t)):
        if any(token.lower() in c.lower() or c.lower() in token.lower() for c in chosen):
            continue
        chosen.append(token)
        if len(chosen) == limit:
            break
    return chosen


def used_sids() -> set[int]:
    sids: set[int] = set()
    for path in (DETECTIONS / "suricata").glob("*.rules"):
        sids.update(int(s) for s in re.findall(r"\bsid:(\d+);", path.read_text()))
    return sids


def allocate_sid(cve: str, taken: Optional[set[int]] = None) -> int:
    """The same CVE gets the same SID on every run; collisions move to the next free one."""
    taken = used_sids() if taken is None else taken
    span = SID_LAST - SID_FIRST + 1
    start = int(hashlib.sha1(cve.encode()).hexdigest(), 16) % span
    for step in range(span):
        sid = SID_FIRST + (start + step) % span
        if sid not in taken:
            return sid
    raise RuntimeError("no free SID left in the rule factory's range 1900501-1900899")


def _clean(text: str, limit: int) -> str:
    text = re.sub(r"[\";\\|]", " ", text)
    return re.sub(r"\s+", " ", text).strip()[:limit]


# ------------------------------------------------------------------ Suricata
def suricata(vuln: Vulnerability, template: Template, sid: Optional[int] = None) -> Optional[Draft]:
    if not template.requests:
        return None
    # Templates often send a few variants (other paths, or the payload in the
    # headers instead of the address). Draft from the ones that carry their
    # payload in the address, when any do; otherwise from the body or headers.
    nontrivial = [r for r in template.requests if urllib.parse.urlsplit(r.uri).query or len(urllib.parse.urlsplit(r.uri).path) > 1]
    primary = nontrivial[0] if nontrivial else template.requests[0]
    same_method = [r for r in (nontrivial or template.requests) if r.method == primary.method]
    buffer, tokens, kept = "http.uri", pick_tokens([_decode(r.uri) for r in same_method]), same_method
    if len(tokens) < 2:
        with_body = [r for r in template.requests if r.body and r.method == primary.method]
        body_tokens = pick_tokens([r.body for r in with_body])
        if len(body_tokens) > len(tokens):
            buffer, tokens, kept = "http.request_body", body_tokens, with_body
    if not tokens:
        with_headers = [r for r in template.requests if r.headers]
        header_tokens = pick_tokens([" ".join(r.headers.values()) for r in with_headers])
        if header_tokens:
            buffer, tokens, kept = "http.header", header_tokens, with_headers
            primary = with_headers[0]
    if not tokens:
        return None

    sid = sid or allocate_sid(vuln.cve)
    paths = {urllib.parse.urlsplit(r.uri).path for r in kept}
    path = paths.pop() if len(paths) == 1 else ""
    options = ["flow:established,to_server", f'http.method; content:"{primary.method}"']
    uri_contents = []
    if path and len(path) > 1 and path.lower() not in ("/" + s for s in STOP) and buffer != "http.uri":
        uri_contents.append(f'content:"{suricata_text(_decode(path))}"; nocase')
    if buffer == "http.uri":
        uri_contents += [f'content:"{suricata_text(t)}"; nocase' for t in tokens]
    if uri_contents:
        options.append("http.uri; " + "; ".join(uri_contents))
    if buffer != "http.uri":
        options.append(f"{buffer}; " + "; ".join(f'content:"{suricata_text(t)}"; nocase' for t in tokens))
    year, number = vuln.cve.split("-")[1:]
    name = vuln.name or template.name or "exploitation attempt"
    what = name if vuln.product and vuln.product.lower() in name.lower() else f"{vuln.title} {name}"
    msg = _clean(f"TECHDETECHTIVES Exploit - {what} ({vuln.cve})", 180)
    today = date.today().strftime("%Y_%m_%d")
    rule = (f'alert http any any -> $HOME_NET any (msg:"{msg}"; ' + "; ".join(options) +
            f"; reference:cve,{year}-{number}; classtype:web-application-attack; priority:1; sid:{sid}; rev:1; "
            f"metadata:created_at {today}, updated_at {today}, created_by rulefactory;)")
    header = (f"# {vuln.cve}: {vuln.title}. Drafted by the TechDetechtives rule factory from the public\n"
              f"# exploit request (Nuclei template {template.id}, ProjectDiscovery, MIT licence).\n"
              f"# Review before approving. SID range of rule factory files: {SID_FIRST} - {SID_LAST}.\n")

    def matches(request: Request) -> bool:
        haystack = {"http.uri": _decode(request.uri), "http.request_body": request.body,
                    "http.header": " ".join(request.headers.values())}[buffer].lower()
        return all(t.lower() in haystack for t in tokens)

    requests = []
    for index, request in enumerate(r for r in kept if matches(r)):
        requests.append({"name": f"{vuln.cve} exploit request {index + 1} (from the Nuclei template)",
                         "request": request.as_case(), "alerts": [sid]})
    plain_path = urllib.parse.urlsplit(primary.uri).path or "/"
    lookalikes = [
        Request("GET", "/", {}, ""),
        Request("GET", plain_path, {}, ""),
        Request("POST", plain_path, {"Content-Type": "application/x-www-form-urlencoded"}, "name=lab&value=1"),
    ]
    seen = set()
    for request in lookalikes:
        key = (request.method, request.uri, request.body)
        if key not in seen and not matches(request):
            seen.add(key)
            requests.append({"name": f"Look-alike: {request.method} {request.uri} without the exploit", "request": request.as_case(),
                             "alerts": []})
    return Draft("suricata", DETECTIONS / "suricata" / f"techdetechtives-{vuln.cve.lower()}.rules", header + rule + "\n",
                 f"Suricata sid {sid}: {buffer} contains " + ", ".join(f"`{t}`" for t in tokens),
                 cases={"covers": [sid], "suricata": requests})


# ------------------------------------------------------------------ Sigma
def load_products() -> list[dict]:
    return yaml.safe_load((Path(__file__).with_name("products.yml")).read_text()).get("products", [])


def product_entry(vuln: Vulnerability) -> Optional[dict]:
    haystack = f"{vuln.vendor} {vuln.product} {vuln.name}".lower()
    return next((p for p in load_products() if any(word in haystack for word in p["match"])), None)


def sigma(vuln: Vulnerability) -> Optional[Draft]:
    entry = product_entry(vuln)
    if not entry:
        return None
    linux = entry["platform"] == "linux"
    shells = LINUX_SHELLS if linux else WINDOWS_SHELLS
    title = f"TechDetechtives - {entry['name']} Server Starts a Shell ({vuln.cve})"
    rule = {
        "title": title,
        "id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"td-rulefactory/{vuln.cve}/{entry['name']}")),
        "status": "experimental",
        "description": (f"Detects the {entry['name']} server process starting a shell or a reconnaissance tool, "
                        f"which is what exploiting {vuln.cve} ({vuln.name or 'remote code execution'}) leads to. "
                        "Drafted by the TechDetechtives rule factory; review before approving."),
        "references": [f"https://nvd.nist.gov/vuln/detail/{vuln.cve}"] + vuln.references[:3],
        "author": "TechDetechtives rule factory",
        "date": date.today().isoformat(),
        "tags": ["attack.initial_access", "attack.t1190", "attack.execution", f"cve.{vuln.cve[4:].lower()}"],
        "logsource": {"category": "process_creation", "product": entry["platform"]},
        "detection": {"selection_parent": entry["parent"], "selection_child": {"Image|endswith": shells},
                      "condition": "selection_parent and selection_child"},
        "falsepositives": [f"Administration scripts that {entry['name']} runs on purpose; add their command lines as filters"],
        "level": "high",
    }
    name = f"techdetechtives_{slug(vuln.cve)}_{re.sub(r'[^a-z0-9]+', '_', entry['name'].lower()).strip('_')}.yml"
    parent = dict(entry["sample_parent"])
    shell = {"Image": "/bin/sh", "CommandLine": "sh -c id"} if linux else \
            {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c whoami"}
    benign = {"Image": parent["ParentImage"], "CommandLine": parent["ParentImage"] + " -version"}
    other_parent = {"ParentImage": "/usr/sbin/sshd" if linux else "C:\\Windows\\explorer.exe", "ParentCommandLine": "sshd" if linux else "explorer.exe"}
    cases = {"sigma": {name: {"match": [{**parent, **shell}], "nomatch": [{**parent, **benign}, {**other_parent, **shell}]}}}
    validation = [{
        "rule": f"sigma/{name}", "title": title, "technique": "T1190", "platform": entry["platform"],
        "needs": f"process start events with parent process from the {entry['name']} server",
        "tests": [{"kind": "manual", "name": f"Exploit {vuln.cve} against a lab copy of {entry['name']}, or start a shell from its server process",
                   "plain": "Run the public proof of concept only against a lab instance you own", "expect": "alert", "confirmed": "no"}],
    }]
    text = "# Drafted by the TechDetechtives rule factory. Review before approving.\n" + yaml.safe_dump(rule, sort_keys=False, allow_unicode=True, width=120)
    return Draft("sigma", DETECTIONS / "sigma" / name, text, f"Sigma: {entry['name']} server process starts a shell",
                 cases=cases, validation=validation)


# ------------------------------------------------------------------ YARA
def _uploads(request: Request) -> list[str]:
    files = []
    for part in re.split(r"\r?\n--[^\r\n]+", "\n" + request.body):
        if not re.search(r'filename\s*=\s*"[^"]+"', part, re.I):
            continue
        pieces = re.split(r"\r?\n\r?\n", part, maxsplit=1)
        content = pieces[1] if len(pieces) == 2 else ""
        if SCRIPT_MARKERS.search(content):
            files.append(content.strip())
    return files


def yara(vuln: Vulnerability, template: Optional[Template]) -> Optional[Draft]:
    if not template:
        return None
    contents = [content for request in template.requests for content in _uploads(request)]
    if not contents:
        return None
    tokens = pick_tokens(contents)
    if len(tokens) < 2:
        return None
    rule_name = f"TechDetechtives_{slug(vuln.cve).upper()}_Uploaded_Script"
    strings = "\n".join(f'        $s{i} = "{t.replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}" ascii nocase'
                        for i, t in enumerate(tokens))
    text = (f"// Drafted by the TechDetechtives rule factory from the public exploit for {vuln.cve}. Review before approving.\n"
            f"rule {rule_name}\n{{\n    meta:\n"
            f'        description = "Script file uploaded by the public exploit for {vuln.cve} ({_clean(vuln.title, 80)})"\n'
            f'        author = "TechDetechtives rule factory"\n        date = "{date.today().isoformat()}"\n'
            f'        severity = "high"\n        reference = "https://nvd.nist.gov/vuln/detail/{vuln.cve}"\n'
            f"    strings:\n{strings}\n    condition:\n        filesize < 1MB and all of them\n}}\n")
    first = contents[0]
    cases = {"yara": {rule_name: {"match": [first],
                                  "nomatch": ["<?php echo 'hello'; ?>", first.replace(tokens[0], "x" * len(tokens[0]))]}}}
    return Draft("yara", DETECTIONS / "yara" / f"techdetechtives_{slug(vuln.cve)}.yar", text,
                 "YARA: the script the exploit uploads (" + ", ".join(f"`{t}`" for t in tokens) + ")", cases=cases)


def all_drafts(vuln: Vulnerability, template: Optional[Template]) -> list[Draft]:
    drafts = []
    if template:
        made = suricata(vuln, template)
        if made:
            drafts.append(made)
    for maker in (lambda: sigma(vuln), lambda: yara(vuln, template)):
        made = maker()
        if made:
            drafts.append(made)
    return drafts
