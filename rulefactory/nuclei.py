# TechDetechtives rule factory: the exploit request, from a Nuclei template.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Nuclei templates (ProjectDiscovery, MIT licence) describe the exact HTTP
request that triggers a vulnerability. This turns one into concrete requests:
template variables become fixed stand-ins, so the requests can seed a rule and
be replayed through Suricata as its test."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

HOST = "10.0.0.5"
OAST = "oast.td-rulefactory.invalid"
VARIABLE = "TDVAR"
_PLACEHOLDER = re.compile(r"\{\{([^{}]*)\}\}")


@dataclass
class Request:
    method: str
    uri: str
    headers: dict = field(default_factory=dict)
    body: str = ""

    def as_case(self) -> dict:
        case = {"method": self.method, "uri": self.uri}
        if self.headers:
            case["headers"] = self.headers
        if self.body:
            case["body"] = self.body
        return case


@dataclass
class Template:
    id: str
    name: str
    severity: str
    tags: list[str]
    requests: list[Request]
    path: Path


def _fill(text: str) -> str:
    def replace(match: re.Match) -> str:
        name = match.group(1).strip().lower()
        if name in ("baseurl", "rooturl"):
            return ""
        if name in ("hostname", "host", "fqdn"):
            return HOST
        if "interactsh" in name:
            return OAST
        return VARIABLE
    previous = None
    while previous != text:          # placeholders can nest: {{base64('{{randstr}}')}}
        previous, text = text, _PLACEHOLDER.sub(replace, text)
    return text


def _uri(path: str) -> str:
    path = _fill(path).strip()
    path = re.sub(r"^https?://[^/]+", "", path)
    return path if path.startswith("/") else "/" + path


def _raw(text: str) -> Request:
    text = _fill(text).replace("\r\n", "\n")
    head, _, body = text.partition("\n\n")
    lines = [line for line in head.split("\n") if line.strip()]
    method, uri, *_ = lines[0].split(" ") + ["", ""]
    headers = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep and name.lower() not in ("host", "content-length", "connection"):
            headers[name.strip()] = value.strip()
    return Request(method.upper() or "GET", _uri(uri), headers, body.rstrip("\n"))


def load(path: Path) -> Template:
    data = yaml.safe_load(path.read_text())
    info = data.get("info", {})
    blocks = data.get("http") or data.get("requests") or []
    requests: list[Request] = []
    for block in blocks:
        for raw in block.get("raw") or []:
            requests.append(_raw(raw))
        method = (block.get("method") or "GET").upper()
        headers = {k: _fill(str(v)) for k, v in (block.get("headers") or {}).items()
                   if k.lower() not in ("host", "content-length", "connection")}
        body = _fill(str(block.get("body") or "")).rstrip("\n")
        for path_item in block.get("path") or []:
            requests.append(Request(method, _uri(str(path_item)), dict(headers), body))
    tags = data.get("info", {}).get("tags", "")
    return Template(id=str(data.get("id", path.stem)), name=str(info.get("name", "")), severity=str(info.get("severity", "")),
                    tags=[t.strip() for t in str(tags).split(",") if t.strip()], requests=requests, path=path)
