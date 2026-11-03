# TechDetechtives rule factory: shared helpers.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
from __future__ import annotations

import json
import logging
import os
import re
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional

from . import VERSION

log = logging.getLogger("rulefactory")

REPO = Path(__file__).resolve().parents[1]
DETECTIONS = REPO / "platform" / "detections"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
USER_AGENT = f"TechDetechtives-rulefactory/{VERSION} (+https://github.com/techdetechtives/techdetechtives)"


def cache_dir() -> Path:
    path = Path(os.environ.get("TD_RF_CACHE") or Path.home() / ".cache" / "td-rulefactory")
    path.mkdir(parents=True, exist_ok=True)
    return path


def check_cve(cve: str) -> str:
    cve = cve.strip().upper()
    if not CVE_RE.match(cve):
        raise ValueError(f"not a CVE id: {cve}")
    return cve


def slug(cve: str) -> str:
    """CVE-2024-4577 -> cve_2024_4577"""
    return check_cve(cve).lower().replace("-", "_")


def fetch(url: str, headers: Optional[dict] = None, timeout: int = 60, tries: int = 3) -> bytes:
    """GET with retries. Honours HTTPS_PROXY / HTTP_PROXY from the environment."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    context = ssl.create_default_context()
    last: Exception = RuntimeError("no attempt")
    for attempt in range(tries):
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            last = error
            if error.code not in (429, 500, 502, 503, 504):
                raise
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            last = error
        time.sleep(2 * (attempt + 1) + (6 if isinstance(last, urllib.error.HTTPError) and last.code == 429 else 0))
    raise last


def fetch_cached(url: str, name: str, max_age_hours: float, headers: Optional[dict] = None) -> bytes:
    """A download kept in the cache folder; refreshed when older than max_age_hours.
    When the refresh fails, the cached copy is used (and that is logged)."""
    path = cache_dir() / name
    fresh = path.exists() and (time.time() - path.stat().st_mtime) < max_age_hours * 3600
    if fresh:
        return path.read_bytes()
    try:
        data = fetch(url, headers)
        path.write_bytes(data)
        return data
    except Exception as error:  # noqa: BLE001  any network failure falls back to the cache
        if path.exists():
            log.warning("could not refresh %s (%s); using the copy from %s", url, error,
                        time.strftime("%Y-%m-%d %H:%M", time.gmtime(path.stat().st_mtime)))
            return path.read_bytes()
        raise


def fetch_json(url: str, name: str, max_age_hours: float, headers: Optional[dict] = None) -> Any:
    return json.loads(fetch_cached(url, name, max_age_hours, headers))


def suricata_text(value: str) -> str:
    """A string for a Suricata content:"..." with the characters the rule
    language reserves written as hex bytes."""
    out = []
    for char in value:
        code = ord(char)
        if char in '";\\|' or code < 0x20 or code > 0x7E:
            out.append("|" + " ".join(f"{b:02X}" for b in char.encode("utf-8", "surrogateescape")) + "|")
        else:
            out.append(char)
    return "".join(out).replace("||", " ")
