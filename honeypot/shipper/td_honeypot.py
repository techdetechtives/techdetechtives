#!/usr/bin/env python3
# TechDetechtives honeypot shipper.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Reads the honeypot's event log and sends every event to the platform.

The honeypot is OpenCanary, a separate program that only pretends to offer
services and writes one JSON line per contact. Nothing legitimate should ever
talk to it, so the first contact from an address is sent as an alert (it shows
on the platform's Alerts page and becomes a ticket). Further contacts from the
same address to the same decoy within TD_HONEYPOT_REPEAT_MINUTES are sent as
plain events: searchable, but they do not raise a new alert each time.

Standard library only. Shares its HTTP and TLS code with the ticket forwarder.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import logging
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import td_forwarder as fw  # shared HTTP, TLS and settings helpers

VERSION = "0.1.0"
log = logging.getLogger("td_honeypot")

LOW, MEDIUM, HIGH = 1, 2, 3
SEVERITY_LABELS = {1: "low", 2: "medium", 3: "high", 4: "critical"}

# OpenCanary event code: (decoy, what happened, action, severity).
# Any contact is at least medium; an attempt to sign in or run a command is
# high. Low is kept for lines that only add detail to a contact already reported.
EVENTS: dict[int, tuple[str, str, str, int]] = {
    2000: ("ftp", "FTP sign-in attempt", "login-attempt", HIGH),
    2001: ("ftp", "FTP sign-in started", "connection", LOW),
    3000: ("http", "Web page requested", "http-request", MEDIUM),
    3001: ("http", "Web sign-in attempt", "login-attempt", HIGH),
    3002: ("http", "Unusual web request method", "http-request", MEDIUM),
    3003: ("http", "Web page requested", "http-request", MEDIUM),
    4000: ("ssh", "SSH connection", "connection", MEDIUM),
    4001: ("ssh", "SSH client version received", "connection", LOW),
    4002: ("ssh", "SSH sign-in attempt", "login-attempt", HIGH),
    5000: ("smb", "File share opened", "file-access", HIGH),
    5001: ("portscan", "Port scan (SYN)", "scan", MEDIUM),
    5002: ("portscan", "Port scan (operating system detection)", "scan", MEDIUM),
    5003: ("portscan", "Port scan (NULL)", "scan", MEDIUM),
    5004: ("portscan", "Port scan (XMAS)", "scan", MEDIUM),
    5005: ("portscan", "Port scan (FIN)", "scan", MEDIUM),
    6001: ("telnet", "Telnet sign-in attempt", "login-attempt", HIGH),
    6002: ("telnet", "Telnet connection", "connection", MEDIUM),
    7001: ("httpproxy", "Web proxy sign-in attempt", "login-attempt", HIGH),
    8001: ("mysql", "MySQL sign-in attempt", "login-attempt", HIGH),
    9001: ("mssql", "SQL Server sign-in attempt", "login-attempt", HIGH),
    9002: ("mssql", "SQL Server sign-in attempt (Windows account)", "login-attempt", HIGH),
    9003: ("mysql", "MySQL connection", "connection", MEDIUM),
    10001: ("tftp", "TFTP request", "file-access", MEDIUM),
    11001: ("ntp", "NTP monlist request", "scan", MEDIUM),
    12001: ("vnc", "VNC sign-in attempt", "login-attempt", HIGH),
    13001: ("snmp", "SNMP request", "scan", MEDIUM),
    14001: ("rdp", "Remote Desktop sign-in attempt", "login-attempt", HIGH),
    15001: ("sip", "SIP request", "scan", MEDIUM),
    16001: ("git", "Git clone request", "file-access", HIGH),
    17001: ("redis", "Redis command", "command", HIGH),
    18001: ("tcpbanner", "TCP connection", "connection", MEDIUM),
    18002: ("tcpbanner", "TCP connection", "connection", MEDIUM),
    18003: ("tcpbanner", "TCP data received", "connection", MEDIUM),
    18004: ("tcpbanner", "TCP data received", "connection", MEDIUM),
    18005: ("tcpbanner", "TCP data received", "connection", MEDIUM),
    19001: ("llmnr", "Name lookup answered by another machine", "spoofing", HIGH),
    20001: ("mongodb", "MongoDB sign-in attempt", "login-attempt", HIGH),
}
# 1000 to 1006 are OpenCanary's own start-up, error and debug lines, not contacts.
INTERNAL_CODES = range(1000, 1007)

MAX_READ_BYTES = 4 * 1024 * 1024
# An event that reaches the platform later than this (after an outage, say) is
# stamped with the delivery time, because the ticket forwarder only looks a few
# minutes back. The time it really happened stays in event.created.
LATE_AFTER = timedelta(minutes=5)
MAX_VALUE_CHARS = 1000
MAX_DETAIL_KEYS = 30
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
DATA_STREAM = re.compile(r"^logs-opencanary\.[a-z0-9_]+-[a-z0-9_.]+$")


class Config:
    def __init__(self) -> None:
        env = os.environ
        host = env.get("TD_ES_HOST", "").strip()
        port = env.get("TD_ES_PORT", "9200").strip() or "9200"
        self.es_url = env.get("TD_ES_URL", "").strip().rstrip("/") or (f"https://{host}:{port}" if host else "")
        self.api_key = env.get("TD_HONEYPOT_API_KEY", "").strip()
        self.ca_cert = env.get("TD_ES_CA_CERT", "").strip()
        self.assert_hostname = fw._flag(env.get("TD_ES_ASSERT_HOSTNAME"), True)
        self.data_stream = env.get("TD_HONEYPOT_DATASTREAM", "").strip() or "logs-opencanary.alerts-techdetechtives"
        self.log_path = Path(env.get("TD_HONEYPOT_LOG", "").strip() or "/honeypot-log/opencanary.log")
        self.state_path = Path(env.get("TD_HONEYPOT_STATE", "").strip() or "/state/honeypot-state.json")
        self.node = env.get("TD_HONEYPOT_NAME", "").strip()
        self.address = env.get("TD_HONEYPOT_IP", "").strip()
        self.repeat_minutes = fw._int("TD_HONEYPOT_REPEAT_MINUTES", 30, 0)
        self.poll_seconds = fw._int("TD_HONEYPOT_POLL_SECONDS", 10, 2)
        self.batch = fw._int("TD_HONEYPOT_BATCH", 500, 1)
        self.keep_passwords = fw._flag(env.get("TD_HONEYPOT_KEEP_PASSWORDS"), False)
        self.port_map = self._port_map(env.get("TD_HONEYPOT_PORT_MAP", ""))
        self.ignore = self._networks(env.get("TD_HONEYPOT_IGNORE_IPS", ""))

        missing = [name for name, value in (("TD_ES_HOST", self.es_url), ("TD_HONEYPOT_API_KEY", self.api_key)) if not value]
        if missing:
            raise fw.ConfigError("missing settings in config/techdetechtives.env: " + ", ".join(missing))
        if not DATA_STREAM.match(self.data_stream):
            raise fw.ConfigError("TD_HONEYPOT_DATASTREAM must look like logs-opencanary.alerts-<name>, in lower case")
        if self.address:
            try:
                ipaddress.ip_address(self.address)
            except ValueError:
                raise fw.ConfigError(f"TD_HONEYPOT_IP is not an IP address: {self.address}") from None

    @staticmethod
    def _port_map(text: str) -> dict[int, int]:
        """'22=2222,80=80': the decoy's own port and the port on the honeypot host."""
        result: dict[int, int] = {}
        for pair in text.split(","):
            if not pair.strip():
                continue
            inside, _, outside = pair.partition("=")
            if not (inside.strip().isdigit() and outside.strip().isdigit()):
                raise fw.ConfigError(f"TD_HONEYPOT_PORT_MAP has an entry that is not NUMBER=NUMBER: '{pair}'")
            result[int(inside)] = int(outside)
        return result

    @staticmethod
    def _networks(text: str) -> list:
        result = []
        for item in text.replace(";", ",").split(","):
            item = item.strip()
            if not item:
                continue
            try:
                result.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                raise fw.ConfigError(f"TD_HONEYPOT_IGNORE_IPS has an entry that is not an address or range: '{item}'") from None
        return result


def parse_address(value: Any) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def ignored(address: Optional[str], networks: list) -> bool:
    if not address:
        return False
    ip = ipaddress.ip_address(address)
    return any(ip.version == network.version and ip in network for network in networks)


def event_time(entry: dict) -> datetime:
    """OpenCanary writes UTC as '2026-10-05 17:21:03.123456'."""
    raw = str(entry.get("utc_time") or "")
    for pattern in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(raw, pattern).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return datetime.now(timezone.utc)


def clean(value: Any, limit: int = MAX_VALUE_CHARS) -> str:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, default=str)
    return CONTROL_CHARS.sub("", str(value))[:limit]


def details(logdata: Any, keep_passwords: bool) -> dict[str, str]:
    """What the visitor sent, as text. Passwords are left out unless asked for:
    a colleague who mistypes into a decoy would otherwise have a real password
    copied into the platform and into a ticket."""
    if not isinstance(logdata, dict):
        return {"message": clean(logdata)} if logdata else {}
    redis_auth = str(logdata.get("CMD", "")).upper() == "AUTH"
    result: dict[str, str] = {}
    for key, value in list(logdata.items())[:MAX_DETAIL_KEYS]:
        name = re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")[:40] or "value"
        secret = "pass" in name or (redis_auth and name == "args")
        if secret and not keep_passwords:
            result[name] = "(withheld)" if value not in ("", None, [], {}) else "(empty)"
        else:
            result[name] = clean(value)
    return result


class Recent:
    """Which (address, decoy) pairs were alerted on lately, and how severely."""

    def __init__(self, entries: Optional[dict] = None) -> None:
        self.entries: dict[str, dict] = dict(entries or {})

    def copy(self) -> "Recent":
        return Recent({key: dict(value) for key, value in self.entries.items()})

    def is_new(self, key: str, when: datetime, severity: int, window: timedelta) -> bool:
        """True when this contact deserves its own alert; records it if so."""
        last = self.entries.get(key)
        if last:
            last_time = fw.parse_time(last.get("t"))
            fresh = last_time is not None and abs(when - last_time) < window
            if fresh and severity <= int(last.get("s", 0)):
                return False
        self.entries[key] = {"t": fw.iso(when), "s": severity}
        return True

    def prune(self, window: timedelta, limit: int = 50000) -> None:
        """Forget pairs that are older than the window, measured from the newest
        event seen (not from the clock: a backlog after an outage is old news
        by the clock, but its repeats must still be recognised)."""
        times = {key: fw.parse_time(value.get("t")) for key, value in self.entries.items()}
        known = [moment for moment in times.values() if moment is not None]
        if not known:
            self.entries = {}
            return
        keep_after = max(known) - window - timedelta(minutes=5)
        kept = [(moment, key) for key, moment in times.items() if moment is not None and moment >= keep_after]
        kept.sort(reverse=True)
        self.entries = {key: self.entries[key] for _, key in kept[:limit]}


def to_document(line: str, entry: dict, config: Config, recent: Recent,
                now: Optional[datetime] = None) -> Optional[tuple[str, dict]]:
    """One OpenCanary log entry as a platform event, or None when it is not a contact."""
    now = now or datetime.now(timezone.utc)
    try:
        code = int(entry.get("logtype"))
    except (TypeError, ValueError):
        return None
    if code in INTERNAL_CODES:
        return None
    decoy, name, action, severity = EVENTS.get(code, ("other", f"Honeypot event {code}", "contact", MEDIUM))
    source = parse_address(entry.get("src_host"))
    if ignored(source, config.ignore):
        return None
    when = event_time(entry)
    node = config.node or clean(entry.get("node_id") or "honeypot", 100)
    inside_port = entry.get("dst_port") if isinstance(entry.get("dst_port"), int) else None
    port = config.port_map.get(inside_port, inside_port) if inside_port and inside_port > 0 else None
    data = details(entry.get("logdata"), config.keep_passwords)

    window = timedelta(minutes=config.repeat_minutes)
    is_alert = severity >= MEDIUM and recent.is_new(f"{source or 'unknown'}|{decoy}", when, severity, window)

    rule = f"Honeypot: {name}"
    message = f"{name} on honeypot {node}" + (f" from {source}" if source else "")
    if data.get("username"):
        message += f" as '{data['username'][:100]}'"
    late = now - when > LATE_AFTER
    if late:
        message += f" (happened at {fw.iso(when)}, delivered late)"

    document: dict[str, Any] = {
        "@timestamp": fw.iso(now if late else when),
        "message": message,
        "tags": (["alert"] if is_alert else []) + ["honeypot", "techdetechtives"],
        "event": {
            "kind": "alert" if is_alert else "event",
            "created": fw.iso(when),
            "category": ["intrusion_detection"],
            "type": ["info"],
            "module": "opencanary",
            "dataset": "opencanary.alerts",
            "code": str(code),
            "action": action,
            "severity": severity,
            "severity_label": SEVERITY_LABELS[severity],
        },
        "rule": {"name": rule, "category": "honeypot", "uuid": f"opencanary-{code}"},
        "observer": {"vendor": "Thinkst", "product": "OpenCanary", "type": "honeypot", "name": node},
        "host": {"name": node},
        "network": {"protocol": decoy},
        "opencanary": {"logtype": code, "node_id": clean(entry.get("node_id") or "", 100),
                       "decoy": decoy, "alerted": is_alert, "delivered_late": late, "logdata": data},
    }
    if decoy not in ("tftp", "ntp", "snmp", "sip", "llmnr"):
        document["network"]["transport"] = "tcp"
    if source:
        document["source"] = {"ip": source}
        if isinstance(entry.get("src_port"), int) and entry["src_port"] > 0:
            document["source"]["port"] = entry["src_port"]
        document["related"] = {"ip": [source]}
    elif entry.get("src_host"):
        document["opencanary"]["src_host"] = clean(entry.get("src_host"), 200)
    destination = config.address or parse_address(entry.get("dst_host"))
    if destination or port:
        document["destination"] = {}
        if destination:
            document["destination"]["ip"] = destination
        if port:
            document["destination"]["port"] = port
    if data.get("username"):
        document["user"] = {"name": data["username"][:256]}
    if data.get("path"):
        document["url"] = {"path": data["path"]}
    if data.get("useragent"):
        document["user_agent"] = {"original": data["useragent"]}

    doc_id = hashlib.sha256(f"{node}|{line}".encode("utf-8", "replace")).hexdigest()[:40]
    return doc_id, document


class State:
    """How far into the log the shipper has got, kept on disk across restarts."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.inode = 0
        self.offset = 0
        self.recent = Recent()

    def load(self) -> None:
        if not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as error:
            raise fw.ConfigError(f"state file {self.path} is unreadable ({error}); move it aside to start fresh") from None
        self.inode = int(data.get("inode") or 0)
        self.offset = int(data.get("offset") or 0)
        self.recent = Recent(data.get("recent") or {})

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps({"inode": self.inode, "offset": self.offset, "recent": self.recent.entries}),
                             encoding="utf-8")
        temporary.replace(self.path)


def read_lines(path: Path, inode: int, offset: int, max_lines: int) -> tuple[list[str], int, int]:
    """Complete lines after offset. Returns (lines, inode, new offset).

    Starts again from the top when the file was replaced or emptied. A line
    still being written (no newline yet) is left for the next pass.
    """
    try:
        status = path.stat()
    except FileNotFoundError:
        return [], inode, offset
    if status.st_ino != inode or status.st_size < offset:
        if inode:
            log.info("the honeypot log was replaced or emptied; reading it from the start")
        inode, offset = status.st_ino, 0
    if status.st_size == offset:
        return [], inode, offset
    with path.open("rb") as handle:
        handle.seek(offset)
        chunk = handle.read(MAX_READ_BYTES)
    lines: list[str] = []
    consumed = 0
    while len(lines) < max_lines:
        end = chunk.find(b"\n", consumed)
        if end < 0:
            break
        lines.append(chunk[consumed:end].decode("utf-8", "replace"))
        consumed = end + 1
    if not lines and len(chunk) == MAX_READ_BYTES:
        # One enormous line with no end in sight: step over it instead of stalling forever.
        log.warning("skipping %d bytes of the honeypot log that hold no complete line", len(chunk))
        consumed = len(chunk)
    return lines, inode, offset + consumed


class Platform:
    """Appends events to one data stream with a key that can do nothing else."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.context = fw._ssl_context(config.es_url, config.ca_cert, config.assert_hostname)
        self.headers = {"Authorization": f"ApiKey {config.api_key}"}

    def info(self) -> dict:
        return fw.http_json("GET", self.config.es_url + "/", self.headers, context=self.context)

    def send(self, documents: list[tuple[str, dict]]) -> dict:
        """Returns counts: delivered and rejected. Raises HttpError when nothing can be trusted."""
        body = "".join(json.dumps({"create": {"_id": doc_id}}) + "\n" + json.dumps(document) + "\n"
                       for doc_id, document in documents)
        target = f"{self.config.es_url}/{urllib.parse.quote(self.config.data_stream, safe='-_.')}/_bulk"
        request = urllib.request.Request(target, data=body.encode("utf-8"), method="POST")
        request.add_header("Content-Type", "application/x-ndjson")
        request.add_header("Authorization", self.headers["Authorization"])
        try:
            with urllib.request.urlopen(request, timeout=120, context=self.context) as response:
                result = json.loads(response.read().decode("utf-8", "replace") or "{}")
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", "replace")[:400]
            raise fw.HttpError(f"the platform returned HTTP {error.code}: {detail}",
                               error.code >= 500 or error.code in (408, 429)) from None
        except (urllib.error.URLError, TimeoutError, ConnectionError, ssl.SSLError, OSError, ValueError) as error:
            raise fw.HttpError(f"could not reach the platform: {error}", True) from None
        items = result.get("items") or []
        if len(items) != len(documents):
            raise fw.HttpError(f"the platform answered for {len(items)} of {len(documents)} events", True)
        counts = {"delivered": 0, "rejected": 0}
        for item in items:
            outcome = item.get("create") or {}
            status = int(outcome.get("status") or 0)
            if status in (200, 201, 409):          # 409: already delivered by an earlier attempt
                counts["delivered"] += 1
            elif status in (401, 403, 404, 429) or status >= 500:
                reason = (outcome.get("error") or {}).get("reason", "unknown error")
                raise fw.HttpError(f"the platform refused the events (HTTP {status}): {reason}", True)
            else:
                # The platform cannot store this one event; do not let it block the rest.
                counts["rejected"] += 1
                log.warning("the platform rejected one event (HTTP %d): %s", status,
                            str((outcome.get("error") or {}).get("reason", ""))[:300])
        return counts


def run_cycle(config: Config, platform: Platform, state: State, max_batches: int = 20,
              now: Optional[datetime] = None) -> dict:
    """Send everything new in the log. Progress is saved only after the platform accepted a batch."""
    counts = {"alerts": 0, "events": 0, "ignored": 0, "malformed": 0, "rejected": 0}
    for _ in range(max_batches):
        lines, inode, offset = read_lines(config.log_path, state.inode, state.offset, config.batch)
        if not lines and (inode, offset) == (state.inode, state.offset):
            break
        recent = state.recent.copy()
        documents: list[tuple[str, dict]] = []
        batch = {"alerts": 0, "events": 0, "ignored": 0, "malformed": 0}
        for line in lines:
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                entry = None
            if not isinstance(entry, dict):
                batch["malformed"] += 1
                continue
            built = to_document(line, entry, config, recent, now)
            if built is None:
                batch["ignored"] += 1
                continue
            documents.append(built)
            batch["alerts" if "alert" in built[1]["tags"] else "events"] += 1
        if documents:
            result = platform.send(documents)
            counts["rejected"] += result["rejected"]
        recent.prune(timedelta(minutes=config.repeat_minutes))
        state.inode, state.offset, state.recent = inode, offset, recent
        state.save()
        for key, value in batch.items():
            counts[key] += value
    return counts


def check(config: Config, platform: Platform) -> int:
    failed = 0
    if config.log_path.is_file():
        size = config.log_path.stat().st_size
        print(f"[ ok ] honeypot log: {config.log_path} ({size} bytes)")
    else:
        failed += 1
        print(f"[FAIL] honeypot log: {config.log_path} does not exist yet (is the honeypot container running?)")
    try:
        info = platform.info()
        print(f"[ ok ] platform: Elasticsearch {info.get('version', {}).get('number', '?')}; "
              f"events go to {config.data_stream}")
    except (fw.HttpError, fw.ConfigError) as error:
        failed += 1
        print(f"[FAIL] platform: {error}")
    return 1 if failed else 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="TechDetechtives honeypot shipper")
    parser.add_argument("--once", action="store_true", help="send what is new in the log and exit")
    parser.add_argument("--check", action="store_true", help="test the log file and the platform connection, then exit")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)
    try:
        config = Config()
        platform = Platform(config)
        if args.check:
            return check(config, platform)
        state = State(config.state_path)
        state.load()
    except fw.ConfigError as error:
        log.error("%s", error)
        return 2

    log.info("TechDetechtives honeypot shipper %s: %s to %s (%s), one alert per address and decoy every %d minutes",
             VERSION, config.log_path, config.es_url, config.data_stream, config.repeat_minutes)
    while True:
        try:
            counts = run_cycle(config, platform, state)
            if any(counts.values()):
                log.info("sent %d alerts and %d repeat events; %d ignored, %d unreadable lines, %d rejected",
                         counts["alerts"], counts["events"], counts["ignored"], counts["malformed"], counts["rejected"])
        except fw.HttpError as error:
            log.error("could not send, will retry: %s", error)
        except fw.ConfigError as error:
            log.error("%s", error)
            return 2
        if args.once:
            return 0
        time.sleep(config.poll_seconds)


if __name__ == "__main__":
    sys.exit(main())
