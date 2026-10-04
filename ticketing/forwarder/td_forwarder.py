#!/usr/bin/env python3
# TechDetechtives alert-to-ticket forwarder.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Create one DFIR-IRIS alert for every platform alert.

Reads alerts from the platform's Elasticsearch with the read-only key and
posts each one to DFIR-IRIS over its HTTP API. It never writes to the
platform. Uses only the Python standard library.

    td_forwarder.py            run forever
    td_forwarder.py --once     one polling cycle, then exit
    td_forwarder.py --check    test both connections and exit
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

VERSION = "0.2.0"
log = logging.getLogger("td_forwarder")

# Platform severity numbers (event.severity) and the IRIS severity they map to.
SEVERITY_NAMES = {1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
# Used only if IRIS cannot be asked for its own identifiers.
FALLBACK_SEVERITY_IDS = {"Unspecified": 1, "Informational": 2, "Low": 3, "Medium": 4, "High": 5, "Critical": 6}
FALLBACK_STATUS_NEW = 2
FALLBACK_CUSTOMER_ID = 1

# Fields copied into the ticket summary. Sigma alerts keep the original event
# under event_data, so each field is looked up in both places.
SUMMARY_FIELDS = [
    ("Sensor", "observer.name"),
    ("Host", "host.name"),
    ("User", "user.name"),
    ("Source", "source.ip"),
    ("Source port", "source.port"),
    ("Destination", "destination.ip"),
    ("Destination port", "destination.port"),
    ("Process", "process.executable"),
    ("Command line", "process.command_line"),
    ("File", "file.name"),
    ("File MD5", "hash.md5"),
    ("Community ID", "network.community_id"),
    ("Rule category", "rule.category"),
    ("Rule ID", "rule.uuid"),
]
MAX_CONTENT_BYTES = 200_000
MAX_FAILURES_PER_ALERT = 5


class ConfigError(Exception):
    pass


def _flag(value: Optional[str], default: bool) -> bool:
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int, minimum: int = 0) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a whole number, got '{raw}'") from None
    if value < minimum:
        raise ConfigError(f"{name} must be at least {minimum}")
    return value


class Config:
    def __init__(self) -> None:
        env = os.environ
        host = env.get("TD_ES_HOST", "").strip()
        port = env.get("TD_ES_PORT", "9200").strip() or "9200"
        self.es_url = env.get("TD_ES_URL", "").strip().rstrip("/") or (f"https://{host}:{port}" if host else "")
        self.es_api_key = env.get("TD_ES_API_KEY", "").strip()
        self.es_ca_cert = env.get("TD_ES_CA_CERT", "").strip()
        self.es_assert_hostname = _flag(env.get("TD_ES_ASSERT_HOSTNAME"), True)
        self.soc_url = env.get("TD_SOC_URL", "").strip().rstrip("/") or (f"https://{host}" if host else "")
        self.index = env.get("TD_TICKET_INDEX", "").strip() or "logs-*"

        self.iris_url = env.get("TD_IRIS_URL", "").strip().rstrip("/")
        self.iris_api_key = env.get("TD_IRIS_API_KEY", "").strip()
        self.iris_ca_cert = env.get("TD_IRIS_CA_CERT", "").strip()
        self.iris_assert_hostname = _flag(env.get("TD_IRIS_ASSERT_HOSTNAME"), True)
        self.iris_customer = env.get("TD_IRIS_CUSTOMER", "").strip() or "IrisInitialClient"

        self.min_severity = _int("TD_TICKET_MIN_SEVERITY", 2, 1)
        self.poll_seconds = _int("TD_TICKET_POLL_SECONDS", 30, 5)
        self.lag_seconds = _int("TD_TICKET_LAG_SECONDS", 30)
        self.overlap_seconds = _int("TD_TICKET_OVERLAP_SECONDS", 600)
        self.max_per_cycle = _int("TD_TICKET_MAX_PER_CYCLE", 200, 1)
        self.backfill_minutes = _int("TD_TICKET_BACKFILL_MINUTES", 0)
        self.state_path = Path(env.get("TD_TICKET_STATE", "").strip() or "/state/forwarder-state.json")

        missing = [
            name
            for name, value in (
                ("TD_ES_HOST", self.es_url),
                ("TD_ES_API_KEY", self.es_api_key),
                ("TD_IRIS_URL", self.iris_url),
                ("TD_IRIS_API_KEY", self.iris_api_key),
            )
            if not value
        ]
        if missing:
            raise ConfigError("missing settings in config/techdetechtives.env: " + ", ".join(missing))
        if self.min_severity > 4:
            raise ConfigError("TD_TICKET_MIN_SEVERITY must be 1 (low), 2 (medium), 3 (high) or 4 (critical)")


class HttpError(Exception):
    def __init__(self, message: str, retryable: bool) -> None:
        super().__init__(message)
        self.retryable = retryable


def _ssl_context(url: str, ca_cert: str, assert_hostname: bool) -> Optional[ssl.SSLContext]:
    if not url.lower().startswith("https://"):
        return None
    if ca_cert:
        if not Path(ca_cert).is_file():
            raise ConfigError(f"CA certificate not found: {ca_cert}")
        context = ssl.create_default_context(cafile=ca_cert)
    else:
        context = ssl.create_default_context()
    if not assert_hostname:
        # The certificate chain is still verified; only the name check is skipped.
        context.check_hostname = False
    return context


def http_json(method: str, url: str, headers: dict, body: Any = None,
              context: Optional[ssl.SSLContext] = None, timeout: int = 60) -> Any:
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Content-Type", "application/json")
    request.add_header("Accept", "application/json")
    for key, value in headers.items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            raw = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")[:500]
        # 4xx other than 408/429 will not get better by retrying.
        retryable = error.code >= 500 or error.code in (408, 429)
        raise HttpError(f"{method} {url} returned HTTP {error.code}: {detail}", retryable) from None
    except (urllib.error.URLError, TimeoutError, ConnectionError, ssl.SSLError, OSError) as error:
        raise HttpError(f"{method} {url} failed: {error}", True) from None
    try:
        return json.loads(raw) if raw else {}
    except ValueError:
        raise HttpError(f"{method} {url} returned a non-JSON response: {raw[:200]}", True) from None


def lookup(document: dict, dotted: str) -> Any:
    """Value of a dotted field, whether stored nested or as a literal dotted key."""
    if dotted in document:
        return document[dotted]
    current: Any = document
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def field(source: dict, dotted: str) -> Any:
    """Field from the alert, falling back to the wrapped original event."""
    value = lookup(source, dotted)
    if value in (None, "", []):
        inner = source.get("event_data")
        if isinstance(inner, dict):
            value = lookup(inner, dotted)
    return None if value in ("", []) else value


def parse_time(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Platform:
    """Read-only access to the platform's alerts."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.headers = {"Authorization": f"ApiKey {config.es_api_key}"}
        self.context = _ssl_context(config.es_url, config.es_ca_cert, config.es_assert_hostname)

    def info(self) -> dict:
        return http_json("GET", self.config.es_url + "/", self.headers, context=self.context)

    def query(self, since: datetime, until: datetime, exclude_ids: Optional[list[str]] = None) -> dict:
        query: dict[str, Any] = {
            "bool": {
                "filter": [
                    {"match": {"tags": "alert"}},
                    {"range": {"event.severity": {"gte": self.config.min_severity}}},
                    {"range": {"@timestamp": {"gte": iso(since), "lte": iso(until)}}},
                ]
            }
        }
        if exclude_ids:
            query["bool"]["must_not"] = [{"ids": {"values": exclude_ids}}]
        return query

    def search(self, since: datetime, until: datetime, size: int,
               exclude_ids: Optional[list[str]] = None) -> list[dict]:
        index = urllib.parse.quote(self.config.index, safe="*,-_.")
        url = f"{self.config.es_url}/{index}/_search?ignore_unavailable=true&allow_no_indices=true"
        body = {
            "size": size,
            "sort": [{"@timestamp": {"order": "asc", "unmapped_type": "date"}}],
            "query": self.query(since, until, exclude_ids),
        }
        result = http_json("POST", url, self.headers, body, context=self.context)
        return result.get("hits", {}).get("hits", [])

    def count(self, since: datetime, until: datetime) -> int:
        index = urllib.parse.quote(self.config.index, safe="*,-_.")
        url = f"{self.config.es_url}/{index}/_count?ignore_unavailable=true&allow_no_indices=true"
        result = http_json("POST", url, self.headers, {"query": self.query(since, until)}, context=self.context)
        return int(result.get("count", 0))


class Iris:
    """The DFIR-IRIS alert API."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.headers = {"Authorization": f"Bearer {config.iris_api_key}"}
        self.context = _ssl_context(config.iris_url, config.iris_ca_cert, config.iris_assert_hostname)
        self.severity_ids: dict[str, int] = dict(FALLBACK_SEVERITY_IDS)
        self.status_new = FALLBACK_STATUS_NEW
        self.customer_id = FALLBACK_CUSTOMER_ID
        self.resolved = False

    def _get(self, path: str) -> list:
        result = http_json("GET", self.config.iris_url + path, self.headers, context=self.context)
        if result.get("status") != "success":
            raise HttpError(f"IRIS {path} did not succeed: {str(result)[:300]}", False)
        data = result.get("data")
        return data if isinstance(data, list) else []

    def resolve_ids(self) -> None:
        """Ask IRIS for its own severity, status and customer identifiers."""
        severities = {row.get("severity_name"): row.get("severity_id") for row in self._get("/manage/severities/list")}
        if severities.get("Medium"):
            self.severity_ids = {name: int(value) for name, value in severities.items() if name and value}
        statuses = {row.get("status_name"): row.get("status_id") for row in self._get("/manage/alert-status/list")}
        if statuses.get("New"):
            self.status_new = int(statuses["New"])
        customers = {row.get("customer_name"): row.get("customer_id") for row in self._get("/manage/customers/list")}
        if self.config.iris_customer not in customers:
            raise ConfigError(
                f"IRIS has no customer named '{self.config.iris_customer}'. "
                f"Set TD_IRIS_CUSTOMER to one of: {sorted(name for name in customers if name)}"
            )
        self.customer_id = int(customers[self.config.iris_customer])
        self.resolved = True

    def create_alert(self, payload: dict) -> int:
        result = http_json("POST", self.config.iris_url + "/alerts/add", self.headers, payload, context=self.context)
        if result.get("status") != "success":
            raise HttpError(f"IRIS rejected the alert: {str(result.get('message') or result)[:400]}", False)
        data = result.get("data") or {}
        return int(data.get("alert_id", 0)) if isinstance(data, dict) else 0


def build_alert(hit: dict, config: Config, iris: Iris) -> dict:
    """Translate one platform alert into a DFIR-IRIS alert."""
    source = hit.get("_source") or {}
    doc_id = str(hit.get("_id", ""))
    module = str(field(source, "event.module") or "alert")
    rule = field(source, "rule.name") or field(source, "file.name") or "Unnamed alert"
    if isinstance(rule, list):
        rule = ", ".join(str(item) for item in rule)
    try:
        severity_number = int(lookup(source, "event.severity"))
    except (TypeError, ValueError):
        severity_number = 0
    severity_name = SEVERITY_NAMES.get(severity_number, "Unspecified")
    severity_id = iris.severity_ids.get(severity_name) or iris.severity_ids.get("Unspecified") or 1

    summary: dict[str, str] = {}
    for label, dotted in SUMMARY_FIELDS:
        value = field(source, dotted)
        if value is None:
            continue
        if isinstance(value, (list, dict)):
            value = json.dumps(value)
        summary[label] = str(value)[:2000]

    when = parse_time(source.get("@timestamp")) or datetime.now(timezone.utc)
    lines = [f"Platform alert from the {module} engine, severity {severity_name.lower()}."]
    lines += [f"{label}: {value}" for label, value in summary.items()]

    content: Any = source
    if len(json.dumps(source, default=str)) > MAX_CONTENT_BYTES:
        content = {"note": "event too large to attach; open it on the platform", "_id": doc_id, "_index": hit.get("_index")}

    link = ""
    if config.soc_url and doc_id:
        link = f"{config.soc_url}/#/hunt?q=" + urllib.parse.quote(f'_id:"{doc_id}"', safe="")

    return {
        "alert_title": f"[{module}] {rule}"[:480],
        "alert_description": "\n".join(lines),
        "alert_source": "TechDetechtives",
        "alert_source_ref": doc_id,
        "alert_source_link": link,
        "alert_source_content": content,
        "alert_source_event_time": when.strftime("%Y-%m-%dT%H:%M:%S.%f"),
        "alert_severity_id": severity_id,
        "alert_status_id": iris.status_new,
        "alert_customer_id": iris.customer_id,
        "alert_context": summary,
        "alert_note": "",
        "alert_tags": ",".join(["techdetechtives", module, severity_name.lower()]),
    }


class State:
    """Where the forwarder got to, kept on disk so restarts do not duplicate tickets."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.checkpoint: Optional[datetime] = None
        self.floor: Optional[datetime] = None  # never ticket alerts older than this
        self.seen: dict[str, str] = {}      # alert id -> its timestamp
        self.failures: dict[str, int] = {}  # alert id -> failed attempts

    def load(self) -> None:
        if not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as error:
            raise ConfigError(f"state file {self.path} is unreadable ({error}); move it aside to start fresh") from None
        self.checkpoint = parse_time(data.get("checkpoint"))
        self.floor = parse_time(data.get("floor"))
        self.seen = dict(data.get("seen") or {})
        self.failures = {key: int(value) for key, value in (data.get("failures") or {}).items()}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps({
                "checkpoint": iso(self.checkpoint) if self.checkpoint else None,
                "floor": iso(self.floor) if self.floor else None,
                "seen": self.seen,
                "failures": self.failures,
            }),
            encoding="utf-8",
        )
        temporary.replace(self.path)

    def prune(self, keep_after: datetime) -> None:
        self.seen = {
            key: stamp for key, stamp in self.seen.items()
            if (parse_time(stamp) or keep_after) >= keep_after
        }
        self.failures = {key: count for key, count in self.failures.items() if key not in self.seen}


def run_cycle(config: Config, platform: Platform, iris: Iris, state: State, now: Optional[datetime] = None) -> dict:
    """One polling pass. Returns counts for logging and tests."""
    now = now or datetime.now(timezone.utc)
    until = now - timedelta(seconds=config.lag_seconds)
    if state.checkpoint is None:
        state.checkpoint = until - timedelta(minutes=config.backfill_minutes)
        state.floor = state.checkpoint
        log.info("first run: creating tickets for alerts from %s onwards", iso(state.checkpoint))
    overlap = timedelta(seconds=config.overlap_seconds)
    # Look back past the checkpoint so alerts that were indexed late are still
    # picked up; the seen list stops them being ticketed twice.
    since = state.checkpoint - overlap
    if state.floor and since < state.floor:
        since = state.floor
    counts = {"created": 0, "skipped": 0, "failed": 0, "backlog": False}
    if not iris.resolved:
        try:
            iris.resolve_ids()
        except HttpError as error:
            log.warning("could not read identifiers from IRIS, using its defaults: %s", error)

    cursor = since
    page_size = min(max(config.max_per_cycle, 100), 1000)
    stop = False
    # Alerts already handled at exactly the cursor time. Each later page asks
    # for "cursor time or newer, except these", so paging always moves forward
    # even when thousands of alerts share one timestamp.
    at_cursor: list[str] = []
    while not stop:
        hits = platform.search(cursor, until, page_size, at_cursor)
        if not hits:
            break
        last_time = cursor
        page: list[tuple[str, str]] = []
        for hit in hits:
            doc_id = str(hit.get("_id", ""))
            stamp = (hit.get("_source") or {}).get("@timestamp")
            moment = parse_time(stamp) or cursor
            last_time = max(last_time, moment)
            page.append((doc_id, iso(moment)))
            if not doc_id or doc_id in state.seen:
                continue
            if counts["created"] >= config.max_per_cycle:
                counts["backlog"] = True
                stop = True
                break
            try:
                alert_id = iris.create_alert(build_alert(hit, config, iris))
            except HttpError as error:
                counts["failed"] += 1
                attempts = state.failures.get(doc_id, 0) + 1
                state.failures[doc_id] = attempts
                if error.retryable or attempts < MAX_FAILURES_PER_ALERT:
                    log.error("ticket for alert %s not created (attempt %d): %s", doc_id, attempts, error)
                    # Stop here and retry from this alert next cycle, so order is kept.
                    stop = True
                    break
                log.error("giving up on alert %s after %d attempts: %s", doc_id, attempts, error)
                state.seen[doc_id] = iso(moment)
                counts["skipped"] += 1
                continue
            state.seen[doc_id] = iso(moment)
            state.failures.pop(doc_id, None)
            counts["created"] += 1
            if moment > state.checkpoint:
                state.checkpoint = moment
            log.info("ticket %s created for alert %s (%s)", alert_id or "?", doc_id,
                     field(hit.get("_source") or {}, "rule.name") or "unnamed")
        if stop or len(hits) < page_size:
            break
        at_last = [doc_id for doc_id, stamp in page if doc_id and stamp == iso(last_time)]
        at_cursor = at_cursor + at_last if iso(last_time) == iso(cursor) else at_last
        cursor = last_time

    if not stop and counts["failed"] == 0 and until > state.checkpoint:
        state.checkpoint = until
    state.prune(state.checkpoint - overlap * 2)
    state.save()
    if counts["backlog"]:
        log.warning("reached TD_TICKET_MAX_PER_CYCLE (%d); the rest follow next cycle", config.max_per_cycle)
    return counts


def check(config: Config, platform: Platform, iris: Iris) -> int:
    failed = 0
    try:
        info = platform.info()
        now = datetime.now(timezone.utc)
        recent = platform.count(now - timedelta(hours=24), now)
        print(f"[ ok ] platform: Elasticsearch {info.get('version', {}).get('number', '?')}; "
              f"{recent} alerts at severity {config.min_severity}+ in the last 24 hours")
    except (HttpError, ConfigError) as error:
        failed += 1
        print(f"[FAIL] platform: {error}")
    try:
        iris.resolve_ids()
        print(f"[ ok ] ticketing: connected to DFIR-IRIS; tickets go to customer "
              f"'{config.iris_customer}' (id {iris.customer_id})")
    except (HttpError, ConfigError) as error:
        failed += 1
        print(f"[FAIL] ticketing: {error}")
    return 1 if failed else 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="TechDetechtives alert-to-ticket forwarder")
    parser.add_argument("--once", action="store_true", help="run one polling cycle and exit")
    parser.add_argument("--check", action="store_true", help="test both connections and exit")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)

    try:
        config = Config()
        platform = Platform(config)
        iris = Iris(config)
        if args.check:
            return check(config, platform, iris)
        state = State(config.state_path)
        state.load()
    except ConfigError as error:
        log.error("%s", error)
        return 2

    log.info("TechDetechtives forwarder %s: severity %d and above from %s to %s, every %ds",
             VERSION, config.min_severity, config.es_url, config.iris_url, config.poll_seconds)
    while True:
        try:
            counts = run_cycle(config, platform, iris, state)
            if counts["created"] or counts["failed"] or counts["skipped"]:
                log.info("cycle done: %d created, %d failed, %d skipped",
                         counts["created"], counts["failed"], counts["skipped"])
        except HttpError as error:
            log.error("cycle failed, will retry: %s", error)
        except ConfigError as error:
            log.error("%s", error)
            return 2
        if args.once:
            return 0
        time.sleep(config.poll_seconds)


if __name__ == "__main__":
    sys.exit(main())
