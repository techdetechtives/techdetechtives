# TechDetechtives network inventory: entry point.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Build the device inventory and traffic map from the platform's records.

    python -m td_net.main            read on a timer and serve the pages
    python -m td_net.main --once     one pass, then exit
    python -m td_net.main --check    test every connection and exit
    python -m td_net.main --accept   take everything seen so far as the baseline
    python -m td_net.main --advisories   fetch published advisories now and match them, then exit
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import td_forwarder as fw

from . import VERSION, advisories
from .outputs import PlatformWriter
from .platform import Platform
from .protocols import OT_DATASETS
from .store import Store
from .sync import Scope, INSIDE_DEFAULT, run_sync
from .web import make_server, use_tls

log = logging.getLogger("td_net")


def _flag(name: str, default: bool) -> bool:
    return fw._flag(os.environ.get(name), default)


class Config:
    def __init__(self, serving: bool = True) -> None:
        env = os.environ
        get = lambda name, default="": (env.get(name, "") or "").strip() or default  # noqa: E731

        host = get("TD_ES_HOST")
        self.es_url = get("TD_ES_URL").rstrip("/") or (f"https://{host}:{get('TD_ES_PORT', '9200')}" if host else "")
        self.es_api_key = get("TD_ES_API_KEY")
        self.es_ca_cert = get("TD_ES_CA_CERT")
        self.es_assert_hostname = _flag("TD_ES_ASSERT_HOSTNAME", True)
        self.index = get("TD_NET_INDEX", "logs-*")
        self.ingest_key = get("TD_NET_INGEST_API_KEY")
        self.data_stream = get("TD_NET_DATASTREAM", "logs-netmap.alerts-techdetechtives")
        self.to_platform = _flag("TD_NET_TO_PLATFORM", True) and bool(self.es_url and self.ingest_key)
        self.node = get("TD_NET_NAME", "network-inventory")[:100]

        self.sync_seconds = fw._int("TD_NET_SYNC_SECONDS", 300, 30)
        self.lag_seconds = fw._int("TD_NET_LAG_SECONDS", 300, 30)
        self.backfill_hours = fw._int("TD_NET_BACKFILL_HOURS", 24, 1)
        self.learn_hours = fw._int("TD_NET_LEARN_HOURS", 72, 0)
        self.max_changes = fw._int("TD_NET_MAX_CHANGES_PER_PASS", 100, 1)
        self.db_path = get("TD_NET_DB", "/state/network.db")
        self.scope = Scope(get("TD_NET_INSIDE", INSIDE_DEFAULT), get("TD_NET_ZONES"))

        # Published advisories (see advisories.py).
        self.adv_enabled = _flag("TD_ADV_ENABLED", True)
        self.adv_feeds = advisories.parse_feeds(get("TD_ADV_FEEDS", advisories.DEFAULT_FEEDS))
        self.adv_import_dir = get("TD_ADV_IMPORT_DIR", "/advisories")
        self.adv_watch = advisories.parse_watch(env.get("TD_ADV_WATCH", ""))
        self.adv_proxy = get("TD_ADV_PROXY")
        if self.adv_proxy and not re.fullmatch(r"https?://[A-Za-z0-9._~:@%-]+/?", self.adv_proxy):
            raise fw.ConfigError("TD_ADV_PROXY must be a proxy address such as http://proxy.example:3128")
        self.adv_fetch_hours = fw._int("TD_ADV_FETCH_HOURS", 6, 1)
        self.adv_recent_days = fw._int("TD_ADV_RECENT_DAYS", 365, 1)
        self.adv_max_documents = fw._int("TD_ADV_MAX_DOCUMENTS", 150, 1)
        self.adv_finding_days = fw._int("TD_ADV_FINDING_DAYS", 30, 1)

        self.web_bind = get("TD_NET_BIND", "0.0.0.0")
        self.web_port = fw._int("TD_NET_PORT", 8445, 1)
        self.web_user = get("TD_NET_USER", "analyst")
        self.web_password = get("TD_NET_PASSWORD")
        self.tls_cert = get("TD_NET_TLS_CERT")
        self.tls_key = get("TD_NET_TLS_KEY")
        self.soc_url = get("TD_SOC_URL").rstrip("/")

        self.brand_name = get("TD_BRAND_NAME", "TechDetechtives")[:60]
        self.brand_header = get("TD_BRAND_HEADER", "#0b0b0d")
        self.brand_accent = get("TD_BRAND_ACCENT", "#f60411")
        self.brand_logo = get("TD_BRAND_LOGO", "/brand/logo.png")
        for name, value in (("TD_BRAND_HEADER", self.brand_header), ("TD_BRAND_ACCENT", self.brand_accent)):
            if not re.fullmatch(r"#[0-9a-fA-F]{6}", value):
                raise fw.ConfigError(f"{name} must be a colour written as #rrggbb, for example #0b0b0d")
        if self.soc_url and not re.fullmatch(r"https?://[A-Za-z0-9._~:/?=%-]+", self.soc_url):
            raise fw.ConfigError("TD_SOC_URL must be a plain http(s) address")

        if not (self.es_url and self.es_api_key):
            raise fw.ConfigError("TD_ES_HOST and TD_ES_API_KEY are not set; this part reads everything from the platform "
                                 "(create the key with platform/create-readonly-key.sh)")
        if serving:
            if len(self.web_password) < 16:
                raise fw.ConfigError("TD_NET_PASSWORD must be at least 16 characters; the pages will not start without it")
            if not (self.tls_cert and self.tls_key) and not _flag("TD_NET_ALLOW_PLAIN_HTTP", False):
                raise fw.ConfigError("TD_NET_TLS_CERT and TD_NET_TLS_KEY are not set; the pages will not be served without TLS")

    def platform(self) -> Platform:
        return Platform(self.es_url, self.es_api_key, self.es_ca_cert, self.es_assert_hostname, self.index)

    def writer(self):
        if not self.to_platform:
            return None
        return PlatformWriter(self.es_url, self.ingest_key, self.es_ca_cert, self.es_assert_hostname, self.data_stream, self.node)


def run_cycle(config: Config, platform: Platform, store: Store, writer, now=None) -> dict:
    """One pass plus delivery of open changes. Problems are returned, not raised."""
    summary = {"conversations": 0, "operations": 0, "changes": 0, "sent": 0, "warnings": [], "errors": []}
    try:
        summary.update(run_sync(platform, store, config.scope, now, config.backfill_hours, config.learn_hours,
                                max_changes=config.max_changes, lag_seconds=config.lag_seconds))
    except fw.HttpError as error:
        summary["errors"].append(f"platform: {error}")
        status = store.meta("status", {}) or {}
        status["error"] = str(error)[:400]
        store.set_meta("status", status)
        store.commit()
    try:
        result = advisories.run(store, platform, config, now)
        summary["changes"] += result["changes"]
        summary["advisories"] = result
        summary["warnings"] += result["errors"]
    except Exception as error:      # advisories must never stop the inventory
        store.db.rollback()
        log.exception("published advisories could not be processed")
        summary["errors"].append(f"published advisories: {error}")
    if writer is not None:
        try:
            summary["sent"] = writer.send(store)
        except fw.HttpError as error:
            summary["errors"].append(f"alerts to the platform: {error}")
    else:
        # Nothing to deliver to: do not let the list of unsent changes grow for ever.
        store.mark_sent([row["id"] for row in store.unsent_changes(1000)])
        store.commit()
    return summary


def check(config: Config) -> int:
    failed = 0
    try:
        platform = config.platform()
        info = platform.info()
        records = platform.count("zeek.conn")
        field = platform.choose_time_field()
        print(f"[ ok ] platform: connected (Elasticsearch {(info.get('version') or {}).get('number', '?')})")
        if records:
            print(f"[ ok ] connection records: {'10,000 or more' if records >= 10000 else format(records, ',')} from Zeek")
        else:
            failed += 1
            print("[FAIL] connection records: none. The inventory is built from Zeek's records: check Zeek on the platform "
                  "(sudo so-status) and that the monitored network card receives traffic")
        print(f"[ ok ] records are picked up by {'the time the platform stored them' if field == 'event.ingested' else 'their own time'}")
        decoded = [label for dataset, (label, _) in OT_DATASETS.items() if platform.count(dataset)]
        print(f"[ ok ] industrial protocols with decoded records: {', '.join(sorted(set(decoded))) or 'none yet'}")
    except (fw.HttpError, fw.ConfigError) as error:
        failed += 1
        print(f"[FAIL] platform: {error}")
    writer = None
    try:
        writer = config.writer()
    except fw.ConfigError as error:
        failed += 1
        print(f"[FAIL] alerts to the platform: {error}")
    if writer is None and not failed:
        print("[skip] alerts to the platform: not configured (TD_NET_INGEST_API_KEY is empty); changes are shown on the pages only")
    elif writer is not None:
        try:
            fw.http_json("GET", config.es_url + "/", {"Authorization": writer.authorization}, context=writer.context)
            print(f"[ ok ] alerts to the platform: key accepted; changes go to {config.data_stream}")
        except fw.HttpError as error:
            failed += 1
            print(f"[FAIL] alerts to the platform: {error}")
    return 1 if failed else 0


def status(config: Config) -> int:
    store = Store(config.db_path)
    try:
        last, counts = store.meta("status", {}) or {}, store.counts()
    finally:
        store.close()
    if not last.get("synced_at"):
        print("[FAIL] the platform has not been read yet" + (f": {last['error']}" if last.get("error") else ""))
        return 1
    if last.get("error"):
        print(f"[FAIL] the last read failed: {last['error']} (last good read {last['synced_at']})")
        return 1
    print(f"[ ok ] last read {last['synced_at']}: {counts['assets']:,} devices, {counts['conversations']:,} conversations, "
          f"{counts['open_changes']:,} open changes")
    for warning in last.get("warnings") or []:
        print(f"[note] {warning}")
    return 0


def advisory_status(config: Config) -> int:
    """One line per advisory source, for scripts/verify.sh network. 1 when a source failed."""
    if not config.adv_enabled:
        print("[skip] published advisories: turned off (TD_ADV_ENABLED=0)")
        return 0
    store = Store(config.db_path)
    try:
        advisories.prepare(store)
        feeds, counts = store.meta("advisory_feeds", {}) or {}, advisories.overview(store)
    finally:
        store.close()
    failed = 0
    if not config.adv_feeds:
        print("[note] published advisories: no feeds from the internet (TD_ADV_FEEDS=off); files in the import folder are read")
    for feed in config.adv_feeds:
        entry = feeds.get(feed.name) or {}
        if not entry.get("checked"):
            print(f"[note] advisories from {feed.name}: not fetched yet")
        elif entry.get("error"):
            failed += 1
            print(f"[FAIL] advisories from {feed.name}: {entry['error']}")
        else:
            print(f"[ ok ] advisories from {feed.name}: last checked {entry['checked']}"
                  + (f", {entry['waiting']:,} documents still to fetch" if entry.get("waiting") else ""))
    for name, mark in sorted(((feeds.get("(files)") or {}).get("files") or {}).items()):
        if str(mark).startswith("error:"):
            failed += 1
            print(f"[FAIL] advisory file {name}: {str(mark).split(':', 3)[-1]}")
    print(f"[ ok ] {counts['advisories']:,} advisories known; {counts['matching']:,} concern {counts['targets']:,} devices or listed products")
    return 1 if failed else 0


def fetch_advisories(config: Config) -> int:
    if not config.adv_enabled:
        print("Published advisories are turned off (TD_ADV_ENABLED=0).")
        return 0
    store = Store(config.db_path, timeout=600)
    try:
        try:
            platform = config.platform()
        except fw.ConfigError:
            platform = None
        result = advisories.run(store, platform, config, force=True)
        counts = advisories.overview(store)
    finally:
        store.close()
    for problem in result["errors"]:
        print(f"[FAIL] {problem}")
    print(f"[{'ok' if not result['errors'] else 'note'}] {counts['advisories']:,} advisories known ({result['new']:,} new or changed, "
          f"{result['documents']:,} documents fetched, {result['waiting']:,} still to fetch); "
          f"{counts['matching']:,} concern this site; {result['changes']:,} new changes")
    return 1 if result["errors"] and not counts["advisories"] else 0


def serve(config: Config) -> threading.Thread:
    server = make_server(config, lambda: Store(config.db_path), config.scope)
    if config.tls_cert and config.tls_key:
        for path in (config.tls_cert, config.tls_key):
            if not Path(path).is_file():
                raise fw.ConfigError(f"TLS file not found: {path}")
        try:
            use_tls(server, config.tls_cert, config.tls_key)
        except (OSError, ValueError) as error:
            raise fw.ConfigError(f"the TLS certificate or key could not be used: {error}") from None
        scheme = "https"
    else:
        scheme = "http"
        log.warning("serving the pages without TLS (TD_NET_ALLOW_PLAIN_HTTP is on)")
    thread = threading.Thread(target=server.serve_forever, daemon=True, name="pages")
    thread.start()
    log.info("pages listening on %s://%s:%d", scheme, config.web_bind, config.web_port)
    return thread


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="TechDetechtives network inventory")
    parser.add_argument("--once", action="store_true", help="run one pass and exit")
    parser.add_argument("--check", action="store_true", help="test every connection and exit")
    parser.add_argument("--accept", action="store_true", help="take everything seen so far as the baseline and exit")
    parser.add_argument("--status", action="store_true", help="say when the platform was last read, and exit")
    parser.add_argument("--advisories", action="store_true", help="fetch published advisories now, match them, and exit")
    parser.add_argument("--advisory-status", action="store_true", help="say when each advisory source was last read, and exit")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)

    try:
        config = Config(serving=not (args.once or args.check or args.accept or args.status or args.advisories or args.advisory_status))
        if args.advisories:
            return fetch_advisories(config)
        if args.check:
            return check(config)
        if args.status:
            return status(config)
        if args.advisory_status:
            return advisory_status(config)
        if args.accept:
            # A pass that is writing at this moment is waited for.
            store = Store(config.db_path, timeout=600)
            try:
                settled = store.accept_all(datetime.now(timezone.utc))
            except sqlite3.OperationalError as error:
                print(f"The baseline was not changed: the inventory is busy ({error}). Try again in a few minutes.")
                return 1
            finally:
                store.close()
            print(f"Baseline set to everything seen so far; {settled} open changes accepted.")
            return 0
        store = Store(config.db_path)
        platform, writer = config.platform(), config.writer()
        if not args.once:
            serve(config)
    except fw.ConfigError as error:
        log.error("%s", error)
        return 2

    log.info("TechDetechtives network inventory %s: reading every %ds, alerts to the platform %s, published advisories %s",
             VERSION, config.sync_seconds, "on" if writer else "off",
             f"from {len(config.adv_feeds)} feeds every {config.adv_fetch_hours}h" if config.adv_enabled else "off")
    while True:
        try:
            summary = run_cycle(config, platform, store, writer)
        except fw.HttpError as error:
            summary = {"errors": [f"platform: {error}"], "warnings": [], "conversations": 0, "operations": 0, "changes": 0, "sent": 0}
        except fw.ConfigError as error:
            log.error("%s", error)
            return 2
        for problem in summary["errors"]:
            log.error("%s", problem)
        for warning in summary["warnings"]:
            log.warning("%s", warning)
        if summary["conversations"] or summary["changes"] or summary["sent"]:
            log.info("pass done: %d conversation groups, %d operation groups, %d changes, %d alerts sent to the platform",
                     summary["conversations"], summary["operations"], summary["changes"], summary["sent"])
        if args.once:
            store.close()
            return 1 if summary["errors"] else 0
        time.sleep(config.sync_seconds)


if __name__ == "__main__":
    sys.exit(main())
