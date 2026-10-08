# TechDetechtives network inventory: reading from the platform.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Read-only queries against the platform's Elasticsearch.

Everything is asked for as grouped totals (composite aggregations), so the
amount of data that travels depends on how many different conversations there
are, not on how many packets or records.
"""

from __future__ import annotations

import ipaddress
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Iterator, Optional

import td_forwarder as fw  # shared HTTP, TLS and settings helpers

from .protocols import OT_DATASETS

PAGE = 1000


def terms(field: str, missing: bool = False) -> dict:
    return {"terms": {"field": field, **({"missing_bucket": True} if missing else {})}}


def is_address(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


class Platform:
    def __init__(self, url: str, api_key: str, ca_cert: str, assert_hostname: bool, index: str = "logs-*",
                 max_pages: int = 200) -> None:
        self.url = url.rstrip("/")
        self.headers = {"Authorization": f"ApiKey {api_key}"}
        self.context = fw._ssl_context(self.url, ca_cert, assert_hostname)
        self.index = index
        self.max_pages = max_pages
        # Records are picked up by the time the platform stored them when it
        # keeps that time, so a connection that lasted a day (and was written
        # when it ended) is not missed. See choose_time_field().
        self.time_field = "@timestamp"
        self.truncated: list[str] = []      # queries that hit a limit in the window being read

    # --- plumbing ----------------------------------------------------------------
    def info(self) -> dict:
        return fw.http_json("GET", self.url + "/", self.headers, context=self.context)

    def _search(self, body: dict) -> dict:
        index = urllib.parse.quote(self.index, safe="*,-_.")
        target = f"{self.url}/{index}/_search?ignore_unavailable=true&allow_no_indices=true"
        result = fw.http_json("POST", target, self.headers, body, context=self.context, timeout=120)
        # An answer built from only some of the data must not be taken for the whole.
        if result.get("timed_out") or int((result.get("_shards") or {}).get("failed") or 0) > 0:
            raise fw.HttpError("the platform answered with only part of the data (a search timed out or a shard failed)", True)
        return result

    def choose_time_field(self) -> str:
        body = {"size": 1, "_source": False, "query": {"bool": {"filter": [
            {"term": {"event.dataset": "zeek.conn"}}, {"exists": {"field": "event.ingested"}}]}}}
        hits = (self._search(body).get("hits") or {}).get("hits") or []
        self.time_field = "event.ingested" if hits else "@timestamp"
        return self.time_field

    def count(self, dataset: str) -> int:
        """How many records of one kind exist at all (used by the connection check)."""
        body = {"size": 0, "track_total_hits": 10000, "query": {"term": {"event.dataset": dataset}}}
        total = (self._search(body).get("hits") or {}).get("total") or {}
        return int(total.get("value") or 0) if isinstance(total, dict) else int(total or 0)

    def first_record(self, since: datetime, until: datetime) -> Optional[datetime]:
        """When the earliest sensor record in a window was stored, or None when there is none.
        Lets a pass step over stretches without records instead of asking about each hour."""
        body = {"size": 1, "_source": [self.time_field], "sort": [{self.time_field: {"order": "asc", "unmapped_type": "date"}}],
                "query": {"bool": {"filter": [{"prefix": {"event.dataset": "zeek."}}, self._window(since, until)]}}}
        hits = (self._search(body).get("hits") or {}).get("hits") or []
        return fw.parse_time(fw.lookup(hits[0].get("_source") or {}, self.time_field)) if hits else None

    def count_window(self, since: datetime, until: datetime) -> int:
        """How many connection records the platform now holds for a window that was read earlier."""
        body = {"size": 0, "track_total_hits": True, "query": {"bool": {"filter": [
            {"term": {"event.dataset": "zeek.conn"}}, {"exists": {"field": "source.ip"}},
            {"exists": {"field": "destination.ip"}}, self._window(since, until)]}}}
        total = (self._search(body).get("hits") or {}).get("total") or {}
        return int(total.get("value") or 0) if isinstance(total, dict) else int(total or 0)

    def _window(self, since: datetime, until: datetime) -> dict:
        return {"range": {self.time_field: {"gt": fw.iso(since), "lte": fw.iso(until)}}}

    def _groups(self, name: str, filters: list[dict], sources: list[tuple[str, dict]],
                metrics: Optional[dict] = None) -> Iterator[dict]:
        """Yield one dict per group: the grouping keys plus 'count' and any metrics.

        sources: (key name, composite source). Stops at max_pages and notes it.
        """
        composite: dict[str, Any] = {"size": PAGE, "sources": [{key: spec} for key, spec in sources]}
        after = None
        for _ in range(self.max_pages):
            if after:
                composite["after"] = after
            aggregation: dict[str, Any] = {"composite": composite}
            if metrics:
                aggregation["aggs"] = metrics
            body = {"size": 0, "track_total_hits": False, "query": {"bool": {"filter": filters}},
                    "aggs": {"groups": aggregation}}
            result = (self._search(body).get("aggregations") or {}).get("groups") or {}
            buckets = result.get("buckets") or []
            for bucket in buckets:
                row = dict(bucket.get("key") or {})
                row["count"] = int(bucket.get("doc_count") or 0)
                for metric in metrics or {}:
                    value = (bucket.get(metric) or {})
                    row[metric] = value.get("value_as_string") if "value_as_string" in value else value.get("value")
                yield row
            after = result.get("after_key")
            if not after or len(buckets) < PAGE:
                return
        self.truncated.append(name)

    # --- what the inventory is built from -----------------------------------------
    def conversations(self, since: datetime, until: datetime) -> Iterator[dict]:
        """Who talked to whom, on which port, how much, in which hour.

        One row per (hour, source, destination, port, transport, service). 'hour'
        is when the connection started, as an ISO time.
        """
        filters = [{"term": {"event.dataset": "zeek.conn"}}, self._window(since, until)]
        sources = [("hour", {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h"}}),
                   ("src", terms("source.ip")), ("dst", terms("destination.ip")), ("port", terms("destination.port", True)),
                   ("transport", terms("network.transport", True)), ("service", terms("network.protocol", True))]
        metrics = {"client_bytes": {"sum": {"field": "client.ip_bytes"}}, "server_bytes": {"sum": {"field": "server.ip_bytes"}},
                   "last": {"max": {"field": "@timestamp"}}}
        for row in self._groups("conversations", filters, sources, metrics):
            if isinstance(row.get("hour"), (int, float)):
                row["hour"] = datetime.fromtimestamp(row["hour"] / 1000, timezone.utc).strftime("%Y-%m-%dT%H:00:00Z")
            yield row

    def card_makers(self, since: datetime, until: datetime) -> Iterator[dict]:
        """The maker of each sender's network card, where the sensor shares its segment."""
        filters = [{"term": {"event.dataset": "zeek.conn"}}, {"exists": {"field": "client.oui"}}, self._window(since, until)]
        return self._groups("card makers", filters, [("ip", terms("source.ip")), ("maker", terms("client.oui"))],
                            {"last": {"max": {"field": "@timestamp"}}})

    def operations(self, dataset: str, since: datetime, until: datetime) -> Iterator[dict]:
        """Decoded industrial operations of one kind: who asked which device to do what."""
        label, field = OT_DATASETS[dataset]
        filters = [{"term": {"event.dataset": dataset}}, self._window(since, until)]
        sources = [("src", terms("source.ip")), ("dst", terms("destination.ip")), ("port", terms("destination.port", True)),
                   ("transport", terms("network.transport", True))]
        if field:
            sources.append(("operation", terms(field, True)))
        for row in self._groups(f"{label} operations", filters, sources, {"last": {"max": {"field": "@timestamp"}}}):
            row["label"], row["named"] = label, bool(field)
            yield row

    def _latest(self, dataset: str, fields: list[str], since: datetime, until: datetime, size: int = 2000) -> list[dict]:
        body = {"size": size, "_source": fields + ["@timestamp"], "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
                "query": {"bool": {"filter": [{"term": {"event.dataset": dataset}}, self._window(since, until)]}}}
        hits = (self._search(body).get("hits") or {}).get("hits") or []
        if len(hits) >= size:
            self.truncated.append(f"{dataset} records")
        return [hit.get("_source") or {} for hit in hits]

    def identities(self, since: datetime, until: datetime) -> list[dict]:
        """What devices say about themselves, newest first: {ip, via, vendor, model, version, serial, kind, software}."""
        found: list[dict] = []
        for doc in self._latest("zeek.cip_identity", ["source.ip", "destination.ip", "cip"], since, until):
            address = fw.field(doc, "cip.socket.address")
            ip = address if is_address(address) and address != "0.0.0.0" else fw.field(doc, "destination.ip")
            found.append({"ip": ip, "via": "EtherNet/IP identity", "vendor": fw.field(doc, "cip.vendor.name"),
                          "model": fw.field(doc, "cip.device.product.name"), "version": fw.field(doc, "cip.device.revision"),
                          "serial": fw.field(doc, "cip.device.serial_number"), "kind": fw.field(doc, "cip.device.type.name")})
        for doc in self._latest("zeek.bacnet_discovery", ["source.ip", "destination.ip", "bacnet"], since, until):
            if str(fw.field(doc, "bacnet.pdu.service") or "").lower().replace("-", "_") != "i_am":
                continue
            ip = fw.field(doc, "source.ip") if fw.field(doc, "bacnet.is_orig") in (True, "true", "T") else fw.field(doc, "destination.ip")
            found.append({"ip": ip, "via": "BACnet I-Am", "vendor": fw.field(doc, "bacnet.vendor"),
                          "model": fw.field(doc, "bacnet.object.name"), "kind": fw.field(doc, "bacnet.object.type")})
        for doc in self._latest("zeek.software", ["source.ip", "software"], since, until):
            name, version = fw.field(doc, "software.name"), fw.field(doc, "software.version.unparsed")
            found.append({"ip": fw.field(doc, "source.ip"), "via": "software banner",
                          "software": " ".join(str(part) for part in (name, version) if part)})
        return [{key: _text(value) for key, value in item.items()} for item in found if is_address(item.get("ip"))]

    def names(self, since: datetime, until: datetime) -> list[dict]:
        """Host names and card addresses seen in DHCP and Windows sign-in traffic, newest first."""
        found = []
        for doc in self._latest("zeek.dhcp", ["host", "dhcp", "client"], since, until):
            ip = fw.field(doc, "dhcp.assigned_ip") or fw.field(doc, "client.address")
            found.append({"ip": ip, "name": fw.field(doc, "host.hostname"), "mac": fw.field(doc, "host.mac")})
        for doc in self._latest("zeek.ntlm", ["source.ip", "host"], since, until):
            found.append({"ip": fw.field(doc, "source.ip"), "name": fw.field(doc, "host.name")})
        return [{key: _text(value) for key, value in item.items()} for item in found
                if is_address(item.get("ip")) and (item.get("name") or item.get("mac"))]

    # --- what the other TechDetechtives parts know about each address -----------------
    def alerts(self, since: datetime, until: datetime) -> Iterator[dict]:
        filters = [{"term": {"tags": "alert"}}, {"range": {"@timestamp": {"gt": fw.iso(since), "lte": fw.iso(until)}}}]
        sources = [("src", terms("source.ip", True)), ("dst", terms("destination.ip", True))]
        return self._groups("alerts", filters, sources, {"worst": {"max": {"field": "event.severity"}}})

    def findings(self, since: datetime, until: datetime) -> Iterator[dict]:
        filters = [{"term": {"event.dataset": "greenbone.result"}}, {"range": {"@timestamp": {"gt": fw.iso(since), "lte": fw.iso(until)}}}]
        return self._groups("vulnerability findings", filters, [("ip", terms("host.ip"))],
                            {"worst": {"max": {"field": "event.severity"}}})

    def finding_cves(self, since: datetime, until: datetime) -> Iterator[dict]:
        """Which CVEs vulnerability scans found on which address: {ip, cve}. Used to match published advisories."""
        filters = [{"term": {"event.dataset": "greenbone.result"}}, {"exists": {"field": "vulnerability.id"}},
                   {"range": {"@timestamp": {"gt": fw.iso(since), "lte": fw.iso(until)}}}]
        return self._groups("vulnerability findings by CVE", filters, [("ip", terms("host.ip")), ("cve", terms("vulnerability.id"))])

    def honeypot_contacts(self, since: datetime, until: datetime) -> Iterator[dict]:
        filters = [{"term": {"event.module": "opencanary"}}, {"range": {"@timestamp": {"gt": fw.iso(since), "lte": fw.iso(until)}}}]
        return self._groups("honeypot contacts", filters, [("ip", terms("source.ip"))])


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        value = ", ".join(str(item) for item in value)
    return str(value)[:200]
