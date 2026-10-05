# TechDetechtives network inventory: sending changes to the platform as alerts.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Each change since the baseline becomes one alert in the platform, where the
ticket forwarder picks it up like any other. Uses a key that can only append."""

from __future__ import annotations

import hashlib
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Optional

import td_forwarder as fw

from .store import Store, parse
from .sync import PSEUDO

SEVERITY_LABELS = {1: "low", 2: "medium", 3: "high"}


LATE_AFTER = timedelta(minutes=5)


def to_document(change, node: str, now: Optional[datetime] = None) -> tuple[str, dict]:
    severity = int(change["severity"])
    now = now or datetime.now(timezone.utc)
    noticed = parse(change["at"]) or now
    # The ticket forwarder only looks a few minutes back, so an alert that could
    # not be delivered at the time is stamped with the delivery time instead.
    late = now - noticed > LATE_AFTER
    document = {
        "@timestamp": fw.iso(now if late else noticed),
        "message": change["detail"] + (f" (noticed at {change['at']}, delivered late)" if late else ""),
        "tags": ["alert", "techdetechtives", "network-baseline"],
        "event": {"kind": "alert", "category": ["network"], "type": ["change"], "module": "netmap",
                  "dataset": "netmap.alerts", "action": change["kind"], "created": fw.iso(noticed), "severity": severity,
                  "severity_label": SEVERITY_LABELS.get(severity, "low")},
        "rule": {"name": f"Network baseline: {change['title']}", "category": "network baseline", "uuid": f"netmap-{change['kind']}"},
        "observer": {"vendor": "TechDetechtives", "product": "Network inventory", "type": "inventory", "name": node},
    }
    related = []
    for key, value in (("source", change["ip"]), ("destination", change["peer"])):
        if value and value not in PSEUDO:
            document[key] = {"ip": value}
            related.append(value)
    if related:
        document["related"] = {"ip": related}
    doc_id = hashlib.sha256(f"{node}|{change['id']}|{change['at']}|{change['kind']}|{change['ip']}|{change['peer']}"
                            .encode("utf-8")).hexdigest()[:40]
    return doc_id, document


class PlatformWriter:
    def __init__(self, url: str, api_key: str, ca_cert: str, assert_hostname: bool, data_stream: str, node: str) -> None:
        self.url, self.data_stream, self.node = url.rstrip("/"), data_stream, node
        self.authorization = f"ApiKey {api_key}"
        self.context = fw._ssl_context(self.url, ca_cert, assert_hostname)

    def send(self, store: Store, batch: int = 200) -> int:
        """Deliver changes not sent yet. Returns how many the platform took."""
        rows = store.unsent_changes(batch)
        if not rows:
            return 0
        body = ""
        for row in rows:
            doc_id, document = to_document(row, self.node)
            body += json.dumps({"create": {"_id": doc_id}}) + "\n" + json.dumps(document) + "\n"
        target = f"{self.url}/{urllib.parse.quote(self.data_stream, safe='-_.')}/_bulk"
        request = urllib.request.Request(target, data=body.encode("utf-8"), method="POST")
        request.add_header("Content-Type", "application/x-ndjson")
        request.add_header("Authorization", self.authorization)
        try:
            with urllib.request.urlopen(request, timeout=120, context=self.context) as response:
                result = json.loads(response.read().decode("utf-8", "replace") or "{}")
        except urllib.error.HTTPError as error:
            raise fw.HttpError(f"the platform returned HTTP {error.code}: {error.read().decode('utf-8', 'replace')[:300]}",
                               error.code >= 500 or error.code in (408, 429)) from None
        except (urllib.error.URLError, TimeoutError, ConnectionError, ssl.SSLError, OSError, ValueError) as error:
            raise fw.HttpError(f"could not reach the platform: {error}", True) from None
        items = result.get("items") or []
        if len(items) != len(rows):
            raise fw.HttpError(f"the platform answered for {len(items)} of {len(rows)} alerts", True)
        done = []
        for row, item in zip(rows, items):
            status = int((item.get("create") or {}).get("status") or 0)
            if status in (200, 201, 409):          # 409: delivered by an earlier attempt
                done.append(row["id"])
            elif status in (401, 403, 404, 429) or status >= 500:
                reason = ((item.get("create") or {}).get("error") or {}).get("reason", "unknown error")
                store.mark_sent(done)
                store.commit()
                raise fw.HttpError(f"the platform refused the alerts (HTTP {status}): {reason}", True)
            else:
                done.append(row["id"])              # the platform cannot store this one; do not retry it for ever
        store.mark_sent(done)
        store.commit()
        return len(done)
