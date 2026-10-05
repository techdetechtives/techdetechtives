# TechDetechtives network inventory tests: a stand-in for the platform.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""A small HTTP server that answers the Elasticsearch requests the network
inventory makes, from records held in memory. It implements only what the
inventory uses: filters (term, exists, range), composite aggregations with
terms and hourly sources, sum and max, plain newest-first searches, and bulk
create. It is a test double, not an Elasticsearch emulator."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def lookup(document: dict, dotted: str):
    current = document
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def millis(value: str) -> float:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp() * 1000


def matches(document: dict, clause: dict) -> bool:
    if "term" in clause:
        (field, wanted), = clause["term"].items()
        actual = lookup(document, field)
        return wanted in actual if isinstance(actual, list) else actual == wanted
    if "prefix" in clause:
        (field, wanted), = clause["prefix"].items()
        return str(lookup(document, field) or "").startswith(wanted)
    if "exists" in clause:
        return lookup(document, clause["exists"]["field"]) not in (None, "", [])
    if "range" in clause:
        (field, bounds), = clause["range"].items()
        actual = lookup(document, field)
        if actual is None:
            return False
        moment = millis(actual)
        return all(test(moment, millis(bounds[name])) for name, test in (
            ("gt", lambda a, b: a > b), ("gte", lambda a, b: a >= b), ("lt", lambda a, b: a < b), ("lte", lambda a, b: a <= b))
            if name in bounds)
    if "bool" in clause:
        return all(matches(document, part) for part in clause["bool"].get("filter", []))
    raise ValueError(f"query clause not handled by the stand-in: {clause}")


class FakePlatform:
    def __init__(self) -> None:
        self.documents: list[dict] = []
        self.created: dict[str, dict] = {}        # bulk-created documents by id
        self.searches = 0
        self.fail_with = 0                         # answer every request with this HTTP status
        self.failed_shards = 0                     # searches answer 200, built from part of the data
        self.bad_fields: set[str] = set()          # composite on these fields answers 400
        self.api_keys = {"read-key", "write-key"}
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def add(self, dataset: str, when: str, ingested: str = "", **fields) -> None:
        """fields use dotted names: add('zeek.conn', '2026-..', **{'source.ip': '10.0.0.1'})"""
        document: dict = {"@timestamp": when, "event": {"dataset": dataset, "ingested": ingested or when}}
        if not ingested and fields.pop("no_ingested", False):
            del document["event"]["ingested"]
        for dotted, value in fields.items():
            current = document
            parts = dotted.split(".")
            for part in parts[:-1]:
                current = current.setdefault(part, {})
            current[parts[-1]] = value
        self.documents.append(document)

    # ---- request handling ------------------------------------------------------
    def search(self, body: dict) -> dict:
        self.searches += 1
        query = body.get("query") or {"bool": {"filter": []}}
        found = [document for document in self.documents if matches(document, query)]
        result: dict = {"timed_out": False, "_shards": {"total": 3, "successful": 3 - self.failed_shards, "failed": self.failed_shards},
                        "hits": {"total": {"value": len(found)}, "hits": []}}
        if body.get("size"):
            (field, how), = (body.get("sort") or [{"@timestamp": {"order": "desc"}}])[0].items()
            dated = [document for document in found if lookup(document, field) is not None]
            ordered = sorted(dated, key=lambda document: millis(lookup(document, field)), reverse=how["order"] == "desc")[:body["size"]]
            result["hits"]["hits"] = [{"_id": str(index), "_source": document} for index, document in enumerate(ordered)]
        groups = (body.get("aggs") or {}).get("groups")
        if groups:
            result["aggregations"] = {"groups": self.composite(found, groups)}
        return result

    def composite(self, found: list[dict], groups: dict) -> dict:
        spec = groups["composite"]
        sources = [next(iter(source.items())) for source in spec["sources"]]
        buckets: dict[tuple, list[dict]] = {}
        for document in found:
            keys: list[list] = [[]]
            for name, source in sources:
                if "date_histogram" in source:
                    value = lookup(document, source["date_histogram"]["field"])
                    value = None if value is None else int(millis(value) // 3_600_000 * 3_600_000)
                    allow_missing = False
                else:
                    field = source["terms"]["field"]
                    if field in self.bad_fields:
                        raise ValueError(f"field [{field}] cannot be grouped on")
                    value = lookup(document, field)
                    allow_missing = source["terms"].get("missing_bucket", False)
                if value is None and not allow_missing:
                    keys = []
                    break
                # A field holding several values puts the record in one group per value.
                keys = [key + [item] for key in keys for item in (value if isinstance(value, list) else [value])]
            for key in keys:
                buckets.setdefault(tuple(key), []).append(document)
        order = lambda key: tuple((value is not None, str(type(value)), value if value is not None else 0) for value in key)  # noqa: E731
        keys = sorted(buckets, key=order)
        if spec.get("after"):
            after = tuple(spec["after"][name] for name, _ in sources)
            keys = [key for key in keys if order(key) > order(after)]
        page = keys[:spec["size"]]
        out = []
        for key in page:
            bucket: dict = {"key": {name: value for (name, _), value in zip(sources, key)}, "doc_count": len(buckets[key])}
            for metric, definition in (groups.get("aggs") or {}).items():
                (kind, options), = definition.items()
                values = [lookup(document, options["field"]) for document in buckets[key]]
                values = [value for value in values if value is not None]
                if kind == "sum":
                    bucket[metric] = {"value": float(sum(values))}
                elif kind == "max" and values and isinstance(values[0], str):
                    bucket[metric] = {"value": millis(max(values)), "value_as_string": max(values)}
                else:
                    bucket[metric] = {"value": max(values) if values else None}
            out.append(bucket)
        answer: dict = {"buckets": out}
        if page:
            answer["after_key"] = out[-1]["key"]
        return answer

    def bulk(self, text: str, key: str) -> dict:
        lines = [json.loads(line) for line in text.splitlines() if line.strip()]
        items = []
        for action, document in zip(lines[0::2], lines[1::2]):
            doc_id = action["create"]["_id"]
            if key != "write-key":
                items.append({"create": {"status": 403, "error": {"reason": "this key cannot write here"}}})
            elif doc_id in self.created:
                items.append({"create": {"status": 409}})
            else:
                self.created[doc_id] = document
                items.append({"create": {"status": 201}})
        return {"items": items}

    def _handler(self):
        platform = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args) -> None:
                pass

            def answer(self, code: int, body: dict) -> None:
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def handle_any(self) -> None:
                key = self.headers.get("Authorization", "").replace("ApiKey ", "")
                text = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
                if platform.fail_with:
                    return self.answer(platform.fail_with, {"error": "stand-in failure"})
                if key not in platform.api_keys:
                    return self.answer(401, {"error": "unknown key"})
                path = self.path.split("?")[0]
                try:
                    if path == "/":
                        return self.answer(200, {"version": {"number": "9.0.8"}})
                    if path.endswith("/_bulk"):
                        return self.answer(200, platform.bulk(text, key))
                    if path.endswith("/_search"):
                        if key != "read-key":
                            return self.answer(403, {"error": "this key cannot read"})
                        return self.answer(200, platform.search(json.loads(text or "{}")))
                except ValueError as error:
                    return self.answer(400, {"error": str(error)})
                return self.answer(404, {"error": "not found"})

            do_GET = do_POST = handle_any

        return Handler
