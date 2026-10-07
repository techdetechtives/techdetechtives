# TechDetechtives OT IDS tests. Copyright (c) 2026 TechDetechtives. MIT licence.
"""Tests for ot-ids/baseline/td_replay.py. Run with:  python3 -m unittest discover -s ot-ids/tests -v

The program is run against a stand-in for OpenSearch that holds records shaped
like the product's and answers the five searches the program makes: the two the
baseline and the traffic profile already make (answered by their own stand-ins,
over the same records), and three of its own (the list of uploaded captures,
the count of records by kind, the detections). A search it does not recognise
is refused.

This shows the program's own logic and wording. It does not show that the real
OpenSearch accepts the searches, that an uploaded capture's records really carry
the node name and tags read from the product's source, or what the product's
engines make of a real capture.

The records are shaped as the product's pipelines write them, as far as that was
read in Malcolm 26.09.0 (an independent reviewer corrected three shapes the first
version had wrong): a file-scan hit has two kinds at once, a list of rule names,
the capture's tags and no "-upload" node (logstash/pipelines/filescan); an
indicator match has no rule name (zeek/1300_zeek_normalize.conf); a rule alert
carries the parent technique only (suricata/11_suricata_logs.conf); an alert from
a monitor or the baseline has no node at all (api/project/__init__.py).
"""
import contextlib
import io
import itertools
import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

KIT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KIT / "baseline"))
sys.path.insert(0, str(KIT / "tests"))

import td_replay                    # noqa: E402
import test_baseline                # noqa: E402
import test_profile                 # noqa: E402

HOUR = 3600
T0 = test_profile.T0                                   # 2026-09-21 14:00 UTC
THEN = T0 - 21 * 24 * HOUR                              # when the incident took place
INDEX, TIME_FIELD = "arkime_sessions3-*", "firstPacket"
HMI, ENG, PLC1, PLC2, INTRUDER = "10.0.0.5", "10.0.0.6", "10.0.1.10", "10.0.1.11", "10.66.6.6"
UPLOADED = {"wildcard": {"node": {"value": "*-upload"}}}


def values(doc, field):
    value = doc.get(field)
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


class Stored:
    """Every record in one list, and the answers to the program's searches."""

    def __init__(self):
        self.docs, self.searches = [], []
        self.ot = test_baseline.Platform()            # answers the baseline's search
        self.conn = test_profile.Records()            # answers the traffic profile's search, and the 'when' search
        self.ot.docs = self.conn.docs = self.docs
        self.partial = False

    # --- records, as the product stores them ---------------------------------
    def add(self, when, **fields):
        doc = {TIME_FIELD: int(when * 1000), "lastPacket": int(when * 1000)}
        doc.update(fields)
        self.docs.append(doc)
        return doc

    def operation(self, when, src, dst, action, protocol="modbus", **more):
        self.add(when, **{"source.ip": src, "destination.ip": dst, "network.protocol": protocol, "event.action": action,
                          "event.category": ["ot", "network"], "event.dataset": protocol, "event.provider": "zeek",
                          "event.kind": "event", "network.is_orig": "T"}, **more)

    def alert(self, when, rule, src, dst, severity=71, tactic=None, technique=None, technique_name=None, **more):
        fields = {"event.dataset": "alert", "event.provider": "suricata", "event.kind": "alert", "rule.name": rule,
                  "source.ip": src, "destination.ip": dst, "event.severity": severity}
        if tactic:
            fields.update({"threat.tactic.name": tactic, "threat.technique.id": technique, "threat.technique.name": technique_name})
        fields.update(more)
        self.add(when, **fields)

    def connection(self, when, src, dst, port, service, sent, received, seconds=1, **more):
        self.add(when, **{"lastPacket": int((when + seconds) * 1000), "source.ip": src, "destination.ip": dst, "destination.port": port,
                          "network.transport": "tcp", "network.protocol": service, "source.bytes": sent, "destination.bytes": received,
                          "server.bytes": max(received - 40, 0), "length": int(seconds * 1000), "event.dataset": "conn",
                          "event.provider": "zeek", "event.kind": "event"}, **more)

    # --- the three searches that are this program's own ---------------------
    @staticmethod
    def scope(extra, exclusions):
        tags, only = [], False
        for clause in extra:
            if clause == UPLOADED:
                only = True
            elif list(clause) == ["term"] and list(clause["term"]) == ["tags"]:
                tags.append(clause["term"]["tags"])
            else:
                raise ValueError("unexpected scope filter")
        if exclusions not in ([], [UPLOADED]):
            raise ValueError("unexpected exclusions")

        def inside(doc):
            uploaded = any(str(node).endswith("-upload") for node in values(doc, "node"))
            return not (exclusions and uploaded) and not (only and not uploaded) and set(tags) <= set(values(doc, "tags"))
        return inside

    @staticmethod
    def period(clause):
        limits = clause["range"][TIME_FIELD]
        if sorted(limits) != ["format", "gte", "lt"] or limits["format"] != "epoch_millis":
            raise ValueError("unexpected range")
        return lambda doc: limits["gte"] <= doc[TIME_FIELD] < limits["lt"]

    def captures(self, body):
        if body["query"] != {"bool": {"filter": [UPLOADED]}} or body["aggs"] != {"tags": {
                "terms": {"field": "tags", "size": 300, "order": {"last": "desc"}},
                "aggs": {"first": {"min": {"field": TIME_FIELD}}, "last": {"max": {"field": TIME_FIELD}},
                         "kinds": {"terms": {"field": "event.dataset", "size": 3}}}}}:
            raise ValueError("unexpected list search")
        inside, groups = self.scope([UPLOADED], []), {}
        for doc in self.docs:
            if inside(doc):
                for tag in values(doc, "tags"):
                    groups.setdefault(tag, []).append(doc)
        ordered = sorted(groups.items(), key=lambda pair: (-max(doc[TIME_FIELD] for doc in pair[1]), pair[0]))

        def kinds(docs):
            counts = {}
            for doc in docs:
                for name in values(doc, "event.dataset"):
                    counts[name] = counts.get(name, 0) + 1
            return {"buckets": [{"key": name, "doc_count": count} for name, count in sorted(counts.items(), key=lambda p: (-p[1], p[0]))[:3]]}

        return {"tags": {"buckets": [{"key": tag, "doc_count": len(docs), "first": {"value": float(min(doc[TIME_FIELD] for doc in docs))},
                                      "last": {"value": float(max(doc[TIME_FIELD] for doc in docs))}, "kinds": kinds(docs)}
                                     for tag, docs in ordered]}}

    def kinds(self, body):
        boolean = body["query"]["bool"]
        if sorted(boolean) != ["filter", "must_not"] or body["aggs"] != {
                "datasets": {"terms": {"field": "event.dataset", "size": 100}}, "total": {"value_count": {"field": TIME_FIELD}}}:
            raise ValueError("unexpected overview search")
        when, inside, counts, total = self.period(boolean["filter"][0]), self.scope(boolean["filter"][1:], boolean["must_not"]), {}, 0
        for doc in self.docs:
            if when(doc) and inside(doc):
                total += 1
                for name in values(doc, "event.dataset"):
                    counts[name] = counts.get(name, 0) + 1
        return {"datasets": {"buckets": [{"key": name, "doc_count": count} for name, count in sorted(counts.items(), key=lambda p: -p[1])]},
                "total": {"value": total}}

    def detections(self, body):
        boolean = body["query"]["bool"]
        if sorted(boolean) != ["filter", "must_not"]:
            raise ValueError("unexpected detection search")
        if boolean["filter"][1] != {"bool": {"should": [{"term": {"event.kind": "alert"}}, {"term": {"event.dataset": "intel"}}],
                                             "minimum_should_match": 1}}:
            raise ValueError("unexpected kinds of record")
        if boolean["must_not"][0] != {"term": {"event.dataset": "weird"}}:
            raise ValueError("weird records are not to be listed")
        when, inside = self.period(boolean["filter"][0]), self.scope(boolean["filter"][2:], boolean["must_not"][1:])
        composite, subs = body["aggs"]["keys"]["composite"], body["aggs"]["keys"]["aggs"]
        wanted = [("dataset", {"field": "event.dataset"}), ("provider", {"field": "event.provider", "missing_bucket": True}),
                  ("rule", {"field": "rule.name", "missing_bucket": True}), ("src", {"field": "source.ip", "missing_bucket": True}),
                  ("dst", {"field": "destination.ip", "missing_bucket": True})]
        if composite["sources"] != [{name: {"terms": options}} for name, options in wanted] or not set(composite) <= {"size", "sources", "after"}:
            raise ValueError("unexpected composite sources")
        if subs != {"first": {"min": {"field": TIME_FIELD}}, "last": {"max": {"field": TIME_FIELD}},
                    "severity": {"max": {"field": "event.severity"}},
                    "technique": {"terms": {"field": "threat.technique.id", "size": 3}},
                    "technique_name": {"terms": {"field": "threat.technique.name", "size": 3}},
                    "tactic": {"terms": {"field": "threat.tactic.name", "size": 3}},
                    "reason": {"terms": {"field": "event.reason", "size": 3}},
                    "indicator": {"terms": {"field": "threat.indicator.name", "size": 3}},
                    "indicator_source": {"terms": {"field": "threat.indicator.provider", "size": 3}},
                    "tags": {"terms": {"field": "tags", "size": 8}}}:
            raise ValueError("unexpected sub-aggregations")
        groups = {}
        for doc in self.docs:
            if not (when(doc) and inside(doc)) or "weird" in values(doc, "event.dataset"):
                continue
            if "alert" not in values(doc, "event.kind") and "intel" not in values(doc, "event.dataset"):
                continue
            choices = [values(doc, options["field"]) or ([None] if options.get("missing_bucket") else []) for _, options in wanted]
            for combination in itertools.product(*choices):
                groups.setdefault(combination, []).append(doc)

        def order(combination):
            return tuple((0, "") if value is None else (1, str(value)) for value in combination)

        ordered = sorted(groups, key=order)
        if "after" in composite:
            after = tuple(composite["after"][name] for name, _ in wanted)
            ordered = [combination for combination in ordered if order(combination) > order(after)]
        buckets = []
        for combination in ordered[:composite["size"]]:
            docs = groups[combination]

            def top(field, size=3):
                counts = {}
                for doc in docs:
                    for value in values(doc, field):
                        counts[value] = counts.get(value, 0) + 1
                return {"buckets": [{"key": key, "doc_count": count} for key, count in sorted(counts.items(), key=lambda p: (-p[1], p[0]))[:size]]}

            severities = [doc["event.severity"] for doc in docs if "event.severity" in doc]
            buckets.append({"key": dict(zip([name for name, _ in wanted], combination)), "doc_count": len(docs),
                            "first": {"value": float(min(doc[TIME_FIELD] for doc in docs))},
                            "last": {"value": float(max(doc[TIME_FIELD] for doc in docs))},
                            "severity": {"value": float(max(severities)) if severities else None},
                            "technique": top("threat.technique.id"), "technique_name": top("threat.technique.name"),
                            "tactic": top("threat.tactic.name"), "reason": top("event.reason"),
                            "indicator": top("threat.indicator.name"), "indicator_source": top("threat.indicator.provider"),
                            "tags": top("tags", 8)})
        result = {"buckets": buckets}
        if buckets:
            result["after_key"] = buckets[-1]["key"]
        return {"keys": result}

    def search(self, body):
        self.searches.append(body)
        if self.partial:
            return {"took": 1, "timed_out": True, "_shards": {"total": 5, "successful": 4, "failed": 1}, "aggregations": {}}
        aggs = body.get("aggs") or {}
        if "tags" in aggs:
            found = self.captures(body)
        elif "datasets" in aggs:
            found = self.kinds(body)
        elif "keys" in aggs and any("rule" in source for source in aggs["keys"]["composite"]["sources"]):
            found = self.detections(body)
        elif "keys" in aggs and any("proto" in source for source in aggs["keys"]["composite"]["sources"]):
            return self.ot.search(body)
        else:
            return self.conn.search(body)             # the traffic profile's search, or the 'when did this take place' search
        return {"took": 1, "timed_out": False, "_shards": {"total": 5, "successful": 5, "failed": 0}, "aggregations": found}


def serve(stored):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            path = urlparse(self.path)
            try:
                if path.path != f"/{INDEX}/_search" or path.query != "ignore_unavailable=true&allow_no_indices=true&allow_partial_search_results=false":
                    raise ValueError("unexpected request")
                reply, status = stored.search(body), 200
            except Exception as error:
                reply, status = {"error": f"{type(error).__name__}: {error}"}, 400
            data = json.dumps(reply).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class ReplayCase(unittest.TestCase):
    def setUp(self):
        self.stored = Stored()
        self.server = serve(self.stored)
        self.folder = tempfile.TemporaryDirectory()
        self.environ = {"OPENSEARCH_URL": f"http://127.0.0.1:{self.server.server_address[1]}", "TD_BASELINE_DIR": self.folder.name,
                        "OPENSEARCH_CREDS_CONFIG_FILE": str(Path(self.folder.name) / "none"), "TD_BASELINE_PAGE_SIZE": "50",
                        "TD_BASELINE_TIMEOUT": "20"}

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.folder.cleanup()

    def run_replay(self, *arguments):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = td_replay.main(list(arguments), now=T0, environ=self.environ)
        return status, out.getvalue(), err.getvalue()

    def report(self, *arguments):
        status, out, err = self.run_replay("report", "--format", "json", *arguments)
        self.assertEqual(status, 0, err)
        return json.loads(out)

    def baseline_list(self, learning=False):
        """What the plant normally does, as the baseline program keeps it: one HMI reading and writing two controllers."""
        hosts = {HMI: {"f": 0, "l": 0, "c": ["modbus"], "s": []}, ENG: {"f": 0, "l": 0, "c": ["modbus"], "s": []},
                 PLC1: {"f": 0, "l": 0, "c": [], "s": ["modbus"]}, PLC2: {"f": 0, "l": 0, "c": [], "s": ["modbus"]}}
        pairs = {f"{HMI}|{PLC1}|modbus": {}, f"{HMI}|{PLC2}|modbus": {}, f"{ENG}|{PLC1}|modbus": {}}
        ops = {f"{HMI}|{PLC1}|modbus|READ_HOLDING_REGISTERS": {}, f"{HMI}|{PLC2}|modbus|READ_HOLDING_REGISTERS": {},
               f"{HMI}|{PLC1}|modbus|WRITE_SINGLE_REGISTER": {}, f"{ENG}|{PLC1}|modbus|READ_HOLDING_REGISTERS": {}}
        (Path(self.folder.name) / "state.json").write_text(json.dumps(
            {"version": 2, "hosts": hosts, "pairs": pairs, "ops": ops, "learn_until": None if learning else 1}))

    def incident(self, tags=("incident7", "pumpstation"), node="malcolm-upload", start=THEN + 1200):
        """A capture of an intrusion: an unknown address reads the controllers' identity, writes, then stops one;
        the plant's own HMI keeps polling meanwhile."""
        more = {"node": node, "tags": list(tags)}
        add = self.stored
        for step in range(12):
            add.operation(start + step * 300, HMI, PLC1, "READ_HOLDING_REGISTERS", **more)
            add.operation(start + step * 300 + 2, HMI, PLC2, "READ_HOLDING_REGISTERS", **more)
        add.connection(start + 100, INTRUDER, PLC1, 3389, "rdp", 400_000, 9_000_000, 900, **more)
        add.connection(start + 200, INTRUDER, "203.0.113.50", 443, "tls", 60_000_000, 80_000, 300, **more)
        for index in range(3):
            add.alert(start + 600 + index, "TECHDETECHTIVES OT Modbus - Read Device Identification (inventory or reconnaissance)",
                      INTRUDER, PLC1 if index < 2 else PLC2, 51, "Discovery", "T0888", "Remote_System_Information_Discovery", **more)
            add.operation(start + 600 + index, INTRUDER, PLC1 if index < 2 else PLC2, "READ_DEVICE_IDENTIFICATION", **more)
        for index in range(5):
            add.operation(start + 1500 + index * 10, INTRUDER, PLC1, "WRITE_SINGLE_COIL", **more)
        add.alert(start + 1500, "TECHDETECHTIVES OT Correlation - Address identified controllers, then wrote to one by Modbus",
                  INTRUDER, PLC1, 71, **more, **{"threat.tactic.name": ["Impair_Process_Control", "Discovery"],
                                                 "threat.technique.id": ["T1692", "T0888"],      # the parent: the product keeps no sub-technique
                                                 "threat.technique.name": ["Command_Message", "Remote_System_Information_Discovery"]})
        add.alert(start + 1800, "TECHDETECHTIVES OT Modbus - Force Listen Only Mode (device stops answering)", INTRUDER, PLC1, 91,
                  "Inhibit_Response_Function", "T0814", "Denial_of_Service", **more)
        add.operation(start + 1800, INTRUDER, PLC1, "DIAGNOSTICS", **more)
        add.add(start + 1900, **{"event.dataset": "notice", "event.provider": "zeek", "event.kind": "alert",
                                 "rule.name": "ATTACK::Discovery", "source.ip": INTRUDER, "destination.ip": PLC2, "event.severity": 60}, **more)
        add.add(start + 250, **{"event.dataset": "intel", "event.provider": "zeek", "event.kind": "event",
                                "threat.indicator.name": "203.0.113.50", "threat.indicator.provider": ["abuse-ch-ipblocklist"],
                                "source.ip": INTRUDER, "destination.ip": "203.0.113.50"}, **more)
        for index in range(7):
            add.add(start + 30 + index, **{"event.dataset": "weird", "event.provider": "zeek", "event.kind": "alert",
                                           "rule.name": "truncated_tcp_payload", "source.ip": HMI, "destination.ip": PLC1}, **more)


class Captures(ReplayCase):
    def test_list_of_uploaded_captures(self):
        status, out, _ = self.run_replay("list")
        self.assertEqual(status, 0)
        self.assertIn("No uploaded capture is stored", out)
        self.incident()
        self.incident(tags=("drill",), start=T0 - 3 * HOUR)
        self.stored.operation(T0 - 600, HMI, PLC1, "READ_HOLDING_REGISTERS", node="sensor1", tags=["live-tag"])      # not an upload
        status, out, _ = self.run_replay("list")
        lines = out.splitlines()
        self.assertEqual([line.split()[0] for line in lines[1:4]], ["drill", "incident7", "pumpstation"], "newest traffic first")
        self.assertNotIn("live-tag", out)
        self.assertIn("2026-08-31 14:20 UTC", lines[2])
        self.assertIn("report --tag WORD", lines[-1])
        self.assertNotIn("Left out", lines[-1])

    def test_the_list_leaves_out_tags_that_are_not_words_of_a_file_name(self):
        # What the product itself leaves on the records of one capture named incident7.pcapng (read in its source):
        # the extension, marks of Suricata's parser, and a tag a Suricata rule carries in its own metadata.
        more = {"node": "malcolm-upload"}
        self.stored.operation(THEN, HMI, PLC1, "READ_COILS", tags=["incident7", "pcapng"], **more)
        self.stored.connection(THEN, HMI, PLC1, 502, "modbus", 100, 100, tags=["incident7", "pcapng"], **more)
        self.stored.alert(THEN + 5, "ET SCAN something", HMI, PLC1, tags=["incident7", "pcapng", "Description_Generated_By_A_Rule_Writer"], **more)
        self.stored.add(THEN + 6, **{"event.dataset": "flow", "event.provider": "suricata", "tags": ["incident7", "proto_parse_failed"]}, **more)
        status, out, _ = self.run_replay("list")
        lines = out.splitlines()
        self.assertEqual([line.split()[0] for line in lines[1:-1]], ["incident7"])
        self.assertIn("Left out: 3 tags the product or a rule put on records (list --all).", lines[-1])
        status, out, _ = self.run_replay("list", "--all")
        self.assertEqual(sorted(line.split()[0] for line in out.splitlines()[1:-1]),
                         ["Description_Generated_By_A_Rule_Writer", "incident7", "pcapng", "proto_parse_failed"])
        self.stored.docs[:] = [doc for doc in self.stored.docs if "incident7" not in doc["tags"] or doc["event.dataset"] == "flow"]
        for doc in self.stored.docs:
            doc["tags"] = ["proto_parse_failed"]
        status, out, _ = self.run_replay("list")
        self.assertIn("No uploaded capture is stored under a tag of its own (1 tags of the product's or a rule's: list --all).", out)

    def test_a_capture_is_found_by_its_tag_wherever_in_time_it_lies(self):
        self.incident()
        result = self.report("--tag", "incident7")
        self.assertEqual((result["from"], result["to"]), (THEN, THEN + 2 * HOUR), "the whole hours the capture's traffic lies in")
        self.assertEqual(result["records"], "live traffic and uploaded captures, tagged incident7")
        self.assertEqual(result["counts"]["modbus"], 24 + 3 + 5 + 1)
        self.assertEqual((result["counts"]["alert"], result["counts"]["weird"], result["counts"]["conn"]), (5, 7, 2))
        status, out, err = self.run_replay("report", "--tag", "nothere")
        self.assertEqual((status, out), (1, ""))
        self.assertIn("No record carries the tag 'nothere'", err)
        self.assertIn("capitals count", err)

    def test_a_tag_with_a_choice_about_uploads_and_with_a_period(self):
        self.incident()
        self.stored.operation(THEN + 1300, HMI, PLC1, "READ_COILS", node="sensor1", tags=["incident7"])      # a live record with the same tag
        self.assertEqual(self.report("--tag", "incident7", "--uploads", "only")["counts"]["modbus"], 33)
        live = self.report("--tag", "incident7", "--uploads", "exclude")
        self.assertEqual((live["counts"], live["records"]), ({"modbus": 1}, "live traffic (uploaded captures left out), tagged incident7"))
        status, out, err = self.run_replay("report", "--tag", "pumpstation", "--uploads", "exclude")
        self.assertEqual(status, 1)
        self.assertIn("No live record carries the tag 'pumpstation' (uploaded captures were left out: --uploads include).", err)
        # a tag and a period: the part of the capture inside the period, which is read in whole hours, outwards
        part = self.report("--tag", "incident7", "--from", "2026-08-31T15:10", "--to", "2026-08-31T15:40")
        self.assertEqual((part["from"], part["to"]), (THEN + HOUR, THEN + 2 * HOUR))
        self.assertEqual((part["counts"], part["detections"]), ({"modbus": 8}, []), "the HMI's last four rounds, and nothing else")

    def test_a_capture_longer_than_seven_days(self):
        more = {"node": "malcolm-upload", "tags": ["longone"]}
        self.stored.operation(THEN, HMI, PLC1, "READ_COILS", **more)
        self.stored.operation(THEN + 9 * 24 * HOUR, HMI, PLC1, "READ_COILS", **more)
        status, out, err = self.run_replay("report", "--tag", "longone")
        self.assertEqual((status, out), (1, ""))
        self.assertIn("seven days", err)
        self.assertIn("--from and --to", err)
        # seven days to the minute, from half past to half past, is eight whole days less an hour of reading: refused, not stretched
        status, out, err = self.run_replay("report", "--from", "2026-08-25T02:30", "--to", "2026-09-01T02:30")
        self.assertEqual(status, 1)
        self.assertIn("counted in whole hours", err)
        self.assertEqual(self.report("--from", "2026-08-25T02:00", "--to", "2026-09-01T02:00")["to"] - THEN, (-12 + 24) * HOUR)

    def test_a_period_of_live_traffic_leaves_uploads_out(self):
        self.incident(start=T0 - 5 * HOUR + 60)                                   # uploaded, with times inside the period
        self.incident(tags=(), node="sensor1", start=T0 - 5 * HOUR + 60)          # and the same seen live
        live = self.report("--from", "2026-09-21T09:00", "--to", "2026-09-21T10:00")
        self.assertEqual(live["records"], "live traffic (uploaded captures left out)")
        self.assertEqual(live["counts"]["alert"], 5)
        both = self.report("--from", "2026-09-21T09:00", "--to", "2026-09-21T10:00", "--uploads", "include")
        self.assertEqual(both["counts"]["alert"], 10)

    def test_arguments_and_failures(self):
        for bad in (["report"], ["report", "--from", "2026-09-21"], ["report", "--to", "2026-09-21"], ["report", "--tag", "x", "--top", "0"],
                    ["report", "--from", "soon", "--to", "later"], []):
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                td_replay.main(bad, environ=self.environ)
        status, out, err = self.run_replay("report", "--from", "2026-01-01", "--to", "2026-02-01")
        self.assertEqual(status, 1)
        self.assertIn("seven days", err)
        self.incident()
        self.stored.partial = True
        for command in (["list"], ["report", "--tag", "incident7"]):
            status, out, err = self.run_replay(*command)
            self.assertEqual((status, out), (1, ""), command)
            self.assertIn("only in part", err)


class WhatTheReplayShows(ReplayCase):
    def setUp(self):
        super().setUp()
        self.incident()
        self.baseline_list()
        self.result = self.report("--tag", "incident7")

    def test_detections_come_in_the_order_they_happened(self):
        found = self.result["detections"]
        self.assertEqual([(item["kind"], item["rule"].split(" - ")[-1][:28], item["destination"], item["count"]) for item in found], [
            ("intel", "", "203.0.113.50", 1),
            ("alert", "Read Device Identification (", PLC1, 2),
            ("alert", "Read Device Identification (", PLC2, 1),
            ("alert", "Address identified controlle", PLC1, 1),
            ("alert", "Force Listen Only Mode (devi", PLC1, 1),
            ("notice", "ATTACK::Discovery", PLC2, 1),
        ])
        first = found[1]
        self.assertEqual((first["first"], first["last"], first["severity"], first["techniques"], first["tactics"]),
                         (THEN + 1800, THEN + 1801, 51, ["T0888"], ["Discovery"]))
        self.assertFalse(any(item["kind"] == "weird" for item in found), "Zeek's odd-packet records are counted, not listed")
        self.assertFalse(self.result["detections_cut_short"])

    def test_the_course_of_events_is_the_tactics_in_order(self):
        steps = self.result["course"]
        self.assertEqual([step["tactic"] for step in steps], ["Discovery", "Impair_Process_Control", "Inhibit_Response_Function"])
        self.assertEqual((steps[0]["first"], steps[0]["techniques"], steps[0]["sources"]), (THEN + 1800, ["T0888"], [INTRUDER]))
        self.assertEqual(steps[1]["techniques"], [], "an event under two tactics does not say which technique belongs to which")
        self.assertEqual(steps[2]["techniques"], ["T0814"])

    def test_against_the_baseline(self):
        novel = self.result["against_baseline"]
        self.assertEqual([entry["client"] for entry in novel], [INTRUDER], "the HMI's own polling is in the list and is not mentioned")
        entry = novel[0]
        self.assertTrue(entry["unknown"] and entry["control"])
        self.assertEqual((entry["new_roles"], entry["new_devices"], entry["first"]), (["modbus"], [], THEN + 1800))
        self.assertEqual(entry["new_operations"], [f"DIAGNOSTICS on {PLC1} (modbus), once",
                                                   f"READ_DEVICE_IDENTIFICATION on {PLC1} (modbus), 2 times",
                                                   f"READ_DEVICE_IDENTIFICATION on {PLC2} (modbus), once",
                                                   f"WRITE_SINGLE_COIL on {PLC1} (modbus), 5 times"])
        text = td_replay.sentence(entry)
        self.assertTrue(text.startswith(f"{INTRUDER} is not in the baseline's list at all. It acted as a master by modbus. Operations never used"), text)
        # replaying changes nothing: the list on disk is as it was
        state = json.loads((Path(self.folder.name) / "state.json").read_text())
        self.assertNotIn(INTRUDER, state["hosts"])

    def test_a_known_master_doing_something_new_and_a_device_never_seen(self):
        more = {"node": "malcolm-upload", "tags": ["incident7"]}
        self.stored.operation(THEN + 2000, ENG, PLC2, "WRITE_MULTIPLE_REGISTERS", **more)        # known master, a controller it never talked to
        self.stored.operation(THEN + 2100, HMI, "10.0.1.99", "READ_COILS", **more)               # an address the list does not hold
        self.stored.operation(THEN + 2200, PLC1, PLC2, "READ_COILS", **more)                     # a device that starts asking
        novel = {entry["client"]: entry for entry in self.report("--tag", "incident7")["against_baseline"]}
        self.assertEqual(sorted(novel), sorted([INTRUDER, ENG, HMI, PLC1]))
        self.assertEqual((novel[ENG]["unknown"], novel[ENG]["new_pairs"], novel[ENG]["control"]), (False, [f"{PLC2} (modbus)"], True))
        self.assertIn("It never talked before to: 10.0.1.11 (modbus)", td_replay.sentence(novel[ENG]))
        self.assertEqual(novel[HMI]["new_devices"], ["10.0.1.99"])
        self.assertIn("is known, but never as a master by modbus", td_replay.sentence(novel[PLC1]))

    def test_without_a_baseline_or_while_it_learns(self):
        (Path(self.folder.name) / "state.json").unlink()
        result = self.report("--tag", "incident7")
        self.assertEqual((result["baseline_known"], result["against_baseline"]), (False, None))
        status, out, _ = self.run_replay("report", "--tag", "incident7")
        self.assertIn("The baseline has no list yet", out)
        self.baseline_list(learning=True)
        status, out, _ = self.run_replay("report", "--tag", "incident7")
        self.assertIn("The baseline is still learning", out)

    def test_other_traffic(self):
        traffic = self.result["traffic"]
        self.assertEqual([(row["client"], row["port"]) for row in traffic["reaching_controllers"]], [(INTRUDER, 3389)])
        self.assertEqual([row["server"] for row in traffic["outside"]], ["203.0.113.50"])
        self.assertEqual(traffic["largest"][0]["bytes"], 60_080_000)

    def test_the_text(self):
        status, out, err = self.run_replay("report", "--tag", "incident7")
        self.assertEqual((status, err), (0, ""))
        lines = out.splitlines()
        self.assertEqual(lines[0], "Incident replay, 2026-08-31 14:00 UTC to 2026-08-31 16:00 UTC")
        self.assertEqual(lines[1], "Records: live traffic and uploaded captures, tagged incident7. Times are UTC.")
        self.assertIn("modbus 33", lines[2])
        for title in ("The course of events", "Against the baseline: what this traffic holds that the plant's normal traffic never did",
                      "Other traffic in the period", "Where to look next"):
            self.assertIn(title, lines)
        self.assertIn("  14:30:00  Discovery (T0888), from 10.66.6.6", lines)
        self.assertIn("  14:50:00  Inhibit Response Function (T0814), from 10.66.6.6", lines)
        self.assertTrue(any(line.startswith("  14:30:00  rule alert: TECHDETECHTIVES OT Modbus - Read Device Identification")
                            and "(10.66.6.6 -> 10.0.1.10; severity 51, 2 times, last 14:30:01)" in line
                            and line.endswith("[T0888 Remote System Information Discovery]") for line in lines), out)
        self.assertTrue(any("then wrote to one by Modbus" in line and line.endswith("[T0888, T1692]") for line in lines))
        self.assertIn("  14:24:10  indicator match: 203.0.113.50 (on the list: abuse-ch-ipblocklist)  (10.66.6.6 -> 203.0.113.50; once)", lines)
        self.assertIn("49 records: modbus 33, weird 7, alert 5, conn 2, intel 1, notice 1.", lines)
        self.assertTrue(any("Not listed: 7 'weird' records" in line for line in lines))
        self.assertTrue(any("10.66.6.6 -> 10.0.1.10 (device)  3389/tcp rdp" in line for line in lines))
        self.assertTrue(any("expression  tags == <the tag>" in line for line in lines))
        self.assertTrue(all(ord(char) < 127 for char in out))

    def test_top_markdown_and_a_file(self):
        status, out, _ = self.run_replay("report", "--tag", "incident7", "--top", "2", "--format", "markdown")
        self.assertTrue(out.startswith("# Incident replay, "))
        self.assertIn("## Detections in order (6 kinds of event between pairs of addresses)", out)
        self.assertIn("- ... and 4 more (--top 6 shows all; --format json has every one).", out)
        target = Path(self.folder.name) / "replay.md"
        status, out, err = self.run_replay("report", "--tag", "incident7", "--out", str(target))
        self.assertEqual((status, out), (0, ""))
        self.assertTrue(target.read_text().startswith("Incident replay, "))
        status, out, err = self.run_replay("report", "--tag", "incident7", "--out", str(Path(self.folder.name) / "no such folder" / "x.md"))
        self.assertEqual((status, out), (1, ""))
        self.assertIn("could not be written", err)

    def test_a_file_scan_hit_is_one_event_under_the_capture_s_tag(self):
        # As the product stores it: two kinds at once, every matching rule in one list, the capture's tags,
        # and the node of the machine, without "-upload".
        hit = {"event.dataset": ["files", "strelka"], "event.provider": "filescan", "event.kind": "alert",
               "rule.name": ["CAPE_Emotet", "TechDetechtives_PowerShell_Download_And_Run"], "source.ip": INTRUDER, "destination.ip": PLC1,
               "node": "malcolm", "tags": ["incident7", "pumpstation"], "threat.tactic.name": ["Execution"], "threat.technique.id": ["T1059"]}
        self.stored.add(THEN + 2600, **hit)
        self.stored.add(THEN + 2700, **dict(hit, **{"rule.name": ["CAPE_Emotet"]}))
        result = self.report("--tag", "incident7")
        self.assertEqual(result["total"], 51, "two records more, though they are counted under two kinds each")
        self.assertEqual((result["counts"]["files"], result["counts"]["strelka"]), (2, 2))
        hits = [(item["rule"], item["count"], item["first"]) for item in result["detections"] if item["kind"] == "filescan"]
        self.assertEqual(hits, [("CAPE_Emotet", 2, THEN + 2600), ("TechDetechtives_PowerShell_Download_And_Run", 1, THEN + 2600)])
        self.assertFalse(any(item["kind"] in ("files", "strelka") for item in result["detections"]))
        status, out, _ = self.run_replay("report", "--tag", "incident7")
        self.assertIn("51 records: ", out)
        self.assertIn("  14:43:20  file-scan hit: CAPE_Emotet  (10.66.6.6 -> 10.0.1.10; 2 times, last 14:45:00)  [T1059]", out.splitlines())
        self.assertNotIn("File-scan hits are", out)
        # the product does not mark a scan hit as uploaded: said where it matters
        status, out, _ = self.run_replay("report", "--tag", "incident7", "--uploads", "only")
        self.assertNotIn("file-scan hit:", out)
        self.assertIn("File-scan hits are not listed with --uploads only", out)
        status, out, _ = self.run_replay("report", "--from", "2026-08-31T14:00", "--to", "2026-08-31T16:00")
        self.assertIn("file-scan hit: CAPE_Emotet  (10.66.6.6 -> 10.0.1.10; 2 times, last 14:45:00; tagged incident7, pumpstation)", out)
        self.assertIn("One that carries a capture's tag came from that capture.", out)

    def test_the_other_kinds_of_detection(self):
        more = {"node": "malcolm-upload", "tags": ["incident7"]}
        self.stored.add(THEN + 2600, **{"event.dataset": "signatures", "event.provider": "zeek", "event.kind": "alert",
                                        "rule.name": "dpd_enip_cip", "source.ip": INTRUDER, "destination.ip": PLC2}, **more)
        # an alert from a monitor or from the baseline: made by the product's webhook, with no node and no addresses
        self.stored.add(THEN + 2700, **{"event.dataset": "alerting", "event.provider": "malcolm", "event.kind": "alert",
                                        "rule.name": "TechDetechtives OT Baseline", "event.reason": "10.66.6.6 was never seen before",
                                        "event.severity": 80, "tags": ["incident7"]})
        status, out, _ = self.run_replay("report", "--tag", "incident7")
        lines = out.splitlines()
        self.assertIn("  14:43:20  Zeek signature: dpd_enip_cip  (10.66.6.6 -> 10.0.1.11; once)", lines)
        self.assertIn("  14:45:00  monitor or baseline alert: TechDetechtives OT Baseline: 10.66.6.6 was never seen before  "
                      "(no address; severity 80, once)", lines)

    def test_a_period_longer_than_a_day_shows_dates(self):
        self.stored.alert(THEN + 30 * HOUR, "a later rule", INTRUDER, PLC1, node="malcolm-upload", tags=["incident7"])
        status, out, _ = self.run_replay("report", "--tag", "incident7")
        self.assertIn("  2026-09-01 20:00:00  rule alert: a later rule", out)
        self.assertIn("  14:30:00  Discovery (T0888)", out, "times inside the first day stay short")

    def test_an_ipv6_master_and_a_list_that_cannot_be_read(self):
        self.stored.operation(THEN + 2000, "fd00::5", PLC1, "WRITE_SINGLE_COIL", node="malcolm-upload", tags=["incident7"])
        status, out, _ = self.run_replay("report", "--tag", "incident7")
        self.assertIn("fd00::5 is not in the baseline's list at all. It acted as a master by modbus.", out)
        self.assertNotIn("Fd00", out)
        state = Path(self.folder.name) / "state.json"
        for text in ("{{{", "[]", json.dumps({"hosts": ["10.0.0.5"], "pairs": {}, "ops": {}}), json.dumps({"hosts": {HMI: 5}, "pairs": {}, "ops": {}}),
                     json.dumps({"hosts": {HMI: {"c": [], "s": []}}})):
            state.write_text(text)
            status, out, err = self.run_replay("report", "--tag", "incident7")
            self.assertEqual((status, err), (0, ""), text)
            self.assertIn("is there but could not be read as a list", out, text)
            self.assertIn("rule alert: TECHDETECHTIVES OT Modbus - Force Listen Only Mode", out, "the rest of the report is still given")
        self.assertEqual(self.report("--tag", "incident7")["baseline_problem"], "unreadable")

    def test_text_from_the_network_cannot_break_the_report(self):
        self.stored.alert(THEN + 2500, "evil\x1b[2J rule\nname|x", INTRUDER, PLC1, node="malcolm-upload", tags=["incident7"])
        status, out, _ = self.run_replay("report", "--tag", "incident7")
        self.assertNotIn("\x1b", out)
        self.assertIn("rule alert: evil?[2J rule?name/x", out)
        # in the Markdown report a rule's name cannot become an image, a link or markup
        self.stored.alert(THEN + 2600, "<img src=x onerror=alert(1)> [click](javascript:alert(1)) `x` *y*", INTRUDER, PLC1,
                          node="malcolm-upload", tags=["incident7"])
        status, out, _ = self.run_replay("report", "--tag", "incident7", "--format", "markdown")
        self.assertIn("rule alert: &lt;img src=x onerror=alert(1)> \\[click\\](javascript:alert(1)) \\`x\\` \\*y\\*", out)
        self.assertNotIn("<img", out)
        self.assertIn("\\[T0888 Remote System Information Discovery\\]", out)

    def test_many_detections_are_read_in_pages(self):
        for index in range(120):
            self.stored.alert(THEN + 3000 + index, f"rule number {index:03d}", INTRUDER, PLC1, node="malcolm-upload", tags=["incident7"])
        result = self.report("--tag", "incident7")
        self.assertEqual(len(result["detections"]), 126)
        self.assertEqual([item["rule"] for item in result["detections"][-2:]], ["rule number 118", "rule number 119"])

    def test_a_quiet_capture(self):
        self.stored.operation(T0 - 2 * HOUR, HMI, PLC1, "READ_HOLDING_REGISTERS", node="malcolm-upload", tags=["quiet"])
        status, out, _ = self.run_replay("report", "--tag", "quiet")
        self.assertIn("None. The engines raised nothing on this traffic with the rules now installed.", out)
        self.assertIn("Nothing: every master, device, conversation and operation in this traffic is in the baseline's list.", out)
        self.assertIn("No detection in this period names an ATT&CK tactic.", out)


if __name__ == "__main__":
    unittest.main()
