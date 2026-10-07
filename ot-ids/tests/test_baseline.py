# TechDetechtives OT IDS tests. Copyright (c) 2026 TechDetechtives. MIT licence.
"""Tests for ot-ids/baseline/td_baseline.py. Run with:  python3 -m unittest discover -s ot-ids/tests -v

The program is run against a stand-in for the product: a small web server that
answers the one OpenSearch search the program makes (worked out from records
held in memory, shaped like the product's) and takes alerts the way the
product's alert webhook does. The stand-in refuses a search it does not
recognise, so a change to the query has to be made in both places on purpose.

This shows that the program's own logic is right. It does not show that the
real OpenSearch accepts the search or that the real webhook stores the alert:
'td_baseline.py check' and 'test-alert' are there to show that on an installed
system.
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
sys.path.insert(0, str(KIT / "tools"))

import attack_ics      # noqa: E402
import td_baseline     # noqa: E402

HOUR = 3600
T0 = (1_790_000_000 // HOUR) * HOUR          # a fixed moment, on the hour
INDEX = "arkime_sessions3-*"
TIME_FIELD = "firstPacket"

HMI, ENG, PLC1, PLC2, PLC3 = "10.0.0.5", "10.0.0.6", "10.0.1.10", "10.0.1.11", "10.0.1.12"


def values(doc, field):
    value = doc.get(field)
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


class Platform:
    """Holds records and alerts, and answers as OpenSearch and the alert webhook would."""

    def __init__(self):
        self.docs, self.alerts, self.searches, self.auth_seen = [], [], [], []
        self.refuse_alerts = False
        self.refuse_search = False
        self.partial = False          # answer as OpenSearch does when a shard failed or the search timed out
        self.no_index = False         # answer as OpenSearch does when no index matches yet

    # --- the search ---------------------------------------------------------
    def search(self, body):
        if sorted(body) != ["aggs", "query", "size", "track_total_hits"] or body["size"] != 0:
            raise ValueError("unexpected search body")
        boolean = body["query"]["bool"]
        if sorted(boolean) != ["filter", "must_not"]:
            raise ValueError("unexpected query")
        time_range = boolean["filter"][0]["range"][TIME_FIELD]
        if sorted(time_range) != ["format", "gte", "lt"] or time_range["format"] != "epoch_millis":
            raise ValueError("unexpected range")
        protocols = boolean["filter"][2]["terms"]["network.protocol"]
        if boolean["filter"][1:2] + boolean["filter"][3:5] != [{"term": {"event.category": "ot"}}, {"exists": {"field": "source.ip"}},
                                                                {"exists": {"field": "destination.ip"}}]:
            raise ValueError("unexpected filters")
        uploaded = {"wildcard": {"node": {"value": "*-upload"}}}
        wanted_tags, only_uploads = [], False
        for extra in boolean["filter"][5:]:                       # the scope: a tag, uploaded captures only
            if extra == uploaded:
                only_uploads = True
            elif list(extra) == ["term"] and list(extra["term"]) == ["tags"]:
                wanted_tags.append(extra["term"]["tags"])
            else:
                raise ValueError("unexpected scope filter")
        if boolean["must_not"][2:] not in ([], [uploaded]):
            raise ValueError("unexpected exclusions")
        no_uploads = boolean["must_not"][2:] == [uploaded]
        if self.no_index:
            return {"took": 1, "timed_out": False, "_shards": {"total": 0, "successful": 0, "failed": 0}, "hits": {"hits": []}}
        skip_datasets = boolean["must_not"][0]["terms"]["event.dataset"]
        skip_providers = boolean["must_not"][1]["terms"]["event.provider"]
        if list(body["aggs"]) != ["keys"] or sorted(body["aggs"]["keys"]) != ["aggs", "composite"]:
            raise ValueError("unexpected aggregation")
        if body["aggs"]["keys"]["aggs"] != {"first": {"min": {"field": TIME_FIELD}}, "last": {"max": {"field": TIME_FIELD}}}:
            raise ValueError("unexpected sub-aggregations")
        composite = body["aggs"]["keys"]["composite"]
        if not set(composite) <= {"size", "sources", "after"}:
            raise ValueError("unexpected composite options")
        sources = []
        for source in composite["sources"]:
            (name, spec), = source.items()
            (kind, options), = spec.items()
            if kind == "date_histogram":
                if options != {"field": TIME_FIELD, "fixed_interval": "1h"}:
                    raise ValueError("unexpected histogram")
            elif kind != "terms" or not set(options) <= {"field", "missing_bucket"}:
                raise ValueError("unexpected source")
            sources.append((name, kind, options))

        buckets = {}
        for doc in self.docs:
            when = doc[TIME_FIELD]
            if not time_range["gte"] <= when < time_range["lt"]:
                continue
            if "ot" not in values(doc, "event.category"):
                continue
            if not all(values(doc, field) for field in ("source.ip", "destination.ip")):
                continue
            if not set(values(doc, "network.protocol")) & set(protocols):
                continue
            if set(values(doc, "event.dataset")) & set(skip_datasets) or set(values(doc, "event.provider")) & set(skip_providers):
                continue
            is_upload = any(str(node).endswith("-upload") for node in values(doc, "node"))
            if (no_uploads and is_upload) or (only_uploads and not is_upload) or not set(wanted_tags) <= set(values(doc, "tags")):
                continue
            choices = []
            for name, kind, options in sources:
                if kind == "date_histogram":
                    choices.append([when - when % (HOUR * 1000)])
                else:
                    found = values(doc, options["field"])
                    if not found and options.get("missing_bucket"):
                        found = [None]
                    choices.append(found)
            for combination in itertools.product(*choices):       # a record with several values counts under each
                bucket = buckets.setdefault(combination, [0, when, when])
                bucket[0] += 1
                bucket[1], bucket[2] = min(bucket[1], when), max(bucket[2], when)

        def order(combination):
            return tuple((0, "") if value is None else (1, value) if isinstance(value, str) else (1, f"{value:020d}") for value in combination)

        ordered = sorted(buckets, key=order)
        if "after" in composite:
            after = tuple(composite["after"][name] for name, _, _ in sources)
            ordered = [combination for combination in ordered if order(combination) > order(after)]
        page = ordered[:composite["size"]]
        result = {"buckets": [{"key": {name: value for (name, _, _), value in zip(sources, combination)},
                               "doc_count": buckets[combination][0],
                               "first": {"value": float(buckets[combination][1])},
                               "last": {"value": float(buckets[combination][2])}} for combination in page]}
        if page:
            result["after_key"] = result["buckets"][-1]["key"]
        if self.partial:
            return {"took": 1, "timed_out": True, "_shards": {"total": 5, "successful": 4, "failed": 1},
                    "aggregations": {"keys": {"buckets": []}}}
        return {"took": 1, "timed_out": False, "_shards": {"total": 5, "successful": 5, "failed": 0}, "aggregations": {"keys": result}}

    # --- the webhook, as the product's api/project/__init__.py event() builds its record ---
    def take_alert(self, payload):
        alert = payload["alert"]
        if sorted(alert) != ["alert", "body", "error", "monitor", "period", "trigger"]:
            raise ValueError("unexpected alert fields")
        if not isinstance(alert["trigger"]["severity"], int) or not 1 <= alert["trigger"]["severity"] <= 5:
            raise ValueError("severity must be 1 to 5")
        record = {TIME_FIELD: alert["period"]["start"], "lastPacket": alert["period"]["end"],
                  "event": {"kind": "alert", "provider": "malcolm", "dataset": "alerting", "module": "alerting",
                            "id": alert["alert"], "start": alert["period"]["start"], "end": alert["period"]["end"]}}
        conflicts = self.merge(record, json.loads(alert["body"]))
        if conflicts:
            record["conflicts"] = conflicts
        record["event"]["reason"] = alert["trigger"]["name"]
        record["rule"] = {"name": alert["monitor"]["name"]}
        record["event"]["severity"] = 100 - (alert["trigger"]["severity"] - 1) * 20
        self.alerts = [old for old in self.alerts if old["event"]["id"] != record["event"]["id"]] + [record]   # same id: replaced
        return {"result": {"result": "created", "_id": record["event"]["id"]}}

    @classmethod
    def merge(cls, base, overlay, conflicts=None):
        """deep_merge from the product's api/project/__init__.py, as it is: a shared object leaves an empty entry behind."""
        if conflicts is None:
            conflicts = {}
        for key, value in overlay.items():
            if key in base:
                if isinstance(base[key], dict) and isinstance(value, dict):
                    cls.merge(base[key], value, conflicts.setdefault(key, {}))
                else:
                    conflicts[key] = value
            else:
                base[key] = value
        return conflicts

    # --- records --------------------------------------------------------------
    def add(self, when, src, dst, protocol="modbus", action="READ_HOLDING_REGISTERS", is_orig=None, **more):
        doc = {TIME_FIELD: when * 1000, "source.ip": src, "destination.ip": dst, "network.protocol": protocol,
               "event.action": action, "event.category": ["ot", "network"], "event.dataset": "modbus", "event.provider": "zeek"}
        if is_orig is not None:
            doc["network.is_orig"] = is_orig
        doc.update(more)
        self.docs.append(doc)

    def poll(self, first_hour, hours, client, server, protocol="modbus", action="READ_HOLDING_REGISTERS", per_hour=4, answers=True, **more):
        """Steady polling: requests, and answers written the way the ICSNPP decoders write them."""
        for hour in range(first_hour, first_hour + hours):
            for step in range(per_hour):
                when = T0 + hour * HOUR + step * (HOUR // per_hour) + 7
                self.add(when, client, server, protocol, action, is_orig="T" if answers else None, **more)
                if answers:
                    self.add(when + 1, server, client, protocol, action, is_orig="F", **more)


def serve(platform):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
            path = urlparse(self.path)
            try:
                if path.path == f"/{INDEX}/_search":
                    if platform.refuse_search:
                        raise RuntimeError("search refused")
                    if path.query != "ignore_unavailable=true&allow_no_indices=true&allow_partial_search_results=false":
                        raise ValueError("unexpected search options")
                    platform.auth_seen.append(self.headers.get("Authorization"))
                    platform.searches.append(body)
                    reply = platform.search(body)
                elif path.path == "/mapi/alert":
                    if platform.refuse_alerts:
                        raise RuntimeError("webhook refused")
                    if self.headers.get("Authorization") or self.headers.get("X-Forwarded-For"):
                        raise ValueError("the webhook is called from inside, without credentials")
                    reply = platform.take_alert(body)
                else:
                    raise ValueError(f"unexpected path {self.path}")
                data, code = json.dumps(reply).encode(), 200
            except (ValueError, KeyError, IndexError, TypeError) as error:
                data, code = json.dumps({"error": f"{type(error).__name__}: {error}"}).encode(), 400
            except RuntimeError as error:
                data, code = json.dumps({"error": str(error)}).encode(), 500
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class BaselineCase(unittest.TestCase):
    LEARN_DAYS = 2

    def setUp(self):
        self.platform = Platform()
        self.server = serve(self.platform)
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        port = self.server.server_address[1]
        creds = Path(self.tmp.name) / "curlrc"
        creds.write_text('user: "reader:s3cret:with:colons"\ninsecure\n')
        self.environ = {
            "TD_BASELINE_DIR": str(Path(self.tmp.name) / "state"),
            "OPENSEARCH_URL": f"http://127.0.0.1:{port}",
            "OPENSEARCH_CREDS_CONFIG_FILE": str(creds),
            "TD_BASELINE_ALERT_URL": f"http://127.0.0.1:{port}/mapi/alert",
            "TD_BASELINE_LEARN_DAYS": str(self.LEARN_DAYS),
            "TD_BASELINE_BACKFILL_DAYS": "3",
            "TD_BASELINE_TIMEOUT": "10",
        }

    def command(self, *argv, now=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = td_baseline.main(list(argv), now=now, environ=self.environ)
        return code, out.getvalue(), err.getvalue()

    def run_at(self, hour, minutes=11):
        """One pass at T0 + hour hours + minutes. With the default 10 minutes of lag, minute 11 closes the hour before."""
        code, _, err = self.command("run", now=T0 + hour * HOUR + minutes * 60)
        self.assertEqual((code, err), (0, ""), err)

    def run_hours(self, first, last):
        for hour in range(first, last + 1):
            self.run_at(hour)

    def state(self):
        return json.loads((Path(self.environ["TD_BASELINE_DIR"]) / "state.json").read_text())

    def findings(self, kind=None):
        path = Path(self.environ["TD_BASELINE_DIR"]) / "findings.jsonl"
        found = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
        return [finding for finding in found if kind is None or finding["kind"] == kind]

    def learned_plant(self, hours=None):
        """Two days of an ordinary plant, read, with learning over: an HMI polling three controllers."""
        hours = hours or self.LEARN_DAYS * 24
        for plc in (PLC1, PLC2, PLC3):
            self.platform.poll(0, hours, HMI, plc)
        self.platform.poll(0, hours, HMI, PLC1, action="WRITE_SINGLE_REGISTER", per_hour=2)
        self.run_at(hours)
        self.assertEqual(self.findings(), [])
        return hours


class Learning(BaselineCase):
    def test_nothing_is_reported_while_learning_and_the_list_is_exact(self):
        hours = self.learned_plant()
        state = self.state()
        self.assertEqual(sorted(state["hosts"]), sorted([HMI, PLC1, PLC2, PLC3]))
        self.assertEqual(state["hosts"][HMI], {"f": T0 + 7, "l": T0 + (hours - 1) * HOUR + 7, "c": ["modbus"], "s": []})
        self.assertEqual(state["hosts"][PLC1]["s"], ["modbus"])
        self.assertEqual(state["hosts"][PLC1]["c"], [], "an answer written with the controller as the sender does not make it a master")
        self.assertEqual(sorted(state["pairs"]), [f"{HMI}|{plc}|modbus" for plc in (PLC1, PLC2, PLC3)])
        self.assertEqual(sorted(state["ops"]), sorted([f"{HMI}|{PLC1}|modbus|READ_HOLDING_REGISTERS", f"{HMI}|{PLC1}|modbus|WRITE_SINGLE_REGISTER",
                                                      f"{HMI}|{PLC2}|modbus|READ_HOLDING_REGISTERS", f"{HMI}|{PLC3}|modbus|READ_HOLDING_REGISTERS"]))
        read = state["ops"][f"{HMI}|{PLC1}|modbus|READ_HOLDING_REGISTERS"]
        self.assertEqual((read["n"], read["mx"]), (hours, 8), "four requests and four answers an hour")
        pair = state["pairs"][f"{HMI}|{PLC1}|modbus"]
        self.assertEqual((pair["h"], pair["dhl"] - pair["dh0"]), (hours, hours))
        self.assertEqual((state["data_hours"], state["learn_until"]), (hours, T0 // HOUR + hours))
        self.assertEqual(self.platform.alerts, [])

    def test_stored_traffic_is_read_in_bounded_steps_and_all_of_it_is_learned(self):
        self.environ.update(TD_BASELINE_MAX_HOURS_PER_RUN="30", TD_BASELINE_LEARN_DAYS="1")
        self.platform.poll(0, 70, HMI, PLC1)
        self.platform.poll(40, 30, ENG, PLC1, action="WRITE_MULTIPLE_REGISTERS")     # new after a day, but before this program first ran
        self.run_at(70)
        self.assertEqual(self.state()["cursor"], T0 // HOUR + 70 - 72 + 30, "first pass: thirty hours of the three days stored")
        self.assertFalse(self.state()["last_run"]["caught_up"])
        self.run_at(70, minutes=26)
        self.run_at(70, minutes=41)
        state = self.state()
        self.assertTrue(state["last_run"]["caught_up"])
        self.assertEqual(state["learn_until"], T0 // HOUR + 70, "what was stored before the first pass is learned, not reported")
        self.assertEqual(self.findings(), [])
        self.assertIn(ENG, state["hosts"])
        # From now on it compares.
        self.platform.add(T0 + 70 * HOUR + 120, "10.0.0.99", PLC1, action="WRITE_SINGLE_COIL")
        self.run_at(71)
        self.assertEqual([finding["kind"] for finding in self.findings()], ["new-master"])

    def test_maintenance_window_learns_and_reports_nothing(self):
        hours = self.learned_plant()
        code, out, _ = self.command("learn", "--hours", "3", now=T0 + hours * HOUR + 600)
        self.assertEqual(code, 0)
        self.assertIn("will be learned as normal", out)
        self.platform.poll(hours, 2, HMI, PLC1)
        self.platform.add(T0 + hours * HOUR + 900, ENG, PLC2, action="WRITE_MULTIPLE_REGISTERS")
        self.run_hours(hours + 1, hours + 2)
        self.assertEqual(self.findings(), [])
        self.assertIn(f"{ENG}|{PLC2}|modbus|WRITE_MULTIPLE_REGISTERS", self.state()["ops"])
        # After the window the same station doing something else is reported.
        self.platform.add(T0 + (hours + 4) * HOUR + 30, ENG, PLC3, action="WRITE_MULTIPLE_REGISTERS")
        self.run_at(hours + 5)
        self.assertEqual([finding["kind"] for finding in self.findings()], ["new-pair"])


class FirstSeen(BaselineCase):
    def test_a_new_address_acting_as_master_is_one_finding_not_four(self):
        hours = self.learned_plant()
        self.platform.poll(hours, 1, HMI, PLC1)
        for plc in (PLC1, PLC2):
            self.platform.add(T0 + hours * HOUR + 300, "10.0.0.99", plc, action="WRITE_SINGLE_REGISTER", is_orig="T")
            self.platform.add(T0 + hours * HOUR + 301, plc, "10.0.0.99", action="WRITE_SINGLE_REGISTER", is_orig="F")
        self.run_at(hours + 1)
        found = self.findings()
        self.assertEqual([finding["kind"] for finding in found], ["new-master"])
        self.assertEqual((found[0]["client"], found[0]["server"], found[0]["protocol"]), ("10.0.0.99", None, "modbus"))
        self.assertEqual(found[0]["time"], td_baseline.iso(T0 + hours * HOUR + 300))
        self.assertIn("never seen before and is acting as a master by modbus", found[0]["text"])
        self.assertIn(f"{PLC1} (modbus), {PLC2} (modbus)", found[0]["text"])
        # It is in the list now, so the next hour of the same says nothing.
        self.platform.add(T0 + (hours + 1) * HOUR + 300, "10.0.0.99", PLC1, action="WRITE_SINGLE_REGISTER", is_orig="T")
        self.run_at(hours + 2)
        self.assertEqual(len(self.findings()), 1)

    def test_a_controller_that_starts_asking(self):
        hours = self.learned_plant()
        self.platform.add(T0 + hours * HOUR + 60, PLC2, PLC1, action="WRITE_SINGLE_COIL", is_orig="T")
        self.run_at(hours + 1)
        found = self.findings()
        self.assertEqual([finding["kind"] for finding in found], ["new-master"])
        self.assertEqual(found[0]["client"], PLC2)
        self.assertIn("until now it only answered", found[0]["text"])
        self.assertEqual(found[0]["actions"], ["WRITE_SINGLE_COIL"])

    def test_new_device_new_service_new_pair_new_operation(self):
        self.platform.poll(0, self.LEARN_DAYS * 24, ENG, "10.0.1.60", protocol="s7comm", action="Read Var")   # known, but only by S7
        hours = self.learned_plant()
        at = T0 + hours * HOUR
        self.platform.poll(hours, 1, ENG, "10.0.1.60", protocol="s7comm", action="Read Var")
        self.platform.add(at + 10, HMI, "10.0.1.50")                                     # a device never seen answers
        self.platform.add(at + 11, "10.0.1.50", HMI, is_orig="F")
        self.platform.add(at + 15, HMI, "10.0.1.60")                                     # a known device answers Modbus for the first time
        self.platform.add(at + 20, HMI, PLC2, protocol="s7comm", action="Read Var")       # the HMI speaks S7 for the first time
        self.platform.add(at + 30, ENG, PLC3, action="READ_COILS")                        # ENG speaks Modbus for the first time
        self.platform.add(at + 40, HMI, PLC2, action="READ_DEVICE_IDENTIFICATION")        # a new operation, nothing changes
        self.platform.add(at + 41, HMI, PLC2, action="WRITE_MULTIPLE_REGISTERS")          # a new operation that changes something
        self.platform.add(at + 50, HMI, PLC3, action="DIAGNOSTICS")
        self.run_at(hours + 1)
        by_kind = {}
        for finding in self.findings():
            by_kind.setdefault(finding["kind"], []).append(finding)
        self.assertEqual(sorted(by_kind), ["new-control-operation", "new-device", "new-master", "new-operation", "new-service"])
        self.assertEqual((by_kind["new-device"][0]["server"], by_kind["new-device"][0]["client"]), ("10.0.1.50", None))
        self.assertIn(f"Talking to it: {HMI} (modbus)", by_kind["new-device"][0]["text"])
        self.assertEqual([(f["server"], f["protocol"]) for f in by_kind["new-service"]], [("10.0.1.60", "modbus")],
                         "PLC2 answering S7 is not a finding of its own: the one about the HMI as a new S7 master names it")
        self.assertIn(f"Asking: {HMI}", by_kind["new-service"][0]["text"])
        self.assertEqual(len(by_kind["new-master"]), 2, "ENG as a modbus master, and the HMI as an s7comm master, each for the first time")
        self.assertEqual(sorted(finding["client"] for finding in by_kind["new-master"]), sorted([ENG, HMI]))
        hmi = [finding for finding in by_kind["new-master"] if finding["client"] == HMI][0]
        self.assertIn("it was a master of other protocols before", hmi["text"])
        self.assertIn(f"It talked to: {PLC2}", hmi["text"])
        control = by_kind["new-control-operation"][0]
        self.assertEqual((control["client"], control["server"]), (HMI, PLC2))
        self.assertEqual(control["actions"], ["READ_DEVICE_IDENTIFICATION", "WRITE_MULTIPLE_REGISTERS"], "one finding for the pair, both named")
        self.assertEqual(by_kind["new-operation"][0]["actions"], ["DIAGNOSTICS"])

    def test_known_master_to_known_device_for_the_first_time(self):
        self.platform.poll(0, self.LEARN_DAYS * 24, ENG, PLC1)        # ENG is known, as a master of PLC1 only
        hours = self.learned_plant()
        self.platform.add(T0 + hours * HOUR + 10, ENG, PLC2, action="READ_COILS")
        self.run_at(hours + 1)
        self.assertEqual([(f["kind"], f["client"], f["server"]) for f in self.findings()], [("new-pair", ENG, PLC2)])
        self.assertIn("Operations: READ_COILS", self.findings()[0]["text"])

    def test_a_sweep_is_one_finding(self):
        hours = self.LEARN_DAYS * 24
        self.platform.poll(0, hours, ENG, PLC1)
        for number in range(7):
            self.platform.poll(0, hours, HMI, f"10.0.2.{number}")
        self.learned_plant()
        for number in range(7):                                    # seven controllers ENG never talked to, in one hour
            self.platform.add(T0 + hours * HOUR + 20 + number, ENG, f"10.0.2.{number}", action="READ_DEVICE_IDENTIFICATION")
        self.run_at(hours + 1)
        self.assertEqual([finding["kind"] for finding in self.findings()], ["sweep"])
        self.assertIn("to 7 devices it never talked to before", self.findings()[0]["text"])
        self.assertEqual((self.findings()[0]["client"], self.findings()[0]["server"]), (ENG, None))

    def test_the_running_hour_is_read_for_what_is_new_and_not_reported_twice(self):
        hours = self.learned_plant()
        self.platform.poll(hours, 1, HMI, PLC1)
        self.platform.add(T0 + hours * HOUR + 15 * 60, "10.0.0.99", PLC1, action="WRITE_SINGLE_COIL")
        self.run_at(hours, minutes=30)                      # the hour is still running; the record is 15 minutes old
        self.assertEqual([finding["kind"] for finding in self.findings()], ["new-master"])
        op = self.state()["ops"][f"10.0.0.99|{PLC1}|modbus|WRITE_SINGLE_COIL"]
        self.assertEqual((op["n"], op["mx"]), (0, 0), "counted when the hour is over, not before")
        self.run_at(hours, minutes=45)
        self.run_at(hours + 1)
        self.assertEqual(len(self.findings()), 1)
        op = self.state()["ops"][f"10.0.0.99|{PLC1}|modbus|WRITE_SINGLE_COIL"]
        self.assertEqual((op["n"], op["mx"]), (1, 1))
        self.assertEqual(self.state()["pairs"][f"{HMI}|{PLC1}|modbus"]["h"], hours + 1, "the hour is counted once")

    def test_a_record_younger_than_the_lag_is_left_for_the_next_pass(self):
        hours = self.learned_plant()
        self.platform.add(T0 + hours * HOUR + 25 * 60, "10.0.0.99", PLC1)
        self.run_at(hours, minutes=30)
        self.assertEqual(self.findings(), [])
        self.run_at(hours, minutes=45)
        self.assertEqual(len(self.findings()), 1)


class RateAndSilence(BaselineCase):
    def test_burst_is_reported_once_and_does_not_become_normal(self):
        hours = self.learned_plant()
        key = f"{HMI}|{PLC1}|modbus|WRITE_SINGLE_REGISTER"
        self.assertEqual(self.state()["ops"][key]["mx"], 4)
        self.platform.poll(hours, 1, HMI, PLC1, action="WRITE_SINGLE_REGISTER", per_hour=16)     # 32 records: above 4, below 4 + 30
        self.run_at(hours + 1)
        self.assertEqual(self.findings(), [])
        for hour in range(hours + 1, hours + 4):
            self.platform.poll(hour, 1, HMI, PLC1, action="WRITE_SINGLE_REGISTER", per_hour=40)
        self.run_hours(hours + 2, hours + 4)
        bursts = self.findings("burst")
        self.assertEqual(len(bursts), 1, "three hours of it, one finding")
        self.assertIn("80 times in one hour; the most in any hour while learning was 4", bursts[0]["text"])
        self.assertEqual(self.state()["ops"][key]["mx"], 4, "what was flagged is not learned")
        self.platform.poll(hours + 8, 1, HMI, PLC1, action="WRITE_SINGLE_REGISTER", per_hour=40)
        self.run_hours(hours + 5, hours + 9)
        self.assertEqual(len(self.findings("burst")), 2, "reported again after six hours")

    def test_an_operation_that_appeared_after_learning_learns_its_own_rate_first(self):
        self.environ["TD_BASELINE_RATE_LEARN_HOURS"] = "2"
        hours = self.learned_plant()
        self.platform.poll(hours, 2, HMI, PLC2, action="READ_COILS", per_hour=30)
        self.run_hours(hours + 1, hours + 2)
        self.assertEqual([finding["kind"] for finding in self.findings()], ["new-operation"])
        op = self.state()["ops"][f"{HMI}|{PLC2}|modbus|READ_COILS"]
        self.assertEqual((op["n"], op["mx"]), (2, 60))
        self.platform.poll(hours + 2, 1, HMI, PLC2, action="READ_COILS", per_hour=120)
        self.run_at(hours + 3)
        self.assertEqual(len(self.findings("burst")), 1)

    def test_a_controller_that_stops_answering(self):
        hours = self.learned_plant()
        for hour in range(hours, hours + 6):
            self.platform.poll(hour, 1, HMI, PLC1)
            self.platform.poll(hour, 1, HMI, PLC2)             # PLC3 is gone
        self.run_hours(hours + 1, hours + 3)
        self.assertEqual(self.findings(), [], "three hours: not yet")
        self.run_at(hours + 4)
        quiet = self.findings("quiet")
        self.assertEqual(len(quiet), 1)
        self.assertEqual((quiet[0]["server"], quiet[0]["client"]), (PLC3, None))
        self.assertIn(f"{PLC3} has stopped answering", quiet[0]["text"])
        self.assertIn(f"Talking to it were: {HMI} (modbus)", quiet[0]["text"])
        self.assertEqual(quiet[0]["time"], td_baseline.iso(T0 + (hours + 4) * HOUR), "dated when it was noticed")
        self.assertIn("Last heard " + td_baseline.iso(T0 + (hours - 1) * HOUR + 2700 + 7 + 1), quiet[0]["text"])
        self.run_hours(hours + 5, hours + 6)
        self.assertEqual(len(self.findings("quiet")), 1, "said once")
        self.platform.poll(hours + 6, 1, HMI, PLC3)
        self.run_at(hours + 7)
        self.assertEqual(len(self.findings("resumed")), 1)
        self.assertNotIn("q", self.state()["pairs"][f"{HMI}|{PLC3}|modbus"])

    def test_a_master_that_stops_and_a_single_conversation_that_stops(self):
        hours = self.LEARN_DAYS * 24
        self.platform.poll(0, hours, ENG, PLC1)
        self.platform.poll(0, hours, ENG, PLC2)
        self.learned_plant()
        for hour in range(hours, hours + 5):                   # the HMI carries on, but no longer with PLC3; ENG is switched off
            self.platform.poll(hour, 1, HMI, PLC1)
            self.platform.poll(hour, 1, HMI, PLC2)
        self.run_hours(hours + 1, hours + 5)
        quiet = {(finding["client"], finding["server"]): finding["text"] for finding in self.findings("quiet")}
        self.assertEqual(sorted(quiet, key=str), sorted([(None, PLC3), (ENG, None)], key=str))
        self.assertIn(f"{PLC3} has stopped answering", quiet[(None, PLC3)])
        self.assertIn(f"{ENG} has stopped asking", quiet[(ENG, None)])
        self.assertIn(f"It was talking to: {PLC1} (modbus), {PLC2} (modbus)", quiet[(ENG, None)])

    def test_an_occasional_conversation_going_away_is_not_reported(self):
        hours = self.LEARN_DAYS * 24
        for hour in range(0, hours, 6):                        # a historian reading four times a day
            self.platform.poll(hour, 1, ENG, PLC1)
        self.learned_plant()
        for hour in range(hours, hours + 12):
            self.platform.poll(hour, 1, HMI, PLC1)
            self.platform.poll(hour, 1, HMI, PLC2)
            self.platform.poll(hour, 1, HMI, PLC3)
        self.run_hours(hours + 1, hours + 12)
        self.assertEqual(self.findings(), [])

    def test_a_sensor_outage_is_one_finding_not_every_device(self):
        hours = self.learned_plant()
        self.run_hours(hours + 1, hours + 3)                   # nothing at all arrives
        self.assertEqual(self.findings(), [])
        self.run_at(hours + 4)
        self.assertEqual([finding["kind"] for finding in self.findings()], ["sensor-silent"])
        self.run_hours(hours + 5, hours + 9)
        self.assertEqual(len(self.findings()), 1)
        for hour in range(hours + 9, hours + 12):              # traffic is back: nothing went quiet, the sensor did
            for plc in (PLC1, PLC2, PLC3):
                self.platform.poll(hour, 1, HMI, plc)
        self.run_hours(hours + 10, hours + 12)
        self.assertEqual(len(self.findings()), 1)
        self.assertFalse(self.state()["silent"])


class Delivery(BaselineCase):
    def intruder(self, hours):
        self.platform.add(T0 + hours * HOUR + 300, "10.0.0.99", PLC1, action="WRITE_SINGLE_COIL", is_orig="T")

    def test_alerts_are_off_until_switched_on(self):
        hours = self.learned_plant()
        self.intruder(hours)
        self.run_at(hours + 1)
        self.assertEqual(len(self.findings()), 1)
        self.assertEqual(self.findings()[0]["delivered"], False)
        self.assertEqual(self.platform.alerts, [])
        self.assertEqual(self.state()["outbox"], [], "what was found while alerts were off is not sent later")
        code, out, _ = self.command("alerts", "on")
        self.assertEqual((code, out.strip()), (0, "Alerts ON."))
        self.platform.add(T0 + (hours + 1) * HOUR + 300, PLC2, PLC3, action="WRITE_SINGLE_COIL", is_orig="T")
        self.run_at(hours + 2)
        self.assertEqual(len(self.platform.alerts), 1)

    def test_alert_as_the_product_stores_it(self):
        hours = self.learned_plant()
        self.command("alerts", "on")
        self.platform.add(T0 + hours * HOUR + 300, HMI, PLC2, action="WRITE_MULTIPLE_REGISTERS", is_orig="T")
        self.intruder(hours)
        self.run_at(hours + 1)
        records = {record["event"]["reason"]: record for record in self.platform.alerts}
        self.assertEqual(sorted(records), ["New control operation between a master and a device", "New industrial master"])
        for record in records.values():
            self.assertEqual(record.get("conflicts", {"event": {}}), {"event": {}},
                             "nothing in the alert collides with what the webhook sets itself "
                             "(the product leaves an empty entry for an object both sides fill)")
            self.assertEqual(record["rule"]["name"], "TechDetechtives OT Baseline")
            self.assertEqual(record["event"]["dataset"], "alerting")
            self.assertTrue(record["event"]["id"].startswith("td-"))
            self.assertEqual(record[TIME_FIELD], td_baseline.iso(T0 + hours * HOUR + 300), "dated when it happened, not when it was found")
            self.assertEqual(record["tags"][0], "td-baseline")
            self.assertEqual(record["threat"]["framework"], "MITRE ATT&CK for ICS")
        master = records["New industrial master"]
        self.assertEqual((master["source"], master["related"], master["event"]["severity"]),
                         ({"ip": ["10.0.0.99"]}, {"ip": ["10.0.0.99"]}, 80))
        self.assertNotIn("destination", master)
        self.assertEqual(master["threat"]["technique"], {"id": ["T0848"], "name": ["Rogue_Master"]})
        self.assertEqual(master["threat"]["tactic"], {"id": ["TA0108"], "name": ["Initial_Access"]})
        self.assertIn("never seen before", master["message"])
        control = records["New control operation between a master and a device"]
        self.assertEqual((control["source"], control["destination"], control["network"]),
                         ({"ip": [HMI]}, {"ip": [PLC2]}, {"protocol": ["modbus"]}))
        self.assertEqual(control["event"]["action"], ["WRITE_MULTIPLE_REGISTERS"])
        self.assertEqual(control["threat"]["technique"]["subtechnique"], {"id": ["T1692.001"], "name": ["Command_Message"]})
        self.assertEqual(control["event"]["severity"], 60)
        self.assertTrue(all(finding["delivered"] for finding in self.findings()))

    def test_a_webhook_that_is_down_gets_the_alert_later_and_once(self):
        hours = self.learned_plant()
        self.command("alerts", "on")
        self.intruder(hours)
        self.platform.refuse_alerts = True
        code, _, err = self.command("run", now=T0 + (hours + 1) * HOUR + 660)
        self.assertEqual(code, 1)
        self.assertIn("alert webhook", err)
        self.assertEqual(len(self.state()["outbox"]), 1)
        self.assertIn("waiting because the alert webhook did not take them", self.command("status", now=T0 + (hours + 1) * HOUR + 700)[1])
        self.platform.refuse_alerts = False
        self.run_at(hours + 2)
        self.run_at(hours + 3)
        self.assertEqual(len(self.platform.alerts), 1)
        self.assertEqual(self.state()["outbox"], [])

    def test_too_many_findings_in_one_pass(self):
        self.environ["TD_BASELINE_MAX_ALERTS_PER_RUN"] = "5"
        hours = self.learned_plant()
        self.command("alerts", "on")
        for number in range(12):                               # twelve addresses nobody has seen, each a master of one controller
            self.platform.add(T0 + hours * HOUR + 60 + number, f"10.9.9.{number}", PLC1, action="READ_COILS")
        self.platform.add(T0 + hours * HOUR + 30, HMI, PLC3, action="DIAGNOSTICS")
        self.run_at(hours + 1)
        self.assertEqual(len(self.findings()), 14, "all recorded: twelve masters, one new operation, one note")
        reasons = [record["event"]["reason"] for record in self.platform.alerts]
        self.assertEqual(sorted(reasons), ["More findings than one pass sends as alerts"] + ["New industrial master"] * 5,
                         "the most serious are sent, and a note saying how many were not")
        self.assertIn("8 more findings", [r for r in self.platform.alerts if "More findings" in r["event"]["reason"]][0]["message"])

    def test_search_failure_changes_nothing_and_is_said(self):
        hours = self.learned_plant()
        before = self.state()
        self.platform.refuse_search = True
        code, _, err = self.command("run", now=T0 + (hours + 2) * HOUR + 660)
        self.assertEqual(code, 1)
        self.assertIn("reading OpenSearch", err)
        after = self.state()
        self.assertEqual(after["cursor"], before["cursor"])
        self.assertEqual(after["hosts"], before["hosts"])
        self.assertIn("errors: reading OpenSearch", self.command("status", now=T0 + (hours + 2) * HOUR + 700)[1])
        self.platform.refuse_search = False
        self.platform.poll(hours, 2, HMI, PLC1)
        self.run_at(hours + 2)
        self.assertEqual(self.state()["cursor"], T0 // HOUR + hours + 2, "the hours it could not read are read now")


class UploadedCaptures(BaselineCase):
    """A capture file handed to the product is analysed like live traffic and stored beside it,
    at the times in the capture, with the node name "<name>-upload"."""

    def ordinary(self, first_hour, hours):
        for plc in (PLC1, PLC2, PLC3):
            self.platform.poll(first_hour, hours, HMI, plc)
        self.platform.poll(first_hour, hours, HMI, PLC1, action="WRITE_SINGLE_REGISTER", per_hour=2)

    def test_an_uploaded_capture_is_not_learned_and_not_reported(self):
        hours = self.learned_plant()
        # Someone uploads a capture of an attack that carries today's times: an unknown master stopping a controller.
        for step in range(6):
            self.platform.add(T0 + hours * HOUR + 600 * step, "10.66.6.6", PLC1, "modbus", "WRITE_SINGLE_COIL", is_orig="T",
                              node="malcolm-upload", tags=["incident7"])
        self.ordinary(hours, 2)
        self.run_hours(hours, hours + 2)
        self.assertEqual(self.findings(), [], "an uploaded capture is not the plant's own traffic")
        self.assertNotIn("10.66.6.6", self.state()["hosts"])
        # The same records from the sensor itself are reported.
        self.platform.add(T0 + (hours + 2) * HOUR + 60, "10.66.6.6", PLC1, "modbus", "WRITE_SINGLE_COIL", is_orig="T", node="sensor1")
        self.ordinary(hours + 2, 1)
        self.run_at(hours + 3)
        self.assertEqual([found["kind"] for found in self.findings()], ["new-master"])

    def test_an_old_capture_uploaded_before_the_first_pass_is_not_taken_for_history(self):
        # First pass reads what is stored. A test capture uploaded last week must not become what is normal.
        self.platform.poll(-48, 48, "10.66.6.6", PLC1, node="malcolm-upload")
        self.platform.poll(0, 2, HMI, PLC1)
        self.run_at(2)
        self.assertEqual(sorted(self.state()["hosts"]), sorted([HMI, PLC1]))

    def test_uploads_can_be_counted_as_the_plants_own_traffic(self):
        self.environ["TD_BASELINE_INCLUDE_UPLOADS"] = "true"
        self.platform.poll(0, 2, HMI, PLC1, node="malcolm-upload")
        self.run_at(2)
        self.assertIn(HMI, self.state()["hosts"])
        self.assertEqual(self.platform.searches[0]["query"]["bool"]["must_not"][2:], [])

    def test_check_says_when_traffic_is_marked_as_read_from_capture_files(self):
        # A system whose Zeek analyses rotated capture files instead of the interface: the product marks ALL its
        # records the way it marks an upload (read in its source), and the baseline would silently read nothing.
        self.platform.poll(0, 2, HMI, PLC1, node="malcolm-upload")
        code, out, _ = self.command("check", now=T0 + HOUR + 660)
        self.assertEqual(code, 0)
        self.assertIn("0 conversations and 0 operations", out)
        self.assertIn("Left out: 1 operations in the same hour from records the product marks as read from capture files", out)
        self.assertIn("TD_BASELINE_INCLUDE_UPLOADS=true", out)
        for yes in ("true", "on", "YES", "1"):
            self.environ["TD_BASELINE_INCLUDE_UPLOADS"] = yes
            code, out, _ = self.command("check", now=T0 + HOUR + 660)
            self.assertIn("1 conversations and 1 operations", out, yes)
            self.assertNotIn("Left out", out)
        self.environ["TD_BASELINE_INCLUDE_UPLOADS"] = "false"
        self.platform.docs.clear()
        self.platform.poll(0, 2, HMI, PLC1, node="sensor1")
        code, out, _ = self.command("check", now=T0 + HOUR + 660)
        self.assertNotIn("Left out", out, "live traffic only: nothing to say")

    def test_scope(self):
        uploaded = {"wildcard": {"node": {"value": "*-upload"}}}
        self.assertEqual(td_baseline.scope_clauses(), ([], [uploaded]))
        self.assertEqual(td_baseline.scope_clauses("include"), ([], []))
        self.assertEqual(td_baseline.scope_clauses("only", "incident7"), ([{"term": {"tags": "incident7"}}, uploaded], []))
        self.assertEqual(td_baseline.scope_clauses("include", "x"), ([{"term": {"tags": "x"}}], []))


class SearchAndRecords(BaselineCase):
    def test_the_search_that_is_sent(self):
        self.platform.poll(0, 1, HMI, PLC1)
        self.run_at(1)
        body = self.platform.searches[0]
        self.assertEqual(body["query"]["bool"]["filter"][0], {"range": {"firstPacket": {
            "gte": (T0 - 71 * HOUR) * 1000, "lt": (T0 - 65 * HOUR) * 1000, "format": "epoch_millis"}}},
            "three days back from the first pass, six hours at a time")
        self.assertEqual(body["query"]["bool"]["filter"][1:], [
            {"term": {"event.category": "ot"}},
            {"terms": {"network.protocol": sorted(td_baseline.PROTOCOLS)}},
            {"exists": {"field": "source.ip"}},
            {"exists": {"field": "destination.ip"}},
        ])
        self.assertEqual(body["query"]["bool"]["must_not"], [
            {"terms": {"event.dataset": td_baseline.SKIP_DATASETS}}, {"terms": {"event.provider": ["suricata", "malcolm"]}},
            {"wildcard": {"node": {"value": "*-upload"}}}])
        self.assertIn("conn", td_baseline.SKIP_DATASETS)
        self.assertEqual(body["aggs"]["keys"]["composite"]["sources"], [
            {"hour": {"date_histogram": {"field": "firstPacket", "fixed_interval": "1h"}}},
            {"src": {"terms": {"field": "source.ip"}}},
            {"dst": {"terms": {"field": "destination.ip"}}},
            {"proto": {"terms": {"field": "network.protocol"}}},
            {"action": {"terms": {"field": "event.action", "missing_bucket": True}}},
            {"is_orig": {"terms": {"field": "network.is_orig", "missing_bucket": True}}},
        ])
        self.assertEqual(body["aggs"]["keys"]["composite"]["size"], 2000)
        self.assertEqual(set(self.platform.auth_seen), {"Basic cmVhZGVyOnMzY3JldDp3aXRoOmNvbG9ucw=="},
                         "the reader's name and password from the product's own settings file")

    def test_results_are_read_page_by_page(self):
        self.environ["TD_BASELINE_PAGE_SIZE"] = "3"
        self.learned_plant(hours=48)
        self.assertGreater(len(self.platform.searches), 60)
        self.assertEqual(self.state()["pairs"][f"{HMI}|{PLC2}|modbus"]["h"], 48)
        self.assertEqual(self.state()["ops"][f"{HMI}|{PLC1}|modbus|READ_HOLDING_REGISTERS"]["mx"], 8)

    def test_what_counts_as_industrial_traffic(self):
        hours = self.learned_plant()
        at = T0 + hours * HOUR
        self.platform.add(at + 5, "10.0.0.99", PLC1, **{"event.category": ["network"]})                         # not industrial
        self.platform.add(at + 6, "10.0.0.98", PLC1, **{"event.dataset": "alert", "event.provider": "suricata"})  # a rule alert about it
        self.platform.add(at + 7, "10.0.0.97", PLC1, **{"event.dataset": "alerting", "event.provider": "malcolm"})  # this program's own alerts
        self.platform.add(at + 8, "10.0.0.96", PLC1, **{"event.dataset": "notice"})
        self.platform.add(at + 9, "10.0.0.95", None)                                                             # no destination
        # The product marks every record of a device with an industrial vendor's network card as "ot":
        # its time synchronisation and its web pages are not industrial protocols.
        self.platform.add(at + 10, PLC1, "10.0.0.123", protocol="ntp", action=None, **{"event.dataset": "ntp"})
        self.platform.add(at + 11, "10.0.0.94", PLC1, protocol=["http", "tcp"], action="GET", **{"event.dataset": "http"})
        # A connection summary names no operation and is written when a connection ends.
        self.platform.add(at + 12, "10.0.0.93", PLC1, action=None, **{"event.dataset": "conn"})
        self.run_at(hours + 1)
        self.assertEqual(self.findings(), [])
        self.assertEqual(len(self.state()["hosts"]), 4)

    def test_direction_marks_and_records_with_several_values(self):
        hours = self.learned_plant()
        at = T0 + hours * HOUR
        for mark in ("F", "false", False, "False"):            # answers, however the decoder spelled it: the HMI stays the master
            self.platform.add(at + 5, PLC2, HMI, is_orig=mark)
        self.platform.add(at + 6, HMI, PLC2, is_orig="true")
        self.platform.add(at + 7, HMI, PLC2, is_orig=True)
        self.platform.add(at + 8, HMI, PLC1, protocol=["cip", "enip"], action=["Get_Attribute_All", "List_Identity"], **{"event.dataset": "cip"})
        self.platform.add(at + 9, HMI, PLC1, action=None)       # a record with no operation name
        self.run_at(hours + 1)
        kinds = sorted((finding["kind"], finding["protocol"]) for finding in self.findings())
        self.assertEqual(kinds, [("new-master", "cip"), ("new-master", "enip"), ("new-operation", "modbus")],
                         "a record naming two protocols counts under each")
        self.assertEqual(self.state()["hosts"][PLC2]["c"], [])
        self.assertIn("an unnamed operation", self.findings("new-operation")[0]["text"])
        self.assertIn(f"{HMI}|{PLC1}|cip|List_Identity", self.state()["ops"])

    def test_answers_do_not_make_operations_and_iec104_is_not_turned_round(self):
        hours = self.learned_plant()
        at = T0 + hours * HOUR
        # An error answer: the decoder names it after the request plus _EXCEPTION. It is the same operation.
        self.platform.add(at + 5, HMI, PLC1, action="WRITE_SINGLE_REGISTER", is_orig="T")
        self.platform.add(at + 6, PLC1, HMI, action=["WRITE_SINGLE_REGISTER_EXCEPTION", "WRITE_SINGLE_REGISTER"], is_orig="F")
        # S7 names the answer differently from the request; an answer alone is not a new operation.
        self.platform.add(at + 7, PLC2, HMI, action="Ack_Data:Read Var", is_orig="F")
        self.run_at(hours + 1)
        self.assertEqual(self.findings(), [])
        self.assertFalse([key for key in self.state()["ops"] if "EXCEPTION" in key or "Ack_Data" in key])
        self.assertEqual(self.state()["ops"][f"{HMI}|{PLC1}|modbus|WRITE_SINGLE_REGISTER"]["n"], hours + 1)
        # The IEC 104 decoder writes the connection's two ends whatever the direction of the message.
        for hour in range(0, hours):
            self.platform.add(T0 + hour * HOUR + 50, HMI, "10.0.1.20", protocol="iec104", action="M_ME_NC_1", is_orig="F",
                              **{"event.dataset": "iec104"})
        self.command("reset", "--yes", "--with-history")
        (Path(self.environ["TD_BASELINE_DIR"]) / "findings.jsonl").unlink(missing_ok=True)
        self.run_at(hours)
        state = self.state()
        self.assertEqual(state["hosts"]["10.0.1.20"]["c"], [], "the station is not made a master by a record marked as an answer")
        self.assertIn(f"{HMI}|10.0.1.20|iec104", state["pairs"])

    def test_text_from_the_network_is_made_safe_to_print(self):
        self.assertEqual(td_baseline.clean("WRITE\x1b[2J|x\n"), "WRITE?[2J/x?")
        self.assertEqual(len(td_baseline.clean("A" * 500)), 120)


class Commands(BaselineCase):
    def test_status_through_the_stages(self):
        code, out, _ = self.command("status", now=T0)
        self.assertEqual(code, 0)
        self.assertIn("No industrial traffic has been read yet.", out)
        self.assertIn("No pass has run yet.", out)
        self.assertIn("Alerts: OFF", out)
        self.platform.poll(0, 10, HMI, PLC1)
        self.run_at(10)
        out = self.command("status", now=T0 + 10 * HOUR + 900)[1]
        self.assertIn("Learning: 10 of 48 hours with traffic read so far", out)
        self.assertIn("Known: 2 addresses (1 act as masters), 1 conversations, 1 operations; 10 hours with traffic read.", out)
        self.platform.poll(10, 40, HMI, PLC1)
        self.run_at(50)
        out = self.command("status", now=T0 + 50 * HOUR + 900)[1]
        self.assertIn(f"Learning ended {td_baseline.iso(T0 + 48 * HOUR)}. Comparing since then.", out)

    def test_check_reads_and_changes_nothing(self):
        self.platform.poll(0, 2, HMI, PLC1)
        code, out, _ = self.command("check", now=T0 + HOUR + 660)
        self.assertEqual(code, 0)
        self.assertIn("in the last hour, 1 conversations and 1 operations", out)
        self.assertIn(f"{HMI} -> {PLC1}  modbus  READ_HOLDING_REGISTERS  x8", out)
        self.assertFalse((Path(self.environ["TD_BASELINE_DIR"]) / "state.json").exists())
        self.platform.refuse_search = True
        code, out, _ = self.command("check", now=T0 + HOUR + 660)
        self.assertEqual(code, 1)
        self.assertIn("Could not read OpenSearch", out)

    def test_test_alert(self):
        code, out, _ = self.command("test-alert", now=T0)
        self.assertEqual(code, 0)
        self.assertIn("Sent.", out)
        self.assertEqual(self.platform.alerts[0]["destination"], {"ip": ["192.0.2.1"]})
        self.assertIn("nothing was detected", self.platform.alerts[0]["message"])
        self.platform.refuse_alerts = True
        code, out, _ = self.command("test-alert", now=T0)
        self.assertEqual(code, 1)
        self.assertIn("did not take it", out)

    def test_dry_run_saves_and_sends_nothing(self):
        hours = self.learned_plant()
        self.command("alerts", "on")
        before = (Path(self.environ["TD_BASELINE_DIR"]) / "state.json").read_text()
        self.platform.add(T0 + hours * HOUR + 300, "10.0.0.99", PLC1)
        code, out, _ = self.command("run", "--dry-run", now=T0 + (hours + 1) * HOUR + 660)
        self.assertEqual(code, 0)
        self.assertIn("new-master", out)
        self.assertIn("1 findings; nothing saved or sent.", out)
        self.assertEqual((Path(self.environ["TD_BASELINE_DIR"]) / "state.json").read_text(), before)
        self.assertEqual((self.platform.alerts, self.findings()), ([], []))

    def test_forget_findings_and_reset(self):
        hours = self.learned_plant()
        self.platform.add(T0 + hours * HOUR + 300, "10.0.0.99", PLC1)
        self.run_at(hours + 1)
        code, out, _ = self.command("findings")
        self.assertIn("new-master", out)
        self.assertEqual(len(out.strip().splitlines()), 1)
        code, out, _ = self.command("forget", "10.0.0.99")
        self.assertEqual(code, 0)
        state = self.state()
        self.assertNotIn("10.0.0.99", state["hosts"])
        self.assertFalse([key for key in list(state["pairs"]) + list(state["ops"]) if "10.0.0.99" in key])
        self.assertEqual(len(state["pairs"]), 3, "other conversations are untouched")
        self.assertEqual(self.command("forget", "10.0.0.99")[0], 1)
        self.platform.add(T0 + (hours + 1) * HOUR + 300, "10.0.0.99", PLC1)
        self.run_at(hours + 2)
        self.assertEqual(len(self.findings("new-master")), 2, "reported again after being forgotten")
        self.command("alerts", "on")
        with self.assertRaises(SystemExit):
            self.command("reset")
        self.assertEqual(self.command("reset", "--yes")[0], 0)
        state = self.state()
        self.assertEqual((state["hosts"], state["cursor"], state["alerts"], state["backfill"]), ({}, None, True, False))

    def test_a_second_pass_at_the_same_time_stands_aside(self):
        store = td_baseline.Store(self.environ["TD_BASELINE_DIR"])
        store.prepare()
        self.assertTrue(store.lock())
        self.addCleanup(store.unlock)
        code, _, err = self.command("run", now=T0)
        self.assertEqual(code, 0)
        self.assertIn("Another pass is still running", err)
        self.assertFalse((Path(self.environ["TD_BASELINE_DIR"]) / "state.json").exists())

    def test_settings_file_of_the_product(self):
        path = Path(self.tmp.name) / "rc"
        for text, expected in (('user: "admin:pa:ss"\n', ("admin", "pa:ss")), ('--user "a\\"b:c"\n', ('a"b', "c")),
                               ("insecure\n", (None, None)), ("", (None, None))):
            path.write_text(text)
            self.assertEqual(td_baseline.read_curlrc(str(path)), expected, text)
        self.assertEqual(td_baseline.read_curlrc(str(path) + ".missing"), (None, None))
        settings = td_baseline.Settings({})
        self.assertEqual((settings.opensearch_url, settings.index, settings.time_field, settings.alert_url, settings.verify_tls),
                         ("https://opensearch:9200", "arkime_sessions3-*", "firstPacket", "http://api:5000/mapi/alert", False))
        self.assertEqual(td_baseline.Settings({"TD_BASELINE_LEARN_DAYS": "x"}).learn_days, 14)


class WhatTheReviewFound(BaselineCase):
    """One test for each defect an independent review demonstrated in the first version."""

    def test_an_incomplete_answer_is_refused_not_taken_as_silence(self):
        hours = self.learned_plant()
        before = self.state()["cursor"]
        self.platform.partial = True
        for hour in range(hours + 1, hours + 7):
            code, _, err = self.command("run", now=T0 + hour * HOUR + 660)
            self.assertEqual(code, 1)
            self.assertIn("answered only in part", err)
        self.assertEqual(self.state()["cursor"], before, "the hours are still to be read")
        self.assertEqual(self.findings(), [], "no 'sensor silent', no device 'gone quiet'")
        self.platform.partial = False
        for hour in range(hours, hours + 6):
            for plc in (PLC1, PLC2, PLC3):
                self.platform.poll(hour, 1, HMI, plc)
        self.run_at(hours + 6)
        self.assertEqual(self.state()["cursor"], T0 // HOUR + hours + 6)
        self.assertEqual(self.findings(), [])

    def test_a_new_installation_with_no_index_yet(self):
        self.platform.no_index = True
        self.run_at(1)
        self.assertIn("No industrial traffic has been read yet.", self.command("status", now=T0 + HOUR)[1])

    def test_stored_traffic_is_kept_step_by_step_when_a_later_step_fails(self):
        self.environ["TD_BASELINE_STEP_HOURS"] = "6"
        self.platform.poll(0, 48, HMI, PLC1)
        real_search, calls = self.platform.search, []

        def failing(body):
            calls.append(1)
            if len(calls) == 4:
                raise RuntimeError("out of memory")
            return real_search(body)
        self.platform.search = failing
        code, _, err = self.command("run", now=T0 + 48 * HOUR + 660)
        self.assertEqual(code, 1)
        state = self.state()
        self.assertEqual(state["cursor"], T0 // HOUR + 48 - 72 + 18, "three steps of six hours were read and kept")
        self.assertEqual(state["step"], 3, "and the next pass asks for less at a time")
        self.platform.search = real_search
        self.run_at(48, minutes=26)
        self.assertEqual(self.state()["pairs"][f"{HMI}|{PLC1}|modbus"]["h"], 48)
        self.assertEqual(self.state()["step"], 6)

    def test_a_wrong_clock_at_the_first_pass(self):
        self.platform.poll(0, 3, HMI, PLC1)
        self.command("run", now=T0 - 700 * 24 * HOUR)            # two years behind
        self.run_at(3)
        self.assertEqual(self.state()["first_hour"], T0 // HOUR, "the corrected clock is used at once")
        self.command("reset", "--yes", "--with-history")
        self.command("run", now=T0 + 400 * 24 * HOUR)            # a year ahead, nothing read yet
        self.run_at(3)
        self.assertEqual(self.state()["first_hour"], T0 // HOUR)
        # Once traffic has been read, a clock that jumps back is said, and nothing is read or lost.
        before = self.state()
        code, _, err = self.command("run", now=T0 - 5 * HOUR)
        self.assertEqual(code, 1)
        self.assertIn("the clock", err)
        self.assertEqual(self.state()["hosts"], before["hosts"])

    def test_a_record_that_arrives_late_is_still_seen(self):
        hours = self.learned_plant()
        self.platform.poll(hours, 3, HMI, PLC1)
        self.run_at(hours + 3)
        # Written by the sensor three hours ago, stored only now.
        self.platform.add(T0 + hours * HOUR + 600, "10.0.0.99", PLC1, action="WRITE_SINGLE_COIL")
        self.run_at(hours + 3, minutes=26)
        self.assertEqual([found["kind"] for found in self.findings()], ["new-master"])
        self.assertEqual(self.findings()[0]["time"], td_baseline.iso(T0 + hours * HOUR + 600))
        self.run_at(hours + 4)
        self.assertEqual(len(self.findings()), 1)

    def test_what_a_new_master_did_is_in_the_finding(self):
        hours = self.learned_plant()
        self.command("alerts", "on")
        for action in ("WRITE_MULTIPLE_REGISTERS", "WRITE_FILE_RECORD"):
            self.platform.add(T0 + hours * HOUR + 60, "10.0.0.99", PLC1, action=action)
        self.run_at(hours + 1)
        found = self.findings()
        self.assertEqual([(f["kind"], f["actions"]) for f in found], [("new-master", ["WRITE_FILE_RECORD", "WRITE_MULTIPLE_REGISTERS"])])
        self.assertIn("Operations: WRITE_FILE_RECORD, WRITE_MULTIPLE_REGISTERS.", found[0]["text"])
        self.assertEqual(self.platform.alerts[0]["event"]["action"], ["WRITE_FILE_RECORD", "WRITE_MULTIPLE_REGISTERS"])

    def test_a_known_master_reaching_many_devices_never_seen_is_a_sweep(self):
        hours = self.learned_plant()
        for number in range(12):
            self.platform.add(T0 + hours * HOUR + 60 + number, HMI, f"10.0.3.{number}", action="READ_DEVICE_IDENTIFICATION")
        self.run_at(hours + 1)
        found = self.findings()
        self.assertEqual([f["kind"] for f in found], ["sweep"], "one finding, not twelve new devices")
        self.assertIn("to 12 devices it never talked to before, 12 of them never seen at all", found[0]["text"])

    def test_a_replaced_master_does_not_make_the_controllers_quiet(self):
        hours = self.learned_plant()
        new_hmi = "10.0.0.7"
        for hour in range(hours, hours + 8):                   # the old HMI is gone; a new one polls the same controllers
            for plc in (PLC1, PLC2, PLC3):
                self.platform.poll(hour, 1, new_hmi, plc)
        self.run_hours(hours + 1, hours + 8)
        kinds = [(found["kind"], found["client"], found["server"]) for found in self.findings()]
        self.assertEqual(kinds, [("new-master", new_hmi, None), ("quiet", HMI, None)],
                         "the new master, and the old one gone; no controller 'stopped answering'")

    def test_what_came_and_went_while_learning_is_not_reported_when_learning_ends(self):
        self.platform.poll(0, 30, ENG, PLC1)                   # a laptop, there for the first thirty hours only
        hours = self.learned_plant()
        for hour in range(hours, hours + 8):
            for plc in (PLC1, PLC2, PLC3):
                self.platform.poll(hour, 1, HMI, plc)
        self.run_hours(hours + 1, hours + 8)
        self.assertEqual(self.findings(), [])
        self.assertEqual(self.state()["pairs"][f"{ENG}|{PLC1}|modbus"]["q"], 1)

    def test_a_device_that_was_away_is_watched_again_once_it_is_regular_again(self):
        hours = self.learned_plant()

        def others(first, count):
            for hour in range(first, first + count):
                self.platform.poll(hour, 1, HMI, PLC1)
                self.platform.poll(hour, 1, HMI, PLC2)
        others(hours, 12)                                      # PLC3 away for twelve hours
        self.run_hours(hours + 1, hours + 12)
        self.assertEqual(len(self.findings("quiet")), 1)
        others(hours + 12, 30)
        self.platform.poll(hours + 12, 30, HMI, PLC3)          # back for thirty hours
        self.run_hours(hours + 13, hours + 42)
        self.assertEqual(len(self.findings("resumed")), 1)
        others(hours + 42, 6)                                  # and away again
        self.run_hours(hours + 43, hours + 48)
        self.assertEqual(len(self.findings("quiet")), 2, "the second time is reported too")

    def test_one_old_record_does_not_end_learning(self):
        self.environ["TD_BASELINE_BACKFILL_DAYS"] = "30"
        self.platform.add(T0 - 20 * 24 * HOUR, "10.9.9.9", PLC1)        # left over from a test capture three weeks ago
        self.platform.poll(0, 4, HMI, PLC1)
        for _ in range(12):
            self.command("run", now=T0 + 4 * HOUR + 660)
        self.assertTrue(self.state()["last_run"]["caught_up"])
        self.assertIsNone(self.state()["learn_until"], "five hours with traffic are not two days' worth")
        self.platform.poll(4, 1, HMI, PLC2)
        self.run_at(5)
        self.assertEqual(self.findings(), [], "still learning: the plant is not reported as new")
        self.assertIn("Learning: 6 of 48 hours", self.command("status", now=T0 + 5 * HOUR + 700)[1])

    def test_reset_learns_from_now_unless_asked_to_read_what_is_stored(self):
        hours = self.learned_plant()
        self.platform.add(T0 + hours * HOUR + 60, "10.0.0.99", PLC1, action="WRITE_SINGLE_COIL")     # the intruder
        self.run_at(hours + 1)
        code, out, _ = self.command("reset", "--yes")
        self.assertIn("from now", out)
        self.run_at(hours + 1, minutes=26)
        state = self.state()
        self.assertEqual((state["hosts"], state["learn_until"]), ({}, None), "what is stored is not read back: the intruder is not learned")
        self.assertEqual(state["cursor"], T0 // HOUR + hours + 1)

    def test_an_alert_the_product_will_not_take_does_not_hold_back_the_others(self):
        hours = self.learned_plant()
        self.command("alerts", "on")
        real = self.platform.take_alert

        def picky(payload):
            if "10.0.0.66" in payload["alert"]["body"]:
                raise RuntimeError("mapping error")
            return real(payload)
        self.platform.take_alert = picky
        for plc in (PLC1, PLC2, PLC3):
            self.platform.poll(hours, 4, HMI, plc)                 # the plant carries on
        self.platform.add(T0 + hours * HOUR + 60, "10.0.0.66", PLC1)
        self.command("run", now=T0 + (hours + 1) * HOUR + 660)
        for hour in range(hours + 1, hours + 4):
            self.platform.add(T0 + hour * HOUR + 60, f"10.0.0.{70 + hour - hours}", PLC1)
            self.command("run", now=T0 + (hour + 1) * HOUR + 660)
        self.assertEqual(len(self.platform.alerts), 3, "the three after it arrived")
        self.assertEqual(self.state()["outbox"], [], "and it was given up after three tries")
        self.assertEqual(len(self.findings("new-master")), 4, "all four are in the findings file")

    def test_a_webhook_that_cannot_be_reached_keeps_everything_waiting(self):
        hours = self.learned_plant()
        self.command("alerts", "on")
        self.environ["TD_BASELINE_ALERT_URL"] = "http://127.0.0.1:9/mapi/alert"      # nothing listens there
        for number in range(3):
            self.platform.add(T0 + hours * HOUR + 60 + number, f"10.0.0.{90 + number}", PLC1)
        code, _, err = self.command("run", now=T0 + (hours + 1) * HOUR + 660)
        self.assertEqual(code, 1)
        self.assertEqual(len(self.state()["outbox"]), 3)
        self.environ["TD_BASELINE_ALERT_URL"] = f"http://127.0.0.1:{self.server.server_address[1]}/mapi/alert"
        self.run_at(hours + 2)
        self.assertEqual((len(self.platform.alerts), self.state()["outbox"]), (3, []))

    def test_devices_coming_back_do_not_raise_a_note_about_too_many_findings(self):
        self.environ["TD_BASELINE_MAX_ALERTS_PER_RUN"] = "2"
        hours = self.LEARN_DAYS * 24
        plcs = [f"10.0.4.{number}" for number in range(6)]
        for plc in plcs:
            self.platform.poll(0, hours, ENG, plc)
        self.learned_plant()
        self.command("alerts", "on")
        for hour in range(hours, hours + 6):
            self.platform.poll(hour, 1, HMI, PLC1)
        self.run_hours(hours + 1, hours + 6)
        self.assertEqual(len(self.platform.alerts), 3, "three things stopped in one pass: two are sent, and a note that one was not")
        sent_before = len(self.platform.alerts)
        for plc in plcs:
            self.platform.poll(hours + 6, 1, ENG, plc)
        self.platform.poll(hours + 6, 1, HMI, PLC1)
        self.run_at(hours + 7)
        self.assertEqual(len(self.findings("resumed")), 6)
        self.assertEqual(len(self.platform.alerts), sent_before, "being back is recorded, never sent, and never counted against the limit")

    def test_a_level_that_holds_for_a_day_becomes_the_new_normal(self):
        self.environ["TD_BASELINE_BURST_ABSORB_HOURS"] = "5"
        hours = self.learned_plant()
        key = f"{HMI}|{PLC1}|modbus|WRITE_SINGLE_REGISTER"
        self.platform.poll(hours, 12, HMI, PLC1, action="WRITE_SINGLE_REGISTER", per_hour=40)
        self.run_hours(hours + 1, hours + 12)
        self.assertEqual(len(self.findings("burst")), 1, "one finding for the whole run of hours")
        self.assertEqual(self.state()["ops"][key]["mx"], 80, "after five hours at the new level it is taken as normal")

    def test_an_operation_learned_in_the_last_minutes_of_learning_learns_its_rate_first(self):
        hours = self.LEARN_DAYS * 24
        self.platform.poll(hours - 1, 1, HMI, PLC2, action="READ_INPUT_REGISTERS", per_hour=3)     # began just before learning ended
        self.learned_plant()
        self.platform.poll(hours, 30, HMI, PLC2, action="READ_INPUT_REGISTERS", per_hour=36)       # its real, steady rate
        self.run_hours(hours + 1, hours + 30)
        self.assertEqual(self.findings("burst"), [])

    def test_the_list_cannot_grow_without_limit(self):
        self.environ.update(TD_BASELINE_MAX_HOSTS="10", TD_BASELINE_EXPIRE_DAYS="5")
        hours = self.learned_plant()
        self.command("alerts", "on")
        for number in range(40):                                   # forged senders
            self.platform.add(T0 + hours * HOUR + 60 + number, f"10.7.0.{number}", PLC1, protocol="bacnet", action="who_is")
        self.run_at(hours + 1)
        self.assertEqual(len(self.state()["hosts"]), 10)
        self.assertEqual(len(self.findings("list-full")), 1)
        self.assertIn("takes no more", self.findings("list-full")[0]["text"])
        self.run_at(hours + 2)
        self.assertEqual(len(self.findings("list-full")), 1, "said once a day")
        # What is not seen for five days is dropped, and is new again if it comes back.
        for hour in range(hours + 2, hours + 6 * 24, 1):
            self.platform.poll(hour, 1, HMI, PLC1)
        self.environ["TD_BASELINE_MAX_HOURS_PER_RUN"] = "200"
        self.run_at(hours + 6 * 24)
        hosts = self.state()["hosts"]
        self.assertEqual(sorted(hosts), sorted([HMI, PLC1]), "the forged addresses and the idle controllers are gone")

    def test_a_command_that_changes_the_list_waits_for_a_running_pass(self):
        self.learned_plant()
        store = td_baseline.Store(self.environ["TD_BASELINE_DIR"])
        self.assertTrue(store.lock())
        threading.Timer(1.0, store.unlock).start()
        code, out, _ = self.command("alerts", "on")
        self.assertEqual((code, out.strip()), (0, "Alerts ON."))
        self.assertTrue(self.state()["alerts"])


class AttackMapping(unittest.TestCase):
    """The techniques the program writes into its alerts are the ones the mapping table gives its findings."""

    def test_kinds_and_table_agree(self):
        reference = attack_ics.Reference()
        rows = attack_ics.read_table(attack_ics.ATTACK_DIR / "baseline-findings.csv", ("kind", "technique", "tactic", "fit", "why"))
        self.assertEqual(sorted(row["kind"] for row in rows), sorted(td_baseline.KINDS))
        for row in rows:
            title, severity, technique = td_baseline.KINDS[row["kind"]]
            self.assertIn(severity, (1, 2, 3, 4, 5))
            self.assertTrue(row["why"].strip(), row["kind"])
            if row["technique"] == "-":
                self.assertIsNone(technique, row["kind"])
                continue
            self.assertEqual(technique, row["technique"], row["kind"])
            self.assertEqual(row["fit"], "related", "a finding from a list of what is normal never sees the technique itself")
            tactic_id, tactic, parent_id, parent, sub_id, sub = td_baseline.TECHNIQUES[technique]
            self.assertEqual(tactic_id, row["tactic"])
            self.assertIn(tactic_id, reference.techniques[technique]["tactics"])
            self.assertEqual(tactic, attack_ics.tag_name(reference.tactic_names[tactic_id]))
            self.assertEqual(parent_id, reference.parent(technique))
            self.assertEqual(parent, attack_ics.tag_name(reference.techniques[parent_id]["name"]))
            if "." in technique:
                self.assertEqual((sub_id, sub), (technique, attack_ics.tag_name(reference.techniques[technique]["name"])))
            else:
                self.assertEqual((sub_id, sub), (None, None))


if __name__ == "__main__":
    unittest.main()
