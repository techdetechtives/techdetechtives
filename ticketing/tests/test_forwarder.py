# TechDetechtives forwarder tests. Copyright (c) 2026 TechDetechtives. MIT licence.
"""Run with:  python3 -m unittest discover -s ticketing/tests -v

The platform and DFIR-IRIS are replaced by small local HTTP servers, so these
tests need no network, no Docker and no extra packages.
"""

import json
import os
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "forwarder"))
import td_forwarder as fw  # noqa: E402

NOW = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)


def stamp(seconds_ago):
    return fw.iso(NOW - timedelta(seconds=seconds_ago))


def alert(doc_id, seconds_ago, severity, module="suricata", rule="ET TEST rule", extra=None):
    source = {"@timestamp": stamp(seconds_ago), "tags": ["alert"],
              "event": {"severity": severity, "module": module, "dataset": f"{module}.alert"},
              "rule": {"name": rule, "uuid": "2000001"},
              "source": {"ip": "10.0.0.5", "port": 51000}, "destination": {"ip": "203.0.113.9", "port": 443}}
    source.update(extra or {})
    return {"_id": doc_id, "_index": "logs-suricata.alerts-so", "_source": source}


class FakePlatform(BaseHTTPRequestHandler):
    docs = []
    auth = []

    def log_message(self, *args):
        pass

    def _send(self, payload):
        raw = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        type(self).auth.append(self.headers.get("Authorization"))
        self._send({"version": {"number": "9.0.8"}})

    def do_POST(self):
        type(self).auth.append(self.headers.get("Authorization"))
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        filters = body["query"]["bool"]["filter"]
        minimum = next(f["range"]["event.severity"]["gte"] for f in filters if "event.severity" in f.get("range", {}))
        window = next(f["range"]["@timestamp"] for f in filters if "@timestamp" in f.get("range", {}))
        excluded = set()
        for clause in body["query"]["bool"].get("must_not", []):
            excluded |= set(clause["ids"]["values"])
        hits = [d for d in type(self).docs
                if d["_id"] not in excluded
                and "alert" in d["_source"].get("tags", [])
                and d["_source"]["event"]["severity"] >= minimum
                and window["gte"] <= d["_source"]["@timestamp"] <= window["lte"]]
        hits.sort(key=lambda d: d["_source"]["@timestamp"])
        if self.path.split("?")[0].endswith("/_count"):
            self._send({"count": len(hits)})
        else:
            self._send({"hits": {"hits": hits[: body.get("size", 10)]}})


class FakeIris(BaseHTTPRequestHandler):
    created = []
    auth = []
    fail_status = None      # e.g. 500 to simulate an outage
    reject_refs = set()     # source refs IRIS refuses with HTTP 400

    def log_message(self, *args):
        pass

    def _send(self, code, payload):
        raw = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        type(self).auth.append(self.headers.get("Authorization"))
        tables = {
            "/manage/severities/list": [{"severity_id": i + 11, "severity_name": n} for i, n in enumerate(
                ["Unspecified", "Informational", "Low", "Medium", "High", "Critical"])],
            "/manage/alert-status/list": [{"status_id": 21, "status_name": "Unspecified"}, {"status_id": 22, "status_name": "New"}],
            "/manage/customers/list": [{"customer_id": 7, "customer_name": "IrisInitialClient"}],
        }
        self._send(200, {"status": "success", "message": "", "data": tables.get(self.path, [])})

    def do_POST(self):
        type(self).auth.append(self.headers.get("Authorization"))
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if type(self).fail_status:
            return self._send(type(self).fail_status, {"status": "error", "message": "unavailable"})
        if payload.get("alert_source_ref") in type(self).reject_refs:
            return self._send(400, {"status": "error", "message": "bad alert"})
        type(self).created.append(payload)
        self._send(200, {"status": "success", "message": "", "data": {"alert_id": len(type(self).created)}})


class ForwarderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = []
        for handler in (FakePlatform, FakeIris):
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            cls.servers.append(server)
        cls.es_url = f"http://127.0.0.1:{cls.servers[0].server_port}"
        cls.iris_url = f"http://127.0.0.1:{cls.servers[1].server_port}"

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown()

    def setUp(self):
        FakePlatform.docs, FakePlatform.auth = [], []
        FakeIris.created, FakeIris.auth, FakeIris.fail_status, FakeIris.reject_refs = [], [], None, set()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = {
            "TD_ES_HOST": "manager.example.internal", "TD_ES_URL": self.es_url, "TD_ES_API_KEY": "es-key",
            "TD_IRIS_URL": self.iris_url, "TD_IRIS_API_KEY": "iris-key",
            "TD_TICKET_STATE": str(Path(self.tmp.name) / "state.json"),
            "TD_TICKET_LAG_SECONDS": "30", "TD_TICKET_BACKFILL_MINUTES": "60",
        }

    def make(self, **overrides):
        env = dict(self.env, **overrides)
        for key in [k for k in os.environ if k.startswith("TD_")]:
            del os.environ[key]
        os.environ.update(env)
        config = fw.Config()
        state = fw.State(config.state_path)
        state.load()
        return config, fw.Platform(config), fw.Iris(config), state

    def cycle(self, now=NOW, **overrides):
        config, platform, iris, state = self.make(**overrides)
        return fw.run_cycle(config, platform, iris, state, now=now)

    def refs(self):
        return [a["alert_source_ref"] for a in FakeIris.created]

    def test_medium_and_above_become_tickets_low_does_not(self):
        FakePlatform.docs = [alert("low", 300, 1), alert("med", 240, 2), alert("high", 180, 3), alert("crit", 120, 4)]
        counts = self.cycle()
        self.assertEqual(counts["created"], 3)
        self.assertEqual(self.refs(), ["med", "high", "crit"])

    def test_events_that_are_not_alerts_are_ignored(self):
        plain = alert("conn", 200, 3)
        plain["_source"]["tags"] = ["conn"]
        FakePlatform.docs = [plain, alert("real", 100, 3)]
        self.cycle()
        self.assertEqual(self.refs(), ["real"])

    def test_one_ticket_per_alert_even_for_the_same_rule(self):
        FakePlatform.docs = [alert(f"a{i}", 200 - i, 3) for i in range(5)]
        self.assertEqual(self.cycle()["created"], 5)

    def test_second_cycle_and_restart_create_no_duplicates(self):
        FakePlatform.docs = [alert("a", 200, 2), alert("b", 100, 3)]
        self.cycle()
        self.cycle(now=NOW + timedelta(seconds=30))
        self.cycle(now=NOW + timedelta(seconds=60))   # fresh objects each time = restart from the state file
        self.assertEqual(self.refs(), ["a", "b"])

    def test_alert_indexed_late_is_still_ticketed(self):
        FakePlatform.docs = [alert("on-time", 100, 3)]
        self.cycle()
        FakePlatform.docs.append(alert("late", 400, 3))   # older timestamp, appears afterwards
        self.cycle(now=NOW + timedelta(seconds=30))
        self.assertEqual(sorted(self.refs()), ["late", "on-time"])

    def test_first_run_does_not_ticket_history(self):
        FakePlatform.docs = [alert("old", 3600, 4), alert("recent", 40, 4)]
        self.cycle(TD_TICKET_BACKFILL_MINUTES="0")
        self.assertEqual(self.refs(), [])
        FakePlatform.docs.append(alert("new", -20, 4))
        self.cycle(now=NOW + timedelta(seconds=60), TD_TICKET_BACKFILL_MINUTES="0")
        self.assertEqual(self.refs(), ["new"])

    def test_alert_inside_the_lag_window_waits_for_the_next_cycle(self):
        FakePlatform.docs = [alert("fresh", 10, 3)]
        self.assertEqual(self.cycle()["created"], 0)
        self.assertEqual(self.cycle(now=NOW + timedelta(seconds=60))["created"], 1)

    def test_iris_outage_loses_nothing(self):
        FakePlatform.docs = [alert("a", 200, 3), alert("b", 100, 3)]
        FakeIris.fail_status = 500
        counts = self.cycle()
        self.assertEqual((counts["created"], counts["failed"]), (0, 1))
        FakeIris.fail_status = None
        self.cycle(now=NOW + timedelta(seconds=30))
        self.assertEqual(self.refs(), ["a", "b"])

    def test_rejected_alert_is_skipped_after_five_attempts_and_does_not_block(self):
        FakePlatform.docs = [alert("bad", 200, 3), alert("good", 100, 3)]
        FakeIris.reject_refs = {"bad"}
        for i in range(4):
            self.cycle(now=NOW + timedelta(seconds=30 * i))
            self.assertEqual(self.refs(), [])
        counts = self.cycle(now=NOW + timedelta(seconds=150))
        self.assertEqual(counts["skipped"], 1)
        self.assertEqual(self.refs(), ["good"])

    def test_cycle_cap_carries_the_rest_over(self):
        FakePlatform.docs = [alert(f"a{i:03d}", 500 - i, 3) for i in range(250)]
        first = self.cycle(TD_TICKET_MAX_PER_CYCLE="100")
        self.assertEqual((first["created"], first["backlog"]), (100, True))
        self.cycle(now=NOW + timedelta(seconds=30), TD_TICKET_MAX_PER_CYCLE="100")
        self.cycle(now=NOW + timedelta(seconds=60), TD_TICKET_MAX_PER_CYCLE="100")
        self.assertEqual(len(self.refs()), 250)
        self.assertEqual(len(set(self.refs())), 250)

    def test_many_alerts_sharing_one_timestamp(self):
        FakePlatform.docs = [alert(f"s{i:04d}", 100, 3) for i in range(2600)] + [alert("after", 90, 3)]
        for i in range(4):
            self.cycle(now=NOW + timedelta(seconds=30 * i), TD_TICKET_MAX_PER_CYCLE="1000")
        self.assertEqual(len(set(self.refs())), len(self.refs()))
        self.assertEqual(len(self.refs()), 2601)

    def test_ticket_contents(self):
        sigma = {"_id": "sig-1", "_index": "logs-detections.alerts-so", "_source": {
            "@timestamp": stamp(100), "tags": "alert",
            "rule": {"name": "TechDetechtives - PowerShell Encoded Command With Hidden Window", "uuid": "fb81b1e9"},
            "event": {"severity": 3, "module": "sigma", "dataset": "sigma.alert", "severity_label": "high"},
            "event_data": {"host": {"name": "srv-file01"}, "user": {"name": "svc_backup"},
                           "process": {"command_line": "powershell.exe -enc AAAA"}}}}
        FakePlatform.docs = [sigma]
        FakePlatform.docs[0]["_source"]["tags"] = ["alert"]
        self.cycle()
        ticket = FakeIris.created[0]
        self.assertEqual(ticket["alert_title"], "[sigma] TechDetechtives - PowerShell Encoded Command With Hidden Window")
        self.assertEqual(ticket["alert_severity_id"], 15)      # "High" as numbered by this IRIS
        self.assertEqual(ticket["alert_status_id"], 22)        # "New"
        self.assertEqual(ticket["alert_customer_id"], 7)
        self.assertEqual(ticket["alert_source"], "TechDetechtives")
        self.assertEqual(ticket["alert_context"]["Host"], "srv-file01")
        self.assertEqual(ticket["alert_context"]["User"], "svc_backup")
        self.assertIn("Command line: powershell.exe -enc AAAA", ticket["alert_description"])
        self.assertEqual(ticket["alert_source_link"], "https://manager.example.internal/#/hunt?q=_id%3A%22sig-1%22")
        self.assertEqual(ticket["alert_tags"], "techdetechtives,sigma,high")
        self.assertEqual(ticket["alert_source_content"]["rule"]["uuid"], "fb81b1e9")
        self.assertRegex(ticket["alert_source_event_time"], r"^2026-10-04T11:58:20\.\d{6}$")

    def test_oversized_event_is_not_attached(self):
        FakePlatform.docs = [alert("big", 100, 3, extra={"payload": "x" * 300_000})]
        self.cycle()
        self.assertIn("too large", FakeIris.created[0]["alert_source_content"]["note"])

    def test_credentials_are_sent_and_not_mixed_up(self):
        FakePlatform.docs = [alert("a", 100, 3)]
        self.cycle()
        self.assertEqual(set(FakePlatform.auth), {"ApiKey es-key"})
        self.assertEqual(set(FakeIris.auth), {"Bearer iris-key"})

    def test_missing_settings_are_reported_by_name(self):
        with self.assertRaises(fw.ConfigError) as caught:
            self.make(TD_IRIS_API_KEY="", TD_ES_API_KEY="")
        self.assertIn("TD_ES_API_KEY", str(caught.exception))
        self.assertIn("TD_IRIS_API_KEY", str(caught.exception))

    def test_unknown_customer_is_a_clear_error(self):
        config, platform, iris, state = self.make(TD_IRIS_CUSTOMER="Nobody")
        with self.assertRaises(fw.ConfigError) as caught:
            iris.resolve_ids()
        self.assertIn("IrisInitialClient", str(caught.exception))

    def test_check_mode(self):
        FakePlatform.docs = [alert("a", 100, 3)]
        config, platform, iris, state = self.make()
        self.assertEqual(fw.check(config, platform, iris), 0)
        config, platform, iris, state = self.make(TD_IRIS_URL="http://127.0.0.1:1")
        self.assertEqual(fw.check(config, platform, iris), 1)


if __name__ == "__main__":
    unittest.main()
