# TechDetechtives honeypot tests. Copyright (c) 2026 TechDetechtives. MIT licence.
"""Run with:  python3 -m unittest discover -s honeypot/tests -v

The platform is replaced by a small local HTTP server and the honeypot by a
log file written in OpenCanary's format, so these tests need no network, no
Docker and no extra packages.
"""

import json
import os
import re
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "ticketing" / "forwarder"))
sys.path.insert(0, str(HERE.parent / "shipper"))
sys.path.insert(0, str(HERE.parent))
import td_forwarder as fw  # noqa: E402
import td_honeypot as hp  # noqa: E402
import make_config  # noqa: E402


NOW = datetime(2026, 10, 5, 17, 0, 0, tzinfo=timezone.utc)     # the test events happen from here on


def line(logtype, src="10.20.30.77", minute=0, second=0, dst_port=21, logdata=None, **extra):
    """One log line as OpenCanary writes it."""
    entry = {
        "dst_host": "172.28.0.2", "dst_port": dst_port,
        "local_time": "2026-10-05 17:%02d:%02d.000001" % (minute, second),
        "local_time_adjusted": "2026-10-05 10:%02d:%02d.000001" % (minute, second),
        "logdata": {} if logdata is None else logdata, "logtype": logtype, "node_id": "td-honeypot",
        "src_host": src, "src_port": 51000,
        "utc_time": "2026-10-05 17:%02d:%02d.000001" % (minute, second),
    }
    entry.update(extra)
    return json.dumps(entry, sort_keys=True)


class FakePlatform(BaseHTTPRequestHandler):
    stored = {}          # id -> document
    requests = []        # (path, authorization)
    fail_status = 0      # answer every request with this HTTP status
    item_status = {}     # document id -> status for that one item
    reject_rule = None   # documents whose rule name matches get HTTP 400

    def log_message(self, *args):
        pass

    def _send(self, status, payload):
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        type(self).requests.append((self.path, self.headers.get("Authorization")))
        if type(self).fail_status:
            return self._send(type(self).fail_status, {"error": "refused"})
        self._send(200, {"version": {"number": "9.0.8"}})

    def do_POST(self):
        cls = type(self)
        cls.requests.append((self.path, self.headers.get("Authorization")))
        body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
        if cls.fail_status:
            return self._send(cls.fail_status, {"error": "refused"})
        rows = [json.loads(row) for row in body.splitlines() if row.strip()]
        items = []
        for action, document in zip(rows[0::2], rows[1::2]):
            doc_id = action["create"]["_id"]
            if doc_id in cls.item_status:
                items.append({"create": {"status": cls.item_status[doc_id], "error": {"reason": "busy"}}})
            elif cls.reject_rule and cls.reject_rule in document["rule"]["name"]:
                items.append({"create": {"status": 400, "error": {"reason": "mapper_parsing_exception"}}})
            elif doc_id in cls.stored:
                items.append({"create": {"status": 409}})
            else:
                cls.stored[doc_id] = document
                items.append({"create": {"status": 201}})
        self._send(200, {"errors": False, "items": items})


class ShipperCase(unittest.TestCase):
    def setUp(self):
        FakePlatform.stored, FakePlatform.requests = {}, []
        FakePlatform.fail_status, FakePlatform.item_status, FakePlatform.reject_rule = 0, {}, None
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), FakePlatform)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.folder = tempfile.TemporaryDirectory()
        self.log = Path(self.folder.name) / "opencanary.log"
        self.saved_env = dict(os.environ)
        for key in [name for name in os.environ if name.startswith("TD_")]:
            del os.environ[key]
        os.environ.update({
            "TD_ES_URL": "http://127.0.0.1:%d" % self.server.server_address[1],
            "TD_HONEYPOT_API_KEY": "honeypot-key",
            "TD_HONEYPOT_LOG": str(self.log),
            "TD_HONEYPOT_STATE": str(Path(self.folder.name) / "state" / "state.json"),
            "TD_HONEYPOT_NAME": "decoy-1",
            "TD_HONEYPOT_IP": "10.20.30.60",
        })

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.folder.cleanup()
        os.environ.clear()
        os.environ.update(self.saved_env)

    def write(self, *lines, partial=""):
        with self.log.open("a", encoding="utf-8") as handle:
            for text in lines:
                handle.write(text + "\n")
            handle.write(partial)

    def run_once(self, now=NOW, **env):
        os.environ.update(env)
        config = hp.Config()
        state = hp.State(config.state_path)
        state.load()
        return hp.run_cycle(config, hp.Platform(config), state, now=now)

    def documents(self):
        return sorted(FakePlatform.stored.values(), key=lambda doc: doc["@timestamp"])

    def alerts(self):
        return [doc for doc in self.documents() if "alert" in doc["tags"]]


class AlertShape(ShipperCase):
    def test_sign_in_attempt_becomes_a_high_alert_the_forwarder_will_ticket(self):
        self.write(line(2000, logdata={"USERNAME": "admin", "PASSWORD": "hunter2"}))
        counts = self.run_once()
        self.assertEqual(counts["alerts"], 1)
        doc = self.documents()[0]
        self.assertIn("alert", doc["tags"])
        self.assertEqual(doc["event"]["severity"], 3)
        self.assertEqual(doc["event"]["severity_label"], "high")
        self.assertEqual(doc["event"]["module"], "opencanary")
        self.assertEqual(doc["rule"]["name"], "Honeypot: FTP sign-in attempt")
        self.assertEqual(doc["source"], {"ip": "10.20.30.77", "port": 51000})
        self.assertEqual(doc["destination"], {"ip": "10.20.30.60", "port": 21})
        self.assertEqual(doc["user"]["name"], "admin")
        self.assertEqual(doc["observer"]["name"], "decoy-1")
        self.assertEqual(doc["@timestamp"], "2026-10-05T17:00:00.000Z")
        # The ticket forwarder selects on exactly these and builds its title from them.
        self.assertGreaterEqual(doc["event"]["severity"], 2)
        self.assertTrue(fw.field(doc, "rule.name") and fw.field(doc, "event.module"))

    def test_goes_to_the_honeypot_data_stream_with_the_honeypot_key(self):
        self.write(line(4002, dst_port=22, logdata={"USERNAME": "root", "PASSWORD": "x"}))
        self.run_once()
        path, authorization = FakePlatform.requests[-1]
        self.assertEqual(path, "/logs-opencanary.alerts-techdetechtives/_bulk")
        self.assertEqual(authorization, "ApiKey honeypot-key")

    def test_password_is_withheld_unless_asked_for(self):
        self.write(line(2000, logdata={"USERNAME": "maria", "PASSWORD": "Real-Password-1"}),
                   line(12001, src="10.20.30.78", dst_port=5900, logdata={"VNC Password": "letmein"}),
                   line(17001, src="10.20.30.79", dst_port=6379, logdata={"CMD": "AUTH", "ARGS": "s3cret"}),
                   line(17001, src="10.20.30.80", dst_port=6379, logdata={"CMD": "KEYS", "ARGS": "*"}))
        self.run_once()
        everything = json.dumps(self.documents())
        for secret in ("Real-Password-1", "letmein", "s3cret"):
            self.assertNotIn(secret, everything)
        self.assertIn("maria", everything)
        self.assertEqual(self.documents()[0]["opencanary"]["logdata"]["password"], "(withheld)")
        self.assertEqual(self.documents()[3]["opencanary"]["logdata"]["args"], "*")

    def test_password_is_kept_when_asked_for(self):
        self.write(line(2000, logdata={"USERNAME": "maria", "PASSWORD": "Real-Password-1"}))
        self.run_once(TD_HONEYPOT_KEEP_PASSWORDS="1")
        self.assertEqual(self.documents()[0]["opencanary"]["logdata"]["password"], "Real-Password-1")

    def test_decoy_port_is_reported_as_the_port_on_the_host(self):
        self.write(line(4002, dst_port=22, logdata={"USERNAME": "root", "PASSWORD": "x"}))
        self.run_once(TD_HONEYPOT_PORT_MAP="22=2222,80=80")
        self.assertEqual(self.documents()[0]["destination"]["port"], 2222)

    def test_visitor_text_is_cleaned_and_shortened(self):
        self.write(line(3000, dst_port=80, logdata={"PATH": "/a\x00\x1b[31m" + "b" * 5000, "USERAGENT": "curl/8",
                                                    "HOSTNAME": "10.20.30.60", "SKIN": "nasLogin"}))
        self.run_once()
        doc = self.documents()[0]
        self.assertLessEqual(len(doc["url"]["path"]), 1000)
        self.assertNotRegex(doc["url"]["path"], r"[\x00\x1b]")
        self.assertEqual(doc["user_agent"]["original"], "curl/8")
        self.assertEqual(doc["event"]["severity"], 2)

    def test_unknown_event_code_is_still_reported(self):
        self.write(line(99001, logdata={"note": "custom module"}))
        self.run_once()
        doc = self.documents()[0]
        self.assertEqual(doc["rule"]["name"], "Honeypot: Honeypot event 99001")
        self.assertIn("alert", doc["tags"])

    def test_source_that_is_not_an_address_is_kept_as_text(self):
        self.write(line(2000, src="not-an-ip", logdata={"USERNAME": "a", "PASSWORD": "b"}))
        self.run_once()
        doc = self.documents()[0]
        self.assertNotIn("source", doc)
        self.assertEqual(doc["opencanary"]["src_host"], "not-an-ip")


class Repeats(ShipperCase):
    def test_brute_force_raises_one_alert_and_stores_the_rest_as_events(self):
        self.write(*[line(4002, dst_port=22, second=n, logdata={"USERNAME": "root", "PASSWORD": "p%d" % n})
                     for n in range(40)])
        counts = self.run_once()
        self.assertEqual((counts["alerts"], counts["events"]), (1, 39))
        self.assertEqual(len(self.documents()), 40)
        self.assertEqual(len(self.alerts()), 1)
        quiet = [doc for doc in self.documents() if "alert" not in doc["tags"]]
        self.assertTrue(all(doc["event"]["kind"] == "event" and "honeypot" in doc["tags"] for doc in quiet))

    def test_connection_then_sign_in_alerts_twice_because_it_got_worse(self):
        self.write(line(4000, dst_port=22, second=1), line(4001, dst_port=22, second=2),
                   line(4002, dst_port=22, second=3, logdata={"USERNAME": "root", "PASSWORD": "x"}),
                   line(4000, dst_port=22, second=9))
        self.run_once()
        self.assertEqual([doc["rule"]["name"] for doc in self.alerts()],
                         ["Honeypot: SSH connection", "Honeypot: SSH sign-in attempt"])

    def test_other_address_or_other_decoy_gets_its_own_alert(self):
        self.write(line(2000, logdata={"USERNAME": "a", "PASSWORD": "b"}),
                   line(2000, src="10.20.30.99", second=1, logdata={"USERNAME": "a", "PASSWORD": "b"}),
                   line(8001, dst_port=3306, second=2, logdata={"USERNAME": "a", "PASSWORD": "b"}))
        self.run_once()
        self.assertEqual(len(self.alerts()), 3)

    def test_alerts_again_after_the_quiet_period(self):
        self.write(line(2000, minute=0, logdata={"USERNAME": "a", "PASSWORD": "b"}),
                   line(2000, minute=29, logdata={"USERNAME": "a", "PASSWORD": "c"}),
                   line(2000, minute=31, logdata={"USERNAME": "a", "PASSWORD": "d"}))
        self.run_once()
        self.assertEqual([doc["@timestamp"][14:16] for doc in self.alerts()], ["00", "31"])

    def test_repeat_memory_survives_a_restart(self):
        self.write(line(2000, second=0, logdata={"USERNAME": "a", "PASSWORD": "b"}))
        self.run_once()
        self.write(line(2000, second=30, logdata={"USERNAME": "a", "PASSWORD": "c"}))
        self.run_once()      # a new Config and State, as after a restart
        self.assertEqual(len(self.alerts()), 1)
        self.assertEqual(len(self.documents()), 2)

    def test_backlog_split_over_batches_still_alerts_once(self):
        self.write(*[line(4002, dst_port=22, second=n % 60, minute=n // 60,
                          logdata={"USERNAME": "root", "PASSWORD": "p"}) for n in range(900)])
        self.run_once(TD_HONEYPOT_BATCH="100")       # 15 minutes of attempts, nine batches
        self.assertEqual(len(self.documents()), 900)
        self.assertEqual(len(self.alerts()), 1)

    def test_old_pairs_are_forgotten(self):
        recent = hp.Recent()
        start = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
        window = timedelta(minutes=30)
        for n in range(10):
            recent.is_new("10.0.0.%d|ftp" % n, start + timedelta(minutes=n * 20), 3, window)
        recent.prune(window)
        self.assertEqual(sorted(recent.entries), ["10.0.0.8|ftp", "10.0.0.9|ftp"])
        recent.prune(window, limit=1)
        self.assertEqual(list(recent.entries), ["10.0.0.9|ftp"])

    def test_zero_minutes_means_every_contact_alerts(self):
        self.write(*[line(2000, second=n, logdata={"USERNAME": "a", "PASSWORD": "b"}) for n in range(3)])
        self.run_once(TD_HONEYPOT_REPEAT_MINUTES="0")
        self.assertEqual(len(self.alerts()), 3)


class Filtering(ShipperCase):
    def test_own_start_up_lines_are_not_sent(self):
        self.write(line(1001, src="", logdata={"msg": {"logdata": "Added service from class CanaryFTP"}}),
                   line(1000, src=""), "[ERR] 'something went wrong'", "", "{broken json")
        counts = self.run_once()
        self.assertEqual(FakePlatform.stored, {})
        self.assertEqual((counts["ignored"], counts["malformed"]), (2, 2))

    def test_ignored_addresses_leave_no_record(self):
        self.write(line(2000, src="10.20.30.50", logdata={"USERNAME": "scan", "PASSWORD": "x"}),
                   line(2000, src="10.99.0.7", logdata={"USERNAME": "scan", "PASSWORD": "x"}),
                   line(2000, src="10.20.30.77", logdata={"USERNAME": "real", "PASSWORD": "x"}))
        self.run_once(TD_HONEYPOT_IGNORE_IPS="10.20.30.50, 10.99.0.0/16")
        self.assertEqual([doc["source"]["ip"] for doc in self.documents()], ["10.20.30.77"])

    def test_low_severity_detail_lines_never_alert(self):
        self.write(line(4001, dst_port=22, logdata={"LOCALVERSION": "SSH-2.0-x", "REMOTEVERSION": "SSH-2.0-y"}))
        self.run_once()
        self.assertEqual(len(self.documents()), 1)
        self.assertEqual(self.alerts(), [])


class Delivery(ShipperCase):
    def test_nothing_is_sent_twice_across_cycles(self):
        self.write(line(2000, logdata={"USERNAME": "a", "PASSWORD": "b"}))
        self.run_once()
        sent = len(FakePlatform.requests)
        counts = self.run_once()
        self.assertEqual(len(FakePlatform.requests), sent)
        self.assertEqual(counts["alerts"], 0)

    def test_line_still_being_written_waits_for_its_end(self):
        whole = line(2000, logdata={"USERNAME": "a", "PASSWORD": "b"})
        self.write(partial=whole[:60])
        self.run_once()
        self.assertEqual(FakePlatform.stored, {})
        self.write(partial=whole[60:] + "\n")
        self.run_once()
        self.assertEqual(len(self.documents()), 1)

    def test_outage_loses_nothing_and_duplicates_nothing(self):
        self.write(*[line(2000, src="10.20.30.%d" % n, logdata={"USERNAME": "a", "PASSWORD": "b"}) for n in range(1, 6)])
        FakePlatform.fail_status = 503
        with self.assertRaises(fw.HttpError) as raised:
            self.run_once()
        self.assertTrue(raised.exception.retryable)
        FakePlatform.fail_status = 0
        self.run_once()
        self.assertEqual(len(self.documents()), 5)
        self.assertEqual(len(self.alerts()), 5)

    def test_partly_delivered_batch_is_finished_on_the_next_try(self):
        first = line(2000, src="10.20.30.1", logdata={"USERNAME": "a", "PASSWORD": "b"})
        second = line(2000, src="10.20.30.2", logdata={"USERNAME": "a", "PASSWORD": "b"})
        self.write(first, second)
        config = hp.Config()
        busy_id = hp.to_document(second, json.loads(second), config, hp.Recent(), NOW)[0]
        FakePlatform.item_status = {busy_id: 429}
        with self.assertRaises(fw.HttpError):
            self.run_once()
        self.assertEqual(len(FakePlatform.stored), 1)
        FakePlatform.item_status = {}
        self.run_once()
        self.assertEqual(len(self.documents()), 2)

    def test_wrong_key_keeps_the_events_for_later(self):
        self.write(line(2000, logdata={"USERNAME": "a", "PASSWORD": "b"}))
        FakePlatform.fail_status = 403
        with self.assertRaises(fw.HttpError):
            self.run_once()
        FakePlatform.fail_status = 0
        self.run_once()
        self.assertEqual(len(self.documents()), 1)

    def test_one_event_the_platform_cannot_store_does_not_block_the_rest(self):
        self.write(line(2000, logdata={"USERNAME": "a", "PASSWORD": "b"}),
                   line(14001, src="10.20.30.90", dst_port=3389, logdata={"USERNAME": "b"}))
        FakePlatform.reject_rule = "FTP"
        counts = self.run_once()
        self.assertEqual(counts["rejected"], 1)
        self.assertEqual([doc["rule"]["name"] for doc in self.documents()], ["Honeypot: Remote Desktop sign-in attempt"])
        self.assertEqual(self.run_once()["alerts"], 0)      # and it is not retried forever

    def test_late_delivery_is_stamped_so_the_forwarder_still_sees_it(self):
        self.write(line(2000, logdata={"USERNAME": "a", "PASSWORD": "b"}))
        later = NOW + timedelta(hours=2)
        self.run_once(now=later)
        doc = self.documents()[0]
        self.assertEqual(doc["@timestamp"], fw.iso(later))
        self.assertEqual(doc["event"]["created"], "2026-10-05T17:00:00.000Z")
        self.assertTrue(doc["opencanary"]["delivered_late"])
        self.assertIn("delivered late", doc["message"])
        self.assertIn("alert", doc["tags"])

    def test_prompt_delivery_keeps_the_time_it_happened(self):
        self.write(line(2000, second=10, logdata={"USERNAME": "a", "PASSWORD": "b"}))
        self.run_once(now=NOW + timedelta(seconds=40))
        doc = self.documents()[0]
        self.assertEqual(doc["@timestamp"], "2026-10-05T17:00:10.000Z")
        self.assertFalse(doc["opencanary"]["delivered_late"])

    def test_log_replaced_by_a_new_file_is_read_from_the_start(self):
        self.write(line(2000, logdata={"USERNAME": "a", "PASSWORD": "b"}),
                   line(2000, second=5, logdata={"USERNAME": "a", "PASSWORD": "c"}))
        self.run_once()
        self.log.unlink()
        self.write(line(8001, src="10.20.30.91", dst_port=3306, logdata={"USERNAME": "x", "PASSWORD": "y"}))
        self.run_once()
        self.assertEqual(len(self.documents()), 3)

    def test_large_backlog_is_sent_in_batches(self):
        self.write(*[line(3000, src="10.20.%d.%d" % (n // 250, n % 250 + 1), dst_port=80,
                          logdata={"PATH": "/", "USERAGENT": "x"}) for n in range(1200)])
        self.run_once(TD_HONEYPOT_BATCH="500")
        self.assertEqual(len(self.documents()), 1200)
        self.assertEqual(len([path for path, _ in FakePlatform.requests if path.endswith("_bulk")]), 3)

    def test_missing_log_file_is_not_an_error(self):
        self.assertEqual(self.run_once()["alerts"], 0)


class Settings(ShipperCase):
    def test_key_and_platform_are_required(self):
        del os.environ["TD_HONEYPOT_API_KEY"]
        with self.assertRaises(fw.ConfigError):
            hp.Config()

    def test_data_stream_must_stay_inside_what_the_key_allows(self):
        os.environ["TD_HONEYPOT_DATASTREAM"] = "logs-suricata.alerts-so"
        with self.assertRaises(fw.ConfigError):
            hp.Config()

    def test_bad_ignore_list_and_port_map_are_refused(self):
        for name, value in (("TD_HONEYPOT_IGNORE_IPS", "10.0.0.300"), ("TD_HONEYPOT_PORT_MAP", "ssh=2222")):
            os.environ[name] = value
            with self.assertRaises(fw.ConfigError):
                hp.Config()
            del os.environ[name]

    def test_check_reports_both_sides(self):
        self.write(line(1000, src=""))
        config = hp.Config()
        self.assertEqual(hp.check(config, hp.Platform(config)), 0)
        FakePlatform.fail_status = 401
        self.assertEqual(hp.check(config, hp.Platform(config)), 1)

    def test_every_known_event_has_a_valid_severity(self):
        for code, (decoy, name, action, severity) in hp.EVENTS.items():
            self.assertIn(severity, (1, 2, 3), code)
            self.assertTrue(decoy and name and action, code)


class MakeConfig(unittest.TestCase):
    def test_only_chosen_decoys_are_on_and_every_port_is_different(self):
        result = make_config.build("decoy-1", "ftp,http,rdp", "0.0.0.0", [])
        settings = result["settings"]
        on = sorted(key[:-8] for key, value in settings.items() if key.endswith(".enabled") and value)
        self.assertEqual(on, ["ftp", "http", "rdp"])
        ports = [value for key, value in settings.items() if key.endswith(".port")]
        self.assertEqual(len(ports), len(set(ports)))          # OpenCanary refuses duplicates
        self.assertTrue(all(isinstance(port, int) for port in ports))
        self.assertEqual(settings["device.node_id"], "decoy-1")

    def test_values_openCanary_checks_at_start_up(self):
        settings = make_config.build("decoy-1", "mysql,mssql", "0.0.0.0", [])["settings"]
        self.assertRegex(settings["mysql.banner"], r"^[3456]\.[-_~.+\w]+$")      # its own rule
        self.assertIn(settings["mssql.version"], ("2008R2", "2012", "2014"))
        self.assertEqual(settings["logger"]["kwargs"]["handlers"]["file"]["filename"], make_config.LOG_FILE)

    def test_port_override_changes_only_the_host_side(self):
        result = make_config.build("decoy-1", "ssh,http", "10.20.30.60", ["ssh=2222"])
        self.assertEqual(result["settings"]["ssh.port"], 22)
        self.assertIn('"10.20.30.60:2222:22"', result["ports_yaml"])
        self.assertIn('"10.20.30.60:80:80"', result["ports_yaml"])
        self.assertEqual(result["port_map"], "22=2222,80=80")
        self.assertEqual(hp.Config._port_map(result["port_map"]), {22: 2222, 80: 80})

    def test_mistakes_are_refused(self):
        for services, bind, ports in (("smtp", "0.0.0.0", []), ("", "0.0.0.0", []), ("ftp", "everywhere", []),
                                      ("ftp", "0.0.0.0", ["ssh=2222"]), ("ftp,http", "0.0.0.0", ["ftp=80"]),
                                      ("ftp", "0.0.0.0", ["ftp=99999"])):
            with self.assertRaises(make_config.ConfigError):
                make_config.build("decoy-1", services, bind, ports)
        with self.assertRaises(make_config.ConfigError):
            make_config.build("bad name;", "ftp", "0.0.0.0", [])

    def test_every_decoy_offered_has_events_the_shipper_knows(self):
        known = {decoy for decoy, _, _, _ in hp.EVENTS.values()}
        http_family = {"https": "http"}
        for name in make_config.SERVICES:
            self.assertIn(http_family.get(name, name), known, name)

    def test_ports_file_is_a_compose_fragment_for_the_honeypot_service(self):
        text = make_config.build("decoy-1", "ftp", "0.0.0.0", [])["ports_yaml"]
        self.assertTrue(re.search(r"^services:\n  td-honeypot:\n    ports:\n      - \"0\.0\.0\.0:21:21\"", text, re.M))


if __name__ == "__main__":
    unittest.main()
