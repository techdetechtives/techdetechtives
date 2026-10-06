# TechDetechtives OT IDS tests. Copyright (c) 2026 TechDetechtives. MIT licence.
"""Tests for ot-ids/baseline/td_profile.py. Run with:  python3 -m unittest discover -s ot-ids/tests -v

The program is run against a stand-in for OpenSearch: a small web server that
answers the one search the program makes, worked out from connection records
held in memory and shaped like the product's (Zeek conn records, with the
'still open' records the product's long-connection script writes). The
stand-in refuses a search it does not recognise.

This shows the program's own arithmetic and wording. It does not show that the
real OpenSearch accepts the search or that the real records carry these fields
with these meanings; the field names were read from the product's source.
"""
import contextlib
import csv
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

import td_profile      # noqa: E402

HOUR = 3600
T0 = (1_790_000_000 // HOUR) * HOUR
INDEX = "arkime_sessions3-*"
TIME_FIELD = "firstPacket"
HMI, ENG, PLC1, PLC2, HISTORIAN, LAPTOP = "10.0.0.5", "10.0.0.6", "10.0.1.10", "10.0.1.11", "10.0.0.20", "10.0.0.99"


def values(doc, field):
    value = doc.get(field)
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


class Records:
    """Connection records, and the answer OpenSearch would give to the profile's search."""

    def __init__(self):
        self.docs, self.searches = [], []
        self.partial = self.no_index = self.refuse = False

    def conn(self, when, src, dst, port, service=None, sent=100, received=200, seconds=1.0, transport="tcp", still_open=False,
             reply=None, **more):
        """sent and received count whole packets (the product's source.bytes and destination.bytes); reply is the data the
        server sent (server.bytes), by default all it sent less one packet header."""
        doc = {TIME_FIELD: int(when * 1000), "lastPacket": int(when * 1000) + int(seconds * 1000),
               "source.ip": src, "destination.ip": dst, "destination.port": port,
               "network.transport": transport, "source.bytes": sent, "destination.bytes": received,
               "server.bytes": max(received - 40, 0) if reply is None else reply,
               "length": int(seconds * 1000), "event.dataset": "conn", "event.provider": "zeek"}
        if service:
            doc["network.protocol"] = service
        if still_open:
            doc["zeek.conn.long"] = "true"
        doc.update(more)
        self.docs.append(doc)

    def search(self, body):
        if sorted(body) != ["aggs", "query", "size", "track_total_hits"] or body["size"] != 0 or body["track_total_hits"] is not False:
            raise ValueError("unexpected search body")
        filters = body["query"]["bool"]["filter"]
        if list(body["query"]["bool"]) != ["filter"] or len(filters) != 6:
            raise ValueError("unexpected query")
        began, ended = filters[0]["range"][TIME_FIELD], filters[1]["range"]["lastPacket"]
        if sorted(began) != ["format", "lt"] or sorted(ended) != ["format", "gte"] or {began["format"], ended["format"]} != {"epoch_millis"}:
            raise ValueError("unexpected range")
        time_range = {"lt": began["lt"], "gte": ended["gte"]}
        if filters[2:] != [{"term": {"event.dataset": "conn"}}, {"term": {"event.provider": "zeek"}},
                           {"exists": {"field": "source.ip"}}, {"exists": {"field": "destination.ip"}}]:
            raise ValueError("unexpected filters")
        if self.no_index:
            return {"took": 1, "timed_out": False, "_shards": {"total": 0, "successful": 0, "failed": 0}, "hits": {"hits": []}}
        composite = body["aggs"]["keys"]["composite"]
        if list(body["aggs"]) != ["keys"] or not set(composite) <= {"size", "sources", "after"}:
            raise ValueError("unexpected aggregation")
        wanted = [("hour", "date_histogram", {"field": TIME_FIELD, "fixed_interval": "1h"}), ("src", "terms", {"field": "source.ip"}),
                  ("dst", "terms", {"field": "destination.ip"}), ("port", "terms", {"field": "destination.port", "missing_bucket": True}),
                  ("transport", "terms", {"field": "network.transport", "missing_bucket": True}),
                  ("open", "terms", {"field": "zeek.conn.long", "missing_bucket": True})]
        sources = [(name, kind, options) for source in composite["sources"] for name, spec in source.items() for kind, options in spec.items()]
        if sources != wanted:
            raise ValueError("unexpected composite sources")
        subs = body["aggs"]["keys"]["aggs"]
        if subs != {"sent": {"sum": {"field": "source.bytes"}}, "received": {"sum": {"field": "destination.bytes"}},
                    "time": {"sum": {"field": "length"}}, "answer": {"sum": {"field": "server.bytes"}},
                    "longest": {"max": {"field": "length"}},
                    "most_sent": {"max": {"field": "source.bytes"}}, "most_received": {"max": {"field": "destination.bytes"}},
                    "service": {"terms": {"field": "network.protocol", "size": 4}}}:
            raise ValueError("unexpected sub-aggregations")

        groups = {}
        for doc in self.docs:
            when = doc[TIME_FIELD]
            if not (when < time_range["lt"] and doc["lastPacket"] >= time_range["gte"]):      # open at some time in the period
                continue
            if doc.get("event.dataset") != "conn" or doc.get("event.provider") != "zeek":
                continue
            if not values(doc, "source.ip") or not values(doc, "destination.ip"):
                continue
            choices = [[when - when % (HOUR * 1000)]]
            for name, kind, options in wanted[1:]:
                found = values(doc, options["field"])
                choices.append(found or ([None] if options.get("missing_bucket") else []))
            for combination in itertools.product(*choices):
                groups.setdefault(combination, []).append(doc)

        def order(combination):
            return tuple((0, "") if value is None else (1, value) if isinstance(value, str) else (1, f"{value:020d}") for value in combination)

        ordered = sorted(groups, key=order)
        if "after" in composite:
            after = tuple(composite["after"][name] for name, _, _ in wanted)
            ordered = [combination for combination in ordered if order(combination) > order(after)]
        page = ordered[:composite["size"]]
        buckets = []
        for combination in page:
            docs = groups[combination]
            services = {}
            for doc in docs:
                for name in values(doc, "network.protocol"):
                    services[name] = services.get(name, 0) + 1

            def total(field):
                return {"value": float(sum(doc.get(field, 0) for doc in docs))}

            def most(field):
                found = [doc[field] for doc in docs if field in doc]
                return {"value": float(max(found)) if found else None}          # OpenSearch gives null for a maximum of nothing

            buckets.append({"key": dict(zip([name for name, _, _ in wanted], combination)), "doc_count": len(docs),
                            "sent": total("source.bytes"), "received": total("destination.bytes"), "time": total("length"),
                            "answer": total("server.bytes"),
                            "longest": most("length"), "most_sent": most("source.bytes"), "most_received": most("destination.bytes"),
                            "service": {"buckets": [{"key": name, "doc_count": count}
                                                    for name, count in sorted(services.items(), key=lambda item: (-item[1], item[0]))[:4]]}})
        result = {"buckets": buckets}
        if page:
            result["after_key"] = buckets[-1]["key"]
        if self.partial:
            return {"took": 1, "timed_out": True, "_shards": {"total": 5, "successful": 4, "failed": 1}, "aggregations": {"keys": {"buckets": []}}}
        return {"took": 1, "timed_out": False, "_shards": {"total": 5, "successful": 5, "failed": 0}, "aggregations": {"keys": result}}


def serve(records):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            path = urlparse(self.path)
            try:
                if records.refuse:
                    raise RuntimeError("refused")
                if path.path != f"/{INDEX}/_search" or path.query != "ignore_unavailable=true&allow_no_indices=true&allow_partial_search_results=false":
                    raise ValueError("unexpected request")
                records.searches.append(body)
                reply, status = records.search(body), 200
            except Exception as error:                     # the stand-in says what it did not like
                reply, status = {"error": str(error)}, 400
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


class ProfileCase(unittest.TestCase):
    def setUp(self):
        self.records = Records()
        self.server = serve(self.records)
        self.folder = tempfile.TemporaryDirectory()
        self.environ = {"OPENSEARCH_URL": f"http://127.0.0.1:{self.server.server_address[1]}", "TD_BASELINE_DIR": self.folder.name,
                        "OPENSEARCH_CREDS_CONFIG_FILE": str(Path(self.folder.name) / "none"), "TD_BASELINE_PAGE_SIZE": "200",
                        "TD_BASELINE_TIMEOUT": "20"}

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.folder.cleanup()

    def run_profile(self, *arguments, now_hour=24, environ=None):
        """The window ends at T0 + now_hour hours (the program steps back from 'now' by its lag and to the whole hour)."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = td_profile.main(list(arguments), now=T0 + now_hour * HOUR + 11 * 60, environ=environ or self.environ)
        return status, out.getvalue(), err.getvalue()

    def report(self, *arguments, **options):
        status, out, err = self.run_profile("--format", "json", *arguments, **options)
        self.assertEqual(status, 0, err)
        return json.loads(out)

    def baseline_knows(self, masters=(HMI, ENG), devices=(PLC1, PLC2)):
        hosts = {address: {"f": 0, "l": 0, "c": ["modbus"], "s": []} for address in masters}
        hosts.update({address: {"f": 0, "l": 0, "c": [], "s": ["modbus"]} for address in devices})
        (Path(self.folder.name) / "state.json").write_text(json.dumps({"version": 2, "hosts": hosts}))

    def plant(self):
        """A day of an ordinary small plant, plus the things the report is for."""
        add = self.records.conn
        for hour in range(24):
            start = T0 + hour * HOUR
            for minute in range(0, 60, 10):                                   # the HMI opens a Modbus connection every ten minutes
                add(start + minute * 60, HMI, PLC1, 502, "modbus", 400, 900, 2)
            for minute in (5, 35):                                             # time synchronisation, twice an hour, from the PLC
                add(start + minute * 60, PLC1, HISTORIAN, 123, "ntp", 76, 76, 0.01, transport="udp")
            add(start + 60, HMI, HISTORIAN, 1433, None, 2000, 90000, 30)       # the HMI reads the historian's database
        add(T0 + 9 * HOUR + 300, ENG, PLC1, 3389, "rdp", 4_000_000, 60_000_000, 2700)              # remote desktop into a controller's network
        add(T0 + 10 * HOUR, ENG, PLC2, 80, "http", 5000, 250_000, 12)
        add(T0 + 11 * HOUR, PLC2, "203.0.113.77", 443, "tls", 3000, 5000, 4)                       # a controller calling a public address
        for hour in range(24):                                                                      # a laptop calling the same place every 5 minutes
            for minute in range(0, 60, 5):
                add(T0 + hour * HOUR + minute * 60 + 7, LAPTOP, "198.51.100.9", 8443, "tls", 310, 420, 0.4)
        for port in range(1, 61):                                                                   # and trying 60 ports of a PLC: each refused
            add(T0 + 14 * HOUR + port, LAPTOP, PLC2, port, None, 60, 40, 0, reply=0, **{"zeek.conn.conn_state": "REJ"})
        # one connection open for 19 hours and not closed: the sensor writes 'so far' records
        for hours_in, sent in ((1, 10_000), (12, 120_000)):
            add(T0 + 2 * HOUR, HISTORIAN, "10.0.0.30", 5432, "postgresql", sent, sent * 3, hours_in * HOUR, still_open=True)


class Reading(ProfileCase):
    def test_the_search_is_one_the_stand_in_accepts_and_pages_are_followed(self):
        self.plant()
        report = self.report(environ=dict(self.environ, TD_BASELINE_PAGE_SIZE="7"))
        self.assertGreater(len(self.records.searches), 20, "a page size of 7 forces many pages")
        self.assertEqual(report["all"], self.report()["all"], "the same answer whatever the page size")
        self.assertEqual(report["hours"], 24)
        self.assertEqual((report["from"], report["to"]), (T0, T0 + 24 * HOUR))
        self.assertFalse(report["cut_short"])
        self.assertEqual(report["totals"]["conversations"], len({(doc["source.ip"], doc["destination.ip"], doc["destination.port"],
                                                                 doc["network.transport"]) for doc in self.records.docs}))

    def test_whole_hours_only_and_the_window_can_be_changed(self):
        self.records.conn(T0 + 23 * HOUR + 10, HMI, HISTORIAN, 80, "http")
        self.records.conn(T0 + 24 * HOUR + 10, HMI, HISTORIAN, 81, "http")          # in the hour still running: not read
        self.records.conn(T0 - 10, HMI, HISTORIAN, 82, "http")                      # before the window
        self.assertEqual([row["port"] for row in self.report()["all"]], [80])
        self.assertEqual(sorted(row["port"] for row in self.report("--hours", "48")["all"]), [80, 82])
        self.assertEqual(self.report("--hours", "1")["hours"], 1)

    def test_a_connection_that_began_before_the_period_is_seen(self):
        # Every record carries the time its connection BEGAN. A master's session opened 30 hours ago and still
        # open is known only from 'so far' records stamped 30 hours ago; a transfer that began 25 hours ago and
        # ended an hour ago is one record stamped 25 hours ago.
        add = self.records.conn
        for hours_in in (1, 12, 24):
            add(T0 - 6 * HOUR, HMI, PLC1, 502, "modbus", 1000 * hours_in, 3000 * hours_in, hours_in * HOUR, still_open=True)
        add(T0 - HOUR, ENG, HISTORIAN, 445, "smb", 9_000_000_000, 5_000_000, 24 * HOUR)
        add(T0 - 9 * HOUR, ENG, HISTORIAN, 22, "ssh", 500, 900, 2 * HOUR)                      # over before the period began
        add(T0 - 40 * HOUR, HMI, PLC2, 502, "modbus", 10, 30, HOUR, still_open=True)            # its last 'so far' record is too old to tell
        result = self.report()
        rows = {(row["client"], row["server"], row["port"]): row for row in result["all"]}
        self.assertEqual(sorted(rows), sorted([(HMI, PLC1, 502), (ENG, HISTORIAN, 445)]))
        session = rows[(HMI, PLC1, 502)]
        self.assertEqual((session["still_open"], session["longest_seconds"], session["sent"], session["connections"]), (True, 24 * HOUR, 24000, 0))
        self.assertEqual(session["hours_with_new_connections"], 0, "it did not begin in the period")
        self.assertEqual(rows[(ENG, HISTORIAN, 445)]["bytes"], 9_005_000_000)
        self.assertEqual([(row["client"], row["port"]) for row in result["longest"]], [(HMI, 502), (ENG, 445)])
        self.assertEqual(result["largest"][0]["port"], 445)

    def test_other_records_are_not_connection_records(self):
        self.records.conn(T0 + HOUR, HMI, PLC1, 502, "modbus", **{"event.dataset": "modbus"})
        self.records.conn(T0 + HOUR, HMI, PLC1, 502, "modbus", **{"event.provider": "arkime"})
        self.assertEqual(self.report()["totals"]["conversations"], 0)

    def test_a_partial_answer_is_refused_and_no_index_is_not_an_error(self):
        self.plant()
        self.records.partial = True
        status, out, err = self.run_profile()
        self.assertEqual((status, out), (1, ""))
        self.assertIn("only in part", err)
        self.records.partial, self.records.no_index = False, True
        status, out, err = self.run_profile()
        self.assertEqual(status, 0)
        self.assertIn("No connection records in this period", out)
        self.records.no_index, self.records.refuse = False, True
        status, out, err = self.run_profile()
        self.assertEqual(status, 1)
        self.assertIn("could not be read", err)

    def test_too_many_records_are_cut_short_and_the_report_says_so(self):
        self.plant()
        status, out, err = self.run_profile(environ=dict(self.environ, TD_PROFILE_MAX_BUCKETS="14", TD_BASELINE_PAGE_SIZE="7"))
        self.assertEqual(status, 0)
        self.assertIn("THE READ WAS CUT SHORT", out)
        self.assertEqual(len(self.records.searches), 2)


class WhatIsReported(ProfileCase):
    def setUp(self):
        super().setUp()
        self.plant()
        self.baseline_knows()
        self.result = self.report()

    def pick(self, section, **match):
        found = [row for row in self.result[section] if all(row[key] == value for key, value in match.items())]
        self.assertEqual(len(found), 1, f"{section} {match}: {found}")
        return found[0]

    def test_totals_and_industrial_traffic_is_set_apart(self):
        totals = self.result["totals"]
        self.assertEqual((totals["industrial"], totals["known_to_baseline"]), (1, 4))
        modbus = self.pick("all", client=HMI, server=PLC1, port=502)
        self.assertTrue(modbus["industrial"])
        self.assertEqual((modbus["connections"], modbus["sent"], modbus["received"]), (144, 144 * 400, 144 * 900))
        for section in ("reaching_controllers", "largest", "steady", "services"):
            self.assertFalse(any(row.get("port") == 502 for row in self.result[section]), section)

    def test_a_port_with_no_protocol_named_counts_as_industrial_only_on_an_industrial_port(self):
        self.records.conn(T0 + HOUR, ENG, PLC1, 44818)                       # EtherNet/IP's port, nothing decoded
        self.records.conn(T0 + HOUR, ENG, PLC1, 502, "http")                 # a web server on the Modbus port
        self.records.conn(T0 + HOUR, ENG, PLC1, 20000, "dnp3_tcp")
        result = self.report()
        rows = {(row["port"], row["service"]): row["industrial"] for row in result["all"] if row["client"] == ENG and row["server"] == PLC1}
        self.assertEqual(rows[(44818, "")], True)
        self.assertEqual(rows[(502, "http")], False)
        self.assertEqual(rows[(20000, "dnp3_tcp")], True)
        self.assertEqual(rows[(3389, "rdp")], False)

    def test_other_protocols_reaching_controllers(self):
        rows = self.result["reaching_controllers"]
        self.assertEqual([(row["client"], row["server"], row["port"]) for row in rows[:2]], [(ENG, PLC1, 3389), (ENG, PLC2, 80)])
        rdp = rows[0]
        self.assertEqual((rdp["bytes"], rdp["longest_seconds"], rdp["client_role"], rdp["server_role"]), (64_000_000, 2700, "master", "device"))
        self.assertEqual(len(rows), 2, "the sixty refused attempts are not traffic reaching the controller")
        self.assertFalse(any(row["server"] == HISTORIAN for row in rows))

    def test_attempts_nobody_answered(self):
        self.assertEqual(self.result["unanswered"], [{"client": LAPTOP, "servers": 1, "services": 60, "attempts": 60, "client_role": ""}])
        refused = self.pick("all", client=LAPTOP, server=PLC2, port=7)
        self.assertEqual((refused["answered"], refused["received"]), (False, 40), "a refusal is a packet, not an answer")
        # A program calling a server that is not there, every five minutes: steady, and marked as not answered.
        for hour in range(24):
            for minute in range(0, 60, 5):
                self.records.conn(T0 + hour * HOUR + minute * 60, HMI, "10.9.9.9", 4444, None, 60, 0, 0)
        result = self.report()
        calling = [row for row in result["steady"] if row["port"] == 4444][0]
        self.assertEqual((calling["answered"], calling["connections"]), (False, 288))
        self.assertIn({"client": HMI, "servers": 1, "services": 1, "attempts": 288, "client_role": "master"}, result["unanswered"])
        self.assertFalse(any(row["port"] == 4444 for row in result["services"]))

    def test_connections_opened_by_controllers(self):
        rows = self.result["opened_by_controllers"]
        self.assertEqual(sorted((row["client"], row["server"], row["port"]) for row in rows),
                         sorted([(PLC2, "203.0.113.77", 443), (PLC1, HISTORIAN, 123)]))

    def test_addresses_outside_the_private_ranges(self):
        rows = self.result["outside"]
        self.assertEqual(sorted(row["server"] for row in rows), ["198.51.100.9", "203.0.113.77"])
        self.assertTrue(td_profile.is_outside("8.8.8.8") and td_profile.is_outside("2001:4860:4860::8888"))
        self.assertTrue(td_profile.is_outside("172.32.0.1") and td_profile.is_outside("::ffff:8.8.8.8"))
        for inside in ("10.1.2.3", "172.16.0.1", "172.31.255.254", "192.168.1.1", "100.64.0.1", "169.254.1.1", "224.0.0.251",
                       "255.255.255.255", "0.0.0.0", "127.0.0.1", "fd00::1", "fe80::1", "ff02::1", "::1", "::ffff:10.0.0.1", "not an address"):
            self.assertFalse(td_profile.is_outside(inside), inside)

    def test_longest_connections_and_one_that_is_still_open(self):
        rows = self.result["longest"]
        self.assertEqual(len(rows), 1)
        still = rows[0]
        self.assertEqual((still["client"], still["server"], still["port"]), (HISTORIAN, "10.0.0.30", 5432))
        self.assertTrue(still["still_open"])
        self.assertEqual((still["longest_seconds"], still["connected_seconds"], still["connections"]), (12 * HOUR, 12 * HOUR, 0))
        self.assertEqual((still["sent"], still["received"]), (120_000, 360_000), "the largest 'so far' record, not the sum of them")

    def test_an_open_transfer_is_not_hidden_by_an_older_longer_connection(self):
        self.records.conn(T0 + HOUR, HMI, HISTORIAN, 22, "ssh", 100, 200, 6 * HOUR)                         # closed, long
        self.records.conn(T0 + 20 * HOUR, HMI, HISTORIAN, 22, "ssh", 900_000_000, 1000, HOUR, still_open=True)   # another one, still going
        row = [row for row in self.report()["all"] if row["port"] == 22][0]
        self.assertTrue(row["still_open"])
        self.assertEqual((row["longest_seconds"], row["connected_seconds"], row["sent"], row["connections"], row["records"]),
                         (6 * HOUR, 7 * HOUR, 900_000_100, 1, 2))

    def test_so_far_records_are_not_counted_as_attempts(self):
        for hours_in in (1 / 6, 0.5, 1, 12):                                                           # four records, one connection
            self.records.conn(T0 + HOUR, HMI, "10.9.9.8", 514, "syslog", 5000 * hours_in, 0, hours_in * HOUR, transport="udp",
                              still_open=True, reply=0)
        entry = [entry for entry in self.report()["unanswered"] if entry["client"] == HMI][0]
        self.assertEqual((entry["services"], entry["attempts"]), (1, 1))

    def test_a_long_connection_that_closed_is_counted_once(self):
        self.records.conn(T0 + 2 * HOUR, HMI, HISTORIAN, 22, "ssh", 1000, 2000, HOUR, still_open=True)
        self.records.conn(T0 + 2 * HOUR, HMI, HISTORIAN, 22, "ssh", 5000, 9000, 5 * HOUR)             # the record written when it ended
        row = [row for row in self.report()["all"] if row["port"] == 22][0]
        self.assertFalse(row["still_open"])
        self.assertEqual((row["longest_seconds"], row["connected_seconds"], row["bytes"], row["connections"]), (5 * HOUR, 5 * HOUR, 14000, 1))

    def test_largest_transfers(self):
        rows = self.result["largest"]
        self.assertEqual((rows[0]["client"], rows[0]["port"], rows[0]["bytes"]), (ENG, 3389, 64_000_000))
        self.assertEqual((rows[1]["client"], rows[1]["server"], rows[1]["port"], rows[1]["bytes"]), (HMI, HISTORIAN, 1433, 24 * 92000))
        self.assertTrue(all(first["bytes"] >= second["bytes"] for first, second in zip(rows, rows[1:])))

    def test_steady_repeaters(self):
        rows = self.result["steady"]
        self.assertEqual(sorted((row["client"], row["server"], row["port"]) for row in rows),
                         sorted([(LAPTOP, "198.51.100.9", 8443), (PLC1, HISTORIAN, 123), (HMI, HISTORIAN, 1433)]))
        laptop = [row for row in rows if row["client"] == LAPTOP][0]
        self.assertEqual((laptop["hours_with_new_connections"], laptop["evenness"], laptop["connections"]), (24, 1.0, 288))
        self.assertFalse(any(row["port"] == 3389 for row in rows), "one session is not a repeater")

    def test_uneven_or_part_time_conversations_are_not_steady(self):
        for hour in range(24):                                                   # every hour, but 1 one hour and 40 the next
            for index in range(1 if hour % 2 else 40):
                self.records.conn(T0 + hour * HOUR + index, HMI, HISTORIAN, 9100, None)
        for hour in range(10):                                                   # even, but only ten hours of the day
            for index in range(6):
                self.records.conn(T0 + hour * HOUR + index * 600, HMI, HISTORIAN, 9200, None)
        result = self.report()
        self.assertFalse(any(row["port"] in (9100, 9200) for row in result["steady"]))
        uneven = [row for row in result["all"] if row["port"] == 9100][0]
        self.assertLess(uneven["evenness"], 0.2)
        self.assertEqual(td_profile.evenness([4, 4, 4]), 1.0)
        self.assertEqual(td_profile.evenness([]), 0.0)

    def test_steady_needs_four_hours_and_works_from_there(self):
        short = self.report("--hours", "4")
        self.assertEqual(sorted((row["client"], row["port"]) for row in short["steady"]), sorted([(LAPTOP, 8443), (PLC1, 123), (HMI, 1433)]))
        self.assertEqual(self.report("--hours", "3")["steady"], [])
        status, out, _ = self.run_profile("--hours", "3")
        self.assertIn("needs a period of four hours or more", out)

    def test_addresses_that_contacted_many_services(self):
        self.assertEqual(self.result["many_services"], [{"client": LAPTOP, "servers": 2, "services": 61, "client_role": ""}])
        self.assertEqual(self.report("--many", "100")["many_services"], [])

    def test_services(self):
        ntp = self.pick("services", port=123)
        self.assertEqual((ntp["transport"], ntp["service"], ntp["servers"], ntp["clients"], ntp["connections"], ntp["only_server"]),
                         ("udp", "ntp", 1, 1, 48, HISTORIAN))
        self.assertEqual(self.pick("services", port=1433)["service"], "")
        self.assertLessEqual(len(self.result["services"]), 30)

    def test_without_a_baseline_no_address_is_named_and_the_report_says_so(self):
        (Path(self.folder.name) / "state.json").unlink()
        result = self.report()
        self.assertEqual((result["reaching_controllers"], result["opened_by_controllers"]), ([], []))
        status, out, _ = self.run_profile()
        self.assertIn("The baseline has no list yet", out)
        (Path(self.folder.name) / "state.json").write_text("{ not json")
        self.assertEqual(self.report()["totals"]["known_to_baseline"], 0)


class Writing(ProfileCase):
    def setUp(self):
        super().setUp()
        self.plant()
        self.baseline_knows()

    def test_text(self):
        status, out, err = self.run_profile()
        self.assertEqual((status, err), (0, ""))
        lines = out.splitlines()
        self.assertTrue(lines[0].startswith("Traffic profile, "))
        self.assertIn("(24 hours)", lines[0])
        self.assertIn("1 industrial (left to the baseline)", lines[1])
        for title in ("Other protocols reaching controllers", "Connections opened by controllers", "Addresses outside the private ranges",
                      "Longest connections", "Largest transfers", "Steady repeaters", "Addresses that contacted many services",
                      "Attempts nobody answered", "Services"):
            self.assertIn(title, lines)
        self.assertTrue(any(f"{ENG} (master)" in line and f"{PLC1} (device)" in line and "3389/tcp rdp" in line
                            and "61.0 MB (3.8 MB / 57.2 MB)" in line and "45 min" in line for line in lines), out)
        self.assertTrue(any("12 h 00 min, still open" in line for line in lines))
        self.assertTrue(all(ord(char) < 127 for char in out), "plain text for a console")

    def test_markdown_csv_and_a_file(self):
        status, out, _ = self.run_profile("--format", "markdown", "--top", "3")
        self.assertEqual(status, 0)
        self.assertTrue(out.startswith("# Traffic profile, "))
        self.assertIn("## Steady repeaters", out)
        self.assertIn("| Client | Server | Port and protocol | Bytes (sent / received) | Connections | Longest |", out)
        section = out.split("## Largest transfers")[1].split("## ")[0]
        self.assertEqual(len([line for line in section.splitlines() if line.startswith("| 10.")]), 3, "--top 3")
        status, out, _ = self.run_profile("--format", "csv")
        table = list(csv.DictReader(io.StringIO(out)))
        self.assertEqual(len(table), self.report()["totals"]["conversations"])
        rdp = [row for row in table if row["port"] == "3389"][0]
        self.assertEqual((rdp["client"], rdp["server_role"], rdp["bytes"], rdp["industrial"]), (ENG, "device", "64000000", "False"))
        target = Path(self.folder.name) / "profile.txt"
        status, out, err = self.run_profile("--out", str(target))
        self.assertEqual((status, out), (0, ""))
        self.assertTrue(target.read_text().startswith("Traffic profile, "))

    def test_text_from_the_network_cannot_break_the_table(self):
        self.records.conn(T0 + HOUR, ENG, PLC1, 8080, "we|ird\x1b[31m\nname")
        status, out, _ = self.run_profile("--format", "markdown")
        self.assertNotIn("\x1b", out)
        row = [line for line in out.splitlines() if "8080/tcp" in line][0]
        self.assertEqual(row.count("|"), 7, row)
        self.assertIn("we/ird?[31m?name", row)

    def test_arguments(self):
        for bad in (["--hours", "0"], ["--hours", "200"], ["--top", "0"], ["--many", "1"]):
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                td_profile.main(bad, now=T0, environ=self.environ)

    def test_sizes_and_spans(self):
        self.assertEqual([td_profile.size(count) for count in (0, 1023, 1024, 1536, 5 * 1024 ** 3)], ["0 B", "1023 B", "1.0 KB", "1.5 KB", "5.0 GB"])
        self.assertEqual([td_profile.span(seconds) for seconds in (0, 59, 60, 3599, 3600, 19 * 3600 + 120)],
                         ["0 min", "0 min", "1 min", "59 min", "1 h 00 min", "19 h 02 min"])


if __name__ == "__main__":
    unittest.main()
