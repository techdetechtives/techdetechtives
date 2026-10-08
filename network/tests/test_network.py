# TechDetechtives network inventory tests. Copyright (c) 2026 TechDetechtives. MIT licence.
"""Run with:  python3 -m unittest discover -s network/tests -v

The inventory is run against a stand-in for the platform (fake_platform.py)
over real HTTP, with records shaped like the ones Security Onion stores for
Zeek. No platform, sensor or network is needed.
"""

import base64
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "network" / "app"))
sys.path.insert(0, str(ROOT / "ticketing" / "forwarder"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ["TD_ADV_FEEDS"] = "off"          # no advisory feeds are fetched from the internet in tests

import td_forwarder as fw  # noqa: E402
from fake_platform import FakePlatform  # noqa: E402
from td_net import outputs, protocols, web  # noqa: E402
from td_net.main import Config, run_cycle  # noqa: E402
from td_net.platform import Platform  # noqa: E402
from td_net.store import Store  # noqa: E402
from td_net.sync import HIGH, LOW, MEDIUM, MULTICAST, OUTSIDE, Scope, run_sync  # noqa: E402

T0 = datetime(2026, 10, 1, 8, 0, 0, tzinfo=timezone.utc)
HMI, ENGINEERING, PLC, PLC2, LAPTOP, OFFICE = "10.10.10.5", "10.10.10.10", "10.10.1.11", "10.10.1.12", "10.10.10.99", "172.16.5.20"


def at(hours: float = 0, minutes: float = 0) -> datetime:
    return T0 + timedelta(hours=hours, minutes=minutes)


def iso(moment: datetime) -> str:
    return fw.iso(moment)


class Case(unittest.TestCase):
    def setUp(self):
        self.fake = FakePlatform()
        self.addCleanup(self.fake.close)
        self.store = Store(":memory:")
        self.addCleanup(self.store.close)
        self.scope = Scope(zones="Control=10.10.1.0/24,Stations=10.10.10.0/24")
        self.platform = Platform(self.fake.url, "read-key", "", True)
        self.platform.choose_time_field()

    def conn(self, when, src, dst, port, transport="tcp", service=None, out=1000, back=2000, maker=None, ingested=None):
        fields = {"source.ip": src, "destination.ip": dst, "destination.port": port, "network.transport": transport,
                  "client.ip_bytes": out, "server.ip_bytes": back}
        if service:
            fields["network.protocol"] = service
        if maker:
            fields["client.oui"] = maker
        self.fake.add("zeek.conn", iso(when), iso(ingested) if ingested else "", **fields)

    def op(self, dataset, when, src, dst, operation, port=502):
        field = protocols.OT_DATASETS[dataset][1]
        self.fake.add(dataset, iso(when), **{"source.ip": src, "destination.ip": dst, "destination.port": port,
                                             "network.transport": "tcp", field: operation})

    def sync(self, now, **options):
        options.setdefault("learn_hours", 24)
        return run_sync(self.platform, self.store, self.scope, now, **options)

    def learn(self):
        """A normal day: the HMI reads from and writes to the PLC over Modbus; the baseline is then closed."""
        self.conn(at(0, 5), HMI, PLC, 502, service="modbus", maker="Siemens AG")
        self.conn(at(0, 6), PLC, HMI, 80, service="http", maker="Schneider Electric")
        self.op("zeek.modbus", at(0, 5), HMI, PLC, "READ_HOLDING_REGISTERS")
        self.op("zeek.modbus", at(0, 5), HMI, PLC, "WRITE_SINGLE_REGISTER")
        self.sync(at(1))
        self.sync(at(25))          # nothing new; the learning time has passed
        self.assertFalse(self.store.learning(at(25)))

    def changes(self):
        return [(row["kind"], row["severity"], row["ip"], row["peer"]) for row in self.store.changes()]


class Inventory(Case):
    def test_first_pass_builds_the_inventory_without_reporting_changes(self):
        self.conn(at(0, 5), HMI, PLC, 502, service="modbus")
        self.conn(at(0, 6), OFFICE, "8.8.8.8", 53, "udp", service="dns")
        self.conn(at(0, 7), "8.8.4.4", "1.1.1.1", 443)                      # passing through: neither end is ours
        self.conn(at(0, 8), PLC, "239.192.0.1", 2222, "udp")
        self.conn(at(0, 9), "0.0.0.0", "255.255.255.255", 67, "udp", service="dhcp")
        summary = self.sync(at(1))
        self.assertEqual(summary["changes"], 0)
        self.assertEqual(sorted(asset["ip"] for asset in self.store.assets()), [PLC, HMI, OFFICE])
        ends = {(row["src"], row["dst"], row["label"], row["industrial"], row["how"]) for row in self.store.conversations()}
        self.assertEqual(ends, {(HMI, PLC, "Modbus", 1, "decoded"), (OFFICE, OUTSIDE, "DNS", 0, "decoded"),
                                (PLC, MULTICAST, "EtherNet/IP I/O (Rockwell Automation)", 1, "port")})
        self.assertTrue(all(asset["baseline"] for asset in self.store.assets()))
        roles = {asset["ip"]: asset["role"] for asset in self.store.assets()}
        self.assertEqual(roles[PLC], "Controller or field device")      # cyclic data to a multicast group does not make it a station
        self.assertEqual(roles[HMI], "Station")
        self.assertEqual(roles[OFFICE], "")

    def test_a_device_that_both_answers_and_asks_is_a_gateway(self):
        self.conn(at(0, 5), HMI, PLC, 502, service="modbus")
        self.conn(at(0, 6), PLC, PLC2, 502, service="modbus")
        self.sync(at(1))
        self.assertEqual({asset["ip"]: asset["role"] for asset in self.store.assets()},
                         {HMI: "Station", PLC: "Gateway or peer", PLC2: "Controller or field device"})

    def test_totals_are_counted_once(self):
        self.conn(at(0, 5), HMI, PLC, 502, service="modbus", out=100, back=300)
        self.sync(at(1))
        self.sync(at(1, 10))
        self.conn(at(1, 15), HMI, PLC, 502, service="modbus", out=10, back=30)
        self.sync(at(1, 20))
        self.sync(at(1, 30))
        row = self.store.conversations()[0]
        self.assertEqual((row["connections"], row["bytes_out"], row["bytes_in"]), (2, 110, 330))
        hours = {row["hour"]: row["bytes"] for row in self.store.hours("")}
        self.assertEqual(hours, {"2026-10-01T08:00:00Z": 400, "2026-10-01T09:00:00Z": 40})

    def test_a_connection_written_long_after_it_started_is_not_missed(self):
        self.conn(at(0, 5), HMI, PLC, 502, service="modbus")
        self.sync(at(1))
        # A session that began before the last pass and is only written when it ends, six hours later.
        self.conn(at(0, 30), ENGINEERING, PLC, 102, service="s7comm", out=5000, back=7000, ingested=at(6, 30))
        self.sync(at(7))
        pairs = {(row["src"], row["dst"], row["label"]) for row in self.store.conversations()}
        self.assertIn((ENGINEERING, PLC, "S7comm"), pairs)
        self.assertEqual({row["hour"]: row["bytes"] for row in self.store.hours("") if row["industrial"]}["2026-10-01T08:00:00Z"], 3000 + 12000)

    def test_without_a_stored_time_the_records_own_time_is_used(self):
        self.fake.add("zeek.conn", iso(at(0, 5)), no_ingested=True, **{"source.ip": HMI, "destination.ip": PLC, "destination.port": 502,
                                                                       "network.transport": "tcp", "network.protocol": "modbus", "server.ip_bytes": 400})
        self.assertEqual(self.platform.choose_time_field(), "@timestamp")
        self.sync(at(1))
        self.assertEqual(len(self.store.conversations()), 1)
        self.assertIn("does not record when it stored", web.status_notice(self.store, at(1)))

    def test_open_sessions_are_known_from_their_operations(self):
        self.op("zeek.s7comm", at(0, 5), ENGINEERING, PLC, "Read Variable", port=102)
        self.sync(at(1))
        row = self.store.conversations()[0]
        self.assertEqual((row["src"], row["dst"], row["port"], row["label"], row["connections"]), (ENGINEERING, PLC, 102, "S7comm", 0))
        self.assertEqual(self.store.asset(PLC)["role"], "Controller or field device")

    def test_a_protocol_without_named_operations_still_gives_the_conversation(self):
        self.fake.add("zeek.s7comm_plus", iso(at(0, 5)), **{"source.ip": ENGINEERING, "destination.ip": PLC2, "destination.port": 102,
                                                            "network.transport": "tcp", "s7.opcode.name": "Request"})
        self.sync(at(1))
        self.assertEqual([(row["src"], row["dst"], row["label"]) for row in self.store.conversations()], [(ENGINEERING, PLC2, "S7comm-plus")])
        self.assertEqual(self.store.operations(), [])

    def test_the_learning_clock_starts_with_the_first_data(self):
        self.sync(at(0))
        self.sync(at(100))                           # four days with a sensor that records nothing
        self.assertIsNone(self.store.meta("learning_until"))
        self.conn(at(100, 5), HMI, PLC, 502, service="modbus")
        self.sync(at(101))
        self.assertTrue(self.store.learning(at(120)))
        self.assertFalse(self.store.learning(at(126)))
        self.assertEqual(self.changes(), [])

    def test_what_devices_say_about_themselves(self):
        self.conn(at(0, 5), HMI, PLC, 44818, service="enip", maker="Rockwell Automation")
        self.fake.add("zeek.cip_identity", iso(at(0, 6)), **{
            "source.ip": HMI, "destination.ip": PLC, "cip.socket.address": "0.0.0.0", "cip.vendor.name": "Rockwell Automation/Allen-Bradley",
            "cip.device.product.name": "1756-L71/B LOGIX5571", "cip.device.revision": "30.11", "cip.device.serial_number": "0x00a1b2c3",
            "cip.device.type.name": "Programmable Logic Controller"})
        self.fake.add("zeek.dhcp", iso(at(0, 7)), **{"dhcp.assigned_ip": HMI, "host.hostname": "HMI-01", "host.mac": "00:1B:21:AA:00:05"})
        self.fake.add("zeek.ntlm", iso(at(0, 8)), **{"source.ip": ENGINEERING, "host.name": "ENG-WS"})
        self.fake.add("zeek.software", iso(at(0, 9)), **{"source.ip": HMI, "software.name": "Firefox", "software.version.unparsed": "128.0"})
        self.conn(at(0, 9), ENGINEERING, PLC, 44818, service="enip")
        self.sync(at(1))
        plc, hmi = self.store.asset(PLC), self.store.asset(HMI)
        self.assertEqual((plc["vendor"], plc["model"], plc["version"], plc["identity_via"]),
                         ("Rockwell Automation/Allen-Bradley", "1756-L71/B LOGIX5571", "30.11", "EtherNet/IP identity"))
        self.assertEqual((hmi["name"], hmi["mac"], hmi["maker"], hmi["software"]), ("HMI-01", "00:1b:21:aa:00:05", "Rockwell Automation", "Firefox 128.0"))
        self.assertEqual(self.store.asset(ENGINEERING)["name"], "ENG-WS")

    def test_alerts_findings_and_honeypot_contacts_are_attached_to_devices(self):
        self.conn(at(0, 5), HMI, PLC, 502, service="modbus")
        self.fake.add("suricata.alert", iso(at(0, 10)), **{"tags": ["alert"], "source.ip": HMI, "destination.ip": PLC, "event.severity": 3})
        self.fake.add("suricata.alert", iso(at(0, 11)), **{"tags": ["alert"], "source.ip": "203.0.113.9", "destination.ip": HMI, "event.severity": 2})
        self.fake.add("greenbone.result", iso(at(0, 12)), **{"host.ip": [PLC], "event.severity": 4})
        self.fake.add("opencanary.alerts", iso(at(0, 13)), **{"event.module": "opencanary", "source.ip": HMI})
        self.sync(at(1))
        hmi, plc = self.store.asset(HMI), self.store.asset(PLC)
        self.assertEqual((hmi["alerts"], hmi["worst_alert"], hmi["honeypot"]), (2, 3, 1))
        self.assertEqual((plc["alerts"], plc["findings"], plc["worst_finding"]), (1, 1, 4))


class Baseline(Case):
    def test_nothing_is_reported_for_what_was_learned(self):
        self.learn()
        self.conn(at(26), HMI, PLC, 502, service="modbus")
        self.op("zeek.modbus", at(26), HMI, PLC, "WRITE_SINGLE_REGISTER")
        self.assertEqual(self.sync(at(27))["changes"], 0)

    def test_a_new_station_sending_control_commands_is_high(self):
        self.learn()
        for port in (502, 1502, 2502):                         # several ports must still be one change
            self.conn(at(26), LAPTOP, PLC, port, service="modbus")
        self.op("zeek.modbus", at(26), LAPTOP, PLC, "WRITE_MULTIPLE_COILS")
        self.op("zeek.modbus", at(26), LAPTOP, PLC, "READ_COILS")
        self.sync(at(27))
        self.assertEqual(sorted(self.changes()), sorted([
            ("new_control_operation", HIGH, LAPTOP, PLC), ("new_industrial_conversation", MEDIUM, LAPTOP, PLC),
            ("new_device", LOW, LAPTOP, "")]))
        detail = [row["detail"] for row in self.store.changes() if row["kind"] == "new_control_operation"][0]
        self.assertIn("WRITE_MULTIPLE_COILS", detail)
        self.assertNotIn("READ_COILS", detail)
        self.assertEqual(self.sync(at(28))["changes"], 0)       # and it is not reported again
        self.conn(at(28, 5), LAPTOP, PLC, 3502, service="modbus")
        self.assertEqual(self.sync(at(29))["changes"], 0)       # nor for yet another port

    def test_a_second_new_command_from_a_station_already_reported_is_not_called_its_first(self):
        self.learn()
        self.conn(at(26), LAPTOP, PLC, 502, service="modbus")
        self.op("zeek.modbus", at(26), LAPTOP, PLC, "WRITE_MULTIPLE_COILS")
        self.sync(at(27))
        self.op("zeek.modbus", at(27, 30), LAPTOP, PLC, "WRITE_SINGLE_REGISTER")
        self.sync(at(28))
        newest = self.store.changes()[0]
        self.assertEqual((newest["kind"], newest["severity"], newest["title"]),
                         ("new_control_operation", MEDIUM, "New kind of control command to a device"))
        self.assertNotIn("had never sent", newest["detail"])

    def test_attempts_that_get_no_answer_do_not_create_devices(self):
        self.learn()
        for index in range(1, 30):
            self.conn(at(26), LAPTOP, f"10.10.1.{100 + index}", 502, back=0)       # a sweep of empty addresses
        self.conn(at(26), LAPTOP, PLC, 23, back=0)                                    # an existing controller that stays silent
        self.sync(at(27))
        self.assertEqual(sorted(asset["ip"] for asset in self.store.assets()), sorted([HMI, PLC, LAPTOP]))
        self.assertEqual(sorted(self.changes()), sorted([("new_conversation_with_controller", MEDIUM, LAPTOP, PLC), ("new_device", LOW, LAPTOP, "")]))

    def test_broadcast_traffic_is_not_a_connection_to_a_controller(self):
        self.conn(at(0, 4), HMI, "10.10.1.255", 47808, "udp", service="bacnet", back=0)      # a BACnet "who is there" in the baseline
        self.learn()
        self.conn(at(26), HMI, "10.10.1.255", 137, "udp", back=0)                             # an ordinary name broadcast later
        self.assertEqual(self.sync(at(27))["changes"], 0)

    def test_a_device_announcing_itself_in_two_ways_does_not_keep_changing(self):
        self.conn(at(0, 5), HMI, PLC2, 44818, service="enip")
        cip = {"source.ip": HMI, "destination.ip": PLC2, "cip.vendor.name": "Rockwell Automation", "cip.device.product.name": "1756-L71",
               "cip.device.revision": "30.11"}
        bacnet = {"source.ip": PLC2, "destination.ip": "10.10.1.255", "bacnet.pdu.service": "i_am", "bacnet.is_orig": True,
                  "bacnet.vendor": "Rockwell", "bacnet.object.name": "Line 2 gateway"}
        self.fake.add("zeek.bacnet_discovery", iso(at(0, 6)), **bacnet)
        self.fake.add("zeek.cip_identity", iso(at(0, 7)), **cip)
        self.learn()
        self.assertEqual(self.store.asset(PLC2)["model"], "1756-L71")
        for hour in (26, 28, 30):
            self.fake.add("zeek.bacnet_discovery", iso(at(hour)), **bacnet)
            self.fake.add("zeek.cip_identity", iso(at(hour, 1)), **cip)
            self.assertEqual(self.sync(at(hour + 1))["changes"], 0)
        self.assertEqual(self.store.asset(PLC2)["model"], "1756-L71")

    def test_a_known_station_using_a_new_command_is_medium(self):
        self.learn()
        self.op("zeek.modbus", at(26), HMI, PLC, "WRITE_FILE_RECORD")
        self.sync(at(27))
        self.assertEqual(self.changes(), [("new_control_operation", MEDIUM, HMI, PLC)])

    def test_industrial_protocol_from_outside_is_high(self):
        self.learn()
        self.conn(at(26), "203.0.113.50", PLC, 502, service="modbus")
        self.sync(at(27))
        self.assertEqual(self.changes(), [("new_industrial_conversation", HIGH, OUTSIDE, PLC)])

    def test_a_new_kind_of_connection_to_a_controller_is_reported_once_per_pair(self):
        self.learn()
        for port in (22, 23, 8080, 9999, 12345):
            self.conn(at(26), OFFICE, PLC, port)
        self.conn(at(26), OFFICE, HMI, 3389)                      # the HMI is not a controller: not reported
        self.sync(at(27))
        self.assertEqual(sorted(self.changes()), sorted([("new_conversation_with_controller", MEDIUM, OFFICE, PLC), ("new_device", LOW, OFFICE, "")]))
        detail = [row["detail"] for row in self.store.changes() if row["kind"] == "new_conversation_with_controller"][0]
        self.assertIn("SSH", detail)
        self.assertIn("Telnet", detail)

    def test_a_card_by_another_maker_is_reported_once(self):
        self.learn()
        self.conn(at(26), PLC, HMI, 80, service="http", maker="VMware, Inc.")
        self.sync(at(27))
        self.assertEqual(self.changes(), [("card_maker_changed", HIGH, PLC, "")])
        self.assertEqual(self.store.asset(PLC)["maker"], "Schneider Electric; VMware, Inc.")
        self.conn(at(27, 5), PLC, HMI, 80, service="http", maker="VMware, Inc.")
        self.conn(at(27, 6), PLC, HMI, 80, service="http", maker="Schneider Electric")
        self.assertEqual(self.sync(at(28))["changes"], 0)

    def test_a_changed_version_is_reported(self):
        identity = {"source.ip": HMI, "destination.ip": PLC, "cip.vendor.name": "Rockwell Automation", "cip.device.product.name": "1756-L71"}
        self.fake.add("zeek.cip_identity", iso(at(0, 6)), **identity, **{"cip.device.revision": "30.11"})
        self.learn()
        self.fake.add("zeek.cip_identity", iso(at(26)), **identity, **{"cip.device.revision": "33.01"})
        self.sync(at(27))
        self.assertEqual(self.changes(), [("identity_changed", MEDIUM, PLC, "")])
        self.assertIn("version was 30.11, now 33.01", self.store.changes()[0]["detail"])

    def test_a_scan_does_not_flood_the_list(self):
        self.learn()
        for index in range(1, 60):
            self.conn(at(26), f"10.10.20.{index}", PLC, 502, service="modbus")
        summary = self.sync(at(27), max_changes=20)
        kinds = [row["kind"] for row in self.store.changes()]
        self.assertEqual(len(kinds), 21)
        self.assertEqual(kinds.count("more_changes"), 1)
        self.assertEqual(kinds.count("new_industrial_conversation"), 20)      # the most severe are the ones kept
        self.assertEqual(summary["changes"], 118)

    def test_accepting_makes_the_present_state_the_baseline(self):
        self.learn()
        self.conn(at(26), LAPTOP, PLC, 502, service="modbus")
        self.op("zeek.modbus", at(26), LAPTOP, PLC, "WRITE_MULTIPLE_COILS")
        self.sync(at(27))
        self.assertEqual(self.store.counts()["open_changes"], 3)
        self.assertEqual(self.store.accept_all(at(28)), 3)
        self.assertEqual(self.store.counts()["open_changes"], 0)
        self.op("zeek.modbus", at(28, 30), LAPTOP, PLC, "WRITE_SINGLE_COIL")
        self.sync(at(29))
        self.assertEqual(self.changes()[0], ("new_control_operation", MEDIUM, LAPTOP, PLC))     # now a known station


class Trouble(Case):
    def test_an_unreachable_platform_loses_nothing(self):
        self.conn(at(0, 5), HMI, PLC, 502, service="modbus")
        self.fake.fail_with = 503
        with self.assertRaises(fw.HttpError):
            self.sync(at(1))
        self.assertEqual(self.store.assets(), [])
        self.assertIsNone(self.store.meta("synced_until"))
        self.fake.fail_with = 0
        self.sync(at(2))
        self.assertEqual(len(self.store.conversations()), 1)

    def test_a_failure_part_way_leaves_no_half_written_pass(self):
        self.conn(at(0, 5), HMI, PLC, 502, service="modbus")
        original = self.platform.card_makers

        def broken(since, until):
            raise fw.HttpError("connection reset", True)
        self.platform.card_makers = broken
        with self.assertRaises(fw.HttpError):
            self.sync(at(1))
        self.assertEqual(self.store.conversations(), [])
        self.platform.card_makers = original
        self.sync(at(1, 5))
        self.assertEqual(self.store.conversations()[0]["connections"], 1)

    def test_a_field_the_platform_cannot_group_on_is_a_warning(self):
        self.conn(at(0, 5), HMI, PLC, 502, service="modbus", maker="Siemens AG")
        self.fake.bad_fields.add("client.oui")
        summary = self.sync(at(1))
        self.assertEqual(len(self.store.conversations()), 1)
        self.assertTrue(any("network card makers could not be read" in warning for warning in summary["warnings"]))
        self.assertIn("network card makers could not be read", web.status_notice(self.store, at(1)))

    def small_reads(self):
        import td_net.platform as module
        saved = module.PAGE
        module.PAGE = 10
        self.addCleanup(setattr, module, "PAGE", saved)
        self.platform.max_pages = 2                    # one read now carries 20 groups

    def test_more_than_one_read_carries_is_read_in_smaller_windows(self):
        for index in range(1, 40):
            self.conn(at(0, index), f"10.10.10.{index}", PLC, 502, service="modbus")
        self.small_reads()
        summary = self.sync(at(2))
        self.assertEqual(len(self.store.conversations()), 39)
        self.assertEqual(summary["warnings"], [])
        self.assertEqual(self.store.conversations()[0]["connections"], 1)       # and nothing was counted twice

    def test_more_than_fits_in_a_single_minute_is_said_plainly(self):
        for index in range(1, 40):
            self.conn(at(0, 5), f"10.10.10.{index}", PLC, 502, service="modbus")
        self.small_reads()
        summary = self.sync(at(2))
        self.assertEqual(len(self.store.conversations()), 20)
        self.assertTrue(any("more in one minute than can be read" in warning for warning in summary["warnings"]), summary["warnings"])
        self.assertIn("more in one minute than can be read", web.status_notice(self.store, at(2)))

    def test_an_answer_built_from_part_of_the_data_is_not_accepted(self):
        self.conn(at(0, 5), HMI, PLC, 502, service="modbus")
        self.fake.failed_shards = 1
        with self.assertRaises(fw.HttpError):
            self.sync(at(1))
        self.assertEqual(self.store.conversations(), [])
        self.fake.failed_shards = 0
        self.sync(at(1, 5))
        self.assertEqual(len(self.store.conversations()), 1)

    def test_records_that_arrive_after_they_were_read_are_noticed(self):
        self.conn(at(0, 5), HMI, PLC, 502, service="modbus")
        self.sync(at(1))
        # Written by the sensor before the last pass, but held up on the way for longer than the pass waits.
        self.conn(at(0, 30), ENGINEERING, PLC, 102, service="s7comm", ingested=at(0, 31))
        summary = self.sync(at(1, 10))
        self.assertTrue(any("1 connection record reached the platform more than 300 seconds" in warning
                            for warning in summary["warnings"]), summary["warnings"])
        self.assertEqual(self.sync(at(1, 20))["warnings"], [])

    def test_run_cycle_reports_instead_of_raising(self):
        os.environ.update({"TD_ES_URL": self.fake.url, "TD_ES_API_KEY": "read-key", "TD_NET_PASSWORD": "x" * 20, "TD_NET_ALLOW_PLAIN_HTTP": "1"})
        self.addCleanup(lambda: [os.environ.pop(name, None) for name in ("TD_ES_URL", "TD_ES_API_KEY", "TD_NET_PASSWORD", "TD_NET_ALLOW_PLAIN_HTTP")])
        config = Config()
        self.fake.fail_with = 500
        summary = run_cycle(config, self.platform, self.store, None, at(1))
        self.assertEqual(len(summary["errors"]), 1)
        self.assertIn("HTTP 500", self.store.meta("status")["error"])
        self.assertIn("failed", web.status_notice(self.store, at(1)))


class Alerts(Case):
    def writer(self, key="write-key"):
        return outputs.PlatformWriter(self.fake.url, key, "", True, "logs-netmap.alerts-techdetechtives", "netmap-01")

    def make_changes(self):
        self.learn()
        self.conn(at(26), LAPTOP, PLC, 502, service="modbus")
        self.op("zeek.modbus", at(26), LAPTOP, PLC, "WRITE_MULTIPLE_COILS")
        self.sync(at(27))

    def test_changes_become_alerts_the_forwarder_can_ticket(self):
        self.make_changes()
        self.assertEqual(self.writer().send(self.store), 3)
        documents = sorted(self.fake.created.values(), key=lambda document: -document["event"]["severity"])
        top = documents[0]
        self.assertEqual(top["tags"][0], "alert")
        self.assertEqual((top["event"]["severity"], top["event"]["severity_label"], top["event"]["module"]), (3, "high", "netmap"))
        self.assertEqual(top["rule"]["name"], "Network baseline: New station sending control commands to a device")
        self.assertEqual((top["source"]["ip"], top["destination"]["ip"]), (LAPTOP, PLC))
        self.assertEqual(self.writer().send(self.store), 0)

    def test_a_second_delivery_of_the_same_change_is_harmless(self):
        self.make_changes()
        self.writer().send(self.store)
        self.store.db.execute("UPDATE changes SET sent = 0")
        self.assertEqual(self.writer().send(self.store), 3)
        self.assertEqual(len(self.fake.created), 3)

    def test_a_key_that_may_not_write_keeps_the_changes_for_later(self):
        self.make_changes()
        with self.assertRaises(fw.HttpError):
            self.writer("read-key").send(self.store)
        self.assertEqual(len(self.store.unsent_changes(10)), 3)

    def test_late_delivery_is_stamped_with_the_delivery_time(self):
        self.make_changes()
        row = self.store.unsent_changes(1)[0]
        _, on_time = outputs.to_document(row, "n", at(27, 1))
        _, late = outputs.to_document(row, "n", at(30))
        self.assertEqual(on_time["@timestamp"], iso(at(27)))
        self.assertEqual(late["@timestamp"], iso(at(30)))
        self.assertEqual(late["event"]["created"], iso(at(27)))
        self.assertIn("delivered late", late["message"])


class Pages(Case):
    def setUp(self):
        super().setUp()
        os.environ.update({"TD_ES_URL": self.fake.url, "TD_ES_API_KEY": "read-key", "TD_NET_PASSWORD": "correct-horse-battery",
                           "TD_NET_ALLOW_PLAIN_HTTP": "1", "TD_NET_BIND": "127.0.0.1",
                           "TD_SOC_URL": "https://securityon", "TD_NET_ZONES": "Control=10.10.1.0/24"})
        self.addCleanup(lambda: [os.environ.pop(name, None) for name in list(os.environ) if name.startswith(("TD_NET_", "TD_ES_", "TD_SOC_"))])
        self.config = Config()
        self.config.web_port = 0                      # any free port
        self.path = str(Path(self.enterContext(__import__("tempfile").TemporaryDirectory())) / "net.db")
        self.store = Store(self.path)
        self.addCleanup(self.store.close)
        self.learn()
        self.fake.add("zeek.dhcp", iso(at(26)), **{"dhcp.assigned_ip": LAPTOP, "host.hostname": "<script>alert(1)</script>", "host.mac": "=cmd|' /C calc'!A0"})
        self.conn(at(26), LAPTOP, PLC, 502, service="modbus")
        self.op("zeek.modbus", at(26), LAPTOP, PLC, "WRITE_MULTIPLE_COILS")
        self.sync(at(27))
        self.server = web.make_server(self.config, lambda: Store(self.path), self.config.scope)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def get(self, path, password="correct-horse-battery"):
        request = urllib.request.Request(self.base + path)
        if password:
            request.add_header("Authorization", "Basic " + base64.b64encode(f"analyst:{password}".encode()).decode())
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, response.read().decode(), response.headers
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode(), error.headers

    def test_pages_need_the_password(self):
        self.assertEqual(self.get("/", password="")[0], 401)
        self.assertEqual(self.get("/devices", password="wrong-password-000")[0], 401)
        self.assertEqual(self.get("/healthz", password="")[0], 200)

    def test_every_page_renders(self):
        for path, expected in (("/", "Network overview"), ("/devices", "Devices"), ("/devices?show=industrial", PLC),
                               ("/devices?zone=Control", PLC), (f"/devices/{PLC}", "It answers"), ("/map", "Traffic map"),
                               ("/map?view=all", "Every line on the map"), ("/operations", "WRITE_MULTIPLE_COILS"),
                               ("/operations?show=control", "Changes the device"), ("/changes", "New station sending control commands"),
                               ("/changes?show=all", "Open")):
            status, text, headers = self.get(path)
            self.assertEqual(status, 200, path)
            self.assertIn(expected, text, path)
            self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
            self.assertNotIn("<script", text.lower(), path)

    def test_text_from_the_network_is_escaped(self):
        for path in ("/devices", f"/devices/{LAPTOP}", "/map", "/"):
            text = self.get(path)[1]
            self.assertNotIn("<script>alert(1)</script>", text, path)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", self.get(f"/devices/{LAPTOP}")[1])

    def test_the_map_draws_devices_lines_and_zones(self):
        text = self.get("/map")[1]
        self.assertEqual(text.count('class="node"'), 3)                  # HMI, PLC, laptop
        self.assertIn("edge ot-s new", text)                              # the laptop's line is dashed: not in the baseline
        self.assertIn("Zone Control", text)
        self.assertIn(f'href="/devices/{PLC}"', text)

    def test_csv_export_cannot_carry_a_formula(self):
        status, text, headers = self.get("/devices.csv")
        self.assertEqual(status, 200)
        self.assertIn("text/csv", headers["Content-Type"])
        self.assertIn("'=cmd|", text)
        self.assertNotIn(",=cmd|", text)

    def test_unknown_addresses_and_pages_are_404(self):
        self.assertEqual(self.get("/devices/10.99.99.99")[0], 404)
        self.assertEqual(self.get("/devices/..%2f..%2fetc")[0], 404)
        self.assertEqual(self.get("/nothing")[0], 404)

    def test_a_malformed_sign_in_header_is_refused_not_a_crash(self):
        import http.client
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=10)
        connection.putrequest("GET", "/")
        connection.putheader("Authorization", "Basic caf\u00e9".encode("latin-1"))
        connection.endheaders()
        self.assertEqual(connection.getresponse().status, 401)
        connection.close()

    @unittest.skipUnless(__import__("shutil").which("openssl"), "openssl is not installed")
    def test_a_silent_visitor_does_not_block_the_others(self):
        import socket
        import ssl
        import subprocess
        folder = Path(self.enterContext(__import__("tempfile").TemporaryDirectory()))
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-keyout", str(folder / "k.pem"),
                        "-out", str(folder / "c.pem")], check=True, capture_output=True)
        server = web.make_server(self.config, lambda: Store(self.path), self.config.scope)
        web.use_tls(server, str(folder / "c.pem"), str(folder / "k.pem"))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        silent = socket.create_connection(("127.0.0.1", port))          # connects, then never starts the handshake
        self.addCleanup(silent.close)
        context = ssl.create_default_context(cafile=str(folder / "c.pem"))
        request = urllib.request.Request(f"https://127.0.0.1:{port}/healthz")
        with urllib.request.urlopen(request, timeout=5, context=context) as response:
            self.assertEqual(response.read(), b"ok\n")

    def test_the_platform_link_is_offered(self):
        self.assertIn('href="https://securityon/#/hunt?q=', self.get(f"/devices/{PLC}")[1])


class EntryPoint(Case):
    def setUp(self):
        super().setUp()
        folder = self.enterContext(__import__("tempfile").TemporaryDirectory())
        os.environ.update({"TD_ES_URL": self.fake.url, "TD_ES_API_KEY": "read-key", "TD_NET_DB": str(Path(folder) / "net.db"),
                           "TD_NET_INGEST_API_KEY": "write-key", "TD_NET_LEARN_HOURS": "0", "TD_NET_BACKFILL_HOURS": "100000"})
        self.addCleanup(lambda: [os.environ.pop(name, None) for name in list(os.environ) if name.startswith(("TD_NET_", "TD_ES_"))])

    def run_main(self, *arguments):
        import contextlib
        import io
        from td_net import main as entry
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = entry.main(list(arguments))
        return code, output.getvalue()

    def test_check_says_what_is_missing(self):
        code, text = self.run_main("--check")
        self.assertEqual(code, 1)
        self.assertIn("[FAIL] connection records: none", text)
        self.assertIn("sudo so-status", text)

    def test_check_passes_with_records_and_names_the_decoded_protocols(self):
        self.conn(at(0, 5), HMI, PLC, 502, service="modbus")
        self.op("zeek.modbus", at(0, 5), HMI, PLC, "READ_COILS")
        code, text = self.run_main("--check")
        self.assertEqual(code, 0, text)
        self.assertIn("industrial protocols with decoded records: Modbus", text)
        self.assertIn("alerts to the platform: key accepted", text)

    def test_check_with_a_wrong_key_fails(self):
        os.environ["TD_ES_API_KEY"] = "nonsense"
        code, text = self.run_main("--check")
        self.assertEqual(code, 1)
        self.assertIn("[FAIL] platform", text)

    def test_one_pass_then_accept(self):
        self.conn(at(0, 5), HMI, PLC, 502, service="modbus")
        self.assertEqual(self.run_main("--once")[0], 0)
        store = Store(os.environ["TD_NET_DB"])
        self.addCleanup(store.close)
        self.assertEqual(len(store.conversations()), 1)
        # With no learning time the next new thing is a change, and it is delivered as an alert.
        # (The two passes run within the same second here, so the first one's mark is moved back.)
        store.set_meta("synced_until", fw.iso(datetime.now(timezone.utc) - timedelta(minutes=10)))
        store.commit()
        self.conn(datetime.now(timezone.utc) - timedelta(minutes=5), LAPTOP, PLC, 502, service="modbus")
        self.assertEqual(self.run_main("--once")[0], 0)
        self.assertEqual(sorted(document["event"]["action"] for document in self.fake.created.values()),
                         ["new_device", "new_industrial_conversation"])
        code, text = self.run_main("--accept")
        self.assertEqual(code, 0)
        self.assertIn("2 open changes accepted", text)

    def test_an_unreachable_platform_is_an_error_exit_not_a_crash(self):
        self.fake.fail_with = 502
        self.assertEqual(self.run_main("--once")[0], 1)

    def test_status_says_when_the_platform_was_last_read(self):
        code, text = self.run_main("--status")
        self.assertEqual(code, 1)
        self.assertIn("has not been read yet", text)
        self.run_main("--once")                       # a quiet network: nothing recorded, and that is still a finished read
        code, text = self.run_main("--status")
        self.assertEqual(code, 0, text)
        self.assertIn("0 devices", text)
        self.fake.fail_with = 502
        self.run_main("--once")
        code, text = self.run_main("--status")
        self.assertEqual(code, 1)
        self.assertIn("the last read failed", text)

    def test_accept_waits_for_a_pass_instead_of_failing(self):
        self.conn(at(0, 5), HMI, PLC, 502, service="modbus")
        self.run_main("--once")
        holding = threading.Event()

        def a_pass_in_progress():
            busy = Store(os.environ["TD_NET_DB"])
            busy.set_meta("held", 1)                   # an open write
            holding.set()
            __import__("time").sleep(1.5)
            busy.commit()
            busy.close()
        worker = threading.Thread(target=a_pass_in_progress)
        worker.start()
        self.addCleanup(worker.join)
        holding.wait(5)
        code, text = self.run_main("--accept")
        self.assertEqual(code, 0, text)


class Knowledge(unittest.TestCase):
    def test_scope(self):
        scope = Scope(zones="Control=10.10.1.0/24,Plant=10.10.0.0/16")
        self.assertEqual(scope.node("10.10.1.5"), "10.10.1.5")
        self.assertEqual(scope.node("8.8.8.8"), OUTSIDE)
        self.assertEqual(scope.node("224.0.0.251"), MULTICAST)
        self.assertEqual(scope.node("10.10.1.255"), MULTICAST)
        self.assertEqual(scope.node("255.255.255.255"), MULTICAST)
        self.assertIsNone(scope.node("0.0.0.0"))
        self.assertIsNone(scope.node("not an address"))
        self.assertEqual(scope.node("fe80::1"), "fe80::1")
        self.assertEqual(scope.zone("10.10.1.5"), "Control")              # the narrower network wins
        self.assertEqual(scope.zone("10.10.7.5"), "Plant")
        self.assertEqual(scope.zone("192.168.3.9"), "192.168.3.0/24")
        self.assertEqual(Scope(inside="10.0.0.0/8").node("192.168.1.1"), OUTSIDE)
        for bad in ({"inside": "10.0.0.0/33"}, {"zones": "Control"}, {"zones": "Control=nonsense"}):
            with self.assertRaises(fw.ConfigError):
                Scope(**bad)

    def test_protocols_are_named_from_the_sensor_first_and_the_port_second(self):
        self.assertEqual(protocols.classify("modbus", "tcp", 1502), ("Modbus", True, "decoded"))
        self.assertEqual(protocols.classify("", "tcp", 502), ("Modbus", True, "port"))
        self.assertEqual(protocols.classify("", "tcp", 55553), ("Honeywell Experion engineering", True, "port"))
        self.assertEqual(protocols.classify("ssl,http", "tcp", 443), ("TLS", False, "decoded"))
        self.assertEqual(protocols.classify("", "tcp", 31337), ("tcp/31337", False, "port"))
        self.assertEqual(protocols.classify("", "icmp", None), ("icmp", False, "port"))

    def test_control_operations(self):
        yes = [("Modbus", "WRITE_SINGLE_COIL"), ("Modbus", "write_multiple_registers"), ("S7comm", "PLC Stop"),
               ("DNP3", "COLD_RESTART"), ("DNP3", "direct-operate-nr"), ("EtherNet/IP", "Set Attributes Single"),
               ("EtherNet/IP", "Reset"), ("BACnet", "reinitialize_device"), ("BACnet", "reinitialize-device"),
               ("Modbus", "READ_WRITE_MULTIPLE_REGISTERS"), ("OPC UA", "WriteRequest"), ("PROFINET", "write")]
        no = [("Modbus", "READ_COILS"), ("S7comm", "Read Variable"), ("DNP3", "READ"), ("EtherNet/IP", "Get Attributes All"),
              ("EtherNet/IP", "Get Attributes Single"), ("OPC UA", "ReadRequest"), ("S7comm-plus", "Request"),
              ("BACnet", "read_property"), ("Modbus", ""), ("Unknown", "WRITE")]
        for label, operation in yes:
            self.assertTrue(protocols.is_control(label, operation), (label, operation))
        for label, operation in no:
            self.assertFalse(protocols.is_control(label, operation), (label, operation))

    def test_industrial_card_makers(self):
        for maker in ("Siemens AG", "Schneider Electric", "Rockwell Automation", "Honeywell International", "ABB Oy", "Yokogawa Digital Computer"):
            self.assertTrue(protocols.industrial_vendor(maker), maker)
        for maker in ("Dell Inc.", "VMware, Inc.", "Intel Corporate", "Fabbrica Italiana", ""):
            self.assertFalse(protocols.industrial_vendor(maker), maker)

    def test_settings(self):
        saved = {name: os.environ.pop(name) for name in list(os.environ) if name.startswith(("TD_NET_", "TD_ES_"))}
        self.addCleanup(os.environ.update, saved)
        self.addCleanup(lambda: [os.environ.pop(name, None) for name in list(os.environ) if name.startswith(("TD_NET_", "TD_ES_"))])
        with self.assertRaises(fw.ConfigError):
            Config()                                          # no platform
        os.environ.update({"TD_ES_HOST": "securityon", "TD_ES_API_KEY": "k"})
        with self.assertRaises(fw.ConfigError):
            Config()                                          # no password
        os.environ["TD_NET_PASSWORD"] = "short"
        with self.assertRaises(fw.ConfigError):
            Config()
        os.environ["TD_NET_PASSWORD"] = "long-enough-password"
        with self.assertRaises(fw.ConfigError):
            Config()                                          # no TLS files
        os.environ.update({"TD_NET_TLS_CERT": "/tls/c.pem", "TD_NET_TLS_KEY": "/tls/k.pem"})
        config = Config()
        self.assertEqual((config.es_url, config.web_port, config.to_platform), ("https://securityon:9200", 8445, False))
        self.assertIsNotNone(Config(serving=False))


if __name__ == "__main__":
    unittest.main()
