# TechDetechtives OT IDS tests. Copyright (c) 2026 TechDetechtives. MIT licence.
"""Run with:  python3 -m unittest discover -s ot-ids/tests -v

What is checked here, without the product or a network:

* Suricata rules in ot-ids/detections: structure, reserved numbers, that every
  flag an alert waits for is set by a marker rule, and, for rules that match
  bytes at fixed positions, sample requests that must and must not match.
  This is not the engine's own syntax check; build-iso.sh runs that.
* YARA rules: compiled and run against sample files made here, when a `yara`
  program is installed; skipped otherwise.
* The tools: Snort conversion, pruning from engine output, indicator
  conversion, the vulnerability index, the source list.
* The anomaly detectors, alert monitors and hardening files: shape only.
* MITRE ATT&CK for ICS: every rule here is in the mapping, every technique
  named exists in the reference, tagging keeps a rule's structure, and the
  coverage page in docs/ is what the tool writes today.
"""

import configparser
import contextlib
import csv
import io
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

KIT = Path(__file__).resolve().parents[1]
ROOT = KIT.parent
sys.path.insert(0, str(KIT / "tools"))

import attack_ics         # noqa: E402
import cve_index          # noqa: E402
import ioc2intel          # noqa: E402
import prune_rules        # noqa: E402
import snort2suricata     # noqa: E402


def rule_lines(folder):
    return [(path.name, number, line)
            for path in sorted(folder.glob("*.rules"))
            for number, line in enumerate(path.read_text().splitlines(), 1)
            if line.strip() and not line.startswith("#")]


RULES = rule_lines(KIT / "detections" / "suricata")
SHARED = rule_lines(ROOT / "platform" / "detections" / "suricata")


def rule(sid):
    for _, _, line in RULES:
        if f"sid:{sid};" in line:
            return line
    raise AssertionError(f"no rule with sid {sid}")


def payload_matches(options, payload):
    """Evaluate the byte-position options these rules use against one packet:
    content with offset/depth, content after the previous match (distance,
    within), and one-byte byte_test with the operators & !& >= <=."""
    steps = re.findall(r'(content):"([^"]*)"|(offset|depth|distance|within):(\d+)|(byte_test):([^;]+)', options)
    parsed = []
    for content, value, modifier, number, test, arguments in steps:
        if content:
            data = b"".join(bytes.fromhex(part) if index % 2 else part.encode() for index, part in enumerate(value.split("|")))
            parsed.append({"data": data})
        elif modifier:
            parsed[-1][modifier] = int(number)
        else:
            parsed.append({"test": [item.strip() for item in arguments.split(",")]})
    cursor = 0
    for step in parsed:
        if "test" in step:
            size, operator, value, offset = step["test"][:4]
            if size != "1":
                raise AssertionError("byte_test size not handled by this test")
            if int(offset) >= len(payload):
                return False
            byte, value = payload[int(offset)], int(value)
            result = {"&": bool(byte & value), "!&": not byte & value, ">=": byte >= value, "<=": byte <= value}.get(operator)
            if result is None:
                raise AssertionError(f"byte_test operator {operator} not handled by this test")
            if not result:
                return False
            continue
        data = step["data"]
        if "distance" in step:
            start = cursor + step["distance"]
            found = payload.find(data, start, start + step["within"] if "within" in step else len(payload))
        else:
            start = step.get("offset", 0)
            window = payload[start:start + step["depth"]] if "depth" in step else payload[start:]
            found = window.find(data)
            found = found + start if found >= 0 else -1
        if found < 0:
            return False
        cursor = found + len(data)
    return True


class SuricataStructure(unittest.TestCase):
    HEADER = re.compile(r"^alert (tcp|udp|modbus|dnp3) (\S+) (\S+) -> (\S+) (\S+) \((.*)\)$")
    THRESHOLD = re.compile(r"^\s*type (limit|both|threshold), track (by_src|by_dst), (count \d+, seconds \d+|seconds \d+, count \d+)\s*$")
    XBITS = re.compile(r"^(set|isset),(td\.[a-z.]+),track ip_(src|dst)(,expire \d+)?$")
    CLASSTYPES = {"attempted-dos", "attempted-recon", "attempted-admin", "policy-violation", "misc-activity"}
    RANGES = {"techdetechtives-ot-behavior.rules": (1900401, 1900449, "TECHDETECHTIVES OT Behaviour - "),
              "techdetechtives-ot-correlation.rules": (1900451, 1900499, "TECHDETECHTIVES OT Correlation - "),
              "techdetechtives-ot-control-extra.rules": (1900501, 1900599, "TECHDETECHTIVES OT ")}

    def test_there_are_rules(self):
        self.assertGreaterEqual(len(RULES), 35)
        self.assertEqual({name for name, _, _ in RULES}, set(self.RANGES))

    def test_structure(self):
        for name, number, line in RULES:
            where = f"{name}:{number}"
            match = self.HEADER.match(line)
            self.assertIsNotNone(match, f"{where}: not 'alert <proto> <src> <port> -> <dst> <port> (options)'")
            options = match.group(6)
            self.assertTrue(options.endswith(";"), where)
            self.assertEqual(options.count('"') % 2, 0, f"{where}: unbalanced quotes")
            self.assertNotIn("(", re.sub(r'"[^"]*"', '""', options), where)
            low, high, prefix = self.RANGES[name]
            message = re.search(r'msg:"([^"]+)"', options)
            self.assertTrue(message and message.group(1).startswith(prefix), f"{where}: msg must start with '{prefix}'")
            self.assertNotIn(";", message.group(1), where)
            sid = int(re.search(r"\bsid:(\d+);", options).group(1))
            self.assertTrue(low <= sid <= high, f"{where}: sid {sid} outside {low}-{high}")
            self.assertRegex(options, r"\brev:\d+;", where)
            classtype = re.search(r"classtype:([a-z-]+);", options)
            self.assertTrue(classtype and classtype.group(1) in self.CLASSTYPES, f"{where}: classtype")
            self.assertRegex(options, r"priority:[123];", where)
            self.assertRegex(options, r"metadata:created_at \d{4}_\d\d_\d\d, updated_at \d{4}_\d\d_\d\d;", where)
            self.assertNotIn("$EXTERNAL_NET", line, f"{where}: write !$HOME_NET")
            for content in re.findall(r'content:"([^"]*)"', options):
                for block in re.findall(r"\|([^|]*)\|", content):
                    self.assertRegex(block, r"^([0-9a-fA-F]{2}( |$))+$", f"{where}: bad hex bytes '{block}'")
            for value in re.findall(r"threshold:([^;]+);", options):
                self.assertIsNotNone(self.THRESHOLD.match(value), f"{where}: threshold '{value}'")
            for value in re.findall(r"xbits:([^;]+);", options):
                self.assertIsNotNone(self.XBITS.match(value), f"{where}: xbits '{value}'")

    def test_numbers_are_unique_across_both_rule_sets(self):
        sids = [re.search(r"\bsid:(\d+);", line).group(1) for _, _, line in RULES + SHARED]
        self.assertEqual(len(sids), len(set(sids)), "a sid is used twice")
        if SHARED:
            self.assertGreaterEqual(len(SHARED), 40)

    def test_protocol_decoders_are_used_with_their_own_options(self):
        for name, number, line in RULES:
            if line.startswith("alert modbus"):
                self.assertRegex(line, r"modbus: (function \d+(, subfunction \d+)?|access write);", f"{name}:{number}")
            if line.startswith("alert dnp3"):
                self.assertRegex(line, r"dnp3_ind:[a-z_]+;", f"{name}:{number}")

    def test_rate_rules_count_at_a_rate_above_ordinary_traffic(self):
        for name, number, line in RULES:
            if name != "techdetechtives-ot-behavior.rules":
                continue
            fields = dict(re.findall(r"(type|track|count|seconds) (\w+)", re.search(r"threshold:([^;]+);", line).group(1)))
            if fields["type"] == "limit":
                continue
            self.assertEqual(fields["type"], "both", f"{name}:{number}: a rate rule alerts once per window")
            self.assertGreaterEqual(int(fields["count"]), 5, f"{name}:{number}")

    def test_every_flag_an_alert_waits_for_is_set_by_a_marker(self):
        setters, readers = {}, {}
        for name, number, line in RULES:
            for action, flag, side in re.findall(r"xbits:(set|isset),([a-z.]+),track ip_(src|dst)", line):
                (setters if action == "set" else readers).setdefault(flag, []).append((number, line))
                if action == "set":
                    self.assertIn("noalert;", line, f"{name}:{number}: a marker must not alert")
                    self.assertRegex(line, r"expire \d+;", f"{name}:{number}: a marker needs an expiry")
                else:
                    self.assertNotIn("noalert;", line, f"{name}:{number}")
                    self.assertEqual(side, "src", f"{name}:{number}: the alert reads the flag of the sender")
        self.assertEqual(set(setters), set(readers), "a flag is set but never read, or read but never set")
        self.assertEqual(set(setters), {"td.ot.recon", "td.remote.in"})
        for name, number, line in RULES:
            if "noalert;" in line:
                self.assertIn("xbits:set,", line, f"{name}:{number}: noalert without a flag does nothing")


class SuricataBytePositions(unittest.TestCase):
    """Requests built from the public layout of each protocol."""

    @staticmethod
    def modbus(function, data, unit=1, transaction=1):
        body = bytes([unit, function]) + data
        return transaction.to_bytes(2, "big") + b"\x00\x00" + len(body).to_bytes(2, "big") + body

    @staticmethod
    def s7(rosctr, parameters, data=b""):
        header = bytes([0x32, rosctr, 0, 0, 0x05, 0x00]) + len(parameters).to_bytes(2, "big") + len(data).to_bytes(2, "big")
        pdu = b"\x02\xf0\x80" + header + parameters + data
        return b"\x03\x00" + (len(pdu) + 4).to_bytes(2, "big") + pdu

    @staticmethod
    def iec104(type_id, body=b"\x01\x06\x00\x01\x00\x00\x00\x00\x01"):
        apdu = b"\x00\x00\x00\x00" + bytes([type_id]) + body
        return b"\x68" + bytes([len(apdu)]) + apdu

    def check(self, cases):
        for sid, (positives, negatives) in cases.items():
            options = rule(sid)
            for payload in positives:
                self.assertTrue(payload_matches(options, payload), f"sid {sid} should match {payload.hex()}")
            for payload in negatives:
                self.assertFalse(payload_matches(options, payload), f"sid {sid} should not match {payload.hex()}")

    def test_layouts(self):
        stop = self.modbus(0x5A, b"\x00\x41\xff\x00")
        self.assertEqual((stop[7], stop[9]), (0x5A, 0x41))
        self.assertEqual(int.from_bytes(stop[4:6], "big"), len(stop) - 6)
        download = self.s7(0x01, b"\x1a\x00\x01\x00\x00\x00\x00\x00\x09_0A00001P")
        self.assertEqual(download[17], 0x1A)
        self.assertEqual(int.from_bytes(download[2:4], "big"), len(download))
        self.assertEqual(self.iec104(0x67)[6], 0x67)

    def test_umas(self):
        # "download" and "upload" as automation practice uses them: 0x30 writes a program to
        # the controller, 0x33 reads it out. The public UMAS write-ups name them the other way.
        umas = {name: self.modbus(0x5A, bytes([0x00, code]) + b"\x00\x00") for name, code in
                {"stop": 0x41, "start": 0x40, "download": 0x30, "upload": 0x33, "reserve": 0x10, "read_id": 0x02, "keepalive": 0x12}.items()}
        write_register = self.modbus(0x06, b"\x00\x41\x00\x41")           # ordinary Modbus write carrying 0x41
        others = lambda keep: [packet for name, packet in umas.items() if name != keep] + [write_register]   # noqa: E731
        self.check({1900501: ([umas["stop"]], others("stop")), 1900502: ([umas["start"]], others("start")),
                    1900503: ([umas["download"]], others("download")), 1900504: ([umas["upload"]], others("upload")),
                    1900505: ([umas["reserve"]], others("reserve")), 1900467: ([umas["stop"]], others("stop"))})

    def test_s7(self):
        stop = self.s7(0x01, b"\x29\x00\x00\x00\x00\x00\x09P_PROGRAM")
        download = self.s7(0x01, b"\x1a\x00\x01\x00\x00\x00\x00\x00\x09_0A00001P")
        upload = self.s7(0x01, b"\x1d\x00\x00\x00\x00\x00\x00\x00\x09_0A00001A")
        insert = self.s7(0x01, b"\x28\x00\x00\x00\x00\x00\x00\xfd\x00\x0a\x01\x000A00001P\x05_INSE")
        delete = self.s7(0x01, b"\x28\x00\x00\x00\x00\x00\x00\xfd\x00\x0a\x01\x000A00001B\x05_DELE")
        read = self.s7(0x01, b"\x04\x01\x12\x0a\x10\x02\x00\x01\x00\x00\x84\x00\x00\x00")
        identity = self.s7(0x07, b"\x00\x01\x12\x04\x11\x44\x01\x00", b"\xff\x09\x00\x04\x00\x1c\x00\x00")
        clock = self.s7(0x07, b"\x00\x01\x12\x04\x11\x47\x01\x00", b"\x0a\x00\x00\x00")
        self.assertEqual(identity[17:24], bytes.fromhex("00011204114401"))
        self.check({1900511: ([download], [stop, upload, insert, read, identity]),
                    1900512: ([upload], [stop, download, read, identity]),
                    1900513: ([insert], [delete, stop, download, read]),
                    1900411: ([identity], [clock, read, stop]), 1900454: ([identity], [clock, read, stop]),
                    1900463: ([stop], [download, read, identity]), 1900476: ([stop], [download, read, identity]),
                    1900464: ([download], [stop, upload, read])})

    def test_iec104(self):
        stopdt, startdt, testfr = (bytes.fromhex(text) for text in ("680413000000", "680407000000", "680443000000"))
        supervisory = bytes.fromhex("680401006700")                       # S-format frame: never a command
        clock = self.iec104(0x67, b"\x01\x06\x00\x01\x00\x00\x00\x00" + b"\x00" * 7)
        parameter, interrogation = self.iec104(0x71), self.iec104(0x64)
        files = [self.iec104(type_id) for type_id in (120, 122, 125, 127)]
        self.check({1900521: ([stopdt], [startdt, testfr, clock, interrogation]),
                    1900522: ([clock], [parameter, interrogation, supervisory, stopdt]),
                    1900523: ([parameter], [clock, interrogation, supervisory]),
                    1900524: (files, [self.iec104(119), self.iec104(128), interrogation, clock, supervisory, stopdt])})

    def test_behaviour_content_rules(self):
        exception = self.modbus(0x83, b"\x02")
        normal_response = self.modbus(0x03, b"\x02\x00\x0a")
        long_exception_like = self.modbus(0x83, b"\x02\x00\x00")           # error bit set but not the length of an error reply
        who_is = bytes.fromhex("810b000c0120ffff00ff1008")
        i_am = bytes.fromhex("810b00140120ffff00ff1000c4020004d22205c491032201f5")
        read_property = bytes.fromhex("810a001101040005010c0c020004d2194d")
        write_request = b"\x00\x02fw.bin\x00octet\x00"
        read_request = b"\x00\x01fw.bin\x00octet\x00"
        self.check({1900403: ([exception], [normal_response, long_exception_like]),
                    1900408: ([who_is], [i_am, read_property]),
                    1900409: ([write_request], [read_request, b"\x00\x03\x00\x01data"])})


@unittest.skipUnless(shutil.which("yara"), "the yara program is not installed")
class YaraRules(unittest.TestCase):
    """Sample files are made here at run time; nothing that looks like attack
    tooling is stored in the repository."""

    FILES = sorted((KIT / "detections" / "yara").glob("*.yar"))
    SAMPLES = {
        "TechDetechtives_OT_Controller_Program_PLCopen_XML": (
            [b'<?xml version="1.0"?>\n<project xmlns="http://www.plcopen.org/xml/tc6_0200"><types><pous><pou name="PLC_PRG" pouType="program"/></pous></types></project>'],
            [b'<project xmlns="http://maven.apache.org/POM/4.0.0"><pous></pous></project>', b"see http://www.plcopen.org/xml/tc6_0200 for the schema"]),
        "TechDetechtives_OT_Controller_Program_Rockwell_Export": (
            [b'<?xml version="1.0" encoding="UTF-8"?>\n<RSLogix5000Content SchemaRevision="1.0" SoftwareRevision="32.00">',
             b'IE_VER := 2.11;\n\nCONTROLLER Line4 (ProcessorType := "1756-L83E", Major := 32)\n'],
            [b"notes: export with IE_VER := 2.11 in the header", b"x" * 4096 + b"<RSLogix5000Content mentioned deep inside a log"]),
        "TechDetechtives_OT_Controller_Program_Schneider_Export": (
            [b'<?xml version="1.0"?><FEFExchangeFile><fileHeader company="Schneider Automation" product="Control Expert"/><contentHeader name="Project"/></FEFExchangeFile>'],
            [b"<FEFExchangeFile> is the root element of an XEF export"]),
        "TechDetechtives_OT_Controller_Program_Source_Text": (
            [b'ORGANIZATION_BLOCK OB 1\nTITLE = "Main"\nBEGIN\nNETWORK\n      A I 0.0\nEND_ORGANIZATION_BLOCK\n',
             b"FUNCTION_BLOCK Pump\nVAR_INPUT\n  run : BOOL;\nEND_VAR\nEND_FUNCTION_BLOCK\n"],
            [b"The keyword FUNCTION_BLOCK starts a block.", b"MZ" + b"\x00" * 64 + b"FUNCTION_BLOCK END_FUNCTION_BLOCK VAR_INPUT"]),
        "TechDetechtives_OT_Substation_Configuration_IEC61850": (
            [b'<?xml version="1.0"?><SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007"><IED name="P1" manufacturer="X"/></SCL>'],
            [b'<SCL xmlns="urn:example"><IED name="x"/></SCL>', b"schema at http://www.iec.ch/61850/2003/SCL"]),
        "TechDetechtives_OT_Scan_Script_Names_Industrial_Probes": (
            [b"nmap -Pn -p 102,502,44818 --script s7-info,modbus-discover,enip-info 10.0.0.0/24\n"],
            [b"nmap -p 102 --script s7-info 10.0.0.5\n", b"nmap --script http-title,ssl-cert,smb-os-discovery 10.0.0.0/24\n"]),
        "TechDetechtives_OT_Exploitation_Framework_Names": (
            [b"python icssploit.py\nuse exploits/plcs/siemens/s7_300_400_plc_control\nset target 10.0.0.5\nrun\n"],
            [b"icssploit is a tool described in the course notes", b"use exploits/plcs/ from another framework"]),
        "TechDetechtives_OT_Industroyer_Component_Names": (
            [b"copy haslo.dat C:\\Users\\Public\\ & copy 104.dll C:\\Users\\Public\\", b"MZ" + b"\x00" * 40 + b"101.dll\x00104.dll\x0061850.dll\x00"],
            [b"haslo.dat alone", b"only 104.dll and 61850.dll are named here"]),
        "TechDetechtives_OT_Stuxnet_File_Names": (
            [b"rename s7otbxdx.dll s7otbxsx.dll", b"~WTR4141.tmp ~WTR4132.tmp"],
            [b"the genuine library s7otbxdx.dll", b"only mrxcls.sys"]),
    }

    def scan(self, data):
        with tempfile.TemporaryDirectory() as folder:
            sample = Path(folder) / "sample.bin"
            sample.write_bytes(data)
            hits = set()
            for path in self.FILES:
                result = subprocess.run([shutil.which("yara"), str(path), str(sample)], capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, f"{path.name} does not compile: {result.stderr}")
                hits.update(line.split()[0] for line in result.stdout.splitlines() if line.strip())
            return hits

    def test_every_rule_has_samples(self):
        defined = set()
        for path in self.FILES:
            defined.update(re.findall(r"^rule (\w+)", path.read_text(), re.M))
        self.assertEqual(defined, set(self.SAMPLES))

    def test_rules_match_their_samples_and_not_the_lookalikes(self):
        for name, (positives, negatives) in self.SAMPLES.items():
            for data in positives:
                self.assertIn(name, self.scan(data), f"{name} should match {data[:60]!r}")
            for data in negatives:
                self.assertNotIn(name, self.scan(data), f"{name} should not match {data[:60]!r}")

    def test_names_metadata_and_size_bound(self):
        shared = set()
        for path in (ROOT / "platform" / "detections" / "yara").glob("*.yar"):
            shared.update(re.findall(r"^rule (\w+)", path.read_text(), re.M))
        for path in self.FILES:
            text = path.read_text()
            for name in re.findall(r"^rule (\w+)", text, re.M):
                self.assertTrue(name.startswith("TechDetechtives_OT_"), name)
                self.assertNotIn(name, shared, f"{name} already exists in the shared rules")
            self.assertEqual(len(re.findall(r"^rule ", text, re.M)), len(re.findall(r"filesize < ", text)), "every rule bounds the file size")
            self.assertEqual(len(re.findall(r"^rule ", text, re.M)), len(re.findall(r'severity = "(low|medium|high|critical)"', text)))


class SnortConversion(unittest.TestCase):
    SOURCE = "\n".join([
        '# a comment',
        'alert tcp $MODBUS_CLIENT any -> $MODBUS_SERVER 502 (flow:from_client,established; content:"|08 00 04|"; offset:7; depth:3; msg:"Force Listen Only; really"; sid:1111001; rev:2;)',
        'alert tcp !$S7_CLIENT any -> $S7_SERVER 102 (msg:"S7 from elsewhere"; sid:5; rev:1;)',
        'alert tcp any any -> any $WEIRD_PORTS (msg:"port variable"; sid:6;)',
        'drop tcp any any -> any 502 (msg:"by function name"; modbus_func:write_single_coil; modbus_unit:3; sid:7;)',
        'alert tcp any any -> any 502 (msg:"needs the Snort preprocessor"; modbus_data; content:"|00|"; sid:8;)',
        'alert tcp any any -> any 80 (msg:"same number twice"; content:"/a"; sid:1; rev:1;)',
        'alert tcp any any -> any 80 (msg:"same number twice"; content:"/b"; \\',
        '    metadata:policy security-ips drop; sid:1; rev:1;)',
        'alert http ( msg:"Snort 3 style"; http_uri; content:"/x"; sid:9; )',
        'pass tcp any any -> any any (msg:"pass"; sid:10;)',
    ])

    def setUp(self):
        self.rules, self.set_aside, self.noted = snort2suricata.convert_text(self.SOURCE, "unit", 1990000, 300)

    def test_counts(self):
        self.assertEqual(len(self.rules), 6)
        self.assertEqual(sorted(reason.split(",")[0].split("(")[0].strip() for reason, _ in self.set_aside),
                         ["not a Snort 2 rule header", "pass rule", "uses 'modbus_data'"])

    def test_numbers_are_new_unique_and_the_original_is_kept(self):
        sids = [re.search(r"sid:(\d+);\)$", line).group(1) for line in self.rules]
        self.assertEqual(sids, [str(1990000 + index) for index in range(6)])
        self.assertIn("td_source unit, td_orig_sid 1111001", self.rules[0])
        self.assertIn("metadata:policy security-ips drop, td_source unit, td_orig_sid 1", self.rules[5])

    def test_variables(self):
        self.assertTrue(self.rules[0].startswith("alert tcp $MODBUS_CLIENT any -> $MODBUS_SERVER 502 ("))
        self.assertTrue(self.rules[1].startswith("alert tcp !$HOME_NET any -> $HOME_NET 102 ("))
        self.assertTrue(self.rules[2].startswith("alert tcp any any -> any any ("))

    def test_keywords_and_action(self):
        self.assertTrue(self.rules[3].startswith("alert tcp any any -> any 502 ("))
        self.assertIn("modbus: unit 3, function 5;", self.rules[3])
        self.assertNotIn("modbus_func", self.rules[3])

    def test_quoted_semicolon_and_rate_limit(self):
        self.assertIn('msg:"Force Listen Only; really";', self.rules[0])
        for line in self.rules:
            self.assertEqual(line.count("threshold:"), 1)
        self.assertTrue(all(line.endswith(";)") for line in self.rules))


class SuricataImport(unittest.TestCase):
    """Suricata rules from outside pass through the same tool: new numbers, a
    rate limit, optionally one alert per window, and a list of rules to leave out."""

    SOURCE = "\n".join([
        'alert tcp any any -> any ![22,80] (msg:"POSSBL PORT SCAN (NMAP -sS)"; flow:to_server,stateless; flags:S; window:1024; tcp.mss:1460; threshold:type threshold, track by_src, count 7, seconds 135; classtype:attempted-recon; sid:3400002; priority:2; rev:11;)',
        'alert ip any any -> any any (msg:"POSSBL SCAN FRAG (NMAP -f)"; fragbits:M+D; threshold:type limit, track by_src, count 3, seconds 1210; classtype:attempted-recon; sid:3400006; rev:6;)',
        'alert tcp any ![22,80] -> any 4444 (msg:"POSSBL SCAN SHELL M-SPLOIT TCP"; classtype:trojan-activity; sid:3400020; priority:1; rev:2;)',
        'alert udp any any -> any 4444 (msg:"every packet"; sid:3400021; rev:2;)',
    ])

    def test_once_per_window_skip_and_limit(self):
        rules, set_aside, _ = snort2suricata.convert_text(self.SOURCE, "nmap", 1912000, 300, True, ["3400020"])
        self.assertEqual(len(rules), 3)
        self.assertEqual([reason for reason, _ in set_aside], ["left out on purpose (skip_sids)"])
        self.assertIn("threshold:type both, track by_src, count 7, seconds 135;", rules[0])
        self.assertIn("tcp.mss:1460;", rules[0])
        self.assertTrue(rules[0].startswith("alert tcp any any -> any ![22,80] ("))
        self.assertIn("threshold:type limit, track by_src, count 3, seconds 1210;", rules[1], "a limit is left as it is")
        self.assertIn("threshold: type limit, track by_src, count 1, seconds 300;", rules[2], "no limit of its own: one is added")
        self.assertEqual([re.search(r"sid:(\d+);\)$", line).group(1) for line in rules], ["1912000", "1912001", "1912002"])

    def test_unchanged_without_the_options(self):
        rules, set_aside, _ = snort2suricata.convert_text(self.SOURCE, "nmap", 1912000)
        self.assertEqual((len(rules), len(set_aside)), (4, 0))
        self.assertIn("threshold:type threshold, track by_src, count 7, seconds 135;", rules[0])
        self.assertNotIn("threshold", rules[3])


class EngineOutputPruning(unittest.TestCase):
    LOG = ('Error: detect: error parsing signature "alert tcp any any -> any any (bad;)" from file /opt/suricata/rules/ext-a.rules at line 3\n'
           '[ERRCODE: SC_ERR_INVALID_SIGNATURE(39)] - error parsing signature "x" from file /opt/suricata/rules/ext-b.rules at line 1\n')

    def test_only_the_named_lines_of_the_named_file_are_commented_out(self):
        self.assertEqual(prune_rules.refused_lines(self.LOG, "ext-a.rules"), {3})
        self.assertEqual(prune_rules.refused_lines(self.LOG, "ext-b.rules"), {1})
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "ext-a.rules"
            path.write_text("# header\nalert tcp any any -> any any (msg:\"one\"; sid:1;)\nalert tcp any any -> any any (bad;)\nalert tcp any any -> any any (msg:\"two\"; sid:2;)\n")
            self.assertEqual(prune_rules.prune(path, {3}), 1)
            lines = path.read_text().splitlines()
            self.assertTrue(lines[2].startswith("#PRUNED alert"))
            self.assertEqual(sum(line.startswith("alert") for line in lines), 2)
            self.assertEqual(prune_rules.prune(path, {3, 1, 99}), 0, "comments and already-pruned lines are left alone")


class IndicatorConversion(unittest.TestCase):
    def test_shapes(self):
        cases = {"8.8.8.8": ("8.8.8.8", "Intel::ADDR"), "1.2.3[.]4": ("1.2.3.4", "Intel::ADDR"),
                 "45.33.32.156:8080": ("45.33.32.156", "Intel::ADDR"), "185.220.101.0/24": ("185.220.101.0/24", "Intel::SUBNET"),
                 "hxxp://Evil.example.com/a/b.exe": ("Evil.example.com/a/b.exe", "Intel::URL"),
                 "Bad-Domain.Example.org": ("bad-domain.example.org", "Intel::DOMAIN"),
                 "user@phish.example.net": ("user@phish.example.net", "Intel::EMAIL"),
                 "D41D8CD98F00B204E9800998ECF8427E": ("d41d8cd98f00b204e9800998ecf8427e", "Intel::FILE_HASH"),
                 "10.1.2.3": ("", "private"), "192.168.0.0/16": ("", "private"), "127.0.0.1": ("", "private")}
        for raw, expected in cases.items():
            self.assertEqual(ioc2intel.classify(raw), expected, raw)
        for raw in ("not an indicator!", "", "12345", "zz" * 16):
            self.assertIsNone(ioc2intel.classify(raw), raw)

    def test_file_format(self):
        lines, counts = ioc2intel.build(["8.8.8.8", "8.8.8.8", "10.0.0.1", "example.org", "???"], "unit", "", True)
        self.assertEqual(lines[0], "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.do_notice")
        self.assertEqual(lines[1:], ["8.8.8.8\tIntel::ADDR\tunit\t-\tT", "example.org\tIntel::DOMAIN\tunit\t-\tT"])
        self.assertEqual((counts["private"], counts["unrecognised"]), (1, 1))


class VulnerabilityIndex(unittest.TestCase):
    def test_scan_and_summary(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            (folder / "a.rules").write_text(
                'alert http any any -> any any (msg:"ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228)"; reference:cve,2021-44228; sid:1;)\n'
                'alert smb any any -> any any (msg:"ET EXPLOIT ETERNALBLUE"; metadata:affected_product Windows_XP, cve CVE_2017_0144; sid:2;)\n'
                'alert tcp any any -> any 102 (msg:"Siemens SIMATIC S7 DoS"; reference:cve,CVE-2019-10929; sid:3;)\n'
                '#alert tcp any any -> any any (msg:"disabled"; reference:cve,2000-0001; sid:4;)\n'
                'alert tcp any any -> any any (msg:"no cve"; sid:5;)\n')
            rows = list(cve_index.scan([folder]))
            self.assertEqual(sorted((cve, sid, platform) for cve, sid, _, _, platform in rows),
                             [("CVE-2017-0144", "2", "windows"), ("CVE-2019-10929", "3", "ot"), ("CVE-2021-44228", "1", "linux")])
            (folder / "kev.json").write_text(json.dumps({"vulnerabilities": [
                {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2", "dateAdded": "2021-12-10"},
                {"cveID": "CVE-2023-0001", "vendorProject": "Rockwell Automation", "product": "ControlLogix", "dateAdded": "2023-01-01"}]}))
            sys.argv = ["cve_index.py", "--rules", str(folder), "--kev", str(folder / "kev.json"),
                        "-o", str(folder / "out.csv"), "--summary", str(folder / "out.md")]
            self.assertEqual(cve_index.main(), 0)
            with (folder / "out.csv").open() as handle:
                table = list(csv.DictReader(handle))
            self.assertEqual({row["cve"]: row["known_exploited"] for row in table},
                             {"CVE-2017-0144": "no", "CVE-2019-10929": "no", "CVE-2021-44228": "yes"})
            summary = (folder / "out.md").read_text()
            self.assertIn("Distinct CVEs covered: 3", summary)
            self.assertIn("covered by at least one rule: 1", summary)
            self.assertIn("| CVE-2023-0001 | Rockwell Automation | ControlLogix |", summary)
            self.assertIn("does not block", summary)


class SourceList(unittest.TestCase):
    def test_sources_conf(self):
        config = configparser.ConfigParser(interpolation=None)
        config.read(KIT / "sources.conf")
        self.assertGreaterEqual(len(config.sections()), 6)
        bases, enabled = [], []
        for name in config.sections():
            section = config[name]
            self.assertRegex(name, r"^[a-z0-9-]+$")
            self.assertIn(section["kind"], ("snort-git", "snort-url", "suricata-git", "suricata-url", "intel-git", "ioc-url", "kev-url"), name)
            self.assertTrue(section["url"].startswith("https://"), name)
            self.assertTrue(section.get("licence"), f"{name}: state the licence")
            self.assertTrue(section.get("about"), name)
            if section["kind"] in ("snort-git", "snort-url", "suricata-git"):
                base = int(section["sid_base"])
                self.assertGreaterEqual(base, 1910000, f"{name}: 1900001-1900999 is the TechDetechtives range")
                bases.append(base)
            if section["kind"] in ("snort-git", "suricata-git"):
                self.assertRegex(section.get("commit", ""), r"^[0-9a-f]{40}$", f"{name}: pin rule repositories to a commit")
            if section.getboolean("enabled"):
                enabled.append(name)
        self.assertEqual(len(bases), len(set(bases)))
        self.assertTrue(all(abs(a - b) >= 1000 for a in bases for b in bases if a != b), "leave 1000 numbers per source")
        self.assertEqual(enabled, ["elitewolf", "quickdraw", "nmap-scans", "public-threat-feeds", "cisa-kev"],
                         "sources under the GPL or custom terms stay off unless the owner turns them on")


class PlatformContent(unittest.TestCase):
    def test_anomaly_detectors(self):
        files = sorted((KIT / "detections" / "anomaly_detectors").glob("*.json"))
        self.assertEqual(len(files), 3)
        for path in files:
            body = json.loads(path.read_text())
            self.assertEqual(body["name"], path.stem)
            self.assertEqual(body["indices"], ["MALCOLM_NETWORK_INDEX_PATTERN_REPLACER"])
            self.assertEqual(body["time_field"], "MALCOLM_NETWORK_INDEX_TIME_FIELD_REPLACER")
            self.assertIn({"term": {"event.category": {"value": "ot", "boost": 1}}}, body["filter_query"]["bool"]["filter"])
            self.assertTrue(1 <= len(body["category_field"]) <= 2)
            for feature in body["feature_attributes"]:
                self.assertEqual(list(feature["aggregation_query"]), [feature["feature_name"]])

    def test_monitors(self):
        files = sorted((KIT / "detections" / "monitors").glob("*.json"))
        self.assertEqual(len(files), 3)
        names = set()
        for path in files:
            body = json.loads(path.read_text())
            names.add(body["name"])
            self.assertTrue(body["name"].startswith("TechDetechtives "))
            self.assertIs(body["enabled"], False, "shipped switched off, like the product's own example")
            self.assertEqual(body["monitor_type"], "query_level_monitor")
            trigger = body["triggers"][0]["query_level_trigger"]
            self.assertEqual(trigger["actions"][0]["destination_id"], "malcolm-api-loopback-webhook")
            json.dumps(body["inputs"][0]["search"]["query"])
        self.assertEqual(len(names), 3)

    def test_correlation_monitor_looks_for_the_correlation_rules_by_name(self):
        body = json.loads((KIT / "detections" / "monitors" / "techdetechtives_ot_correlation_alert_monitor.json").read_text())
        prefix = [item["prefix"]["rule.name"] for item in body["inputs"][0]["search"]["query"]["query"]["bool"]["filter"] if "prefix" in item][0]
        alerts = [line for name, _, line in RULES if "correlation" in name and "noalert;" not in line]
        self.assertGreaterEqual(len(alerts), 8)
        for line in alerts:
            self.assertIn(f'msg:"{prefix}', line)


class HardeningFiles(unittest.TestCase):
    ROOTFS = KIT / "hardening" / "rootfs"

    def test_sysctl_file(self):
        keys = []
        for line in (self.ROOTFS / "etc/sysctl.d/98-ot-ids-hardening.conf").read_text().splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            match = re.match(r"^-?([a-z0-9_.]+) = (\d+)$", line)
            self.assertIsNotNone(match, line)
            keys.append(match.group(1))
        self.assertEqual(len(keys), len(set(keys)))
        # The product's containers need forwarding, and the base system sets these itself.
        for forbidden in ("net.ipv4.ip_forward", "kernel.dmesg_restrict", "vm.max_map_count", "net.ipv4.conf.all.rp_filter"):
            self.assertNotIn(forbidden, keys)

    def test_modprobe_file(self):
        modules = []
        for line in (self.ROOTFS / "etc/modprobe.d/ot-ids-hardening.conf").read_text().splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            match = re.match(r"^install ([a-z0-9_-]+) /bin/false$", line)
            self.assertIsNotNone(match, line)
            modules.append(match.group(1))
        for needed in ("usb-storage", "squashfs", "overlay", "vfat", "udf", "br_netfilter"):
            self.assertNotIn(needed, modules, f"{needed} is needed by the product or for updates by USB")

    def test_scripts_parse(self):
        scripts = [KIT / "build-iso.sh", *sorted((KIT / "tools").glob("*.sh")), *sorted((self.ROOTFS / "usr/local/bin").iterdir())]
        self.assertGreaterEqual(len(scripts), 5)
        for path in scripts:
            self.assertEqual(subprocess.run(["bash", "-n", str(path)], capture_output=True).returncode, 0, path.name)
            self.assertTrue(path.stat().st_mode & 0o111, f"{path.name} must be executable")


class AttackIcs(unittest.TestCase):
    """MITRE ATT&CK for ICS: the reference, the mapping tables, tagging and the coverage report."""

    @classmethod
    def setUpClass(cls):
        cls.reference = attack_ics.Reference()
        cls.mapping = attack_ics.Mapping(cls.reference)   # raises if a row names an unknown technique or tactic

    @staticmethod
    def run_tool(arguments):
        with contextlib.redirect_stderr(io.StringIO()):
            return attack_ics.main(arguments)

    def test_reference(self):
        ref = self.reference
        self.assertEqual([tactic["id"] for tactic in ref.tactics],
                         ["TA0108", "TA0104", "TA0110", "TA0111", "TA0103", "TA0102", "TA0109", "TA0100", "TA0101",
                          "TA0107", "TA0106", "TA0105"])
        self.assertGreaterEqual(len(ref.techniques), 90)
        for key, technique in ref.techniques.items():
            self.assertRegex(key, r"^T\d{4}(\.\d{3})?$")
            self.assertTrue(technique["tactics"], key)
            self.assertTrue(set(technique["tactics"]) <= set(ref.tactic_names), key)
            self.assertEqual(bool(technique["parent"]), "." in key, key)
            if technique["parent"]:
                self.assertEqual(technique["parent"], key.split(".")[0])
                self.assertIn(technique["parent"], ref.techniques)
            self.assertTrue(technique["summary"].endswith("."), key)
            self.assertTrue(set(technique["mitigations"]) <= set(ref.mitigations), key)
        for old, new in ref.superseded.items():
            self.assertNotIn(old, ref.techniques)
            self.assertIn(new, ref.techniques)
        for actor in ref.actors:
            self.assertTrue(set(actor["techniques"]) <= set(ref.techniques), actor["name"])
        # MITRE's licence asks for its copyright line and the licence in every copy.
        self.assertIn("The MITRE Corporation", ref.data["copyright"])
        self.assertIn("non-exclusive, royalty-free license", ref.data["licence"])
        self.assertRegex(ref.data["source_commit"], r"^[0-9a-f]{40}$")

    def test_reference_is_built_from_mitres_data_format(self):
        def obj(kind, ident, external=None, **more):
            body = {"type": kind, "id": f"{kind}--{ident}", **more}
            if external:
                body["external_references"] = [{"source_name": "mitre-attack", "external_id": external}]
            return body

        def rel(kind, source, target):
            return {"type": "relationship", "id": f"relationship--{source}{target}{kind}", "relationship_type": kind,
                    "source_ref": source, "target_ref": target}

        phase = [{"kill_chain_name": "mitre-ics-attack", "phase_name": "discovery"}]
        objects = [
            obj("x-mitre-collection", "c", name="ICS ATT&CK", x_mitre_version="9.9", modified="2026-01-01T00:00:00Z"),
            obj("x-mitre-tactic", "disc", "TA0102", name="Discovery", x_mitre_shortname="discovery"),
            obj("x-mitre-matrix", "m", tactic_refs=["x-mitre-tactic--disc"]),
            obj("attack-pattern", "a", "T0001", name="Find Things", kill_chain_phases=phase,
                description="Adversaries may find things (Citation: X). They use [a tool](https://example.org/t). More."),
            obj("attack-pattern", "b", "T0001.001", name="Find Faster", kill_chain_phases=phase,
                x_mitre_is_subtechnique=True, description="Adversaries may hurry."),
            obj("attack-pattern", "old", "T0000", name="Old Name", revoked=True, kill_chain_phases=phase),
            obj("attack-pattern", "gone", "T0002", name="Dropped", x_mitre_deprecated=True, kill_chain_phases=phase),
            obj("course-of-action", "m1", "M0001", name="Segment"),
            obj("x-mitre-data-component", "dc", "DC0001", name="Network Traffic Content"),
            obj("x-mitre-analytic", "an", "AN0001",
                x_mitre_log_source_references=[{"x_mitre_data_component_ref": "x-mitre-data-component--dc"}]),
            obj("x-mitre-detection-strategy", "ds", "DET0001", x_mitre_analytic_refs=["x-mitre-analytic--an"]),
            obj("malware", "mw", "S0001", name="Badware"),
            rel("subtechnique-of", "attack-pattern--b", "attack-pattern--a"),
            rel("revoked-by", "attack-pattern--old", "attack-pattern--a"),
            rel("mitigates", "course-of-action--m1", "attack-pattern--a"),
            rel("detects", "x-mitre-detection-strategy--ds", "attack-pattern--a"),
            rel("uses", "malware--mw", "attack-pattern--b"),
            rel("uses", "malware--mw", "attack-pattern--gone"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "stix.json"
            path.write_text(json.dumps({"objects": objects}))
            built = attack_ics.build_reference(path, "0" * 40)
        self.assertEqual(built["version"], "9.9")
        self.assertEqual(built["tactics"], [{"id": "TA0102", "name": "Discovery", "shortname": "discovery"}])
        self.assertEqual(sorted(built["techniques"]), ["T0001", "T0001.001"])
        first = built["techniques"]["T0001"]
        self.assertEqual(first["summary"], "Adversaries may find things.")
        self.assertEqual((first["tactics"], first["parent"], first["mitigations"], first["data_components"]),
                         (["TA0102"], None, ["M0001"], ["Network Traffic Content"]))
        self.assertEqual(built["techniques"]["T0001.001"]["parent"], "T0001")
        self.assertEqual(built["superseded"], {"T0000": "T0001"})
        self.assertEqual(built["actors"], [{"id": "S0001", "name": "Badware", "kind": "software", "techniques": ["T0001.001"]}])

    def test_every_rule_in_this_repository_is_in_the_mapping(self):
        sids = {re.search(r"sid:(\d+);", line).group(1) for _, _, line in RULES + SHARED}
        self.assertEqual(sids - set(self.mapping.by_sid), set(), "rules with no row in attack/rule-mapping.csv")
        self.assertEqual(set(self.mapping.by_sid) - sids, set(), "rows in attack/rule-mapping.csv for rules that do not exist")
        for sid, entries in self.mapping.by_sid.items():
            techniques = [entry["technique"] for entry in entries]
            self.assertEqual(len(techniques), len(set(techniques)), f"sid {sid} names a technique twice")
            if None in techniques:
                self.assertEqual(techniques, [None], f"sid {sid}: '-' cannot be mixed with techniques")

    def test_markers_have_no_technique_and_chains_have_two_tactics(self):
        for name, _, line in RULES:
            if "correlation" not in name:
                continue
            sid = re.search(r"sid:(\d+);", line).group(1)
            entries = [entry for entry in self.mapping.by_sid[sid] if entry["technique"]]
            if "noalert;" in line:
                self.assertEqual(entries, [], f"marker {sid} raises no alert, so it carries no technique")
            elif "Address identified controllers, then" in line:
                written = attack_ics.tagged_entries(entries)
                self.assertEqual(len({entry["tactic"] for entry in written}), 2, f"{sid}: the two steps are two tactics")
                self.assertIn("T0888", [entry["technique"] for entry in written], f"{sid}: the first step is identification")

    def test_tag_names_are_safe_in_rule_metadata(self):
        self.assertEqual(attack_ics.tag_name("Device Restart/Shutdown"), "Device_Restart_or_Shutdown")
        self.assertEqual(attack_ics.tag_name("Point & Tag Identification"), "Point_and_Tag_Identification")
        self.assertEqual(attack_ics.tag_name("Brute Force I/O"), "Brute_Force_IO")
        for technique in self.reference.techniques.values():
            self.assertRegex(attack_ics.tag_name(technique["name"]), r"^[A-Za-z0-9_]+$")
        for name in self.reference.tactic_names.values():
            self.assertRegex(attack_ics.tag_name(name), r"^[A-Za-z0-9_]+$")

    def test_tagging_keeps_the_rule_and_is_done_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / "suricata" / "rules"
            rules.mkdir(parents=True)
            for folder in (KIT / "detections" / "suricata", ROOT / "platform" / "detections" / "suricata"):
                for path in folder.glob("*.rules"):
                    shutil.copy(path, rules / path.name)
            before = {path.name: path.read_text() for path in rules.glob("*.rules")}
            counts = attack_ics.tag_folder(tmp, self.reference, self.mapping)
            after = {path.name: path.read_text() for path in rules.glob("*.rules")}
            again = attack_ics.tag_folder(tmp, self.reference, self.mapping)
            self.assertEqual(after, {path.name: path.read_text() for path in rules.glob("*.rules")}, "second run changed a file")
        self.assertGreaterEqual(counts["tagged"], 70)
        self.assertNotIn("unmapped", counts)
        self.assertEqual(again.get("already"), counts["tagged"])
        self.assertNotIn("tagged", again)
        added = re.compile(r", ((?:(?:mitre_(?:sub)?t(?:actic|echnique)_(?:id|name)|td_attack_fit) [A-Za-z0-9_.]+(?:, )?)+);")
        for name in before:
            old_lines, new_lines = before[name].split("\n"), after[name].split("\n")
            self.assertEqual(len(old_lines), len(new_lines))
            for old, new in zip(old_lines, new_lines):
                if old == new:
                    continue
                sid = re.search(r"sid:(\d+);", old).group(1)
                match = added.search(new)
                self.assertIsNotNone(match, new)
                self.assertEqual(new.replace(match.group(0), ";"), old, f"sid {sid}: only the technique may be added")
                self.assertNotIn("noalert;", new)
                pairs = [item.split(" ") for item in match.group(1).split(", ")]
                keys = [key for key, _ in pairs]
                for needed in attack_ics.TAG_KEYS[:4]:   # the four keys the product reads
                    self.assertIn(needed, keys, f"sid {sid}")
                rows = self.mapping.by_sid[sid]
                wanted = [entry for index, entry in enumerate(rows) if index == 0 or entry["fit"] == "direct"]
                self.assertEqual([value for key, value in pairs if key == "td_attack_fit"], [rows[0]["fit"]], f"sid {sid}")
                self.assertEqual({value for key, value in pairs if key == "mitre_tactic_id"}, {entry["tactic"] for entry in wanted})
                self.assertEqual({value for key, value in pairs if key == "mitre_technique_id"},
                                 {self.reference.parent(entry["technique"]) for entry in wanted})
                self.assertEqual({value for key, value in pairs if key == "mitre_subtechnique_id"},
                                 {entry["technique"] for entry in wanted if "." in entry["technique"]})

    def test_tagging_odd_lines(self):
        tag = lambda line: attack_ics.tag_line(line, self.reference, self.mapping)   # noqa: E731
        imported = ('alert tcp any any -> any 502 (msg:"SCADA_IDS: Modbus TCP - Force Listen Only Mode; (x)"; content:"|08 00 04|"; '
                    'metadata:td_source quickdraw, td_orig_sid 1111001; sid:1911035;)')
        line, outcome = tag(imported)
        self.assertEqual(outcome, "tagged")
        self.assertIn("td_orig_sid 1111001, mitre_tactic_id TA0107, mitre_tactic_name Inhibit_Response_Function, "
                      "mitre_technique_id T0814, mitre_technique_name Denial_of_Service, td_attack_fit direct; sid:1911035;)", line)
        self.assertIn('msg:"SCADA_IDS: Modbus TCP - Force Listen Only Mode; (x)";', line)
        # No metadata option yet: one is added before the closing bracket.
        line, outcome = tag('alert tcp any any -> any 102 (msg:"x"; sid:1900151; rev:1;)')
        self.assertEqual((outcome, line), ("tagged", 'alert tcp any any -> any 102 (msg:"x"; sid:1900151; rev:1; metadata:mitre_tactic_id TA0104, '
                         'mitre_tactic_name Execution, mitre_technique_id T0858, mitre_technique_name Change_Operating_Mode, td_attack_fit direct;)'))
        # A sub-technique goes in its own key, its parent in the key the product reads.
        line, _ = tag('alert modbus any any -> any any (msg:"x"; sid:1900111; metadata:created_at 2026_10_05;)')
        self.assertIn("mitre_technique_id T1692, mitre_technique_name Unauthorized_Message, "
                      "mitre_subtechnique_id T1692.001, mitre_subtechnique_name Command_Message, td_attack_fit direct;)", line)
        # A related first technique is written, and marked as such; a related second one is not written.
        line, _ = tag('alert tcp any any -> any 44818 (msg:"x"; sid:1900465;)')
        self.assertIn("mitre_tactic_id TA0104, mitre_tactic_id TA0102,", line)
        self.assertIn("mitre_technique_id T0858, mitre_technique_id T0888,", line)
        self.assertIn("td_attack_fit related;)", line)
        line, _ = tag('alert dnp3 any any -> any any (msg:"x"; sid:1900127;)')
        self.assertIn("mitre_technique_id T1691,", line)
        self.assertNotIn("T0838", line)
        self.assertNotIn("T0878", line)
        # Several metadata options: read together, the last one is added to, and once only.
        twice = 'alert tcp any any -> any 102 (msg:"x"; metadata:created_at 2026_10_05; sid:1900151; metadata:policy balanced;)'
        line, outcome = tag(twice)
        self.assertEqual(outcome, "tagged")
        self.assertTrue(line.endswith("metadata:policy balanced, mitre_tactic_id TA0104, mitre_tactic_name Execution, "
                                      "mitre_technique_id T0858, mitre_technique_name Change_Operating_Mode, td_attack_fit direct;)"))
        self.assertEqual(tag(line), (line, "already"))
        line, outcome = tag('alert tcp any any -> any any (msg:"POSSBL PORT SCAN (NMAP -sS)"; metadata:td_source nmap-scans, td_orig_sid 1; '
                            'sid:1912000; metadata:policy balanced;)')
        self.assertEqual(outcome, "tagged")
        self.assertIn("mitre_subtechnique_id T0846.001", line)
        # Indented rules are rules too.
        self.assertEqual(tag('  alert tcp any any -> any 102 (msg:"x"; sid:1900151;)')[1], "tagged")
        for untouched, outcome in (
            ("# alert tcp any any -> any any (msg:\"x\"; sid:1900151;)", "skipped"),
            ("#PRUNED alert tcp any any -> any any (msg:\"x\"; sid:1900151;)", "skipped"),
            ("", "skipped"),
            ('alert tcp any any -> any any (msg:"someone else\'s rule"; sid:2000001;)', "unmapped"),
            ('alert tcp any any -> any any (msg:"x"; metadata:mitre_technique_id T1190; sid:1900151;)', "already"),
            ('alert tcp any any -> any any (msg:"x"; sid:1900186;)', "none"),
            ('alert tcp any any -> any 102 (msg:"x"; flowbits:set,seen; flowbits:noalert; sid:1900151;)', "marker"),
            ('alert tcp any any -> any 102 (msg:"x"; noalert; sid:1900151;)', "marker"),
            ('alert tcp any any -> any any (msg:"New thing"; metadata:td_source quickdraw, td_orig_sid 9; sid:1911999;)', "unmapped"),
        ):
            self.assertEqual(tag(untouched), (untouched, outcome))

    def test_imported_rules_are_mapped_by_source_and_message(self):
        sources = configparser.ConfigParser()
        sources.read(KIT / "sources.conf")
        for entry in self.mapping.imports:
            self.assertIn(entry["source"], sources.sections())

        def in_order(source, msg):
            return [entry["technique"] for entry in self.mapping.for_rule({"sid": "1", "msg": msg, "source": source})[0]]

        def techniques(source, msg):
            entries, reviewed = self.mapping.for_rule({"sid": "1", "msg": msg, "source": source})
            return sorted(entry["technique"] for entry in entries), reviewed

        for source, msg, expected in (
            ("nmap-scans", "POSSBL PORT SCAN (NMAP -sS)", ["T0846.001"]),
            ("nmap-scans", "POSSBL SCAN FRAG (NMAP -f)", ["T0846.001"]),
            ("quickdraw", "SCADA_IDS: DNP3 - Cold Restart From Unauthorized Client", ["T0816", "T0848"]),
            ("quickdraw", "SCADA_IDS: DNP3 - Disable Unsolicited Responses", ["T0838", "T0878", "T1691.002"]),
            ("quickdraw", "SCADA_IDS: Modbus TCP - Unauthorized Write Request to a PLC", ["T0848", "T1692.001"]),
            ("quickdraw", "SCADA_IDS: Modbus TCP - Non-Modbus Communication on TCP Port 502", ["T0885"]),
            # Digital Bond names transfers from the PC's side, the opposite of ATT&CK's words.
            ("quickdraw", "Schneider Modicon Function Code 90 - Download Ladder Logic Started", ["T0845"]),
            ("quickdraw", "Schneider Modicon Function Code 90 - Upload Ladder Logic Started", ["T0843"]),
            ("quickdraw", "S7 Enumerate Redpoint NSE Request CPU Function Read SZL attempt", ["T0888"]),
            ("quickdraw", "BACnet Foreign Device Join Attempt", []),
            # "-" wins where a "-" row and a technique row could both match.
            ("quickdraw", "BACnet foreign Device Join Attempt From Non Authorized Host", []),
            ("quickdraw", "BACnet Read Property Attempt From Non Authorized Host", ["T0801"]),
            ("quickdraw", "S7 Enumerate Redpoint NSE Request CPU Function Read SZL attempt From Non Authorized Host", ["T0888"]),
            ("elitewolf", "ELITEWOLF Allen-Bradley/Rockwell Automation URL Path Activity-TCP REQUEST", ["T0888"]),
            ("elitewolf", "ELITEWOLF Allen-Bradley/Rockwell Automation URL Path Activity-CSS Path", []),
            ("elitewolf", "ELITEWOLF SEL-3530-RTAC URL path activity - homepage", []),
            ("elitewolf", "ELITEWOLF SEL FTP Activity - Default Password", ["T1694.001"]),
            ("elitewolf", "ELITEWOLF SEL FTP Activity - STOR SET_DNP1.TXT file", ["T0836"]),
            ("elitewolf", "ELITEWOLF SEL FTP Activity - RETR DNPMAP.TXT file", ["T0861"]),
            ("elitewolf", "ELITEWOLF SEL-3530-RTAC Possible AcSELerator Firmware Activity", []),
            ("elitewolf", "ELITEWOLF_SEL-3620 X509 certificate activity", []),
        ):
            self.assertEqual(techniques(source, msg), (expected, True), msg)
        self.assertEqual(techniques("quickdraw", "A rule added upstream later"), ([], False))
        # The first row is the one written to the alert when none is direct: the missing master list comes first.
        self.assertEqual(in_order("quickdraw", "SCADA_IDS: Modbus TCP - Unauthorized Read Request to a PLC"), ["T0848", "T0801"])
        self.assertEqual(self.mapping.for_rule({"sid": "1", "msg": "x Force Listen Only Mode", "source": "quickdraw"})[0][0]["fit"], "direct")
        # A source's patterns never reach another source's rules.
        self.assertEqual(techniques("elitewolf", "POSSBL PORT SCAN (NMAP -sS)"), ([], False))

    def test_other_detections_name_things_that_exist(self):
        yara_text = "".join(path.read_text() for folder in (KIT / "detections" / "yara", ROOT / "platform" / "detections" / "yara")
                            for path in folder.glob("*.yar"))
        yara_rules = set(re.findall(r"^rule (\w+)", yara_text, re.M))
        watch = (ROOT / "platform" / "zeek" / "techdetechtives" / "l2-watch.zeek").read_text()
        notices = set(re.findall(r"^\t\t(\w+),$", watch[watch.index("redef enum Notice::Type"):watch.index("};")], re.M))
        self.assertGreaterEqual(len(notices), 8)
        mapped = {"yara": set(), "zeek-l2": set()}
        for entry in self.mapping.others:
            self.assertIn(entry["kind"], attack_ics.KIND_NAMES)
            if entry["kind"] in mapped:
                mapped[entry["kind"]].add(entry["name"])
            if entry["kind"] == "zeek-l2":
                self.assertEqual(entry["needs"], "zeek/custom/techdetechtives/l2-watch.zeek")
                self.assertFalse(entry["tagged"])
        self.assertEqual(mapped["yara"], yara_rules, "every YARA rule has a row, and only YARA rules that exist")
        self.assertEqual(mapped["zeek-l2"], notices, "every layer 2 notice has a row, and only notices that exist")

    def test_coverage_page_in_docs_is_current(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self.run_tool(["coverage", "--out-dir", tmp, "--name", "ATTACK-ICS-COVERAGE"]), 0)
            for name in ("ATTACK-ICS-COVERAGE.md", "ATTACK-ICS-COVERAGE.csv", "attack-ics-layer.json"):
                self.assertEqual((Path(tmp) / name).read_text(), (KIT / "docs" / name).read_text(),
                                 f"docs/{name} is out of date: run tools/attack_ics.py coverage --out-dir docs --name ATTACK-ICS-COVERAGE")
            page = (Path(tmp) / "ATTACK-ICS-COVERAGE.md").read_text()
            layer = json.loads((Path(tmp) / "attack-ics-layer.json").read_text())
            with open(Path(tmp) / "ATTACK-ICS-COVERAGE.csv", newline="") as handle:
                table = list(csv.DictReader(handle))
        self.assertNotIn("## Rules nobody has mapped yet", page)
        self.assertNotIn("No note written yet", page, "a gap in network traffic has no row in attack/gap-notes.csv")
        self.assertIn(self.reference.data["copyright"], page)
        self.assertEqual(layer["domain"], "ics-attack")
        for item in layer["techniques"]:
            self.assertIn(item["techniqueID"], self.reference.techniques)
        self.assertEqual({row["coverage"] for row in table}, {"direct", "related", "none"})
        by_id = {row["technique_id"]: row for row in table}
        self.assertEqual(by_id["T0858"]["coverage"], "direct")
        self.assertIn("1900151", by_id["T0858"]["detections"])
        self.assertEqual((by_id["T1692"]["coverage"], by_id["T1692"]["detections"]), ("direct", ""), "counted through its sub-technique")
        self.assertEqual(by_id["T0879"]["seen_in_if_uncovered"], "effect")

    def test_a_build_counts_only_what_it_ships(self):
        with tempfile.TemporaryDirectory() as tmp:
            content, out = Path(tmp) / "content", Path(tmp) / "out"
            rules = content / "suricata" / "rules"
            rules.mkdir(parents=True)
            (rules / "a.rules").write_text(
                'alert tcp any any -> any 102 (msg:"x"; sid:1900151;)\n'
                '#PRUNED alert tcp any any -> any 102 (msg:"x"; sid:1900512;)\n'
                'alert tcp any any -> any any (msg:"POSSBL PORT SCAN (NMAP -sS)"; metadata:td_source nmap-scans, td_orig_sid 3400001; sid:1912000;)\n'
                'alert tcp any any -> any any (msg:"New upstream rule"; metadata:td_source nmap-scans, td_orig_sid 3400099; sid:1912009;)\n')
            found, unmapped, _ = attack_ics.gather(self.reference, self.mapping, [rules], content)
            self.assertEqual([item["label"] for item in found["T0858"] if item["kind"] == "suricata"], ["1900151"])
            self.assertFalse(any(item["kind"] == "suricata" for item in found.get("T0845", [])), "a pruned rule is not counted")
            self.assertEqual([item["label"] for item in found["T0846.001"]], ["nmap-scans 1912000"])
            self.assertEqual(unmapped, [("a.rules", "1912009", "New upstream rule")])
            self.assertNotIn("T0830", found, "the layer 2 watch is counted only when the build added it")
            (content / "zeek" / "custom" / "techdetechtives").mkdir(parents=True)
            (content / "zeek" / "custom" / "techdetechtives" / "l2-watch.zeek").write_text("")
            found, _, _ = attack_ics.gather(self.reference, self.mapping, [rules], content)
            self.assertIn("T0830", found)
            self.assertEqual(self.run_tool(["coverage", "--content", str(content), "--out-dir", str(out)]), 0)
            self.assertIn("## Rules nobody has mapped yet", (out / "attack-ics-coverage.md").read_text())

    def test_reference_page(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self.run_tool(["reference", "-o", str(Path(tmp) / "ref.md")]), 0)
            page = (Path(tmp) / "ref.md").read_text()
        self.assertIn(self.reference.data["copyright"], page)
        self.assertIn(self.reference.data["licence"], page)
        for key in self.reference.techniques:
            self.assertIn(f"### {key} ", page)
        self.assertIn("| T0855 | T1692.001 Unauthorized Message: Command Message |", page)

    def test_tactic_chain_monitor_counts_the_reference_tactics(self):
        body = json.loads((KIT / "detections" / "monitors" / "techdetechtives_attack_ics_tactic_chain_monitor.json").read_text())
        query = body["inputs"][0]["search"]["query"]
        wanted = [tactic["id"] for tactic in self.reference.tactics]
        self.assertIn({"terms": {"threat.tactic.id": wanted}}, query["query"]["bool"]["filter"])
        # ACID raises a tactic-only notice for every session setup; only events that name a technique count.
        self.assertIn({"exists": {"field": "threat.technique.id"}}, query["query"]["bool"]["filter"])
        aggs = query["aggregations"]["by_source"]["aggregations"]
        self.assertEqual(sorted(aggs[key]["filter"]["term"]["threat.tactic.id"] for key in aggs if "filter" in aggs[key]), sorted(wanted))
        self.assertEqual(sorted(aggs["tactics"]["bucket_script"]["buckets_path"]), sorted(key.lower() for key in wanted))
        self.assertEqual(aggs["three_or_more_tactics"]["bucket_selector"]["script"], "params.t >= 3")

    def test_content_collection_tags_rules_and_ships_the_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            done = subprocess.run([str(KIT / "tools" / "collect-content.sh"), tmp], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
            text = (Path(tmp) / "suricata" / "rules" / "techdetechtives-ot.rules").read_text()
            self.assertIn("mitre_technique_id T0858", text)
            self.assertTrue((Path(tmp) / "attack-ics" / "attack-ics-techniques.md").is_file())
        with tempfile.TemporaryDirectory() as tmp:
            done = subprocess.run([str(KIT / "tools" / "collect-content.sh"), tmp], capture_output=True, text=True,
                                  env={"PATH": "/usr/local/bin:/usr/bin:/bin", "ATTACK_ICS_TAGS": "false"})
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual((Path(tmp) / "suricata" / "rules" / "techdetechtives-ot.rules").read_text(),
                             (ROOT / "platform" / "detections" / "suricata" / "techdetechtives-ot.rules").read_text())


if __name__ == "__main__":
    unittest.main()
