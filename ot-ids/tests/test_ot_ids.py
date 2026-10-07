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
import fetch_sources      # noqa: E402
import ioc2intel          # noqa: E402
import protocol_events    # noqa: E402
import prune_rules        # noqa: E402
import snort2suricata     # noqa: E402
import yara_sources       # noqa: E402


def rule_lines(folder):
    return [(path.name, number, line)
            for path in sorted(folder.glob("*.rules"))
            for number, line in enumerate(path.read_text().splitlines(), 1)
            if line.strip() and not line.startswith("#")]


RULES = rule_lines(KIT / "detections" / "suricata")
SHARED = rule_lines(ROOT / "platform" / "detections" / "suricata")


def rule(sid):
    for _, _, line in RULES + SHARED:
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

    def test_modbus_subfunction_is_only_written_for_function_8(self):
        # Suricata compares "subfunction" for the Diagnostics function only (8.0,
        # rust/src/modbus/detect.rs). With any other function the rule loads and never matches.
        for name, number, line in RULES + SHARED:
            for function in re.findall(r"modbus: (?:unit \d+, )?function (\d+), subfunction \d+", line):
                self.assertEqual(function, "8", f"{name}:{number}: 'subfunction' never matches function {function}")

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

    def test_modbus_device_identification(self):
        # Function 43 (0x2B), interface type 14 (0x0E): Read Device Identification.
        identify = self.modbus(0x2B, b"\x0e\x01\x00")
        self.assertEqual((identify[2:4], identify[7], identify[8]), (b"\x00\x00", 0x2B, 0x0E))
        canopen = self.modbus(0x2B, b"\x0d\x00\x00\x00\x00")           # same function, CANopen interface
        refused = self.modbus(0xAB, b"\x01")                              # a device refusing function 43
        diagnostics = self.modbus(0x08, b"\x00\x04\x00\x00")
        read = self.modbus(0x03, b"\x2b\x0e\x00\x02")                   # the two bytes as a register address
        other_unit = self.modbus(0x2B, b"\x0e\x01\x00", unit=0x2B, transaction=0x2B0E)
        not_modbus = b"\x00\x01\x12\x34\x00\x05\x01\x2b\x0e\x01\x00"     # protocol identifier is not zero
        others = [canopen, refused, diagnostics, read, not_modbus]
        if SHARED:
            self.check({1900103: ([identify, other_unit], others)})
        self.check({1900406: ([identify, other_unit], others), 1900451: ([identify, other_unit], others)})
        for sid in ([1900103] if SHARED else []) + [1900406, 1900451]:
            self.assertRegex(rule(sid), r"^alert tcp any any -> any 502 \(", sid)
            self.assertIn("flow:established,to_server;", rule(sid), sid)

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
                         ["Snort 3 rule with no addresses in its header", "pass rule", "uses 'modbus_data'"])

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


class Snort3Conversion(unittest.TestCase):
    """Snort 3 rules that keep the classic header: the mechanical part is converted, the rest set aside with the reason."""

    SOURCE = "\n".join([
        'alert tcp any any -> any 20000 ( msg:"modifiers after commas"; flow:to_server,established; content:"|05 64|", depth 2; '
        'content:"a,b\\"c", distance 4, within 10, nocase, fast_pattern; service:dnp3; rem:"x"; sid:1; )',
        'alert tcp any any -> any 20000 ( msg:"dnp3 object"; dnp3_func:operate; dnp3_obj:group 12, var 1; sid:2; )',
        'alert tcp any any -> any 44818 ( msg:"cip"; cip_service:78; cip_class:6; cip_instance:1; cip_attribute:3; cip_status:0; sid:3; )',
        'alert tcp any any -> any 2404 ( msg:"iec104 single command"; flow:to_server; iec104_asdu_func:C_SC_NA_1; sid:4; )',
        'alert tcp any any -> any 2404 ( msg:"iec104 lower case"; iec104_asdu_func:c_rp_na_1; sid:5; )',
        'alert tcp any any -> any 102 ( msg:"s7commplus"; s7commplus_func:explore; sid:6; )',
        'alert tcp any any -> any 102 ( msg:"mms"; mms_func:5; sid:7; )',
        'alert tcp any any -> any 4840 ( msg:"opcua"; opcua_msg_type:MSG; sid:8; )',
        'alert tcp any any -> any 2404 ( msg:"apci"; iec104_apci_type:unnumbered_control_function; sid:9; )',
        'alert tcp any any -> any 44818 ( msg:"cip range"; cip_class:<10; sid:10; )',
        'alert tcp any any -> any 80 ( msg:"unknown modifier"; content:"x", width 16; sid:11; )',
        'alert udp any any -> any 2404 ( msg:"iec104 over udp"; iec104_asdu_func:C_SC_NA_1; sid:12; )',
        'alert tcp any any -> any 2404 ( msg:"iec104 unknown"; iec104_asdu_func:X_YZ_NA_1; sid:13; )',
        'alert tcp any any -> any 20000 ( msg:"dnp3 odd"; dnp3_obj:group 12; sid:14; )',
        'alert tcp any any -> any 20000 ( msg:"dnp3 as suricata writes it"; dnp3_obj:12,1; sid:15; )',
        'alert modbus ( msg:"service rule"; modbus_func:5; sid:16; )',
        # Snort 3 names a buffer before the content it applies to; Suricata reads the same word as applying to the content before it.
        'alert tcp any any -> any 80 ( msg:"sticky after comma content"; content:"GET", depth 3; http_uri; content:"/admin", nocase; sid:17; )',
        'alert tcp any any -> any 80 ( msg:"sticky first"; flow:to_server; http_uri; content:"/admin"; sid:18; )',
        'alert tcp any any -> any 80 ( msg:"sticky with service"; content:"/admin"; http_uri; service:http; sid:19; )',
        # The Snort 2 form, a modifier after its content, is left as it is.
        'alert tcp any any -> any 80 ( msg:"snort 2 modifier"; content:"/admin"; nocase; http_uri; content:"x"; http_header; sid:20; )',
    ])

    def setUp(self):
        self.rules, self.set_aside, self.noted = snort2suricata.convert_text(self.SOURCE, "unit3", 1995000)

    def by_message(self, text):
        return next(line for line in self.rules if f'msg:"{text}"' in line)

    def test_what_is_converted_and_what_is_set_aside(self):
        self.assertEqual(len(self.rules), 7)
        reasons = sorted(reason for reason, _ in self.set_aside)
        self.assertEqual(len(reasons), 13)
        self.assertEqual(sum("the Snort 3 way" in reason for reason in reasons), 3)
        self.assertIn('content:"/admin"; nocase; http_uri; content:"x"; http_header;', self.by_message("snort 2 modifier"))
        for wanted in ("S7CommPlus", "MMS (IEC 61850)", "OPC UA", "IEC 104 frame types", "is a range", "content modifier 'width 16'",
                       "not a tcp rule", "not 'group N, var M'", "no addresses in its header"):
            self.assertTrue(any(wanted in reason for reason in reasons), f"{wanted}: {reasons}")

    def test_content_modifiers(self):
        line = self.by_message("modifiers after commas")
        self.assertIn('content:"|05 64|"; depth:2; content:"a,b\\"c"; distance:4; within:10; nocase; fast_pattern;', line)
        self.assertNotIn("service", line.split("msg:")[1].split(";", 1)[1])
        self.assertNotIn("rem:", line)

    def test_decoder_keywords(self):
        self.assertIn("dnp3_func:operate; dnp3_obj:12,1;", self.by_message("dnp3 object"))
        self.assertIn("dnp3_obj:12,1;", self.by_message("dnp3 as suricata writes it"))
        self.assertIn("cip_service:78; enip.cip_class:6; enip.cip_instance:1; enip.cip_attribute:3; enip.cip_status:0;", self.by_message("cip"))

    def test_iec104_types_become_the_bytes_the_kits_own_rules_use(self):
        single = self.by_message("iec104 single command")
        self.assertIn('content:"|68|"; depth:1; byte_test:1,!&,1,2; content:"|2d|"; offset:6; depth:1;', single)
        self.assertIn('content:"|69|"; offset:6; depth:1;', self.by_message("iec104 lower case"))
        # the same bytes as the kit's own Reset Process rule, and a real command matches them
        own = next(line for _, _, line in SHARED if "sid:1900161;" in line) if SHARED else None
        if own:
            self.assertIn('content:"|68|"; depth:1; byte_test:1,!&,1,2; content:"|69|"; offset:6; depth:1;', own)
        command = SuricataBytePositions.iec104(0x2D)
        self.assertTrue(payload_matches(single, command))
        self.assertFalse(payload_matches(single, SuricataBytePositions.iec104(0x2E)))
        self.assertFalse(payload_matches(single, bytes.fromhex("680401002d00")))          # a supervisory frame is not a command
        self.assertEqual(len(snort2suricata.IEC104_TYPES), 67)
        self.assertEqual((snort2suricata.IEC104_TYPES["c_cs_na_1"], snort2suricata.IEC104_TYPES["f_sc_nb_1"]), (103, 127))


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
                {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2", "dateAdded": "2021-12-10",
                 "knownRansomwareCampaignUse": "Known"},
                {"cveID": "CVE-2023-0001", "vendorProject": "Rockwell Automation", "product": "ControlLogix", "dateAdded": "2023-01-01",
                 "knownRansomwareCampaignUse": "Unknown"},
                {"cveID": "CVE-2020-0002", "vendorProject": "Moxa", "product": "EDR", "dateAdded": "2022-03-03"}]}))
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
            self.assertIn("| CVE-2023-0001 | Rockwell Automation | ControlLogix | 2023-01-01 | Unknown |", summary)
            self.assertIn("| CVE-2020-0002 | Moxa | EDR | 2022-03-03 | not stated |", summary)
            self.assertIn("used by ransomware campaigns: 1, of which covered: 1", summary)
            log4j = next(row for row in table if row["cve"] == "CVE-2021-44228")
            self.assertEqual((log4j["kev_date_added"], log4j["kev_ransomware_use"]), ("2021-12-10", "Known"))
            self.assertEqual(next(row for row in table if row["cve"] == "CVE-2017-0144")["kev_ransomware_use"], "")
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
            self.assertIn(section["kind"], fetch_sources.KINDS, name)
            self.assertTrue(section["url"].startswith("https://"), name)
            self.assertTrue(section.get("licence"), f"{name}: state the licence")
            self.assertTrue(section.get("about"), name)
            if section["kind"] in ("snort-git", "snort-url", "suricata-git"):
                base = int(section["sid_base"])
                self.assertGreaterEqual(base, 1910000, f"{name}: 1900001-1900999 is the TechDetechtives range")
                bases.append(base)
            if section["kind"] in ("snort-git", "suricata-git", "yara-git"):
                self.assertRegex(section.get("commit", ""), r"^[0-9a-f]{40}$", f"{name}: pin rule repositories to a commit")
            if section["kind"] == "yara-git":
                self.assertTrue(name.startswith("yara-"), f"{name}: the name becomes the folder and the start of every file name")
                self.assertTrue(section.get("drop_known") is None or name == "yara-rules-legacy", name)
            if section.getboolean("enabled"):
                enabled.append(name)
        self.assertEqual(len(bases), len(set(bases)))
        self.assertTrue(all(abs(a - b) >= 1000 for a in bases for b in bases if a != b), "leave 1000 numbers per source")
        bundled = ["yara-signature-base", "yara-elastic", "yara-reversinglabs", "yara-sekoia", "yara-atr", "yara-bartblaze",
                   "yara-eset", "yara-volexity", "yara-cape"]
        self.assertEqual(enabled, ["elitewolf", "quickdraw", "nmap-scans", "public-threat-feeds"] + bundled + ["cisa-kev"],
                         "sources under the GPL or custom terms stay off unless the owner turns them on")
        owner_turned_on = {"yara-cape"}          # GPL-3.0; switched on at the owner's request in 0.14.0
        for name in config.sections():
            if config[name]["licence"].startswith(("GPL", "AGPL", "LGPL")) and name not in owner_turned_on:
                self.assertFalse(config[name].getboolean("enabled"), f"{name}: GPL content is the owner's choice")
        # The legacy collection is listed after the sets it is compared with, or drop_known has nothing to compare.
        order = config.sections()
        self.assertTrue(all(order.index(name) < order.index("yara-rules-legacy") for name in bundled))


class YaraSources(unittest.TestCase):
    """Rule files from outside repositories, named so the product's start-up compile accepts them."""

    FIRST = 'rule Alpha : tag {\n  strings:\n    $a = "rule Hidden {"\n  condition:\n    $a\n}\n'
    SECOND = '/*\nrule Commented { condition: true }\n*/\nprivate rule Helper { condition: true }\nrule Beta { condition: Helper }\n'

    def test_namespace_is_the_one_the_product_gives(self):
        # Checked on 2026-10-06 against Malcolm 26.09.0's strelka/backend/yara_rules_setup.sh, run over
        # 3,667 fetched files: every namespace agreed. These are the shapes that matter.
        for name, expected in (("techdetechtives_ot.yar", "ns__techdetechtives_ot"),
                               ("yara-sekoia__yara_rules_apt_x_strings.yar", "ns__yara_sekoia__yara_rules_apt_x_strings"),
                               ("apt_apt_x.y.yar", "ns__apt_x_y"), ("9 odd--name__x.yar", "ns__9_odd__name__x"),
                               ("folder/inside/a.b.yara", "ns__a_b")):
            self.assertEqual(yara_sources.namespace(name), expected, name)

    def test_file_names_are_unique_where_the_product_would_see_one_namespace(self):
        taken = set()
        first = yara_sources.flat_name("yara-x", "malware/apt_apt_one.yar", taken)
        second = yara_sources.flat_name("yara-x", "malware/apt_one.yar", taken)        # the product drops the repeated 'apt'
        third = yara_sources.flat_name("yara-x", "malware/apt.one.yar", taken)
        self.assertEqual(len({first, second, third}), 3)
        self.assertEqual(len({yara_sources.namespace(name) for name in (first, second, third)}), 3)
        for name in (first, second, third):
            self.assertRegex(name, r"^yara-x__[A-Za-z0-9_-]+\.yar$")

    def test_what_is_taken(self):
        self.assertTrue(yara_sources.wanted("malware/a.yar", ["malware", "cve_rules"], []))
        self.assertTrue(yara_sources.wanted("deep/er/B.YARA", [], []))
        self.assertFalse(yara_sources.wanted("malware_extra/a.yar", ["malware"], []))
        self.assertFalse(yara_sources.wanted("malware/a.yar", ["malware"], ["malware/a.yar"]))
        self.assertFalse(yara_sources.wanted("malware/a.yar", [], ["mal*"]))
        self.assertFalse(yara_sources.wanted("malware/readme.md", ["malware"], []))
        self.assertTrue(yara_sources.is_licence_file("LICENSE.txt") and yara_sources.is_licence_file("COPYING"))
        self.assertFalse(yara_sources.is_licence_file("docs/LICENSE") or yara_sources.is_licence_file("license_check.yar"))

    def test_rules_are_named_and_cut_whole(self):
        self.assertEqual(yara_sources.rule_names(self.FIRST + self.SECOND), ["Alpha", "Helper", "Beta"])
        text, cut = yara_sources.cut_rules(self.FIRST + self.SECOND, {"Alpha", "Commented", "Hidden"})
        self.assertEqual(cut, ["Alpha"])
        self.assertEqual(text, "private rule Helper { condition: true }\nrule Beta { condition: Helper }\n")
        # A rule inside a comment is not cut: cutting it would take the end of the comment with it.
        text, cut = yara_sources.cut_rules(self.SECOND, {"Commented"})
        self.assertEqual((text, cut), (self.SECOND, []))
        tricky = ('rule One {\n  strings:\n    $a = /rule Two \\{ "x/ nocase\n    $b = "http://x" // rule Three {\n    $c = { 41 42 }\n'
                  '  condition:\n    $a or $b or $c\n}\nrule Four { condition: One }\n')
        self.assertEqual(yara_sources.rule_names(tricky), ["One", "Four"])
        self.assertEqual(len(yara_sources.code_only(tricky)), len(tricky))
        self.assertIn("{ 41 42 }", yara_sources.code_only(tricky))
        text, cut = yara_sources.cut_rules(self.FIRST + self.SECOND, {"Beta", "Nothing"})
        self.assertEqual((cut, yara_sources.rule_names(text)), (["Beta"], ["Alpha", "Helper"]))

    def gather(self, files, **options):
        with tempfile.TemporaryDirectory() as folder:
            repo, out = Path(folder) / "repo", Path(folder) / "out"
            for name, text in files.items():
                (repo / name).parent.mkdir(parents=True, exist_ok=True)
                (repo / name).write_text(text)
            done = yara_sources.gather(repo, list(files), out, "yara-x", **options)
            return done, {path.name: path.read_text() for path in out.iterdir()}

    def test_gathering(self):
        files = {"LICENSE": "terms", "docs/LICENSE": "other", "index.yar": 'include "./malware/a.yar"\n',
                 "malware/a.yar": self.FIRST, "malware/b.yar": self.SECOND, "malware/empty.yar": "/* moved */\n",
                 "malware/nc.yar": '/* License: CC BY-NC-SA 4.0 */\nrule Gamma { condition: true }\n', "notes.txt": "x"}
        known = {"Beta": "yara-earlier"}
        done, written = self.gather(files, known=known)
        self.assertEqual(sorted(written), ["LICENSE", "yara-x__malware_a.yar", "yara-x__malware_b.yar"])
        self.assertEqual((done["files"], done["rules"]), (2, 3))
        self.assertEqual((done["index_files"], done["noncommercial"], done["emptied"]), (["index.yar"], ["malware/nc.yar"], ["malware/empty.yar"]))
        self.assertEqual(known, {"Beta": "yara-earlier", "Alpha": "yara-x"}, "a private helper is not a rule anyone else supplies")
        done, written = self.gather(files, skip_noncommercial=False)
        self.assertIn("yara-x__malware_nc.yar", written)

    def test_cutting_named_and_known_rules(self):
        files = {"a.yar": self.FIRST + "rule Noisy { condition: true }\n", "b.yar": self.SECOND, "c.yar": "rule Noisy2 { condition: true }\n"}
        done, written = self.gather(files, drop_rules=["Noisy", "Noisy2"])
        self.assertEqual(sorted(written), ["yara-x__a.yar", "yara-x__b.yar"])
        self.assertNotIn("Noisy", written["yara-x__a.yar"])
        self.assertEqual((done["cut"], done["emptied"]), (["a.yar: Noisy", "c.yar: Noisy2"], ["c.yar"]))
        # A rule an earlier source supplies is cut only when asked. A private helper is never cut that way:
        # Beta leans on Helper, and a helper matches nothing by itself.
        done, written = self.gather(files, known={"Alpha": "s", "Helper": "s"})
        self.assertEqual(done["cut_known"], 0)
        done, written = self.gather(files, known={"Alpha": "s", "Helper": "s"}, drop_known=True)
        self.assertEqual((done["cut_known"], done["dependent"]), (1, []))
        self.assertEqual(sorted(written), ["yara-x__a.yar", "yara-x__b.yar", "yara-x__c.yar"])
        self.assertEqual(yara_sources.rule_names(written["yara-x__a.yar"]), ["Noisy"])
        self.assertEqual(written["yara-x__b.yar"], self.SECOND)
        # When every rule that matches is cut, the helpers left behind are not worth a file.
        done, written = self.gather(files, known={"Beta": "s"}, drop_known=True)
        self.assertIn("b.yar", done["emptied"])

    def test_a_file_is_not_left_half_working(self):
        files = {
            # UsesBase calls Base in its condition: cutting Base would break it, so the file is left out whole.
            "d.yar": "rule Base { condition: true }\nrule UsesBase { condition: Base and filesize > 1 }\n",
            # Here 'Base' is only a tag, and '$Base' a string: cutting the rule Base harms nothing.
            "e.yar": 'rule Base { condition: true }\nrule Tagged : Base other {\n  strings:\n    $Base = "x"\n  condition:\n    $Base\n}\n',
            # An import between two rules stays when the rule above it goes.
            "f.yar": 'rule Base { condition: true }\nimport "pe"\nrule NeedsPe { condition: pe.number_of_sections > 0 }\n',
            "g.yar": "rule Base { condition: true }\r\nimport \"math\"\r\nrule Crlf { condition: math.entropy(0, 10) > 1 }\r\n",
        }
        done, written = self.gather(files, known={"Base": "s"}, drop_known=True)
        self.assertEqual(done["dependent"], ["d.yar"])
        self.assertEqual(sorted(written), ["yara-x__e.yar", "yara-x__f.yar", "yara-x__g.yar"])
        self.assertEqual(yara_sources.rule_names(written["yara-x__e.yar"]), ["Tagged"])
        self.assertEqual(written["yara-x__f.yar"], 'import "pe"\nrule NeedsPe { condition: pe.number_of_sections > 0 }\n')
        self.assertTrue(written["yara-x__g.yar"].startswith('import "math"\n'))
        self.assertEqual(done["cut_known"], 3)
        if shutil.which("yarac"):
            with tempfile.TemporaryDirectory() as folder:
                for name, text in written.items():
                    (Path(folder) / name).write_text(text)
                self.assertEqual(yara_sources.check(folder)["refused"], [])

    @unittest.skipUnless(shutil.which("git"), "git is not installed")
    def test_fetching_a_repository(self):
        with tempfile.TemporaryDirectory() as folder:
            repo, out = Path(folder) / "repo", Path(folder) / "out"
            (repo / "rules" / "sub").mkdir(parents=True)
            (repo / "rules" / "a.yar").write_text(self.FIRST)
            (repo / "rules" / "sub" / "b.yara").write_text(self.SECOND)
            (repo / "other.yar").write_text("rule Elsewhere { condition: true }\n")
            (repo / "LICENSE").write_text("terms\n")
            (repo / "big.bin").write_bytes(b"\x00" * 4096)
            git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "init.defaultBranch=main", "-C", str(repo)]
            for command in (["init", "-q"], ["add", "."], ["commit", "-q", "-m", "rules"]):
                subprocess.run(git + command, check=True, capture_output=True, timeout=60)
            commit = subprocess.run(git + ["rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
            config = configparser.ConfigParser(interpolation=None)
            config.read_string(f"[yara-x]\nkind = yara-git\nurl = {repo}\ncommit = {commit}\ninclude = rules\nlicence = MIT\n"
                               f"[yara-y]\nkind = yara-git\nurl = {repo}\ndrop_known = yes\nlicence = MIT\n"
                               f"[yara-z]\nkind = yara-git\nurl = {repo}\ninclude = nothing-here\nlicence = MIT\n")
            shared = {}
            result = fetch_sources.fetch_one("yara-x", config["yara-x"], out, shared)
            self.assertEqual(result, f"3 rules in 2 files; commit {commit[:12]}")
            self.assertEqual(sorted(path.name for path in (out / "yara" / "yara-x").iterdir()),
                             ["LICENSE", "yara-x__rules_a.yar", "yara-x__rules_sub_b.yar"])
            self.assertIn("yara-x: 3 rules in 2 files", (out / "reports" / "yara-x.txt").read_text())
            # The second source has the same rules and one more; only the one more is kept.
            result = fetch_sources.fetch_one("yara-y", config["yara-y"], out, shared)
            self.assertTrue(result.startswith("1 rules in 1 files, 2 files left out, 2 rules cut"), result)
            self.assertEqual([path.name for path in (out / "yara" / "yara-y").glob("*.yar")], ["yara-y__other.yar"])
            with self.assertRaises(fetch_sources.SourceError):
                fetch_sources.fetch_one("yara-z", config["yara-z"], out, shared)
            self.assertFalse((out / "yara" / "yara-z").exists())
            (out / "yara-sources.txt").write_text("yara-x ok\nyara-y ok\n")
            # The collector puts each source in its own folder beside the kit's own rules.
            content = Path(folder) / "content"
            done = subprocess.run(["bash", str(KIT / "tools" / "collect-content.sh"), str(content), str(out)],
                                  capture_output=True, text=True, timeout=120)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertTrue((content / "yara" / "rules" / "yara-x" / "yara-x__rules_a.yar").is_file())
            self.assertTrue((content / "yara" / "rules" / "yara-x" / "LICENSE").is_file())
            self.assertTrue((content / "yara" / "rules" / "techdetechtives_ot.yar").is_file())

    def test_the_kits_own_rules_do_not_go_in_alone(self):
        # Alone in the product's folder they would replace the thousands of rules the product is built with.
        collector = ["bash", str(KIT / "tools" / "collect-content.sh")]
        with tempfile.TemporaryDirectory() as folder:
            mine = Path(folder) / "yara" / "rules" / "site.yar"
            mine.parent.mkdir(parents=True)
            mine.write_text("rule Site { condition: false }\n")                  # a file the owner put in the overlay
            done = subprocess.run(collector + [folder], capture_output=True, text=True, timeout=120)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(sorted(path.name for path in mine.parent.iterdir()), ["site.yar"])
            self.assertIn("no YARA rules are added (no YARA source was fetched)", done.stderr)
            self.assertIn("1 YARA rule file(s) of your own", done.stderr)
            self.assertTrue((Path(folder) / "suricata" / "rules" / "techdetechtives-ot.rules").is_file())
        with tempfile.TemporaryDirectory() as folder:
            done = subprocess.run(collector + [folder], capture_output=True, text=True, timeout=120,
                                  env={"PATH": "/usr/local/bin:/usr/bin:/bin", "YARA_ALONE": "true"})
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertTrue((Path(folder) / "yara" / "rules" / "techdetechtives_ot.yar").is_file())
            self.assertIn("YARA_ALONE is set", done.stderr)

    def test_yara_rule_sets_go_in_together_or_not_at_all(self):
        collector = ["bash", str(KIT / "tools" / "collect-content.sh")]
        with tempfile.TemporaryDirectory() as folder:
            fetched, content = Path(folder) / "fetched", Path(folder) / "content"
            for name in ("yara-a", "yara-b"):
                (fetched / "yara" / name).mkdir(parents=True)
                (fetched / "yara" / name / f"{name}__one.yar").write_text("rule One { condition: false }\n")
            stale = content / "yara" / "rules" / "yara-old"
            stale.mkdir(parents=True)
            (stale / "yara-old__x.yar").write_text("rule Old { condition: false }\n")       # from a source switched off since

            def collect(status):
                (fetched / "yara-sources.txt").write_text(status)
                done = subprocess.run(collector + [str(content), str(fetched)], capture_output=True, text=True, timeout=120)
                self.assertEqual(done.returncode, 0, done.stderr)
                return done.stderr, sorted(str(path.relative_to(content / "yara" / "rules")) for path in (content / "yara" / "rules").rglob("*.yar"))

            # One of two sources could not be fetched: nothing goes in, and the message names it.
            message, files = collect("yara-a ok\nyara-b FAILED\n")
            self.assertEqual(files, [])
            self.assertIn("not fetched: yara-b", message)
            # Both fetched: the sets and the kit's own rules go in; the stale folder stays gone.
            message, files = collect("yara-a ok\nyara-b ok\n")
            self.assertIn("yara-a/yara-a__one.yar", files)
            self.assertIn("yara-b/yara-b__one.yar", files)
            self.assertIn("techdetechtives_ot.yar", files)
            self.assertFalse(any(name.startswith("yara-old") for name in files))
            self.assertNotIn("NOTE", message)
            # A later run in which a source fails takes them out again.
            message, files = collect("yara-a FAILED\nyara-b ok\n")
            self.assertEqual(files, [])

    def test_a_link_in_a_repository_is_not_followed(self):
        if not shutil.which("git"):
            self.skipTest("git is not installed")
        with tempfile.TemporaryDirectory() as folder:
            repo, out, secret = Path(folder) / "repo", Path(folder) / "out", Path(folder) / "secret.txt"
            secret.write_text("a file of the build machine\n")
            repo.mkdir()
            (repo / "real.yar").write_text(self.FIRST)
            (repo / "LICENSE").symlink_to(secret)
            (repo / "linked.yar").symlink_to(secret)
            git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "init.defaultBranch=main", "-C", str(repo)]
            for command in (["init", "-q"], ["add", "."], ["commit", "-q", "-m", "rules"]):
                subprocess.run(git + command, check=True, capture_output=True, timeout=60)
            config = configparser.ConfigParser(interpolation=None)
            config.read_string(f"[yara-l]\nkind = yara-git\nurl = {repo}\nlicence = MIT\n")
            fetch_sources.fetch_one("yara-l", config["yara-l"], out, {})
            self.assertEqual(sorted(path.name for path in (out / "yara" / "yara-l").iterdir()), ["yara-l__real.yar"])

    @unittest.skipUnless(shutil.which("yarac"), "the yarac program is not installed")
    def test_check_compiles_as_the_product_does(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "s").mkdir()
            (root / "s" / "good.yar").write_text(self.FIRST)
            (root / "s" / "also.yar").write_text(self.FIRST)             # the same rule name in another file is fine: another namespace
            (root / "s" / "broken.yar").write_text("rule Broken { condition: no_such_thing }\n")
            (root / "_skipped.yar").write_text("this is not YARA")
            result = yara_sources.check(root)
            self.assertEqual((result["files"], result["passed"], result["together"]), (3, 2, "ok"))
            self.assertEqual([name for name, _ in result["refused"]], ["s/broken.yar"])


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
        self.assertEqual(len(files), 4)
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
        self.assertEqual(len(names), 4)

    def test_dnp3_monitor_names_the_flags_as_the_product_writes_them(self):
        # The product turns the outstation's 16 indication bits into these words
        # (Malcolm 26.09.0, logstash/pipelines/zeek/1200_zeek_mutate.conf, zeek.dnp3.iin_flags).
        written = ['Function Code not Implemented', 'Requested Objects Unknown', 'Parameters Invalid or Out of Range', 'Event Buffer Overflow',
                   'Operation Already Executing', 'Configuration Corrupt', 'Reserved', 'Reserved', 'Broadcast Msg Rx', 'Class 1 Data Available',
                   'Class 2 Data Available', 'Class 3 Data Available', 'Time Sync Required', 'Digital Outputs in Local', 'Device Trouble',
                   'Device Restart']
        body = json.loads((KIT / "detections" / "monitors" / "techdetechtives_dnp3_outstation_trouble_monitor.json").read_text())
        query = body["inputs"][0]["search"]["query"]
        filters = query["query"]["bool"]["filter"]
        self.assertIn({"term": {"event.dataset": "dnp3"}}, filters)
        flags = [item["terms"]["zeek.dnp3.iin_flags"] for item in filters if "terms" in item][0]
        self.assertEqual(sorted(flags), ["Configuration Corrupt", "Device Trouble", "Digital Outputs in Local", "Event Buffer Overflow"])
        self.assertTrue(set(flags) <= set(written))
        self.assertNotIn("Device Restart", flags, "rule 1900132 already reports a restart")
        self.assertEqual(query["aggregations"]["outstation"]["terms"]["field"], "destination.ip")
        self.assertEqual(body["triggers"][0]["query_level_trigger"]["condition"]["script"]["source"], "ctx.results[0].hits.total.value > 0")

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

    def test_each_host_command_finds_its_program(self):
        """A host command runs a program the build puts in a container image or on the host: the two paths must agree."""
        build = (KIT / "build-iso.sh").read_text()
        for name in ("baseline", "profile", "replay"):
            wrapper = (self.ROOTFS / f"usr/local/bin/td-{name}").read_text()
            self.assertIn(f"dashboards-helper python3 /opt/techdetechtives/td_{name}.py", wrapper)
            self.assertIn(f"COPY --chmod=644 baseline/td_{name}.py /opt/techdetechtives/td_{name}.py", build)
            self.assertTrue((KIT / f"baseline/td_{name}.py").is_file())
        replay = (KIT / "baseline/td_replay.py").read_text()
        self.assertIn("import td_baseline as base", replay)
        self.assertIn("import td_profile as profile", replay)
        self.assertIn('-f "$KIT_DIR/baseline/td_replay.py" && -f "$KIT_DIR/baseline/td_profile.py"', build,
                      "the replay report is only copied together with the profile it imports")
        wrapper = (self.ROOTFS / "usr/local/bin/td-pcap-order").read_text()
        self.assertIn("python3 /usr/local/lib/techdetechtives/td_pcap_order.py", wrapper)
        self.assertTrue((self.ROOTFS / "usr/local/lib/techdetechtives/td_pcap_order.py").is_file())
        self.assertIn('cp -a "$KIT_DIR/hardening/rootfs/." "$root/"', build)

    def test_scripts_parse(self):
        scripts = [KIT / "build-iso.sh", *sorted((KIT / "tools").glob("*.sh")), *sorted((self.ROOTFS / "usr/local/bin").iterdir())]
        self.assertGreaterEqual(len(scripts), 5)
        for path in scripts:
            self.assertEqual(subprocess.run(["bash", "-n", str(path)], capture_output=True).returncode, 0, path.name)
            self.assertTrue(path.stat().st_mode & 0o111, f"{path.name} must be executable")


class BuildSettings(unittest.TestCase):
    """The build script's own helper, run by bash on a copy of the product's file layout."""

    def set_value(self, folder, name, value, text):
        target = Path(folder) / "suricata.env.example"
        target.write_text(text)
        script = (KIT / "build-iso.sh").read_text()
        function = re.search(r"^set_env_value\(\) \{\n.*?^\}\n", script, re.M | re.S)
        self.assertIsNotNone(function, "set_env_value is not in build-iso.sh")
        done = subprocess.run(["bash", "-c", function.group(0) + 'set_env_value "$1" "$2" "$3"', "bash", str(target), name, value],
                              capture_output=True, text=True, timeout=30)
        return done.returncode, target.read_text()

    def test_a_setting_is_added_once_and_replaced_after_that(self):
        with tempfile.TemporaryDirectory() as folder:
            status, text = self.set_value(folder, "SURICATA_STREAM_REASSEMBLY_DEPTH", "0", "SURICATA_DISABLE_SIDS=\n# a comment with no line end")
            self.assertEqual(status, 0)
            self.assertEqual(text, "SURICATA_DISABLE_SIDS=\n# a comment with no line end\nSURICATA_STREAM_REASSEMBLY_DEPTH=0\n")
            status, text = self.set_value(folder, "SURICATA_STREAM_REASSEMBLY_DEPTH", "16mb", text)
            self.assertEqual(text.count("SURICATA_STREAM_REASSEMBLY_DEPTH="), 1)
            self.assertTrue(text.endswith("SURICATA_STREAM_REASSEMBLY_DEPTH=16mb\n"))
            status, text = self.set_value(folder, "SURICATA_DISABLE_SIDS", "2250002", text)
            self.assertIn("SURICATA_DISABLE_SIDS=2250002\n", text)
            self.assertIn("SURICATA_STREAM_REASSEMBLY_DEPTH=16mb\n", text)
        missing = subprocess.run(["bash", "-c", re.search(r"^set_env_value\(\) \{\n.*?^\}\n", (KIT / "build-iso.sh").read_text(), re.M | re.S).group(0)
                                  + 'set_env_value /nonexistent/file A 1'], capture_output=True, timeout=30)
        self.assertNotEqual(missing.returncode, 0)

    def test_the_stream_depth_is_set_where_the_installed_system_reads_it(self):
        script = (KIT / "build-iso.sh").read_text()
        self.assertIn('set_env_value "$SRC_DIR/config/suricata.env.example" SURICATA_STREAM_REASSEMBLY_DEPTH "$SURICATA_STREAM_DEPTH"', script)
        self.assertIn('SURICATA_STREAM_DEPTH="0"', (KIT / "build.conf").read_text())


class SuricataExtras(unittest.TestCase):
    """The suppression file, and the tool that switches on Suricata's own protocol event rules."""

    FOLDER = KIT / "overlay" / "malcolm" / "suricata" / "include-configs"
    SUPPRESS = re.compile(r"^suppress gen_id 1, sig_id \d+(, track by_(src|dst|either), ip [0-9./]+)?$")
    THRESHOLD = re.compile(r"^threshold gen_id 1, sig_id \d+, type (limit|both|threshold), track by_(src|dst|rule|both), count \d+, seconds \d+$")

    def test_suppression_file_changes_nothing_until_it_is_edited(self):
        include = (self.FOLDER / "td-threshold.yaml").read_text()
        self.assertTrue(include.startswith("%YAML 1.1\n---\n"), "Suricata refuses an included file without this header")
        settings = [line for line in include.splitlines()[2:] if line.strip() and not line.startswith("#")]
        # /opt/suricata/include-configs is where the product mounts ./suricata/include-configs (its docker-compose.yml).
        self.assertEqual(settings, ["threshold-file: /opt/suricata/include-configs/td-threshold.config"])
        lines = (self.FOLDER / "td-threshold.config").read_text().splitlines()
        self.assertEqual([line for line in lines if line.strip() and not line.startswith("#")], [], "examples only: nothing is suppressed as shipped")
        examples = [line[1:] for line in lines if line.startswith(("#suppress", "#threshold"))]
        self.assertGreaterEqual(len(examples), 4)
        for example in examples:
            self.assertTrue(self.SUPPRESS.match(example) or self.THRESHOLD.match(example), example)

    BUNDLED = [
        'alert http any any -> any any (msg:"ET something"; sid:2034647; rev:3;)',
        '# alert modbus any any -> any any (msg:"SURICATA Modbus invalid Length"; app-layer-event:modbus.invalid_length; classtype:protocol-command-decode; sid:2250003; rev:2;)',
        '#alert modbus any any -> any any (msg:"SURICATA Modbus invalid Value"; app-layer-event:modbus.invalid_value; sid:2250006; rev:2;)',
        'alert dnp3 any any -> any any (msg:"SURICATA DNP3 Request flood detected"; app-layer-event:dnp3.flooded; sid:2270000; rev:2;)',
        '# alert dnp3 any any -> any any (msg:"ET SCADA something the publisher switched off"; sid:2099003; rev:1;)',
        '# alert tcp any any -> any any (msg:"ET disabled"; sid:2099002; rev:1;)',
        '# a comment that mentions sid:2250001; and is not a rule',
    ]

    def test_status_of_the_protocol_event_rules(self):
        lines, found = protocol_events.status_lines(self.BUNDLED)
        self.assertEqual(found, {2250003: "commented", 2250006: "commented", 2270000: "active"})
        self.assertEqual(lines[0], "modbus: 0 of 8 event rules active, 2 commented out, 6 not in the file; "
                                   "all 'modbus' rules in the file: 0 active, 2 commented out")
        self.assertTrue(lines[1].startswith("dnp3: 1 of 8 event rules active, 0 commented out, 7 not in the file; all 'dnp3' rules in the file: 1 active, 1 commented out"))
        self.assertEqual(len(protocol_events.WANTED), 18)

    def test_only_the_event_rules_are_switched_on(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "dist"
            source.mkdir()
            (source / "enip-events.rules").write_text(
                '# ENIP app layer event rules\n'
                'alert enip any any -> any any (msg:"SURICATA ENIP too many transactions"; app-layer-event:enip.too_many_transactions; sid:2234000; rev:1;)\n'
                '#alert enip any any -> any any (msg:"SURICATA ENIP invalid PDU"; app-layer-event:enip.invalid_pdu; sid:2234001; rev:1;)\n')
            (source / "dnp3-events.rules").write_text(            # Suricata writes these over several lines
                '# Flooded.\n'
                'alert dnp3 any any -> any any (msg:"SURICATA DNP3 Request flood detected"; \\\n'
                '      app-layer-event:dnp3.flooded; classtype:protocol-command-decode; sid:2270000; rev:2;)\n'
                '\n'
                'alert dnp3 any any -> any any (msg:"SURICATA DNP3 Length too small"; \\\n'
                '      app-layer-event:dnp3.len_too_small; classtype:protocol-command-decode; sid:2270001; rev:3;)\n')
            (source / "modbus-events.rules").write_text(
                'alert modbus any any -> any any (msg:"SURICATA Modbus invalid Length"; app-layer-event:modbus.invalid_length; sid:2250003; rev:2;)\n'
                'alert modbus any any -> any any (msg:"SURICATA Modbus Request flood detected"; app-layer-event:modbus.flooded; sid:2250009; rev:2;)\n')
            target = Path(folder) / "suricata.rules"
            target.write_text("\n".join(self.BUNDLED) + "\n")
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(protocol_events.main(["enable", str(target), "--from", str(source)]), 0)
            self.assertIn("2 switched on, 3 added", out.getvalue())
            after = target.read_text().splitlines()
            self.assertEqual(after[0], self.BUNDLED[0])
            self.assertTrue(after[1].startswith("alert modbus") and after[2].startswith("alert modbus"))
            self.assertEqual(after[3:7], self.BUNDLED[3:7], "rules the publisher switched off, and comments, stay as they were")
            added = [line for line in after[7:] if line.startswith("alert ")]
            self.assertEqual(sorted(re.search(r"sid:(\d+)", line).group(1) for line in added), ["2234000", "2250009", "2270001"],
                             "a rule already in the file is not added twice, and a rule Suricata ships switched off is not added")
            joined = [line for line in added if "sid:2270001;" in line][0]
            self.assertEqual(joined, 'alert dnp3 any any -> any any (msg:"SURICATA DNP3 Length too small"; '
                                     'app-layer-event:dnp3.len_too_small; classtype:protocol-command-decode; sid:2270001; rev:3;)')
            # A second run finds nothing to do and leaves the file alone.
            before = target.read_text()
            with contextlib.redirect_stdout(io.StringIO()) as out:
                protocol_events.main(["enable", str(target), "--from", str(source)])
            self.assertIn("0 switched on, 0 added", out.getvalue())
            self.assertEqual(target.read_text(), before)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(protocol_events.main(["status", str(target)]), 1)        # not all 18 are there
                self.assertEqual(protocol_events.main(["status", str(Path(folder) / "none")]), 2)


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
