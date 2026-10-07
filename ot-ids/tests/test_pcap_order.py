# TechDetechtives OT IDS tests. Copyright (c) 2026 TechDetechtives. MIT licence.
"""Tests for the tool that puts a capture file's packets in time order (td-pcap-order).

Run with:  python3 -m unittest discover -s ot-ids/tests -v

The capture files are made here, byte by byte. No engine reads the result: that
Suricata and Zeek then see the events in the right order follows from the order
of the packets, and was not watched.
"""
import contextlib
import importlib.util
import io
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

KIT = Path(__file__).resolve().parents[1]
PROGRAM = KIT / "hardening/rootfs/usr/local/lib/techdetechtives/td_pcap_order.py"
spec = importlib.util.spec_from_file_location("td_pcap_order", PROGRAM)
td_pcap_order = importlib.util.module_from_spec(spec)
_written, sys.dont_write_bytecode = sys.dont_write_bytecode, True      # no __pycache__ in the folder that is copied into the ISO
try:
    spec.loader.exec_module(td_pcap_order)
finally:
    sys.dont_write_bytecode = _written

T = 1_788_000_000                                     # some second in 2026


def capture(packets, order="<", nanoseconds=False):
    """A classic capture file: packets is [(seconds, fraction, payload bytes)]."""
    magic = 0xA1B23C4D if nanoseconds else 0xA1B2C3D4
    out = struct.pack(order + "IHHiIII", magic, 2, 4, 0, 0, 65535, 1)
    for seconds, fraction, payload in packets:
        out += struct.pack(order + "IIII", seconds, fraction, len(payload), len(payload)) + payload
    return out


def packets_of(data, order="<"):
    found, position = [], 24
    while position < len(data):
        seconds, fraction, captured, _ = struct.unpack_from(order + "IIII", data, position)
        found.append((seconds, fraction, data[position + 16:position + 16 + captured]))
        position += 16 + captured
    return found


class PcapOrder(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.source, self.target = Path(self.folder.name) / "export.pcap", Path(self.folder.name) / "incident7.pcap"

    def tearDown(self):
        self.folder.cleanup()

    def run_tool(self, *arguments):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = td_pcap_order.main([str(argument) for argument in arguments])
        return status, out.getvalue(), err.getvalue()

    def test_an_export_written_session_by_session_is_put_in_time_order(self):
        # As Arkime writes it: a short session that ended first, then a long one that began before it.
        short = [(T + 600, 0, b"write-1"), (T + 601, 500, b"write-2")]
        long_one = [(T, 0, b"identify-1"), (T + 1, 250000, b"identify-2"), (T + 3000, 0, b"still-open")]
        self.source.write_bytes(capture(short + long_one))
        status, out, err = self.run_tool(self.source, self.target)
        self.assertEqual((status, err), (0, ""))
        self.assertIn("5 packets", out)
        self.assertIn("NOT in time order: 2 packets come after a later one; the largest step back is 601.000 seconds.", out)
        self.assertIn(f"Written in time order to {self.target}.", out)
        written = self.target.read_bytes()
        self.assertEqual(written[:24], self.source.read_bytes()[:24], "the file header is kept as it is")
        self.assertEqual([payload for _, _, payload in packets_of(written)],
                         [b"identify-1", b"identify-2", b"write-1", b"write-2", b"still-open"])
        self.assertEqual(sorted(packets_of(written)), sorted(short + long_one), "no packet lost, added or changed")
        self.assertEqual(self.run_tool("--check", self.target)[0], 0)
        self.assertEqual(self.run_tool("--check", self.source)[0], 3)
        self.assertEqual(sorted(os.listdir(self.folder.name)), ["export.pcap", "incident7.pcap"], "no temporary file is left behind")

    def test_packets_with_the_same_time_keep_their_order_and_fractions_count(self):
        self.source.write_bytes(capture([(T + 5, 10, b"c"), (T + 5, 10, b"d"), (T + 5, 9, b"b"), (T, 999999, b"a"), (T + 5, 10, b"e")]))
        status, out, _ = self.run_tool(self.source, self.target)
        self.assertEqual(status, 0)
        self.assertIn("the largest step back is 4.000 seconds", out, "microseconds are read as microseconds")
        self.assertEqual(b"".join(payload for _, _, payload in packets_of(self.target.read_bytes())), b"abcde")

    def test_both_byte_orders_and_nanosecond_times(self):
        for order, nanoseconds in (("<", True), (">", False), (">", True)):
            target = Path(self.folder.name) / f"out{order == '<'}{nanoseconds}.pcap"
            # 999,999,999 ns sorts after 5 ns; read with the wrong byte order the seconds would be nonsense
            self.source.write_bytes(capture([(T + 1, 5, b"second"), (T, 999_999_999 if nanoseconds else 999_999, b"first")], order, nanoseconds))
            status, out, _ = self.run_tool(self.source, target)
            self.assertEqual(status, 0)
            self.assertIn("2026-", out, "the times are read in the file's own byte order")
            self.assertEqual([payload for _, _, payload in packets_of(target.read_bytes(), order)], [b"first", b"second"])

    def test_a_file_already_in_order_is_copied_as_it_is(self):
        data = capture([(T, 0, b"a"), (T, 1, b"b"), (T + 9, 0, b"c")])
        self.source.write_bytes(data)
        status, out, _ = self.run_tool(self.source, self.target)
        self.assertEqual(status, 0)
        self.assertIn("In time order.", out)
        self.assertEqual(self.target.read_bytes(), data)

    def test_a_packet_cut_off_at_the_end_is_left_out_and_said(self):
        data = capture([(T + 2, 0, b"later"), (T, 0, b"earlier"), (T + 3, 0, b"this one is cut off")])
        self.source.write_bytes(data[:-6])
        status, out, _ = self.run_tool(self.source, self.target)
        self.assertEqual(status, 0)
        self.assertIn("is left out", out)
        self.assertEqual([payload for _, _, payload in packets_of(self.target.read_bytes())], [b"earlier", b"later"])

    def test_what_it_refuses(self):
        good = capture([(T, 0, b"a")])
        cases = {
            "pcapng": (b"\x0a\x0d\x0d\x0a" + b"\0" * 40, "pcapng"),
            "text": (b"this is not a capture file at all", "not a capture file"),
            "empty": (b"", "empty"),
            "short": (good[:10], "ends inside its own header"),
            "absurd": (good[:24] + struct.pack("<IIII", T, 0, 0x7FFFFFFF, 0x7FFFFFFF) + b"x" * 40, "claims a packet of"),
        }
        for name, (data, words) in cases.items():
            self.source.write_bytes(data)
            status, out, err = self.run_tool(self.source, self.target)
            self.assertEqual(status, 1, name)
            self.assertIn(words, err, name)
            self.assertFalse(self.target.exists(), name)
        self.source.write_bytes(good)
        self.target.write_bytes(b"something of the operator's")
        status, out, err = self.run_tool(self.source, self.target)
        self.assertEqual(status, 1)
        self.assertIn("exists already", err)
        self.assertEqual(self.target.read_bytes(), b"something of the operator's")
        self.assertEqual(self.run_tool(self.source, self.source)[0], 1, "never over the file it reads")
        self.assertEqual(self.source.read_bytes(), good)
        status, out, err = self.run_tool(Path(self.folder.name) / "missing.pcap", self.target.with_name("x.pcap"))
        self.assertEqual(status, 1)
        self.assertIn("No such file", err)
        status, out, err = self.run_tool(self.source, Path(self.folder.name) / "no such folder" / "x.pcap")
        self.assertEqual(status, 1)
        for arguments in ([], [str(self.source)], ["--check", str(self.source), str(self.target)]):
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                td_pcap_order.main(arguments)

    def test_many_packets_and_the_program_run_as_the_host_command_runs_it(self):
        import random
        chooser = random.Random(7)
        packets = [(T + chooser.randrange(0, 3600), chooser.randrange(0, 1_000_000), struct.pack("<I", number) * chooser.randrange(1, 40))
                   for number in range(20000)]
        self.source.write_bytes(capture(packets))
        done = subprocess.run([sys.executable, str(PROGRAM), str(self.source), str(self.target)], capture_output=True, text=True, timeout=120)
        self.assertEqual((done.returncode, done.stderr), (0, ""))
        written = packets_of(self.target.read_bytes())
        self.assertEqual([(seconds, fraction) for seconds, fraction, _ in written], sorted((seconds, fraction) for seconds, fraction, _ in packets))
        self.assertEqual(sorted(written), sorted(packets))
        wrapper = (KIT / "hardening/rootfs/usr/local/bin/td-pcap-order").read_text()
        self.assertIn("exec python3 /usr/local/lib/techdetechtives/td_pcap_order.py", wrapper)
        self.assertTrue(PROGRAM.stat().st_mode & 0o111)


if __name__ == "__main__":
    unittest.main()
