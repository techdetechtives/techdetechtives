# TechDetechtives layer 2 watch tests. Copyright (c) 2026 TechDetechtives. MIT licence.
"""Run with:  python3 -m unittest discover -s platform/tests -p "test_l2_watch.py" -v

The Zeek script platform/zeek/techdetechtives/l2-watch.zeek is run by Zeek
itself against small captures made here (ARP frames and connection attempts
written byte by byte), and the notices it writes are compared with what each
scene should produce. Skipped when no `zeek` program is installed; the text
checks at the end always run.
"""

import json
import random
import shutil
import socket
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "zeek" / "techdetechtives" / "l2-watch.zeek"
SIGMA = Path(__file__).resolve().parents[1] / "detections" / "sigma"

GATEWAY = ("10.0.0.1", "00:1b:21:aa:00:01")
VICTIM = ("10.0.0.5", "00:1b:21:aa:00:05")
ATTACKER = ("10.0.0.66", "00:0c:29:66:66:66")
BROADCAST = "ff:ff:ff:ff:ff:ff"
NOBODY = "00:00:00:00:00:00"


def mac(text):
    return bytes.fromhex(text.replace(":", ""))


def arp(operation, sender_card, sender_ip, target_card, target_ip, to=None):
    to = to or (BROADCAST if operation == 1 else target_card)
    frame = mac(to) + mac(sender_card) + b"\x08\x06" + struct.pack("!HHBBH", 1, 0x0800, 6, 4, operation)
    frame += mac(sender_card) + socket.inet_aton(sender_ip) + mac(target_card) + socket.inet_aton(target_ip)
    return frame.ljust(60, b"\x00")


def ask(who, about_ip):
    return arp(1, who[1], who[0], NOBODY, about_ip)


def answer(who, to):
    return arp(2, who[1], who[0], to[1], to[0])


def announce(who):
    return arp(1, who[1], who[0], NOBODY, who[0])


def connection_attempt(source_card, source_ip, target_ip, source_port=40000, target_port=80):
    def checksum(data):
        total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
        total = (total & 0xFFFF) + (total >> 16)
        return ~(total + (total >> 16)) & 0xFFFF
    tcp = struct.pack("!HHIIBBHHH", source_port, target_port, 1000, 0, 5 << 4, 0x02, 64240, 0, 0)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, socket.inet_aton(source_ip), socket.inet_aton(target_ip))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return (mac(GATEWAY[1]) + mac(source_card) + b"\x08\x00" + header + tcp).ljust(60, b"\x00")


def capture(path, packets):
    """packets: [(seconds from the start, frame bytes)]"""
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for when, frame in sorted(packets, key=lambda item: item[0]):
            stamp = 1_760_000_000 + when
            handle.write(struct.pack("<IIII", int(stamp), int((stamp % 1) * 1_000_000), len(frame), len(frame)))
            handle.write(frame)


def ordinary_traffic(minutes, hosts=20):
    """Machines asking for the gateway and each other, and getting answers."""
    packets = []
    for index in range(hosts):
        host = ("10.0.0.%d" % (100 + index), "00:1b:21:bb:00:%02x" % index)
        for minute in range(minutes):
            at = minute * 60 + index
            packets.append((at, ask(host, GATEWAY[0])))
            packets.append((at + 0.001, answer(GATEWAY, host)))
            packets.append((at + 30, ask(GATEWAY, host[0])))
            packets.append((at + 30.001, answer(host, GATEWAY)))
    return packets


@unittest.skipUnless(shutil.which("zeek"), "the zeek program is not installed")
class LayerTwoWatch(unittest.TestCase):
    def notices(self, packets, settings="redef TechDetechtives::l2_learning_time = 0secs;"):
        with tempfile.TemporaryDirectory() as folder:
            capture(Path(folder) / "scene.pcap", packets)
            (Path(folder) / "run.zeek").write_text("@load %s\nredef LogAscii::use_json = T;\n"
                                                    "redef FilteredTraceDetection::enable = F;\n%s\n" % (SCRIPT, settings))
            result = subprocess.run([shutil.which("zeek"), "-C", "-r", "scene.pcap", "run.zeek"],
                                    cwd=folder, capture_output=True, text=True, timeout=300)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr.strip(), "", "Zeek printed warnings")
            log = Path(folder) / "notice.log"
            if not log.exists():
                return []
            return [json.loads(line) for line in log.read_text().splitlines()]

    def names(self, packets, **keywords):
        return sorted(notice["note"].split("::")[1] for notice in self.notices(packets, **keywords))

    def test_ordinary_traffic_raises_nothing(self):
        self.assertEqual(self.names(ordinary_traffic(40)), [])

    def test_arp_poisoning(self):
        # The attacker tells the victim every two seconds that the gateway's
        # address is at the attacker's card, while the real gateway keeps talking.
        packets = ordinary_traffic(6)
        packets.append((1, ask(VICTIM, GATEWAY[0])))
        packets.append((1.001, answer(GATEWAY, VICTIM)))
        for step in range(90):
            at = 120 + step * 2
            packets.append((at, arp(2, ATTACKER[1], GATEWAY[0], VICTIM[1], VICTIM[0])))
        found = self.notices(packets)
        names = sorted(notice["note"].split("::")[1] for notice in found)
        self.assertEqual(names, ["ARP_Reply_Burst", "Address_Claimed_By_Two_Cards", "Address_Taken_Over"])
        by_name = {notice["note"].split("::")[1]: notice for notice in found}
        self.assertIn(GATEWAY[0], by_name["Address_Claimed_By_Two_Cards"]["msg"])
        self.assertIn(ATTACKER[1], by_name["Address_Claimed_By_Two_Cards"]["msg"])
        self.assertIn(GATEWAY[1], by_name["Address_Claimed_By_Two_Cards"]["msg"])
        self.assertIn(ATTACKER[1], by_name["ARP_Reply_Burst"]["msg"])
        self.assertEqual(by_name["Address_Taken_Over"]["src"], GATEWAY[0])

    def test_address_handed_to_another_machine_after_a_quiet_spell(self):
        old, new = ("10.0.0.50", "00:1b:21:cc:00:01"), ("10.0.0.50", "00:1b:21:cc:00:02")
        packets = [(0, announce(old)), (2 * 3600, announce(new)), (2 * 3600 + 60, announce(new))]
        self.assertEqual(self.names(packets), ["Address_Has_New_Card"])

    def test_address_replaced_while_still_in_use(self):
        old, new = ("10.0.0.50", "00:1b:21:cc:00:01"), ("10.0.0.50", "00:1b:21:cc:00:02")
        packets = [(0, announce(old)), (600, announce(new)), (1300, announce(new))]
        self.assertEqual(self.names(packets), ["Address_Taken_Over"])

    def test_mac_flood(self):
        generator = random.Random(7)
        packets = ordinary_traffic(2)
        for index in range(2000):
            card = "%02x:%02x:%02x:%02x:%02x:%02x" % tuple([generator.randrange(256) & 0xFE] + [generator.randrange(256) for _ in range(5)])
            source = "%d.%d.%d.%d" % tuple(generator.randrange(1, 255) for _ in range(4))
            packets.append((200 + index * 0.002, connection_attempt(card, source, "10.0.0.9", 1024 + index)))
        names = self.names(packets)
        self.assertEqual(names.count("Many_New_Cards"), 1)
        # Single-card reports stop once the flood is recognised.
        self.assertLess(names.count("Software_Set_Card_Address"), 100)
        self.assertEqual(set(names), {"Many_New_Cards", "Software_Set_Card_Address"})

    def test_arp_sweep(self):
        packets = ordinary_traffic(2)
        for index in range(1, 400):
            packets.append((130 + index * 0.02, ask(ATTACKER, "10.0.%d.%d" % (1 + index // 250, index % 250 + 1))))
        self.assertEqual(self.names(packets), ["ARP_Request_Flood"])

    def test_one_card_claiming_a_whole_segment(self):
        packets = ordinary_traffic(2)
        for index in range(30):
            packets.append((130 + index, arp(2, ATTACKER[1], "10.0.0.%d" % (200 + index), BROADCAST, "10.0.0.%d" % (200 + index), to=BROADCAST)))
        self.assertEqual(self.names(packets), ["Card_Answers_For_Many_Addresses"])

    def test_software_set_card_after_learning(self):
        phone = ("10.0.0.77", "a6:11:22:33:44:55")       # second digit 6: set by software
        packets = ordinary_traffic(15) + [(5, announce(("10.0.0.78", "02:42:ac:11:00:02"))), (700, announce(phone))]
        found = self.notices(packets, settings="")       # default: ten minutes of learning
        self.assertEqual([notice["note"].split("::")[1] for notice in found], ["Software_Set_Card_Address"])
        self.assertIn(phone[1], found[0]["msg"])

    def test_ignored_cards_and_addresses_are_left_alone(self):
        packets = [(0, announce(GATEWAY))]
        for step in range(90):
            packets.append((60 + step * 2, arp(2, ATTACKER[1], GATEWAY[0], VICTIM[1], VICTIM[0])))
            packets.append((61 + step * 2, announce(GATEWAY)))
        self.assertIn("Address_Claimed_By_Two_Cards", self.names(packets))
        quiet = 'redef TechDetechtives::l2_learning_time = 0secs;\nredef TechDetechtives::l2_ignore_cards += { "%s" };' % ATTACKER[1]
        self.assertEqual(self.names(packets, settings=quiet), [])
        quiet = "redef TechDetechtives::l2_learning_time = 0secs;\nredef TechDetechtives::l2_ignore_addresses += { 10.0.0.1/32 };"
        self.assertEqual(self.names(packets, settings=quiet), ["ARP_Reply_Burst"])

    def test_address_probes_are_not_claims(self):
        # A machine checking that an address is free asks from 0.0.0.0.
        packets = [(index, arp(1, "00:1b:21:dd:00:%02x" % index, "0.0.0.0", NOBODY, "10.0.0.50")) for index in range(5)]
        self.assertEqual(self.names(packets), [])


class ScriptText(unittest.TestCase):
    TEXT = SCRIPT.read_text()

    def test_survives_the_platforms_template_step(self):
        # Security Onion copies custom Zeek scripts through Jinja.
        for sequence in ("{{", "{%", "{#"):
            self.assertNotIn(sequence, self.TEXT)

    def test_every_notice_has_a_sigma_rule_and_the_other_way_round(self):
        import re
        import yaml
        block = re.search(r"redef enum Notice::Type \+= \{(.*?)\};", self.TEXT, re.S).group(1)
        declared = {"TechDetechtives::" + name for name in re.findall(r"\b([A-Z][A-Za-z0-9_]+),", block)}
        self.assertEqual(len(declared), 8)
        used = set()
        for path in SIGMA.glob("techdetechtives_l2_*.yml"):
            rule = yaml.safe_load(path.read_text())
            self.assertEqual(rule["detection"]["selection"]["event.dataset"], "zeek.notice", path.name)
            used.update(rule["detection"]["selection"]["notice.note"])
        self.assertEqual(used, declared)

    def test_loader_names_the_script(self):
        self.assertEqual((SCRIPT.parent / "__load__.zeek").read_text().strip(), "@load ./l2-watch")


if __name__ == "__main__":
    unittest.main()
