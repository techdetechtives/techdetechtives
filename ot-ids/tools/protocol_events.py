#!/usr/bin/env python3
# TechDetechtives OT IDS. Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Check, and switch on, Suricata's own Modbus, DNP3 and EtherNet/IP event rules.

Suricata's decoders raise an event when a message breaks its protocol: a Modbus
length that does not add up, a read of more registers than the protocol allows,
an answer nobody asked for, a DNP3 checksum that is wrong, a flood of requests
with no answers. Suricata ships one small rule per event (modbus-events.rules,
dnp3-events.rules, enip-events.rules); without the rule the event is never
reported.

Why they may be off. The product's Suricata image builds its rule file with
suricata-update while Suricata's configuration is still the packaged default,
in which Modbus, DNP3 and EtherNet/IP are disabled. suricata-update comments
out every rule for a disabled protocol ("Disabling rules for protocol modbus").
The product enables the three protocols when it starts, and does not build the
rule file again unless rule updates are switched on. Read from the sources of
Malcolm 26.09.0 (Dockerfiles/suricata.Dockerfile), Suricata 8.0
(suricata.yaml.in) and suricata-update 1.3.8 (main.py); not seen in a built
image. `status` says what a given rule file really holds.

  protocol_events.py status suricata.rules
  protocol_events.py enable suricata.rules [--from /usr/share/suricata/rules]

`enable` removes the comment mark from those rules, and adds the ones that are
not in the file at all from Suricata's own rule files when it finds them. It
touches no other rule and writes the file only when something changed.

If the installed system later builds its rule file again (rule updates
switched on, with Internet access), suricata-update writes it afresh with the
protocols enabled: the Modbus and DNP3 rules are then active by its doing, and
the EtherNet/IP ones, which suricata-update does not carry, are gone again.
"""
import argparse
import re
import sys
from pathlib import Path

# The signature numbers Suricata 8.0 gives its own event rules (rules/*-events.rules).
EVENT_SIDS = {
    "modbus": (2250001, 2250002, 2250003, 2250005, 2250006, 2250007, 2250008, 2250009),
    "dnp3": tuple(range(2270000, 2270008)),
    "enip": (2234000, 2234001),
}
WANTED = {sid: protocol for protocol, sids in EVENT_SIDS.items() for sid in sids}
SOURCE_DIRS = ("/usr/share/suricata/rules", "/etc/suricata/rules")
RULE = re.compile(r"^(?P<mark>(?:#\s*)*)(?P<rule>alert\s+(?P<proto>\S+)\s.*\bsid\s*:\s*(?P<sid>\d+)\s*;.*)$")


def read(path):
    return Path(path).read_text(encoding="utf-8", errors="replace").splitlines()


def read_joined(path):
    """Lines of one of Suricata's own rule files, with a rule written over several lines (ending in a backslash) made one."""
    lines, pending = [], ""
    for line in read(path):
        if line.rstrip().endswith("\\"):
            pending += line.rstrip()[:-1].rstrip() + " "
            continue
        lines.append(pending + line.strip() if pending else line)
        pending = ""
    return lines + ([pending.strip()] if pending else [])


def scan(lines):
    """{sid: 'active' | 'commented'} for the event rules found in the lines, and counts for all industrial rules."""
    found, totals = {}, {protocol: [0, 0] for protocol in EVENT_SIDS}
    for line in lines:
        match = RULE.match(line.strip())
        if not match:
            continue
        active = not match.group("mark")
        if match.group("proto") in totals:
            totals[match.group("proto")][0 if active else 1] += 1
        sid = int(match.group("sid"))
        if sid in WANTED and (active or sid not in found):
            found[sid] = "active" if active else "commented"
    return found, totals


def status_lines(lines):
    found, totals = scan(lines)
    out = []
    for protocol, sids in EVENT_SIDS.items():
        states = [found.get(sid, "missing") for sid in sids]
        out.append(f"{protocol}: {states.count('active')} of {len(sids)} event rules active, {states.count('commented')} commented out, "
                   f"{states.count('missing')} not in the file; all '{protocol}' rules in the file: {totals[protocol][0]} active, "
                   f"{totals[protocol][1]} commented out")
    return out, found


def enable(lines, source_dirs=()):
    """Return (new lines, number uncommented, number added)."""
    found, _ = scan(lines)
    uncommented, out = 0, []
    for line in lines:
        match = RULE.match(line.strip())
        if match and match.group("mark") and int(match.group("sid")) in WANTED and found.get(int(match.group("sid"))) == "commented":
            out.append(match.group("rule"))
            found[int(match.group("sid"))] = "active"
            uncommented += 1
        else:
            out.append(line)
    missing = {sid for sid in WANTED if sid not in found}
    added = []
    for folder in source_dirs:
        for protocol in EVENT_SIDS:
            path = Path(folder) / f"{protocol}-events.rules"
            if not path.is_file():
                continue
            for line in read_joined(path):
                match = RULE.match(line.strip())
                if match and not match.group("mark") and int(match.group("sid")) in missing:
                    added.append(match.group("rule"))
                    missing.discard(int(match.group("sid")))
    if added:
        out += ["", "# Suricata's own protocol event rules, added from its rule files by the TechDetechtives build:"] + added
    return out, uncommented, len(added)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status").add_argument("file", type=Path)
    enabler = commands.add_parser("enable")
    enabler.add_argument("file", type=Path)
    enabler.add_argument("--from", dest="sources", action="append", default=None,
                         help="folder holding Suricata's own *-events.rules (default: where the Debian package puts them)")
    args = parser.parse_args(argv)
    try:
        lines = read(args.file)
    except OSError as error:
        print(f"cannot read {args.file}: {error}", file=sys.stderr)
        return 2
    if args.command == "status":
        report, found = status_lines(lines)
        print("\n".join(report))
        return 0 if all(found.get(sid) == "active" for sid in WANTED) else 1
    new, uncommented, added = enable(lines, args.sources if args.sources is not None else SOURCE_DIRS)
    if uncommented or added:
        with open(args.file, "w", encoding="utf-8") as handle:       # written in place: the file keeps its owner
            handle.write("\n".join(new) + "\n")
    print(f"protocol event rules: {uncommented} switched on, {added} added, in {args.file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
