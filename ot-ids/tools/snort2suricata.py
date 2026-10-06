#!/usr/bin/env python3
# TechDetechtives OT IDS. Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Convert Snort 2.x rules into rules Suricata can load.

Suricata rules from outside can be passed through it too: they come out
unchanged apart from the new sid, the rate limit and the options below.

Most Snort 2 rules load in Suricata unchanged. The ones that do not usually
fail for one of four reasons, and this tool deals with each:

  1. variables the sensor does not define ($S7_SERVER, $BACNET_CLIENT, ...):
     replaced by $HOME_NET (addresses) or any (ports);
  2. Snort preprocessor keywords Suricata spells differently (modbus_func):
     rewritten;
  3. keywords Suricata does not have (modbus_data, sip_method, ...) or Snort 3
     syntax: the rule is set aside with the reason, not guessed at;
  4. signature numbers that repeat or collide with other rule sets: every rule
     gets a new sid from --sid-base, and the original is kept in the metadata.

With --limit-seconds, a rule that has no rate limit of its own is given one
alert per source address per window, so an informational rule cannot flood.

"drop", "sdrop" and "reject" become "alert": this sensor watches, it does not
block.

The engine has the last word. build-iso.sh runs `suricata -T` on the output
and tools/prune_rules.py comments out whatever the engine still refuses.

  snort2suricata.py --name quickdraw --sid-base 1911000 -o ext-quickdraw.rules all-quickdraw.rules
"""
import argparse
import re
import sys
from pathlib import Path

# Address and port variables present in the sensor's Suricata configuration
# (Suricata 8 suricata.yaml, which the product starts from).
KNOWN_ADDRESS_VARS = {
    "HOME_NET", "EXTERNAL_NET", "HTTP_SERVERS", "SMTP_SERVERS", "SQL_SERVERS", "DNS_SERVERS",
    "TELNET_SERVERS", "AIM_SERVERS", "DC_SERVERS", "DNP3_SERVER", "DNP3_CLIENT", "MODBUS_CLIENT",
    "MODBUS_SERVER", "ENIP_CLIENT", "ENIP_SERVER",
}
KNOWN_PORT_VARS = {
    "HTTP_PORTS", "SHELLCODE_PORTS", "ORACLE_PORTS", "SSH_PORTS", "DNP3_PORTS", "MODBUS_PORTS",
    "FILE_DATA_PORTS", "FTP_PORTS", "GENEVE_PORTS", "VXLAN_PORTS", "TEREDO_PORTS", "SIP_PORTS",
}

# Snort keywords with no Suricata equivalent: the rule cannot be converted.
UNSUPPORTED = {
    "modbus_data", "sip_method", "sip_stat_code", "sip_header", "sip_body", "gtp_type", "gtp_info",
    "gtp_version", "cvs", "logto", "session", "resp", "react", "activates", "activated_by", "count",
    "replace", "soid", "sd_pattern", "appid", "stream_reassemble", "http_encode", "protected_content",
    "file_type", "so",
}
# Snort 3 only: harmless to drop.
DROPPED = {"rem", "service"}

MODBUS_FUNCTIONS = {
    "read_coils": 1, "read_discrete_inputs": 2, "read_holding_registers": 3, "read_input_registers": 4,
    "write_single_coil": 5, "write_single_register": 6, "read_exception_status": 7, "diagnostics": 8,
    "get_comm_event_counter": 11, "get_comm_event_log": 12, "write_multiple_coils": 15,
    "write_multiple_registers": 16, "report_slave_id": 17, "read_file_record": 20,
    "write_file_record": 21, "mask_write_register": 22, "read_write_multiple_registers": 23,
    "read_fifo_queue": 24, "encapsulated_interface_transport": 43,
}

HEADER = re.compile(
    r"^(alert|drop|sdrop|reject|log|pass)\s+(\S+)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s*\((.*)\)\s*$",
    re.S,
)


def logical_lines(text):
    """Rule lines, with backslash continuations joined; comments and blanks skipped."""
    pending = ""
    for raw in text.splitlines():
        line = raw.strip()
        if pending:
            line = pending + " " + line
            pending = ""
        if line.endswith("\\"):
            pending = line[:-1].rstrip()
            continue
        if line and not line.startswith("#"):
            yield line
    if pending:
        yield pending


def split_options(body):
    """Split 'a:1; msg:"x; y"; b;' on semicolons that are outside quotes."""
    parts, current, quoted, escaped = [], "", False, False
    for char in body:
        if escaped:
            current += char
            escaped = False
            continue
        if char == "\\":
            current += char
            escaped = True
            continue
        if char == '"':
            quoted = not quoted
        if char == ";" and not quoted:
            if current.strip():
                parts.append(current.strip())
            current = ""
        else:
            current += char
    if current.strip():
        parts.append(current.strip())
    return parts


def fix_variables(field, known, fallback, notes):
    def swap(match):
        name = match.group(1)
        if name in known:
            return match.group(0)
        notes.add(f"${name} is not defined on the sensor, used {fallback}")
        return fallback
    return re.sub(r"\$([A-Za-z0-9_]+)", swap, field)


def convert_rule(line, new_sid, source, limit_seconds=0, once_per_window=False, skip_sids=()):
    """Return (converted rule or None, reason it was set aside or None, notes)."""
    notes = set()
    match = HEADER.match(line)
    if not match:
        return None, "not a Snort 2 rule header (Snort 3 syntax, or a broken line)", notes
    action, proto, src, sport, direction, dst, dport, body = match.groups()
    if action == "pass":
        return None, "pass rule (would hide traffic from other rules)", notes
    if action != "alert":
        notes.add(f"action {action} changed to alert")
    src = fix_variables(src, KNOWN_ADDRESS_VARS, "$HOME_NET", notes)
    dst = fix_variables(dst, KNOWN_ADDRESS_VARS, "$HOME_NET", notes)
    sport = fix_variables(sport, KNOWN_PORT_VARS, "any", notes)
    dport = fix_variables(dport, KNOWN_PORT_VARS, "any", notes)
    for field in (sport, dport):
        if field in ("!any", "[!any]"):
            return None, "a negated port variable is not defined on the sensor", notes

    options, modbus, original_sid, metadata = [], {}, None, None
    for option in split_options(body):
        key, _, value = option.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key in UNSUPPORTED:
            return None, f"uses '{key}', which Suricata does not have", notes
        if key in DROPPED:
            notes.add(f"dropped Snort 3 option '{key}'")
            continue
        if key == "modbus_func":
            number = MODBUS_FUNCTIONS.get(value.lower(), value)
            if not str(number).isdigit():
                return None, f"modbus_func '{value}' is not a known function", notes
            modbus["function"] = number
            notes.add("modbus_func rewritten as 'modbus: function'")
            continue
        if key == "modbus_unit":
            if not value.isdigit():
                return None, f"modbus_unit '{value}' is not a number", notes
            modbus["unit"] = value
            notes.add("modbus_unit rewritten as 'modbus: unit'")
            continue
        if key == "sid":
            original_sid = value
            continue
        if key == "metadata":
            metadata = value
            continue
        options.append(option)
    if original_sid is None:
        return None, "no sid", notes
    if original_sid in skip_sids:
        return None, "left out on purpose (skip_sids)", notes
    if once_per_window:
        # "type threshold" alerts on every Nth match, so one scan raises dozens of
        # alerts. "type both" raises one per window once the count is reached.
        for index, option in enumerate(options):
            if option.lower().startswith("threshold") and re.search(r"type\s+threshold\b", option):
                options[index] = re.sub(r"type\s+threshold\b", "type both", option)
                notes.add("threshold changed from every Nth match to once per window")
    if not any(option.lower().startswith("msg") for option in options):
        return None, "no msg", notes
    if modbus:
        pieces = ([f"unit {modbus['unit']}"] if "unit" in modbus else []) + \
                 ([f"function {modbus['function']}"] if "function" in modbus else [])
        options.append("modbus: " + ", ".join(pieces))
    # Imported sets often alert on every matching packet. One alert per address
    # per window keeps an informational rule from flooding the console.
    if limit_seconds and not any(option.lower().startswith(("threshold", "detection_filter")) for option in options):
        options.append(f"threshold: type limit, track by_src, count 1, seconds {limit_seconds}")
        notes.add(f"no rate limit in the source, limited to one alert per address per {limit_seconds} s")
    tag = f"td_source {source}, td_orig_sid {original_sid}"
    options.append(f"metadata:{metadata + ', ' if metadata else ''}{tag}")
    options.append(f"sid:{new_sid}")
    rule = f"alert {proto} {src} {sport} {direction} {dst} {dport} ({'; '.join(options)};)"
    return rule, None, notes


def convert_text(text, source, sid_base, limit_seconds=0, once_per_window=False, skip_sids=()):
    """Convert every rule in text. Returns (rules, set_aside, notes_by_sid)."""
    rules, set_aside, noted = [], [], {}
    next_sid = sid_base
    for line in logical_lines(text):
        if not re.match(r"^(alert|drop|sdrop|reject|log|pass)\s", line):
            continue
        rule, reason, notes = convert_rule(line, next_sid, source, limit_seconds, once_per_window, set(skip_sids))
        if rule is None:
            set_aside.append((reason, line))
            continue
        rules.append(rule)
        if notes:
            noted[next_sid] = sorted(notes)
        next_sid += 1
    return rules, set_aside, noted


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("inputs", nargs="+", type=Path, help="Snort rule files")
    parser.add_argument("--name", required=True, help="short source name, written into each rule's metadata")
    parser.add_argument("--sid-base", required=True, type=int, help="first sid to hand out")
    parser.add_argument("--licence", default="", help="licence of the source, written in the file header")
    parser.add_argument("--limit-seconds", type=int, default=0,
                        help="give rules that have no rate limit one alert per source address per this many seconds")
    parser.add_argument("--once-per-window", action="store_true",
                        help="turn 'type threshold' (an alert every Nth match) into 'type both' (one alert per window)")
    parser.add_argument("--skip-sids", default="", help="comma-separated original sids to leave out")
    parser.add_argument("-o", "--output", required=True, type=Path)
    parser.add_argument("--report", type=Path, help="write what was changed and set aside to this file")
    args = parser.parse_args()

    text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in args.inputs)
    skip = [item.strip() for item in args.skip_sids.split(",") if item.strip()]
    rules, set_aside, noted = convert_text(text, args.name, args.sid_base, args.limit_seconds, args.once_per_window, skip)
    header = [
        f"# Imported and renumbered by tools/snort2suricata.py. Source: {args.name}.",
        f"# Licence of the source: {args.licence or 'see the source'}.",
        f"# {len(rules)} rules, sids {args.sid_base} to {args.sid_base + max(len(rules) - 1, 0)}; "
        f"{len(set_aside)} set aside (see the conversion report).",
        "",
    ]
    args.output.write_text("\n".join(header + rules) + "\n", encoding="utf-8")
    lines = [f"{args.name}: {len(rules)} converted, {len(set_aside)} set aside", ""]
    if noted:
        lines.append("Changed during conversion:")
        lines += [f"  sid {sid}: {'; '.join(notes)}" for sid, notes in sorted(noted.items())]
        lines.append("")
    if set_aside:
        lines.append("Set aside (not written to the output):")
        lines += [f"  {reason}\n      {line[:200]}" for reason, line in set_aside]
    report = "\n".join(lines) + "\n"
    if args.report:
        args.report.write_text(report, encoding="utf-8")
    print(lines[0], file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
