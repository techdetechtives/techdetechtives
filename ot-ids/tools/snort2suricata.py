#!/usr/bin/env python3
# TechDetechtives OT IDS. Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Convert Snort 2.x rules, and the plain part of Snort 3 rules, into rules Suricata can load.

Suricata rules from outside can be passed through it too: they come out
unchanged apart from the new sid, the rate limit and the options below.

Most Snort 2 rules load in Suricata unchanged. The ones that do not usually
fail for one of four reasons, and this tool deals with each:

  1. variables the sensor does not define ($S7_SERVER, $BACNET_CLIENT, ...):
     replaced by $HOME_NET (addresses) or any (ports);
  2. Snort preprocessor keywords Suricata spells differently (modbus_func):
     rewritten;
  3. keywords Suricata does not have (modbus_data, sip_method, ...): the rule
     is set aside with the reason, not guessed at;
  4. signature numbers that repeat or collide with other rule sets: every rule
     gets a new sid from --sid-base, and the original is kept in the metadata.

With --limit-seconds, a rule that has no rate limit of its own is given one
alert per source address per window, so an informational rule cannot flood.

Snort 3. A Snort 3 rule that keeps the classic header (addresses and ports) is
converted where the change is mechanical: content options with their modifiers
after commas, "dnp3_obj: group N, var M", single-value cip_class, cip_instance,
cip_attribute and cip_status, and iec104_asdu_func (written as bytes, because
Suricata has no IEC 104 decoder: it then matches only a message that starts its
packet). A rule is set aside when it has no addresses in its header (Snort 3's
service rules), uses a Snort 3 inspector Suricata has no decoder for
(S7CommPlus, MMS, OPC UA, IEC 104 frame types, CIP connection paths), or names
a buffer the Snort 3 way: in Snort 3 "http_uri;" says where the options after
it look, in Suricata the same word says where the content before it looks, so
such a rule would load and look in the wrong place.

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
# Snort 3 options that read what a Snort inspector decoded. Suricata 8 has no
# decoder for these protocols, or no keyword for this part of one.
SNORT3_ONLY = {
    "s7commplus_content": "S7CommPlus", "s7commplus_func": "S7CommPlus", "s7commplus_opcode": "S7CommPlus",
    "mms_data": "MMS (IEC 61850)", "mms_func": "MMS (IEC 61850)",
    "opcua_msg_service": "OPC UA", "opcua_msg_type": "OPC UA", "opcua_node_id": "OPC UA", "opcua_node_namespace_index": "OPC UA",
    "iec104_apci_type": "IEC 104 frame types",
    "cip_conn_path_class": "CIP connection paths", "cip_req": "CIP request or response", "cip_rsp": "CIP request or response",
    "enip_req": "EtherNet/IP request or response", "enip_rsp": "EtherNet/IP request or response",
    "dnp3_data": "reassembled DNP3 data", "regex": "Snort 3 'regex'", "js_data": "Snort 3 buffers", "vba_data": "Snort 3 buffers",
    "ber_data": "Snort 3 'ber_data'", "ber_skip": "Snort 3 'ber_skip'", "bufferlen": "Snort 3 'bufferlen'",
}
# Snort 3 writes a content option's modifiers after commas: content:"abc", depth 4, nocase;
# Options that name a buffer and take no value. Snort 2 and Suricata write them after the content
# they apply to; Snort 3 writes them before ("sticky"), which reads the other way round.
BUFFER_WORDS = {
    "http_uri", "http_raw_uri", "http_header", "http_raw_header", "http_client_body", "http_raw_body", "http_cookie",
    "http_raw_cookie", "http_method", "http_stat_code", "http_stat_msg", "http_version", "http_trailer", "http_raw_trailer",
    "http_true_ip", "http_param", "http_raw_request", "http_raw_status", "http_header_test", "http_trailer_test", "raw_data",
    "sip_header", "sip_body",
}
CONTENT_FOLLOWERS = {"nocase", "fast_pattern", "rawbytes", "offset", "depth", "distance", "within", "isdataat", "startswith", "endswith"}
CONTENT_FLAGS = {"nocase", "fast_pattern", "rawbytes"}
CONTENT_NUMBERS = {"offset", "depth", "distance", "within"}
CIP_SINGLE = {"cip_class": "enip.cip_class", "cip_instance": "enip.cip_instance", "cip_attribute": "enip.cip_attribute",
              "cip_status": "enip.cip_status"}
# IEC 60870-5-104 type identifications, by the names Snort 3's iec104_asdu_func takes.
IEC104_TYPES = {
    "m_sp_na_1": 1, "m_sp_ta_1": 2, "m_dp_na_1": 3, "m_dp_ta_1": 4, "m_st_na_1": 5, "m_st_ta_1": 6, "m_bo_na_1": 7,
    "m_bo_ta_1": 8, "m_me_na_1": 9, "m_me_ta_1": 10, "m_me_nb_1": 11, "m_me_tb_1": 12, "m_me_nc_1": 13, "m_me_tc_1": 14,
    "m_it_na_1": 15, "m_it_ta_1": 16, "m_ep_ta_1": 17, "m_ep_tb_1": 18, "m_ep_tc_1": 19, "m_ps_na_1": 20, "m_me_nd_1": 21,
    "m_sp_tb_1": 30, "m_dp_tb_1": 31, "m_st_tb_1": 32, "m_bo_tb_1": 33, "m_me_td_1": 34, "m_me_te_1": 35, "m_me_tf_1": 36,
    "m_it_tb_1": 37, "m_ep_td_1": 38, "m_ep_te_1": 39, "m_ep_tf_1": 40, "c_sc_na_1": 45, "c_dc_na_1": 46, "c_rc_na_1": 47,
    "c_se_na_1": 48, "c_se_nb_1": 49, "c_se_nc_1": 50, "c_bo_na_1": 51, "c_sc_ta_1": 58, "c_dc_ta_1": 59, "c_rc_ta_1": 60,
    "c_se_ta_1": 61, "c_se_tb_1": 62, "c_se_tc_1": 63, "c_bo_ta_1": 64, "m_ei_na_1": 70, "c_ic_na_1": 100, "c_ci_na_1": 101,
    "c_rd_na_1": 102, "c_cs_na_1": 103, "c_ts_na_1": 104, "c_rp_na_1": 105, "c_cd_na_1": 106, "c_ts_ta_1": 107,
    "p_me_na_1": 110, "p_me_nb_1": 111, "p_me_nc_1": 112, "p_ac_na_1": 113, "f_fr_na_1": 120, "f_sr_na_1": 121,
    "f_sc_na_1": 122, "f_ls_na_1": 123, "f_af_na_1": 124, "f_sg_na_1": 125, "f_dr_ta_1": 126, "f_sc_nb_1": 127,
}
SERVICE_HEADER = re.compile(r"^(alert|drop|sdrop|reject|log|pass|block|rewrite)\s+\w*\s*\(")

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


def split_commas(text):
    """Split on commas that are outside quotes."""
    parts, current, quoted, escaped = [], "", False, False
    for char in text:
        if escaped:
            current, escaped = current + char, False
        elif char == "\\":
            current, escaped = current + char, True
        elif char == '"':
            current, quoted = current + char, not quoted
        elif char == "," and not quoted:
            parts.append(current.strip())
            current = ""
        else:
            current += char
    parts.append(current.strip())
    return parts


def snort3_content(value):
    """content:"abc", depth 4, nocase  ->  (['content:"abc"', 'depth:4', 'nocase'], None), or (None, why not)."""
    pieces = split_commas(value)
    options = [f"content:{pieces[0]}"]
    for piece in pieces[1:]:
        word, _, number = piece.partition(" ")
        word, number = word.strip().lower(), number.strip()
        if word in CONTENT_FLAGS and not number:
            options.append(word)
        elif word in CONTENT_NUMBERS and re.fullmatch(r"-?\d+|[A-Za-z_]\w*", number):
            options.append(f"{word}:{number}")
        else:
            return None, f"content modifier '{piece}' has no Suricata form"
    return options, None


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
        if SERVICE_HEADER.match(line):
            return None, "Snort 3 rule with no addresses in its header (a service rule)", notes
        return None, "not a rule header this tool reads (a broken line)", notes
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
    snort3, buffers, after_content = False, [], False
    for option in split_options(body):
        key, _, value = option.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key in BUFFER_WORDS and not value:
            # after a content (or its modifiers) it is the Snort 2 form; anywhere else it is Snort 3's
            buffers.append((key, after_content))
        if key in ("content", "uricontent", "pcre"):
            after_content = True
        elif key not in CONTENT_FOLLOWERS and key not in BUFFER_WORDS:
            after_content = False
        if key in DROPPED or key in SNORT3_ONLY or (key == "content" and len(split_commas(value)) > 1):
            snort3 = True
        if key in UNSUPPORTED:
            return None, f"uses '{key}', which Suricata does not have", notes
        if key in SNORT3_ONLY:
            return None, f"uses Snort 3's '{key}': Suricata has no decoder or keyword for {SNORT3_ONLY[key]}", notes
        if key == "content" and len(split_commas(value)) > 1:
            converted, problem = snort3_content(value)
            if converted is None:
                return None, problem, notes
            options += converted
            notes.add("Snort 3 content modifiers written as separate options")
            continue
        if key == "dnp3_obj" and "group" in value.lower():
            numbers = re.fullmatch(r"group\s+(\d+)\s*,\s*var\s+(\d+)", value.strip(), re.I)
            if not numbers:
                return None, f"dnp3_obj '{value}' is not 'group N, var M'", notes
            options.append(f"dnp3_obj:{numbers.group(1)},{numbers.group(2)}")
            notes.add("Snort 3 dnp3_obj rewritten as 'dnp3_obj:group,variation'")
            continue
        if key in CIP_SINGLE:
            if not value.isdigit():
                return None, f"{key} '{value}' is a range; only a single value is converted", notes
            options.append(f"{CIP_SINGLE[key]}:{value}")
            notes.add(f"Snort 3 {key} rewritten as '{CIP_SINGLE[key]}'")
            continue
        if key == "iec104_asdu_func":
            number = IEC104_TYPES.get(value.strip().lower())
            if number is None or proto.lower() != "tcp":
                return None, f"iec104_asdu_func '{value}' is not a type this tool knows, or the rule is not a tcp rule", notes
            # Start byte, an information frame (lowest bit of the first control byte clear), the type identification.
            options += ['content:"|68|"', "depth:1", "byte_test:1,!&,1,2", f'content:"|{number:02x}|"', "offset:6", "depth:1"]
            notes.add("Snort 3 iec104_asdu_func written as bytes: matches only a message that starts its packet")
            continue
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
    for word, follows_content in buffers:
        if snort3 or not follows_content:
            return None, (f"names the buffer '{word}' the Snort 3 way (before the content it applies to); "
                          "Suricata would read it the other way round"), notes
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
