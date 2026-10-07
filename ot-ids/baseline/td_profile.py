#!/usr/bin/env python3
# TechDetechtives OT IDS. Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""What else is on the control network: a profile of the traffic that is not industrial.

The baseline program (td_baseline.py) watches the industrial protocols. This
one reports, on request, on everything else the sensor saw in the last day:
the remote desktop session into a controller's network, the machine that sends
the same small request every few minutes around the clock, the connection that
has been open for nineteen hours, the address that is not a private one. It
reads the connection records the sensor already wrote (Zeek's conn records in
OpenSearch) with one search, keeps nothing, changes nothing and raises no
alerts: it prints a report for a person to read.

    td_profile.py                      the last 24 whole hours, as text (--hours 1 to 168)
    td_profile.py --hours 72 --top 25
    td_profile.py --from 2026-10-01T02:00 --to 2026-10-01T09:00    a period in the past (UTC), such as an incident
    td_profile.py --tag incident7      an uploaded capture, by a word of its file name; its period is looked up
    td_profile.py --format markdown --out /data/init/td-baseline/profile.md
    td_profile.py --format csv         every conversation, one per line
    td_profile.py --format json

What it lists:

  other protocols reaching controllers   non-industrial traffic, answered, to an address the baseline knows as a device
  connections opened by controllers      a device that starts conversations of its own
  addresses outside the private ranges   one end is a public address
  longest connections                    1 hour or more, still open or closed
  largest transfers                      by bytes, with the direction
  steady repeaters                       the same conversation at the same rate hour after hour
  addresses that contacted many services one address, many destinations and ports
  attempts nobody answered               the client sent, the server sent nothing back
  services                               each port and protocol: how many servers, how many clients

Where the ideas come from. The measures (time connected in total, the longest
single connection, hours of the day covered, how even the hourly counts are,
how many clients use a service, one address reaching many) are the ones RITA
reports (activecm/rita, GPL-3.0). None of RITA's code is used: RITA needs its
own database and a second copy of the records, and by default drops every
conversation between two internal addresses, which in an isolated plant is all
of them. See ot-ids/docs/LISTED-REPOSITORIES-REVIEW.md.

Which records: the live traffic the sensors saw. A capture file uploaded to
the product is left out unless asked for with --tag or --uploads.

What a period holds: every connection that was open at some time in it. A
connection that began before the period and ended in it is counted whole, with
all its bytes; one that is still open is counted with its totals so far.

A steady repeater is not an alarm. Time synchronisation, monitoring and backup
agents look like this, and so does a program calling home; the report cannot
tell them apart, only make sure a person has seen the list.
"""
import argparse
import csv
import io
import ipaddress
import json
import math
import os
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import td_baseline as base      # noqa: E402  (settings, the OpenSearch client, the list of industrial protocols)

HOUR = 3600
# Ports industrial protocols are registered on, for conversations whose record names no protocol.
INDUSTRIAL_PORTS = {102, 502, 1911, 2222, 2404, 4840, 4911, 5094, 9600, 18245, 20000, 34962, 34963, 34964, 44818, 47808}
TRUE_MARKS = {"true", "t", "1", "yes"}
# sent and received count whole packets; 'answer' is what the server sent as data, and is zero when it
# only refused the connection or never replied.
SUMS = {"sent": "source.bytes", "received": "destination.bytes", "time": "length", "answer": "server.bytes"}
MAXIMA = {"longest": "length", "most_sent": "source.bytes", "most_received": "destination.bytes"}


END_FIELD = "lastPacket"        # the product writes it on every Zeek record: the start time plus the duration


def search_body(settings, start_ms, end_ms, after=None, scope=None):
    """Connection records per hour of their start, client, server, server port, transport and 'still open' mark.

    A record carries the time its connection began, however long ago, so the
    period is matched against the connection's whole life: began before the
    period's end, last seen at or after its start.
    """
    must, must_not = scope if scope is not None else base.scope_clauses("exclude")
    field = settings.time_field
    composite = {"size": settings.page_size, "sources": [
        {"hour": {"date_histogram": {"field": field, "fixed_interval": "1h"}}},
        {"src": {"terms": {"field": "source.ip"}}},
        {"dst": {"terms": {"field": "destination.ip"}}},
        {"port": {"terms": {"field": "destination.port", "missing_bucket": True}}},
        {"transport": {"terms": {"field": "network.transport", "missing_bucket": True}}},
        {"open": {"terms": {"field": "zeek.conn.long", "missing_bucket": True}}},
    ]}
    if after:
        composite["after"] = after
    aggs = {name: {"sum": {"field": source}} for name, source in SUMS.items()}
    aggs.update({name: {"max": {"field": source}} for name, source in MAXIMA.items()})
    aggs["service"] = {"terms": {"field": "network.protocol", "size": 4}}
    return {
        "size": 0,
        "track_total_hits": False,
        "query": {"bool": {"filter": [
            {"range": {field: {"lt": end_ms, "format": "epoch_millis"}}},
            {"range": {END_FIELD: {"gte": start_ms, "format": "epoch_millis"}}},
            {"term": {"event.dataset": "conn"}},
            {"term": {"event.provider": "zeek"}},
            {"exists": {"field": "source.ip"}},
            {"exists": {"field": "destination.ip"}},
        ] + must, "must_not": list(must_not)}},
        "aggs": {"keys": {"composite": composite, "aggs": aggs}},
    }


def number(bucket, name):
    value = (bucket.get(name) or {}).get("value")
    return int(value) if isinstance(value, (int, float)) and math.isfinite(value) else 0


def collect(http, settings, start, end, max_buckets, scope=None):
    """{(client, server, port, transport): conversation} for connections open between start and end (seconds),
    and whether the read was cut short.

    The sensor writes a record when a connection ends, and for a connection
    that stays open one record at 10 minutes, 30 minutes, 1, 12 and 24 hours
    and then daily, each carrying the connection's start time and its totals
    so far (zeek.conn.long). Closed records are added up. The 'so far' records
    of one connection share its start hour with the record written when it
    ends: per start hour only the largest 'so far' record is kept, and it
    counts as a connection still open only when no closed record that began in
    that hour is as long.
    """
    url = (f"{settings.opensearch_url}/{settings.index}/_search"
           "?ignore_unavailable=true&allow_no_indices=true&allow_partial_search_results=false")
    conversations, after, read = {}, None, 0
    while True:
        reply = http.post(url, search_body(settings, start * 1000, end * 1000, after, scope), auth=True)
        shards = reply.get("_shards") or {}
        if reply.get("timed_out") or shards.get("failed"):
            raise ValueError("OpenSearch answered only in part (timed out, or a shard failed)")
        if "aggregations" not in reply:
            if shards.get("total") == 0:
                return conversations, False          # no index yet: a new installation
            raise ValueError("OpenSearch answered without the counts that were asked for")
        keys = reply["aggregations"].get("keys") or {}
        buckets = keys.get("buckets") or []
        for bucket in buckets:
            key = bucket["key"]
            port = key.get("port")
            name = (base.clean(key["src"]), base.clean(key["dst"]), int(port) if isinstance(port, (int, float)) else None,
                    base.clean(key.get("transport") or ""))
            item = conversations.setdefault(name, {
                "count": 0, "sent": 0, "received": 0, "time": 0, "longest": 0, "open": {}, "closed_longest": {},
                "answer": 0, "hours": {}, "seen": set(), "services": {}})
            hour = int(key["hour"]) // 1000 // HOUR
            item["seen"].add(hour)
            item["answer"] += number(bucket, "answer")
            for service in ((bucket.get("service") or {}).get("buckets") or []):
                label = base.clean(service.get("key"))
                item["services"][label] = item["services"].get(label, 0) + int(service.get("doc_count") or 0)
            if str(key.get("open")).strip().lower() in TRUE_MARKS:
                so_far = item["open"].setdefault(hour, [0, 0, 0])
                so_far[0] = max(so_far[0], number(bucket, "longest"))
                so_far[1] = max(so_far[1], number(bucket, "most_sent"))
                so_far[2] = max(so_far[2], number(bucket, "most_received"))
            else:
                count = int(bucket.get("doc_count") or 0)
                item["count"] += count
                item["hours"][hour] = item["hours"].get(hour, 0) + count
                item["sent"] += number(bucket, "sent")
                item["received"] += number(bucket, "received")
                item["time"] += number(bucket, "time")
                item["longest"] = max(item["longest"], number(bucket, "longest"))
                item["closed_longest"][hour] = max(item["closed_longest"].get(hour, 0), number(bucket, "longest"))
        read += len(buckets)
        after = keys.get("after_key")
        if not after or len(buckets) < settings.page_size:
            return conversations, False
        if read >= max_buckets:
            return conversations, True


# --- Working the conversations out ------------------------------------------------------

# Addresses that belong to a site or to one link: private, shared, link-local, loopback, multicast, broadcast.
INSIDE = [ipaddress.ip_network(block) for block in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8", "0.0.0.0/8",
    "224.0.0.0/4", "240.0.0.0/4", "fc00::/7", "fe80::/10", "ff00::/8", "::1/128", "::/128")]


def is_outside(address):
    """True for an address that is none of: private, shared, link-local, loopback, multicast, broadcast."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    mapped = getattr(parsed, "ipv4_mapped", None)
    parsed = mapped or parsed
    return not any(parsed.version == block.version and parsed in block for block in INSIDE)


def is_industrial(services, port):
    names = {name.lower().removesuffix("_tcp").removesuffix("_udp") for name in services}
    if names & set(base.PROTOCOLS):
        return True
    return not names and port in INDUSTRIAL_PORTS


def evenness(counts):
    """1 when every hour has the same count, towards 0 as the hours differ (1 - standard deviation / mean)."""
    if not counts:
        return 0.0
    mean = sum(counts) / len(counts)
    if mean <= 0:
        return 0.0
    deviation = math.sqrt(sum((count - mean) ** 2 for count in counts) / len(counts))
    return max(0.0, 1.0 - deviation / mean)


def roles_from_baseline(folder):
    """{address: 'device' | 'master' | 'master and device'} from the baseline's list, or {} when there is none yet."""
    try:
        with open(os.path.join(folder, "state.json"), encoding="utf-8") as handle:
            hosts = json.load(handle).get("hosts") or {}
    except (OSError, ValueError, AttributeError):
        return {}
    roles = {}
    for address, host in (hosts.items() if isinstance(hosts, dict) else []):
        if not isinstance(host, dict):       # a list this program cannot read: no roles, rather than a failed report
            return {}
        asks, answers = bool(host.get("c")), bool(host.get("s"))
        if asks or answers:
            roles[address] = "master and device" if asks and answers else "master" if asks else "device"
    return roles


def build(conversations, roles, start, end, top=15, many=50, which="live traffic (uploaded captures left out)"):
    """The report as a dictionary: totals and the lists, each already sorted and cut to 'top'."""
    window = max(1, (end - start) // HOUR)
    first_hour = start // HOUR
    rows = []
    for (client, server, port, transport), item in conversations.items():
        # connections still open: per start hour, a 'so far' record longer than any closed record that began then
        still = [so_far for hour, so_far in item["open"].items() if so_far[0] > item["closed_longest"].get(hour, 0)]
        services = sorted(item["services"], key=lambda name: (-item["services"][name], name))
        sent = item["sent"] + sum(so_far[1] for so_far in still)
        received = item["received"] + sum(so_far[2] for so_far in still)
        counts = [count for hour, count in item["hours"].items() if hour >= first_hour]      # connections begun in the period
        rows.append({
            "client": client, "server": server, "port": port, "transport": transport, "service": ",".join(services[:3]),
            "industrial": is_industrial(services, port), "connections": item["count"], "sent": sent, "received": received,
            "bytes": sent + received, "connected_seconds": (item["time"] + sum(so_far[0] for so_far in still)) // 1000,
            "longest_seconds": max([item["longest"]] + [so_far[0] for so_far in still]) // 1000, "still_open": bool(still),
            "hours_with_new_connections": len(counts),
            "evenness": round(evenness(counts), 2) if len(counts) >= 2 else 0.0,
            "client_role": roles.get(client, ""), "server_role": roles.get(server, ""),
            "outside": is_outside(client) or is_outside(server), "answered": item["answer"] > 0,
            "records": item["count"] + len(still),
        })
    others = [row for row in rows if not row["industrial"]]

    def best(items, key, limit=top):
        return sorted(items, key=key)[:limit]

    by_size = lambda row: (-row["bytes"], row["client"], row["server"], row["port"] or 0)                     # noqa: E731
    reaching = best([row for row in others if "device" in row["server_role"] and row["answered"]], by_size)
    opened = best([row for row in others if row["client_role"] == "device"], by_size)
    outside = best([row for row in rows if row["outside"]], by_size)
    longest = best([row for row in rows if row["longest_seconds"] >= HOUR],
                   lambda row: (-row["longest_seconds"], row["client"], row["server"], row["port"] or 0))
    largest = best([row for row in others if row["bytes"] > 0], by_size)
    steady = best([row for row in others
                   if window >= 4 and row["hours_with_new_connections"] >= math.ceil(0.75 * window) and row["evenness"] >= 0.6
                   and row["connections"] >= row["hours_with_new_connections"]],
                  lambda row: (-row["hours_with_new_connections"], -row["evenness"], row["client"], row["server"], row["port"] or 0))

    reach = {}
    for row in rows:
        entry = reach.setdefault(row["client"], [set(), set()])
        entry[0].add(row["server"])
        entry[1].add((row["server"], row["port"], row["transport"]))
    sweepers = best([{"client": client, "servers": len(servers), "services": len(services), "client_role": roles.get(client, "")}
                     for client, (servers, services) in reach.items() if len(services) >= many],
                    lambda entry: (-entry["services"], entry["client"]))

    silent = {}
    for row in rows:
        if not row["answered"]:
            entry = silent.setdefault(row["client"], [set(), set(), 0])
            entry[0].add(row["server"])
            entry[1].add((row["server"], row["port"], row["transport"]))
            entry[2] += row["records"]
    unanswered = best([{"client": client, "servers": len(servers), "services": len(services), "attempts": attempts,
                        "client_role": roles.get(client, "")} for client, (servers, services, attempts) in silent.items()],
                      lambda entry: (-entry["services"], -entry["attempts"], entry["client"]))

    grouped = {}
    for row in others:
        if not row["answered"]:
            continue
        entry = grouped.setdefault((row["port"], row["transport"], row["service"].split(",")[0]),
                                   {"servers": set(), "clients": set(), "connections": 0, "bytes": 0})
        entry["servers"].add(row["server"])
        entry["clients"].add(row["client"])
        entry["connections"] += row["connections"]
        entry["bytes"] += row["bytes"]
    services = best([{"port": port, "transport": transport, "service": service, "servers": len(entry["servers"]),
                      "clients": len(entry["clients"]), "connections": entry["connections"], "bytes": entry["bytes"],
                      "only_server": sorted(entry["servers"])[0] if len(entry["servers"]) == 1 else ""}
                     for (port, transport, service), entry in grouped.items()],
                    lambda entry: (-entry["clients"], -entry["bytes"], entry["port"] or 0, entry["transport"], entry["service"]), top * 2)

    addresses = {row["client"] for row in rows} | {row["server"] for row in rows}
    return {
        "from": start, "to": end, "hours": window, "records": which,
        "totals": {"conversations": len(rows), "industrial": len(rows) - len(others), "other": len(others),
                   "addresses": len(addresses), "connections": sum(row["connections"] for row in rows),
                   "bytes": sum(row["bytes"] for row in rows), "known_to_baseline": len(roles)},
        "reaching_controllers": reaching, "opened_by_controllers": opened, "outside": outside, "longest": longest,
        "largest": largest, "steady": steady, "many_services": sweepers, "unanswered": unanswered, "services": services, "all": rows,
    }


# --- Writing it down ----------------------------------------------------------------------

def size(count):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if count < 1024 or unit == "TB":
            return f"{count:.0f} {unit}" if unit == "B" else f"{count:.1f} {unit}"
        count /= 1024
    return str(count)


def span(seconds):
    hours, minutes = seconds // HOUR, seconds % HOUR // 60
    return f"{hours} h {minutes:02d} min" if hours else f"{minutes} min"


def stamp(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def who(address, role):
    return f"{address} ({role})" if role else address


def what(row):
    port = "" if row["port"] is None else str(row["port"])
    label = "/".join(part for part in (port, row["transport"]) if part) or "-"
    return f"{label} {row['service']}".strip()


def conversation_table(rows, extra):
    """Header and lines for a list of conversations; 'extra' picks the last columns."""
    columns = {"size": ("Bytes (sent / received)", lambda row: f"{size(row['bytes'])} ({size(row['sent'])} / {size(row['received'])})"),
               "count": ("Connections", lambda row: str(row["connections"])),
               "longest": ("Longest", lambda row: span(row["longest_seconds"]) + (", still open" if row["still_open"] else "")),
               "connected": ("Connected in total", lambda row: span(row["connected_seconds"])),
               "hours": ("Hours with new connections", lambda row: str(row["hours_with_new_connections"])),
               "even": ("Evenness", lambda row: f"{row['evenness']:.2f}"),
               "answered": ("Answered", lambda row: "yes" if row["answered"] else "no")}
    header = ["Client", "Server", "Port and protocol"] + [columns[name][0] for name in extra]
    lines = [[who(row["client"], row["client_role"]), who(row["server"], row["server_role"]), what(row)]
             + [columns[name][1](row) for name in extra] for row in rows]
    return header, lines


def sections(report):
    """[(title, note, header, lines)] in the order they are printed."""
    out = []

    def add(title, note, rows, extra):
        header, lines = conversation_table(rows, extra)
        out.append((title, note, header, lines))

    add("Other protocols reaching controllers",
        "Traffic that is not an industrial protocol, answered by an address the baseline knows as a device. Engineering and remote access show here.",
        report["reaching_controllers"], ("size", "count", "longest"))
    add("Connections opened by controllers",
        "A device that starts conversations of its own. Time and name lookups are usual; little else is.",
        report["opened_by_controllers"], ("size", "count", "answered"))
    add("Addresses outside the private ranges",
        "One end is a public address. In an isolated network there should be none.",
        report["outside"], ("size", "count", "longest", "answered"))
    add("Longest connections",
        "One connection open for an hour or more, industrial ones included.",
        report["longest"], ("longest", "connected", "size"))
    add("Largest transfers",
        "By bytes, industrial protocols left out.",
        report["largest"], ("size", "count"))
    add("Steady repeaters",
        "New connections in at least three hours out of four, at an even rate (needs a period of four hours or more). Time "
        "synchronisation, monitoring and backup agents look like this; so does a program calling home.",
        report["steady"], ("hours", "even", "count", "answered", "size"))
    out.append(("Addresses that contacted many services",
                "One address, many destinations and ports: an inventory or monitoring tool, or a scan.",
                ["Client", "Servers", "Server ports"],
                [[who(entry["client"], entry["client_role"]), str(entry["servers"]), str(entry["services"])] for entry in report["many_services"]]))
    out.append(("Attempts nobody answered",
                "The client sent and the server sent no data back: refused, or not there. A scan looks like this; so does a program "
                "calling a server it cannot reach. One-way protocols (syslog, SNMP traps) show here too.",
                ["Client", "Servers", "Server ports", "Attempts"],
                [[who(entry["client"], entry["client_role"]), str(entry["servers"]), str(entry["services"]), str(entry["attempts"])]
                 for entry in report["unanswered"]]))
    out.append(("Services",
                "Each port and protocol that is not industrial and was answered. A service only one address offers to one or two "
                "clients is worth a look.",
                ["Port and protocol", "Servers", "Clients", "Connections", "Bytes", "Only server"],
                [[what(entry), str(entry["servers"]), str(entry["clients"]), str(entry["connections"]), size(entry["bytes"]), entry["only_server"]]
                 for entry in report["services"]]))
    return out


def intro(report, cut_short):
    totals = report["totals"]
    lines = [f"Traffic profile, {stamp(report['from'])} to {stamp(report['to'])} ({report['hours']} hours)",
             f"Records: {report['records']}.",
             f"{totals['conversations']} conversations between {totals['addresses']} addresses: {totals['industrial']} industrial "
             f"(left to the baseline), {totals['other']} other. {totals['connections']} connections, {size(totals['bytes'])}."]
    if not totals["conversations"]:
        lines.append("No connection records in this period. Check that the sensor is capturing (the product's Connections dashboard).")
    if totals["known_to_baseline"]:
        lines.append(f"Masters and devices are named from the baseline's list ({totals['known_to_baseline']} addresses).")
    else:
        lines.append("The baseline has no list yet, so no address is named as a master or a device and the two controller lists are empty.")
    if cut_short:
        lines.append("THE READ WAS CUT SHORT: there were more records than one report takes. Use fewer hours for a complete one.")
    return lines


def render_text(report, cut_short):
    out = intro(report, cut_short)
    for title, note, header, lines in sections(report):
        out += ["", title, "  " + note]
        if not lines:
            out.append("  none")
            continue
        widths = [max(len(str(row[index])) for row in [header] + lines) for index in range(len(header))]
        for row in [header] + lines:
            out.append("  " + "  ".join(str(cell).ljust(width) for cell, width in zip(row, widths)).rstrip())
    return "\n".join(out) + "\n"


def render_markdown(report, cut_short):
    head = intro(report, cut_short)
    out = [f"# {head[0]}", ""] + head[1:]
    for title, note, header, lines in sections(report):
        out += ["", f"## {title}", "", note, ""]
        if not lines:
            out.append("None.")
            continue
        out += ["| " + " | ".join(header) + " |", "| " + " | ".join("---" for _ in header) + " |"]
        out += ["| " + " | ".join(str(cell).replace("|", "/") for cell in row) + " |" for row in lines]
    return "\n".join(out) + "\n"


def render_csv(report):
    fields = ["client", "client_role", "server", "server_role", "port", "transport", "service", "industrial", "outside",
              "answered", "connections", "sent", "received", "bytes", "connected_seconds", "longest_seconds", "still_open",
              "hours_with_new_connections", "evenness"]
    handle = io.StringIO()
    writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for row in sorted(report["all"], key=lambda row: (row["client"], row["server"], row["port"] or 0, row["transport"])):
        writer.writerow({name: row[name] for name in fields})
    return handle.getvalue()


def main(argv=None, now=None, environ=os.environ):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--hours", type=int, default=24, help="how many whole hours back to read (1 to 168; default 24)")
    parser.add_argument("--from", dest="start", help="start of a period in the past, UTC, such as 2026-10-01T02:00 (with --to, or --hours long)")
    parser.add_argument("--to", dest="end", help="end of that period, UTC")
    parser.add_argument("--tag", help="only records carrying this tag: an uploaded capture is tagged with the words of its file name")
    parser.add_argument("--uploads", choices=("exclude", "include", "only"),
                        help="uploaded captures: leave out (default), count with the live traffic, or nothing else (default with --tag: include)")
    parser.add_argument("--top", type=int, default=15, help="how many lines each list shows (default 15)")
    parser.add_argument("--many", type=int, default=50, help="how many destination ports make 'many services' (default 50)")
    parser.add_argument("--format", choices=("text", "markdown", "json", "csv"), default="text")
    parser.add_argument("--out", help="write to this file instead of the screen")
    args = parser.parse_args(argv)
    if not 1 <= args.hours <= 168 or args.top < 1 or args.many < 2:
        parser.error("--hours takes 1 to 168, --top 1 or more, --many 2 or more")

    settings = base.Settings(environ)
    now = int(time.time() if now is None else now)
    uploads = args.uploads or ("include" if args.tag else "exclude")
    scope = base.scope_clauses(uploads, args.tag)
    which = {"exclude": "live traffic (uploaded captures left out)", "include": "live traffic and uploaded captures",
             "only": "uploaded captures only"}[uploads] + (f", tagged {base.clean(args.tag)}" if args.tag else "")
    http = base.Http(settings)
    max_buckets = base.env_int(environ, "TD_PROFILE_MAX_BUCKETS", 100000)     # each is a few hundred bytes of memory here
    if args.end and not args.start:
        parser.error("--to needs --from")
    try:
        asked_start = base.parse_time(args.start) if args.start else None
        asked_end = base.parse_time(args.end) if args.end else None
    except ValueError as error:
        parser.error(str(error))
    try:
        if asked_start is not None:
            start = asked_start // HOUR * HOUR
            end = -(-asked_end // HOUR) * HOUR if asked_end is not None else start + args.hours * HOUR
        elif args.tag:
            # An uploaded capture's records carry the times in the capture, whenever that was: look them up.
            span = base.time_span(http, settings, scope)
            if span is None:
                where = {"exclude": "No live record carries", "only": "No uploaded record carries"}.get(uploads, "No record carries")
                print(f"{where} the tag '{base.clean(args.tag)}'"
                      + (" (uploaded captures were left out: --uploads include)." if uploads == "exclude" else ".")
                      + " Tags are the words of the capture's file name (numbers and 'pcap' are not tags; capitals count); "
                      "td-replay list shows them.", file=sys.stderr)
                return 1
            start, end = span[0] // HOUR * HOUR, -(-(span[1] + 1) // HOUR) * HOUR
        else:
            end = (now - settings.lag_minutes * 60) // HOUR * HOUR
            start = end - args.hours * HOUR
        if not start < end or end - start > 168 * HOUR:
            print(f"The period {stamp(start)} to {stamp(end)} is not between one hour and seven days long. "
                  "Give a shorter one with --from and --to.", file=sys.stderr)
            return 1
        conversations, cut_short = collect(http, settings, start, end, max_buckets, scope)
    except base.NETWORK_ERRORS as error:
        print(f"The connection records could not be read from OpenSearch: {base.clean(error)}", file=sys.stderr)
        return 1
    report = build(conversations, roles_from_baseline(settings.folder), start, end, args.top, args.many, which)
    if args.format == "json":
        report["cut_short"] = cut_short
        text = json.dumps(report, indent=1, sort_keys=True) + "\n"
    elif args.format == "csv":
        text = render_csv(report)
    elif args.format == "markdown":
        text = render_markdown(report, cut_short)
    else:
        text = render_text(report, cut_short)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
        print(f"written to {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
