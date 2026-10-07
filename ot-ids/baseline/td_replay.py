#!/usr/bin/env python3
# TechDetechtives OT IDS. Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Replay an incident: what the sensor's engines made of a capture, or of a period, in order.

To replay an incident on this appliance is to hand its packets to the engines
again and read what they say. The product does the first half: a capture file
given to it (the upload page, or a file exported from Arkime for the hours in
question) goes through Zeek with the industrial decoders, Suricata with every
rule now installed, Arkime, and the file scanner, and the records are stored at
the times in the capture, tagged with the words of the file's name. This
program does the second half. It reads those records, changes nothing, and
prints one report:

    td_replay.py list                       the captures that were uploaded, by tag, with when their traffic took place
    td_replay.py report --tag incident7     one uploaded capture
    td_replay.py report --from 2026-10-01T02:00 --to 2026-10-01T09:00     a period of live traffic (UTC)
    td_replay.py report --tag incident7 --format markdown --out /data/init/td-baseline/incident7.md

What the report holds:

  the period and what was recorded     records by kind
  the course of events                 ATT&CK tactics in the order they first appeared, with the techniques
  detections in order                  rule alerts, Zeek notices, signature and intelligence matches, file-scan hits:
                                       first seen, how often, between which addresses, which technique
  against the baseline                 what in this traffic the plant's normal traffic never contained: an address
                                       that was never a master, a device never spoken to, an operation never used
  other traffic                        non-industrial traffic reaching controllers, public addresses, the largest
                                       transfers (the traffic profile, cut short; td_profile.py has the whole)

A period of live traffic leaves uploaded captures out; a tag takes the records
that carry it, live or uploaded. The baseline is only read: replaying a capture
never teaches it anything and never raises its alerts.

Two things the product does that this program has to know (read in its source):
a file-scan hit is stored under two kinds at once and may name several rules,
and it is not marked as coming from an uploaded capture, though it carries the
capture's tags; an indicator match has no rule name, only the indicator and the
list it came from.

Rules change. A capture replayed after a rule update is judged by the rules of
today, so the same incident can show detections it did not raise when it
happened. That is the use of replaying one.
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import td_baseline as base      # noqa: E402
import td_profile as profile    # noqa: E402

HOUR = 3600
MAX_HOURS = 168
DETECTION_SOURCES = (("dataset", "event.dataset", False), ("provider", "event.provider", True), ("rule", "rule.name", True),
                     ("src", "source.ip", True), ("dst", "destination.ip", True))
# name in the report: (field, how many values to read)
DETECTION_TERMS = {"technique": ("threat.technique.id", 3), "technique_name": ("threat.technique.name", 3),
                   "tactic": ("threat.tactic.name", 3), "reason": ("event.reason", 3),
                   "indicator": ("threat.indicator.name", 3), "indicator_source": ("threat.indicator.provider", 3), "tags": ("tags", 8)}
# What each kind of record is called in the report. Zeek's "weird" records (odd packets) are counted, not listed.
KINDS = {"alert": "rule alert", "notice": "Zeek notice", "signatures": "Zeek signature", "intel": "indicator match",
         "alerting": "monitor or baseline alert", "filescan": "file-scan hit"}
# Tags the product puts on records by itself. A capture's own tags are the words of its file name.
PRODUCT_TAGS = frozenset(("pcapng", "pcap", "cap", "proto_parse_failed", "client_stream_failed", "server_stream_failed", "netbox",
                          "cross_segment"))


def search(http, settings, body):
    url = (f"{settings.opensearch_url}/{settings.index}/_search"
           "?ignore_unavailable=true&allow_no_indices=true&allow_partial_search_results=false")
    reply = http.post(url, body, auth=True)
    if reply.get("timed_out") or (reply.get("_shards") or {}).get("failed"):
        raise ValueError("OpenSearch answered only in part (timed out, or a shard failed)")
    return reply.get("aggregations") or {}


def in_period(settings, start, end):
    return {"range": {settings.time_field: {"gte": start * 1000, "lt": end * 1000, "format": "epoch_millis"}}}


def list_captures(http, settings):
    """[{tag, records, first, last, own}] for the tags on the records of uploaded captures, newest traffic first.

    'own' is False for a tag that is not a word of a file name: one the product adds by itself, or one found only on
    rule alerts (Suricata rules can carry tags of their own, which the product copies onto the alert).
    """
    field = settings.time_field
    body = {"size": 0, "track_total_hits": False, "query": {"bool": {"filter": [base.UPLOADED]}},
            "aggs": {"tags": {"terms": {"field": "tags", "size": 300, "order": {"last": "desc"}},
                              "aggs": {"first": {"min": {"field": field}}, "last": {"max": {"field": field}},
                                       "kinds": {"terms": {"field": "event.dataset", "size": 3}}}}}}
    found = []
    for bucket in ((search(http, settings, body).get("tags") or {}).get("buckets") or []):
        first, last = (bucket.get("first") or {}).get("value"), (bucket.get("last") or {}).get("value")
        kinds = [str(kind.get("key")) for kind in ((bucket.get("kinds") or {}).get("buckets") or [])]
        if first is not None and last is not None:
            tag = base.clean(bucket.get("key"))
            found.append({"tag": tag, "records": int(bucket.get("doc_count") or 0), "first": int(first) // 1000, "last": int(last) // 1000,
                          "own": tag.lower() not in PRODUCT_TAGS and not tag.startswith("_") and kinds != ["alert"]})
    return found


def overview(http, settings, start, end, scope):
    """({kind of record: count}, how many records) for the period and scope.

    The counts by kind can add up to more than the records: the product stores a file-scan hit under two kinds.
    """
    must, must_not = scope
    body = {"size": 0, "track_total_hits": False,
            "query": {"bool": {"filter": [in_period(settings, start, end)] + must, "must_not": list(must_not)}},
            "aggs": {"datasets": {"terms": {"field": "event.dataset", "size": 100}},
                     "total": {"value_count": {"field": settings.time_field}}}}
    found = search(http, settings, body)
    counts = {base.clean(bucket.get("key")): int(bucket.get("doc_count") or 0)
              for bucket in ((found.get("datasets") or {}).get("buckets") or [])}
    total = (found.get("total") or {}).get("value")
    return counts, int(total) if isinstance(total, (int, float)) else sum(counts.values())


def detections_body(settings, start, end, scope, after=None):
    must, must_not = scope
    field = settings.time_field
    composite = {"size": settings.page_size, "sources": [
        {name: {"terms": dict({"field": source}, **({"missing_bucket": True} if optional else {}))}}
        for name, source, optional in DETECTION_SOURCES]}
    if after:
        composite["after"] = after
    aggs = {"first": {"min": {"field": field}}, "last": {"max": {"field": field}}, "severity": {"max": {"field": "event.severity"}}}
    aggs.update({name: {"terms": {"field": source, "size": size}} for name, (source, size) in DETECTION_TERMS.items()})
    return {
        "size": 0,
        "track_total_hits": False,
        "query": {"bool": {
            "filter": [in_period(settings, start, end),
                       {"bool": {"should": [{"term": {"event.kind": "alert"}}, {"term": {"event.dataset": "intel"}}],
                                 "minimum_should_match": 1}}] + must,
            "must_not": [{"term": {"event.dataset": "weird"}}] + list(must_not),
        }},
        "aggs": {"keys": {"composite": composite, "aggs": aggs}},
    }


def detections(http, settings, start, end, scope, limit=20000):
    """One entry per kind, rule and pair of addresses, in order of first appearance; and whether the read was cut short."""
    merged, after = {}, None
    lists = ("techniques", "technique_names", "tactics", "reasons", "indicators", "indicator_sources", "tags")
    while True:
        keys = search(http, settings, detections_body(settings, start, end, scope, after)).get("keys") or {}
        buckets = keys.get("buckets") or []
        for bucket in buckets:
            key = bucket["key"]

            def names(which):
                return [base.clean(item.get("key")) for item in ((bucket.get(which) or {}).get("buckets") or [])]

            first = (bucket.get("first") or {}).get("value")
            last = (bucket.get("last") or {}).get("value")
            severity = (bucket.get("severity") or {}).get("value")
            kind, provider = base.clean(key.get("dataset")), base.clean(key.get("provider") or "")
            if provider == "filescan":
                # The product stores one scan hit under two kinds ("files" and "strelka"), so it comes back twice: one event.
                kind = "filescan"
            entry = {
                "kind": kind, "provider": provider,
                "rule": base.clean(key.get("rule") or ""), "source": base.clean(key.get("src") or ""),
                "destination": base.clean(key.get("dst") or ""), "count": int(bucket.get("doc_count") or 0),
                "first": int(first) // 1000 if first is not None else start,
                "last": int(last) // 1000 if last is not None else start,
                "severity": int(severity) if isinstance(severity, (int, float)) else None,
                "techniques": names("technique"), "technique_names": names("technique_name"), "tactics": names("tactic"),
                "reasons": names("reason"), "indicators": names("indicator"), "indicator_sources": names("indicator_source"),
                "tags": [tag for tag in names("tags") if tag.lower() not in PRODUCT_TAGS and not tag.startswith("_")],
            }
            ident = (entry["kind"], entry["provider"], entry["rule"], entry["source"], entry["destination"])
            seen = merged.get(ident)
            if seen is None:
                merged[ident] = entry
                continue
            seen["count"] = max(seen["count"], entry["count"])           # the same records, seen under another kind
            seen["first"], seen["last"] = min(seen["first"], entry["first"]), max(seen["last"], entry["last"])
            if entry["severity"] is not None:
                seen["severity"] = max(seen["severity"] or 0, entry["severity"])
            for name in lists:
                seen[name].extend(value for value in entry[name] if value not in seen[name])
        after = keys.get("after_key")
        if not after or len(buckets) < settings.page_size:
            cut = False
            break
        if len(merged) >= limit:
            cut = True
            break
    found = list(merged.values())
    found.sort(key=lambda item: (item["first"], -(item["severity"] or 0), item["kind"], item["rule"], item["source"], item["destination"]))
    return found, cut


def course(found):
    """The ATT&CK tactics in the order they first appeared: [{tactic, first, techniques, sources}]."""
    steps = {}
    for item in found:
        for tactic in item["tactics"]:
            step = steps.setdefault(tactic, {"tactic": tactic, "first": item["first"], "techniques": [], "sources": []})
            step["first"] = min(step["first"], item["first"])
            # an event under two tactics does not say which of its techniques belongs to which
            for technique in (item["techniques"] if len(item["tactics"]) == 1 else []):
                if technique not in step["techniques"]:
                    step["techniques"].append(technique)
            if item["source"] and item["source"] not in step["sources"]:
                step["sources"].append(item["source"])
    return sorted(steps.values(), key=lambda step: (step["first"], step["tactic"]))


def read_baseline(folder):
    """((hosts, pairs, operations, still learning), None) from the baseline's list; or (None, "none") when there is
    no list yet, (None, "unreadable") when the file is there and is not a list this program can use."""
    try:
        with open(os.path.join(folder, "state.json"), encoding="utf-8") as handle:
            state = json.load(handle)
    except FileNotFoundError:
        return None, "none"
    except (OSError, ValueError):
        return None, "unreadable"
    hosts, pairs, operations = [state.get(name) for name in ("hosts", "pairs", "ops")] if isinstance(state, dict) else [None] * 3
    if not (isinstance(hosts, dict) and isinstance(pairs, dict) and isinstance(operations, dict)
            and all(isinstance(host, dict) and isinstance(host.get("c", []), list) and isinstance(host.get("s", []), list)
                    for host in hosts.values())):
        return None, "unreadable"
    if not hosts:
        return None, "none"
    return (hosts, pairs, operations, state.get("learn_until") is None), None


def against_baseline(records, known):
    """What the industrial traffic of the period holds that the baseline's list does not.

    records: {(client, server, protocol, operation): [count, first ms, last ms, asked]}.
    Returns entries, one per master, each with what is new about it.
    """
    hosts, pairs, operations, _ = known
    masters = {}
    for (client, server, protocol, action), (count, first, _, asked) in sorted(records.items()):
        entry = masters.setdefault(client, {"client": client, "first": first // 1000, "unknown": client not in hosts,
                                            "new_roles": set(), "new_devices": set(), "new_services": set(), "new_pairs": set(),
                                            "new_operations": {}, "control": False})
        entry["first"] = min(entry["first"], first // 1000)
        if protocol not in (hosts.get(client) or {}).get("c", []):
            entry["new_roles"].add(protocol)
        if server not in hosts:
            entry["new_devices"].add(server)
        elif protocol not in hosts[server].get("s", []):
            entry["new_services"].add(f"{server} ({protocol})")
        pair = f"{client}|{server}|{protocol}"
        if pair not in pairs:
            entry["new_pairs"].add(f"{server} ({protocol})")
        if asked and f"{pair}|{action}" not in operations:
            label = f"{action or 'an unnamed operation'} on {server} ({protocol})"
            entry["new_operations"][label] = entry["new_operations"].get(label, 0) + count
            entry["control"] = entry["control"] or bool(base.CONTROL_WORDS.search(action or ""))
    out = []
    for entry in masters.values():
        if not (entry["unknown"] or entry["new_roles"] or entry["new_devices"] or entry["new_services"] or entry["new_pairs"]
                or entry["new_operations"]):
            continue
        entry.update({name: sorted(entry[name]) for name in ("new_roles", "new_devices", "new_services", "new_pairs")})
        entry["new_operations"] = [f"{label}, {'once' if count == 1 else f'{count} times'}"
                                   for label, count in sorted(entry["new_operations"].items())]
        out.append(entry)
    # an address never seen first, then those that sent something that changes the process, then by time
    out.sort(key=lambda entry: (not entry["unknown"], not entry["control"], entry["first"], entry["client"]))
    return out


def sentence(entry):
    client = entry["client"]
    parts = []
    if entry["unknown"]:
        parts.append(f"{client} is not in the baseline's list at all")
        if entry["new_roles"]:
            parts.append(f"it acted as a master by {', '.join(entry['new_roles'])}")
    elif entry["new_roles"]:
        parts.append(f"{client} is known, but never as a master by {', '.join(entry['new_roles'])}")
    else:
        parts.append(f"{client} is a known master")
    if entry["new_devices"]:
        parts.append(f"it talked to addresses the list does not hold: {', '.join(entry['new_devices'][:8])}")
    if entry["new_services"]:
        parts.append(f"to known addresses by a protocol they never answered: {', '.join(entry['new_services'][:8])}")
    known_new_pairs = [pair for pair in entry["new_pairs"] if pair.split(" ")[0] not in entry["new_devices"]]
    if known_new_pairs and not entry["unknown"]:
        parts.append(f"it never talked before to: {', '.join(known_new_pairs[:8])}")
    if entry["new_operations"]:
        parts.append(f"operations never used there before: {'; '.join(entry['new_operations'][:10])}")
    # a sentence that starts with the address keeps it as it is (an IPv6 address has letters)
    return ". ".join(part if part.startswith(client) else part[0].upper() + part[1:] for part in parts) + "."


# --- The report -----------------------------------------------------------------------------

def gather(http, settings, start, end, scope, which, environ=os.environ, uploads="include", tag=None):
    counts, total = overview(http, settings, start, end, scope)
    found, cut = detections(http, settings, start, end, scope)
    known, problem = read_baseline(settings.folder)
    novel = None
    if known is not None:
        hours = base.collect(http, settings, start, end, by_hour=False, scope=scope)
        merged = {}
        for records in hours.values():
            merged.update(records)
        novel = against_baseline(merged, known)
    conversations, traffic_cut = profile.collect(http, settings, start, end, base.env_int(environ, "TD_PROFILE_MAX_BUCKETS", 100000), scope)
    traffic = profile.build(conversations, profile.roles_from_baseline(settings.folder), start, end, top=5, which=which)
    return {
        "from": start, "to": end, "records": which, "uploads": uploads, "tag": tag, "counts": counts, "total": total,
        "detections": found, "detections_cut_short": cut,
        "course": course(found), "baseline_known": known is not None, "baseline_problem": problem,
        "baseline_learning": bool(known and known[3]),
        "against_baseline": novel, "traffic": {name: traffic[name] for name in ("totals", "reaching_controllers", "outside", "largest")},
        "traffic_cut_short": traffic_cut,
    }


def clock(seconds, start):
    """Time of day, with the date when the report's period is longer than a day."""
    form = "%H:%M:%S"
    return time.strftime("%Y-%m-%d " + form if seconds - start >= 86400 or seconds < start else form, time.gmtime(seconds))


def detection_line(item, start, show_tags=False):
    kind = KINDS.get(item["kind"], item["kind"])
    who = " -> ".join(part for part in (item["source"], item["destination"]) if part) or "no address"
    technique = ""
    if len(item["techniques"]) == 1 and len(item["technique_names"]) == 1:
        technique = f"  [{item['techniques'][0]} {item['technique_names'][0].replace('_', ' ')}]"
    elif item["techniques"]:
        technique = "  [" + ", ".join(item["techniques"]) + "]"       # several: the names come in an order of their own
    name = item["rule"] or "; ".join(item["reasons"]) or "(no name)"
    if item["rule"] and item["reasons"] and item["kind"] == "alerting":
        name = f"{item['rule']}: {'; '.join(item['reasons'])}"
    if item["kind"] == "intel" and not item["rule"]:
        # the product gives an indicator match no rule name: the indicator, and the list it is on
        name = ", ".join(item.get("indicators") or []) or "(indicator not recorded)"
        if item.get("indicator_sources"):
            name += f" (on the list: {', '.join(item['indicator_sources'])})"
    severity = "" if item["severity"] is None else f"severity {item['severity']}, "
    times = f"{item['count']} times, last {clock(item['last'], start)}" if item["count"] > 1 else "once"
    tags = f"; tagged {', '.join(item['tags'])}" if show_tags and item["kind"] == "filescan" and item.get("tags") else ""
    return f"{clock(item['first'], start)}  {kind}: {name}  ({who}; {severity}{times}{tags}){technique}"


def for_markdown(text):
    """Text from records (a rule's name, a tag) must not turn into a link, an image or markup in the Markdown report."""
    for mark, safe in (("\\", "\\\\"), ("<", "&lt;"), ("[", "\\["), ("]", "\\]"), ("`", "\\`"), ("*", "\\*")):
        text = text.replace(mark, safe)
    return text


def render(report, top, markdown=False):
    start, end = report["from"], report["to"]
    title = f"Incident replay, {profile.stamp(start)} to {profile.stamp(end)}"
    out = [("# " if markdown else "") + title, ""] if markdown else [title]

    def heading(text):
        out.extend(["", ("## " if markdown else "") + text] + ([""] if markdown else []))

    def item(text):
        out.append("- " + for_markdown(text) if markdown else "  " + text)

    out.append(f"Records: {for_markdown(report['records']) if markdown else report['records']}. Times are UTC.")
    counts = report["counts"]
    if not counts:
        out.append("No records in this period. For an uploaded capture, give it a few minutes after the upload, and check the tag "
                   "with 'list'.")
        return "\n".join(out) + "\n"
    listed = sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))
    kinds = ", ".join(f"{name} {count}" for name, count in listed[:14])
    out.append(f"{report.get('total', sum(counts.values()))} records: " + (for_markdown(kinds) if markdown else kinds)
               + (f", and {len(listed) - 14} more kinds" if len(listed) > 14 else "") + ".")

    heading("The course of events")
    if report["course"]:
        for step in report["course"]:
            item(f"{clock(step['first'], start)}  {step['tactic'].replace('_', ' ')}"
                 + (f" ({', '.join(step['techniques'][:6])})" if step["techniques"] else "")
                 + (f", from {', '.join(step['sources'][:4])}" if step["sources"] else ""))
    else:
        item("No detection in this period names an ATT&CK tactic.")

    found = report["detections"]
    heading(f"Detections in order ({len(found)} kinds of event between pairs of addresses)")
    if not found:
        item("None. The engines raised nothing on this traffic with the rules now installed.")
    for entry in found[:top]:
        item(detection_line(entry, start, show_tags=not report.get("tag")))
    if len(found) > top:
        item(f"... and {len(found) - top} more (--top {len(found)} shows all; --format json has every one).")
    if report["detections_cut_short"]:
        item("THE LIST WAS CUT SHORT: more detections than one report reads. Use a shorter period.")
    # The product does not mark a file-scan hit as coming from an uploaded capture; it does give it the capture's tags.
    if report.get("uploads") == "only":
        item("File-scan hits are not listed with --uploads only: the product does not mark them as uploaded. Use --tag.")
    elif report.get("uploads") == "exclude" and any(entry["kind"] == "filescan" for entry in found):
        item("File-scan hits are listed whether their file came from live traffic or from an uploaded capture: the product "
             "does not mark them. One that carries a capture's tag came from that capture.")
    if counts.get("weird"):
        item(f"Not listed: {counts['weird']} 'weird' records (packets Zeek found odd). See the product's Zeek Weird dashboard.")

    heading("Against the baseline: what this traffic holds that the plant's normal traffic never did")
    novel = report["against_baseline"]
    if report.get("baseline_problem") == "unreadable":
        item("The baseline's list (state.json) is there but could not be read as a list, so there is nothing to compare with. "
             "td-baseline shows its state.")
    elif not report["baseline_known"]:
        item("The baseline has no list yet (td-baseline), so there is nothing to compare with.")
    elif not novel:
        item("Nothing: every master, device, conversation and operation in this traffic is in the baseline's list.")
    else:
        if report["baseline_learning"]:
            item("The baseline is still learning, so its list is short and more looks new here than is.")
        for entry in novel[:top]:
            item(f"{clock(entry['first'], start)}  {sentence(entry)}")
        if len(novel) > top:
            item(f"... and {len(novel) - top} more masters with something new.")

    heading("Other traffic in the period")
    traffic = report["traffic"]
    totals = traffic["totals"]
    item(f"{totals['conversations']} conversations between {totals['addresses']} addresses, {totals['industrial']} of them industrial; "
         f"{profile.size(totals['bytes'])}.")
    for label, name in (("Other protocols reaching controllers", "reaching_controllers"), ("Addresses outside the private ranges", "outside"),
                        ("Largest transfers", "largest")):
        rows = traffic[name]
        if not rows:
            item(f"{label}: none.")
            continue
        item(f"{label}:")
        for row in rows:
            item(f"    {profile.who(row['client'], row['client_role'])} -> {profile.who(row['server'], row['server_role'])}  "
                 f"{profile.what(row)}  {profile.size(row['bytes'])}, {row['connections']} connections")

    heading("Where to look next")
    item("The packets themselves: Arkime, Sessions, the same period" + (", expression  tags == <the tag>" if "tagged" in report["records"] else "")
         + ". Open a session to read its payload; the arrow beside the search bar exports the sessions as a capture file.")
    item("The whole traffic profile of the period: td-profile with the same --tag or --from and --to.")
    return "\n".join(out) + "\n"


def main(argv=None, now=None, environ=os.environ):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list", help="the uploaded captures still stored, by tag")
    listing.add_argument("--all", action="store_true", help="also the tags the product or a rule put on the records")
    report = commands.add_parser("report", help="what the engines made of a capture or a period")
    report.add_argument("--tag", help="an uploaded capture, by one of the words of its file name")
    report.add_argument("--from", dest="start", help="start of a period, UTC, such as 2026-10-01T02:00")
    report.add_argument("--to", dest="end", help="end of the period, UTC")
    report.add_argument("--uploads", choices=("exclude", "include", "only"),
                        help="uploaded captures: leave out (default for a period), count in (default with --tag), or nothing else")
    report.add_argument("--top", type=int, default=40, help="how many detections and masters to list (default 40)")
    report.add_argument("--format", choices=("text", "markdown", "json"), default="text")
    report.add_argument("--out", help="write to this file instead of the screen")
    args = parser.parse_args(argv)
    settings = base.Settings(environ)
    http = base.Http(settings)

    if args.command == "list":
        try:
            captures = list_captures(http, settings)
        except base.NETWORK_ERRORS as error:
            print(f"The records could not be read from OpenSearch: {base.clean(error)}", file=sys.stderr)
            return 1
        shown = [capture for capture in captures if args.all or capture["own"]]
        hidden = len(captures) - len(shown)
        if not shown:
            print("No uploaded capture is stored" + (f" under a tag of its own ({hidden} tags of the product's or a rule's: list --all)."
                                                     if hidden else ".")
                  + " Upload one on the product's upload page; its records are tagged with the words of its file name.")
            return 0
        width = max(len(capture["tag"]) for capture in shown)
        print(f"{'Tag'.ljust(width)}  Records   Traffic from (UTC)      to")
        for capture in shown:
            print(f"{capture['tag'].ljust(width)}  {str(capture['records']).ljust(8)}  {profile.stamp(capture['first'])}  "
                  f"{profile.stamp(capture['last'])}")
        print("A capture has one line for each word of its file name (and of the Tags box of the upload page). Capitals count."
              + (f" Left out: {hidden} tags the product or a rule put on records (list --all)." if hidden else "")
              + " Report on one with: report --tag WORD")
        return 0

    if not args.tag and not args.start:
        parser.error("give --tag (an uploaded capture) or --from and --to (a period)")
    if (args.end and not args.start) or (args.start and not args.end):
        parser.error("--from and --to go together")
    if args.top < 1:
        parser.error("--top takes 1 or more")
    try:
        asked = (base.parse_time(args.start), base.parse_time(args.end)) if args.start else None
    except ValueError as error:
        parser.error(str(error))
    uploads = args.uploads or ("include" if args.tag else "exclude")
    scope = base.scope_clauses(uploads, args.tag)
    which = {"exclude": "live traffic (uploaded captures left out)", "include": "live traffic and uploaded captures",
             "only": "uploaded captures only"}[uploads] + (f", tagged {base.clean(args.tag)}" if args.tag else "")
    try:
        if asked:
            start, end = asked
        else:
            span = base.time_span(http, settings, scope)
            if span is None:
                where = {"exclude": "No live record carries", "only": "No uploaded record carries"}.get(uploads, "No record carries")
                print(f"{where} the tag '{base.clean(args.tag)}'"
                      + (" (uploaded captures were left out: --uploads include)." if uploads == "exclude" else ".")
                      + " 'list' shows the tags of the uploaded captures; capitals count; a capture needs a few minutes after "
                      "the upload before its records are there.", file=sys.stderr)
                return 1
            start, end = span[0], span[1] + 1
        whole = (start // HOUR * HOUR, -(-end // HOUR) * HOUR) if start < end else (start, end)
        if not start < end or whole[1] - whole[0] > MAX_HOURS * HOUR:
            print(f"The period {profile.stamp(start)} to {profile.stamp(end)} is not between a moment and seven days long "
                  "(counted in whole hours). Give a shorter one with --from and --to.", file=sys.stderr)
            return 1
        # whole hours for the traffic profile's sake; the detections are listed with their own times
        start, end = whole
        result = gather(http, settings, start, end, scope, which, environ, uploads, base.clean(args.tag) if args.tag else None)
    except base.NETWORK_ERRORS as error:
        print(f"The records could not be read from OpenSearch: {base.clean(error)}", file=sys.stderr)
        return 1
    if args.format == "json":
        text = json.dumps(result, indent=1, sort_keys=True, default=sorted) + "\n"
    else:
        text = render(result, args.top, markdown=args.format == "markdown")
    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as handle:
                handle.write(text)
        except OSError as error:
            print(f"The report could not be written to {base.clean(args.out)}: {base.clean(error.strerror or error)}", file=sys.stderr)
            return 1
        print(f"written to {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
