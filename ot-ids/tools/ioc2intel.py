#!/usr/bin/env python3
# TechDetechtives OT IDS. Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Turn lists of threat indicators into a Zeek intelligence file.

Input: text or CSV files with one indicator per line (or in one column).
Addresses, networks, domains, URLs, e-mail addresses and MD5/SHA-1/SHA-256
file hashes are recognised by their shape. Lines starting with # are skipped.
"Defanged" indicators (hxxp://, 1.2.3[.]4) are restored.

Output: the tab-separated format Zeek's intelligence framework reads. On the
sensor, a file placed in ~/Malcolm/zeek/intel/<any folder>/ is loaded on its
own, and a match appears as an "Intelligence" event.

Private, loopback and multicast addresses are left out: on a plant network they
would match ordinary traffic.

  ioc2intel.py --source "CERT advisory 2026-041" -o custom.intel advisory.txt
  ioc2intel.py --source feodo --column 1 --delimiter , -o feodo.intel ipblocklist.csv
"""
import argparse
import csv
import ipaddress
import re
import sys
from pathlib import Path

FIELDS = ["indicator", "indicator_type", "meta.source", "meta.desc", "meta.do_notice"]
DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{1,62}$")
HASH = re.compile(r"^[0-9a-f]+$")


def refang(text):
    text = text.strip().strip('"').strip("'")
    text = re.sub(r"^hxxp", "http", text, flags=re.I)
    return text.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[@]", "@")


def classify(raw):
    """Return (indicator, Zeek type), ('', 'private') for a skipped address, or None."""
    value = refang(raw)
    if not value:
        return None
    lowered = value.lower()
    if re.match(r"^https?://", lowered):
        return (re.sub(r"^https?://", "", value, flags=re.I).rstrip("/"), "Intel::URL")
    if "@" in value and DOMAIN.match(lowered.rsplit("@", 1)[1]) and " " not in value:
        return lowered, "Intel::EMAIL"
    candidate = value
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$", value):        # address:port
        candidate = value.rsplit(":", 1)[0]
    try:
        if "/" in candidate:
            network = ipaddress.ip_network(candidate, strict=False)
            if network.is_private or network.is_loopback or network.is_multicast or network.is_link_local:
                return "", "private"
            return str(network), "Intel::SUBNET"
        address = ipaddress.ip_address(candidate)
        if (address.is_private or address.is_loopback or address.is_multicast or address.is_link_local
                or address.is_unspecified or address.is_reserved):
            return "", "private"
        return str(address), "Intel::ADDR"
    except ValueError:
        pass
    if len(lowered) in (32, 40, 64) and HASH.match(lowered):
        return lowered, "Intel::FILE_HASH"
    if DOMAIN.match(lowered):
        return lowered, "Intel::DOMAIN"
    if "/" in value and DOMAIN.match(lowered.split("/", 1)[0]):          # URL written without a scheme
        return value.rstrip("/"), "Intel::URL"
    return None


def read_values(path, column, delimiter):
    text = path.read_text(encoding="utf-8", errors="replace")
    if column is None:
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                yield line.split()[0]
        return
    for row in csv.reader((line for line in text.splitlines() if line.strip() and not line.startswith("#")),
                          delimiter=delimiter):
        if len(row) > column:
            yield row[column]


def build(values, source, description, notice):
    """Return (lines of the intel file, counts)."""
    seen, rows = set(), []
    counts = {"private": 0, "unrecognised": 0}
    for raw in values:
        result = classify(raw)
        if result is None:
            counts["unrecognised"] += 1
            continue
        indicator, kind = result
        if kind == "private":
            counts["private"] += 1
            continue
        if (indicator, kind) in seen:
            continue
        seen.add((indicator, kind))
        counts[kind] = counts.get(kind, 0) + 1
        rows.append("\t".join([indicator, kind, source, description or "-", "T" if notice else "F"]))
    return ["#fields\t" + "\t".join(FIELDS)] + rows, counts


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--source", required=True, help="where the indicators came from (shown with each match)")
    parser.add_argument("--desc", default="", help="short description (shown with each match)")
    parser.add_argument("--column", type=int, help="CSV column holding the indicator, counted from 0")
    parser.add_argument("--delimiter", default=",")
    parser.add_argument("--notice", action="store_true", help="also raise a Zeek notice on each match")
    parser.add_argument("-o", "--output", required=True, type=Path)
    args = parser.parse_args()
    for label in (args.source, args.desc):
        if "\t" in label or "\n" in label:
            parser.error("--source and --desc cannot contain tabs or line breaks")

    values = (value for path in args.inputs for value in read_values(path, args.column, args.delimiter))
    lines, counts = build(values, args.source, args.desc, args.notice)
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    kept = len(lines) - 1
    print(f"{args.output.name}: {kept} indicators "
          f"({', '.join(f'{count} {kind}' for kind, count in sorted(counts.items()) if count)})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
