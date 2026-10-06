#!/usr/bin/env python3
# TechDetechtives OT IDS. Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""List which known vulnerabilities the loaded rules can recognise on the wire.

A rule that recognises an attempt to use a vulnerability is sometimes called a
"virtual patch". On this sensor it is a detection, not a patch: the sensor
watches a copy of the traffic and cannot block it. The value is knowing which
unpatched weaknesses you would at least see being attacked.

This tool reads Suricata rule files, collects every CVE number a rule names
(reference:cve,..., "cve CVE_..." in the metadata, or CVE-... in the message),
and writes:

  - a CSV with one row per CVE and rule: number, sid, rule message, file,
    platform guess (windows / linux / ot / other), and whether the CVE is in
    CISA's Known Exploited Vulnerabilities catalogue;
  - a short summary: how many CVEs are covered per platform, and how many of
    the known-exploited ones, with the uncovered known-exploited OT entries.

The platform is guessed from words in the rule, so treat it as a filter, not a
fact.

  cve_index.py --rules rules-dir more.rules --kev known_exploited_vulnerabilities.json \
               -o coverage.csv --summary coverage.md
"""
import argparse
import csv
import json
import re
import sys
from pathlib import Path

CVE_PATTERNS = [
    re.compile(r"reference\s*:\s*cve\s*,\s*(?:CVE-)?(\d{4})-(\d{4,7})", re.I),
    re.compile(r"\bcve[ _]CVE[_-](\d{4})[_-](\d{4,7})", re.I),
    re.compile(r"\bCVE-(\d{4})-(\d{4,7})", re.I),
]
SID = re.compile(r"\bsid\s*:\s*(\d+)")
MSG = re.compile(r'\bmsg\s*:\s*"((?:[^"\\]|\\.)*)"')

OT_WORDS = (
    "scada", " ics ", "plc", "siemens", "simatic", "schneider", "modicon", "rockwell", "allen-bradley",
    "allen bradley", "honeywell", "experion", " abb ", "codesys", "wago", "moxa", "advantech", "emerson",
    "yokogawa", "omron", "mitsubishi", "delta electronics", "phoenix contact", "beckhoff", "wonderware",
    "aveva", "ignition", "kepware", "modbus", "dnp3", "bacnet", "opc ", "opc-ua", "triconex", "ge proficy",
    "cimplicity", "iconics", "wincc", "tia portal", "step 7", "factorytalk", "rslogix", "unitronics",
    "sel-", "schweitzer", "hirschmann", "red lion", "ewon", "cogent", "indusoft",
)
WINDOWS_WORDS = (
    "windows", "microsoft", " smb", "ms-rpc", "msrpc", "rdp ", "remote desktop", "exchange", " iis", "netlogon",
    "active directory", "kerberos", "ntlm", "print spooler", "sharepoint", "office", "internet explorer",
    "powershell", "win32", ".net", "mssql", "outlook", "eternalblue", "bluekeep", "zerologon", "printnightmare",
)
LINUX_WORDS = (
    "linux", "unix", "apache", "nginx", "openssh", " sudo", "samba", "bash", "glibc", "kernel", "exim",
    "postfix", "dovecot", "openssl", "php", "tomcat", "log4j", "struts", "spring", "confluence", "jenkins",
    "docker", "kubernetes", "redis", "proftpd", "vsftpd", "shellshock", "polkit", "cups",
)


def platform_of(text):
    lowered = " " + text.lower() + " "
    if any(word in lowered for word in OT_WORDS):
        return "ot"
    if any(word in lowered for word in WINDOWS_WORDS):
        return "windows"
    if any(word in lowered for word in LINUX_WORDS):
        return "linux"
    return "other"


def rule_files(paths):
    for path in paths:
        if path.is_dir():
            yield from sorted(path.rglob("*.rules"))
        elif path.is_file():
            yield path


def scan(paths):
    """Yield (cve, sid, message, file name, platform) for every enabled rule that names a CVE."""
    for path in rule_files(paths):
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            found = set()
            for pattern in CVE_PATTERNS:
                found.update(f"CVE-{year}-{number}" for year, number in pattern.findall(line))
            if not found:
                continue
            sid = SID.search(line)
            message = MSG.search(line)
            text = message.group(1) if message else ""
            for cve in sorted(found):
                yield cve, sid.group(1) if sid else "", text, path.name, platform_of(text + " " + line[-400:])


def load_kev(path):
    """CISA catalogue as {cve: (vendor, product, date added)}; empty if the file is absent or unreadable."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {item["cveID"].upper(): (item.get("vendorProject", ""), item.get("product", ""), item.get("dateAdded", ""))
                for item in data.get("vulnerabilities", [])}
    except (OSError, ValueError, KeyError, AttributeError, TypeError):
        return {}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--rules", nargs="+", required=True, type=Path, help="rule files or folders")
    parser.add_argument("--kev", type=Path, help="CISA known_exploited_vulnerabilities.json")
    parser.add_argument("-o", "--output", required=True, type=Path, help="CSV to write")
    parser.add_argument("--summary", type=Path, help="Markdown summary to write")
    args = parser.parse_args()

    kev = load_kev(args.kev) if args.kev else {}
    rows = list(scan(args.rules))
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["cve", "sid", "rule", "file", "platform_guess", "known_exploited", "kev_vendor", "kev_product"])
        for cve, sid, message, name, platform in sorted(rows):
            vendor, product, _ = kev.get(cve, ("", "", ""))
            writer.writerow([cve, sid, message, name, platform, "yes" if cve in kev else ("no" if kev else ""), vendor, product])

    covered = {}
    for cve, _, _, _, platform in rows:
        covered.setdefault(cve, set()).add(platform)
    per_platform = {name: sum(1 for platforms in covered.values() if name in platforms)
                    for name in ("windows", "linux", "ot", "other")}
    lines = ["# Vulnerabilities the loaded rules can recognise", "",
             "A rule here detects an attempt to use the vulnerability. The sensor watches; it does not block.", "",
             f"- Rules that name a CVE: {len({(sid, name) for _, sid, _, name, _ in rows})}",
             f"- Distinct CVEs covered: {len(covered)}"]
    lines += [f"  - {name}: {count}" for name, count in per_platform.items()]
    if kev:
        hit = sorted(cve for cve in covered if cve in kev)
        lines += ["", f"- CISA known-exploited CVEs in the catalogue: {len(kev)}",
                  f"- Of those, covered by at least one rule: {len(hit)}"]
        ot_gaps = sorted((added, cve, vendor, product) for cve, (vendor, product, added) in kev.items()
                         if cve not in covered and platform_of(f"{vendor} {product}") == "ot")
        if ot_gaps:
            lines += ["", "## Known-exploited OT vulnerabilities with no rule (newest first)", "",
                      "| CVE | Vendor | Product | Added to the catalogue |", "| --- | --- | --- | --- |"]
            lines += [f"| {cve} | {vendor} | {product} | {added} |" for added, cve, vendor, product in reversed(ot_gaps[-40:])]
    elif args.kev:
        lines += ["", "- The known-exploited catalogue could not be read, so that comparison is missing."]
    summary = "\n".join(lines) + "\n"
    if args.summary:
        args.summary.write_text(summary, encoding="utf-8")
    print(f"{len(covered)} CVEs covered by {len(rows)} rule references"
          + (f"; {sum(1 for cve in covered if cve in kev)} of {len(kev)} known-exploited" if kev else ""), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
