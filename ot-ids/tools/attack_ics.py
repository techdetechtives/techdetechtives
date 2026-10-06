#!/usr/bin/env python3
# TechDetechtives OT IDS. Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""MITRE ATT&CK for ICS in the OT IDS.

  attack_ics.py tag <content folder>
      Write each rule's technique into its metadata, in the four keys the
      product turns into the alert's threat.* fields. Works on the copies in
      <content folder>/suricata/rules; the rule files in the repository are
      not changed. Running it twice changes nothing the second time.

  attack_ics.py coverage [--content <folder>] --out-dir <folder>
      Report which techniques have a detection and which do not: a page to
      read, a table, and a layer for MITRE's ATT&CK Navigator. With --content
      it reports on the rules in that folder (what a build is about to ship);
      without, on the rules in this repository.

  attack_ics.py reference -o <file>
      Write the technique list as a page to keep on the appliance, where
      attack.mitre.org cannot be reached.

  attack_ics.py update <ics-attack.json> [--commit <sha>]
      Rebuild attack/ics-attack.json from MITRE's own data file
      (github.com/mitre-attack/attack-stix-data, ics-attack/ics-attack.json).

Which detection belongs to which technique is decided by people, in three
tables in ot-ids/attack/: rule-mapping.csv (this repository's rules, by sid),
import-mapping.csv (imported rule sets, by source and message) and
other-detections.csv (everything that is not a Suricata rule).

"direct" means the rule matches the network operation the technique is carried
out with. "related" means it matches something that goes with the technique,
or a wider operation of which the technique is only one use. Neither says the
operation was unauthorised: that is for a person to decide.

Rules are read one per line. A rule continued over several lines with a
backslash is not recognised and is left as it is.
"""
import argparse
import csv
import json
import re
import sys
from collections import OrderedDict
from pathlib import Path

KIT = Path(__file__).resolve().parents[1]
ATTACK_DIR = KIT / "attack"
REFERENCE = ATTACK_DIR / "ics-attack.json"
FITS = ("direct", "related")
NETWORK_COMPONENTS = {"Network Traffic Content", "Network Traffic Flow"}
TAG_KEYS = ("mitre_tactic_id", "mitre_tactic_name", "mitre_technique_id", "mitre_technique_name",
            "mitre_subtechnique_id", "mitre_subtechnique_name", "td_attack_fit")
RULE_START = re.compile(r"^\s*(alert|drop|pass|reject\w*)\s")


# --- The reference ------------------------------------------------------------

class Reference:
    def __init__(self, path=REFERENCE):
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        self.data = data
        self.version = data["version"]
        self.tactics = data["tactics"]
        self.tactic_names = {tactic["id"]: tactic["name"] for tactic in self.tactics}
        self.techniques = data["techniques"]
        self.mitigations = data["mitigations"]
        self.superseded = data["superseded"]
        self.actors = data["actors"]

    def current(self, technique_id):
        """The identifier in this version, for one MITRE has since replaced."""
        return self.superseded.get(technique_id, technique_id)

    def parent(self, technique_id):
        return self.techniques[technique_id].get("parent") or technique_id

    def full_name(self, technique_id):
        technique = self.techniques[technique_id]
        if technique.get("parent"):
            return f"{self.techniques[technique['parent']]['name']}: {technique['name']}"
        return technique["name"]

    def children(self, technique_id):
        return sorted(key for key, value in self.techniques.items() if value.get("parent") == technique_id)

    def in_tactic(self, tactic_id):
        """Techniques of a tactic in matrix order: each technique, then its sub-techniques."""
        tops = sorted((key for key, value in self.techniques.items()
                       if tactic_id in value["tactics"] and not value.get("parent")),
                      key=lambda key: self.techniques[key]["name"].lower())
        ordered = []
        for key in tops:
            ordered.append(key)
            ordered += self.children(key)
        return ordered


def tag_name(text):
    """A name as rule metadata wants it: no spaces, commas or semicolons.

    The same spelling the product uses in its own lists (Brute_Force_IO,
    Device_Restart_or_Shutdown, Point_and_Tag_Identification).
    """
    text = text.replace("I/O", "IO").replace("/", " or ").replace("&", " and ")
    return re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_")


# --- The mapping tables --------------------------------------------------------

def read_table(path, columns):
    with open(path, newline="", encoding="utf-8") as handle:
        rows = [row for row in csv.DictReader(line for line in handle if not line.startswith("#"))]
    for row in rows:
        missing = [column for column in columns if row.get(column) is None]
        if missing:
            raise ValueError(f"{path.name}: a row is short of columns {missing}: {row}")
    return rows


class Mapping:
    """The three tables, checked against the reference."""

    def __init__(self, reference, folder=ATTACK_DIR):
        self.reference = reference
        self.by_sid = OrderedDict()
        for row in read_table(folder / "rule-mapping.csv", ("sid", "technique", "tactic", "fit", "why")):
            self.by_sid.setdefault(row["sid"], []).append(self._checked(row, f"rule-mapping.csv sid {row['sid']}"))
        self.imports = []
        for row in read_table(folder / "import-mapping.csv", ("source", "pattern", "technique", "tactic", "fit", "why")):
            entry = self._checked(row, f"import-mapping.csv {row['source']} /{row['pattern']}/")
            entry["source"] = row["source"]
            entry["pattern"] = re.compile(row["pattern"], re.I)
            self.imports.append(entry)
        self.others = []
        for row in read_table(folder / "other-detections.csv",
                              ("kind", "name", "tagged", "needs", "technique", "tactic", "fit", "why")):
            entry = self._checked(row, f"other-detections.csv {row['name']}")
            entry.update(kind=row["kind"], name=row["name"], tagged=row["tagged"] == "yes", needs=row["needs"])
            self.others.append(entry)
        self.gap_notes = {}
        for row in read_table(folder / "gap-notes.csv", ("technique", "note")):
            if row["technique"] not in reference.techniques:
                raise ValueError(f"gap-notes.csv: {row['technique']} is not a technique in ATT&CK for ICS {reference.version}")
            self.gap_notes[row["technique"]] = row["note"].strip()

    def _checked(self, row, where):
        technique, tactic, fit = row["technique"].strip(), row["tactic"].strip(), row["fit"].strip()
        why = row["why"].strip()
        if technique == "-":
            if not why:
                raise ValueError(f"{where}: a detection left without a technique needs the reason in 'why'")
            return {"technique": None, "tactic": None, "fit": None, "why": why}
        known = self.reference.techniques.get(technique)
        if known is None:
            hint = self.reference.superseded.get(technique)
            raise ValueError(f"{where}: {technique} is not a technique in ATT&CK for ICS {self.reference.version}"
                             + (f" (MITRE replaced it with {hint})" if hint else ""))
        if tactic not in known["tactics"]:
            raise ValueError(f"{where}: {technique} is not in tactic {tactic}; it is in {', '.join(known['tactics'])}")
        if fit not in FITS:
            raise ValueError(f"{where}: fit must be one of {FITS}, not '{fit}'")
        return {"technique": technique, "tactic": tactic, "fit": fit, "why": why}

    def rows_for(self, rule):
        if rule["source"]:
            return [entry for entry in self.imports
                    if entry["source"] == rule["source"] and entry["pattern"].search(rule["msg"])]
        return self.by_sid.get(rule["sid"], [])

    def for_rule(self, rule):
        """(entries, reviewed) for one parsed rule. reviewed is False when no table mentions it.

        A "-" row wins over technique rows that match the same rule: with message
        patterns two rows can meet by accident, and no tag is better than a doubtful one.
        """
        rows = self.rows_for(rule)
        if any(entry["technique"] is None for entry in rows):
            return [], True
        return rows, bool(rows)

    def reason(self, rule):
        """Why a reviewed rule has no technique."""
        return next((entry["why"] for entry in self.rows_for(rule) if entry["technique"] is None), "")


# --- Rules ---------------------------------------------------------------------

def option_spans(line):
    """(start, end, key) of each option between the rule's brackets; end is past its semicolon."""
    open_at = line.find("(")
    close_at = line.rfind(")")
    if open_at < 0 or close_at < open_at:
        return [], close_at
    spans, start, quoted, escaped = [], open_at + 1, False, False
    for index in range(open_at + 1, close_at):
        char = line[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == ";" and not quoted:
            text = line[start:index]
            spans.append((start + len(text) - len(text.lstrip()), index + 1, text.split(":", 1)[0].strip().lower()))
            start = index + 1
    return spans, close_at


def parse_rule(line):
    """sid, msg, source of an active rule line, or None for comments and anything else."""
    if not RULE_START.match(line):
        return None
    spans, _ = option_spans(line)
    found = {}
    for start, end, key in spans:
        text = line[start:end - 1]
        if key in ("sid", "msg", "metadata", "flowbits") and ":" in text:
            found.setdefault(key, []).append(text.split(":", 1)[1].strip())
    if "sid" not in found:
        return None
    metadata = ", ".join(found.get("metadata", []))    # a rule may have several metadata options
    source = re.search(r"(?:^|,)\s*td_source\s+([^,\s]+)", metadata)
    return {
        "sid": found["sid"][0],
        "msg": found.get("msg", [""])[0].strip('"'),
        "source": source.group(1) if source else None,
        "noalert": any(key == "noalert" for _, _, key in spans) or "noalert" in found.get("flowbits", []),
        "tagged": bool(re.search(r"(?:^|,)\s*mitre_technique_id\s", metadata)),
        "spans": spans,
    }


def tagged_entries(entries):
    """The entries that go into the alert: the first, and every direct one."""
    return [entry for index, entry in enumerate(entries) if index == 0 or entry["fit"] == "direct"]


def tag_values(reference, entries):
    """The metadata to add for a rule's entries, as 'key value' pieces.

    The rule's first entry is written, and every "direct" one. td_attack_fit
    says which kind the first is, so a reader of the alert can tell a rule that
    sees the technique's own operation from one that sees something near it.
    The product keeps a sub-technique under its parent, so the parent goes in
    mitre_technique_id and the sub-technique in its own key.
    """
    chosen = tagged_entries(entries)
    values = OrderedDict((key, []) for key in TAG_KEYS)

    def add(key, value):
        if value not in values[key]:
            values[key].append(value)

    for entry in chosen:
        technique, parent = entry["technique"], reference.parent(entry["technique"])
        add("mitre_tactic_id", entry["tactic"])
        add("mitre_tactic_name", tag_name(reference.tactic_names[entry["tactic"]]))
        add("mitre_technique_id", parent)
        add("mitre_technique_name", tag_name(reference.techniques[parent]["name"]))
        if parent != technique:
            add("mitre_subtechnique_id", technique)
            add("mitre_subtechnique_name", tag_name(reference.techniques[technique]["name"]))
    add("td_attack_fit", entries[0]["fit"])
    return [f"{key} {value}" for key, items in values.items() for value in items]


def tag_line(line, reference, mapping):
    """Return (line, outcome); outcome is tagged, already, unmapped, none, marker or skipped."""
    rule = parse_rule(line)
    if rule is None:
        return line, "skipped"
    if rule["tagged"]:
        return line, "already"
    entries, reviewed = mapping.for_rule(rule)
    if not entries:
        return line, ("none" if reviewed else "unmapped")
    if rule["noalert"]:
        return line, "marker"
    addition = ", ".join(tag_values(reference, entries))
    for start, end, key in reversed(rule["spans"]):
        if key == "metadata":
            return line[:end - 1].rstrip() + ", " + addition + line[end - 1:], "tagged"
    _, close_at = option_spans(line)
    return line[:close_at].rstrip() + " metadata:" + addition + ";" + line[close_at:], "tagged"


def tag_folder(content, reference, mapping):
    counts = {}
    for path in sorted((Path(content) / "suricata" / "rules").glob("*.rules")):
        lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
        changed = False
        for index, line in enumerate(lines):
            lines[index], outcome = tag_line(line, reference, mapping)
            changed = changed or lines[index] != line
            if outcome != "skipped":
                counts[outcome] = counts.get(outcome, 0) + 1
        if changed:
            path.write_text("\n".join(lines), encoding="utf-8")
    return counts


# --- Coverage --------------------------------------------------------------------

def rules_in(folders):
    for folder in folders:
        for path in sorted(Path(folder).glob("*.rules")):
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                rule = parse_rule(line)
                if rule:
                    rule["file"] = path.name
                    yield rule


def gather(reference, mapping, rule_folders, content=None):
    """What detects what.

    Returns (by_technique, unmapped, without) where by_technique maps a
    technique to its detections, unmapped lists rules no table mentions, and
    without lists detections reviewed and left with no technique.
    """
    by_technique, unmapped, without = {}, [], []

    def add(technique, detection):
        by_technique.setdefault(technique, []).append(detection)

    for rule in rules_in(rule_folders):
        if rule["noalert"]:
            continue
        entries, reviewed = mapping.for_rule(rule)
        label = rule["sid"] if not rule["source"] else f"{rule['source']} {rule['sid']}"
        if not reviewed:
            unmapped.append((rule["file"], rule["sid"], rule["msg"]))
        elif not entries:
            without.append({"group": f"Suricata, {rule['source']}" if rule["source"] else "",
                            "label": f"Suricata {rule['sid']}: {rule['msg']}", "why": mapping.reason(rule)})
        for entry in entries:
            add(entry["technique"], {"kind": "suricata" if not rule["source"] else f"suricata:{rule['source']}",
                                     "label": label, "msg": rule["msg"], "fit": entry["fit"], "tagged": True})
    for entry in mapping.others:
        if content is not None and entry["needs"] and not (Path(content) / entry["needs"]).exists():
            continue
        if entry["technique"] is None:
            without.append({"group": "", "label": f"{KIND_NAMES.get(entry['kind'], entry['kind'])} {entry['name']}",
                            "why": entry["why"]})
            continue
        add(entry["technique"], {"kind": entry["kind"], "label": entry["name"], "msg": entry["why"],
                                 "fit": entry["fit"], "tagged": entry["tagged"]})
    return by_technique, unmapped, without


def status_of(reference, by_technique, technique_id):
    """direct, related or none; a technique also counts what its sub-techniques have."""
    detections = list(by_technique.get(technique_id, []))
    for child in reference.children(technique_id):
        detections += by_technique.get(child, [])
    if any(item["fit"] == "direct" for item in detections):
        return "direct"
    return "related" if detections else "none"


def reach_of(reference, technique_id):
    """Where MITRE says a technique can be seen, for one that has no detection here."""
    components = set(reference.techniques[technique_id]["data_components"])
    if not components:
        return "effect"
    return "network" if components & NETWORK_COMPONENTS else "host"


KIND_NAMES = OrderedDict([
    ("suricata", "Suricata"), ("zeek-acid", "Zeek ACID"), ("zeek-l2", "Zeek layer 2 watch"),
    ("zeek-intel", "Zeek intelligence"), ("yara", "YARA"),
])


def describe(detections):
    """'Suricata 1900151, 1900152 · Zeek ACID s7comm' with related ones in brackets."""
    groups = OrderedDict()
    for item in detections:
        kind = item["kind"]
        name = KIND_NAMES.get(kind) or ("Suricata, " + kind.split(":", 1)[1] if kind.startswith("suricata:") else kind)
        label = item["label"].split(" ", 1)[1] if kind.startswith("suricata:") else item["label"]
        groups.setdefault(name, []).append(label if item["fit"] == "direct" else f"({label})")
    parts = []
    for name, labels in groups.items():
        unique = sorted(OrderedDict.fromkeys(labels), key=lambda label: label.strip("()"))
        if len(unique) > 8:
            unique = unique[:8] + [f"and {len(unique) - 8} more"]
        parts.append(f"{name} {', '.join(unique)}")
    return " · ".join(parts)


STATUS_WORDS = {"direct": "Direct", "related": "Related only", "none": "None"}
REACH_WORDS = {
    "network": "Shows in network traffic, by MITRE's list; see Gaps",
    "host": "Shows in host logs, device alarms or the process itself, not in network traffic",
    "effect": "An effect on the plant; MITRE lists no data to detect it with",
}


def coverage_rows(reference, by_technique):
    """One row per technique and tactic it sits in, in matrix order."""
    rows = []
    for tactic in reference.tactics:
        for technique_id in reference.in_tactic(tactic["id"]):
            technique = reference.techniques[technique_id]
            status = status_of(reference, by_technique, technique_id)
            own = by_technique.get(technique_id, [])
            rows.append({
                "tactic_id": tactic["id"], "tactic": tactic["name"], "technique_id": technique_id,
                "technique": reference.full_name(technique_id), "sub": bool(technique.get("parent")),
                "status": status, "detections": describe(own),
                "through_sub": status != "none" and not own,
                "under_parent": status == "none" and bool(technique.get("parent"))
                                and bool(by_technique.get(technique["parent"])),
                "reach": reach_of(reference, technique_id) if status == "none" else "",
                "mitigations": technique["mitigations"],
            })
    return rows


def covered(reference, by_technique, technique_id):
    """For the malware table: a sub-technique also counts a detection mapped to its parent."""
    if status_of(reference, by_technique, technique_id) != "none":
        return True
    parent = reference.parent(technique_id)
    return parent != technique_id and bool(by_technique.get(parent))


def write_markdown(path, reference, by_technique, unmapped, without, scope, gap_notes):
    rows = coverage_rows(reference, by_technique)
    tops = sorted(key for key, value in reference.techniques.items() if not value.get("parent"))
    counts = {status: sum(1 for key in tops if status_of(reference, by_technique, key) == status) for status in STATUS_WORDS}
    gaps = OrderedDict((reach, []) for reach in REACH_WORDS)
    for technique_id in sorted(reference.techniques):
        if not covered(reference, by_technique, technique_id):
            gaps[reach_of(reference, technique_id)].append(technique_id)
    top_gaps = {reach: sum(1 for key in keys if key in tops) for reach, keys in gaps.items()}
    out = [
        "# MITRE ATT&CK for ICS coverage",
        "",
        f"Generated by `ot-ids/tools/attack_ics.py coverage` from ATT&CK for ICS {reference.version}. Do not edit by hand:",
        "change the tables in `ot-ids/attack/` and run the tool again.",
        "",
        f"Scope: {scope}",
        "",
        "## How to read this",
        "",
        "- **Direct**: a detection matches the network operation the technique is carried out with.",
        "- **Related only**: a detection matches something that goes with the technique, or a wider operation of which",
        "  the technique is only one use. In the tables, related detections are in brackets.",
        "- **None**: nothing here is mapped to the technique.",
        "",
        "A detection mapped to a technique means the sensor has a rule for one way of doing it, on the protocols that",
        "rule covers. It does not mean every way of doing it is seen, and no alert says by itself that an operation was",
        "unauthorised. MITRE's own caution applies: covering a technique does not guarantee full defensive coverage.",
        "",
        "## Summary",
        "",
        f"{len(tops)} techniques (sub-techniques counted with their technique): **{counts['direct']} direct**, "
        f"**{counts['related']} related only**, **{counts['none']} none**.",
        "",
        f"Of the {counts['none']} with none, MITRE lists network traffic as a way to detect {top_gaps['network']}; "
        f"{top_gaps['host']} show only in host logs, device alarms or the process; {top_gaps['effect']} are effects on the "
        "plant with no detection data at all.",
        "",
        "| Tactic | Techniques | Direct | Related only | None |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for tactic in reference.tactics:
        mine = [row for row in rows if row["tactic_id"] == tactic["id"] and not row["sub"]]
        tally = [sum(1 for row in mine if row["status"] == status) for status in STATUS_WORDS]
        out.append(f"| {tactic['id']} {tactic['name']} | {len(mine)} | {tally[0]} | {tally[1]} | {tally[2]} |")
    out += ["", "A technique that sits in several tactics is counted in each.", ""]

    for tactic in reference.tactics:
        out += [f"## {tactic['id']} {tactic['name']}", "", "| Technique | Coverage | Detections, or where it would be seen |", "| --- | --- | --- |"]
        for row in (row for row in rows if row["tactic_id"] == tactic["id"]):
            name = f"{row['technique_id']} {row['technique']}"
            if row["under_parent"]:
                detail = "Not told apart from the technique above"
            elif row["status"] == "none":
                detail = REACH_WORDS[row["reach"]]
            elif row["through_sub"]:
                detail = "Through its sub-techniques"
            else:
                detail = row["detections"]
            out.append(f"| {'&nbsp;&nbsp;&nbsp;' if row['sub'] else ''}{name} | {STATUS_WORDS[row['status']]} | {detail} |")
        out.append("")

    out += [
        "## Gaps",
        "",
        "Sorted by where MITRE's detection guidance says each technique shows up (its data components).",
        "",
        f"### In network traffic, with no detection here ({len(gaps['network'])}, sub-techniques included)",
        "",
        "MITRE lists network traffic among the data these can be detected with. That is not the same as a rule being",
        "possible: the note on each says what it would take.",
        "",
    ]
    out += [f"- **{key} {reference.full_name(key)}.** {gap_notes.get(key, 'No note written yet.')}" for key in gaps["network"]] or ["- none"]
    out += ["", f"### Not in network traffic ({len(gaps['host'])})", "",
            "Host logs, device alarms, firmware or the process itself. A network sensor cannot see these;",
            "they need logs from the workstations and servers, or the control system's own alarms.", ""]
    out += [f"- {key} {reference.full_name(key)}" for key in gaps["host"]] or ["- none"]
    out += ["", f"### Effects ({len(gaps['effect'])})", "",
            "What an attack does to the plant. MITRE lists no data to detect these with; they are recognised by operators.", ""]
    out += [f"- {key} {reference.full_name(key)}" for key in gaps["effect"]] or ["- none"]

    out += [
        "",
        "## Known ICS malware, campaigns and groups",
        "",
        "For each one MITRE documents: how many of the techniques it used have any detection here, direct or related",
        "(a sub-technique counts when its technique has one).",
        "This is counted by technique, not by how that malware carried the technique out. Industroyer sent its commands",
        "by IEC 104, IEC 61850 and OPC; a rule for the same technique on Modbus does not see that. Read the numbers as",
        "\"how much of this chain the sensor has rules near\", not as \"would have detected it\".",
        "",
        "| Name | Kind | Techniques used | With a detection | Without |",
        "| --- | --- | ---: | ---: | --- |",
    ]
    for actor in sorted(reference.actors, key=lambda item: ({"software": 0, "campaign": 1, "group": 2}[item["kind"]], item["name"].lower())):
        used = [key for key in actor["techniques"] if key in reference.techniques]
        if not used:
            continue
        missing = [key for key in used if not covered(reference, by_technique, key)]
        out.append(f"| {actor['name']} ({actor['id']}) | {actor['kind']} | {len(used)} | {len(used) - len(missing)} | {', '.join(missing) or '-'} |")

    out += ["", "## Detections with no technique", "",
            "Looked at and left without one, with the reason.", "",
            "| Detection | Reason |", "| --- | --- |"]
    grouped = OrderedDict()
    for item in without:
        if item["group"]:
            grouped[(item["group"], item["why"])] = grouped.get((item["group"], item["why"]), 0) + 1
        else:
            out.append(f"| {item['label']} | {item['why']} |")
    out += [f"| {group}: {count} rule{'s' if count != 1 else ''} | {why} |" for (group, why), count in grouped.items()]
    if unmapped:
        out += ["", "## Rules nobody has mapped yet", "",
                "In the rule files but in none of the tables. Add a row for each to `ot-ids/attack/`.", ""]
        out += [f"- {name} sid {sid}: {msg}" for name, sid, msg in unmapped]
    out += [
        "",
        "## Where the technique appears in the product",
        "",
        "- Suricata alerts carry it in the alert itself: the build writes `mitre_tactic_id`, `mitre_tactic_name`,",
        "  `mitre_technique_id` and `mitre_technique_name` into each mapped rule, and the product turns those into the",
        "  `threat.tactic.*` and `threat.technique.*` fields and adds the tactic to the alert's category.",
        "  A sub-technique is kept in the alert's `mitre_subtechnique_id`, and `td_attack_fit` says whether the rule's",
        "  first technique is a direct or a related one. An alert carries its rule's first technique and every direct one.",
        "- Zeek ACID notices carry it already (category ATTACKICS).",
        "- The layer 2 watch and YARA matches do not carry it; this page is where they are mapped.",
        "",
        "---",
        "",
        reference.data["copyright"],
        "",
        reference.data["licence"],
        "",
    ]
    Path(path).write_text("\n".join(out), encoding="utf-8")
    return counts, gaps


def write_csv(path, reference, by_technique):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(["tactic_id", "tactic", "technique_id", "technique", "coverage", "detections",
                         "seen_in_if_uncovered", "mitigations"])
        for row in coverage_rows(reference, by_technique):
            writer.writerow([row["tactic_id"], row["tactic"], row["technique_id"], row["technique"], row["status"],
                             row["detections"], row["reach"],
                             "; ".join(f"{key} {reference.mitigations[key]}" for key in row["mitigations"])])


def write_layer(path, reference, by_technique, scope):
    """A layer file for MITRE's ATT&CK Navigator (layer format 4.5)."""
    scores = {"direct": 2, "related": 1}
    techniques = []
    for technique_id in sorted(reference.techniques):
        own = by_technique.get(technique_id, [])
        if not own:
            if status_of(reference, by_technique, technique_id) != "none":
                techniques.append({"techniqueID": technique_id, "comment": "Through its sub-techniques",
                                   "enabled": True, "showSubtechniques": True})
            continue
        status = status_of(reference, by_technique, technique_id)    # as the page counts it, sub-techniques included
        techniques.append({"techniqueID": technique_id, "score": scores[status], "comment": describe(own),
                           "enabled": True, "showSubtechniques": bool(reference.children(technique_id))})
    layer = {
        "name": "TechDetechtives OT IDS detections",
        "versions": {"attack": reference.version.split(".")[0], "navigator": "5.1.0", "layer": "4.5"},
        "domain": "ics-attack",
        "description": f"Techniques with a detection. Score 2: direct. Score 1: related only. {scope}",
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#ffe08a", "#5bbf7a"], "minValue": 0, "maxValue": 2},
        "legendItems": [{"label": "Direct detection", "color": "#5bbf7a"},
                        {"label": "Related detection only", "color": "#ffe08a"}],
        "showTacticRowBackground": False,
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }
    Path(path).write_text(json.dumps(layer, indent=1) + "\n", encoding="utf-8")


def write_reference_page(path, reference):
    out = [
        f"# MITRE ATT&CK for ICS {reference.version}: technique reference",
        "",
        "For reading on the appliance, where attack.mitre.org cannot be reached. One line on each technique, the",
        "kinds of data MITRE says it can be detected with, and the mitigations MITRE lists for it.",
        "",
        reference.data["copyright"],
        "",
        reference.data["licence"],
        "",
    ]
    described = {}
    for tactic in reference.tactics:
        out += [f"## {tactic['id']} {tactic['name']}", ""]
        for technique_id in reference.in_tactic(tactic["id"]):
            technique = reference.techniques[technique_id]
            if technique_id in described:
                out += [f"### {technique_id} {reference.full_name(technique_id)}", "", f"Described under {described[technique_id]}.", ""]
                continue
            described[technique_id] = f"{tactic['id']} {tactic['name']}"
            out += [f"### {technique_id} {reference.full_name(technique_id)}", "", technique["summary"], ""]
            others = [key for key in technique["tactics"] if key != tactic["id"]]
            if others:
                out.append("- Also in: " + ", ".join(f"{key} {reference.tactic_names[key]}" for key in others))
            out.append("- Detected with: " + (", ".join(technique["data_components"]) or "no data listed by MITRE"))
            out.append("- Mitigations: " + (", ".join(f"{key} {reference.mitigations[key]}" for key in technique["mitigations"]) or "none listed"))
            out.append("")
    out += ["## Identifiers MITRE has replaced", "",
            "Older tools and reports may still show these.", "",
            "| Old | Now |", "| --- | --- |"]
    out += [f"| {old} | {new} {reference.full_name(new)} |" for old, new in sorted(reference.superseded.items())]
    out.append("")
    Path(path).write_text("\n".join(out), encoding="utf-8")


# --- Rebuilding the reference from MITRE's data ------------------------------------

COPYRIGHT = "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."
LICENCE = ("LICENSE: The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use "
           "ATT&CK® for research, development, and commercial purposes. Any copy you make for such purposes is "
           "authorized provided that you reproduce MITRE's copyright designation and this license in any such copy.")


def first_sentence(text):
    text = re.sub(r"\s*\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"\s+", " ", text).strip()
    sentences = re.split(r"(?<=[a-z\)]\.)\s+(?=[A-Z])", text)
    # MITRE opens a few descriptions with background; the sentence that says what the adversary does is the one wanted.
    return next((sentence for sentence in sentences if "dversar" in sentence), sentences[0])


def build_reference(stix_path, commit=""):
    objects = json.loads(Path(stix_path).read_text(encoding="utf-8"))["objects"]
    by_id = {item["id"]: item for item in objects}

    def external(item):
        found = [ref["external_id"] for ref in item.get("external_references", []) if ref.get("source_name") == "mitre-attack"]
        return found[0] if found else None

    def active(item):
        return not item.get("revoked") and not item.get("x_mitre_deprecated")

    collection = next(item for item in objects if item["type"] == "x-mitre-collection")
    matrix = next(item for item in objects if item["type"] == "x-mitre-matrix")
    tactics = [{"id": external(by_id[ref]), "name": by_id[ref]["name"], "shortname": by_id[ref]["x_mitre_shortname"]}
               for ref in matrix["tactic_refs"]]
    short = {tactic["shortname"]: tactic["id"] for tactic in tactics}

    techniques = {}
    for item in objects:
        if item["type"] == "attack-pattern" and active(item):
            techniques[external(item)] = {
                "name": item["name"],
                "tactics": [short[phase["phase_name"]] for phase in item.get("kill_chain_phases", [])
                            if phase.get("kill_chain_name") == "mitre-ics-attack"],
                "parent": None, "summary": first_sentence(item.get("description")),
                "data_components": [], "mitigations": [],
            }
    mitigations, superseded, uses = {}, {}, {}
    for rel in (item for item in objects if item["type"] == "relationship" and active(item)):
        source, target = by_id.get(rel["source_ref"]), by_id.get(rel["target_ref"])
        if not source or not target:
            continue
        kind = rel["relationship_type"]
        if kind == "revoked-by" and source["type"] == "attack-pattern":
            superseded[external(source)] = external(target)
        if target["type"] != "attack-pattern" or not active(target) or not active(source):
            continue
        technique = techniques[external(target)]
        if kind == "subtechnique-of":
            techniques[external(source)]["parent"] = external(target)
        elif kind == "mitigates" and source["type"] == "course-of-action":
            mitigations[external(source)] = source["name"]
            technique["mitigations"].append(external(source))
        elif kind == "detects":
            for ref in source.get("x_mitre_analytic_refs", []):
                for log_source in by_id[ref].get("x_mitre_log_source_references", []):
                    component = by_id.get(log_source["x_mitre_data_component_ref"])
                    if component:
                        technique["data_components"].append(component["name"])
        elif kind == "uses" and source["type"] in ("malware", "tool", "campaign", "intrusion-set"):
            uses.setdefault(source["id"], set()).add(external(target))
    for technique in techniques.values():
        technique["data_components"] = sorted(set(technique["data_components"]))
        technique["mitigations"] = sorted(set(technique["mitigations"]))
    kinds = {"malware": "software", "tool": "software", "campaign": "campaign", "intrusion-set": "group"}
    actors = sorted(({"id": external(by_id[key]), "name": by_id[key]["name"], "kind": kinds[by_id[key]["type"]],
                      "techniques": sorted(value)} for key, value in uses.items()), key=lambda item: item["id"])
    return {
        "source": "MITRE ATT&CK for ICS, github.com/mitre-attack/attack-stix-data, ics-attack/ics-attack.json",
        "source_commit": commit,
        "version": collection["x_mitre_version"],
        "modified": collection["modified"],
        "copyright": COPYRIGHT,
        "licence": LICENCE,
        "note": "Built by ot-ids/tools/attack_ics.py update. Names, relations and the first sentence of each description; MITRE's full text is at attack.mitre.org.",
        "tactics": tactics,
        "techniques": dict(sorted(techniques.items())),
        "mitigations": dict(sorted(mitigations.items())),
        "superseded": dict(sorted(superseded.items())),
        "actors": actors,
    }


# --- Command line -------------------------------------------------------------------

def repository_rule_folders():
    return [KIT.parent / "platform" / "detections" / "suricata", KIT / "detections" / "suricata"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    tag = commands.add_parser("tag", help="write technique metadata into the rules of a content folder")
    tag.add_argument("content", type=Path)
    coverage = commands.add_parser("coverage", help="report covered techniques and gaps")
    coverage.add_argument("--content", type=Path, help="report on this content folder instead of the repository")
    coverage.add_argument("--out-dir", type=Path, required=True)
    coverage.add_argument("--name", default="attack-ics-coverage", help="base name of the files written")
    page = commands.add_parser("reference", help="write the technique list as a page")
    page.add_argument("-o", "--output", type=Path, required=True)
    update = commands.add_parser("update", help="rebuild attack/ics-attack.json from MITRE's data file")
    update.add_argument("stix", type=Path)
    update.add_argument("--commit", default="", help="commit of attack-stix-data the file came from")
    args = parser.parse_args(argv)

    if args.command == "update":
        data = build_reference(args.stix, args.commit)
        REFERENCE.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"[attack] wrote {REFERENCE}: ATT&CK for ICS {data['version']}, {len(data['techniques'])} techniques", file=sys.stderr)
        return 0

    reference = Reference()
    if args.command == "reference":
        write_reference_page(args.output, reference)
        return 0
    mapping = Mapping(reference)
    if args.command == "tag":
        counts = tag_folder(args.content, reference, mapping)
        print("[attack] rules: " + (", ".join(f"{counts[key]} {word}" for key, word in (
            ("tagged", "given a technique"), ("already", "already carried one"), ("none", "reviewed, no technique"),
            ("marker", "markers that raise no alert"), ("unmapped", "not in any mapping table")) if counts.get(key))
            or "none found"), file=sys.stderr)
        return 0

    if args.content:
        folders = [args.content / "suricata" / "rules"]
        scope = ("the rules and scripts in the content folder a build put together, imported rule sets included, plus "
                 "the Zeek ACID package the product loads. The general rule set bundled with the product (Emerging "
                 "Threats Open) is not counted: its rules carry ATT&CK Enterprise techniques, not ICS ones.")
    else:
        folders = repository_rule_folders()
        scope = ("the detections kept in this repository (the shared rules in `platform/detections`, the OT IDS rules in "
                 "`ot-ids/detections`), the YARA rules, the Zeek ACID package the product loads, and the layer 2 watch. "
                 "Imported rule sets are not counted here; a build writes this same report for everything it ships to "
                 "`out/attack-ics-coverage.md`. The general rule set bundled with the product (Emerging Threats Open) is "
                 "not counted in either: its rules carry ATT&CK Enterprise techniques, not ICS ones.")
    by_technique, unmapped, without = gather(reference, mapping, folders, args.content)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    counts, gaps = write_markdown(args.out_dir / f"{args.name}.md", reference, by_technique, unmapped, without, scope,
                                  mapping.gap_notes)
    write_csv(args.out_dir / f"{args.name}.csv", reference, by_technique)
    write_layer(args.out_dir / "attack-ics-layer.json", reference, by_technique, scope.split(".")[0].replace("`", "") + ".")
    print(f"[attack] techniques: {counts['direct']} direct, {counts['related']} related only, {counts['none']} none; "
          f"{len(gaps['network'])} gaps are in network traffic; {len(unmapped)} rules not in any mapping table", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
