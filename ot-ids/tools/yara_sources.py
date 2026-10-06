#!/usr/bin/env python3
# TechDetechtives OT IDS. Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""YARA rule files from outside repositories, laid out so the product compiles them.

Why this exists. The product's file scanner loads one compiled rule file. Its
image is built with nine public rule repositories compiled into that file and
the rule sources then deleted (Dockerfiles/strelka-backend.Dockerfile). At every
start the product compiles again from the rule files it can find
(strelka/backend/yara_rules_setup.sh). With no Internet those are only the
files in ./yara/rules, so as soon as that folder holds one rule file, the
compiled set becomes that folder alone and the nine repositories are gone. This
kit puts its own rules in that folder. So the sources of the nine are fetched
at build time and put there too.

What it does with a repository's files:

  * takes the .yar and .yara files (all of them, or those under 'include', less 'exclude');
  * leaves out index files (they only include other files) and, unless told
    otherwise, files that state a non-commercial licence;
  * cuts out rules named in 'drop_rules', and, with 'drop_known', rules whose
    name an earlier source already supplied (never a private rule: those are
    helpers other rules lean on, and match nothing by themselves); a file in
    which a rule that is left uses a rule that was cut is left out whole;
  * writes each file under a name that is unique, because the product names a
    rule's namespace after the file and two files with one namespace and one
    rule name stop the whole compile;
  * copies the repository's licence files beside them.

It does not judge the rules. The product compiles each file alone at start and
skips the ones its own YARA refuses; `yara_sources.py check FOLDER` does the
same with the yarac on this machine, as a report.

  yara_sources.py check out/yara            compile each file alone, then all together, and count
  yara_sources.py names FOLDER              rule names, one per line
"""
import argparse
import fnmatch
import re
import shutil
import subprocess
import sys
from pathlib import Path

RULE = re.compile(r"^[ \t]*(?:(?:private|global)[ \t]+)*rule[ \t]+([A-Za-z_][A-Za-z0-9_]*)", re.M)
PRIVATE = re.compile(r"^[ \t]*(?:global[ \t]+)?private[ \t]+(?:global[ \t]+)?rule[ \t]+([A-Za-z_][A-Za-z0-9_]*)", re.M)
HEADER_TAGS = re.compile(r"^([ \t]*(?:(?:private|global)[ \t]+)*rule[ \t]+[A-Za-z_][A-Za-z0-9_]*)[ \t]*:[^{\n]*", re.M)
IMPORT = re.compile(r'^[ \t]*import[ \t]+"[^"\n]*"[ \t]*\r?$', re.M)      # applied to code_only text, where the name is blanked
INCLUDE = re.compile(r'^[ \t]*include[ \t]+"', re.M)
NONCOMMERCIAL = re.compile(r"by-nc|non-?commercial", re.I)
LICENCE_FILES = re.compile(r"^(licen[cs]e|copying|notice)([._-].*)?$", re.I)
RULE_SUFFIXES = (".yar", ".yara")


def names(text):
    return [item.strip() for item in text.split(",") if item.strip()]


def is_rule_file(path):
    return str(path).lower().endswith(RULE_SUFFIXES)


def is_licence_file(path):
    return "/" not in str(path) and bool(LICENCE_FILES.match(str(path))) and not is_rule_file(path)


def matches(relative, patterns):
    """A pattern is a file pattern (malware/*.yar) or a folder (malware)."""
    for pattern in patterns:
        pattern = pattern.strip("/")
        if fnmatch.fnmatch(relative, pattern) or relative.startswith(pattern + "/"):
            return True
    return False


def wanted(relative, include, exclude):
    if not is_rule_file(relative):
        return False
    if include and not matches(relative, include):
        return False
    return not matches(relative, exclude)


def code_only(text):
    """The text with comments, quoted strings and regular expressions blanked out, every position kept.

    'rule Old {' inside a comment is not a rule, and a rule name inside a
    string is not a use of that rule.
    """
    out, index, size = list(text), 0, len(text)

    def blank(start, end):
        for position in range(start, min(end, size)):
            if out[position] != "\n":
                out[position] = " "

    last_word = ""
    while index < size:
        char = text[index]
        if char == '"':
            end = index + 1
            while end < size and text[end] != '"' and text[end] != "\n":
                end += 2 if text[end] == "\\" else 1
            blank(index + 1, end)
            index, last_word = end + 1, '"'
        elif text.startswith("//", index):
            end = text.find("\n", index)
            end = size if end < 0 else end
            blank(index, end)
            index = end
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            end = size if end < 0 else end + 2
            blank(index, end)
            index = end
        elif char == "/" and last_word in ("=", "matches"):
            end = index + 1
            while end < size and text[end] != "/" and text[end] != "\n":
                end += 2 if text[end] == "\\" else 1
            blank(index + 1, end)
            index, last_word = end + 1, "/"
        elif char.isspace():
            index += 1
        else:
            end = index + 1
            if char.isalnum() or char == "_":
                while end < size and (text[end].isalnum() or text[end] == "_"):
                    end += 1
            last_word = text[index:end]
            index = end
    return "".join(out)


def rule_names(text):
    return RULE.findall(code_only(text))


def cut_rules(text, unwanted):
    """Remove whole rules by name. Returns (text, names cut).

    A rule runs from its 'rule NAME' line to the next one. That is cruder than
    reading YARA's grammar and it is enough: a file left broken by a cut is one
    the product refuses at start, alone, without touching the others. An
    'import' line that stood between two rules stays.
    """
    code = code_only(text)
    heads = [(match.start(), match.group(1)) for match in RULE.finditer(code)]
    cut, pieces, position = [], [], 0
    for index, (start, name) in enumerate(heads):
        if name not in unwanted:
            continue
        end = heads[index + 1][0] if index + 1 < len(heads) else len(text)
        pieces.append(text[position:start])
        pieces += [text[found.start():found.end()].rstrip("\r") + "\n" for found in IMPORT.finditer(code, start, end)]
        position = end
        cut.append(name)
    pieces.append(text[position:])
    return "".join(pieces), cut


def uses_any(code, names):
    """True when the rule text (already through code_only) uses one of the rule names, other than as a tag."""
    if not names:
        return False
    body = HEADER_TAGS.sub(lambda match: match.group(1) + " ", code)
    return bool(re.search(r"(?<![$#@!\w.])(?:%s)\b" % "|".join(map(re.escape, names)), body))


def namespace(filename):
    """The namespace the product gives a rule file in its custom folder.

    Follows strelka/backend/yara_rules_setup.sh in Malcolm 26.09.0: an empty
    folder part, an underscore, the file name without its last extension with
    every other character turned into an underscore, 'ns_' in front because
    that does not start with a letter, then repeated parts between underscores
    dropped.
    """
    base = str(filename).rsplit("/", 1)[-1]
    stem = base.rsplit(".", 1)[0] if "." in base else base
    name = "_" + re.sub(r"[^A-Za-z0-9]", "_", stem)
    if not re.match(r"[A-Za-z]", name):
        name = "ns_" + name
    parts = name.split("_")
    return "_".join(part for index, part in enumerate(parts) if index == 0 or part != parts[index - 1])


def flat_name(source, relative, taken):
    """A file name for one rule file of a source, with a namespace nobody else has."""
    stem = relative.rsplit(".", 1)[0]
    base = f"{source}__{re.sub(r'[^A-Za-z0-9-]', '_', stem)}"
    name, number = base, 1
    while namespace(name + ".yar") in taken:
        number += 1
        name = f"{base}_{number}"
    taken.add(namespace(name + ".yar"))
    return name + ".yar"


def gather(repo, paths, out, source, include=(), exclude=(), drop_rules=(), known=None, drop_known=False,
           skip_noncommercial=True, taken=None):
    """Copy the wanted rule files of one repository into 'out'. Returns what was done.

    paths: the repository's files, relative. known: {rule name: source} of what
    earlier sources supplied; this source's names are added to it.
    """
    known = {} if known is None else known
    taken = set() if taken is None else taken
    done = {"files": 0, "rules": 0, "index_files": [], "noncommercial": [], "cut": [], "cut_known": 0, "emptied": [], "dependent": [], "licences": []}
    unwanted = set(drop_rules)
    out.mkdir(parents=True, exist_ok=True)
    supplied = {}
    for relative in sorted(paths):
        if is_licence_file(relative) and (repo / relative).is_file() and not (repo / relative).is_symlink():
            shutil.copyfile(repo / relative, out / relative)
            done["licences"].append(relative)
            continue
        if not wanted(relative, include, exclude) or not (repo / relative).is_file() or (repo / relative).is_symlink():
            continue
        text = (repo / relative).read_text(encoding="utf-8", errors="replace")
        code = code_only(text)
        if INCLUDE.search(code):
            done["index_files"].append(relative)
            continue
        if skip_noncommercial and NONCOMMERCIAL.search(text):
            done["noncommercial"].append(relative)
            continue
        left = RULE.findall(code)
        private = set(PRIVATE.findall(code))
        remove = {name for name in left if name in unwanted}
        duplicates = {name for name in left if drop_known and name in known and name not in private} - remove
        if remove or duplicates:
            text, cut = cut_rules(text, remove | duplicates)
            code = code_only(text)
            if uses_any(code, cut):
                done["dependent"].append(relative)      # a rule that is left uses one that was cut
                continue
            done["cut"] += sorted(f"{relative}: {name}" for name in cut if name in remove)
            done["cut_known"] += sum(1 for name in cut if name in duplicates)
            left = RULE.findall(code)
        if not [name for name in left if name not in private]:
            done["emptied"].append(relative)             # nothing, or only helpers nothing uses any more
            continue
        (out / flat_name(source, relative, taken)).write_text(text, encoding="utf-8")
        done["files"] += 1
        done["rules"] += len(left)
        for name in left:
            if name not in private:
                supplied.setdefault(name, source)
    for name, origin in supplied.items():
        known.setdefault(name, origin)
    return done


def report_lines(source, done):
    lines = [f"{source}: {done['rules']} rules in {done['files']} files"]
    if done["licences"]:
        lines.append(f"licence files copied: {', '.join(done['licences'])}")
    for label, key in (("index files left out (they only include other files)", "index_files"),
                       ("files left out because they state a non-commercial licence", "noncommercial"),
                       ("files left out because they hold no rule, or none was left after cutting", "emptied"),
                       ("files left out because a rule in them uses a rule that was cut", "dependent"),
                       ("rules cut out by name (drop_rules)", "cut")):
        if done[key]:
            lines += ["", f"{label}: {len(done[key])}"] + [f"  {item}" for item in done[key]]
    if done["cut_known"]:
        lines += ["", f"rules cut out because an earlier source already supplies a rule of that name: {done['cut_known']}"]
    return lines


def summary(done):
    parts = [f"{done['rules']} rules in {done['files']} files"]
    left_out = len(done["index_files"]) + len(done["noncommercial"]) + len(done["emptied"]) + len(done["dependent"])
    if left_out:
        parts.append(f"{left_out} files left out")
    if done["cut"] or done["cut_known"]:
        parts.append(f"{len(done['cut']) + done['cut_known']} rules cut")
    return ", ".join(parts)


# --- A report with this machine's own yarac ---------------------------------------------

def rule_files(folder):
    return sorted(path for path in Path(folder).rglob("*") if path.is_file() and is_rule_file(path.name)
                  and not path.name.startswith((".", "~", "_")))


def check(folder, yarac=None, together=True):
    """Compile each file alone, then the ones that passed together, as the product does at start.

    Returns {"files", "passed", "refused": [(file, first error line)], "together": None | "ok" | error text}.
    """
    yarac = yarac or shutil.which("yarac")
    if not yarac:
        raise RuntimeError("no yarac program on this machine")
    files = rule_files(folder)
    passed, refused = [], []
    for path in files:
        result = subprocess.run([yarac, "-w", str(path), "/dev/null"], capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            passed.append(path)
        else:
            lines = [line for line in result.stderr.splitlines() if line.strip()]
            refused.append((str(path.relative_to(folder)), lines[0][-200:] if lines else "refused"))
    outcome = None
    if together and passed:
        arguments = [f"{namespace(path.name)}:{path}" for path in passed]
        result = subprocess.run([yarac, "-w", *arguments, "/dev/null"], capture_output=True, text=True, timeout=1800)
        outcome = "ok" if result.returncode == 0 else (result.stderr.strip().splitlines() or ["refused"])[0][-300:]
    return {"files": len(files), "passed": len(passed), "refused": refused, "together": outcome}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    checker = commands.add_parser("check", help="compile each file alone and all together with this machine's yarac")
    checker.add_argument("folder", type=Path)
    checker.add_argument("--yarac")
    lister = commands.add_parser("names", help="rule names in a folder")
    lister.add_argument("folder", type=Path)
    args = parser.parse_args(argv)
    if args.command == "names":
        for path in rule_files(args.folder):
            for name in rule_names(path.read_text(encoding="utf-8", errors="replace")):
                print(name)
        return 0
    try:
        result = check(args.folder, args.yarac)
    except RuntimeError as error:
        print(f"not checked: {error}", file=sys.stderr)
        return 2
    print(f"{result['passed']} of {result['files']} rule files compile alone with this machine's yarac")
    for name, error in result["refused"]:
        print(f"  refused: {name}: {error}")
    if result["together"] is not None:
        print(f"compiled together, one namespace per file: {result['together']}")
    return 0 if result["together"] in (None, "ok") else 1


if __name__ == "__main__":
    sys.exit(main())
