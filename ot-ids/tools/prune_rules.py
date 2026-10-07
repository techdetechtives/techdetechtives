#!/usr/bin/env python3
# TechDetechtives OT IDS. Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Comment out the rules that `suricata -T` refused.

Suricata names each rule it cannot load as
    ... error parsing signature "<rule>" from file <path> at line <n>
This tool reads that output and puts "#PRUNED " in front of those lines of the
rule file, so one bad rule (most often from an imported Snort set) does not
keep the rest of the file from being used.

  prune_rules.py --rules ext-quickdraw.rules --log suricata-test-output.txt

Prints the number of lines it commented out. Exit status 0 always; run
`suricata -T` again afterwards, since fixing one error can reveal the next.
"""
import argparse
import re
import sys
from pathlib import Path

REFUSED = re.compile(r"from file (\S+) at line (\d+)")


def refused_lines(log_text, rules_name):
    """Line numbers of rules_name that the engine refused."""
    numbers = set()
    for path, number in REFUSED.findall(log_text):
        if Path(path).name == rules_name:
            numbers.add(int(number))
    return numbers


def prune(rules_path, numbers):
    lines = rules_path.read_text(encoding="utf-8", errors="replace").splitlines()
    done = 0
    for number in sorted(numbers):
        if 1 <= number <= len(lines) and lines[number - 1].strip() and not lines[number - 1].lstrip().startswith("#"):
            lines[number - 1] = "#PRUNED " + lines[number - 1]
            done += 1
    if done:
        rules_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return done


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--rules", required=True, type=Path)
    parser.add_argument("--log", required=True, type=Path, help="saved output of suricata -T")
    args = parser.parse_args()
    numbers = refused_lines(args.log.read_text(encoding="utf-8", errors="replace"), args.rules.name)
    print(prune(args.rules, numbers))
    return 0


if __name__ == "__main__":
    sys.exit(main())
