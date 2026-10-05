#!/usr/bin/env python3
# TechDetechtives: add or remove the layer 2 watch in the list of scripts Zeek loads.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Security Onion keeps the list of Zeek scripts to load in one setting
(zeek, config, local, load). A local value replaces the whole default list, so
this writes the list in effect plus one entry, and takes that entry out again
on "off" (removing the local value altogether when what is left is the default).

    zeek_load_setting.py on     LOCAL_SETTINGS DEFAULT_SETTINGS [--backup-dir DIR] [--state FILE]
    zeek_load_setting.py off    LOCAL_SETTINGS DEFAULT_SETTINGS [--backup-dir DIR] [--state FILE]
    zeek_load_setting.py status LOCAL_SETTINGS DEFAULT_SETTINGS

LOCAL_SETTINGS   /opt/so/saltstack/local/pillar/zeek/soc_zeek.sls
DEFAULT_SETTINGS /opt/so/saltstack/default/salt/zeek/defaults.yaml (read only)

The same list can be edited by hand in the console under Administration,
Configuration, zeek, config, local, load. While a local value is in place,
changes Security Onion makes to its default list in a later version do not
reach this platform. The state file remembers the default list that "on"
started from, so that:

* "off" removes the local value even after an upgrade changed the default
  (as long as nobody edited the list in between), and
* running "on" again after an upgrade carries the new default list over.
"""

import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from local_rules_setting import dig, drop, load, put, save  # noqa: E402

LOAD = ("zeek", "config", "local", "load")
ENTRY = "custom/techdetechtives"


def default_list(defaults):
    value = dig(defaults, LOAD)
    if not isinstance(value, list) or not value:
        sys.exit("ERROR: the list of Zeek scripts was not found in the platform defaults; "
                 "this platform version stores it differently, so nothing was changed")
    return list(value)


def in_effect(local, defaults):
    value = dig(local, LOAD)
    if value is None:
        return default_list(defaults)
    if not isinstance(value, list):
        sys.exit("ERROR: the local list of Zeek scripts is not a list; nothing was changed")
    return list(value)


def read_state(path):
    """The default list "on" started from, when the local value was put there by this tool alone."""
    try:
        with open(path, encoding="utf-8") as handle:
            value = json.load(handle).get("default_at_on")
        return value if isinstance(value, list) else None
    except (OSError, ValueError, AttributeError):
        return None


def on(local, defaults, started_from=None):
    """Returns (settings, default list to remember, or None when the list is not ours alone)."""
    default = default_list(defaults)
    existing = dig(local, LOAD)
    if existing is None:
        put(local, LOAD, default + [ENTRY])
        return local, default
    current = in_effect(local, defaults)
    if started_from is not None and current == started_from + [ENTRY]:
        # Ours alone: carry a changed default list over.
        put(local, LOAD, default + [ENTRY])
        return local, default
    if ENTRY not in current:
        put(local, LOAD, current + [ENTRY])
    return local, None


def off(local, defaults, started_from=None):
    if dig(local, LOAD) is None:
        return local
    cleaned = [item for item in in_effect(local, defaults) if item != ENTRY]
    if cleaned == default_list(defaults) or (started_from is not None and cleaned == started_from):
        drop(local, LOAD)
    else:
        put(local, LOAD, cleaned)
    return local


def main(argv):
    if len(argv) < 4 or argv[1] not in ("on", "off", "status"):
        sys.exit(__doc__)
    command, local_path, defaults_path = argv[1:4]
    backup_dir = argv[argv.index("--backup-dir") + 1] if "--backup-dir" in argv else ""
    state_path = argv[argv.index("--state") + 1] if "--state" in argv else ""
    defaults = load(defaults_path, required=True)
    local = load(local_path, required=False)
    if command == "status":
        loaded = ENTRY in in_effect(local, defaults)
        print("in the list of scripts Zeek loads" if loaded else "not in the list of scripts Zeek loads")
        return 0 if loaded else 1
    before = copy.deepcopy(local)
    started_from = read_state(state_path) if state_path else None
    remember = None
    if command == "on":
        local, remember = on(local, defaults, started_from)
    else:
        local = off(local, defaults, started_from)
    if local != before:
        save(local_path, local, backup_dir)
    if state_path:
        if command == "on" and remember is not None:
            os.makedirs(os.path.dirname(state_path) or ".", exist_ok=True)
            with open(state_path, "w", encoding="utf-8") as handle:
                json.dump({"default_at_on": remember}, handle)
        elif command == "off" or (command == "on" and local != before):
            # Switched off, or the list is no longer ours alone: nothing to remember.
            if os.path.exists(state_path):
                os.remove(state_path)
    print("no change needed" if local == before else "updated %s" % local_path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
