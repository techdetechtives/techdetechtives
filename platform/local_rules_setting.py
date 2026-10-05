#!/usr/bin/env python3
# TechDetechtives: make the platform enable locally added Sigma and YARA rules on import.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Security Onion only auto-enables rules from its own rulesets. This adds the
local Sigma and YARA rulesets (where the TechDetechtives rules are installed) to
the two settings that control that, in the platform's local settings file.

    local_rules_setting.py enable  LOCAL_SETTINGS DEFAULT_SETTINGS [--backup-dir DIR]
    local_rules_setting.py disable LOCAL_SETTINGS DEFAULT_SETTINGS
    local_rules_setting.py status  LOCAL_SETTINGS DEFAULT_SETTINGS

LOCAL_SETTINGS   /opt/so/saltstack/local/pillar/soc/soc_soc.sls
DEFAULT_SETTINGS /opt/so/saltstack/default/salt/soc/defaults.yaml (read only)

The same settings can be changed by hand in the console under Administration,
Configuration. Rules that were imported before the change stay as they are.
"""

import copy
import os
import shutil
import sys
import time

import yaml

MODULES = ("soc", "config", "server", "modules")
SIGMA = MODULES + ("elastalertengine", "enabledSigmaRules")
YARA = MODULES + ("strelkaengine", "autoEnabledYaraRules")
SIGMA_RULESET = "local-sigma"
YARA_RULESET = "local-yara"
MARKER = "# TechDetechtives - local rules"
BLOCK = "\n".join([
    MARKER,
    '- ruleset: ["%s"]' % SIGMA_RULESET,
    '  level: ["critical", "high", "medium", "low", "informational"]',
    '  product: ["*"]',
    '  category: ["*"]',
    '  service: ["*"]',
])


def load(path, required):
    if not os.path.exists(path):
        if required:
            sys.exit("ERROR: %s not found" % path)
        return {}
    with open(path, encoding="utf-8") as handle:
        data = yaml.safe_load(handle.read())
    if data is None:
        return {}
    if not isinstance(data, dict):
        sys.exit("ERROR: %s is not a settings file (expected a mapping at the top level)" % path)
    return data


def dig(data, path):
    for key in path:
        if not isinstance(data, dict) or key not in data:
            return None
        data = data[key]
    return data


def put(data, path, value):
    for key in path[:-1]:
        if not isinstance(data.get(key), dict):
            data[key] = {}
        data = data[key]
    data[path[-1]] = value


def drop(data, path):
    """Remove a key, then any parents left empty, so the default applies again."""
    chain = [data]
    for key in path[:-1]:
        nxt = chain[-1].get(key) if isinstance(chain[-1], dict) else None
        if not isinstance(nxt, dict):
            return
        chain.append(nxt)
    chain[-1].pop(path[-1], None)
    for depth in range(len(path) - 2, -1, -1):
        if chain[depth + 1] == {}:
            chain[depth].pop(path[depth], None)
        else:
            break


def sigma_roles(defaults):
    roles = dig(defaults, SIGMA)
    if not isinstance(roles, dict) or not roles:
        sys.exit("ERROR: the Sigma auto-enable setting was not found in the platform defaults; "
                 "this platform version stores it differently, so nothing was changed")
    return roles


def without_block(text):
    lines, out, skip = text.split("\n"), [], 0
    for line in lines:
        if line.strip() == MARKER:
            skip = len(BLOCK.split("\n")) - 1
            continue
        if skip:
            skip -= 1
            continue
        out.append(line)
    return "\n".join(out).rstrip("\n")


def state(local, defaults):
    """What is in effect now: {setting name: enabled?}."""
    result = {}
    for role, default_text in sigma_roles(defaults).items():
        text = dig(local, SIGMA + (role,))
        text = default_text if text is None else text
        result["sigma:" + role] = SIGMA_RULESET in str(text or "")
    current = dig(local, YARA)
    current = dig(defaults, YARA) if current is None else current
    result["yara"] = YARA_RULESET in (current or [])
    return result


def enable(local, defaults):
    for role, default_text in sigma_roles(defaults).items():
        text = dig(local, SIGMA + (role,))
        text = default_text if text is None else text
        text = str(text or "")
        if SIGMA_RULESET not in text:
            put(local, SIGMA + (role,), (text.rstrip("\n") + "\n" if text.strip() else "") + BLOCK)
    current = dig(local, YARA)
    current = dig(defaults, YARA) if current is None else current
    current = list(current or [])
    if YARA_RULESET not in current:
        put(local, YARA, current + [YARA_RULESET])
    return local


def disable(local, defaults):
    for role, default_text in sigma_roles(defaults).items():
        text = dig(local, SIGMA + (role,))
        if text is None:
            continue
        cleaned = without_block(str(text))
        if cleaned.strip() == str(default_text or "").strip():
            drop(local, SIGMA + (role,))
        else:
            put(local, SIGMA + (role,), cleaned)
    current = dig(local, YARA)
    if current is not None:
        cleaned = [item for item in current if item != YARA_RULESET]
        if cleaned == list(dig(defaults, YARA) or []):
            drop(local, YARA)
        else:
            put(local, YARA, cleaned)
    return local


def save(path, data, backup_dir):
    if backup_dir and os.path.exists(path):
        os.makedirs(backup_dir, exist_ok=True)
        shutil.copy2(path, os.path.join(backup_dir, os.path.basename(path) + "." + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())))
    existed = os.path.exists(path)
    temporary = path + ".td-new"
    with open(temporary, "w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, default_flow_style=False)
    yaml.safe_load(open(temporary, encoding="utf-8").read())      # must read back cleanly before it replaces anything
    if existed:
        shutil.copymode(path, temporary)
        stat = os.stat(path)
        try:
            os.chown(temporary, stat.st_uid, stat.st_gid)
        except PermissionError:
            pass
    os.replace(temporary, path)


def main(argv):
    if len(argv) < 4 or argv[1] not in ("enable", "disable", "status"):
        sys.exit(__doc__)
    command, local_path, defaults_path = argv[1:4]
    backup_dir = argv[argv.index("--backup-dir") + 1] if "--backup-dir" in argv else ""
    defaults = load(defaults_path, required=True)
    local = load(local_path, required=False)
    before = copy.deepcopy(local)
    if command == "status":
        now = state(local, defaults)
        for name, on in sorted(now.items()):
            print("%s: %s" % (name, "local rules enabled on import" if on else "local rules not enabled on import"))
        return 0 if all(now.values()) else 1
    local = enable(local, defaults) if command == "enable" else disable(local, defaults)
    if local == before:
        print("no change needed")
        return 0
    save(local_path, local, backup_dir)
    print("updated %s" % local_path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
