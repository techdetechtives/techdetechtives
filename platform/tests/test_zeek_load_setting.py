# TechDetechtives: tests for the helper that edits the list of scripts Zeek loads.
# Copyright (c) 2026 TechDetechtives. MIT licence.
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

TOOL = Path(__file__).resolve().parents[1] / "zeek_load_setting.py"
DEFAULTS = {"zeek": {"enabled": False, "config": {"local": {
    "load": ["misc/loaded-scripts", "protocols/conn/known-hosts", "oui-logging"],
    "redef": ["LogAscii::use_json = T;"]}}}}
ENTRY = "custom/techdetechtives"


class ZeekLoadSetting(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.local = Path(self.folder.name) / "soc_zeek.sls"
        self.defaults = Path(self.folder.name) / "defaults.yaml"
        self.defaults.write_text(yaml.safe_dump(DEFAULTS))

    def run_tool(self, command, *extra):
        return subprocess.run([sys.executable, str(TOOL), command, str(self.local), str(self.defaults), *extra],
                              capture_output=True, text=True)

    def load_list(self):
        data = yaml.safe_load(self.local.read_text()) or {}
        return data.get("zeek", {}).get("config", {}).get("local", {}).get("load")

    def test_on_writes_the_default_list_plus_the_watch(self):
        self.assertEqual(self.run_tool("status").returncode, 1)
        self.assertEqual(self.run_tool("on").returncode, 0)
        self.assertEqual(self.load_list(), DEFAULTS["zeek"]["config"]["local"]["load"] + [ENTRY])
        self.assertEqual(self.run_tool("status").returncode, 0)
        self.assertIn("no change needed", self.run_tool("on").stdout)

    def test_off_removes_the_local_value_when_only_the_default_is_left(self):
        self.local.write_text("zeek:\n  config:\n    node:\n      lb_procs: 2\n")
        self.run_tool("on")
        self.run_tool("off")
        self.assertEqual(yaml.safe_load(self.local.read_text()), {"zeek": {"config": {"node": {"lb_procs": 2}}}})

    def test_a_list_the_administrator_changed_is_kept(self):
        own = ["misc/loaded-scripts", "custom/site-policy"]
        self.local.write_text(yaml.safe_dump({"zeek": {"config": {"local": {"load": own}}}}))
        self.run_tool("on")
        self.assertEqual(self.load_list(), own + [ENTRY])
        self.run_tool("off")
        self.assertEqual(self.load_list(), own)

    def test_off_without_a_local_value_changes_nothing(self):
        self.local.write_text("")
        self.assertIn("no change needed", self.run_tool("off").stdout)
        self.assertEqual(self.local.read_text(), "")

    def test_backup_is_written_before_a_change(self):
        self.local.write_text("zeek:\n  config:\n    node:\n      lb_procs: 2\n")
        backups = Path(self.folder.name) / "backups"
        self.run_tool("on", "--backup-dir", str(backups))
        saved = list(backups.glob("soc_zeek.sls.*"))
        self.assertEqual(len(saved), 1)
        self.assertNotIn(ENTRY, saved[0].read_text())

    def test_off_after_an_upgrade_changed_the_default_list(self):
        state = str(Path(self.folder.name) / "state")
        self.run_tool("on", "--state", state)
        upgraded = {"zeek": {"config": {"local": {"load": DEFAULTS["zeek"]["config"]["local"]["load"] + ["new-in-upgrade"]}}}}
        self.defaults.write_text(yaml.safe_dump(upgraded))
        self.run_tool("off", "--state", state)
        self.assertIsNone(self.load_list())                    # the platform's new list applies again
        self.assertFalse(Path(state).exists())

    def test_on_again_after_an_upgrade_carries_the_new_default(self):
        state = str(Path(self.folder.name) / "state")
        self.run_tool("on", "--state", state)
        upgraded = DEFAULTS["zeek"]["config"]["local"]["load"] + ["new-in-upgrade"]
        self.defaults.write_text(yaml.safe_dump({"zeek": {"config": {"local": {"load": upgraded}}}}))
        self.run_tool("on", "--state", state)
        self.assertEqual(self.load_list(), upgraded + [ENTRY])

    def test_a_list_edited_while_the_watch_is_on_is_never_dropped(self):
        state = str(Path(self.folder.name) / "state")
        self.run_tool("on", "--state", state)
        edited = self.load_list() + ["custom/site-policy"]
        self.local.write_text(yaml.safe_dump({"zeek": {"config": {"local": {"load": edited}}}}))
        self.run_tool("on", "--state", state)
        self.assertEqual(self.load_list(), edited)
        self.run_tool("off", "--state", state)
        self.assertEqual(self.load_list(), [item for item in edited if item != ENTRY])

    def test_unknown_platform_layout_is_refused(self):
        self.defaults.write_text("zeek:\n  config: {}\n")
        result = self.run_tool("on")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.local.exists())


if __name__ == "__main__":
    unittest.main()
