# TechDetechtives platform tests. Copyright (c) 2026 TechDetechtives. MIT licence.
"""Run with:  python3 -m unittest discover -s platform/tests -v"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

TOOL = str(Path(__file__).resolve().parents[1] / "local_rules_setting.py")
DEFAULT_BLOCK = '# Core\n- ruleset: ["core"]\n  level: ["critical"]\n  product: ["*"]\n  category: ["*"]\n  service: ["*"]'
DEFAULTS = {"soc": {"enabled": True, "config": {"server": {"modules": {
    "elastalertengine": {"autoUpdateEnabled": True,
                         "enabledSigmaRules": {"default": DEFAULT_BLOCK, "so-eval": DEFAULT_BLOCK}},
    "strelkaengine": {"autoEnabledYaraRules": ["securityonion-yara"]}}}}}}


class LocalRulesSetting(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.local = os.path.join(self.dir.name, "soc_soc.sls")
        self.defaults = os.path.join(self.dir.name, "defaults.yaml")
        Path(self.defaults).write_text(yaml.safe_dump(DEFAULTS))

    def run_tool(self, command, *extra):
        return subprocess.run([sys.executable, TOOL, command, self.local, self.defaults, *extra],
                              capture_output=True, text=True)

    def settings(self):
        return yaml.safe_load(Path(self.local).read_text())

    def modules(self):
        return self.settings()["soc"]["config"]["server"]["modules"]

    def test_enable_on_a_platform_with_no_local_settings_file(self):
        self.assertEqual(self.run_tool("status").returncode, 1)
        result = self.run_tool("enable")
        self.assertEqual(result.returncode, 0, result.stderr)
        sigma = self.modules()["elastalertengine"]["enabledSigmaRules"]
        for role in ("default", "so-eval"):
            self.assertTrue(sigma[role].startswith(DEFAULT_BLOCK))            # the platform's own entries are kept
            entries = yaml.safe_load(sigma[role])                             # and the result is still a valid list
            self.assertEqual(entries[-1]["ruleset"], ["local-sigma"])
            self.assertIn("medium", entries[-1]["level"])
        self.assertEqual(self.modules()["strelkaengine"]["autoEnabledYaraRules"], ["securityonion-yara", "local-yara"])
        self.assertEqual(self.run_tool("status").returncode, 0)

    def test_other_local_settings_are_untouched(self):
        mine = {"soc": {"config": {"server": {"modules": {
            "elastalertengine": {"allowRegex": "SecurityOnion"},
            "strelkaengine": {"autoEnabledYaraRules": ["securityonion-yara", "my-ruleset"]}}}},
            "telemetryEnabled": False}}
        Path(self.local).write_text(yaml.safe_dump(mine))
        os.chmod(self.local, 0o640)
        self.run_tool("enable")
        data = self.settings()
        self.assertEqual(data["soc"]["telemetryEnabled"], False)
        self.assertEqual(self.modules()["elastalertengine"]["allowRegex"], "SecurityOnion")
        self.assertEqual(self.modules()["strelkaengine"]["autoEnabledYaraRules"],
                         ["securityonion-yara", "my-ruleset", "local-yara"])
        self.assertEqual(oct(os.stat(self.local).st_mode & 0o777), "0o640")   # permissions preserved

    def test_enable_twice_changes_nothing_the_second_time(self):
        self.run_tool("enable")
        first = Path(self.local).read_text()
        result = self.run_tool("enable")
        self.assertIn("no change needed", result.stdout)
        self.assertEqual(Path(self.local).read_text(), first)
        self.assertEqual(first.count("local-sigma"), 2)                        # once per role, not duplicated

    def test_disable_restores_the_defaults(self):
        self.run_tool("enable")
        self.run_tool("disable")
        self.assertIn(self.settings(), ({}, None))                             # nothing left overriding the defaults
        self.assertEqual(self.run_tool("status").returncode, 1)

    def test_disable_keeps_the_owners_own_changes(self):
        custom = DEFAULT_BLOCK + '\n- ruleset: ["core"]\n  level: ["high"]\n  product: ["windows"]\n  category: ["*"]\n  service: ["*"]'
        Path(self.local).write_text(yaml.safe_dump({"soc": {"config": {"server": {"modules": {
            "elastalertengine": {"enabledSigmaRules": {"default": custom}}}}}}}))
        self.run_tool("enable")
        self.run_tool("disable")
        sigma = self.modules()["elastalertengine"]["enabledSigmaRules"]
        self.assertEqual(sigma, {"default": custom})

    def test_backup_is_written_before_changing_an_existing_file(self):
        Path(self.local).write_text(yaml.safe_dump({"soc": {"telemetryEnabled": False}}))
        backups = os.path.join(self.dir.name, "backups")
        self.run_tool("enable", "--backup-dir", backups)
        saved = os.listdir(backups)
        self.assertEqual(len(saved), 1)
        self.assertEqual(yaml.safe_load(Path(backups, saved[0]).read_text()), {"soc": {"telemetryEnabled": False}})

    def test_unknown_platform_layout_changes_nothing(self):
        Path(self.defaults).write_text(yaml.safe_dump({"soc": {"config": {}}}))
        result = self.run_tool("enable")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("nothing was changed", result.stderr)
        self.assertFalse(os.path.exists(self.local))

    def test_broken_local_file_is_not_overwritten(self):
        Path(self.local).write_text("- just\n- a list\n")
        result = self.run_tool("enable")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(Path(self.local).read_text(), "- just\n- a list\n")


if __name__ == "__main__":
    unittest.main()
