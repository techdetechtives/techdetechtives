# TechDetechtives rule factory tests. Copyright (c) 2026 TechDetechtives. MIT licence.
"""Run from the repository root:  python3 -m unittest discover -s rulefactory/tests -v

Offline: the KEV feed and the exploit templates come from fixtures/.
"""
import json
import re
import sys
import unittest
from datetime import date
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "platform" / "tests"))

from rulefactory import draft, factory, feeds, nuclei  # noqa: E402
from rulefactory.common import suricata_text  # noqa: E402
import test_detection_rules as rules  # noqa: E402  (module import, so its tests are not collected twice)

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def kev_sample():
    data = json.loads((FIXTURES / "kev-sample.json").read_text())
    for entry in data["vulnerabilities"]:
        if entry["dateAdded"] == "TODAY":
            entry["dateAdded"] = date.today().isoformat()
    return data["vulnerabilities"]


CONFLUENCE = feeds.Vulnerability(cve="CVE-2022-26134", vendor="Atlassian", product="Confluence Server and Data Center",
                                 name="Atlassian Confluence Server and Data Center Remote Code Execution Vulnerability",
                                 cwes=["CWE-917"], in_kev=True)


class Feeds(unittest.TestCase):
    def test_remote_code_execution_is_recognised(self):
        self.assertTrue(feeds.Vulnerability(cve="CVE-2024-4577", cwes=["CWE-78"]).is_rce)
        self.assertTrue(feeds.Vulnerability(cve="CVE-2024-1", description="allows remote attackers to execute arbitrary code").is_rce)
        self.assertFalse(feeds.Vulnerability(cve="CVE-2023-0001", cwes=["CWE-200"], description="exposes memory").is_rce)

    def test_recent_rce_picks_recent_code_execution_only(self):
        with mock.patch.object(feeds, "kev", kev_sample), mock.patch.object(feeds, "nvd", lambda cve: {}):
            picked = [v.cve for v in feeds.recent_rce(14, [])]
            self.assertEqual(sorted(picked), ["CVE-2022-26134", "CVE-2024-4577"])
            self.assertEqual([v.cve for v in feeds.recent_rce(14, ["confluence"])], ["CVE-2022-26134"])


class Templates(unittest.TestCase):
    def test_variables_become_fixed_stand_ins(self):
        template = nuclei.load(FIXTURES / "CVE-2021-44228.yaml")
        self.assertTrue(template.requests)
        for request in template.requests:
            text = request.uri + json.dumps(request.headers) + request.body
            self.assertNotIn("{{", text)
        self.assertIn("jndi:ldap", template.requests[0].uri)


class Drafting(unittest.TestCase):
    def test_suricata_draft_from_the_exploit_request(self):
        template = nuclei.load(FIXTURES / "CVE-2022-26134.yaml")
        made = draft.suricata(CONFLUENCE, template, sid=1900777)
        self.assertIsNotNone(made)
        rule = made.text.strip().splitlines()[-1]
        self.assertRegex(rule, rules.SuricataRules.HEADER)
        self.assertIn("@java.lang.Runtime@getRuntime", rule)
        self.assertIn("sid:1900777;", rule)
        self.assertIn("reference:cve,2022-26134;", rule)
        self.assertNotIn("TDVAR", rule)
        positives = [c for c in made.cases["suricata"] if c["alerts"]]
        negatives = [c for c in made.cases["suricata"] if not c["alerts"]]
        self.assertGreaterEqual(len(positives), 1)
        self.assertGreaterEqual(len(negatives), 1)
        self.assertEqual(made.cases["covers"], [1900777])

    def test_suricata_draft_for_a_payload_in_the_address(self):
        template = nuclei.load(FIXTURES / "CVE-2021-44228.yaml")
        log4j = feeds.Vulnerability(cve="CVE-2021-44228", vendor="Apache", product="Log4j2", name="Apache Log4j2 Remote Code Execution Vulnerability")
        made = draft.suricata(log4j, template, sid=1900778)
        self.assertIn('content:"jndi:ldap:"', made.text)

    def test_sigma_draft_matches_its_own_cases(self):
        made = draft.sigma(CONFLUENCE)
        self.assertIsNotNone(made)
        import yaml
        rule = yaml.safe_load(made.text)
        self.assertTrue(rule["title"].startswith("TechDetechtives - "))
        for name, case in made.cases["sigma"].items():
            for event in case["match"]:
                self.assertTrue(rules.sigma_matches(rule, event), event)
            for event in case["nomatch"]:
                self.assertFalse(rules.sigma_matches(rule, event), event)
        self.assertEqual(made.validation[0]["title"], rule["title"])

    def test_no_sigma_draft_for_unknown_products(self):
        self.assertIsNone(draft.sigma(feeds.Vulnerability(cve="CVE-2024-9999", vendor="Nobody", product="Nothing")))

    def test_yara_draft_from_an_uploaded_script(self):
        template = nuclei.load(FIXTURES / "upload-template.yaml")
        made = draft.yara(feeds.Vulnerability(cve="CVE-2099-0001", vendor="Example", product="Portal"), template)
        self.assertIsNotNone(made)
        self.assertIn("rule TechDetechtives_CVE_2099_0001_Uploaded_Script", made.text)
        self.assertIn("shell_exec", made.text)
        self.assertIn("filesize < 1MB", made.text)

    def test_no_yara_draft_without_an_upload(self):
        self.assertIsNone(draft.yara(CONFLUENCE, nuclei.load(FIXTURES / "CVE-2022-26134.yaml")))

    def test_sid_is_stable_and_avoids_collisions(self):
        first = draft.allocate_sid("CVE-2022-26134", taken=set())
        self.assertEqual(first, draft.allocate_sid("CVE-2022-26134", taken=set()))
        self.assertTrue(draft.SID_FIRST <= first <= draft.SID_LAST)
        self.assertNotEqual(first, draft.allocate_sid("CVE-2022-26134", taken={first}))

    def test_reserved_characters_become_hex(self):
        self.assertEqual(suricata_text('a"b;c|d\\e'), "a|22|b|3B|c|7C|d|5C|e")
        self.assertEqual(suricata_text('";'), "|22 3B|")


class Factory(unittest.TestCase):
    def test_a_cve_our_rules_already_name_is_not_redrafted(self):
        result = factory.build("CVE-2024-4577", offline=True)
        self.assertTrue(any("techdetechtives-web.rules" in path for path in result.already))
        self.assertEqual(result.drafts, [])

    def test_report_says_what_was_searched_and_drafted(self):
        result = factory.build("CVE-2022-26134", nuclei_path=FIXTURES / "CVE-2022-26134.yaml", offline=True, vuln=CONFLUENCE)
        self.assertEqual({d.kind for d in result.drafts}, {"suricata", "sigma"})
        report = factory.render_report(result)
        self.assertIn("Not searched: ET Open, SigmaHQ and YARA Forge (running offline)", report)
        self.assertIn("Suricata sid", report)
        self.assertIn("Before approving", report)
        self.assertNotRegex(report, re.compile(r"\b10\.\d+\.\d+\.\d+\b"), "no internal addresses in a public report")


if __name__ == "__main__":
    unittest.main()
