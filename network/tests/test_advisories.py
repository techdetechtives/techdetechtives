# TechDetechtives network inventory: published advisory tests. Copyright (c) 2026 TechDetechtives. MIT licence.
"""Run with:  python3 -m unittest discover -s network/tests -v

The CISA advisories in tests/advisories/ are real (CSAF documents from
github.com/cisagov/CSAF, public domain). The JVN-style, RSS, Atom and KEV
samples below are made up for the tests: their vendors and CVE numbers are
fictional, so nothing here can be mistaken for a real advisory.
No feed is fetched from the internet: a stand-in fetcher hands out the files.
"""

import base64
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "network" / "app"))
sys.path.insert(0, str(ROOT / "ticketing" / "forwarder"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ["TD_ADV_FEEDS"] = "off"

import logging  # noqa: E402

import td_forwarder as fw  # noqa: E402

logging.getLogger("td_net").setLevel(logging.ERROR)
from fake_platform import FakePlatform  # noqa: E402
from td_net import advisories as adv  # noqa: E402
from td_net import outputs, web  # noqa: E402
from td_net.platform import Platform  # noqa: E402
from td_net.store import Store  # noqa: E402
from td_net.sync import Scope  # noqa: E402

HERE = Path(__file__).resolve().parent / "advisories"
NOW = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)

JVNDB = b"""<?xml version="1.0" encoding="UTF-8"?>
<rdf:RDF xmlns="http://purl.org/rss/1.0/" xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
  xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/"
  xmlns:sec="http://jvn.jp/rss/mod_sec/3.0/" xml:lang="ja">
 <channel rdf:about="https://jvndb.jvn.jp/en/rss/jvndb.rdf"><title>JVN iPedia</title></channel>
 <item rdf:about="https://jvndb.jvn.jp/en/contents/2026/JVNDB-2026-900001.html">
  <title>Examplesoft FieldLink gateway vulnerable to authentication bypass</title>
  <link>https://jvndb.jvn.jp/en/contents/2026/JVNDB-2026-900001.html</link>
  <description>FieldLink gateway provided by Examplesoft Co., Ltd. allows authentication bypass.</description>
  <sec:identifier>JVNDB-2026-900001</sec:identifier>
  <sec:references source="JVN" id="JVNVU#90000001">https://jvn.jp/en/vu/JVNVU90000001/</sec:references>
  <sec:references source="NVD" id="CVE-2099-10001">https://nvd.nist.gov/vuln/detail/CVE-2099-10001</sec:references>
  <sec:references id="CWE-287" title="Improper Authentication(CWE-287)">https://cwe.mitre.org/data/definitions/287.html</sec:references>
  <sec:cpe version="2.2" vendor="Examplesoft Co., Ltd." product="FieldLink gateway">cpe:/h:examplesoft:fieldlink_gateway</sec:cpe>
  <sec:cvss version="3.0" score="9.8" type="Base" severity="Critical" vector="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"/>
  <dc:date>2026-10-01T14:00+09:00</dc:date>
  <dcterms:issued>2026-09-30T14:00+09:00</dcterms:issued>
  <dcterms:modified>2026-10-01T14:00+09:00</dcterms:modified>
 </item>
 <item rdf:about="https://jvndb.jvn.jp/en/contents/2026/JVNDB-2026-900002.html">
  <title>Multiple vulnerabilities in Sampleweb CMS</title>
  <link>https://jvndb.jvn.jp/en/contents/2026/JVNDB-2026-900002.html</link>
  <description>Sampleweb CMS contains cross-site scripting.</description>
  <sec:identifier>JVNDB-2026-900002</sec:identifier>
  <sec:references source="NVD" id="CVE-2099-10002">https://nvd.nist.gov/vuln/detail/CVE-2099-10002</sec:references>
  <sec:cpe version="2.2" vendor="Sampleweb" product="Sampleweb CMS">cpe:/a:sampleweb:sampleweb_cms</sec:cpe>
  <sec:cvss version="3.0" score="5.4" type="Base" severity="Medium" vector="CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"/>
  <dcterms:issued>2026-10-02T14:00+09:00</dcterms:issued>
  <dcterms:modified>2026-10-02T14:00+09:00</dcterms:modified>
 </item>
</rdf:RDF>"""

JVN = b"""<?xml version="1.0" encoding="UTF-8"?>
<rdf:RDF xmlns="http://purl.org/rss/1.0/" xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
  xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">
 <item rdf:about="https://jvn.jp/en/vu/JVNVU90000001/">
  <title>Examplesoft FieldLink gateway vulnerable to authentication bypass</title>
  <link>https://jvn.jp/en/vu/JVNVU90000001/</link>
  <description>FieldLink gateway provided by Examplesoft contains a vulnerability.</description>
  <dc:identifier>JVNVU#90000001</dc:identifier>
  <dc:date>2026-09-30T14:00:00+09:00</dc:date>
  <dcterms:issued>2026-09-30T14:00:00+09:00</dcterms:issued>
  <dcterms:modified>2026-09-30T14:00:00+09:00</dcterms:modified>
 </item>
</rdf:RDF>"""

RSS2 = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>Example CERT</title>
<item><title>Advisory EX-2026-01: Demovendor PLC firmware</title><link>https://cert.example/ex-2026-01</link>
<guid>EX-2026-01</guid><pubDate>Mon, 05 Oct 2026 09:00:00 GMT</pubDate>
<description>&lt;p&gt;Fixes CVE-2099-10003 in Demovendor DV-500 controllers.&lt;/p&gt;</description></item>
</channel></rss>"""

ATOM = b"""<?xml version="1.0" encoding="utf-8"?><feed xmlns="http://www.w3.org/2005/Atom"><title>Example PSIRT</title>
<entry><id>urn:example:psirt:2026-7</id><title>PSIRT-2026-7 Demovendor HMI panel</title>
<link href="https://psirt.example/2026-7"/><updated>2026-10-04T10:00:00Z</updated>
<summary>CVE-2099-10004 allows a reboot of the panel.</summary></entry></feed>"""

KEV = json.dumps({"title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": "2099.01.01", "count": 1,
                  "vulnerabilities": [{"cveID": "CVE-2099-10001", "vendorProject": "Examplesoft", "product": "FieldLink gateway",
                                       "vulnerabilityName": "Examplesoft FieldLink Authentication Bypass", "dateAdded": "2026-10-03",
                                       "shortDescription": "Fictional entry for tests.", "requiredAction": "Apply updates.",
                                       "dueDate": "2026-10-24", "knownRansomwareCampaignUse": "Known"}]}).encode()

ROLIE_URL = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/cisa-csaf-ot-feed-tlp-white.json"
DOCS = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/"


class FakeFetcher:
    """Hands out files by address; counts requests; can answer 'unchanged' or fail."""

    def __init__(self, files: dict[str, bytes]) -> None:
        self.files, self.asked, self.failing, self.unchanged = dict(files), [], set(), set()

    def get(self, url, etag="", modified=""):
        self.asked.append(url)
        if url in self.failing:
            raise fw.HttpError(f"{url} could not be reached: refused", True)
        if url in self.unchanged and etag:
            return None, etag, modified
        if url not in self.files:
            raise fw.HttpError(f"{url} answered HTTP 404", False)
        return self.files[url], f'"{len(self.files[url])}"', ""


def settings(**overrides):
    values = dict(adv_enabled=True, adv_feeds=adv.parse_feeds(
        f"JVN iPedia=rss:https://jvndb.example/jvndb.rdf,JVN=rss:https://jvn.example/jvn.rdf,CISA KEV=kev:https://kev.example/kev.json,"
        f"CISA ICS=csaf-feed:{ROLIE_URL}"), adv_import_dir="", adv_watch=[], adv_proxy="", adv_fetch_hours=6,
        adv_recent_days=365, adv_max_documents=150, adv_finding_days=30, max_changes=100)
    values.update(overrides)
    return SimpleNamespace(**values)


def files() -> dict[str, bytes]:
    out = {"https://jvndb.example/jvndb.rdf": JVNDB, "https://jvn.example/jvn.rdf": JVN, "https://kev.example/kev.json": KEV,
           ROLIE_URL: (HERE / "cisa-csaf-ot-feed-trimmed.json").read_bytes()}
    for year, name in (("2021", "icsa-21-278-04"), ("2023", "icsa-23-194-06"), ("2025", "icsa-25-205-03")):
        out[f"{DOCS}{year}/{name}.json"] = (HERE / f"{name}.json").read_bytes()
    return out


class Formats(unittest.TestCase):
    def test_feed_settings(self):
        feeds = adv.parse_feeds(adv.DEFAULT_FEEDS)
        self.assertEqual([feed.name for feed in feeds], ["JPCERT/CC", "JVN", "JVN iPedia", "CISA ICS", "CISA KEV"])
        self.assertEqual(feeds[0].url, "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf")
        self.assertEqual(adv.parse_feeds("off"), [])
        for bad in ("x=rss:http://plain.example/feed", "x=html:https://a.example/", "x=rss:file:///etc/passwd", "=rss:https://a.example/",
                    "a=rss:https://a.example/,a=kev:https://b.example/"):
            with self.assertRaises(fw.ConfigError, msg=bad):
                adv.parse_feeds(bad)
        self.assertEqual(adv.parse_watch("Honeywell Experion PKS; Honeywell C300\n\n;Honeywell C300"),
                         ["Honeywell Experion PKS", "Honeywell C300"])

    def test_jvn_security_extension(self):
        first, second = adv.read_rss(JVNDB, "JVN iPedia")
        self.assertEqual(first["ident"], "JVNDB-2026-900001")
        self.assertEqual(first["score"], 9.8)
        self.assertIn("CVE-2099-10001", first["refs"])
        self.assertIn("JVNVU#90000001", first["refs"])
        self.assertNotIn("CWE-287", first["refs"])
        self.assertEqual(first["products"], [("Examplesoft Co., Ltd.", "FieldLink gateway", [])])
        self.assertEqual(first["published"], "2026-09-30T05:00:00Z")
        self.assertEqual(second["refs"], ["CVE-2099-10002"])

    def test_plain_rss_and_atom(self):
        (item,) = adv.read_rss(RSS2, "Example CERT")
        self.assertEqual((item["ident"], item["link"], item["published"]), ("EX-2026-01", "https://cert.example/ex-2026-01", "2026-10-05T09:00:00Z"))
        self.assertEqual(item["refs"], ["CVE-2099-10003"])
        self.assertNotIn("<p>", item["summary"])
        (entry,) = adv.read_rss(ATOM, "Example PSIRT")
        self.assertEqual((entry["link"], entry["updated"], entry["refs"]), ("https://psirt.example/2026-7", "2026-10-04T10:00:00Z", ["CVE-2099-10004"]))

    def test_real_cisa_csaf_advisories(self):
        item = adv.read_csaf((HERE / "icsa-21-278-04.json").read_bytes(), "CISA ICS")
        self.assertEqual(item["ident"], "ICSA-21-278-04")
        self.assertEqual(set(item["refs"]) & {"CVE-2021-38397", "CVE-2021-38395", "CVE-2021-38399"},
                         {"CVE-2021-38397", "CVE-2021-38395", "CVE-2021-38399"})
        products = {product: versions for vendor, product, versions in item["products"]}
        self.assertEqual(products["C300 and ACE controllers"], ["vers:all/*"])
        self.assertTrue(item["link"].startswith("https://www.cisa.gov/"))
        later = adv.read_csaf((HERE / "icsa-25-205-03.json").read_bytes(), "CISA ICS")
        ranges = {product: versions for vendor, product, versions in later["products"]}
        self.assertTrue(any(version.startswith("<R520.2") for version in ranges["Experion PKS"]))
        self.assertGreater(later["score"], 7)

    def test_kev_catalogue(self):
        (item,) = adv.read_kev(KEV, "CISA KEV")
        self.assertEqual((item["ident"], item["kev"], item["refs"]), ("CVE-2099-10001", 1, ["CVE-2099-10001"]))
        self.assertIn("ransomware", item["summary"])

    def test_xml_with_entities_is_refused(self):
        bomb = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><rss><channel><item><title>&b;</title></item></channel></rss>'
        with self.assertRaises(ValueError):
            adv.read_rss(bomb, "x")

    def test_versions(self):
        self.assertEqual(adv.version_status("R520.1", ["<R520.2_TCU9_Hot_Fix_1"]), "affected")
        self.assertEqual(adv.version_status("R531.1", ["<R520.2", "<R530_TCU3"]), "not affected")
        self.assertEqual(adv.version_status("1.5", ["vers:generic/>=1.0|<2.0"]), "affected")
        self.assertEqual(adv.version_status("2.0", ["vers:generic/>=1.0|<2.0"]), "not affected")
        self.assertEqual(adv.version_status("7.2", ["vers:all/*"]), "affected")
        self.assertEqual(adv.version_status("", ["<3.0"]), "check version")
        self.assertEqual(adv.version_status("3.1", []), "check version")
        self.assertEqual(adv.version_status("3.1", ["see vendor"]), "check version")
        self.assertEqual(adv.version_status("R530.4", ["<R530_TCU3"]), "check version")      # written too differently to compare


class Settings(unittest.TestCase):
    def test_settings_from_the_environment(self):
        from td_net.main import Config
        names = ("TD_ES_URL", "TD_ES_API_KEY", "TD_ADV_FEEDS", "TD_ADV_WATCH", "TD_ADV_PROXY")
        saved = {name: os.environ.get(name) for name in names}
        self.addCleanup(lambda: [os.environ.pop(name, None) if value is None else os.environ.__setitem__(name, value)
                                 for name, value in saved.items()])
        os.environ.update({"TD_ES_URL": "https://platform.example:9200", "TD_ES_API_KEY": "k", "TD_ADV_FEEDS": "",
                           "TD_ADV_WATCH": "Honeywell Experion PKS; Honeywell C300", "TD_ADV_PROXY": "http://proxy.example:3128"})
        config = Config(serving=False)
        self.assertEqual(len(config.adv_feeds), 5)                    # empty means the standard feeds
        self.assertEqual(config.adv_watch, ["Honeywell Experion PKS", "Honeywell C300"])
        os.environ["TD_ADV_FEEDS"] = "off"
        self.assertEqual(Config(serving=False).adv_feeds, [])
        os.environ["TD_ADV_PROXY"] = "proxy.example:3128; rm"
        with self.assertRaises(fw.ConfigError):
            Config(serving=False)


class Matching(unittest.TestCase):
    def setUp(self):
        self.fake = FakePlatform()
        self.addCleanup(self.fake.close)
        self.platform = Platform(self.fake.url, "read-key", "", True)
        self.store = Store(":memory:")
        self.addCleanup(self.store.close)
        adv.prepare(self.store)
        self.fetcher = FakeFetcher(files())
        # A C300 controller that announces itself, a gateway a scan found vulnerable, and an office PC.
        for ip in ("10.10.1.11", "10.10.1.20", "172.16.5.20"):
            self.store.see_asset(ip, "2026-10-01T08:00:00Z", True)
        self.store.describe_asset("10.10.1.11", vendor="Honeywell", model="C300", version="R511.5", identity_via="EtherNet/IP identity")
        self.store.describe_asset("172.16.5.20", maker="Dell Inc.", software="Sampleweb CMS 4.2")
        self.fake.add("greenbone.result", "2026-10-07T10:00:00Z", **{"host.ip": ["10.10.1.20"],
                      "vulnerability.id": ["CVE-2099-10001", "CVE-2099-99999"], "event.severity": 4})
        self.store.commit()

    def run_once(self, **overrides):
        return adv.run(self.store, self.platform, settings(**overrides), NOW, self.fetcher)

    def changes(self):
        return [dict(row) for row in self.store.changes(limit=100)]

    def test_matches_findings_models_and_watch_list(self):
        summary = self.run_once(adv_watch=["Honeywell Experion PKS", "Nothingmade Widget"])
        self.assertEqual(summary["errors"], [])
        changes = {(row["kind"], row["ip"]): row for row in self.changes()}

        # The scan found a CVE that JVN iPedia, JVN and CISA's catalogue all describe; CISA says it is exploited.
        found = changes[("advisory_device", "10.10.1.20")]
        self.assertEqual(found["severity"], adv.HIGH)
        self.assertEqual(found["title"], "Published advisory for a vulnerability found on a device")
        self.assertIn("JVNDB-2026-900001", found["detail"])
        self.assertIn("[known to be exploited]", found["detail"])

        # The C300 is named by ICSA-21-278-04 for all versions (CVSS 9.8 there makes it high).
        c300 = changes[("advisory_device", "10.10.1.11")]
        self.assertIn("ICSA-21-278-04", c300["detail"])
        self.assertIn("version: affected", c300["detail"])

        # The site's list: Experion PKS is named by all three Honeywell advisories; the made-up product by none.
        watched = changes[("advisory_watched_product", "")]
        self.assertIn("Experion PKS", watched["title"])
        self.assertIn("3 published advisories", watched["detail"])
        self.assertFalse(any("Nothingmade" in row["title"] for row in self.changes()))

        # A software banner is shown as possible, and raises nothing.
        rows = adv.match_rows(self.store, target="172.16.5.20")
        self.assertEqual([(row["how"], row["ident"]) for row in rows], [("software", "JVNDB-2026-900002")])
        self.assertNotIn(("advisory_device", "172.16.5.20"), changes)

        # Nothing new on the next pass, and nothing fetched again before it is due.
        asked = len(self.fetcher.asked)
        again = adv.run(self.store, self.platform, settings(adv_watch=["Honeywell Experion PKS"]), NOW + timedelta(minutes=5), self.fetcher)
        self.assertEqual(again["changes"], 0)
        self.assertEqual(len(self.fetcher.asked), asked)

    def test_version_outside_the_range_raises_nothing(self):
        self.store.describe_asset("10.10.1.11", model="Experion PKS", version="R531.1")
        self.store.commit()
        self.run_once()
        rows = [row for row in adv.match_rows(self.store, target="10.10.1.11") if row["ident"] == "ICSA-25-205-03"]
        self.assertEqual(rows[0]["status"], "not affected")
        self.assertFalse(any("ICSA-25-205-03" in row["detail"] for row in self.changes() if row["ip"] == "10.10.1.11"))

    def test_old_listings_are_fetched_only_for_vendors_seen_here(self):
        self.store.describe_asset("10.10.1.11", vendor="", model="")
        self.store.db.execute("UPDATE assets SET vendor = ''")
        self.store.commit()
        summary = self.run_once(adv_recent_days=30)
        fetched = [url for url in self.fetcher.asked if url.startswith(DOCS + "20")]
        # Only the two advisories of the last 30 days are asked for (the stand-in does not have them: 404, noted, not retried).
        self.assertEqual(sorted(fetched), [DOCS + "2026/icsa-26-279-02.json", DOCS + "2026/icsa-26-280-01.json"])
        self.assertEqual(summary["errors"], [])
        titles = {row["ident"]: row["detail"] for row in adv.advisory_rows(self.store, source="CISA ICS")}
        self.assertEqual(titles["ICSA-21-278-04"], "title")
        # Once a device says it is made by Honeywell, its advisories are fetched in full.
        self.store.describe_asset("10.10.1.11", vendor="Honeywell", model="C300")
        self.store.commit()
        adv.run(self.store, self.platform, settings(adv_recent_days=30), NOW + timedelta(minutes=5), self.fetcher)
        titles = {row["ident"]: row["detail"] for row in adv.advisory_rows(self.store, source="CISA ICS")}
        self.assertEqual(titles["ICSA-21-278-04"], "full")

    def test_document_limit_and_backlog(self):
        summary = self.run_once(adv_max_documents=1)
        self.assertLessEqual(summary["documents"], 1)
        self.assertGreater(summary["waiting"], 0)
        # A backlog makes the next pass fetch more, without waiting for the usual interval.
        later = adv.run(self.store, self.platform, settings(adv_max_documents=10), NOW + timedelta(minutes=5), self.fetcher)
        self.assertGreater(later["documents"], 0)

    def test_listing_may_only_point_at_its_own_host(self):
        feed = json.loads(files()[ROLIE_URL])
        feed["feed"]["entry"][0]["content"]["src"] = "https://elsewhere.example/icsa.json"
        self.fetcher.files[ROLIE_URL] = json.dumps(feed).encode()
        self.run_once()
        self.assertNotIn("https://elsewhere.example/icsa.json", self.fetcher.asked)

    def test_feed_problems_are_reported_and_retried(self):
        self.fetcher.failing.add("https://jvn.example/jvn.rdf")
        summary = self.run_once()
        self.assertTrue(any("JVN" in error for error in summary["errors"]))
        self.assertGreater(adv.overview(self.store)["advisories"], 0)        # the others were read
        self.fetcher.failing.clear()
        self.fetcher.unchanged.update(self.fetcher.files)
        mark = len(self.fetcher.asked)
        soon = adv.run(self.store, self.platform, settings(), NOW + timedelta(minutes=5), self.fetcher)
        self.assertNotIn("https://jvn.example/jvn.rdf", self.fetcher.asked[mark:])  # a failed feed waits half an hour
        self.assertEqual(soon["errors"], [])
        again = adv.run(self.store, self.platform, settings(), NOW + timedelta(minutes=31), self.fetcher)
        self.assertEqual(again["errors"], [])
        self.assertIn("https://jvn.example/jvn.rdf", self.fetcher.asked[mark:])
        feeds = self.store.meta("advisory_feeds")
        self.assertEqual(feeds["JVN"]["error"], "")

    def test_unreadable_feed(self):
        self.fetcher.files["https://kev.example/kev.json"] = b"<html>maintenance</html>"
        summary = self.run_once()
        self.assertTrue(any("CISA KEV" in error for error in summary["errors"]))

    def test_platform_unreachable_keeps_earlier_matches(self):
        self.run_once()
        before = len(adv.match_rows(self.store, target="10.10.1.20"))
        self.fake.fail_with = 503
        summary = adv.run(self.store, self.platform, settings(), NOW + timedelta(minutes=5), self.fetcher)
        self.assertTrue(any("vulnerability findings" in error for error in summary["errors"]))
        self.assertEqual(len(adv.match_rows(self.store, target="10.10.1.20")), before)

    def test_import_folder(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "psirt.atom").write_bytes(ATOM)
            Path(folder, "icsa-21-278-04.json").write_bytes((HERE / "icsa-21-278-04.json").read_bytes())
            Path(folder, "notes.txt").write_text("ignored")
            Path(folder, "broken.json").write_text("{")
            summary = adv.run(self.store, None, settings(adv_feeds=[], adv_import_dir=folder), NOW, self.fetcher)
            self.assertEqual(self.fetcher.asked, [])                  # no feeds: nothing fetched
            idents = {row["ident"] for row in adv.advisory_rows(self.store)}
            self.assertEqual(idents, {"urn:example:psirt:2026-7", "ICSA-21-278-04"})
            self.assertTrue(any("broken.json" in error for error in summary["errors"]))
            self.assertTrue(any("ICSA-21-278-04" in row["detail"] for row in self.changes()))
            # Files are read again only when they change.
            again = adv.run(self.store, None, settings(adv_feeds=[], adv_import_dir=folder), NOW + timedelta(hours=7), self.fetcher)
            self.assertEqual(again["new"], 0)

    def test_turned_off(self):
        summary = self.run_once(adv_enabled=False)
        self.assertEqual(self.fetcher.asked, [])
        self.assertEqual(summary["changes"], 0)

    def test_changes_become_alerts(self):
        self.run_once()
        row = next(row for row in self.store.changes(limit=50) if row["ip"] == "10.10.1.20")
        _, document = outputs.to_document(row, "inventory", NOW)
        self.assertEqual(document["event"]["action"], "advisory_device")
        self.assertEqual(document["event"]["severity"], 3)
        self.assertEqual(document["source"]["ip"], "10.10.1.20")
        self.assertIn("alert", document["tags"])


class Pages(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.db = str(Path(folder.name) / "net.db")
        store = Store(self.db)
        adv.prepare(store)
        store.see_asset("10.10.1.11", "2026-10-01T08:00:00Z", True)
        store.describe_asset("10.10.1.11", vendor="Honeywell", model="C300", version="R511.5", identity_via="EtherNet/IP identity")
        hostile = adv.advisory("Example CERT", "EX-1", "<script>alert(1)</script> Honeywell C300", "javascript:alert(1)",
                               "2026-10-01T00:00:00Z", summary="<img src=x onerror=alert(1)>")
        adv.save(store, hostile, NOW)
        adv.save(store, adv.read_csaf((HERE / "icsa-21-278-04.json").read_bytes(), "CISA ICS"), NOW)
        store.commit()
        adv.record_matches(store, adv.find_matches(store, {}, ["Honeywell C300"]), NOW, 100)
        store.close()
        self.config = SimpleNamespace(web_user="analyst", web_password="correct-horse-battery", brand_name="TechDetechtives",
                                      brand_header="#0b0b0d", brand_accent="#f60411", brand_logo="/nonexistent", soc_url="",
                                      adv_enabled=True, adv_watch=["Honeywell C300"])
        self.server = web.make_server(SimpleNamespace(**vars(self.config), web_bind="127.0.0.1", web_port=0),
                                      lambda: Store(self.db), Scope())
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def get(self, path):
        request = urllib.request.Request(self.base + path)
        request.add_header("Authorization", "Basic " + base64.b64encode(b"analyst:correct-horse-battery").decode())
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.read().decode()

    def test_pages(self):
        page = self.get("/advisories")
        self.assertIn("ICSA-21-278-04", page)
        self.assertIn("C300 and ACE controllers", page)
        self.assertNotIn("<script>", page)
        detail = self.get("/advisories/" + urllib.parse.quote("CISA ICS|ICSA-21-278-04", safe=""))
        self.assertIn("CVE-2021-38397", detail)
        self.assertIn("https://www.cisa.gov/", detail)
        self.assertIn("10.10.1.11", detail)
        hostile = self.get("/advisories/" + urllib.parse.quote("Example CERT|EX-1", safe=""))
        self.assertNotIn('href="javascript', hostile)
        self.assertNotIn("<img src=x", hostile)
        device = self.get("/devices/10.10.1.11")
        self.assertIn("Published advisories", device)
        self.assertIn("ICSA-21-278-04", device)
        self.assertIn("Published advisories", self.get("/"))
        self.assertIn("Matched", self.get("/advisories?show=matching&q=C300").replace("matched", "Matched"))
        with self.assertRaises(urllib.error.HTTPError):
            self.get("/advisories/nothing")


import urllib.error  # noqa: E402
import urllib.parse  # noqa: E402

if __name__ == "__main__":
    unittest.main()
