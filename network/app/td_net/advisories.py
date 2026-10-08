# TechDetechtives network inventory: published security advisories.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Published advisories (JPCERT/CC, JVN, CISA ICS advisories, CISA's catalogue
of exploited vulnerabilities, or any feed in the same formats) matched against
what this site has.

Three ways an advisory can concern this site:

  finding   a vulnerability scan sent to the platform found one of the
            advisory's CVEs on a device
  device    a device announced a vendor and model (EtherNet/IP identity,
            BACnet I-Am) that the advisory names
  watch     the advisory names a product on the site's own list of what it
            runs (TD_ADV_WATCH), for products that do not announce themselves

Advisories are read from the internet (TD_ADV_FEEDS) and from files dropped
into a folder (TD_ADV_IMPORT_DIR), for sites that are not connected. Nothing is
sent to the monitored network, and nothing about the site is sent to the
publishers: each feed is a plain download.

Formats read:
  rss        RSS 1.0 (RDF), RSS 2.0 and Atom. JVN's security extension
             (sec:identifier, sec:references, sec:cpe, sec:cvss) is read when
             present, as in the JVN iPedia feed.
  kev        CISA's Known Exploited Vulnerabilities catalogue (JSON).
  csaf-feed  a ROLIE feed listing CSAF 2.0 advisories, as CISA publishes its
             ICS advisories. The advisories themselves are fetched one by one.
  csaf       a single CSAF 2.0 advisory (JSON).
"""

from __future__ import annotations

import email.utils
import json
import logging
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ElementTree
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

import td_forwarder as fw

from . import VERSION
from .store import Store, stamp

log = logging.getLogger("td_net")

LOW, MEDIUM, HIGH = 1, 2, 3

DEFAULT_FEEDS = ",".join([
    "JPCERT/CC=rss:https://www.jpcert.or.jp/english/rss/jpcert-en.rdf",
    "JVN=rss:https://jvn.jp/en/rss/jvn.rdf",
    "JVN iPedia=rss:https://jvndb.jvn.jp/en/rss/jvndb.rdf",
    "CISA ICS=csaf-feed:https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/cisa-csaf-ot-feed-tlp-white.json",
    "CISA KEV=kev:https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
])
KINDS = ("rss", "kev", "csaf-feed", "csaf")
MAX_BYTES = 25 * 1024 * 1024

CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
OTHER_IDS = re.compile(r"\b(?:JVN(?:VU|TA)?#\d{6,8}|JVNDB-\d{4}-\d{6}|ICSA-\d{2}-\d{3}-\d{2}[A-Z]?|ICSMA-\d{2}-\d{3}-\d{2}[A-Z]?)\b")

SCHEMA = """
CREATE TABLE IF NOT EXISTS advisories (
    id TEXT PRIMARY KEY, source TEXT, ident TEXT, title TEXT, link TEXT, published TEXT, updated TEXT,
    summary TEXT DEFAULT '', score REAL DEFAULT 0, kev INTEGER DEFAULT 0,
    document_url TEXT DEFAULT '', detail TEXT DEFAULT 'full', fetched TEXT
);
CREATE INDEX IF NOT EXISTS advisories_published ON advisories (published);
CREATE TABLE IF NOT EXISTS advisory_refs (
    advisory TEXT NOT NULL, ref TEXT NOT NULL, PRIMARY KEY (advisory, ref)
);
CREATE INDEX IF NOT EXISTS advisory_refs_ref ON advisory_refs (ref);
CREATE TABLE IF NOT EXISTS advisory_products (
    advisory TEXT NOT NULL, vendor TEXT NOT NULL, product TEXT NOT NULL, versions TEXT DEFAULT '[]',
    PRIMARY KEY (advisory, vendor, product)
);
CREATE TABLE IF NOT EXISTS advisory_matches (
    advisory TEXT NOT NULL, target TEXT NOT NULL, how TEXT NOT NULL, status TEXT, detail TEXT,
    first_seen TEXT, last_seen TEXT, PRIMARY KEY (advisory, target, how)
);
CREATE INDEX IF NOT EXISTS advisory_matches_target ON advisory_matches (target);
"""


# ---- settings ---------------------------------------------------------------------
class Feed:
    def __init__(self, name: str, kind: str, url: str) -> None:
        self.name, self.kind, self.url = name, kind, url


def parse_feeds(text: str) -> list[Feed]:
    """'NAME=KIND:URL,NAME=KIND:URL'. Empty or 'off' means no feeds from the internet."""
    if text.strip().lower() in ("", "off", "none", "0"):
        return []
    feeds = []
    for part in [item.strip() for item in text.split(",") if item.strip()]:
        name, _, rest = part.partition("=")
        kind, _, url = rest.partition(":")
        name, kind, url = name.strip()[:40], kind.strip().lower(), url.strip()
        if not name or kind not in KINDS or not re.fullmatch(r"https://[A-Za-z0-9.-]+(:\d+)?/[A-Za-z0-9._~:/?#=&%+-]*", url):
            raise fw.ConfigError(f"TD_ADV_FEEDS: '{part}' is not NAME=KIND:https://ADDRESS (KIND is one of {', '.join(KINDS)})")
        if any(feed.name == name for feed in feeds):
            raise fw.ConfigError(f"TD_ADV_FEEDS: the name '{name}' is used twice")
        feeds.append(Feed(name, kind, url))
    return feeds


def parse_watch(text: str) -> list[str]:
    """Products the site runs, separated by ';' or new lines: 'Honeywell Experion PKS; Honeywell C300'."""
    phrases = []
    for part in re.split(r"[;\n]", text or ""):
        phrase = " ".join(part.split())[:80]
        if phrase and len(tokens(phrase)) and phrase not in phrases:
            phrases.append(phrase)
    return phrases[:100]


# ---- words --------------------------------------------------------------------------
LEGAL = {"inc", "corp", "corporation", "co", "ltd", "limited", "llc", "gmbh", "ag", "sa", "kg", "bv", "nv", "oy", "ab",
         "spa", "srl", "kk", "international", "the", "company", "group", "holdings"}
GENERIC = {"series", "firmware", "software", "controller", "controllers", "module", "modules", "and", "all", "versions",
           "version", "the", "for", "with", "system", "systems", "device", "devices", "products", "product", "plc", "cpu",
           "of", "in", "on", "a", "an", "by", "multiple", "other", "family", "platform", "server", "client", "web", "unit",
           "station", "edition", "model", "models", "hardware", "application", "tool", "tools", "terminal", "s"}


def tokens(text: Any) -> list[str]:
    return [word for word in re.split(r"[^a-z0-9]+", str(text or "").lower()) if word]


def vendor_key(text: Any) -> str:
    """'Rockwell Automation/Allen-Bradley' -> 'rockwell', 'KEYENCE CORPORATION.' -> 'keyence'."""
    for word in tokens(text):
        if word not in LEGAL:
            return word
    return ""


def significant(text: Any) -> set[str]:
    return {word for word in tokens(text) if word not in GENERIC and word not in LEGAL}


def distinctive(words: set[str]) -> bool:
    """Enough to name a product: a word with a digit in it, or a word of four letters or more."""
    return any(any(ch.isdigit() for ch in word) or len(word) >= 4 for word in words)


# ---- versions -------------------------------------------------------------------------
def version_key(text: str) -> tuple:
    parts = re.findall(r"\d+|[a-z]+", text.lower().lstrip("v"))
    return tuple((0, int(part)) if part.isdigit() else (1, part) for part in parts)


def _compare(left: tuple, right: tuple) -> Optional[int]:
    """-1, 0 or 1; None when the two are written too differently to compare
    (a number in one where the other has letters, as in R530.4 against R530 TCU3)."""
    for a, b in zip(left, right):
        if a == b:
            continue
        if a[0] != b[0]:
            return None
        return -1 if a[1] < b[1] else 1
    return (len(left) > len(right)) - (len(left) < len(right))


def _holds(version: tuple, condition: str) -> Optional[bool]:
    condition = condition.strip().replace(" ", "")
    match = re.fullmatch(r"(<=|>=|<|>|=)?(.+)", condition)
    if not match:
        return None
    operator, bound = match.group(1) or "=", match.group(2)
    if bound in ("*", "all"):
        return True
    limit = version_key(bound)
    if not limit or not any(kind == 0 for kind, _ in limit):
        return None
    order = _compare(version, limit)
    if order is None:
        return None
    return {"<": order < 0, "<=": order <= 0, ">": order > 0, ">=": order >= 0, "=": order == 0}[operator]


def version_status(version: str, ranges: list[str]) -> str:
    """'affected', 'not affected' or 'check version'."""
    if not ranges:
        return "check version"
    key = version_key(version or "")
    if not key or not any(kind == 0 for kind, _ in key):
        return "check version"
    unsure = False
    for text in ranges:
        text = text.strip()
        if text.startswith("vers:"):
            text = text.split("/", 1)[1] if "/" in text else ""
            conditions = [part for part in text.split("|") if part]
        else:
            conditions = [text]
        results = [_holds(key, condition) for condition in conditions]
        if None in results:
            unsure = True
        elif all(results):
            return "affected"
    return "check version" if unsure else "not affected"


# ---- reading the formats ----------------------------------------------------------
def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _time(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    moment = fw.parse_time(text)
    if moment is None:
        try:
            moment = email.utils.parsedate_to_datetime(text)
        except (TypeError, ValueError):
            moment = None
    if moment is None and re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        moment = datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    if moment is None:
        return ""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return stamp(moment)


def _clean(text: Any, limit: int = 2000) -> str:
    text = re.sub(r"<[^>]{0,500}>", " ", str(text or ""))
    return " ".join(text.split())[:limit]


def _score(value: Any) -> float:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return 0.0
    return score if 0 <= score <= 10 else 0.0


def safe_xml(data: bytes):
    """Parse XML that came from outside. Documents that declare a DTD or
    entities are refused: no feed needs them, and they are how XML attacks work."""
    head = data[:4096].lower()
    if b"<!doctype" in head or b"<!entity" in data.lower():
        raise ValueError("the document declares a DTD or entities, which is not accepted")
    return ElementTree.fromstring(data)


def advisory(source: str, ident: str, title: str, link: str = "", published: str = "", updated: str = "", summary: str = "",
             score: float = 0.0, refs: Iterable[str] = (), products: Iterable[tuple[str, str, list[str]]] = (),
             kev: bool = False, document_url: str = "", detail: str = "full", read_text: bool = True) -> dict:
    """read_text: also take CVE and advisory numbers from the title and summary.
    Off for structured formats, whose summaries mention related but different CVEs."""
    ident = (ident or link or title).strip()[:200]
    text = " ".join([ident, title or "", summary or ""]) if read_text else ""
    found: set[str] = set()
    for ref in list(refs) + [text]:
        found.update(cve.upper() for cve in CVE.findall(ref or ""))
        found.update(OTHER_IDS.findall(ref or ""))
    if not CVE.fullmatch(ident):
        found.discard(ident.upper())       # an advisory is not its own reference; a CVE entry keeps its CVE
    return {"id": f"{source}|{ident}", "source": source, "ident": ident, "title": _clean(title, 300) or ident,
            "link": link if re.match(r"https?://", link or "") else "", "published": published or updated,
            "updated": updated or published, "summary": _clean(summary), "score": score, "kev": 1 if kev else 0,
            "refs": sorted(found)[:500], "products": list(products)[:200], "document_url": document_url, "detail": detail}


def read_rss(data: bytes, source: str) -> list[dict]:
    root = safe_xml(data)
    out = []
    for item in root.iter():
        if _local(item.tag) not in ("item", "entry"):
            continue
        values: dict[str, str] = {}
        refs, products, scores = [], {}, []
        link = item.get("{http://www.w3.org/1999/02/22-rdf-syntax-ns#}about") or ""
        for child in item:
            name, text = _local(child.tag), (child.text or "").strip()
            if name == "link":
                link = child.get("href") or text or link
            elif name == "references":
                refs.append(child.get("id") or "")
                refs.append(text)
            elif name == "cpe":
                vendor, product = child.get("vendor") or "", child.get("product") or ""
                parts = text.split(":")
                if not product and len(parts) >= 4:
                    vendor, product = vendor or parts[2], parts[3]
                if vendor or product:
                    products[(vendor.replace("_", " ").strip()[:100], product.replace("_", " ").strip()[:150])] = []
            elif name == "cvss":
                scores.append(_score(child.get("score")))
            elif name not in values and text:
                values[name] = text
        ident = values.get("identifier") or values.get("guid") or values.get("id") or link
        published = _time(values.get("issued") or values.get("published") or values.get("pubDate") or values.get("date"))
        updated = _time(values.get("modified") or values.get("updated") or values.get("date") or values.get("pubDate"))
        out.append(advisory(source, ident, values.get("title", ""), link, published, updated,
                            values.get("description") or values.get("summary") or values.get("content", ""),
                            max(scores or [0.0]), [ref for ref in refs if ref],
                            [(vendor, product, versions) for (vendor, product), versions in products.items()]))
    return out


def read_kev(data: bytes, source: str) -> list[dict]:
    catalogue = json.loads(data.decode("utf-8", "replace"))
    out = []
    for entry in (catalogue.get("vulnerabilities") or [])[:20000]:
        cve = str(entry.get("cveID") or "").strip().upper()
        if not CVE.fullmatch(cve):
            continue
        ransomware = str(entry.get("knownRansomwareCampaignUse") or "").lower() == "known"
        summary = " ".join(part for part in (
            str(entry.get("shortDescription") or ""), f"Required action: {entry.get('requiredAction')}" if entry.get("requiredAction") else "",
            "Known to be used in ransomware campaigns." if ransomware else "") if part)
        out.append(advisory(source, cve, str(entry.get("vulnerabilityName") or cve), f"https://nvd.nist.gov/vuln/detail/{cve}",
                            _time(entry.get("dateAdded")), _time(entry.get("dateAdded")), summary, 0.0, [cve],
                            [(str(entry.get("vendorProject") or "")[:100], str(entry.get("product") or "")[:150], [])], kev=True,
                            read_text=False))
    return out


def read_csaf(data: bytes, source: str, document_url: str = "") -> dict:
    document = json.loads(data.decode("utf-8", "replace"))
    head = document.get("document") or {}
    tracking = head.get("tracking") or {}
    if not tracking.get("id"):
        raise ValueError("not a CSAF advisory (document.tracking.id is missing)")
    affected: set[str] = set()
    refs, scores = [], []
    for vulnerability in document.get("vulnerabilities") or []:
        if vulnerability.get("cve"):
            refs.append(str(vulnerability["cve"]))
        status = vulnerability.get("product_status") or {}
        for key in ("known_affected", "first_affected", "last_affected", "under_investigation"):
            affected.update(str(item) for item in status.get(key) or [])
        for score in vulnerability.get("scores") or []:
            for key in ("cvss_v4", "cvss_v3"):
                scores.append(_score((score.get(key) or {}).get("baseScore")))
    products: dict[tuple[str, str], list[str]] = {}

    def walk(branch: dict, vendor: str, product: str) -> None:
        category, name = branch.get("category"), str(branch.get("name") or "").strip()
        if category == "vendor":
            vendor = name
        elif category in ("product_name", "product_family"):
            product = name          # a product's name is more precise than its family's
        children = branch.get("branches") or []
        if children:
            for child in children:
                walk(child, vendor, product)
            return
        product_id = str((branch.get("product") or {}).get("product_id") or "")
        if affected and product_id not in affected:
            return
        if not (vendor or product):
            return
        versions = products.setdefault((vendor[:100], (product or name)[:150]), [])
        if category in ("product_version_range", "product_version") and name and len(versions) < 50:
            versions.append(name if category == "product_version_range" or name.startswith("vers:") else f"={name}")

    for branch in (document.get("product_tree") or {}).get("branches") or []:
        walk(branch, "", "")
    link = ""
    for reference in head.get("references") or []:
        url = str(reference.get("url") or "")
        if url.startswith("https://") and not url.endswith(".json"):
            link = url
            break
    summary = " ".join(str(note.get("text") or "") for note in head.get("notes") or [] if note.get("category") == "summary")
    return advisory(source, str(tracking["id"]), str(head.get("title") or ""), link or document_url,
                    _time(tracking.get("initial_release_date")), _time(tracking.get("current_release_date")), summary,
                    max(scores or [0.0]), refs, [(vendor, product, versions) for (vendor, product), versions in products.items()],
                    document_url=document_url, read_text=False)


def read_csaf_feed(data: bytes, source: str) -> list[dict]:
    """A ROLIE feed: one entry per advisory, with its title and where to fetch it."""
    feed = (json.loads(data.decode("utf-8", "replace")) or {}).get("feed") or {}
    out = []
    for entry in (feed.get("entry") or [])[:50000]:
        url = str((entry.get("content") or {}).get("src") or "")
        if not url:
            url = next((str(link.get("href") or "") for link in entry.get("link") or [] if link.get("rel") == "self"), "")
        if not entry.get("id"):
            continue
        item = advisory(source, str(entry["id"]), str(entry.get("title") or ""), "", _time(entry.get("published")),
                        _time(entry.get("updated")), document_url=url, detail="title", read_text=False)
        # The advisory's own page at CISA, until the document says otherwise.
        if re.fullmatch(r"ICSM?A-\d{2}-\d{3}-\d{2}[A-Z]?", item["ident"]):
            item["link"] = f"https://www.cisa.gov/news-events/ics-advisories/{item['ident'].lower()}"
        out.append(item)
    return out


def read_any(data: bytes, source: str, name: str = "") -> list[dict]:
    """A file of unknown format, from the import folder."""
    start = data.lstrip()[:1]
    if start == b"<":
        return read_rss(data, source)
    document = json.loads(data.decode("utf-8", "replace"))
    if isinstance(document, dict) and "vulnerabilities" in document and "catalogVersion" in document:
        return read_kev(data, source)
    if isinstance(document, dict) and "feed" in document:
        return read_csaf_feed(data, source)
    if isinstance(document, dict) and "document" in document:
        return [read_csaf(data, source)]
    raise ValueError(f"{name or 'file'}: not a format this part reads (RSS, Atom, CSAF, ROLIE feed or KEV catalogue)")


# ---- storing ------------------------------------------------------------------------
def prepare(store: Store) -> None:
    store.db.executescript(SCHEMA)


def save(store: Store, item: dict, now: datetime) -> bool:
    """Insert or update one advisory. True when it is new or changed."""
    row = store.db.execute("SELECT updated, detail, document_url FROM advisories WHERE id=?", (item["id"],)).fetchone()
    if row is not None:
        if item["detail"] == "title":
            # A listing never replaces a fetched document, only says it changed.
            if row["detail"] != "title" and (item["updated"] or "") > (row["updated"] or ""):
                store.db.execute("UPDATE advisories SET detail='stale', document_url=? WHERE id=?", (item["document_url"], item["id"]))
            return False
        if row["detail"] == "full" and (item["updated"] or "") <= (row["updated"] or "") and row["updated"]:
            same = store.db.execute("SELECT COUNT(*) FROM advisory_refs WHERE advisory=?", (item["id"],)).fetchone()[0] == len(item["refs"])
            if same:
                return False
    store.db.execute(
        "INSERT INTO advisories (id, source, ident, title, link, published, updated, summary, score, kev, document_url, detail, fetched) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET title=excluded.title, "
        "link=CASE WHEN excluded.link != '' THEN excluded.link ELSE advisories.link END, published=excluded.published, "
        "updated=excluded.updated, summary=excluded.summary, score=excluded.score, kev=excluded.kev, "
        "document_url=CASE WHEN excluded.document_url != '' THEN excluded.document_url ELSE advisories.document_url END, "
        "detail=excluded.detail, fetched=excluded.fetched",
        (item["id"], item["source"], item["ident"], item["title"], item["link"], item["published"], item["updated"],
         item["summary"], item["score"], item["kev"], item["document_url"], item["detail"], stamp(now)))
    store.db.execute("DELETE FROM advisory_refs WHERE advisory=?", (item["id"],))
    store.db.executemany("INSERT OR IGNORE INTO advisory_refs (advisory, ref) VALUES (?,?)", [(item["id"], ref) for ref in item["refs"]])
    store.db.execute("DELETE FROM advisory_products WHERE advisory=?", (item["id"],))
    store.db.executemany("INSERT OR IGNORE INTO advisory_products (advisory, vendor, product, versions) VALUES (?,?,?,?)",
                         [(item["id"], vendor, product, json.dumps(versions)) for vendor, product, versions in item["products"]
                          if vendor or product])
    return True


# ---- fetching -------------------------------------------------------------------------
class Fetcher:
    """Plain downloads with certificate checks. Uses TD_ADV_PROXY when set, and
    no other proxy: the platform connection must not be sent through it."""

    def __init__(self, proxy: str = "", timeout: int = 60) -> None:
        handlers: list[Any] = [urllib.request.ProxyHandler({"https": proxy, "http": proxy} if proxy else {}),
                               urllib.request.HTTPSHandler(context=ssl.create_default_context())]
        self.opener = urllib.request.build_opener(*handlers)
        self.timeout = timeout

    def get(self, url: str, etag: str = "", modified: str = "") -> tuple[Optional[bytes], str, str]:
        """(body or None when unchanged, etag, last-modified)."""
        request = urllib.request.Request(url, headers={"User-Agent": f"TechDetechtives-advisories/{VERSION}",
                                                       "Accept": "application/json, application/xml, text/xml, */*"})
        if etag:
            request.add_header("If-None-Match", etag)
        if modified:
            request.add_header("If-Modified-Since", modified)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                data = response.read(MAX_BYTES + 1)
                if len(data) > MAX_BYTES:
                    raise fw.HttpError(f"{url} is larger than {MAX_BYTES // (1024 * 1024)} MB; not read", False)
                return data, response.headers.get("ETag", "") or "", response.headers.get("Last-Modified", "") or ""
        except urllib.error.HTTPError as error:
            if error.code == 304:
                return None, etag, modified
            raise fw.HttpError(f"{url} answered HTTP {error.code}", error.code >= 500 or error.code in (408, 429)) from None
        except (urllib.error.URLError, TimeoutError, ConnectionError, ssl.SSLError, OSError) as error:
            raise fw.HttpError(f"{url} could not be reached: {getattr(error, 'reason', error)}", True) from None


def interesting_vendors(store: Store, watch: list[str]) -> set[str]:
    """Vendors this site has: from what devices announce, their network cards, and the watch list."""
    vendors = {vendor_key(phrase) for phrase in watch}
    for row in store.db.execute("SELECT vendor, maker FROM assets WHERE vendor != '' OR maker != ''"):
        vendors.add(vendor_key(row["vendor"]))
        for maker in (row["maker"] or "").split("; "):
            vendors.add(vendor_key(maker))
    vendors.discard("")
    return vendors


def fetch_documents(store: Store, fetcher: Fetcher, feed: Feed, now: datetime, recent_days: int, limit: int,
                    watch: list[str]) -> tuple[int, int]:
    """Fetch CSAF advisories listed by a feed: recent ones, and older ones for
    vendors this site has. Returns (fetched, still waiting)."""
    vendors = interesting_vendors(store, watch)
    host = urllib.parse.urlsplit(feed.url).hostname
    recent = stamp(now - timedelta(days=recent_days))
    waiting = []
    for row in store.db.execute("SELECT id, title, updated, document_url FROM advisories WHERE source=? AND detail IN ('title','stale') "
                                "ORDER BY updated DESC", (feed.name,)):
        url = row["document_url"] or ""
        if not url.startswith("https://") or urllib.parse.urlsplit(url).hostname != host:
            continue        # a listing may only point at documents on its own host
        if (row["updated"] or "") >= recent or vendor_key(row["title"]) in vendors or matches_watch(row["title"], watch):
            waiting.append((row["id"], url))
    fetched = 0
    for advisory_id, url in waiting[:limit]:
        try:
            data, _, _ = fetcher.get(url)
        except fw.HttpError as error:
            if error.retryable:
                raise               # the publisher is unreachable: carry on next time
            # Withdrawn or moved: the title stays, and it is not asked for again until the listing changes.
            store.db.execute("UPDATE advisories SET detail='unreadable' WHERE id=?", (advisory_id,))
            log.warning("advisory %s: %s", url, error)
            continue
        if data is None:
            continue
        try:
            item = read_csaf(data, feed.name, url)
        except (ValueError, KeyError, TypeError, AttributeError) as error:
            store.db.execute("UPDATE advisories SET detail='unreadable' WHERE id=?", (advisory_id,))
            log.warning("advisory %s could not be read: %s", url, error)
            continue
        if item["id"] != advisory_id:
            store.db.execute("UPDATE advisories SET detail='unreadable' WHERE id=?", (advisory_id,))
            continue
        save(store, item, now)
        fetched += 1
        if fetched % 25 == 0:
            store.commit()
    store.commit()
    return fetched, max(0, len(waiting) - limit)


def read_feed(feed: Feed, data: bytes) -> list[dict]:
    if feed.kind == "rss":
        return read_rss(data, feed.name)
    if feed.kind == "kev":
        return read_kev(data, feed.name)
    if feed.kind == "csaf-feed":
        return read_csaf_feed(data, feed.name)
    return [read_csaf(data, feed.name, feed.url)]


RETRY_AFTER = timedelta(minutes=30)


def fetch_all(store: Store, settings, now: datetime, fetcher: Optional[Fetcher] = None) -> dict:
    """Read every feed whose turn it is (a feed that failed is tried again after
    half an hour), fetch advisory documents still waiting, and read the import
    folder. Problems are noted per feed, not raised."""
    fetcher = fetcher or Fetcher(settings.adv_proxy)
    state = store.meta("advisory_feeds", {}) or {}
    summary = {"new": 0, "documents": 0, "waiting": 0, "errors": []}
    due_before = stamp(now - timedelta(hours=settings.adv_fetch_hours))
    for feed in settings.adv_feeds:
        entry = state.setdefault(feed.name, {})
        entry.update({"kind": feed.kind, "url": feed.url})
        if not entry.get("checked") or entry["checked"] <= due_before or (
                entry.get("error") and entry["checked"] <= stamp(now - RETRY_AFTER)):
            try:
                data, etag, modified = fetcher.get(feed.url, entry.get("etag", ""), entry.get("modified", ""))
                if data is not None:
                    items = read_feed(feed, data)
                    new = sum(1 for item in items if save(store, item, now))
                    summary["new"] += new
                    entry.update({"etag": etag, "modified": modified, "items": len(items), "changed": stamp(now)})
                entry.update({"checked": stamp(now), "error": ""})
            except fw.HttpError as error:
                entry.update({"checked": stamp(now), "error": str(error)[:300]})
                summary["errors"].append(f"advisories from {feed.name}: {error}")
            except (ValueError, KeyError, TypeError, AttributeError, ElementTree.ParseError) as error:
                entry.update({"checked": stamp(now), "error": f"could not be read: {str(error)[:250]}"})
                summary["errors"].append(f"advisories from {feed.name} could not be read: {error}")
            store.commit()
        if feed.kind == "csaf-feed" and entry.get("items") is not None:
            try:
                fetched, waiting = fetch_documents(store, fetcher, feed, now, settings.adv_recent_days,
                                                   settings.adv_max_documents, settings.adv_watch)
                summary["documents"] += fetched
                summary["waiting"] += waiting
                entry["waiting"] = waiting
            except fw.HttpError as error:
                summary["errors"].append(f"advisories from {feed.name}: {error}")
                entry["document_error"] = str(error)[:300]
            else:
                entry["document_error"] = ""
    _import_folder(store, settings, now, state, summary)
    store.set_meta("advisory_feeds", state)
    store.commit()
    return summary


def _import_folder(store: Store, settings, now: datetime, state: dict, summary: dict) -> None:
    folder = Path(settings.adv_import_dir) if settings.adv_import_dir else None
    if folder is None or not folder.is_dir():
        return
    seen = state.setdefault("(files)", {"kind": "files", "url": str(folder), "files": {}})
    files = seen.setdefault("files", {})
    for path in sorted(folder.iterdir())[:2000]:
        if not path.is_file() or path.suffix.lower() not in (".json", ".xml", ".rdf", ".rss", ".atom"):
            continue
        mark = "?"
        try:
            info = path.stat()
            mark = f"{int(info.st_mtime)}:{info.st_size}"
            known = str(files.get(path.name) or "")
            if known == mark or known.startswith(f"error:{mark}:"):
                continue            # unchanged since it was read, or since it was found unreadable
            if info.st_size > MAX_BYTES:
                raise ValueError(f"larger than {MAX_BYTES // (1024 * 1024)} MB")
            items = read_any(path.read_bytes(), "Imported", path.name)
            summary["new"] += sum(1 for item in items if save(store, item, now))
            files[path.name] = mark
        except (OSError, ValueError, KeyError, TypeError, AttributeError, ElementTree.ParseError) as error:
            summary["errors"].append(f"advisory file {path.name} could not be read: {str(error)[:200]}")
            files[path.name] = f"error:{mark}:{str(error)[:100]}"
        store.commit()
    seen["checked"] = stamp(now)


# ---- matching ---------------------------------------------------------------------------
def matches_watch(text: str, watch: list[str]) -> list[str]:
    words = set(tokens(text))
    return [phrase for phrase in watch if set(tokens(phrase)) <= words]


def _kev_cves(store: Store) -> set[str]:
    return {row["ref"] for row in store.db.execute(
        "SELECT r.ref FROM advisory_refs r JOIN advisories a ON a.id = r.advisory WHERE a.kev = 1")}


def find_matches(store: Store, findings: dict[str, set[str]], watch: list[str]) -> list[dict]:
    """Every way a known advisory concerns this site, as it stands now.

    findings: {ip: CVEs a vulnerability scan found there}."""
    out: list[dict] = []
    # 1. Scan findings, by CVE.
    by_cve: dict[str, list[str]] = {}
    for ip, cves in findings.items():
        for cve in cves:
            by_cve.setdefault(cve.upper(), []).append(ip)
    if by_cve:
        wanted = list(by_cve)
        for start in range(0, len(wanted), 500):
            part = wanted[start:start + 500]
            for row in store.db.execute(f"SELECT advisory, ref FROM advisory_refs WHERE ref IN ({','.join('?' * len(part))})", part):
                for ip in by_cve[row["ref"]]:
                    out.append({"advisory": row["advisory"], "target": ip, "how": "finding", "status": "found by a scan",
                                "detail": row["ref"]})
    # 2. What devices announce about themselves.
    devices: dict[str, list[dict]] = {}
    for row in store.db.execute("SELECT ip, vendor, model, version, kind, software, identity_via FROM assets "
                                "WHERE vendor != '' OR software != ''"):
        if row["vendor"]:
            devices.setdefault(vendor_key(row["vendor"]), []).append(
                {"ip": row["ip"], "words": significant(f'{row["model"]} {row["kind"]}'), "model": row["model"],
                 "version": row["version"], "how": "device", "via": row["identity_via"]})
        for banner in (row["software"] or "").split("; "):
            if banner:
                name, _, version = banner.rpartition(" ") if re.search(r"\d", banner.rsplit(" ", 1)[-1]) else (banner, "", "")
                devices.setdefault(vendor_key(name), []).append(
                    {"ip": row["ip"], "words": significant(name), "model": name, "version": version, "how": "software",
                     "via": "software banner"})
    if devices:
        for row in store.db.execute("SELECT advisory, vendor, product, versions FROM advisory_products"):
            vendor = vendor_key(row["vendor"]) or vendor_key(row["product"])
            candidates = devices.get(vendor, [])
            # Software banners often carry only the product's name ('OpenSSH'), with no vendor in front.
            product_words = significant(row["product"])
            if not candidates and product_words:
                candidates = [device for device in devices.get(vendor_key(row["product"]), []) if device["how"] == "software"]
            for device in candidates:
                words = device["words"]
                if not (product_words and distinctive(product_words) and words and distinctive(words)):
                    continue
                if not (product_words <= words or words <= product_words):
                    continue
                status = version_status(device["version"], json.loads(row["versions"] or "[]"))
                out.append({"advisory": row["advisory"], "target": device["ip"], "how": device["how"], "status": status,
                            "detail": f'{row["vendor"]} {row["product"]}'.strip() + f' (seen: {device["model"]}'
                                      + (f' {device["version"]}' if device["version"] else "") + f', from its {device["via"]})'})
    # 3. The site's own list of what it runs.
    if watch:
        texts: dict[str, list[str]] = {}
        for row in store.db.execute("SELECT id, title, summary FROM advisories"):
            texts[row["id"]] = [row["title"] or "", row["summary"] or ""]
        for row in store.db.execute("SELECT advisory, vendor, product FROM advisory_products"):
            if row["advisory"] in texts and len(texts[row["advisory"]]) < 60:
                texts[row["advisory"]].append(f'{row["vendor"]} {row["product"]}')
        for advisory_id, parts in texts.items():
            for phrase in matches_watch(" ".join(parts), watch):
                out.append({"advisory": advisory_id, "target": f"watch:{phrase}", "how": "watch", "status": "check version",
                            "detail": phrase})
    # One row per advisory, target and way of matching; a finding of several CVEs keeps them all.
    merged: dict[tuple[str, str, str], dict] = {}
    for match in out:
        key = (match["advisory"], match["target"], match["how"])
        if key in merged and match["how"] == "finding":
            cves = sorted(set(merged[key]["detail"].split(", ")) | {match["detail"]})
            merged[key]["detail"] = ", ".join(cves)
        elif key not in merged or (merged[key]["status"] == "not affected" and match["status"] != "not affected"):
            merged[key] = match
    return list(merged.values())


def record_matches(store: Store, matches: list[dict], now: datetime, max_changes: int) -> int:
    """Store the matches and write a change for each device or watched product
    that an advisory newly concerns. Returns how many changes were written."""
    at = stamp(now)
    kev = _kev_cves(store)
    fresh: dict[str, list[dict]] = {}
    for match in matches:
        row = store.db.execute("SELECT status FROM advisory_matches WHERE advisory=? AND target=? AND how=?",
                               (match["advisory"], match["target"], match["how"])).fetchone()
        if row is None:
            store.db.execute("INSERT INTO advisory_matches (advisory, target, how, status, detail, first_seen, last_seen) "
                             "VALUES (?,?,?,?,?,?,?)", (match["advisory"], match["target"], match["how"], match["status"],
                                                        match["detail"], at, at))
            alerting = match["how"] in ("finding", "device", "watch") and match["status"] != "not affected"
        else:
            store.db.execute("UPDATE advisory_matches SET status=?, detail=?, last_seen=? WHERE advisory=? AND target=? AND how=?",
                             (match["status"], match["detail"], at, match["advisory"], match["target"], match["how"]))
            alerting = row["status"] == "not affected" and match["status"] != "not affected" and match["how"] in ("finding", "device")
        if alerting:
            fresh.setdefault(match["target"], []).append(match)

    changes = []
    for target, found in fresh.items():
        details = []
        severity = MEDIUM
        for match in found:
            item = store.db.execute("SELECT * FROM advisories WHERE id=?", (match["advisory"],)).fetchone()
            if item is None:
                continue
            cves = {row["ref"] for row in store.db.execute("SELECT ref FROM advisory_refs WHERE advisory=?", (item["id"],))
                    if row["ref"].startswith("CVE-")}
            exploited = bool(item["kev"] or (cves & kev))
            if exploited or (item["score"] or 0) >= 9.0:
                severity = HIGH
            details.append((exploited, item["score"] or 0, item, match))
        if not details:
            continue
        details.sort(key=lambda entry: (not entry[0], -entry[1], entry[2]["published"] or ""), reverse=False)
        lines = []
        for exploited, score, item, match in details[:5]:
            lines.append(f'{item["source"]} {item["ident"]}: {item["title"]}'
                         + (f" (CVSS {score:.1f})" if score else "") + (" [known to be exploited]" if exploited else "")
                         + (f" - {match['detail']}" if match["how"] != "watch" else "")
                         + (f" - version: {match['status']}" if match["how"] == "device" else "")
                         + (f" {item['link']}" if item["link"] else ""))
        more = f" And {len(details) - 5} more." if len(details) > 5 else ""
        if target.startswith("watch:"):
            phrase = target[len("watch:"):]
            changes.append((severity, "advisory_watched_product", "", "",
                            f"Published advisory for a product you run: {phrase}"[:200],
                            f"{len(details)} published advisor{'y names' if len(details) == 1 else 'ies name'} {phrase}, "
                            f"which is on this site's list of products it runs: " + "; ".join(lines) + more))
        else:
            kinds = {match["how"] for _, _, _, match in details}
            title = ("Published advisory for a vulnerability found on a device" if kinds == {"finding"}
                     else "Published advisory for a device's model")
            changes.append((severity, "advisory_device", target, "", title,
                            f"{len(details)} published advisor{'y concerns' if len(details) == 1 else 'ies concern'} {target}: "
                            + "; ".join(lines) + more))
    changes.sort(key=lambda change: -change[0])
    for severity, kind, ip, peer, title, detail in changes[:max_changes]:
        store.add_change(at, kind, severity, ip, peer, title, detail[:4000])
    if len(changes) > max_changes:
        store.add_change(at, "more_changes", LOW, "", "", "More advisory matches than can be listed",
                         f"{len(changes) - max_changes} further devices or products concerned by published advisories were "
                         "not listed one by one; see the Advisories page.")
    store.commit()
    return len(changes)


def run(store: Store, platform, settings, now: Optional[datetime] = None, fetcher: Optional[Fetcher] = None,
        force: bool = False) -> dict:
    """Fetch what is due, then match. Returns {'new', 'documents', 'waiting', 'changes', 'errors'}."""
    now = now or datetime.now(timezone.utc)
    prepare(store)
    summary = {"new": 0, "documents": 0, "waiting": 0, "changes": 0, "errors": []}
    if not settings.adv_enabled:
        return summary
    if force:
        store.set_meta("advisory_feeds", {name: {**entry, "checked": ""} for name, entry in
                                          (store.meta("advisory_feeds", {}) or {}).items()})
    result = fetch_all(store, settings, now, fetcher)
    for key in ("new", "documents", "waiting"):
        summary[key] = result[key]
    summary["errors"] += result["errors"]
    store.commit()

    findings: dict[str, set[str]] = {}
    if platform is not None:
        try:
            for row in platform.finding_cves(now - timedelta(days=settings.adv_finding_days), now):
                cve = str(row.get("cve") or "").upper()
                if CVE.fullmatch(cve) and row.get("ip"):
                    findings.setdefault(str(row["ip"]), set()).add(cve)
        except fw.HttpError as error:
            summary["errors"].append(f"vulnerability findings could not be read for advisory matching: {str(error)[:200]}")
            findings = {}
            # Without the findings, matches by finding are left as they were.
    matches = find_matches(store, findings, settings.adv_watch)
    summary["changes"] = record_matches(store, matches, now, settings.max_changes)
    store.set_meta("advisory_status", {"matched_at": stamp(now), "errors": summary["errors"][:20],
                                       "findings_read": platform is not None})
    store.commit()
    return summary


# ---- reading back, for the pages ------------------------------------------------------
def overview(store: Store) -> dict:
    prepare(store)
    one = lambda sql, *args: store.db.execute(sql, args).fetchone()[0] or 0  # noqa: E731
    return {
        "advisories": one("SELECT COUNT(*) FROM advisories"),
        "titles_only": one("SELECT COUNT(*) FROM advisories WHERE detail != 'full'"),
        "matching": one("SELECT COUNT(DISTINCT advisory) FROM advisory_matches WHERE status != 'not affected' AND how != 'software'"),
        "targets": one("SELECT COUNT(DISTINCT target) FROM advisory_matches WHERE status != 'not affected' AND how != 'software'"),
        "kev": one("SELECT COUNT(*) FROM advisories WHERE kev = 1"),
    }


def match_rows(store: Store, target: str = "", limit: int = 1000) -> list[dict]:
    prepare(store)
    kev = _kev_cves(store)
    clause, values = ("WHERE m.target = ?", [target]) if target else ("", [])
    rows = store.db.execute(f"""
        SELECT m.*, a.source, a.ident, a.title, a.link, a.published, a.score, a.kev,
               (SELECT GROUP_CONCAT(ref, ' ') FROM advisory_refs r WHERE r.advisory = a.id AND r.ref LIKE 'CVE-%') AS cves
        FROM advisory_matches m JOIN advisories a ON a.id = m.advisory {clause}
        ORDER BY m.status = 'not affected', m.how = 'software', a.published DESC LIMIT ?""", values + [limit]).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        cves = set((item["cves"] or "").split())
        item["exploited"] = bool(item["kev"] or (cves & kev))
        item["cves"] = sorted(cves)
        out.append(item)
    return out


def advisory_rows(store: Store, source: str = "", text: str = "", only_matching: bool = False, limit: int = 300) -> list[dict]:
    prepare(store)
    where, values = [], []
    if source:
        where.append("a.source = ?")
        values.append(source)
    if text:
        where.append("(a.title LIKE ? OR a.ident LIKE ? OR a.summary LIKE ? OR EXISTS (SELECT 1 FROM advisory_refs r "
                     "WHERE r.advisory = a.id AND r.ref LIKE ?))")
        like = f"%{text}%"
        values += [like, like, like, like]
    if only_matching:
        where.append("EXISTS (SELECT 1 FROM advisory_matches m WHERE m.advisory = a.id AND m.status != 'not affected')")
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    rows = store.db.execute(f"""
        SELECT a.*, (SELECT COUNT(DISTINCT target) FROM advisory_matches m WHERE m.advisory = a.id
                     AND m.status != 'not affected' AND m.how != 'software') AS concerns,
               (SELECT GROUP_CONCAT(ref, ' ') FROM advisory_refs r WHERE r.advisory = a.id AND r.ref LIKE 'CVE-%') AS cves
        FROM advisories a {clause} ORDER BY COALESCE(NULLIF(a.updated, ''), a.published) DESC LIMIT ?""", values + [limit]).fetchall()
    kev = _kev_cves(store)
    out = []
    for row in rows:
        item = dict(row)
        cves = set((item["cves"] or "").split())
        item["exploited"] = bool(item["kev"] or (cves & kev))
        item["cves"] = sorted(cves)
        out.append(item)
    return out


def one_advisory(store: Store, advisory_id: str) -> Optional[dict]:
    prepare(store)
    row = store.db.execute("SELECT * FROM advisories WHERE id=?", (advisory_id,)).fetchone()
    if row is None:
        return None
    item = dict(row)
    item["refs"] = [r["ref"] for r in store.db.execute("SELECT ref FROM advisory_refs WHERE advisory=? ORDER BY ref", (advisory_id,))]
    item["products"] = [dict(r) for r in store.db.execute("SELECT vendor, product, versions FROM advisory_products WHERE advisory=? "
                                                         "ORDER BY vendor, product", (advisory_id,))]
    item["matches"] = [dict(r) for r in store.db.execute("SELECT * FROM advisory_matches WHERE advisory=? ORDER BY target", (advisory_id,))]
    kev = _kev_cves(store)
    item["exploited"] = bool(item["kev"] or (set(item["refs"]) & kev))
    # The same vulnerabilities as told by other publishers.
    item["related"] = [dict(r) for r in store.db.execute("""
        SELECT DISTINCT a.id, a.source, a.ident, a.title FROM advisories a JOIN advisory_refs r ON r.advisory = a.id
        WHERE a.id != ? AND (r.ref IN (SELECT ref FROM advisory_refs WHERE advisory = ?) OR r.ref = ?)
        ORDER BY a.source LIMIT 30""", (advisory_id, advisory_id, item["ident"].upper()))]
    return item
