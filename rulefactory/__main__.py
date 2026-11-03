# TechDetechtives rule factory: command line.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Usage (from the repository root):

  python3 -m rulefactory build CVE-2024-4577          draft, write and test rules for one CVE
  python3 -m rulefactory build CVE-... --nuclei FILE   use this exploit template (offline drafting)
  python3 -m rulefactory build CVE-... --publish       also open a pull request (needs TD_RF_GITHUB_TOKEN)
  python3 -m rulefactory watch [--days 14] [--publish] new exploited RCE CVEs from CISA KEV, each built
  python3 -m rulefactory exposure [--days 60] [--every 6]  on your network: CVEs your scanner finds -> DFIR-IRIS

Settings (environment):
  TD_RF_GITHUB_TOKEN / GITHUB_TOKEN   token that may push branches and open pull requests
  TD_RF_REPO                          owner/name of the repository (default techdetechtives/techdetechtives)
  TD_RF_WATCH                         comma-separated vendor or product words; only these are watched
  TD_RF_MAX_PER_RUN                   most CVEs built in one watch run (default 3)
  TD_RF_NVD_API_KEY                   optional NVD API key (higher rate limit)
  TD_RF_CACHE                         download cache (default ~/.cache/td-rulefactory)
  TD_SURICATA_IMAGE                   Suricata image for the replay test, e.g. jasonish/suricata:7.0.11
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from . import VERSION, factory, feeds
from .common import log


def _token() -> str:
    return os.environ.get("TD_RF_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""


def _repo() -> str:
    return os.environ.get("TD_RF_REPO") or os.environ.get("GITHUB_REPOSITORY") or "techdetechtives/techdetechtives"


def build_one(cve: str, nuclei_path, offline: bool, publish: bool, vuln=None) -> int:
    result = factory.build(cve, nuclei_path=Path(nuclei_path) if nuclei_path else None, offline=offline, vuln=vuln)
    factory.write(result)
    if result.drafts:
        factory.validate(result)
        factory.write(result)              # the report now carries the test results
    print(factory.render_report(result))
    if result.drafts and result.passed is False:
        print(result.tests[-3000:], file=sys.stderr)
    if publish:
        if not _token():
            log.error("--publish needs TD_RF_GITHUB_TOKEN (or GITHUB_TOKEN)")
            return 2
        url = factory.publish(result, _repo(), _token())
        print(f"pull request: {url}")
    return 0 if result.passed is not False else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="rulefactory", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build", help="one CVE")
    b.add_argument("cve")
    b.add_argument("--nuclei", help="Nuclei template file to draft from (skips the online searches)")
    b.add_argument("--offline", action="store_true", help="no downloads at all (needs --nuclei)")
    b.add_argument("--publish", action="store_true")
    w = sub.add_parser("watch", help="new exploited remote-code-execution CVEs")
    w.add_argument("--days", type=int, default=14)
    w.add_argument("--publish", action="store_true")
    w.add_argument("--list", action="store_true", help="only list what would be built")
    e = sub.add_parser("exposure", help="on your network: exploited CVEs the scanner finds")
    e.add_argument("--days", type=int, default=60)
    e.add_argument("--dry-run", action="store_true", help="print, do not raise alerts")
    e.add_argument("--every", type=float, default=0, help="repeat every this many hours (0: run once)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if args.command == "build":
        return build_one(args.cve, args.nuclei, args.offline, args.publish)

    if args.command == "watch":
        watch = [w.strip() for w in os.environ.get("TD_RF_WATCH", "").split(",") if w.strip()]
        limit = int(os.environ.get("TD_RF_MAX_PER_RUN") or 3)
        todo = [v for v in feeds.recent_rce(args.days, watch) if not factory.processed(v.cve)]
        log.info("%d exploited RCE CVE(s) in the last %d days not yet processed", len(todo), args.days)
        if args.list:
            for vuln in todo:
                print(f"{vuln.cve}  {vuln.date_added}  {vuln.title}: {vuln.name}")
            return 0
        status = 0
        for vuln in todo[:limit]:
            log.info("building %s (%s)", vuln.cve, vuln.title)
            try:
                status |= build_one(vuln.cve, None, False, args.publish, vuln=feeds.enrich(vuln))
            except Exception as error:  # noqa: BLE001  one bad CVE must not stop the rest
                log.error("%s failed: %s", vuln.cve, error)
                status = 1
        return status

    if args.command == "exposure":
        import time
        from . import exposure
        while True:
            try:
                exposure.run(args.days, dry_run=args.dry_run)
            except Exception as error:  # noqa: BLE001  keep the service running; the next round retries
                log.error("exposure check failed: %s", error)
                if not args.every:
                    return 1
            if not args.every:
                return 0
            time.sleep(args.every * 3600)
    return 2


if __name__ == "__main__":
    sys.exit(main())
