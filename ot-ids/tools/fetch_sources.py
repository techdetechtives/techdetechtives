#!/usr/bin/env python3
# TechDetechtives OT IDS. Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Download and convert the external sources listed in sources.conf.

Run on a machine with Internet access (needs git and Python 3; nothing else).
Writes a folder laid out like the product's own:

    suricata/rules/ext-<source>.rules     converted or as-published rules
    yara/<source>/*.yar                   YARA rule files, each under a unique name
    zeek/intel/<source>/*.intel           threat indicators
    kev/known_exploited_vulnerabilities.json
    yara-sources.txt                      each enabled YARA source and whether it was fetched
    reports/<source>.txt                  what conversion changed or set aside
    SOURCES.txt                           what was fetched, from where, when

A source that cannot be fetched is reported and skipped; the others continue.

  fetch_sources.py --config sources.conf --out work/sources-out
"""
import argparse
import configparser
import datetime
import fnmatch
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ioc2intel          # noqa: E402
import snort2suricata     # noqa: E402
import yara_sources       # noqa: E402

KINDS = ("snort-git", "snort-url", "suricata-git", "suricata-url", "yara-git", "intel-git", "ioc-url", "kev-url")
MAX_DOWNLOAD = 300 * 1024 * 1024
# A repository that is private or gone makes git ask for a name and password; fail instead of waiting.
GIT_ENV = dict(os.environ, GIT_TERMINAL_PROMPT="0")


class SourceError(Exception):
    pass


def names(text):
    return [item.strip() for item in text.split(",") if item.strip()]


def git_fetch(url, commit, folder):
    """Shallow copy of a repository at its newest commit, or at one named commit."""
    def run(*command):
        result = subprocess.run(["git", *command], cwd=folder, capture_output=True, text=True, timeout=900, env=GIT_ENV)
        if result.returncode != 0:
            raise SourceError(f"git {' '.join(command[:2])} failed: {result.stderr.strip()[-300:]}")
        return result.stdout.strip()
    run("init", "-q")
    run("remote", "add", "origin", url)
    run("fetch", "-q", "--depth", "1", "origin", commit or "HEAD")
    run("checkout", "-q", "FETCH_HEAD")
    return run("rev-parse", "HEAD")


def git_fetch_some(url, commit, folder, choose):
    """The files of a repository that 'choose' picks, at its newest commit or at one named commit.

    Asks the server for the commit without file contents, then for the chosen
    files in one request, so a large repository costs what its rule files
    weigh. A server that cannot do either sends everything, and the result is
    the same. Returns (commit, chosen paths).
    """
    def run(*command, feed=None, must=True):
        result = subprocess.run(["git", "-c", "core.quotepath=off", "-c", "gc.auto=0", *command], cwd=folder, input=feed,
                                capture_output=True, encoding="utf-8", errors="replace", timeout=1800, env=GIT_ENV)
        if result.returncode != 0 and must:
            raise SourceError(f"git {' '.join(command[:2])} failed: {result.stderr.strip()[-300:]}")
        return result.stdout
    run("init", "-q")
    run("remote", "add", "origin", url)
    run("fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", commit or "HEAD")
    chosen, objects = [], []
    for entry in run("ls-tree", "-r", "-z", "FETCH_HEAD").split("\0"):
        meta, _, path = entry.partition("\t")
        fields = meta.split()
        # Ordinary files only: a link (mode 120000) could point at a file of the build machine, and a
        # name that is not UTF-8 (shown here with a replacement mark) cannot be asked for by name.
        if len(fields) == 3 and fields[1] == "blob" and fields[0] in ("100644", "100755") and "\ufffd" not in path and choose(path):
            chosen.append(path)
            objects.append(fields[2])
    if objects:
        # One request for all the chosen files. Without it git asks for them one at a time.
        run("-c", "fetch.negotiationAlgorithm=noop", "fetch", "-q", "origin", "--no-tags", "--no-write-fetch-head",
            "--recurse-submodules=no", "--filter=blob:none", "--stdin", feed="\n".join(objects) + "\n", must=False)
    for start in range(0, len(chosen), 200):
        run("checkout", "-q", "FETCH_HEAD", "--", *chosen[start:start + 200])
    return run("rev-parse", "FETCH_HEAD").strip(), chosen


def download(url):
    request = urllib.request.Request(url, headers={"User-Agent": "techdetechtives-ot-ids-fetch/1"})
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            data = response.read(MAX_DOWNLOAD + 1)
    except Exception as error:                                   # network, TLS, HTTP status
        raise SourceError(f"download failed: {error}") from error
    if len(data) > MAX_DOWNLOAD:
        raise SourceError("download is larger than 300 MB")
    return data


def rule_texts(data, url, patterns):
    """Rule file contents from a download: one .rules file, or the matching members of a tar archive."""
    if url.endswith((".tar.gz", ".tgz")):
        texts = []
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
                for member in archive.getmembers():
                    base = Path(member.name).name
                    if member.isfile() and any(fnmatch.fnmatch(base, pattern) for pattern in patterns):
                        texts.append((base, archive.extractfile(member).read().decode("utf-8", errors="replace")))
        except tarfile.TarError as error:
            raise SourceError(f"not a readable .tar.gz: {error}") from error
        if not texts:
            raise SourceError(f"no file in the archive matches {patterns}")
        return texts
    return [(Path(url).name or "rules", data.decode("utf-8", errors="replace"))]


def count_rules(text):
    return sum(1 for line in text.splitlines() if line.startswith(("alert ", "drop ", "reject ")))


def fetch_yara(name, section, out, shared):
    include, exclude = names(section.get("include", "")), names(section.get("exclude", ""))

    def choose(path):
        return yara_sources.is_licence_file(path) or yara_sources.wanted(path, include, exclude)

    with tempfile.TemporaryDirectory() as folder:
        commit, paths = git_fetch_some(section["url"], section.get("commit", ""), folder, choose)
        if not any(yara_sources.is_rule_file(path) for path in paths):
            raise SourceError("no .yar or .yara file in the repository matches 'include'")
        done = yara_sources.gather(
            Path(folder), paths, out / "yara" / name, name, include, exclude,
            drop_rules=names(section.get("drop_rules", "")), known=shared.setdefault("yara_names", {}),
            drop_known=section.getboolean("drop_known", fallback=False),
            skip_noncommercial=section.getboolean("skip_noncommercial", fallback=True),
            taken=shared.setdefault("yara_namespaces", set()))
    if not done["files"]:
        shutil.rmtree(out / "yara" / name, ignore_errors=True)
        raise SourceError("no rule was left after the filters")
    reports = out / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / f"{name}.txt").write_text("\n".join(yara_sources.report_lines(name, done)) + "\n", encoding="utf-8")
    return f"{yara_sources.summary(done)}; commit {commit[:12]}"


def fetch_one(name, section, out, shared=None):
    kind = section.get("kind", "")
    url = section.get("url", "")
    if kind not in KINDS or not url:
        raise SourceError(f"needs a url and a kind from: {', '.join(KINDS)}")
    licence = section.get("licence", "")
    rules_dir, intel_dir, reports = out / "suricata" / "rules", out / "zeek" / "intel" / name, out / "reports"
    detail = ""

    if kind == "yara-git":
        return fetch_yara(name, section, out, {} if shared is None else shared)
    if kind in ("snort-git", "suricata-git", "intel-git"):
        with tempfile.TemporaryDirectory() as folder:
            commit = git_fetch(url, section.get("commit", ""), folder)
            wanted = names(section.get("files", ""))
            found = [path for pattern in wanted for path in sorted(Path(folder).glob(pattern)) if path.is_file()]
            if not found:
                raise SourceError(f"none of the listed files exist in the repository: {wanted}")
            if kind in ("snort-git", "suricata-git"):
                text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in found)
                detail = convert_snort(name, text, section, rules_dir, reports, licence)
            else:
                intel_dir.mkdir(parents=True, exist_ok=True)
                total = 0
                for path in found:
                    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
                    if not lines or not lines[0].startswith("#fields\t"):
                        raise SourceError(f"{path.name} is not a Zeek intelligence file")
                    shutil.copyfile(path, intel_dir / path.name)
                    total += len(lines) - 1
                detail = f"{total} indicators in {len(found)} files"
            return f"{detail}; commit {commit[:12]}"

    data = download(url)
    if kind == "kev-url":
        import json
        try:
            count = len(json.loads(data)["vulnerabilities"])
        except (ValueError, KeyError, TypeError) as error:
            raise SourceError("not the catalogue's JSON format") from error
        (out / "kev").mkdir(parents=True, exist_ok=True)
        (out / "kev" / "known_exploited_vulnerabilities.json").write_bytes(data)
        return f"{count} catalogue entries"
    if kind == "ioc-url":
        values = [line.split("#", 1)[0].strip().split()[0] for line in data.decode("utf-8", errors="replace").splitlines()
                  if line.split("#", 1)[0].strip()]
        lines, counts = ioc2intel.build(values, name, section.get("about", "")[:120].replace("\t", " "), False)
        if len(lines) < 2:
            raise SourceError("no indicator recognised in the download")
        intel_dir.mkdir(parents=True, exist_ok=True)
        (intel_dir / f"{name}.intel").write_text("\n".join(lines) + "\n", encoding="utf-8")
        return f"{len(lines) - 1} indicators"
    texts = rule_texts(data, url, names(section.get("files", "*.rules")))
    text = "\n".join(body for _, body in texts)
    if kind == "snort-url":
        return convert_snort(name, text, section, rules_dir, reports, licence)
    rules_dir.mkdir(parents=True, exist_ok=True)
    header = f"# {name}: Suricata rules as published at {url}\n# Licence of the source: {licence or 'see the source'}.\n\n"
    (rules_dir / f"ext-{name}.rules").write_text(header + text + "\n", encoding="utf-8")
    return f"{count_rules(text)} rules, as published"


def convert_snort(name, text, section, rules_dir, reports, licence):
    try:
        sid_base = int(section["sid_base"])
    except (KeyError, ValueError) as error:
        raise SourceError("a Snort source needs a numeric sid_base") from error
    limit = int(section.get("limit_seconds", "0") or 0)
    rules, set_aside, noted = snort2suricata.convert_text(
        text, name, sid_base, limit, section.getboolean("once_per_window", fallback=False), names(section.get("skip_sids", "")))
    if not rules:
        raise SourceError("no rule could be converted")
    rules_dir.mkdir(parents=True, exist_ok=True)
    reports.mkdir(parents=True, exist_ok=True)
    header = [f"# Imported and renumbered by tools/snort2suricata.py. Source: {name}.",
              f"# Licence of the source: {licence or 'see the source'}.",
              f"# {len(rules)} rules, sids {sid_base} to {sid_base + len(rules) - 1}; {len(set_aside)} set aside.", ""]
    (rules_dir / f"ext-{name}.rules").write_text("\n".join(header + rules) + "\n", encoding="utf-8")
    report = [f"{name}: {len(rules)} converted, {len(set_aside)} set aside", ""]
    report += [f"sid {sid}: {'; '.join(notes)}" for sid, notes in sorted(noted.items())]
    report += [f"SET ASIDE ({reason}): {line[:200]}" for reason, line in set_aside]
    (reports / f"{name}.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    return f"{len(rules)} rules imported, {len(set_aside)} set aside"


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--only", help="comma-separated source names (default: every enabled source)")
    args = parser.parse_args()

    config = configparser.ConfigParser(interpolation=None)
    if not config.read(args.config, encoding="utf-8"):
        parser.error(f"cannot read {args.config}")
    only = set(names(args.only)) if args.only else None
    bases = {}
    for name in config.sections():
        base = config[name].get("sid_base")
        if base and base in bases:
            parser.error(f"[{name}] and [{bases[base]}] share sid_base {base}")
        bases[base] = name

    if args.out.exists():
        shutil.rmtree(args.out)
    args.out.mkdir(parents=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    manifest, failed, shared, yara_status = [f"External sources fetched {stamp}", ""], 0, {}, []
    for name in config.sections():
        section = config[name]
        if only is not None and name not in only:
            continue
        if only is None and not section.getboolean("enabled", fallback=False):
            continue
        try:
            result = fetch_one(name, section, args.out, shared)
            status = "ok"
        except SourceError as error:
            result, status, failed = str(error), "FAILED", failed + 1
        except subprocess.TimeoutExpired:
            result, status, failed = "timed out", "FAILED", failed + 1
        except (OSError, ValueError) as error:                   # a file that cannot be read or written, odd text
            result, status, failed = f"{type(error).__name__}: {error}", "FAILED", failed + 1
        if section.get("kind") == "yara-git":
            yara_status.append(f"{name} {status}")
        print(f"[{status}] {name}: {result}", file=sys.stderr)
        manifest += [f"{name}  [{status}]", f"  {section.get('about', '')}", f"  from: {section.get('url', '')}",
                     f"  licence: {section.get('licence', 'not stated')}", f"  result: {result}", ""]
    (args.out / "SOURCES.txt").write_text("\n".join(manifest), encoding="utf-8")
    # Read by collect-content.sh: YARA rule sets go into the product together or not at all (tools/yara_sources.py).
    (args.out / "yara-sources.txt").write_text("".join(line + "\n" for line in yara_status), encoding="utf-8")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
