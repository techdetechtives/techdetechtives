# TechDetechtives network inventory: pages.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Server-rendered pages. No scripts and no external assets: plain HTML, CSS
and inline SVG, so they work on an isolated network. Every value that came off
the wire (host names, device descriptions, operation names) is escaped."""

from __future__ import annotations

import base64
import csv
import hmac
import io
import ipaddress
import math
import re
import ssl
import urllib.parse
from datetime import datetime, timedelta, timezone
from html import escape as e
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable

from . import VERSION
from .protocols import industrial_vendor
from .store import Store, parse, stamp
from .sync import OUTSIDE, PSEUDO, Scope

BUILTIN_LOGO = b"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="TechDetechtives">
  <title>TechDetechtives</title>
  <rect width="64" height="64" rx="14" fill="#0b0b0d"/>
  <g fill="none" stroke="#ffffff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round">
    <path d="M51.97 37.49A21 21 0 1 0 12.27 38.18 M45.69 28.09A14 14 0 1 0 23.38 42.03 M37.36 35.50A7 7 0 1 0 25.00 31.00"/>
    <path d="M12.27 38.18V52.00 M45.69 28.09V49.50 M25.00 31.00V47.00"/>
  </g>
  <g fill="#f60411">
    <circle cx="12.27" cy="52.00" r="3.6"/>
    <circle cx="45.69" cy="49.50" r="3.6"/>
    <circle cx="25.00" cy="47.00" r="3.6"/>
  </g>
</svg>
"""
LOGO_TYPES = {".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp"}
MAX_LOGO_BYTES = 512 * 1024
SEVERITY = {1: "low", 2: "medium", 3: "high"}

# Two categories, two colours: industrial (orange) and everything else (blue).
# Both pairs pass the dataviz palette validator on their surface, colour-blind
# checks included. Severity chips reuse the ramp of the vulnerability dashboard.
# Text always wears the ink tokens; colour is only on marks, beside a label.
CSS = """
:root{color-scheme:light;--page:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#6f6d68;
--grid:#e1e0d9;--axis:#c3c2b7;--border:rgba(11,11,11,.10);--link:#184f95;
--it:#2a78d6;--ot:#eb6834;--low:#e99a78;--medium:#e8703f;--high:#c93a32}
@media (prefers-color-scheme:dark){:root{color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--ink:#fff;--ink2:#c3c2b7;
--muted:#9a988f;--grid:#2c2c2a;--axis:#383835;--border:rgba(255,255,255,.10);--link:#86b6ef;
--it:#3987e5;--ot:#d95926;--low:#8a3526;--medium:#c44f2f;--high:#ec835a}}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:var(--link)}
header{background:var(--band);color:var(--band-ink);border-bottom:3px solid var(--accent)}
.bar{max-width:1180px;margin:0 auto;padding:12px 16px;display:flex;flex-wrap:wrap;gap:8px 28px;align-items:center}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:18px;letter-spacing:-.01em;color:var(--band-ink);text-decoration:none}.brand img{width:38px;height:38px;border-radius:9px;flex:none}.brand span{font-weight:400;opacity:.72}
nav{display:flex;flex-wrap:wrap;gap:4px 20px}nav a{text-decoration:none;color:var(--band-ink);opacity:.72;padding:3px 0;border-bottom:2px solid transparent}
nav a.on{opacity:1;font-weight:600;border-bottom-color:var(--accent)}nav a:hover{opacity:1}a:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:2px}
main{max-width:1180px;margin:0 auto;padding:20px 16px 48px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:0 0 2px}
.sub{color:var(--ink2);margin:0 0 16px}.note{color:var(--ink2);font-size:13px;margin:0 0 12px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px;margin:0 0 16px}
.notice{border-left:4px solid var(--medium)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(150px,100%),1fr));gap:12px;margin:0 0 16px}
.tile{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:14px 16px;text-decoration:none;color:inherit}
.tile .l{color:var(--ink2);font-size:13px;display:flex;align-items:center;gap:6px}
.tile .v{font-size:28px;font-weight:650;line-height:1.2}.tile.hero .v{font-size:48px}
.tile .d{color:var(--ink2);font-size:13px}
.sw{display:inline-block;width:10px;height:10px;border-radius:3px;flex:none}
.sw.ot{background:var(--ot)}.sw.it{background:var(--it)}.sw.high{background:var(--high)}.sw.medium{background:var(--medium)}.sw.low{background:var(--low)}
.sw.ring{background:none;border:2px solid var(--muted);border-radius:50%}
.legend{display:flex;flex-wrap:wrap;gap:4px 18px;color:var(--ink2);font-size:13px;margin:8px 0 0}
.legend span{display:inline-flex;align-items:center;gap:6px}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(340px,100%),1fr));gap:16px;margin:0 0 16px}
.grid2 .card{margin:0}
svg{display:block;width:100%;height:auto}
svg text{fill:var(--muted);font:12px system-ui,-apple-system,"Segoe UI",sans-serif}
svg .val{fill:var(--ink2)}svg .strong{fill:var(--ink);font-weight:600}svg .gl{stroke:var(--grid);stroke-width:1}svg .ax{stroke:var(--axis);stroke-width:1}
.ot-f{fill:var(--ot)}.it-f{fill:var(--it)}
.ot-s{stroke:var(--ot)}.it-s{stroke:var(--it)}
.edge{fill:none;stroke-linecap:round;opacity:.6}.edge.new{stroke-dasharray:5 4;opacity:.95}
.node circle{stroke:var(--surface);stroke-width:2}.node.pseudo circle{fill:var(--surface);stroke:var(--muted)}
.node text,.zone{paint-order:stroke;stroke:var(--surface);stroke-width:4px;stroke-linejoin:round}
.node text{fill:var(--ink2)}.node:hover text,.node:focus text{fill:var(--ink)}
.map{min-width:760px}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:14px}
th{text-align:left;color:var(--ink2);font-weight:600;font-size:13px;border-bottom:1px solid var(--axis);padding:6px 14px 6px 0;white-space:nowrap}
td{border-bottom:1px solid var(--grid);padding:7px 14px 7px 0;vertical-align:top;overflow-wrap:break-word}
td .note{display:block;margin:0}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}td.k{white-space:nowrap}
.chip{display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.tag{display:inline-block;border:1px solid var(--border);border-radius:999px;padding:0 8px;font-size:12px;color:var(--ink2);white-space:nowrap}
.filters{display:flex;flex-wrap:wrap;gap:6px 8px;margin:0 0 12px}
.filters a{display:inline-flex;align-items:center;gap:6px;text-decoration:none;color:var(--ink2);border:1px solid var(--border);border-radius:999px;padding:3px 12px;font-size:13px}
.filters a.on{color:var(--ink);border-color:var(--ink);font-weight:600}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 18px;margin:0}dt{color:var(--ink2)}dd{margin:0;overflow-wrap:anywhere}
table.devices td:nth-child(4),table.devices td:nth-child(5){min-width:150px}
code{font:13px ui-monospace,monospace}
footer{max-width:1180px;margin:0 auto;padding:0 16px 32px;color:var(--muted);font-size:13px}
"""


def load_logo(path: str) -> tuple[bytes, str]:
    try:
        file = Path(path)
        kind = LOGO_TYPES.get(file.suffix.lower())
        if kind and file.is_file() and 0 < file.stat().st_size <= MAX_LOGO_BYTES:
            return file.read_bytes(), kind
    except OSError:
        pass
    return BUILTIN_LOGO, "image/svg+xml"


def readable_ink(colour: str) -> str:
    channels = []
    for i in (1, 3, 5):
        c = int(colour[i:i + 2], 16) / 255
        channels.append(c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4)
    return "#ffffff" if 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2] < 0.4 else "#0b0b0b"


# ---- small formatters -----------------------------------------------------------
def volume(value: float) -> str:
    value = float(value or 0)
    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:,.0f} {unit}" if unit == "bytes" else f"{value:,.1f} {unit}"
        value /= 1024
    return ""


def short_date(value: str) -> str:
    return (value or "")[:16].replace("T", " ")


def chip(severity: int) -> str:
    name = SEVERITY.get(int(severity or 1), "low")
    return f'<span class="chip"><span class="sw {name}"></span>{name.title()}</span>'


def kind_chip(industrial: bool) -> str:
    return (f'<span class="chip"><span class="sw {"ot" if industrial else "it"}"></span>'
            f'{"Industrial" if industrial else "Other"}</span>')


def node_name(node: str) -> str:
    return PSEUDO.get(node, node)


def node_link(node: str) -> str:
    if node in PSEUDO:
        return e(PSEUDO[node])
    return f'<a href="/devices/{urllib.parse.quote(node, safe="")}">{e(node)}</a>'


def address_key(value: str):
    try:
        address = ipaddress.ip_address(value)
        return (address.version, int(address))
    except ValueError:
        return (9, 0)


def is_industrial(asset: dict) -> bool:
    return bool(asset["serves"] or asset["starts"] or asset["vendor"] or industrial_vendor(asset["maker"]))


def how_note(how: str) -> str:
    return "" if how == "decoded" else ' <span class="tag" title="Known only from the port number; the contents were not read">by port</span>'


def nice_ceiling(value: float) -> float:
    if value <= 0:
        return 1.0
    magnitude = 10 ** math.floor(math.log10(value))
    for step in (1, 2, 4, 5, 8, 10):
        if step * magnitude >= value:
            return step * magnitude
    return 10 * magnitude


def byte_axis(top: float) -> tuple[float, str, float]:
    """(axis maximum in bytes, unit name, bytes per unit) with a round maximum in that unit."""
    unit, size = "bytes", 1.0
    for name, factor in (("KB", 1024.0), ("MB", 1024.0 ** 2), ("GB", 1024.0 ** 3), ("TB", 1024.0 ** 4)):
        if top >= factor:
            unit, size = name, factor
    return nice_ceiling(top / size) * size, unit, size


# ---- charts -----------------------------------------------------------------------
def protocol_bars(rows: list[dict], industrial: bool) -> str:
    """Volume per protocol, one bar each, largest first."""
    rows = [row for row in rows if bool(row["industrial"]) == industrial][:10]
    if not rows:
        return ('<p class="note">No industrial protocol has been seen yet.</p>' if industrial
                else '<p class="note">Nothing recorded yet.</p>')
    # A conversation known only from its decoded operations has no byte count; rank those by devices instead.
    measure = "volume" if any(row["volume"] for row in rows) else "answering"
    top = max(row[measure] for row in rows) or 1
    label_w, value_w, width, row_h, bar_h = 190, 96, 560, 26, 14
    scale = (width - label_w - value_w) / top
    out = [f'<svg viewBox="0 0 {width} {row_h * len(rows)}" role="img" '
           f'aria-label="{"Industrial" if industrial else "Other"} protocols by volume">']
    for index, row in enumerate(rows):
        y = row_h * index + (row_h - bar_h) / 2
        label = row["label"] if len(row["label"]) <= 28 else row["label"][:27] + "…"
        suffix = "" if row["how"] == "decoded" else " (by port)"
        shown = volume(row["volume"]) if measure == "volume" else f'{row["answering"]:,} devices'
        w = max(row[measure] * scale, 2)
        out.append(f'<text class="val" x="0" y="{y + 11:.1f}"><title>{e(row["label"] + suffix)}</title>{e(label)}</text>')
        out.append(f'<rect class="{"ot" if industrial else "it"}-f" x="{label_w}" y="{y:.1f}" width="{w:.1f}" height="{bar_h}" '
                   f'rx="{4 if w >= 8 else 1}"><title>{e(row["label"] + suffix)}: {volume(row["volume"])}, '
                   f'{row["connections"]:,} connections, answered by {row["answering"]:,} devices</title></rect>')
        out.append(f'<text class="val" x="{label_w + w + 8:.1f}" y="{y + 11:.1f}">{e(shown)}</text>')
    out.append("</svg>")
    return "".join(out)


def hour_columns(hours: list, industrial: bool, now: datetime, span: int = 48) -> str:
    """Volume per hour for the last two days."""
    by_hour = {row["hour"]: row["bytes"] for row in hours if bool(row["industrial"]) == industrial}
    start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=span - 1)
    series = [(start + timedelta(hours=index)) for index in range(span)]
    values = [by_hour.get(stamp(moment), 0) for moment in series]
    if not any(values):
        return '<p class="note">No traffic recorded in the last two days.</p>'
    top, unit, size = byte_axis(max(values))
    left, right, plot_h, top_pad, band, width = 52, 8, 150, 14, 26, 560
    slot = (width - left - right) / span
    bar_w = max(slot - 2, 2)          # 2px surface gap between neighbours
    out = [f'<svg viewBox="0 0 {width} {top_pad + plot_h + band}" role="img" '
           f'aria-label="{"Industrial" if industrial else "Other"} traffic per hour, last {span} hours">']
    for i in range(5):
        y = top_pad + plot_h - plot_h * i / 4
        out.append(f'<line class="{"ax" if i == 0 else "gl"}" x1="{left}" x2="{width - right}" y1="{y:.1f}" y2="{y:.1f}"/>')
        out.append(f'<text x="{left - 8}" y="{y + 4:.1f}" text-anchor="end">{top / size * i / 4:,.4g}</text>')
    out.append(f'<text x="0" y="10">{unit}</text>')
    for index, (moment, value) in enumerate(zip(series, values)):
        x = left + slot * index + (slot - bar_w) / 2
        h = plot_h * value / top
        if value:
            h = max(h, 1.5)
            out.append(f'<rect class="{"ot" if industrial else "it"}-f" x="{x:.1f}" y="{top_pad + plot_h - h:.1f}" width="{bar_w:.1f}" '
                       f'height="{h:.1f}" rx="{2 if h >= 4 else 0}"><title>{moment:%Y-%m-%d %H}:00 UTC: {volume(value)}</title></rect>')
        if moment.hour % 12 == 0:
            label = f"{moment:%d %b}" if moment.hour == 0 else f"{moment:%H}:00"
            out.append(f'<text x="{x + bar_w / 2:.1f}" y="{top_pad + plot_h + 17}" text-anchor="middle">{label}</text>')
    out.append("</svg>")
    return "".join(out)


def talker_bars(assets: list[dict]) -> str:
    rows = sorted(assets, key=lambda asset: asset["sent"] + asset["received"], reverse=True)[:10]
    rows = [row for row in rows if row["sent"] + row["received"] > 0]
    if not rows:
        return '<p class="note">No traffic volumes recorded yet.</p>'
    top = max(row["sent"] + row["received"] for row in rows)
    label_w, value_w, width, row_h, bar_h = 190, 96, 560, 26, 14
    scale = (width - label_w - value_w) / top
    out = [f'<svg viewBox="0 0 {width} {row_h * len(rows)}" role="img" aria-label="Busiest devices by traffic volume">']
    for index, row in enumerate(rows):
        y = row_h * index + (row_h - bar_h) / 2
        total = row["sent"] + row["received"]
        name = row["name"] or row["ip"]
        shown = name if len(name) <= 26 else name[:25] + "…"
        w = max(total * scale, 2)
        out.append(f'<a href="/devices/{urllib.parse.quote(row["ip"], safe="")}"><text class="val" x="0" y="{y + 11:.1f}">'
                   f'<title>{e(row["ip"])}</title>{e(shown)}</text></a>')
        out.append(f'<rect class="{"ot" if is_industrial(row) else "it"}-f" x="{label_w}" y="{y:.1f}" width="{w:.1f}" height="{bar_h}" '
                   f'rx="{4 if w >= 8 else 1}"><title>{e(name)}: sent {volume(row["sent"])}, received {volume(row["received"])}</title></rect>')
        out.append(f'<text class="val" x="{label_w + w + 8:.1f}" y="{y + 11:.1f}">{volume(total)}</text>')
    out.append("</svg>")
    return "".join(out) + ('<div class="legend"><span><span class="sw ot"></span>Industrial device</span>'
                           '<span><span class="sw it"></span>Other device</span></div>')


ROWS = ("Outside and broadcast", "Stations: they start industrial conversations",
        "Controllers and field devices: they answer", "Other devices")
PER_LINE, MAP_WIDTH, LINE_H = 9, 1120, 104


def traffic_map(links: list[dict], assets: dict[str, dict], scope: Scope, max_nodes: int = 72, max_links: int = 220) -> tuple[str, str]:
    """(svg, note). Devices in rows by what they do; one line per pair of devices and protocol."""
    if not links:
        return "", ""
    weight: dict[str, float] = {}
    for link in links:
        for end in (link["src"], link["dst"]):
            weight[end] = weight.get(end, 0) + (link["volume"] or 0) + 1
    keep = set(sorted(weight, key=lambda node: weight[node], reverse=True)[:max_nodes])
    shown = [link for link in links if link["src"] in keep and link["dst"] in keep][:max_links]
    note = ""
    if len(keep) < len(weight) or len(shown) < len(links):
        note = (f"Showing the {len(keep):,} busiest of {len(weight):,} devices and {len(shown):,} of {len(links):,} lines. "
                "The tables below list everything.")

    def row_of(node: str) -> int:
        if node in PSEUDO:
            return 0
        asset = assets.get(node) or {}
        if asset.get("serves"):
            return 2
        return 1 if asset.get("starts") else 3

    rows: dict[int, list[str]] = {0: [], 1: [], 2: [], 3: []}
    for node in keep:
        rows[row_of(node)].append(node)
    position: dict[str, tuple[float, float]] = {}
    label_side: dict[int, bool] = {}
    parts: list[str] = []
    titles: list[str] = []
    y = 0.0
    for index in range(4):
        nodes = sorted(rows[index], key=lambda node: (scope.zone(node), address_key(node)))
        if not nodes:
            continue
        y += 22
        titles.append(f'<text class="strong zone" x="0" y="{y:.0f}">{e(ROWS[index])}</text>')
        # Rows that start conversations carry their labels above the dot, rows that
        # answer carry them below, so the lines between two rows cross open space.
        above = index < 2
        label_side[index] = above
        for line_start in range(0, len(nodes), PER_LINE):
            line = nodes[line_start:line_start + PER_LINE]
            slot = MAP_WIDTH / PER_LINE
            offset = (MAP_WIDTH - slot * len(line)) / 2
            cy = y + (62 if above else 34)
            run_start = 0
            for i, node in enumerate(line):
                position[node] = (offset + slot * i + slot / 2, cy)
                last = i == len(line) - 1
                if index and (last or scope.zone(line[i + 1]) != scope.zone(node)):
                    # One bracket per run of neighbours in the same zone.
                    x1 = position[line[run_start]][0] - slot / 2 + 8
                    x2 = position[node][0] + slot / 2 - 8
                    zone = scope.zone(node)
                    room = max(int((x2 - x1) / 6.6), 6)
                    rule, text = (cy - 36, cy - 42) if above else (cy + 36, cy + 51)
                    parts.append(f'<line class="ax" x1="{x1:.0f}" x2="{x2:.0f}" y1="{rule:.0f}" y2="{rule:.0f}"/>')
                    parts.append(f'<text class="zone" x="{(x1 + x2) / 2:.0f}" y="{text:.0f}" text-anchor="middle"><title>Zone {e(zone)}</title>'
                                 f'{e(zone if len(zone) <= room else zone[:room - 1] + "…")}</text>')
                    run_start = i + 1
            y += LINE_H
        y += 4
    height = y + 6

    top = max((link["volume"] or 0) for link in shown) or 1
    edges = []
    for link in sorted(shown, key=lambda item: item["industrial"]):       # industrial lines drawn last, on top
        (x1, y1), (x2, y2) = position[link["src"]], position[link["dst"]]
        width = 1.25 + 3.75 * (math.log1p(link["volume"] or 0) / math.log1p(top))
        if abs(y1 - y2) < 1:
            lift = min(26 + abs(x2 - x1) * 0.12, 60)
            path = f"M{x1:.1f},{y1 - 9:.1f} Q{(x1 + x2) / 2:.1f},{y1 - 9 - lift:.1f} {x2:.1f},{y2 - 9:.1f}"
        else:
            down = y2 > y1
            a, b = (y1 + 9, y2 - 9) if down else (y1 - 9, y2 + 9)
            mid = (a + b) / 2
            path = f"M{x1:.1f},{a:.1f} C{x1:.1f},{mid:.1f} {x2:.1f},{mid:.1f} {x2:.1f},{b:.1f}"
        kind = "ot" if link["industrial"] else "it"
        new = "" if link["baseline"] else " new"
        title = (f'{node_name(link["src"])} to {node_name(link["dst"])}: {link["label"]}'
                 f'{"" if link["how"] == "decoded" else " (by port)"}, {volume(link["volume"])}, '
                 f'{link["connections"]:,} connections, last seen {short_date(link["last_seen"])} UTC'
                 f'{"" if link["baseline"] else ". Not in the baseline."}')
        edges.append(f'<path class="edge {kind}-s{new}" stroke-width="{width:.2f}" marker-end="url(#arrow-{kind})" d="{path}">'
                     f'<title>{e(title)}</title></path>')
    nodes_svg = []
    for node, (x, cy) in position.items():
        asset = assets.get(node) or {}
        pseudo = node in PSEUDO
        label = ("Outside" if node == OUTSIDE else "Broadcast") if pseudo else (asset.get("name") or node)
        label = label if len(label) <= 17 else label[:16] + "…"
        kind = "ot" if (not pseudo and is_industrial(asset)) else "it"
        described = " ".join(part for part in (asset.get("vendor"), asset.get("model")) if part) or asset.get("maker") or ""
        title = node_name(node) + (f" ({asset['name']})" if asset.get("name") else "") + (f": {described}" if described else "")
        label_y = cy - 16 if label_side.get(row_of(node)) else cy + 25
        body = (f'<circle class="{kind}-f" cx="{x:.1f}" cy="{cy:.1f}" r="9"><title>{e(title)}</title></circle>'
                f'<text x="{x:.1f}" y="{label_y:.1f}" text-anchor="middle">{e(label)}</text>')
        if pseudo:
            nodes_svg.append(f'<g class="node pseudo">{body}</g>')
        else:
            nodes_svg.append(f'<a class="node" href="/devices/{urllib.parse.quote(node, safe="")}">{body}</a>')
    markers = "".join(
        f'<marker id="arrow-{kind}" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="9" markerHeight="9" markerUnits="userSpaceOnUse" orient="auto">'
        f'<path class="{kind}-f" d="M0,0 L8,4 L0,8 z"/></marker>' for kind in ("ot", "it"))
    svg = (f'<div class="scroll"><svg class="map" viewBox="0 0 {MAP_WIDTH} {height:.0f}" role="img" '
           f'aria-label="Traffic map: devices in rows by what they do, one line per pair of devices and protocol">'
           f'<defs>{markers}</defs>{"".join(parts)}{"".join(edges)}{"".join(nodes_svg)}{"".join(titles)}</svg></div>'
           '<div class="legend"><span><span class="sw ot"></span>Industrial protocol or device</span>'
           '<span><span class="sw it"></span>Other</span><span><span class="sw ring"></span>Not a single device</span>'
           '<span>Thicker line: more data</span><span>Dashed line: not in the baseline</span>'
           '<span>The arrow points at the device that answers</span></div>')
    return svg, note


# ---- pages -----------------------------------------------------------------------
def page(title: str, active: str, body: str, config) -> bytes:
    links = [("/", "Overview"), ("/devices", "Devices"), ("/map", "Traffic map"), ("/operations", "Industrial operations"),
             ("/changes", "Changes")]
    nav = "".join(f'<a href="{href}" class="{"on" if href == active else ""}">{label}</a>' for href, label in links)
    if config.soc_url:
        nav += f'<a href="{e(config.soc_url, quote=True)}" rel="noreferrer">Open platform</a>'
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>{e(title)} | {e(config.brand_name)}</title><link rel=\"icon\" href=\"/brand/logo\">"
        f"<style>{CSS}</style></head><body>"
        # The brand colours are validated as #rrggbb in Config before they reach this attribute.
        f"<header style=\"--band:{config.brand_header};--band-ink:{readable_ink(config.brand_header)};--accent:{config.brand_accent}\">"
        f"<div class=\"bar\"><a class=\"brand\" href=\"/\"><img src=\"/brand/logo\" alt=\"\">"
        f"{e(config.brand_name)} <span>Network</span></a><nav>{nav}</nav></div></header>"
        f"<main>{body}</main><footer>{e(config.brand_name)} network inventory {VERSION}. Built from what the platform's "
        "sensor recorded; nothing is sent to the devices themselves.</footer></body></html>"
    ).encode("utf-8")


def status_notice(store: Store, now: datetime) -> str:
    status = store.meta("status", {}) or {}
    lines = []
    if status.get("error"):
        lines.append(f"The last read from the platform failed: {e(status['error'])}")
    elif not status:
        lines.append("Nothing has been read from the platform yet. The first pass starts within a minute of this part starting.")
    elif not status.get("seen_data"):
        lines.append("The platform has no connection records yet. They come from Zeek on the sensor: check that it is running "
                     "(<code>sudo so-status</code> on the platform) and that the monitored network card receives traffic.")
    for warning in status.get("warnings") or []:
        lines.append(e(warning))
    until = parse(store.meta("learning_until") or "")
    if status.get("seen_data") and until and now < until:
        lines.append(f"Learning what is normal until {until:%Y-%m-%d %H:%M} UTC. Everything seen before then is taken as the "
                     "baseline, and nothing is reported as a change.")
    if status.get("late_records") and not any("reached the platform" in line for line in lines):
        lines.append(f"{int(status['late_records']):,} connection records in all reached the platform too late to be counted "
                     "(see TD_NET_LAG_SECONDS).")
    if status.get("time_field") == "@timestamp":
        lines.append("The platform does not record when it stored each record, so a connection that stays open for longer than "
                     "this part looks back may be missed in the volumes. Industrial operations are not affected.")
    return f'<div class="card notice">{"<br>".join(lines)}</div>' if lines else ""


def changes_table(rows, with_state: bool = True) -> str:
    if not rows:
        return '<p class="note">No changes since the baseline.</p>'
    out = ['<div class="scroll"><table><thead><tr><th>When (UTC)</th><th>Severity</th><th>What</th><th>Device</th><th>Other end</th>'
           '<th>Details</th>' + ("<th>State</th>" if with_state else "") + "</tr></thead><tbody>"]
    for row in rows:
        out.append(f'<tr><td class="k">{e(short_date(row["at"]))}</td><td>{chip(row["severity"])}</td><td>{e(row["title"])}</td>'
                   f'<td class="k">{node_link(row["ip"]) if row["ip"] else ""}</td><td class="k">{node_link(row["peer"]) if row["peer"] else ""}</td>'
                   f'<td>{e(row["detail"])}</td>' + (f'<td class="k">{"Accepted" if row["accepted"] else "Open"}</td>' if with_state else "")
                   + "</tr>")
    out.append("</tbody></table></div>")
    return "".join(out)


def zone_table(assets: list[dict], scope: Scope) -> str:
    zones: dict[str, list[int]] = {}
    for asset in assets:
        entry = zones.setdefault(scope.zone(asset["ip"]), [0, 0, 0])
        entry[0] += 1
        entry[1] += 1 if is_industrial(asset) else 0
        entry[2] += asset["sent"] + asset["received"]
    if not zones:
        return '<p class="note">No devices yet.</p>'
    rows = "".join(
        f'<tr><td><a href="/devices?{urllib.parse.urlencode({"zone": name})}">{e(name)}</a></td><td class="n">{total:,}</td>'
        f'<td class="n">{industrial:,}</td><td class="n">{volume(data)}</td></tr>'
        for name, (total, industrial, data) in sorted(zones.items(), key=lambda item: (-item[1][1], -item[1][0]))[:12])
    more = f'<p class="note">The {len(zones) - 12:,} smallest zones are left out.</p>' if len(zones) > 12 else ""
    return ('<div class="scroll"><table><thead><tr><th>Zone</th><th class="n">Devices</th><th class="n">Industrial</th>'
            f'<th class="n">Traffic</th></tr></thead><tbody>{rows}</tbody></table></div>{more}')


def render_overview(store: Store, config, scope: Scope, now: datetime) -> bytes:
    counts, assets = store.counts(), store.assets()
    industrial = sum(1 for asset in assets if is_industrial(asset))
    mix = store.protocol_mix()
    hours = store.hours(stamp(now - timedelta(hours=49)))
    status = store.meta("status", {}) or {}
    synced = short_date(status.get("synced_at", ""))
    tiles = (
        f'<a class="tile hero" href="/devices"><div class="l">Devices seen</div><div class="v">{counts["assets"]:,}</div>'
        f'<div class="d">{industrial:,} industrial</div></a>'
        f'<a class="tile" href="/devices?show=industrial"><div class="l"><span class="sw ot"></span>Industrial devices</div>'
        f'<div class="v">{industrial:,}</div><div class="d">answering or using industrial protocols, or made by an industrial vendor</div></a>'
        f'<a class="tile" href="/map"><div class="l">Industrial conversations</div><div class="v">{counts["industrial_conversations"]:,}</div>'
        f'<div class="d">of {counts["conversations"]:,} in all</div></a>'
        f'<a class="tile" href="/operations"><div class="l">Industrial protocols</div><div class="v">{counts["industrial_protocols"]:,}</div>'
        f'<div class="d">{counts["operations"]:,} kinds of operation recorded</div></a>'
        f'<a class="tile" href="/changes"><div class="l">Open changes</div><div class="v">{counts["open_changes"]:,}</div>'
        f'<div class="d">since the baseline</div></a>')
    body = (
        f'<h1>Network overview</h1><p class="sub">Devices, conversations and industrial operations, as the platform\'s sensor '
        f'recorded them. {("Last read " + e(synced) + " UTC.") if synced else ""}</p>{status_notice(store, now)}'
        f'<div class="tiles">{tiles}</div>'
        '<div class="grid2">'
        f'<div class="card"><h2>Industrial protocols</h2><p class="note">Data carried since this part started, by protocol.</p>{protocol_bars(mix, True)}</div>'
        f'<div class="card"><h2>Other protocols</h2><p class="note">The ten largest. Each chart has its own scale.</p>{protocol_bars(mix, False)}</div>'
        '</div><div class="grid2">'
        f'<div class="card"><h2>Industrial traffic per hour</h2><p class="note">Last 48 hours, by the hour a connection started (UTC).</p>{hour_columns(hours, True, now)}</div>'
        f'<div class="card"><h2>Other traffic per hour</h2><p class="note">Last 48 hours. Each chart has its own scale.</p>{hour_columns(hours, False, now)}</div>'
        '</div>'
        '<div class="grid2">'
        f'<div class="card"><h2>Busiest devices</h2><p class="note">Data sent and received, ten largest.</p>{talker_bars(assets)}</div>'
        f'<div class="card"><h2>Zones</h2><p class="note">A named network from the settings, or else each /24 network.</p>{zone_table(assets, scope)}</div>'
        '</div>'
        f'<div class="card"><h2>Latest changes</h2><p class="note">New since the baseline. <a href="/changes">All changes</a></p>'
        f'{changes_table(store.changes(limit=8), with_state=False)}</div>')
    return page("Overview", "/", body, config)


def device_cells(asset: dict, scope: Scope) -> list[str]:
    identity = " ".join(part for part in (asset["vendor"], asset["model"], asset["version"]) if part)
    signals = [f'{asset[key]:,} {one if asset[key] == 1 else many}' for key, one, many in (
        ("alerts", "alert", "alerts"), ("findings", "finding", "findings"),
        ("honeypot", "honeypot contact", "honeypot contacts")) if asset[key]]
    return [asset["ip"], asset["name"], scope.zone(asset["ip"]), asset["role"], identity, asset["maker"],
            ", ".join(asset["answers"][:6]), ", ".join(asset["uses"][:6]), str(asset["peers"]),
            volume(asset["sent"] + asset["received"]), ", ".join(signals), short_date(asset["last_seen"])]


DEVICE_COLUMNS = ["Address", "Name", "Zone", "Role", "Says it is", "Card maker", "Answers", "Uses", "Peers", "Traffic",
                  "Also known for", "Last seen (UTC)"]


def render_devices(store: Store, config, scope: Scope, show: str, zone: str) -> bytes:
    assets = sorted(store.assets(), key=lambda asset: address_key(asset["ip"]))
    zones = sorted({scope.zone(asset["ip"]) for asset in assets})
    rows = [asset for asset in assets if (show != "industrial" or is_industrial(asset)) and (not zone or scope.zone(asset["ip"]) == zone)]
    query = lambda **kw: "/devices?" + urllib.parse.urlencode({k: v for k, v in kw.items() if v})  # noqa: E731
    filters = [f'<a href="{query(zone=zone)}" class="{"" if show else "on"}">All devices</a>',
               f'<a href="{query(show="industrial", zone=zone)}" class="{"on" if show == "industrial" else ""}">'
               '<span class="sw ot"></span>Industrial</a>']
    for name in zones[:30]:
        filters.append(f'<a href="{query(show=show, zone="" if zone == name else name)}" class="{"on" if zone == name else ""}">{e(name)}</a>')
    table = '<p class="note">No devices match.</p>'
    if rows:
        lines = []
        for asset in rows:
            cells = device_cells(asset, scope)
            new = "" if asset["baseline"] else ' <span class="tag">new</span>'
            name = f'<span class="note">{e(cells[1])}</span>' if cells[1] else ""
            role = (f'<span class="chip"><span class="sw ot"></span>{e(cells[3] or "Industrial")}</span>' if is_industrial(asset) else "")
            maker = f'<span class="note">Card by {e(cells[5])}</span>' if cells[5] else ""
            answers = f'Answers {e(cells[6])}' if cells[6] else ""
            uses = f'<span class="note">Uses {e(cells[7])}</span>' if cells[7] else ""
            lines.append(
                f'<tr><td class="k">{node_link(asset["ip"])}{new}{name}</td><td class="k">{e(cells[2])}</td><td>{role}</td>'
                f'<td>{e(cells[4])}{maker}</td><td>{answers}{uses}</td>'
                f'<td class="n">{asset["peers"]:,}</td><td class="n">{e(cells[9])}</td><td>{e(cells[10])}</td><td class="k">{e(cells[11])}</td></tr>')
        table = ('<div class="scroll"><table class="devices"><thead><tr><th>Address and name</th><th>Zone</th><th>Role</th><th>What it is</th>'
                 '<th>Protocols</th><th class="n">Peers</th><th class="n">Traffic</th><th>Also known for</th><th>Last seen (UTC)</th>'
                 f'</tr></thead><tbody>{"".join(lines)}</tbody></table></div>')
    body = (f'<h1>Devices</h1><p class="sub">{len(rows):,} of {len(assets):,} devices inside the monitored networks. '
            f'<a href="/devices.csv">Download all as CSV</a></p><div class="filters">{"".join(filters)}</div>'
            f'<div class="card">{table}</div>'
            '<p class="note">"What it is" comes from what a device announces about itself (EtherNet/IP identity, BACnet I-Am). '
            'The maker of its network card is only known for devices on the same network segment as the sensor.</p>')
    return page("Devices", "/devices", body, config)


def csv_cell(value) -> str:
    """Stop spreadsheet programs treating text from the network as a formula."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def render_devices_csv(store: Store, scope: Scope) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["address", "name", "zone", "role", "says_it_is", "card_maker", "answers", "uses", "peers", "traffic",
                     "also_known_for", "last_seen_utc", "serial", "card_address", "software", "first_seen_utc", "in_baseline"])
    for asset in sorted(store.assets(), key=lambda item: address_key(item["ip"])):
        writer.writerow([csv_cell(value) for value in device_cells(asset, scope) + [
            asset["serial"], asset["mac"], asset["software"], short_date(asset["first_seen"]), "yes" if asset["baseline"] else "no"]])
    return buffer.getvalue().encode("utf-8")


def conversation_table(rows, ip: str = "") -> str:
    if not rows:
        return '<p class="note">None recorded.</p>'
    out = ['<div class="scroll"><table><thead><tr><th>From</th><th>To</th><th>Protocol</th><th>Port</th><th class="n">Connections</th>'
           '<th class="n">Sent</th><th class="n">Answered</th><th>Last seen (UTC)</th></tr></thead><tbody>']
    for row in rows:
        new = "" if row["baseline"] else ' <span class="tag">new</span>'
        port = f'{e(row["transport"])}/{row["port"]}' if row["port"] else e(row["transport"])
        out.append(
            f'<tr><td class="k">{e(node_name(row["src"])) if row["src"] == ip else node_link(row["src"])}</td>'
            f'<td class="k">{e(node_name(row["dst"])) if row["dst"] == ip else node_link(row["dst"])}</td>'
            f'<td><span class="chip"><span class="sw {"ot" if row["industrial"] else "it"}"></span>{e(row["label"])}</span>'
            f'{how_note(row["how"])}{new}</td><td class="k">{port}</td><td class="n">{row["connections"]:,}</td>'
            f'<td class="n">{volume(row["bytes_out"])}</td><td class="n">{volume(row["bytes_in"])}</td>'
            f'<td class="k">{e(short_date(row["last_seen"]))}</td></tr>')
    out.append("</tbody></table></div>")
    return "".join(out)


def operation_table(rows) -> str:
    if not rows:
        return '<p class="note">None recorded.</p>'
    out = ['<div class="scroll"><table><thead><tr><th>From</th><th>To</th><th>Protocol</th><th>Operation</th><th>Kind</th>'
           '<th class="n">Times</th><th>First seen (UTC)</th><th>Last seen (UTC)</th></tr></thead><tbody>']
    for row in rows:
        new = "" if row["baseline"] else ' <span class="tag">new</span>'
        out.append(f'<tr><td class="k">{node_link(row["src"])}</td><td class="k">{node_link(row["dst"])}</td><td>{e(row["label"])}</td>'
                   f'<td>{e(row["operation"])}{new}</td><td class="k">{"Changes the device" if row["control"] else "Reads"}</td>'
                   f'<td class="n">{row["count"]:,}</td><td class="k">{e(short_date(row["first_seen"]))}</td>'
                   f'<td class="k">{e(short_date(row["last_seen"]))}</td></tr>')
    out.append("</tbody></table></div>")
    return "".join(out)


def render_device(store: Store, config, scope: Scope, asset: dict) -> bytes:
    ip = asset["ip"]
    facts = [("Address", e(ip)), ("Zone", e(scope.zone(ip))), ("Name", e(asset["name"])), ("Role", e(asset["role"])),
             ("Says it is", e(" ".join(part for part in (asset["vendor"], asset["model"]) if part))
              + (f' <span class="note">(from its {e(asset["identity_via"])})</span>' if asset["identity_via"] and asset["vendor"] else "")),
             ("Version", e(asset["version"])), ("Serial number", e(asset["serial"])), ("Device type", e(asset["kind"])),
             ("Card maker", e(asset["maker"])), ("Card address", e(asset["mac"])), ("Software seen", e(asset["software"])),
             ("First seen", e(short_date(asset["first_seen"])) + " UTC"), ("Last seen", e(short_date(asset["last_seen"])) + " UTC"),
             ("In the baseline", "Yes" if asset["baseline"] else "No, first seen after it was learned")]
    listing = "".join(f"<dt>{label}</dt><dd>{value}</dd>" for label, value in facts if value and value != " UTC")
    hunt = ""
    if config.soc_url:
        search = urllib.parse.quote(f'source.ip:"{ip}" OR destination.ip:"{ip}"', safe="")
        hunt = f' · <a href="{e(config.soc_url, quote=True)}/#/hunt?q={search}" rel="noreferrer">Search this address on the platform</a>'
    tiles = "".join(
        f'<div class="tile"><div class="l">{label}</div><div class="v">{value}</div><div class="d">{detail}</div></div>'
        for label, value, detail in (
            ("Alerts, last 7 days", f'{asset["alerts"]:,}', f'worst: {SEVERITY.get(asset["worst_alert"], "critical" if asset["worst_alert"] > 3 else "none")}' if asset["alerts"] else "as source or destination"),
            ("Vulnerability findings", f'{asset["findings"]:,}', "from Greenbone scans sent to the platform"),
            ("Honeypot contacts", f'{asset["honeypot"]:,}', "times this address touched a decoy"),
            ("Peers", f'{asset["peers"]:,}', "devices it talked with"),
            ("Traffic", volume(asset["sent"] + asset["received"]), f'sent {volume(asset["sent"])}, received {volume(asset["received"])}')))
    conversations = store.conversations(ip=ip, limit=500)
    body = (f'<p class="note"><a href="/devices">← All devices</a></p><h1>{e(asset["name"] or ip)}</h1>'
            f'<p class="sub">{kind_chip(is_industrial(asset))}{hunt}</p>'
            f'<div class="tiles">{tiles}</div>'
            f'<div class="card"><h2>What is known</h2><p class="note">Read from traffic. Nothing was asked of the device.</p><dl>{listing}</dl></div>'
            f'<div class="card"><h2>It answers</h2><p class="note">Conversations others start with this device.</p>'
            f'{conversation_table([row for row in conversations if row["dst"] == ip], ip)}</div>'
            f'<div class="card"><h2>It starts</h2><p class="note">Conversations this device starts.</p>'
            f'{conversation_table([row for row in conversations if row["src"] == ip], ip)}</div>'
            f'<div class="card"><h2>Industrial operations</h2><p class="note">Decoded by the sensor, to and from this device.</p>'
            f'{operation_table(store.operations(ip=ip, limit=300))}</div>'
            f'<div class="card"><h2>Changes</h2>{changes_table(store.changes(ip=ip, limit=100))}</div>')
    return page(asset["name"] or ip, "/devices", body, config)


def render_map(store: Store, config, scope: Scope, view: str) -> bytes:
    assets = {asset["ip"]: asset for asset in store.assets()}
    industrial_links = store.links(industrial_only=True)
    if view not in ("industrial", "all"):
        view = "industrial" if industrial_links else "all"
    links = industrial_links if view == "industrial" else store.links(industrial_only=False)
    svg, note = traffic_map(links, assets, scope)
    filters = (f'<a href="/map?view=industrial" class="{"on" if view == "industrial" else ""}"><span class="sw ot"></span>Industrial conversations</a>'
               f'<a href="/map?view=all" class="{"on" if view == "all" else ""}">All conversations</a>')
    zones: dict[tuple[str, str], dict] = {}
    for link in links:
        key = (scope.zone(link["src"]), scope.zone(link["dst"]))
        entry = zones.setdefault(key, {"volume": 0, "connections": 0, "labels": set(), "industrial": False, "pairs": 0})
        entry["volume"] += link["volume"] or 0
        entry["connections"] += link["connections"] or 0
        entry["labels"].add(link["label"])
        entry["industrial"] = entry["industrial"] or bool(link["industrial"])
        entry["pairs"] += 1
    zone_rows = "".join(
        f'<tr><td>{e(src)}</td><td>{e(dst)}</td><td>{kind_chip(entry["industrial"])}</td>'
        f'<td>{e(", ".join(sorted(entry["labels"])[:8]))}{" …" if len(entry["labels"]) > 8 else ""}</td>'
        f'<td class="n">{entry["pairs"]:,}</td><td class="n">{entry["connections"]:,}</td><td class="n">{volume(entry["volume"])}</td></tr>'
        for (src, dst), entry in sorted(zones.items(), key=lambda item: (item[0][0] == item[0][1], -item[1]["volume"])))
    link_rows = "".join(
        f'<tr><td class="k">{node_link(link["src"])}</td><td class="k">{node_link(link["dst"])}</td>'
        f'<td><span class="chip"><span class="sw {"ot" if link["industrial"] else "it"}"></span>{e(link["label"])}</span>{how_note(link["how"])}'
        f'{"" if link["baseline"] else " <span class=tag>new</span>"}</td><td class="n">{link["connections"]:,}</td>'
        f'<td class="n">{volume(link["volume"])}</td><td class="k">{e(short_date(link["last_seen"]))}</td></tr>' for link in links[:400])
    body = (f'<h1>Traffic map</h1><p class="sub">Who talks to whom. Devices are placed in rows by what they do, and next to '
            f'the others in their zone.</p><div class="filters">{filters}</div>'
            + (f'<div class="card">{f"<p class=note>{e(note)}</p>" if note else ""}{svg}</div>' if svg else
               '<div class="card"><p class="note">No conversations recorded yet.</p></div>')
            + '<div class="card"><h2>Between zones</h2><p class="note">Conversations that cross from one zone to another come first. '
              'A zone is a named network from the settings, or else each /24 network.</p>'
            + (f'<div class="scroll"><table><thead><tr><th>From zone</th><th>To zone</th><th>Kind</th><th>Protocols</th>'
               f'<th class="n">Lines</th><th class="n">Connections</th><th class="n">Data</th></tr></thead><tbody>{zone_rows}</tbody></table></div>'
               if zone_rows else '<p class="note">Nothing to show yet.</p>') + '</div>'
            + '<div class="card"><h2>Every line on the map</h2><p class="note">Largest first'
            + (f', first 400 of {len(links):,}' if len(links) > 400 else '') + '.</p>'
            + (f'<div class="scroll"><table><thead><tr><th>From</th><th>To</th><th>Protocol</th><th class="n">Connections</th>'
               f'<th class="n">Data</th><th>Last seen (UTC)</th></tr></thead><tbody>{link_rows}</tbody></table></div>'
               if link_rows else '<p class="note">Nothing to show yet.</p>') + '</div>')
    return page("Traffic map", "/map", body, config)


def render_operations(store: Store, config, show: str) -> bytes:
    rows = store.operations(control_only=show == "control")
    filters = (f'<a href="/operations" class="{"" if show == "control" else "on"}">All operations</a>'
               f'<a href="/operations?show=control" class="{"on" if show == "control" else ""}">Only those that change a device</a>')
    body = (f'<h1>Industrial operations</h1><p class="sub">What each station asked each device to do, for the protocols the sensor '
            f'decodes (Modbus, DNP3, S7comm, EtherNet/IP, BACnet, PROFINET, OPC UA). New ones come first.</p>'
            f'<div class="filters">{filters}</div><div class="card">{operation_table(rows)}</div>'
            '<p class="note">"Changes the device" covers writes, starts, stops, restarts and program transfers. '
            'Protocols known only by their port number have no operations here: their contents are not read. Neither has '
            'S7comm-plus (Siemens S7-1200 and S7-1500): the platform records that it was spoken, not what was asked.</p>')
    return page("Industrial operations", "/operations", body, config)


def render_changes(store: Store, config, now: datetime, show: str) -> bytes:
    rows = store.changes(open_only=show != "all")
    filters = (f'<a href="/changes" class="{"" if show == "all" else "on"}">Open</a>'
               f'<a href="/changes?show=all" class="{"on" if show == "all" else ""}">All, including accepted</a>')
    learned = store.meta("accepted_at") or store.meta("learning_until") or ""
    body = (f'<h1>Changes since the baseline</h1><p class="sub">Devices, industrial conversations and control commands that were not '
            f'there when the baseline was learned{(" (" + e(short_date(learned)) + " UTC)") if learned else ""}.</p>'
            f'{status_notice(store, now)}<div class="filters">{filters}</div><div class="card">{changes_table(rows)}</div>'
            '<p class="note">When everything listed is expected, take the present state as the new baseline on the machine that runs '
            'this part: <code>scripts/install.sh network --accept</code>. Changes at medium severity and above are also sent to the '
            'platform as alerts when its key is set, and from there become tickets.</p>')
    return page("Changes", "/changes", body, config)


def make_handler(config, open_store: Callable[[], Store], scope: Scope):
    expected = base64.b64encode(f"{config.web_user}:{config.web_password}".encode())
    realm = re.sub(r"[^A-Za-z0-9 ._-]", "", config.brand_name) + " network"

    class Handler(BaseHTTPRequestHandler):
        server_version = "TechDetechtives"
        sys_version = ""
        timeout = 30          # a connection that says nothing is dropped, TLS handshake included

        def log_message(self, *args) -> None:
            pass

        def _send(self, code: int, body: bytes, content_type: str = "text/html; charset=utf-8", extra=None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _authorised(self) -> bool:
            scheme, _, supplied = self.headers.get("Authorization", "").partition(" ")
            return scheme.lower() == "basic" and hmac.compare_digest(supplied.strip().encode("utf-8", "replace"), expected)

        def do_HEAD(self) -> None:
            self.do_GET()

        def do_GET(self) -> None:
            parsed = urllib.parse.urlsplit(self.path)
            path = parsed.path.rstrip("/") or "/"
            if path == "/healthz":
                return self._send(200, b"ok\n", "text/plain; charset=utf-8")
            if not self._authorised():
                return self._send(401, b"Sign in required.\n", "text/plain; charset=utf-8",
                                  {"WWW-Authenticate": f'Basic realm="{realm}", charset="UTF-8"'})
            query = urllib.parse.parse_qs(parsed.query)
            first = lambda name: (query.get(name) or [""])[0][:100]  # noqa: E731
            now = datetime.now(timezone.utc)
            store = open_store()
            try:
                if path == "/brand/logo":
                    logo, kind = load_logo(config.brand_logo)
                    return self._send(200, logo, kind)
                if path == "/":
                    return self._send(200, render_overview(store, config, scope, now))
                if path == "/devices":
                    return self._send(200, render_devices(store, config, scope, first("show"), first("zone")))
                if path == "/devices.csv":
                    return self._send(200, render_devices_csv(store, scope), "text/csv; charset=utf-8",
                                      {"Content-Disposition": 'attachment; filename="techdetechtives-devices.csv"'})
                if path.startswith("/devices/"):
                    asset = store.asset(urllib.parse.unquote(path[len("/devices/"):])[:64])
                    if asset is None:
                        return self._send(404, page("Not found", "/devices", "<h1>Device not found</h1>", config))
                    return self._send(200, render_device(store, config, scope, asset))
                if path == "/map":
                    return self._send(200, render_map(store, config, scope, first("view")))
                if path == "/operations":
                    return self._send(200, render_operations(store, config, first("show")))
                if path == "/changes":
                    return self._send(200, render_changes(store, config, now, first("show")))
                return self._send(404, page("Not found", "", "<h1>Page not found</h1>", config))
            finally:
                store.close()

    return Handler


def make_server(config, open_store: Callable[[], Store], scope: Scope) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((config.web_bind, config.web_port), make_handler(config, open_store, scope))
    server.daemon_threads = True
    return server


def use_tls(server: ThreadingHTTPServer, cert: str, key: str) -> None:
    """Serve over TLS. The handshake is left to each connection's own thread:
    done while accepting, one visitor who connects and then says nothing would
    keep everyone else waiting."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
