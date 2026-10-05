# TechDetechtives network inventory: local store.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""SQLite store: devices, who talks to whom, industrial operations, hourly
volume, and what changed since the baseline was learned.

Everything the sensor reports during the learning time is taken as normal
(baseline = 1). After that, a device, an industrial conversation or a control
operation that was not there before is written with baseline = 0 and the
caller records it as a change.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    ip TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT,
    maker TEXT DEFAULT '', mac TEXT DEFAULT '', name TEXT DEFAULT '',
    vendor TEXT DEFAULT '', model TEXT DEFAULT '', version TEXT DEFAULT '', serial TEXT DEFAULT '',
    kind TEXT DEFAULT '', identity_via TEXT DEFAULT '', software TEXT DEFAULT '',
    baseline INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS conversations (
    src TEXT NOT NULL, dst TEXT NOT NULL, port INTEGER NOT NULL, transport TEXT NOT NULL,
    label TEXT, industrial INTEGER DEFAULT 0, how TEXT,
    first_seen TEXT, last_seen TEXT, connections INTEGER DEFAULT 0,
    bytes_out INTEGER DEFAULT 0, bytes_in INTEGER DEFAULT 0, baseline INTEGER DEFAULT 0,
    PRIMARY KEY (src, dst, port, transport)
);
CREATE INDEX IF NOT EXISTS conversations_dst ON conversations (dst);
CREATE TABLE IF NOT EXISTS operations (
    src TEXT NOT NULL, dst TEXT NOT NULL, label TEXT NOT NULL, operation TEXT NOT NULL,
    control INTEGER DEFAULT 0, first_seen TEXT, last_seen TEXT, count INTEGER DEFAULT 0, baseline INTEGER DEFAULT 0,
    PRIMARY KEY (src, dst, label, operation)
);
CREATE TABLE IF NOT EXISTS hourly (
    hour TEXT NOT NULL, industrial INTEGER NOT NULL, bytes INTEGER DEFAULT 0, connections INTEGER DEFAULT 0,
    PRIMARY KEY (hour, industrial)
);
CREATE TABLE IF NOT EXISTS signals (
    ip TEXT PRIMARY KEY, alerts INTEGER DEFAULT 0, worst_alert INTEGER DEFAULT 0,
    findings INTEGER DEFAULT 0, worst_finding INTEGER DEFAULT 0, honeypot INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, kind TEXT, severity INTEGER,
    ip TEXT DEFAULT '', peer TEXT DEFAULT '', title TEXT, detail TEXT,
    accepted INTEGER DEFAULT 0, sent INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""

# Roles are read off the conversations: who answers industrial protocols and who starts them.
# Cyclic data sent to a multicast group does not make a controller a station.
ROLE_SQL = """
    (SELECT COUNT(*) FROM conversations c WHERE c.dst = a.ip AND c.industrial = 1) AS serves,
    (SELECT COUNT(*) FROM conversations c WHERE c.src = a.ip AND c.industrial = 1
        AND c.dst NOT IN ('outside', 'multicast')) AS starts
"""


def stamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse(value: str) -> Optional[datetime]:
    try:
        return datetime.strptime((value or "")[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def role_of(serves: int, starts: int) -> str:
    if serves and starts:
        return "Gateway or peer"
    if serves:
        return "Controller or field device"
    if starts:
        return "Station"
    return ""


class Store:
    def __init__(self, path: str, timeout: float = 30) -> None:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=timeout)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)

    def close(self) -> None:
        self.db.close()

    def commit(self) -> None:
        self.db.commit()

    # ---- settings kept between runs ------------------------------------------
    def meta(self, key: str, default: Any = None) -> Any:
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(row["value"]) if row else default

    def set_meta(self, key: str, value: Any) -> None:
        self.db.execute("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (key, json.dumps(value)))

    # ---- baseline --------------------------------------------------------------
    def start_learning(self, now: datetime, hours: float) -> None:
        if self.meta("learning_until") is None:
            self.set_meta("learning_from", stamp(now))
            self.set_meta("learning_until", stamp(now + timedelta(hours=hours)))

    def learning(self, now: datetime) -> bool:
        until = parse(self.meta("learning_until") or "")
        return until is None or now < until

    def accept_all(self, now: datetime) -> int:
        """Take everything seen so far as normal. Returns how many open changes that settles."""
        with self.db:
            for table in ("assets", "conversations", "operations"):
                self.db.execute(f"UPDATE {table} SET baseline = 1")
            settled = self.db.execute("UPDATE changes SET accepted = 1 WHERE accepted = 0").rowcount
            self.set_meta("learning_until", stamp(now))
            self.set_meta("accepted_at", stamp(now))
        return settled

    # ---- writing -----------------------------------------------------------------
    def see_asset(self, ip: str, when: str, baseline: bool) -> bool:
        """Record that a device exists. True when it was not known before."""
        row = self.db.execute("SELECT first_seen, last_seen FROM assets WHERE ip=?", (ip,)).fetchone()
        if row is None:
            self.db.execute("INSERT INTO assets (ip, first_seen, last_seen, baseline) VALUES (?,?,?,?)",
                            (ip, when, when, 1 if baseline else 0))
            return True
        if when > (row["last_seen"] or ""):
            self.db.execute("UPDATE assets SET last_seen=? WHERE ip=?", (when, ip))
        if when < (row["first_seen"] or when):
            self.db.execute("UPDATE assets SET first_seen=? WHERE ip=?", (when, ip))
        return False

    def describe_asset(self, ip: str, **fields: str) -> dict:
        """Fill in what is known about a device. Returns {field: (old, new)} for values that changed."""
        row = self.db.execute("SELECT * FROM assets WHERE ip=?", (ip,)).fetchone()
        if row is None:
            return {}
        changed = {}
        for key, value in fields.items():
            value = (value or "").strip()
            if value and value != row[key]:
                changed[key] = (row[key], value)
        if changed:
            assignments = ", ".join(f"{key}=?" for key in changed)
            self.db.execute(f"UPDATE assets SET {assignments} WHERE ip=?", [new for _, new in changed.values()] + [ip])
        return changed

    def add_conversation(self, src: str, dst: str, port: int, transport: str, label: str, industrial: bool, how: str,
                         when: str, connections: int, bytes_out: int, bytes_in: int, baseline: bool) -> bool:
        """Add to a conversation's totals. True when the pair had not talked on this port before."""
        key = (src, dst, port, transport)
        row = self.db.execute("SELECT how FROM conversations WHERE src=? AND dst=? AND port=? AND transport=?", key).fetchone()
        if row is None:
            self.db.execute(
                "INSERT INTO conversations (src, dst, port, transport, label, industrial, how, first_seen, last_seen, "
                "connections, bytes_out, bytes_in, baseline) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                key + (label, 1 if industrial else 0, how, when, when, connections, bytes_out, bytes_in, 1 if baseline else 0))
            return True
        # A protocol the sensor decoded beats a guess from the port number.
        relabel = how == "decoded" and row["how"] != "decoded"
        self.db.execute(
            "UPDATE conversations SET connections = connections + ?, bytes_out = bytes_out + ?, bytes_in = bytes_in + ?, "
            "last_seen = MAX(last_seen, ?), first_seen = MIN(first_seen, ?)"
            + (", label = ?, industrial = ?, how = ?" if relabel else "")
            + " WHERE src=? AND dst=? AND port=? AND transport=?",
            (connections, bytes_out, bytes_in, when, when) + ((label, 1 if industrial else 0, how) if relabel else ()) + key)
        return False

    def add_operation(self, src: str, dst: str, label: str, operation: str, control: bool, when: str, count: int,
                      baseline: bool) -> bool:
        """Add to an operation's count. True when this source had not asked this device for it before."""
        key = (src, dst, label, operation)
        if self.db.execute("SELECT 1 FROM operations WHERE src=? AND dst=? AND label=? AND operation=?", key).fetchone() is None:
            self.db.execute("INSERT INTO operations (src, dst, label, operation, control, first_seen, last_seen, count, baseline) "
                            "VALUES (?,?,?,?,?,?,?,?,?)", key + (1 if control else 0, when, when, count, 1 if baseline else 0))
            return True
        self.db.execute("UPDATE operations SET count = count + ?, last_seen = MAX(last_seen, ?) "
                        "WHERE src=? AND dst=? AND label=? AND operation=?", (count, when) + key)
        return False

    def controlled_before(self, src: str, dst: str) -> bool:
        """Has this source sent a control operation to this device before?"""
        return self.db.execute("SELECT 1 FROM operations WHERE src=? AND dst=? AND control=1 LIMIT 1",
                               (src, dst)).fetchone() is not None

    def known_addresses(self) -> set[str]:
        return {row["ip"] for row in self.db.execute("SELECT ip FROM assets")}

    def talked_before(self, src: str, dst: str, label: str) -> bool:
        """Has this pair used this protocol before, on any port? (A change is written once, not once per port.)"""
        return self.db.execute("SELECT 1 FROM conversations WHERE src=? AND dst=? AND label=? LIMIT 1",
                               (src, dst, label)).fetchone() is not None

    def add_hour(self, hour: str, industrial: bool, volume: int, connections: int) -> None:
        self.db.execute("INSERT INTO hourly (hour, industrial, bytes, connections) VALUES (?,?,?,?) "
                        "ON CONFLICT(hour, industrial) DO UPDATE SET bytes = bytes + excluded.bytes, "
                        "connections = connections + excluded.connections", (hour, 1 if industrial else 0, volume, connections))

    def forget_old_hours(self, before: str) -> None:
        self.db.execute("DELETE FROM hourly WHERE hour < ?", (before,))

    def replace_signals(self, signals: dict[str, dict]) -> None:
        self.db.execute("DELETE FROM signals")
        self.db.executemany(
            "INSERT INTO signals (ip, alerts, worst_alert, findings, worst_finding, honeypot) VALUES (?,?,?,?,?,?)",
            [(ip, s.get("alerts", 0), s.get("worst_alert", 0), s.get("findings", 0), s.get("worst_finding", 0), s.get("honeypot", 0))
             for ip, s in signals.items()])

    def add_change(self, at: str, kind: str, severity: int, ip: str, peer: str, title: str, detail: str) -> None:
        self.db.execute("INSERT INTO changes (at, kind, severity, ip, peer, title, detail) VALUES (?,?,?,?,?,?,?)",
                        (at, kind, severity, ip, peer, title, detail))

    def unsent_changes(self, limit: int) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM changes WHERE sent = 0 ORDER BY id LIMIT ?", (limit,)).fetchall()

    def mark_sent(self, ids: list[int]) -> None:
        self.db.executemany("UPDATE changes SET sent = 1 WHERE id = ?", [(item,) for item in ids])

    # ---- reading -----------------------------------------------------------------
    def assets(self) -> list[dict]:
        rows = self.db.execute(f"""
            SELECT a.*, {ROLE_SQL},
              COALESCE((SELECT SUM(bytes_out) FROM conversations c WHERE c.src = a.ip), 0)
                + COALESCE((SELECT SUM(bytes_in) FROM conversations c WHERE c.dst = a.ip), 0) AS sent,
              COALESCE((SELECT SUM(bytes_in) FROM conversations c WHERE c.src = a.ip), 0)
                + COALESCE((SELECT SUM(bytes_out) FROM conversations c WHERE c.dst = a.ip), 0) AS received,
              (SELECT COUNT(*) FROM (SELECT dst AS peer FROM conversations c WHERE c.src = a.ip
                                     UNION SELECT src FROM conversations c WHERE c.dst = a.ip)) AS peers,
              (SELECT GROUP_CONCAT(label, '|') FROM (SELECT DISTINCT label FROM conversations c
                   WHERE c.dst = a.ip ORDER BY industrial DESC, label)) AS answers,
              (SELECT GROUP_CONCAT(label, '|') FROM (SELECT DISTINCT label FROM conversations c
                   WHERE c.src = a.ip ORDER BY industrial DESC, label)) AS uses,
              COALESCE(s.alerts, 0) AS alerts, COALESCE(s.worst_alert, 0) AS worst_alert,
              COALESCE(s.findings, 0) AS findings, COALESCE(s.worst_finding, 0) AS worst_finding,
              COALESCE(s.honeypot, 0) AS honeypot
            FROM assets a LEFT JOIN signals s ON s.ip = a.ip
        """).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["role"] = role_of(item["serves"], item["starts"])
            item["answers"] = [label for label in (item["answers"] or "").split("|") if label]
            item["uses"] = [label for label in (item["uses"] or "").split("|") if label]
            out.append(item)
        return out

    def asset(self, ip: str) -> Optional[dict]:
        for item in self.assets():
            if item["ip"] == ip:
                return item
        return None

    def conversations(self, ip: str = "", industrial_only: bool = False, limit: int = 5000) -> list[sqlite3.Row]:
        where, values = [], []
        if ip:
            where.append("(src = ? OR dst = ?)")
            values += [ip, ip]
        if industrial_only:
            where.append("industrial = 1")
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        return self.db.execute(f"SELECT * FROM conversations {clause} ORDER BY industrial DESC, bytes_out + bytes_in DESC LIMIT ?",
                               values + [limit]).fetchall()

    def links(self, industrial_only: bool) -> list[dict]:
        """One line per pair of devices and protocol, whatever the ports: what the map draws."""
        clause = "WHERE industrial = 1" if industrial_only else ""
        rows = self.db.execute(f"""
            SELECT src, dst, label, MAX(industrial) AS industrial, MIN(how) AS how, SUM(connections) AS connections,
                   SUM(bytes_out + bytes_in) AS volume, MAX(last_seen) AS last_seen, MIN(baseline) AS baseline
            FROM conversations {clause} GROUP BY src, dst, label ORDER BY volume DESC""").fetchall()
        return [dict(row) for row in rows]

    def operations(self, ip: str = "", control_only: bool = False, limit: int = 2000) -> list[sqlite3.Row]:
        where, values = [], []
        if ip:
            where.append("(src = ? OR dst = ?)")
            values += [ip, ip]
        if control_only:
            where.append("control = 1")
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        return self.db.execute(f"SELECT * FROM operations {clause} ORDER BY baseline, control DESC, count DESC LIMIT ?",
                               values + [limit]).fetchall()

    def hours(self, since: str) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM hourly WHERE hour >= ? ORDER BY hour", (since,)).fetchall()

    def protocol_mix(self) -> list[dict]:
        rows = self.db.execute("""
            SELECT label, MAX(industrial) AS industrial, MIN(how) AS how, SUM(bytes_out + bytes_in) AS volume,
                   SUM(connections) AS connections, COUNT(DISTINCT dst) AS answering
            FROM conversations GROUP BY label ORDER BY volume DESC""").fetchall()
        return [dict(row) for row in rows]

    def changes(self, ip: str = "", open_only: bool = False, limit: int = 500) -> list[sqlite3.Row]:
        where, values = [], []
        if ip:
            where.append("(ip = ? OR peer = ?)")
            values += [ip, ip]
        if open_only:
            where.append("accepted = 0")
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        return self.db.execute(f"SELECT * FROM changes {clause} ORDER BY at DESC, severity DESC, id DESC LIMIT ?",
                               values + [limit]).fetchall()

    def counts(self) -> dict:
        one = lambda sql: self.db.execute(sql).fetchone()[0] or 0  # noqa: E731
        return {
            "assets": one("SELECT COUNT(*) FROM assets"),
            "conversations": one("SELECT COUNT(*) FROM conversations"),
            "industrial_conversations": one("SELECT COUNT(*) FROM conversations WHERE industrial = 1"),
            "industrial_protocols": one("SELECT COUNT(DISTINCT label) FROM conversations WHERE industrial = 1"),
            "operations": one("SELECT COUNT(*) FROM operations"),
            "open_changes": one("SELECT COUNT(*) FROM changes WHERE accepted = 0"),
        }
