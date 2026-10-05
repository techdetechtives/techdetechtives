# TechDetechtives network inventory: one pass over what the platform recorded.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Reads grouped totals from the platform, updates the local store, and
writes down what is new compared with the learned baseline."""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import td_forwarder as fw

from .platform import Platform
from .protocols import OT_DATASETS, classify, industrial_vendor, is_control
from .store import Store, stamp

log = logging.getLogger("td_net")

LOW, MEDIUM, HIGH = 1, 2, 3
OUTSIDE, MULTICAST = "outside", "multicast"
PSEUDO = {OUTSIDE: "Outside the monitored networks", MULTICAST: "Broadcast and multicast"}
INSIDE_DEFAULT = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,fc00::/7,fe80::/10"


class Scope:
    """Which addresses are 'ours', and which named zone each one belongs to."""

    def __init__(self, inside: str = INSIDE_DEFAULT, zones: str = "") -> None:
        try:
            self.inside = [ipaddress.ip_network(part.strip(), strict=False) for part in inside.split(",") if part.strip()]
        except ValueError as error:
            raise fw.ConfigError(f"TD_NET_INSIDE: {error}") from None
        self.zones: list[tuple[str, Any]] = []
        for part in [item.strip() for item in zones.split(",") if item.strip()]:
            name, _, network = part.partition("=")
            try:
                self.zones.append((name.strip()[:40] or network.strip(), ipaddress.ip_network(network.strip(), strict=False)))
            except ValueError:
                raise fw.ConfigError(f"TD_NET_ZONES: '{part}' is not NAME=NETWORK, for example Control=10.10.1.0/24") from None
        # The narrowest network wins when zones overlap.
        self.zones.sort(key=lambda zone: zone[1].prefixlen, reverse=True)

    def node(self, value: Any) -> Optional[str]:
        """The name a conversation's end is filed under: its own address when it
        is ours, one shared name for everything outside, another for broadcast
        and multicast, None for addresses that mean nothing (0.0.0.0)."""
        try:
            address = ipaddress.ip_address(str(value))
        except ValueError:
            return None
        if address.is_unspecified or address.is_loopback:
            return None
        if address.is_multicast or str(address) == "255.255.255.255":
            return MULTICAST
        if not any(address in network for network in self.inside if network.version == address.version):
            return OUTSIDE
        # The last address of a /24 is nearly always that network's broadcast address.
        if address.version == 4 and str(address).endswith(".255"):
            return MULTICAST
        return str(address)

    def zone(self, node: str) -> str:
        if node in PSEUDO:
            return PSEUDO[node]
        try:
            address = ipaddress.ip_address(node)
        except ValueError:
            return ""
        for name, network in self.zones:
            if network.version == address.version and address in network:
                return name
        if address.version == 4:
            return str(ipaddress.ip_network(f"{address}/24", strict=False))
        return str(ipaddress.ip_network(f"{address}/64", strict=False))


def _when(value: Any, fallback: str) -> str:
    moment = fw.parse_time(value) if isinstance(value, str) else None
    return stamp(moment) if moment else fallback


def _number(value: Any) -> int:
    try:
        return int(float(value or 0))
    except (TypeError, ValueError):
        return 0


def _list(items: list[str], limit: int = 5) -> str:
    items = sorted(set(items))
    return ", ".join(items[:limit]) + (f" and {len(items) - limit} more" if len(items) > limit else "")


class Pass:
    """State of one pass: what was new, so that changes are written once per pair, not once per port."""

    def __init__(self, store: Store, scope: Scope, learning: bool, now: datetime) -> None:
        self.store, self.scope, self.learning = store, scope, learning
        self.at = stamp(now)
        self.new_devices: dict[str, str] = {}
        self.new_industrial: dict[tuple[str, str], list[str]] = {}
        self.new_to_controller: dict[tuple[str, str], list[str]] = {}
        self.new_control: dict[tuple[str, str, str], list[str]] = {}
        self.first_control: dict[tuple[str, str], bool] = {}
        self.controllers: Optional[set[str]] = None
        self.known = store.known_addresses()

    def is_controller(self, ip: str) -> bool:
        if self.controllers is None:
            self.controllers = {row["dst"] for row in self.store.db.execute(
                "SELECT DISTINCT dst FROM conversations WHERE industrial = 1 AND baseline = 1")} - set(PSEUDO)
        return ip in self.controllers

    def see(self, node: str, when: str) -> None:
        if node in PSEUDO:
            return
        self.known.add(node)
        if self.store.see_asset(node, when, self.learning) and not self.learning:
            self.new_devices[node] = when

    def conversation(self, src: str, dst: str, port: int, transport: str, label: str, industrial: bool, how: str,
                     when: str, connections: int, bytes_out: int, bytes_in: int, answered: bool = True) -> bool:
        """Record one group of connections. False when it was left out: an attempt
        that got no answer, to an address no device has been seen at. (A scan of
        empty addresses would otherwise fill the inventory with devices that do
        not exist.)"""
        self.see(src, when)
        if not answered and dst not in PSEUDO and dst not in self.known:
            return False
        self.see(dst, when)
        known = self.store.talked_before(src, dst, label)
        new = self.store.add_conversation(src, dst, port, transport, label, industrial, how, when, connections,
                                          bytes_out, bytes_in, self.learning)
        if not new or self.learning or known:
            return True
        if industrial:
            self.new_industrial.setdefault((src, dst), []).append(label)
        elif self.is_controller(dst):
            self.new_to_controller.setdefault((src, dst), []).append(label)
        return True

    def operation(self, src: str, dst: str, label: str, operation: str, when: str, count: int) -> None:
        control = is_control(label, operation)
        if control and (src, dst) not in self.first_control:
            # Asked before this pass writes anything for the pair.
            self.first_control[(src, dst)] = not self.store.controlled_before(src, dst)
        new = self.store.add_operation(src, dst, label, operation or "(not named)", control, when, count, self.learning)
        if new and control and not self.learning:
            self.new_control.setdefault((src, dst, label), []).append(operation)

    def write_changes(self, limit: int) -> int:
        store, changes = self.store, []
        for (src, dst, label), operations in self.new_control.items():
            first = self.first_control.get((src, dst), False)
            title = "New station sending control commands to a device" if first else "New kind of control command to a device"
            changes.append((HIGH if first else MEDIUM, "new_control_operation", src, dst, title,
                            f"{src} sent {label} control operations to {dst} that are not in the baseline: {_list(operations)}."
                            + (" This source had never sent a control operation to this device." if first else "")))
        for (src, dst), labels in self.new_industrial.items():
            outside = src == OUTSIDE or dst == OUTSIDE
            changes.append((HIGH if outside else MEDIUM, "new_industrial_conversation", src, dst,
                            "Industrial protocol crossing the edge of the monitored networks" if outside
                            else "New industrial conversation",
                            f"{PSEUDO.get(src, src)} started talking {_list(labels)} to {PSEUDO.get(dst, dst)}. "
                            "This pair is not in the baseline."))
        for (src, dst), labels in self.new_to_controller.items():
            changes.append((MEDIUM, "new_conversation_with_controller", src, dst, "New kind of connection to a controller",
                            f"{PSEUDO.get(src, src)} connected to {dst}, which answers industrial protocols, using {_list(labels)}. "
                            "This pair had not used " + ("these" if len(set(labels)) > 1 else "this") + " before."))
        for ip, when in self.new_devices.items():
            changes.append((LOW, "new_device", ip, "", "New device on the network",
                            f"{ip} was first seen at {when} and is not in the baseline."))
        changes.sort(key=lambda change: -change[0])
        for severity, kind, ip, peer, title, detail in changes[:limit]:
            store.add_change(self.at, kind, severity, ip, peer, title, detail)
        if len(changes) > limit:
            store.add_change(self.at, "more_changes", LOW, "", "", "More changes than can be listed",
                             f"{len(changes) - limit} further changes found at the same time were not listed one by one "
                             "(the most severe were kept). A scan or a newly mirrored network segment causes this.")
        return len(changes)


MIN_WINDOW = timedelta(minutes=1)


def run_sync(platform: Platform, store: Store, scope: Scope, now: Optional[datetime] = None, backfill_hours: float = 24,
             learn_hours: float = 72, signal_days: int = 7, max_changes: int = 100, lag_seconds: int = 300,
             window_minutes: int = 60) -> dict:
    """One pass: everything stored on the platform since the last pass, read in
    windows of at most an hour. Each window is written and committed on its own.
    Raises fw.HttpError when the platform cannot be read; whatever windows were
    finished before that stay, and the next pass carries on from there.

    lag_seconds: records are read this long after the platform's sensor wrote
    them, to give them time to arrive. A record that arrives later than that is
    not in the inventory; the pass says so when it sees it happen."""
    now = now or datetime.now(timezone.utc)
    until = now - timedelta(seconds=lag_seconds)
    previous = fw.parse_time(store.meta("synced_until") or "")
    since = previous or until - timedelta(hours=backfill_hours)
    summary: dict[str, Any] = {"conversations": 0, "operations": 0, "changes": 0, "warnings": []}
    if until <= since:
        return summary
    if platform.time_field == "@timestamp":
        # Asked again on every pass until the answer is yes: a platform with no
        # records yet cannot say whether it keeps the time it stored them.
        platform.choose_time_field()
    _late_arrivals(platform, store, lag_seconds, summary)

    span = timedelta(minutes=window_minutes)
    while since < until:
        first = platform.first_record(since, until)
        if first is None:
            # Nothing more was recorded: the rest of the time is done in one step.
            store.set_meta("synced_until", fw.iso(until))
            store.set_meta("last_window", {"since": fw.iso(since), "until": fw.iso(until), "records": 0,
                                           "field": platform.time_field})
            store.commit()
            break
        since = max(since, first - timedelta(milliseconds=1))
        end = min(since + span, until)
        platform.truncated = []
        part: dict[str, Any] = {"conversations": 0, "operations": 0, "changes": 0, "warnings": [], "records": 0}
        try:
            _read_window(platform, store, scope, since, end, now, max_changes, part)
        except Exception:
            store.db.rollback()
            raise
        if platform.truncated and end - since > MIN_WINDOW:
            # More than one read can carry: nothing of this window is kept, and it is read again in two halves.
            store.db.rollback()
            span = max((end - since) / 2, MIN_WINDOW)
            continue
        if part["conversations"] and store.meta("learning_until") is None:
            # The clock starts with the first data, so a sensor that is not
            # recording yet does not use up the learning time.
            store.start_learning(now, learn_hours)
        for key in ("conversations", "operations", "changes"):
            summary[key] += part[key]
        summary["warnings"] += part["warnings"]
        summary["warnings"] += [f"{name}: more in one minute than can be read ({fw.iso(since)[:16]} UTC); the rest was left out"
                                for name in platform.truncated]
        store.set_meta("synced_until", fw.iso(end))
        store.set_meta("last_window", {"since": fw.iso(since), "until": fw.iso(end), "records": part["records"],
                                       "field": platform.time_field})
        store.commit()
        since = end

    try:
        _signals(platform, store, scope, now, signal_days, summary)
    except Exception:
        store.db.rollback()
        raise
    store.forget_old_hours(stamp(now - timedelta(days=8)))
    store.set_meta("status", {"synced_at": stamp(now), "error": "", "warnings": sorted(set(summary["warnings"])),
                              "time_field": platform.time_field, "seen_data": bool(store.counts()["conversations"]),
                              "late_records": int(store.meta("late_records") or 0)})
    store.commit()
    return summary


def _late_arrivals(platform: Platform, store: Store, lag_seconds: int, summary: dict) -> None:
    """Did records for the window read last time reach the platform after it was read?"""
    last = store.meta("last_window")
    if not last or last.get("field") != platform.time_field:
        return
    since, until = fw.parse_time(last.get("since")), fw.parse_time(last.get("until"))
    if not since or not until:
        return
    try:
        late = platform.count_window(since, until) - int(last.get("records") or 0)
    except fw.HttpError as error:
        if error.retryable:
            raise
        return
    store.set_meta("last_window", None)          # each window is checked once
    if late > 0:
        store.set_meta("late_records", int(store.meta("late_records") or 0) + late)
        summary["warnings"].append(
            f"{late:,} connection record{'' if late == 1 else 's'} reached the platform more than {lag_seconds} seconds after the "
            "sensor wrote them and are not in the inventory. Raise TD_NET_LAG_SECONDS if this keeps happening.")


def _read_window(platform: Platform, store: Store, scope: Scope, since: datetime, until: datetime, now: datetime,
                 max_changes: int, summary: dict) -> None:
    state = Pass(store, scope, store.learning(now), now)
    fallback = stamp(until)
    for row in platform.conversations(since, until):
        summary["records"] += row["count"]
        src, dst = scope.node(row.get("src")), scope.node(row.get("dst"))
        if src is None or dst is None or (src in PSEUDO and dst in PSEUDO):
            continue
        port = row.get("port")
        port = int(port) if isinstance(port, (int, float)) else None
        transport = str(row.get("transport") or "").lower()
        label, industrial, how = classify(str(row.get("service") or ""), transport, port)
        out, back = _number(row.get("client_bytes")), _number(row.get("server_bytes"))
        kept = state.conversation(src, dst, port or 0, transport or "other", label, industrial, how,
                                  _when(row.get("last"), fallback), row["count"], out, back, answered=back > 0)
        if kept and row.get("hour"):
            store.add_hour(str(row["hour"]), industrial, out + back, row["count"])
        summary["conversations"] += 1

    for dataset, (label, _) in OT_DATASETS.items():
        try:
            for row in platform.operations(dataset, since, until):
                src, dst = scope.node(row.get("src")), scope.node(row.get("dst"))
                if src is None or dst is None or (src in PSEUDO and dst in PSEUDO):
                    continue
                when = _when(row.get("last"), fallback)
                port = row.get("port")
                # Sessions that stay open for days are only written to the connection
                # records when they end, so the conversation is noted from here as well.
                state.conversation(src, dst, int(port) if isinstance(port, (int, float)) else 0,
                                   str(row.get("transport") or "tcp").lower(), label, True, "decoded", when, 0, 0, 0)
                if row.get("named"):
                    state.operation(src, dst, label, str(row.get("operation") or ""), when, row["count"])
                    summary["operations"] += 1
        except fw.HttpError as error:
            if error.retryable:
                raise
            summary["warnings"].append(f"{label} operations could not be read: {str(error)[:200]}")

    _describe(platform, store, state, since, until, summary)
    summary["changes"] += state.write_changes(max_changes)


def _describe(platform: Platform, store: Store, state: Pass, since: datetime, until: datetime, summary: dict) -> None:
    """Card makers, what devices say about themselves, and names. All optional."""
    def optional(name: str, call):
        try:
            return list(call(since, until))
        except fw.HttpError as error:
            if error.retryable:
                raise
            summary["warnings"].append(f"{name} could not be read: {str(error)[:200]}")
            return []

    for row in optional("network card makers", platform.card_makers):
        ip, maker = state.scope.node(row.get("ip")), str(row.get("maker") or "").strip()[:80]
        if ip is None or ip in PSEUDO or not maker:
            continue
        current = store.db.execute("SELECT maker FROM assets WHERE ip=?", (ip,)).fetchone()
        if current is None:
            continue
        known = [item for item in (current["maker"] or "").split("; ") if item]
        if maker in known:
            continue
        store.describe_asset(ip, maker="; ".join(known + [maker]))
        if known and not state.learning:
            industrial = state.is_controller(ip) or any(industrial_vendor(item) for item in known)
            store.add_change(state.at, "card_maker_changed", HIGH if industrial else MEDIUM, ip, "",
                             "Device answering from a network card by a different maker",
                             f"{ip} was seen with a network card made by {maker}. Before, its card was by {_list(known)}. "
                             "A replaced device, a changed card address or another machine using this address causes this; "
                             "so does a mirror that sees the address both directly and through a router.")
            summary["changes"] += 1

    # A device that announces itself in two ways is described by one of them,
    # always the same one, or its model would change back and forth for ever.
    preferred = {"EtherNet/IP identity": 0, "BACnet I-Am": 1}
    newest: dict[str, dict] = {}
    software: dict[str, list[str]] = {}
    for item in optional("device identities", platform.identities):
        ip = state.scope.node(item.get("ip"))
        if ip is None or ip in PSEUDO:
            continue
        if item.get("software"):
            if item["software"] not in software.setdefault(ip, []) and len(software[ip]) < 5:
                software[ip].append(item["software"])
        elif ip not in newest or preferred.get(item["via"], 9) < preferred.get(newest[ip]["via"], 9):
            newest[ip] = item                                 # the list is newest first
    for ip, item in newest.items():
        via = item["via"]
        current = store.db.execute("SELECT identity_via FROM assets WHERE ip=?", (ip,)).fetchone()
        if current and current["identity_via"] and preferred.get(via, 9) > preferred.get(current["identity_via"], 9):
            continue
        changed = store.describe_asset(ip, vendor=item.get("vendor", ""), model=item.get("model", ""),
                                       version=item.get("version", ""), serial=item.get("serial", ""),
                                       kind=item.get("kind", ""), identity_via=via)
        moved = {key: pair for key, pair in changed.items() if key in ("model", "version", "serial") and pair[0]}
        if moved and not state.learning:
            what = "; ".join(f"{key} was {old}, now {new}" for key, (old, new) in moved.items())
            store.add_change(state.at, "identity_changed", MEDIUM, ip, "", "Device reports a different model, version or serial number",
                             f"{ip} ({via}): {what}. A firmware update or a replaced device causes this.")
            summary["changes"] += 1
    for ip, names in software.items():
        store.describe_asset(ip, software="; ".join(names))

    seen: set[str] = set()
    for item in optional("host names", platform.names):
        ip = state.scope.node(item.get("ip"))
        if ip is None or ip in PSEUDO or ip in seen:
            continue
        seen.add(ip)
        store.describe_asset(ip, name=item.get("name", "")[:100], mac=item.get("mac", "")[:40].lower())


def _signals(platform: Platform, store: Store, scope: Scope, now: datetime, days: int, summary: dict) -> None:
    """Alerts, vulnerability findings and honeypot contacts per address, over the last days."""
    since, signals = now - timedelta(days=days), {}

    def slot(value: Any) -> Optional[dict]:
        node = scope.node(value)
        if node is None or node in PSEUDO:
            return None
        return signals.setdefault(node, {})

    try:
        for row in platform.alerts(since, now):
            for end in ("src", "dst"):
                entry = slot(row.get(end))
                if entry is not None:
                    entry["alerts"] = entry.get("alerts", 0) + row["count"]
                    entry["worst_alert"] = max(entry.get("worst_alert", 0), _number(row.get("worst")))
        for row in platform.findings(since, now):
            entry = slot(row.get("ip"))
            if entry is not None:
                entry["findings"] = entry.get("findings", 0) + row["count"]
                entry["worst_finding"] = max(entry.get("worst_finding", 0), _number(row.get("worst")))
        for row in platform.honeypot_contacts(since, now):
            entry = slot(row.get("ip"))
            if entry is not None:
                entry["honeypot"] = entry.get("honeypot", 0) + row["count"]
    except fw.HttpError as error:
        if error.retryable:
            raise
        summary["warnings"].append(f"alerts and findings could not be read: {str(error)[:200]}")
        return
    store.replace_signals(signals)
