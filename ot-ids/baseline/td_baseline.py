#!/usr/bin/env python3
# TechDetechtives OT IDS. Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Learn what an industrial network normally does, then report what is new.

An industrial network repeats itself: the same masters ask the same controllers
for the same things around the clock. This program reads the industrial
protocol records the sensor has already decoded (Zeek records in OpenSearch),
keeps an exact list of who talks to whom and with which operations, and after a
learning period reports, in plain words:

  new-master     an address acting as a master (client) of a protocol for the
                 first time: one never seen before, or one that until now only
                 answered
  new-device     an address never seen before that answers an industrial protocol
  new-service    a known device answering a protocol it never answered before
  new-pair       a known master talking to a device it never talked to
  sweep          a master reaching many devices it never talked to
  new-operation  an operation never used before between a master and a device
  burst          an operation used far more in an hour than in any hour while learning
  quiet          a device or master that was there every hour and has stopped
  sensor-silent  no industrial traffic at all for hours, after there was some

It runs inside the product's dashboards-helper container every 15 minutes
(from that container's crontab), needs nothing but Python's standard library,
keeps its list in a file on that container's own volume, and hands findings to
the product's alert webhook, which stores them beside every other alert.

    td_baseline.py run            one pass (what the crontab calls)
    td_baseline.py status         where learning stands and what is known
    td_baseline.py check          read the last hour from OpenSearch and say what was found; changes nothing
    td_baseline.py findings       the most recent findings
    td_baseline.py alerts on|off  hand findings to the alert webhook, or only record them (default: off)
    td_baseline.py test-alert     send one test alert through the webhook
    td_baseline.py learn --hours N   treat the next N hours as normal (maintenance, commissioning)
    td_baseline.py learn --stop
    td_baseline.py forget ADDRESS    drop an address, so it is reported again when it next appears
    td_baseline.py reset --yes       forget everything and learn again from now
    td_baseline.py reset --yes --with-history   the same, learning from the traffic already stored

Where the ideas come from (none of their code is used here; see
ot-ids/docs/ANOMALY-DETECTION-REVIEW.md): "first seen" and "went quiet" follow
ElastAlert 2's new_term and flatline rules, with the difference that the list
is kept on disk and a sensor outage is not mistaken for every device going
quiet; "more than its own history" follows MIDAS, with exact counts in place of
sketches and one check per closed hour; "do not learn from what was just
flagged" follows MIDAS-F and River; "a function this master never used" and
"a device that starts acting as a master" follow dmtkfs/ics-modbus-anomaly-detection.
"""
import argparse
import base64
import fcntl
import hashlib
import http.client
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

HOUR = 3600
DAY = 24 * HOUR
STATE_VERSION = 2
MONITOR_NAME = "TechDetechtives OT Baseline"
FRAMEWORK = "MITRE ATT&CK for ICS"

# kind: (what the alert is called, severity 1 (highest) to 5, ATT&CK for ICS technique or None).
# The techniques are kept in step with ot-ids/attack/baseline-findings.csv by the tests.
KINDS = {
    "new-master": ("New industrial master", 2, "T0848"),
    "new-device": ("New industrial device", 3, "T0864"),
    "new-service": ("Device answers a new industrial protocol", 3, None),
    "new-pair": ("Master talks to a new device", 3, None),
    "sweep": ("Master reaches many new devices", 2, "T0846"),
    "new-operation": ("New operation between a master and a device", 4, None),
    "new-control-operation": ("New control operation between a master and a device", 3, "T1692.001"),
    "burst": ("Operation far above its learned rate", 3, None),
    "quiet": ("Device or master went quiet", 3, "T0814"),
    "sensor-silent": ("No industrial traffic seen", 2, None),
    "list-full": ("The list of known conversations is full", 2, None),
    "overflow": ("More findings than one pass sends as alerts", 3, None),
    "resumed": ("Device or master is back", 5, None),
}
RECORD_ONLY = {"resumed"}       # written to the findings file, never sent
TECHNIQUES = {
    "T0848": ("TA0108", "Initial_Access", "T0848", "Rogue_Master", None, None),
    "T0864": ("TA0108", "Initial_Access", "T0864", "Transient_Cyber_Asset", None, None),
    "T0846": ("TA0102", "Discovery", "T0846", "Remote_System_Discovery", None, None),
    "T0814": ("TA0107", "Inhibit_Response_Function", "T0814", "Denial_of_Service", None, None),
    "T1692.001": ("TA0106", "Impair_Process_Control", "T1692", "Unauthorized_Message", "T1692.001", "Command_Message"),
}
# Operation names that change something or belong to engineering work, in the
# spellings the protocol decoders use.
CONTROL_WORDS = re.compile(
    r"write|force|stop|start|restart|reset|download|operate|select|delete|program|firmware|"
    r"initiali[sz]e|freeze|clear|disable|enable|activate|command|set[_ ]|mode", re.I)
# The protocol names the product itself treats as industrial (its
# logstash/pipelines/enrichment/20_enriched_to_ecs.conf). The product also marks
# as "ot" every record of a device whose network card is from an industrial
# vendor, DNS and time synchronisation included; those are not wanted here.
PROTOCOLS = [
    "bacnet", "bsap", "c1222", "cip", "cotp", "dnp3", "ecat", "enip", "ethercat", "ge_srtp", "genisys", "hart_ip",
    "iec104", "modbus", "omron_fins", "opcua-binary", "profinet", "profinet_dce_rpc", "profinet_io_cm", "roc_plus",
    "s7comm", "s7comm-plus", "s7comm_plus", "synchrophasor",
]
# Records that are about industrial traffic without being it. Connection
# summaries are left out too: they name no operation and are written only when
# a connection ends, which for a polling master may be never.
SKIP_DATASETS = ["alert", "alerting", "conn", "notice", "signatures", "weird", "intel",
                 "known_modbus", "known_hosts", "known_services"]
SKIP_PROVIDERS = ["suricata", "malcolm"]
# Most decoders write each message with its sender as the source and mark an
# answer with is_orig false. The IEC 104 decoder marks direction the same way
# but always writes the connection's two ends, so its records are not turned round.
RESPONSE_MARKS = {"f", "false", "0", "no"}
NOT_TURNED = {"iec104"}
NETWORK_ERRORS = (urllib.error.URLError, http.client.HTTPException, OSError, ValueError, KeyError)


def clean(value):
    """Text taken from the network, made safe to print and short enough to read."""
    return re.sub(r"[^\x20-\x7e]", "?", str(value))[:120].replace("|", "/")


def env_int(environ, name, default):
    try:
        return int(environ.get(name, "") or default)
    except ValueError:
        return default


class Settings:
    def __init__(self, environ=os.environ):
        get = environ.get
        self.folder = get("TD_BASELINE_DIR", "/data/init/td-baseline")
        self.opensearch_url = (get("OPENSEARCH_URL") or "https://opensearch:9200").rstrip("/")
        self.creds_file = get("OPENSEARCH_CREDS_CONFIG_FILE", "/var/local/curlrc/.opensearch.primary.curlrc")
        self.verify_tls = (get("OPENSEARCH_SSL_CERTIFICATE_VERIFICATION", "false") or "false").strip().lower() in ("true", "1", "yes")
        self.index = get("MALCOLM_NETWORK_INDEX_PATTERN") or "arkime_sessions3-*"
        self.time_field = get("MALCOLM_NETWORK_INDEX_TIME_FIELD") or "firstPacket"
        self.alert_url = get("TD_BASELINE_ALERT_URL", "http://api:5000/mapi/alert")
        self.protocols = sorted(set(PROTOCOLS) | {name.strip() for name in get("TD_BASELINE_EXTRA_PROTOCOLS", "").split(",") if name.strip()})
        self.learn_days = env_int(environ, "TD_BASELINE_LEARN_DAYS", 14)        # learning needs this many days' worth of hours with traffic
        self.backfill_days = env_int(environ, "TD_BASELINE_BACKFILL_DAYS", 30)  # how far back the first pass reads what is already stored
        self.lag_minutes = env_int(environ, "TD_BASELINE_LAG_MINUTES", 10)      # records younger than this may still be on their way
        self.late_hours = env_int(environ, "TD_BASELINE_LATE_HOURS", 6)         # closed hours read again for records that arrived late
        self.quiet_hours = env_int(environ, "TD_BASELINE_QUIET_HOURS", 4)
        self.burst_factor = env_int(environ, "TD_BASELINE_BURST_FACTOR", 3)
        self.burst_min = env_int(environ, "TD_BASELINE_BURST_MIN", 30)
        self.burst_rearm_hours = env_int(environ, "TD_BASELINE_BURST_REARM_HOURS", 6)
        self.burst_absorb_hours = env_int(environ, "TD_BASELINE_BURST_ABSORB_HOURS", 24)
        self.rate_learn_hours = env_int(environ, "TD_BASELINE_RATE_LEARN_HOURS", 24)  # an operation's rate is learned over its first hours
        self.sweep_pairs = env_int(environ, "TD_BASELINE_SWEEP_PAIRS", 5)
        self.step_hours = env_int(environ, "TD_BASELINE_STEP_HOURS", 6)
        self.max_hours_per_run = env_int(environ, "TD_BASELINE_MAX_HOURS_PER_RUN", 72)
        self.max_alerts_per_run = env_int(environ, "TD_BASELINE_MAX_ALERTS_PER_RUN", 40)
        self.expire_days = env_int(environ, "TD_BASELINE_EXPIRE_DAYS", 90)       # what was not seen for this long is dropped from the list
        self.max_operations = env_int(environ, "TD_BASELINE_MAX_OPERATIONS", 300000)
        self.max_hosts = env_int(environ, "TD_BASELINE_MAX_HOSTS", 50000)
        self.page_size = env_int(environ, "TD_BASELINE_PAGE_SIZE", 2000)
        self.timeout = env_int(environ, "TD_BASELINE_TIMEOUT", 120)


# --- Reading OpenSearch ---------------------------------------------------------------

def read_curlrc(path):
    """user and password from the product's curl settings file (user: "name:password")."""
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                match = re.match(r'^\s*-{0,2}user\s*[:=]?\s*"?(.*?)"?\s*$', line)
                if match and match.group(1):
                    user, _, password = match.group(1).replace('\\"', '"').replace("\\\\", "\\").partition(":")
                    return user, password
    except OSError:
        pass
    return None, None


class Http:
    def __init__(self, settings):
        self.settings = settings
        user, password = read_curlrc(settings.creds_file)
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode() if user else None
        self.context = ssl.create_default_context()
        trust = "/var/local/ca-trust"       # the product's own certificate authority, when it has one
        if settings.verify_tls and os.path.isdir(trust):
            for name in sorted(os.listdir(trust)):
                try:
                    self.context.load_verify_locations(os.path.join(trust, name))
                except (ssl.SSLError, OSError):
                    pass
        if not settings.verify_tls:
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def post(self, url, body, auth=False):
        request = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                         headers={"Content-Type": "application/json"})
        if auth and self.auth:
            request.add_header("Authorization", self.auth)
        kwargs = {"context": self.context} if url.startswith("https") else {}
        with urllib.request.urlopen(request, timeout=self.settings.timeout, **kwargs) as response:
            return json.loads(response.read().decode() or "{}")


def search_body(settings, start_ms, end_ms, by_hour, after=None):
    """Counts per (hour,) sender, receiver, protocol, operation and direction mark."""
    field = settings.time_field
    sources = []
    if by_hour:
        sources.append({"hour": {"date_histogram": {"field": field, "fixed_interval": "1h"}}})
    sources += [
        {"src": {"terms": {"field": "source.ip"}}},
        {"dst": {"terms": {"field": "destination.ip"}}},
        {"proto": {"terms": {"field": "network.protocol"}}},
        {"action": {"terms": {"field": "event.action", "missing_bucket": True}}},
        {"is_orig": {"terms": {"field": "network.is_orig", "missing_bucket": True}}},
    ]
    composite = {"size": settings.page_size, "sources": sources}
    if after:
        composite["after"] = after
    return {
        "size": 0,
        "track_total_hits": False,
        "query": {"bool": {
            "filter": [
                {"range": {field: {"gte": start_ms, "lt": end_ms, "format": "epoch_millis"}}},
                {"term": {"event.category": "ot"}},
                {"terms": {"network.protocol": settings.protocols}},
                {"exists": {"field": "source.ip"}},
                {"exists": {"field": "destination.ip"}},
            ],
            "must_not": [
                {"terms": {"event.dataset": SKIP_DATASETS}},
                {"terms": {"event.provider": SKIP_PROVIDERS}},
            ],
        }},
        "aggs": {"keys": {
            "composite": composite,
            "aggs": {"first": {"min": {"field": field}}, "last": {"max": {"field": field}}},
        }},
    }


def collect(http, settings, start, end, by_hour):
    """{hour: {(client, server, protocol, operation): [count, first_ms, last_ms, asked]}} for start <= t < end (seconds).

    The key is always (who asked, who answered): records marked as answers are
    turned round. 'asked' counts the records that were not answers; an
    operation that was only ever seen in answers is not an operation anyone used.
    An answer from OpenSearch that is not complete is refused: half an hour's
    records would look like half the plant going quiet.
    """
    url = (f"{settings.opensearch_url}/{settings.index}/_search"
           "?ignore_unavailable=true&allow_no_indices=true&allow_partial_search_results=false")
    wanted = set(settings.protocols)
    hours, after = {}, None
    while True:
        reply = http.post(url, search_body(settings, start * 1000, end * 1000, by_hour, after), auth=True)
        shards = reply.get("_shards") or {}
        if reply.get("timed_out") or shards.get("failed"):
            raise ValueError("OpenSearch answered only in part (timed out, or a shard failed)")
        if "aggregations" not in reply:
            if shards.get("total") == 0:
                return hours                      # no index to read yet: a new installation
            raise ValueError("OpenSearch answered without the counts that were asked for")
        keys = reply["aggregations"].get("keys") or {}
        buckets = keys.get("buckets") or []
        for bucket in buckets:
            key = bucket["key"]
            protocol = clean(key["proto"])
            if protocol not in wanted:            # a record naming two protocols is counted under each; keep the industrial one
                continue
            src, dst = clean(key["src"]), clean(key["dst"])
            answer = str(key.get("is_orig")).strip().lower() in RESPONSE_MARKS and protocol not in NOT_TURNED
            if answer:
                src, dst = dst, src
            action = "" if key.get("action") is None else re.sub(r"_EXCEPTION$", "", clean(key["action"]))
            count = int(bucket.get("doc_count") or 0)
            hour = int(key["hour"]) // 1000 // HOUR if by_hour else start // HOUR
            first = int((bucket.get("first") or {}).get("value") or start * 1000)
            last = int((bucket.get("last") or {}).get("value") or first)
            record = hours.setdefault(hour, {}).setdefault((src, dst, protocol, action), [0, first, last, 0])
            record[0] += count
            record[1], record[2] = min(record[1], first), max(record[2], last)
            record[3] += 0 if answer else count
        after = keys.get("after_key")
        if not after or len(buckets) < settings.page_size:
            return hours


# --- The list ---------------------------------------------------------------------------

def new_state():
    return {"version": STATE_VERSION, "created": int(time.time()), "alerts": False, "backfill": True,
            "first_hour": None, "started_hour": None, "learn_until": None, "maintenance_from": 0, "maintenance_until": 0,
            "cursor": None, "step": None, "data_hours": 0, "empty_hours": 0, "silent": False, "quiet_primed": False,
            "full_at": 0, "expired_at": 0, "hosts": {}, "pairs": {}, "ops": {}, "pending": [], "outbox": [],
            "runs": 0, "last_run": None}


class Store:
    def __init__(self, folder):
        self.folder = folder
        self.path = os.path.join(folder, "state.json")
        self.log = os.path.join(folder, "findings.jsonl")
        self.lock_handle = None

    def prepare(self):
        os.makedirs(self.folder, exist_ok=True)

    def lock(self, wait=0):
        """False when another pass still holds the list after 'wait' seconds."""
        self.lock_handle = open(os.path.join(self.folder, "lock"), "w")
        deadline = time.monotonic() + wait
        while True:
            try:
                fcntl.flock(self.lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
            except OSError:
                if time.monotonic() >= deadline:
                    self.unlock()
                    return False
                time.sleep(0.5)

    def unlock(self):
        if self.lock_handle:
            self.lock_handle.close()
            self.lock_handle = None

    def load(self):
        try:
            with open(self.path, encoding="utf-8") as handle:
                state = json.load(handle)
        except FileNotFoundError:
            return new_state()
        if state.get("version") != STATE_VERSION:
            raise SystemExit(f"{self.path} was written by another version of this program; run 'reset --yes' to start again")
        return state

    def save(self, state):
        temporary = self.path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(state, handle, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.path)

    def record(self, findings):
        if not findings:
            return
        if os.path.exists(self.log) and os.path.getsize(self.log) > 5_000_000:
            os.replace(self.log, self.log + ".1")
        with open(self.log, "a", encoding="utf-8") as handle:
            for finding in findings:
                handle.write(json.dumps(finding, sort_keys=True) + "\n")

    def recent(self, count):
        lines = []
        for path in (self.log + ".1", self.log):
            if os.path.exists(path):
                with open(path, encoding="utf-8") as handle:
                    lines += handle.readlines()
        return [json.loads(line) for line in lines[-count:]]


def iso(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def listing(items, limit=8):
    items = sorted(items)
    return ", ".join(items[:limit]) + (f" and {len(items) - limit} more" if len(items) > limit else "")


def finding(kind, when, client, server, protocol, actions, text):
    actions = sorted(action for action in actions if action)
    subject = "|".join(str(part or "") for part in (kind, client, server, protocol, ",".join(actions)))
    return {"id": hashlib.sha1(f"{subject}|{when}".encode()).hexdigest()[:20], "kind": kind, "time": iso(when),
            "client": client, "server": server, "protocol": protocol, "actions": actions, "text": text}


# --- Learning and comparing -----------------------------------------------------------

class Engine:
    def __init__(self, settings, state):
        self.settings = settings
        self.state = state
        self.new_hosts, self.new_roles, self.new_pairs, self.new_ops = {}, {}, {}, {}
        self.findings = []
        self.refused = 0

    # What is new is first only noted, then put together in consolidate(), so a
    # new laptop does not raise one alert for itself, one for its role, one for
    # each device it talks to and one for each operation.

    def learning(self, hour):
        state = self.state
        if state["learn_until"] is None or hour < state["learn_until"]:
            return True
        return hour * HOUR < state["maintenance_until"] and (hour + 1) * HOUR > state["maintenance_from"]

    def room(self, table, limit):
        if len(self.state[table]) < limit:
            return True
        self.refused += 1
        return False

    def touch_host(self, address, role, protocol, when, learning):
        hosts = self.state["hosts"]
        host = hosts.get(address)
        if host is None:
            if not self.room("hosts", self.settings.max_hosts):
                return False
            host = hosts[address] = {"f": when, "l": when, "c": [], "s": []}
            if not learning:
                self.new_hosts[address] = {"when": when, "roles": set(), "peers": set(), "ops": set(), "swept": set()}
        host["f"], host["l"] = min(host["f"], when), max(host["l"], when)
        if protocol not in host[role]:
            had_client_role = bool(host["c"])
            host[role].append(protocol)
            if not learning:
                if address in self.new_hosts:
                    self.new_hosts[address]["roles"].add((role, protocol))
                else:
                    self.new_roles[(address, role, protocol)] = {"when": when, "only_answered": role == "c" and not had_client_role,
                                                                 "peers": set(), "ops": set(), "covered": set()}
        return True

    def process_hour(self, hour, records, closed):
        """Take in one hour's records.

        closed is False for records read outside a finished hour (the hour still
        running, and late arrivals in hours already counted): then only what is
        new is noted, and nothing is counted.
        """
        state, settings = self.state, self.settings
        if closed:
            if records:
                state["data_hours"] += 1
                state["empty_hours"] = 0
                state["silent"] = False
                if state["learn_until"] is None and state["data_hours"] >= settings.learn_days * 24 and hour + 1 >= state["started_hour"]:
                    state["learn_until"] = hour + 1          # this hour is the last one learned
            else:
                state["empty_hours"] += 1
        seen_pairs = set()
        for (client, server, protocol, action), (count, first, last, asked) in sorted(records.items()):
            first, last = first // 1000, last // 1000
            learning = self.learning(hour if closed else first // HOUR)
            if not self.touch_host(client, "c", protocol, first, learning) or not self.touch_host(server, "s", protocol, first, learning):
                continue
            pair_key = f"{client}|{server}|{protocol}"
            pair = state["pairs"].get(pair_key)
            if pair is None:
                if not self.room("ops", settings.max_operations):
                    continue
                pair = state["pairs"][pair_key] = {"f": first, "l": last, "h": 0, "dh0": state["data_hours"] - (1 if closed else 0),
                                                   "dhl": state["data_hours"]}
                if not learning:
                    self.new_pairs[(client, server, protocol)] = {"when": first, "ops": set()}
            pair["f"], pair["l"] = min(pair["f"], first), max(pair["l"], last)
            if closed and pair_key not in seen_pairs:
                seen_pairs.add(pair_key)
                if pair.pop("q", None):
                    self.findings.append(finding("resumed", last, client, server, protocol, [],
                                                 f"{client} and {server} are talking by {protocol} again."))
                if state["data_hours"] - pair["dhl"] > settings.quiet_hours:
                    pair["dh0"], pair["h"] = state["data_hours"] - 1, 0     # back after a gap: how regular it is counts from now
                pair["h"] += 1
                pair["dhl"] = state["data_hours"]
            op_key = f"{pair_key}|{action}"
            op = state["ops"].get(op_key)
            if op is None:
                if not asked or not self.room("ops", settings.max_operations):
                    continue                                  # seen only in answers so far: not something anyone asked for
                op = state["ops"][op_key] = {"f": first, "l": last, "n": 0, "mx": 0}
                if not learning:
                    self.new_ops[(client, server, protocol, action)] = first
            op["f"], op["l"] = min(op["f"], first), max(op["l"], last)
            if not closed:
                continue
            op["n"] += 1
            if learning or op["n"] <= settings.rate_learn_hours:
                op["mx"] = max(op["mx"], count)               # an operation's own first day is how its rate is learned
                continue
            if count <= max(op["mx"] * settings.burst_factor, op["mx"] + settings.burst_min):
                op.pop("bc", None)
                op.pop("bl", None)
                continue
            # Above its learned rate. One finding for the run of such hours; the hours are not
            # learned, so what was flagged does not become normal by itself. Only a level that
            # holds for a whole day is taken as the new normal.
            if op.get("bh") != hour - 1:
                op.pop("bc", None)                            # not the hour straight after the last such hour: a new run
                op.pop("bl", None)
            op["bh"] = hour
            op["bc"] = op.get("bc", 0) + 1
            op["bl"] = min(op.get("bl", count), count)
            if op["bc"] == 1 and hour - op.get("b", -10 ** 9) >= settings.burst_rearm_hours:
                op["b"] = hour
                self.findings.append(finding(
                    "burst", last, client, server, protocol, [action],
                    f"{client} used {action or 'an unnamed operation'} on {server} ({protocol}) {count} times in one hour; "
                    f"the most in any hour while learning was {op['mx']}."))
            if op["bc"] >= settings.burst_absorb_hours:
                op["mx"] = op.pop("bl")
                op.pop("bc")

    def check_quiet(self):
        """After closed hours: conversations that were there nearly every hour and have stopped."""
        state, settings = self.state, self.settings
        if state["learn_until"] is None or state["cursor"] is None or self.learning(state["cursor"] - 1):
            state["quiet_primed"] = False
            return
        now_hour, data_hours = state["cursor"], state["data_hours"]
        if not state["quiet_primed"]:
            # Learning has just ended (or a maintenance window has): what came and went while
            # learning is not news. Mark it as already quiet without a word.
            for pair in state["pairs"].values():
                if data_hours - pair["dhl"] >= settings.quiet_hours:
                    pair["q"] = 1
            state["quiet_primed"] = True
            return
        if state["empty_hours"] >= settings.quiet_hours and data_hours >= 24:
            # Nothing at all arrived: that is the sensor or its mirror port, not every device at once.
            if not state["silent"]:
                state["silent"] = True
                self.findings.append(finding(
                    "sensor-silent", now_hour * HOUR, None, None, None, [],
                    f"No industrial traffic has been recorded for {state['empty_hours']} hours. "
                    "Check the sensor, its capture interface and the mirror port before anything else."))
            return

        def regular(pair):
            span = pair["dhl"] - pair["dh0"]
            return span >= 24 and pair["h"] >= 0.9 * span

        stopped, still_answering, still_asking = [], set(), set()
        for key, pair in state["pairs"].items():
            client, server, protocol = key.split("|")
            if data_hours - pair["dhl"] < settings.quiet_hours:
                still_asking.add(client)             # heard lately, in any conversation, however new
                still_answering.add(server)
            elif not pair.get("q") and regular(pair):
                pair["q"] = 1
                stopped.append((client, server, protocol, pair["l"]))
        if not stopped:
            return
        said = "It was heard in at least nine hours out of ten before."
        by_server, by_client, single = {}, {}, []
        for item in stopped:
            client, server, protocol, last = item
            if server not in still_answering:
                by_server.setdefault(server, []).append(item)
            elif client not in still_asking:
                by_client.setdefault(client, []).append(item)
            else:
                single.append(item)
        hours = settings.quiet_hours
        for server, gone in sorted(by_server.items()):
            last = max(item[3] for item in gone)
            self.findings.append(finding(
                "quiet", now_hour * HOUR, None, server, gone[0][2], [],
                f"{server} has stopped answering: nothing from it in {hours} hours of otherwise normal traffic. "
                f"{said} Last heard {iso(last)}. Talking to it were: {listing({f'{c} ({p})' for c, _, p, _ in gone})}."))
        for client, gone in sorted(by_client.items()):
            last = max(item[3] for item in gone)
            self.findings.append(finding(
                "quiet", now_hour * HOUR, client, None, gone[0][2], [],
                f"{client} has stopped asking: nothing from it in {hours} hours of otherwise normal traffic. "
                f"{said} Last heard {iso(last)}. It was talking to: {listing({f'{s} ({p})' for _, s, p, _ in gone})}."))
        for client, server, protocol, last in sorted(single):
            self.findings.append(finding(
                "quiet", now_hour * HOUR, client, server, protocol, [],
                f"{client} and {server} have stopped talking by {protocol} for {hours} hours, while both still "
                f"talk to others. {said} Last heard {iso(last)}."))

    def consolidate(self):
        """Turn what was noted as new into as few findings as say it all."""
        settings = self.settings
        for (client, server, protocol, action), when in self.new_ops.items():
            if (client, server, protocol) in self.new_pairs:
                self.new_pairs[(client, server, protocol)]["ops"].add(action)
        per_client = {}
        for (client, server, protocol), detail in sorted(self.new_pairs.items()):
            # The master's side first: a finding about a new master names the devices it talked to.
            said = True
            if client in self.new_hosts:
                self.new_hosts[client]["peers"].add(f"{server} ({protocol})")
                self.new_hosts[client]["ops"] |= detail["ops"]
            elif (client, "c", protocol) in self.new_roles:
                role = self.new_roles[(client, "c", protocol)]
                role["peers"].add(server)
                role["ops"] |= detail["ops"]
            else:
                said = False
            # Then the device's side. A known device answering a new protocol is not reported
            # separately when the finding about the new master already names it.
            if server in self.new_hosts:
                self.new_hosts[server]["peers"].add(f"{client} ({protocol})")
                if not said:
                    per_client.setdefault((client, protocol), []).append((server, detail, True))
            elif (server, "s", protocol) in self.new_roles:
                self.new_roles[(server, "s", protocol)]["covered" if said else "peers"].add(client)
            elif not said:
                per_client.setdefault((client, protocol), []).append((server, detail, False))

        for (client, protocol), pairs in sorted(per_client.items()):
            if len(pairs) > settings.sweep_pairs:
                unseen = [server for server, _, is_new in pairs if is_new]
                for server in unseen:
                    self.new_hosts[server]["swept"].add(f"{client} ({protocol})")
                self.findings.append(finding(
                    "sweep", min(detail["when"] for _, detail, _ in pairs), client, None, protocol, [],
                    f"{client} talked by {protocol} to {len(pairs)} devices it never talked to before"
                    + (f", {len(unseen)} of them never seen at all" if unseen else "")
                    + f": {listing(server for server, _, _ in pairs)}."))
                continue
            for server, detail, is_new in pairs:
                if is_new:
                    continue                           # said by the finding about the new device
                self.findings.append(finding(
                    "new-pair", detail["when"], client, server, protocol, detail["ops"],
                    f"{client} talked to {server} by {protocol} for the first time. "
                    f"Operations: {listing(op or 'unnamed' for op in detail['ops']) or 'none named'}."))

        for address, detail in sorted(self.new_hosts.items()):
            masters = sorted(protocol for role, protocol in detail["roles"] if role == "c")
            answers = sorted(protocol for role, protocol in detail["roles"] if role == "s")
            if masters:
                used = listing(op for op in detail["ops"] if op)
                self.findings.append(finding(
                    "new-master", detail["when"], address, None, masters[0], detail["ops"],
                    f"{address} was never seen before and is acting as a master by {listing(masters)}. "
                    f"It talked to: {listing(detail['peers']) or 'nothing that answered'}."
                    + (f" Operations: {used}." if used else "")))
            elif not (detail["swept"] and detail["peers"] <= detail["swept"]):      # else the sweep finding names it
                self.findings.append(finding(
                    "new-device", detail["when"], None, address, answers[0] if answers else None, [],
                    f"{address} was never seen before and answers by {listing(answers)}. "
                    f"Talking to it: {listing(detail['peers'])}."))
        for (address, role, protocol), detail in sorted(self.new_roles.items()):
            if role == "c":
                before = "until now it only answered" if detail["only_answered"] else "it was a master of other protocols before"
                used = listing(op for op in detail["ops"] if op)
                self.findings.append(finding(
                    "new-master", detail["when"], address, None, protocol, detail["ops"],
                    f"{address} is acting as a {protocol} master for the first time; {before}. "
                    f"It talked to: {listing(detail['peers'])}." + (f" Operations: {used}." if used else "")))
            elif detail["peers"]:
                self.findings.append(finding(
                    "new-service", detail["when"], None, address, protocol, [],
                    f"{address} answered by {protocol} for the first time. Asking: {listing(detail['peers'])}."))

        per_pair = {}
        for (client, server, protocol, action), when in sorted(self.new_ops.items()):
            if (client, server, protocol) not in self.new_pairs:
                per_pair.setdefault((client, server, protocol), []).append((action, when))
        for (client, server, protocol), ops in sorted(per_pair.items()):
            names = [action for action, _ in ops]
            control = [name for name in names if CONTROL_WORDS.search(name)]
            self.findings.append(finding(
                "new-control-operation" if control else "new-operation", min(when for _, when in ops),
                client, server, protocol, names,
                f"{client} used {listing(name or 'an unnamed operation' for name in names)} on {server} ({protocol}) "
                "for the first time."))
        self.new_hosts, self.new_roles, self.new_pairs, self.new_ops = {}, {}, {}, {}

    def expire(self, now):
        """Once a day: drop what has not been seen for a long time, so the list cannot grow for ever."""
        state, settings = self.state, self.settings
        if now - state["expired_at"] < DAY or settings.expire_days <= 0:
            return
        state["expired_at"] = now
        horizon = now - settings.expire_days * DAY
        for table in ("ops", "pairs", "hosts"):
            for key in [key for key, entry in state[table].items() if entry["l"] < horizon]:
                del state[table][key]


# --- Handing findings on ---------------------------------------------------------------

def alert_payload(found):
    """One finding in the shape the product's alert webhook takes (its /mapi/alert)."""
    title, severity, technique = KINDS[found["kind"]]
    body = {"message": found["text"], "tags": ["td-baseline", found["kind"]]}
    addresses = [address for address in (found["client"], found["server"]) if address]
    if found["client"]:
        body["source"] = {"ip": [found["client"]]}
    if found["server"]:
        body["destination"] = {"ip": [found["server"]]}
    if addresses:
        body["related"] = {"ip": addresses}
    if found["protocol"]:
        body["network"] = {"protocol": [found["protocol"]]}
    if found["actions"]:
        body["event"] = {"action": found["actions"]}
    if technique:
        tactic_id, tactic, parent_id, parent, sub_id, sub = TECHNIQUES[technique]
        body["threat"] = {"framework": FRAMEWORK, "tactic": {"id": [tactic_id], "name": [tactic]},
                          "technique": {"id": [parent_id], "name": [parent]}}
        if sub_id:
            body["threat"]["technique"]["subtechnique"] = {"id": [sub_id], "name": [sub]}
    return {"alert": {
        "monitor": {"name": MONITOR_NAME},
        "trigger": {"name": title, "severity": severity},
        "period": {"start": found["time"], "end": found["time"]},
        "body": json.dumps(body),
        "alert": "td-" + found["id"],
        "error": "",
    }}


def deliver(http, settings, state, findings, errors):
    """Send findings and whatever earlier passes could not send.

    When the webhook cannot be reached, everything waits. When it answers and
    refuses one alert, that alert is tried three times in all and then given
    up, so one alert the product will not take cannot hold back all the others.
    """
    waiting = state["outbox"] + findings
    state["outbox"] = []
    sent = 0
    for index, found in enumerate(waiting):
        try:
            http.post(settings.alert_url, alert_payload(found))
            found["delivered"] = True
            sent += 1
        except urllib.error.HTTPError as error:
            found["tries"] = found.get("tries", 0) + 1
            errors.append(f"alert webhook refused an alert ({error.code})")
            if found["tries"] < 3:
                state["outbox"].append(found)
        except NETWORK_ERRORS as error:
            errors.append(f"alert webhook: {error}")
            state["outbox"] += waiting[index:]            # not reachable: keep the rest, in order
            break
    if len(state["outbox"]) > 200:
        errors.append(f"{len(state['outbox']) - 200} alerts that could not be sent were given up; they are in the findings file")
        state["outbox"] = state["outbox"][-200:]
    return sent


def cap(findings, limit):
    """Keep the most serious findings when one pass has too many, and say how many were left out."""
    if len(findings) <= limit:
        return findings, 0
    ranked = sorted(findings, key=lambda found: (KINDS[found["kind"]][1], found["time"]))
    return ranked[:limit], len(findings) - limit


# --- One pass ----------------------------------------------------------------------------

def run_pass(settings, store, http, now=None, dry_run=False):
    now = int(now if now is not None else time.time())
    state = store.load()
    engine = Engine(settings, state)
    errors, notes = [], []
    last_closed = (now - settings.lag_minutes * 60) // HOUR - 1      # the newest hour that is over and has had time to arrive
    oldest = last_closed + 1 - (settings.backfill_days * 24 if state["backfill"] else 0)
    if state["cursor"] is None:
        state["started_hour"], state["cursor"] = last_closed + 1, oldest
    elif state["cursor"] > last_closed + 1:
        # The clock is behind what was already read: it was wrong then, or is wrong now.
        if state["first_hour"] is None:
            state["started_hour"], state["cursor"] = last_closed + 1, oldest
        else:
            errors.append(f"the clock ({iso(now)}) is behind what has already been read (up to {iso(state['cursor'] * HOUR)}); "
                          "nothing is read until it catches up. If the clock was wrong before, run 'reset --yes'")
    elif state["cursor"] < oldest:
        # Far behind: the clock was wrong at the first pass, or the program did not run for a long time.
        if state["first_hour"] is None:
            state["started_hour"] = last_closed + 1
        else:
            notes.append(f"skipped {oldest - state['cursor']} hours older than what is read back")
        state["cursor"] = oldest
    start_hour = state["cursor"]
    end_hour = min(last_closed + 1, start_hour + settings.max_hours_per_run)
    caught_up = end_hour == last_closed + 1

    def keep():
        engine.consolidate()
        state["pending"] += engine.findings
        engine.findings = []
        if not dry_run:
            store.save(state)

    step = max(1, state["step"] or settings.step_hours)
    failed = bool(errors)
    while not failed and state["cursor"] < end_hour:
        chunk_end = min(end_hour, state["cursor"] + step)
        try:
            hours = collect(http, settings, state["cursor"] * HOUR, chunk_end * HOUR, by_hour=True)
        except NETWORK_ERRORS as error:
            errors.append(f"reading OpenSearch: {error}")
            state["step"] = max(1, step // 2)          # ask for less next time
            failed = True
            break
        for hour in range(state["cursor"], chunk_end):
            records = hours.get(hour, {})
            if records and state["first_hour"] is None:
                state["first_hour"] = hour
            if state["first_hour"] is not None:
                engine.process_hour(hour, records, closed=True)
            state["cursor"] = hour + 1
        engine.check_quiet()
        step = min(settings.step_hours, step * 2)
        state["step"] = step
        keep()                                          # what was read is kept step by step
    if caught_up and not failed and state["first_hour"] is not None:
        # The hour still running, and the last few finished hours once more for records that
        # arrived late. Only for what is new: nothing here is counted.
        late_start = max(state["first_hour"], last_closed + 1 - settings.late_hours) * HOUR
        late_end = now - settings.lag_minutes * 60
        if late_end > late_start:
            try:
                for hour, records in collect(http, settings, late_start, late_end, by_hour=False).items():
                    engine.process_hour(hour, records, closed=False)
            except NETWORK_ERRORS as error:
                errors.append(f"reading OpenSearch: {error}")
        engine.expire(now)
    if engine.refused and now - state["full_at"] >= DAY:
        state["full_at"] = now
        engine.findings.append(finding(
            "list-full", now, None, None, None, [],
            f"The list holds {len(state['hosts'])} addresses and {len(state['ops'])} operations and takes no more. "
            "That many is not a plant: look for a scan or forged addresses, then run 'reset --yes' or raise the limits."))
    keep()

    findings, state["pending"] = state["pending"], []
    to_send, left_out = cap([found for found in findings if found["kind"] not in RECORD_ONLY], settings.max_alerts_per_run)
    if left_out:
        overflow = finding(
            "overflow", now, None, None, None, [],
            f"{left_out} more findings in this pass were recorded but not sent as alerts. "
            "See 'findings' on the server (td-baseline findings).")
        findings.append(overflow)
        to_send = to_send + [overflow]
    sent = 0
    if not dry_run:
        if state["alerts"]:
            sent = deliver(http, settings, state, to_send, errors)
        for found in findings:
            found.setdefault("delivered", False)
        store.record(findings)
        state["runs"] += 1
        state["last_run"] = {"at": now, "from_hour": start_hour, "to_hour": state["cursor"], "caught_up": caught_up and not failed,
                             "findings": len(findings), "sent": sent, "errors": errors[:3], "notes": notes[:3]}
        store.save(state)
    return {"findings": findings, "sent": sent, "errors": errors, "caught_up": caught_up and not failed, "state": state}


# --- Commands ---------------------------------------------------------------------------

def describe(state, settings, now):
    lines = []
    wanted = settings.learn_days * 24
    if state["first_hour"] is None:
        lines.append("No industrial traffic has been read yet.")
    elif state["learn_until"] is None:
        lines.append(f"First industrial record: {iso(state['first_hour'] * HOUR)}")
        lines.append(f"Learning: {state['data_hours']} of {wanted} hours with traffic read so far "
                     f"(read up to {iso(state['cursor'] * HOUR)}). Nothing is reported while learning.")
    else:
        lines.append(f"First industrial record: {iso(state['first_hour'] * HOUR)}")
        lines.append(f"Learning ended {iso(state['learn_until'] * HOUR)}. Comparing since then.")
    if state["maintenance_until"] > now:
        lines.append(f"Maintenance: everything until {iso(state['maintenance_until'])} is being learned as normal.")
    masters = sum(1 for host in state["hosts"].values() if host["c"])
    lines.append(f"Known: {len(state['hosts'])} addresses ({masters} act as masters), {len(state['pairs'])} conversations, "
                 f"{len(state['ops'])} operations; {state['data_hours']} hours with traffic read.")
    lines.append("Alerts: " + ("ON, findings go to the product's alert webhook" if state["alerts"]
                               else "OFF, findings are only recorded here (switch on with: alerts on)"))
    if state["outbox"]:
        lines.append(f"{len(state['outbox'])} findings are waiting because the alert webhook did not take them.")
    last = state.get("last_run")
    if last:
        lines.append(f"Last pass: {iso(last['at'])}, {last['findings']} findings, {last['sent']} sent"
                     + ("" if last["caught_up"] else ", still catching up on stored traffic")
                     + ("; " + "; ".join(last["notes"]) if last.get("notes") else "")
                     + ("; errors: " + "; ".join(last["errors"]) if last["errors"] else ""))
    else:
        lines.append("No pass has run yet.")
    return "\n".join(lines)


def become_owner_of(folder):
    """Run as the account that owns the folder when started as root (as 'docker compose exec' does)."""
    if os.geteuid() != 0:
        return
    probe = folder if os.path.exists(folder) else os.path.dirname(folder.rstrip("/")) or "/"
    try:
        owner = os.stat(probe)
        if owner.st_uid != 0:
            os.setgroups([])
            os.setgid(owner.st_gid)
            os.setuid(owner.st_uid)
    except OSError:
        pass


def main(argv=None, now=None, environ=os.environ):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command")
    run = commands.add_parser("run", help="one pass")
    run.add_argument("--dry-run", action="store_true", help="show what would be found; save and send nothing")
    commands.add_parser("status")
    commands.add_parser("check")
    show = commands.add_parser("findings")
    show.add_argument("--last", type=int, default=20)
    alerts = commands.add_parser("alerts")
    alerts.add_argument("switch", choices=("on", "off"))
    commands.add_parser("test-alert")
    learn = commands.add_parser("learn")
    learn.add_argument("--hours", type=int)
    learn.add_argument("--stop", action="store_true")
    forget = commands.add_parser("forget")
    forget.add_argument("address")
    reset = commands.add_parser("reset")
    reset.add_argument("--yes", action="store_true")
    reset.add_argument("--with-history", action="store_true", help="learn from the traffic already stored instead of from now")
    args = parser.parse_args(argv)
    command = args.command or "run"
    settings = Settings(environ)
    become_owner_of(settings.folder)
    store = Store(settings.folder)
    store.prepare()
    now = int(now if now is not None else time.time())
    out = sys.stdout

    if command == "status":
        print(describe(store.load(), settings, now), file=out)
        return 0
    if command == "findings":
        for found in store.recent(args.last):
            print(f"{found['time']}  {found['kind']:<22} {found['text']}", file=out)
        return 0

    http_client = Http(settings)
    if command == "check":
        try:
            hours = collect(http_client, settings, now - HOUR - settings.lag_minutes * 60, now - settings.lag_minutes * 60, by_hour=False)
        except NETWORK_ERRORS as error:
            print(f"Could not read OpenSearch at {settings.opensearch_url}: {error}", file=out)
            return 1
        records = next(iter(hours.values()), {})
        pairs = {key[:3] for key in records}
        print(f"Read {settings.index} at {settings.opensearch_url}: in the last hour, {len(pairs)} conversations "
              f"and {len(records)} operations in industrial protocols.", file=out)
        for client, server, protocol, action in sorted(records)[:15]:
            print(f"  {client} -> {server}  {protocol}  {action or '(unnamed)'}  x{records[(client, server, protocol, action)][0]}", file=out)
        if not records:
            print("Nothing found. If the plant is running, check that the sensor sees industrial traffic "
                  "(Dashboards, ICS/IoT Security Overview).", file=out)
        return 0
    if command == "test-alert":
        found = finding("new-device", now, None, "192.0.2.1", "modbus", [],
                        "Test alert from td_baseline.py. 192.0.2.1 is a documentation address; nothing was detected.")
        try:
            reply = http_client.post(settings.alert_url, alert_payload(found))
        except NETWORK_ERRORS as error:
            print(f"The alert webhook at {settings.alert_url} did not take it: {error}", file=out)
            return 1
        print(f"Sent. The webhook answered: {json.dumps(reply)[:300]}\nLook for rule.name \"{MONITOR_NAME}\" in the dashboards.", file=out)
        return 0

    if not store.lock(wait=0 if command == "run" else 60):
        if command == "run":
            print("Another pass is still running; this one does nothing.", file=sys.stderr)
            return 0
        print("A pass is running and did not finish within a minute; nothing was changed. Try again.", file=sys.stderr)
        return 1
    try:
        if command == "run":
            result = run_pass(settings, store, http_client, now=now, dry_run=args.dry_run)
            if args.dry_run:
                for found in result["findings"]:
                    print(f"{found['time']}  {found['kind']:<22} {found['text']}", file=out)
                print(f"{len(result['findings'])} findings; nothing saved or sent.", file=out)
            for error in result["errors"]:
                print(f"td-baseline: {error}", file=sys.stderr)
            return 1 if result["errors"] else 0

        state = store.load()
        if command == "alerts":
            state["alerts"] = args.switch == "on"
            if not state["alerts"]:
                state["outbox"] = []
            print("Alerts " + ("ON." if state["alerts"] else "OFF."), file=out)
        elif command == "learn":
            if args.stop:
                state["maintenance_until"] = 0
                print("Maintenance learning stopped.", file=out)
            elif args.hours and args.hours > 0:
                state["maintenance_from"], state["maintenance_until"] = now, now + args.hours * HOUR
                print(f"Everything until {iso(state['maintenance_until'])} will be learned as normal and not reported.", file=out)
            else:
                parser.error("learn needs --hours N or --stop")
        elif command == "forget":
            address = args.address
            if address not in state["hosts"]:
                print(f"{address} is not in the list.", file=out)
                return 1
            del state["hosts"][address]
            for table in ("pairs", "ops"):
                for key in [key for key in state[table] if address in key.split("|")[:2]]:
                    del state[table][key]
            print(f"{address} forgotten with its conversations. It will be reported when it next appears.", file=out)
        elif command == "reset":
            if not args.yes:
                parser.error("reset forgets everything that was learned; add --yes to confirm")
            state = dict(new_state(), alerts=state["alerts"], backfill=args.with_history)
            print("Everything forgotten. Learning starts again " +
                  ("from the traffic already stored." if args.with_history else "from now; what is stored from before is not read."), file=out)
        store.save(state)
        return 0
    finally:
        store.unlock()


if __name__ == "__main__":
    sys.exit(main())
