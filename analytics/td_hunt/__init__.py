# SPDX-License-Identifier: GPL-3.0-only
#
# td_hunt - hunting helpers for the TechDetechtives analytics workbench.
#
# Part of the TechDetechtives analytics layer, a modified work derived from
# HELK, "The Hunting ELK" (https://github.com/Cyb3rWard0g/HELK),
# Copyright Roberto Rodriguez (@Cyb3rWard0g), licensed GPL-3.0.
# Modified by TechDetechtives, 2026: HELK's own ELK stack and its Spark
# Elasticsearch connector are replaced by a read-only client for the
# platform's Elasticsearch, and field names follow ECS.
"""Read platform events into pandas and Spark for hunting.

Typical use in a notebook::

    import td_hunt as td
    procs = td.events("process", since="24h")      # pandas DataFrame
    spark = td.spark_session()
    td.to_spark(procs, view="process", spark=spark)  # Spark SQL view

When no Elasticsearch host is configured the same calls return a small
bundled sample data set, so the notebooks run end to end without a platform.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional, Union

import pandas as pd

__version__ = "0.2.0"

SAMPLE_DIR = Path(__file__).parent / "sample_data"

# Named data sets: the index patterns they live in on the platform, and the
# bundled sample file used in demo mode.
DATASETS = {
    "process": {
        "index": "logs-endpoint.events.process-*,logs-windows.sysmon_operational-*",
        "sample": "process.jsonl",
        "filter": {"term": {"event.category": "process"}},
    },
    "logon": {
        "index": "logs-system.security-*",
        "sample": "logon.jsonl",
        "filter": {"term": {"event.code": "4624"}},
    },
    "zeek_conn": {
        "index": "logs-zeek-so*",
        "sample": "zeek_conn.jsonl",
        "filter": {"term": {"event.dataset": "zeek.conn"}},
    },
    "alerts": {
        "index": "logs-suricata.alerts-*",
        "sample": None,
        "filter": None,
    },
}

_SINCE = re.compile(r"^\d+[smhdw]$")


@dataclass(frozen=True)
class Config:
    es_host: str
    es_port: int
    es_api_key: str
    es_ca_cert: str
    es_assert_hostname: bool
    spark_master: str
    spark_driver_memory: str
    demo: bool


def _flag(value: Optional[str], default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def config() -> Config:
    """Settings from the environment (see config/techdetechtives.env.example)."""
    host = os.environ.get("TD_ES_HOST", "").strip()
    return Config(
        es_host=host,
        es_port=int(os.environ.get("TD_ES_PORT", "9200") or 9200),
        es_api_key=os.environ.get("TD_ES_API_KEY", "").strip(),
        es_ca_cert=os.environ.get("TD_ES_CA_CERT", "").strip(),
        es_assert_hostname=_flag(os.environ.get("TD_ES_ASSERT_HOSTNAME"), True),
        spark_master=os.environ.get("TD_SPARK_MASTER", "local[*]") or "local[*]",
        spark_driver_memory=os.environ.get("TD_SPARK_DRIVER_MEMORY", "2g") or "2g",
        demo=_flag(os.environ.get("TD_DEMO"), False) or not host,
    )


def demo_mode() -> bool:
    """True when events come from bundled sample data instead of the platform."""
    return config().demo


def client():
    """A read-only Elasticsearch client for the platform."""
    cfg = config()
    if not cfg.es_host:
        raise RuntimeError("TD_ES_HOST is not set; see config/techdetechtives.env.example")
    if not cfg.es_api_key:
        raise RuntimeError("TD_ES_API_KEY is not set; create one with platform/create-readonly-key.sh")
    from elasticsearch import Elasticsearch  # imported here so demo mode needs no client

    kwargs: dict[str, Any] = {
        "hosts": [f"https://{cfg.es_host}:{cfg.es_port}"],
        "api_key": cfg.es_api_key,
        "request_timeout": 60,
    }
    if cfg.es_ca_cert:
        if not Path(cfg.es_ca_cert).is_file():
            raise RuntimeError(
                f"CA certificate {cfg.es_ca_cert} not found; copy the manager's "
                "/etc/pki/ca.crt into analytics/certs/so-ca.crt"
            )
        kwargs["ca_certs"] = cfg.es_ca_cert
    if not cfg.es_assert_hostname:
        kwargs["ssl_assert_hostname"] = False
    return Elasticsearch(**kwargs)


def flatten(records: Iterable[dict]) -> pd.DataFrame:
    """Nested event documents to a flat table with dotted column names."""
    df = pd.json_normalize(list(records))
    if "@timestamp" in df.columns:
        df["@timestamp"] = pd.to_datetime(df["@timestamp"], utc=True, errors="coerce")
        df = df.sort_values("@timestamp").reset_index(drop=True)
    return df


def _load_sample(name: str) -> list[dict]:
    path = SAMPLE_DIR / name
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _build_query(base_filter: Optional[dict], query: Union[str, dict, None], since: Optional[str]) -> dict:
    filters: list[dict] = []
    if base_filter:
        filters.append(base_filter)
    if since:
        if not _SINCE.match(since):
            raise ValueError("since must look like 15m, 24h, 7d or 2w")
        filters.append({"range": {"@timestamp": {"gte": f"now-{since}"}}})
    if isinstance(query, str) and query.strip():
        filters.append({"query_string": {"query": query, "analyze_wildcard": True}})
    elif isinstance(query, dict):
        filters.append(query)
    return {"bool": {"filter": filters}} if filters else {"match_all": {}}


def events(
    dataset: str,
    query: Union[str, dict, None] = None,
    since: Optional[str] = "24h",
    fields: Optional[list[str]] = None,
    limit: int = 10000,
    quiet: bool = False,
) -> pd.DataFrame:
    """Fetch events as a pandas DataFrame.

    dataset  a name from DATASETS ("process", "logon", "zeek_conn", "alerts")
             or any index pattern such as "logs-*".
    query    a Lucene query string, or an Elasticsearch query DSL dict.
    since    look-back window: 15m, 24h, 7d. None for no time limit.
    fields   restrict the returned fields (faster, smaller).
    limit    maximum number of events to return.
    """
    spec = DATASETS.get(dataset)
    if demo_mode():
        if spec is None or not spec["sample"]:
            raise ValueError(
                f"no sample data for '{dataset}' in demo mode; "
                f"available: {[k for k, v in DATASETS.items() if v['sample']]}"
            )
        if not quiet:
            print(f"[td_hunt] demo mode: '{dataset}' loaded from bundled sample data, not from the platform")
        df = flatten(_load_sample(spec["sample"])[:limit])
        if fields:
            df = df[[c for c in df.columns if c in fields or c == "@timestamp"]]
        return df

    from elasticsearch import helpers

    index = spec["index"] if spec else dataset
    body: dict[str, Any] = {"query": _build_query(spec["filter"] if spec else None, query, since)}
    if fields:
        body["_source"] = sorted(set(fields) | {"@timestamp"})
    records = []
    es = client()
    for hit in helpers.scan(es, index=index, query=body, size=1000, ignore_unavailable=True):
        records.append(hit["_source"])
        if len(records) >= limit:
            break
    if not quiet:
        note = " (limit reached; narrow the query or raise limit)" if len(records) >= limit else ""
        print(f"[td_hunt] {len(records)} events from {index}{note}")
    return flatten(records)


def spark_column(name: str) -> str:
    """Dotted ECS field name to a Spark-friendly column name."""
    return name.replace("@", "").replace(".", "_").replace("-", "_")


def spark_session(app: str = "TechDetechtives"):
    """Create (or reuse) a Spark session using TD_SPARK_MASTER."""
    from pyspark.sql import SparkSession

    cfg = config()
    return (
        SparkSession.builder.appName(app)
        .master(cfg.spark_master)
        .config("spark.driver.memory", cfg.spark_driver_memory)
        .config("spark.sql.session.timeZone", "UTC")
        # Local mode only: keep Spark's own ports off the network.
        .config("spark.driver.bindAddress", "127.0.0.1")
        .config("spark.driver.host", "127.0.0.1")
        .config("spark.ui.enabled", "false")
        .config("spark.ui.showConsoleProgress", "false")
        .getOrCreate()
    )


def spark_ready(df: pd.DataFrame) -> pd.DataFrame:
    """Copy of df that converts cleanly to Spark.

    Column names lose their dots (process.parent.name -> process_parent_name),
    lists and dicts become JSON strings, and text columns become plain strings
    with None for missing values, so every column has a single type.
    """
    out = pd.DataFrame(index=df.index)
    for col in df.columns:
        series = df[col]
        name = spark_column(col)
        if pd.api.types.is_datetime64_any_dtype(series):
            # Naive UTC timestamps; the Spark session time zone is UTC.
            out[name] = series.dt.tz_convert("UTC").dt.tz_localize(None) if series.dt.tz is not None else series
        elif pd.api.types.is_bool_dtype(series) or pd.api.types.is_numeric_dtype(series):
            out[name] = series
        else:
            out[name] = [
                None
                if (value is None or (isinstance(value, float) and pd.isna(value)) or value is pd.NA)
                else (json.dumps(value) if isinstance(value, (list, dict)) else str(value))
                for value in series
            ]
            out[name] = out[name].astype(object)
    return out


def to_spark(df: pd.DataFrame, view: Optional[str] = None, spark=None):
    """pandas DataFrame to a Spark DataFrame, optionally registered as a SQL view."""
    from pyspark.sql import types as T

    spark = spark or spark_session()
    ready = spark_ready(df)
    fields = []
    for col in ready.columns:
        series = ready[col]
        if pd.api.types.is_datetime64_any_dtype(series):
            spark_type = T.TimestampType()
        elif pd.api.types.is_bool_dtype(series):
            spark_type = T.BooleanType()
        elif pd.api.types.is_integer_dtype(series):
            spark_type = T.LongType()
        elif pd.api.types.is_float_dtype(series):
            spark_type = T.DoubleType()
        else:
            spark_type = T.StringType()
        fields.append(T.StructField(col, spark_type, True))

    def native(value):
        # Spark wants plain Python values, not pandas or numpy scalars.
        if isinstance(value, str):
            return value
        if value is None or pd.isna(value):
            return None
        if isinstance(value, pd.Timestamp):
            return value.to_pydatetime()
        return value.item() if hasattr(value, "item") else value

    rows = [tuple(native(v) for v in row) for row in ready.itertuples(index=False, name=None)]
    sdf = spark.createDataFrame(rows, schema=T.StructType(fields))
    if view:
        sdf.createOrReplaceTempView(view)
    return sdf


def process_tree(df: pd.DataFrame):
    """Directed graph of parent -> child processes from process events.

    Nodes are process entity ids, with name, command line, host and user as
    attributes. Requires the process.entity_id and process.parent.entity_id
    fields.
    """
    import networkx as nx

    needed = ["process.entity_id", "process.parent.entity_id"]
    missing = [c for c in needed if c not in df.columns]
    if missing:
        raise ValueError(f"missing fields for a process tree: {missing}")

    def value(row, column):
        item = row.get(column)
        return None if item is None or (isinstance(item, float) and pd.isna(item)) else item

    graph = nx.DiGraph()
    for _, row in df.iterrows():
        child = value(row, "process.entity_id")
        parent = value(row, "process.parent.entity_id")
        if not child:
            continue
        graph.add_node(
            child,
            name=value(row, "process.name"),
            command_line=value(row, "process.command_line"),
            host=value(row, "host.name"),
            user=value(row, "user.name"),
            timestamp=value(row, "@timestamp"),
        )
        if parent:
            if parent not in graph:
                graph.add_node(parent, name=value(row, "process.parent.name"), host=value(row, "host.name"))
            elif not graph.nodes[parent].get("name"):
                graph.nodes[parent]["name"] = value(row, "process.parent.name")
            graph.add_edge(parent, child)
    return graph


def lineage(graph, node: str) -> list[str]:
    """Process names from the root ancestor down to node."""
    chain = [node]
    while True:
        parents = list(graph.predecessors(chain[0]))
        if not parents or parents[0] in chain:
            break
        chain.insert(0, parents[0])
    return [graph.nodes[n].get("name") or n for n in chain]
