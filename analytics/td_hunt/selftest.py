# SPDX-License-Identifier: GPL-3.0-only
# Part of the TechDetechtives analytics layer (derived from HELK, GPL-3.0).
"""Smoke test for the analytics workbench:  python -m td_hunt.selftest"""

from __future__ import annotations

import sys

import td_hunt as td

JOIN_SQL = """
SELECT l.user_name, l.source_ip, p.process_parent_name, p.process_name
FROM logon l
JOIN process p
  ON p.winlog_event_data_LogonId = l.winlog_event_data_TargetLogonId
 AND p.host_name = l.host_name
WHERE l.winlog_event_data_LogonType = '3'
"""


def check_sample_data() -> str:
    process = td.flatten(td._load_sample("process.jsonl"))
    logon = td.flatten(td._load_sample("logon.jsonl"))
    if process.empty or logon.empty:
        raise AssertionError("bundled sample data is empty")
    graph = td.process_tree(process)
    if graph.number_of_edges() == 0:
        raise AssertionError("process tree has no edges")
    return f"{len(process)} process and {len(logon)} logon events, {graph.number_of_edges()} parent-child links"


def check_spark() -> str:
    spark = td.spark_session("TechDetechtives selftest")
    version = spark.version
    try:
        td.to_spark(td.flatten(td._load_sample("process.jsonl")), view="process", spark=spark)
        td.to_spark(td.flatten(td._load_sample("logon.jsonl")), view="logon", spark=spark)
        rows = spark.sql(JOIN_SQL).collect()
    finally:
        spark.stop()
    if len(rows) != 5:
        raise AssertionError(f"expected 5 joined rows from the sample data, got {len(rows)}")
    return f"Spark {version} joined logons to processes ({len(rows)} rows)"


def check_platform() -> str:
    if td.demo_mode():
        return "skipped (demo mode: TD_ES_HOST is not set or TD_DEMO=1)"
    es = td.client()
    info = es.info()
    count = es.count(index="logs-*", ignore_unavailable=True)["count"]
    return f"connected to Elasticsearch {info['version']['number']}; logs-* holds {count} events"


def main() -> int:
    failed = 0
    for label, check in (
        ("sample data", check_sample_data),
        ("spark", check_spark),
        ("platform connection", check_platform),
    ):
        try:
            print(f"[ ok ] {label}: {check()}")
        except Exception as error:  # report every check, then fail
            failed += 1
            print(f"[FAIL] {label}: {type(error).__name__}: {error}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
