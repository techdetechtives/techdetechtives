---
name: techdetechtives-hunting
description: How to hunt in platform data with the TechDetechtives workbench - Jupyter, pandas, Spark SQL and the td_hunt helper library - including the available data sets, the ECS field names, and how to turn a hunt into a detection rule. Use when exploring events beyond what the console offers, joining data sets such as logons to process starts, building process trees, working in the analytics notebooks, or porting a query written for another stack.
license: MIT
---

# Hunting with the TechDetechtives workbench

The workbench is a Jupyter and Spark container on the second host. It reads
events from the platform with a read-only key, so nothing done in a notebook
can change or delete platform data. Use it when a question needs joins,
statistics or graphs that the console's Hunt screen cannot express; for a
quick filter, Hunt is faster.

## Getting in

`scripts/install.sh analytics` builds and starts it. It listens on the second
host's own loopback address only, so from another computer open a tunnel
first:

```bash
ssh -L 8888:127.0.0.1:8888 <user>@<second host>
```

then browse to `http://127.0.0.1:8888/lab` and sign in with the
`TD_JUPYTER_TOKEN` value from `config/techdetechtives.env`.
`scripts/verify.sh analytics` checks the container, the platform connection
and Spark. With `TD_ES_HOST` empty the workbench runs in demo mode on bundled
sample data, and every call says so; never present demo results as findings.

## The library

```python
import td_hunt as td

procs = td.events("process", since="24h")                  # pandas DataFrame
ps = td.events("process", query='process.name: "powershell.exe"', since="7d",
               fields=["host.name", "user.name", "process.command_line"])
spark = td.spark_session()
td.to_spark(procs, view="process", spark=spark)            # Spark SQL view
spark.sql("SELECT process_parent_name, process_name, count(*) AS n "
          "FROM process GROUP BY 1, 2 ORDER BY n").show(20, truncate=False)
tree = td.process_tree(procs)                              # networkx graph
td.lineage(tree, some_entity_id)                           # names from root to node
```

| Data set | What it holds | Needs |
| --- | --- | --- |
| `process` | Process starts | Elastic Defend or Sysmon on endpoints |
| `logon` | Windows logons (event 4624) | Windows Security log collection |
| `zeek_conn` | Network connections | A sensor seeing the traffic |
| `alerts` | Network alerts | Suricata |

Any index pattern works in place of a name: `td.events("logs-*", query="tags: alert")`.

Things that matter in practice:

- `since` is a look-back such as `15m`, `24h`, `7d`. `limit` defaults to
  10,000 events and the call prints a note when it is hit; narrow the query or
  ask for specific `fields` rather than raising the limit a long way, because
  everything is loaded into memory on a host that also runs ticketing and
  scanning.
- Field names are ECS, with dots: `process.parent.name`, `source.ip`,
  `winlog.event_data.LogonType`. In Spark SQL views the dots become
  underscores and `@timestamp` becomes `timestamp`. `docs/FIELD-MAPPING.md`
  maps the names used by HELK and Sysmon-style guides.
- Which fields are filled depends on the agent integrations in use. Look at
  `df.columns` and a few rows before trusting a query that returns nothing.

## Notebooks

`analytics/notebooks/` holds four worked hunts: connection check and regular-
interval connections, rare parent-child process pairs and encoded PowerShell,
a Spark SQL join of network logons to the processes they started, and process
ancestry graphs. Copy one as a starting point; clear outputs before
committing, because outputs carry host names, user names and command lines
from the monitored network.

## A hunt that is worth keeping

State the hypothesis and the technique first ("remote WMI execution, T1047:
WmiPrvSE.exe starting an interpreter"), then what data would show it, then
the query. Record what was searched and found, including "nothing", in the
DFIR-IRIS case or the notebook. When a hunt finds a pattern that should never
be normal, turn it into a rule with the `techdetechtives-detections` skill so
it is watched from then on.

Follow the limits in `techdetechtives-platform`: no outside lookups without
the operator's agreement, and no changes to hosts from a hunt.
