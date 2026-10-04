# Modifications

This file is the prominent notice of modification required by the upstream licences. Update it whenever the overlay or the analytics layer changes.

## Changes to an installed Security Onion

Applied by `platform/apply-overlay.sh` on the manager node. First applied in version 0.1.0, 2026-10-04.

| What changes | Where on the platform | How |
| --- | --- | --- |
| Login banner | `/opt/so/saltstack/local/salt/soc/files/soc/banner.md` | Replaced with the TechDetechtives banner. Previous file backed up. |
| Console overview page | `/opt/so/saltstack/local/salt/soc/files/soc/motd.md` | Replaced with the TechDetechtives overview. Previous file backed up. |
| Sigma rules | `/nsm/rules/custom-local-repos/local-sigma` | 3 rule files added and committed |
| Suricata rules | `/nsm/rules/custom-local-repos/local-suricata` | 1 rule file (2 rules, SIDs 1900001 and 1900002) added and committed |
| YARA rules | `/nsm/rules/custom-local-repos/local-yara` | 1 rule file added and committed |

Applied by `platform/create-readonly-key.sh`:

| What changes | How |
| --- | --- |
| Elasticsearch API keys | One read-only key named `techdetechtives-analytics-ro` is created (read access to `logs-*` and `so-*`) |
| Firewall | With `--allow-ip`, the analytics host is added to the `elasticsearch_rest` host group (port 9200) |

**Not changed:** Security Onion's source code, container images, logo, licence notices, licence-key functionality, and Pro features. Both console pages state that the deployment is modified and what it is built on.

Backups are stored under `/nsm/backup/techdetechtives/`. `sudo platform/apply-overlay.sh revert` restores the previous pages and removes the rules.

## Changes relative to HELK

Everything under `analytics/`. Changed by TechDetechtives, 2026-10-04.

| HELK | TechDetechtives |
| --- | --- |
| Ships its own Elasticsearch, Logstash, Kibana, Nginx, Kafka, KSQL, ElastAlert | Removed. The platform provides collection, storage, alerting and the console. |
| Spark master and worker containers | Removed. Spark runs in local mode in the notebook container; `TD_SPARK_MASTER` can point at an external cluster. |
| Jupyter image based on `cyb3rward0g/jupyter-hunter`, with PostgreSQL and a Hive metastore | Rebuilt on `python:3.11-slim-bookworm` with JupyterLab and PySpark from PyPI. No PostgreSQL or Hive. |
| Reads Elasticsearch through the Spark connector with the `elastic` user | Reads through the Python client with a read-only API key, then hands the data to pandas and Spark (`td_hunt`). |
| Field names from HELK's Logstash pipeline (`process_parent_name`, `user_logon_id`) | ECS field names as stored by the platform. See `docs/FIELD-MAPPING.md`. |
| `demos/read_elasticsearch_via_spark.ipynb` | Reworked as `01_connect_and_explore.ipynb` |
| `demos/basic_event_log_analysis_pandas.ipynb` | Reworked as `02_process_creation_hunt.ipynb`; adds decoding of encoded PowerShell |
| `demos/security_sysmon_sql_join.ipynb` | Reworked as `03_logon_to_process_sql_join.ipynb` |
| `tutorials/06-Intro_pyspark_graphframes_sysmon.ipynb` | Reworked as `04_process_tree_graph.ipynb`; NetworkX instead of GraphFrames |
| Sample data set captured from an attack simulation | Replaced by small synthetic sample data written for this project |
| Sigma notebooks, Kibana dashboards, Logstash pipelines | Not carried over. Detections run on the platform. |

## Test status

As of 0.1.0.

Tested:

- `platform/apply-overlay.sh` apply, re-apply, status, dry-run and revert, against a mock of the Security Onion directory layout (not a live installation).
- `scripts/install.sh analytics` configuration handling and the container entrypoint's token check, with a stand-in for Docker.
- `scripts/fetch-upstream.sh` against GitHub.
- `td_hunt` sample-data loading, flattening, Spark preparation and process-tree functions.
- Every notebook code cell, executed on the sample data with pandas. For the Spark SQL cells, an SQLite stand-in ran the same SQL text.
- `docker compose config` accepts the Compose file. `scripts/verify.sh repo` passes.

Not yet tested:

- Applying the overlay to a live Security Onion, including the Salt state run and rule import.
- `platform/create-readonly-key.sh` (needs a live manager).
- Building the container image, and running Spark and JupyterLab in it. Package versions in `analytics/requirements.txt` are ranges that have not been resolved in a build.
- `td_hunt` against a live Elasticsearch.
- The Suricata and YARA rules have not been run through their engines' syntax checks.

`scripts/verify.sh analytics` runs a self-test inside the container that covers Spark and the platform connection.
