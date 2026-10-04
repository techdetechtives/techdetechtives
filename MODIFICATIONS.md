# Modifications

This file is the prominent notice of modification required by the upstream licences. Update it whenever the overlay or the analytics layer changes.

## Changes to an installed Security Onion

Applied by `platform/apply-overlay.sh` on the manager node. First applied in version 0.1.0, 2026-10-04.

| What changes | Where on the platform | How |
| --- | --- | --- |
| Login banner | `/opt/so/saltstack/local/salt/soc/files/soc/banner.md` | Replaced with the TechDetechtives banner. Previous file backed up. |
| Console overview page | `/opt/so/saltstack/local/salt/soc/files/soc/motd.md` | Replaced with the TechDetechtives overview, which shows the TechDetechtives emblem (an image loaded from this repository on GitHub, or from an address you choose). Previous file backed up. |
| Sigma rules | `/nsm/rules/custom-local-repos/local-sigma` | 4 rule files added and committed |
| Suricata rules | `/nsm/rules/custom-local-repos/local-suricata` | 1 rule file (2 rules, SIDs 1900001 and 1900002) added and committed |
| YARA rules | `/nsm/rules/custom-local-repos/local-yara` | 1 rule file added and committed |

Applied by `platform/create-readonly-key.sh`:

| What changes | How |
| --- | --- |
| Elasticsearch API keys | One read-only key named `techdetechtives-analytics-ro` is created (read access to `logs-*` and `so-*`) |
| Firewall | With `--allow-ip`, the analytics host is added to the `elasticsearch_rest` host group (port 9200) |

Rules from the local repositories are imported **disabled**. Enable them in the console under Detections after the first import.

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

## Ticketing

Added in version 0.2.0, 2026-10-04. Original work; nothing here modifies Security Onion or DFIR-IRIS code.

| What | How |
| --- | --- |
| DFIR-IRIS | Installed unmodified at the version in `upstream.lock`. Configuration supplied: generated database passwords and application secrets, an administrator password and API key, host name, port 8443, and a TLS certificate generated on the host in place of the shipped development certificate. |
| Platform | No change. The forwarder reads alerts with the existing read-only key. |

## Vulnerability scanning

Added in version 0.3.0, 2026-10-04. Original work; nothing here modifies Security Onion, DFIR-IRIS or Greenbone code.

| What | How |
| --- | --- |
| Greenbone Community Edition | Installed unmodified from its official container setup at the version in `upstream.lock`. A generated override publishes only its HTTPS interface, on port 9443, and sets its host name. The default `admin` / `admin` sign-in is replaced with a generated password. |
| Platform | One API key named `techdetechtives-vulnerability-ingest` is created by `platform/create-ingest-key.sh`. It can only append to the `logs-greenbone.results-*` data stream, which the connector fills with scan findings. The overview page gains links to the ticketing and vulnerability pages. |
| DFIR-IRIS | No change. The connector opens tickets through its API. |

## Test status

As of 0.4.0.

Tested:

- `platform/apply-overlay.sh` apply, re-apply, status, dry-run and revert, against a mock of the Security Onion directory layout.
- `scripts/install.sh analytics` configuration handling and the container entrypoint's token check, with a stand-in for Docker.
- `scripts/fetch-upstream.sh` against GitHub.
- `td_hunt` sample-data loading, flattening, Spark preparation and process-tree functions.
- Every notebook code cell, executed on the sample data with pandas. For the Spark SQL cells, an SQLite stand-in ran the same SQL text.
- `docker compose config` accepts the Compose file. `scripts/verify.sh repo` passes.

- Applied to a live Security Onion 2.4.211 standalone install (2026-10-04): the login banner and overview page were confirmed in the browser. Rule import and rule matching on that install are not yet confirmed.

- Forwarder: 17 automated tests against local stand-ins for the platform and DFIR-IRIS, covering severity filtering, one ticket per alert, no duplicates across cycles and restarts, late-arriving alerts, outages, rejected alerts, the per-cycle cap, thousands of alerts sharing one timestamp, ticket contents and credentials.
- `ticketing/setup-iris.sh`: fetching DFIR-IRIS 2.4.29, secret generation, re-run behaviour and the TLS certificate, with a stand-in for Docker. The forwarder was confirmed to trust that certificate and to refuse others.
- Vulnerability connector: 33 automated tests against local stand-ins for Greenbone, the platform and DFIR-IRIS, covering report sync, the "currently open" view, platform delivery without duplicates, ticket rules, outages, sign-in, markup and spreadsheet-formula injection from scan text, CSV export, and branding (custom name, colours and logo, with safe fallbacks).
- Dashboard and reports pages: rendered with synthetic scan data and checked by eye in light and dark mode and at a narrow width. The severity colours pass an automated check for colour-blind readers.
- `vulnerability/setup-greenbone.sh`: fetching the pinned setup, the generated override (confirmed with `docker compose config` to publish only port 9443), certificate, secrets and re-runs, with a stand-in for Docker.

Not yet tested:

- Rule import and matching on a live install; the Sigma rules have not been run through the platform's Sigma conversion.
- `platform/create-readonly-key.sh` (needs a live manager).
- Building the container image, and running Spark and JupyterLab in it. Package versions in `analytics/requirements.txt` are ranges that have not been resolved in a build.
- `td_hunt` against a live Elasticsearch.
- DFIR-IRIS has not been started from this setup, and the forwarder has not posted to a real DFIR-IRIS or read from a real platform. The alert fields and API calls were written from the Security Onion 2.4.211 and DFIR-IRIS 2.4.29 source code.
- The forwarder container image has not been built.
- Greenbone has not been started from this setup. The connector has not read from a real Greenbone: its protocol handling was written from the published protocol and tested against a stand-in, so field names in real responses may need adjusting.
- `platform/create-ingest-key.sh`, and writing findings to a real platform data stream.
- The vulnerability connector container image has not been built.
- The Suricata and YARA rules have not been run through their engines' syntax checks.

`scripts/verify.sh analytics` runs a self-test inside the container that covers Spark and the platform connection.
