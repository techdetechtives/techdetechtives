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
| Which rules are switched on at import | `/opt/so/saltstack/local/pillar/soc/soc_soc.sls`, settings `enabledSigmaRules` and `autoEnabledYaraRules` | The local Sigma and YARA rulesets are added to the platform's own lists (the same settings as Administration, Configuration in the console). Other settings in the file are kept; the file is rewritten in the platform's own format and the previous copy is backed up. Since 0.5.0; skipped with `--no-auto-enable`. |

Applied by `platform/create-readonly-key.sh`:

| What changes | How |
| --- | --- |
| Elasticsearch API keys | One read-only key named `techdetechtives-analytics-ro` is created (read access to `logs-*` and `so-*`) |
| Firewall | With `--allow-ip`, the analytics host is added to the `elasticsearch_rest` host group (port 9200) |

The platform applies the switch-on setting only the first time it imports a rule. Rules it imported earlier (for example with an overlay older than 0.5.0) stay disabled until enabled once in the console under Detections. `sudo platform/apply-overlay.sh rules` lists each rule's state; it only reads.

**Not changed:** Security Onion's source code, container images, logo, licence notices, licence-key functionality, and Pro features. Both console pages state that the deployment is modified and what it is built on.

Backups are stored under `/nsm/backup/techdetechtives/`. `sudo platform/apply-overlay.sh revert` restores the previous pages, removes the rules, and takes the local rulesets back out of the two settings.

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

Changed 2026-10-05 (0.5.0): Spark's driver is bound to the container's loopback address and its web interface is off; the Compose file passes the platform's address to the container (`extra_hosts`), looked up on the host by the installer.

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

## Honeypot

Added in 0.6.0. OpenCanary 0.9.10 is installed unmodified into a container image at the commit in `upstream.lock`. TechDetechtives supplies its settings file (which decoys are on, their banners, where it logs) and runs it on its own Docker network with a reduced privilege list. The shipper is original work.

On the platform, `platform/create-ingest-key.sh --for honeypot` creates one more API key, `techdetechtives-honeypot-ingest`, which can only append to `logs-opencanary.*`, and with `--allow-ip` adds the honeypot machine to the `elasticsearch_rest` firewall group. Honeypot events are written to the data stream `logs-opencanary.alerts-techdetechtives`; first contacts are tagged `alert`, so they appear on the Alerts page and are ticketed.

## Analyst skills

Added in 0.5.0. `skills/community/` holds documents copied **unchanged** from the community cybersecurity skills library (Apache-2.0; commit in `upstream.lock`): `SKILL.md`, `LICENSE`, `references/` and `assets/` for the 26 skills in `skills/selection.txt`. The upstream `scripts/` folders and translations were left out. Checksums are in `skills/MANIFEST.sha256`. The four skills under `skills/techdetechtives/` are original.

## Test status

As of 0.6.0.

Confirmed on a live system (Security Onion 2.4.211 standalone, with a second VM; 2026-10-04 and 2026-10-05):

- The login banner and overview page, in the browser.
- `platform/create-readonly-key.sh` and `platform/create-ingest-key.sh` created their keys.
- `scripts/install.sh ticketing`: DFIR-IRIS 2.4.29 came up (5 of 5 services) and sign-in worked; the forwarder image built and started.
- `scripts/verify.sh ticketing`: the forwarder connected to the platform (Elasticsearch 9.0.8) with the read-only key and to DFIR-IRIS.

Tested with automated checks or stand-ins:

- `platform/apply-overlay.sh` apply, re-apply, status, rules, dry-run, `--no-auto-enable` and revert, against a mock of the platform's folders (`platform/tests/test_overlay.sh`, 19 checks).
- The rule-settings helper: 8 unit tests, and a run against the real default settings files of Security Onion 2.4.211 and 3.3.0.
- `scripts/install.sh analytics` configuration handling, platform name lookup and the container entrypoint's token check, with a stand-in for Docker. `docker compose config` accepts the Compose files.
- `scripts/fetch-upstream.sh` and `skills/sync-skills.sh` against GitHub; a fresh fetch reproduces `skills/MANIFEST.sha256`.
- `skills/install-skills.sh` install, re-install, skip-existing and remove.
- `platform/detections/validation.yml`: every test id and name was checked against the Atomic Red Team definitions at the pinned commit.
- `td_hunt` sample-data loading, flattening, Spark preparation and process-tree functions.
- Every notebook code cell, executed on the sample data with pandas. For the Spark SQL cells, an SQLite stand-in ran the same SQL text.
- Honeypot: 41 automated tests against a stand-in for the platform and log files in OpenCanary's format, covering alert contents, one alert per address and decoy with repeats stored as plain events, escalation, restarts, ignored addresses, withheld passwords, cleaning of visitor-supplied text, outages, partly delivered batches, a wrong key, an event the platform cannot store, log rotation, late delivery, and the generated settings. The generated settings file passes OpenCanary's own settings check. The installer was run with stand-ins for Docker, and `docker compose config` accepts the files. A honeypot alert was passed through the forwarder's ticket builder.
- `platform/create-ingest-key.sh --for honeypot` with stand-ins for the platform's tools.
- `scripts/install.sh` refusing `analytics`, `ticketing`, `vulnerability` and `honeypot` on a machine that has Security Onion's version file.
- Forwarder: 17 automated tests against local stand-ins for the platform and DFIR-IRIS, covering severity filtering, one ticket per alert, no duplicates across cycles and restarts, late-arriving alerts, outages, rejected alerts, the per-cycle cap, thousands of alerts sharing one timestamp, ticket contents and credentials.
- Vulnerability connector: 33 automated tests against local stand-ins for Greenbone, the platform and DFIR-IRIS, covering report sync, the "currently open" view, platform delivery without duplicates, ticket rules, outages, sign-in, markup and spreadsheet-formula injection from scan text, CSV export, and branding.
- Dashboard and reports pages: rendered with synthetic scan data and checked by eye in light and dark mode and at a narrow width. The severity colours pass an automated check for colour-blind readers.
- `vulnerability/setup-greenbone.sh`: fetching the pinned setup, the generated override (confirmed with `docker compose config` to publish only port 9443), certificate, secrets and re-runs, with a stand-in for Docker.

Not yet tested:

- The rule-enable setting on a live platform: that the console accepts the rewritten settings file and switches newly imported local rules on.
- `platform/apply-overlay.sh rules` against a live detection list (its query was written from the platform's index mapping).
- Any rule firing on a live install. The Sigma rules have not been run through the platform's Sigma conversion, the Suricata and YARA rules have not been through their engines' syntax checks, and none of the tests in `validation.yml` has been run; each entry says `confirmed: "no"`.
- An alert becoming a DFIR-IRIS ticket end to end (the forwarder is connected, but no alert at medium or above had occurred when it was checked).
- Building the workbench container image, and running Spark and JupyterLab in it. Package versions in `analytics/requirements.txt` are ranges that have not been resolved in a build. `td_hunt` has not read from a live Elasticsearch.
- Greenbone has not been started from this setup. The connector has not read from a real Greenbone: its protocol handling was written from the published protocol and tested against a stand-in, so field names in real responses may need adjusting. Its container image has not been built, and findings have not been written to a real platform data stream.
- Greenbone was started from this setup on a live machine on 2026-10-05: all images downloaded, and the first start stopped when one data container (`notus-data`) missed its start-up check. The setup now retries the start (five tries, two minutes apart) and reports the cause when it still fails; a completed start has not been confirmed yet.
- The honeypot has not been started. The OpenCanary image has not been built, and OpenCanary has not been run under the reduced privilege list in `honeypot/docker-compose.yml`. Whether alerts show the visitor's real address depends on Docker's networking on the machine. The platform has not yet been asked to create the honeypot data stream or to show its alerts.
- The skills have not been tried with an assistant on a live deployment. The community skills are included as their authors wrote them; see `skills/README.md` for their limits.

`scripts/verify.sh analytics` runs a self-test inside the container that covers Spark and the platform connection.
