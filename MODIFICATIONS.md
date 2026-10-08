# Modifications

This file is the prominent notice of modification required by the upstream licences. Update it whenever the overlay or the analytics layer changes.

## Changes to an installed Security Onion

Applied by `platform/apply-overlay.sh` on the manager node. First applied in version 0.1.0, 2026-10-04.

| What changes | Where on the platform | How |
| --- | --- | --- |
| Login banner | `/opt/so/saltstack/local/salt/soc/files/soc/banner.md` | Replaced with the TechDetechtives banner. Previous file backed up. |
| Console overview page | `/opt/so/saltstack/local/salt/soc/files/soc/motd.md` | Replaced with the TechDetechtives overview, which shows the TechDetechtives emblem (an image loaded from this repository on GitHub, or from an address you choose). Previous file backed up. |
| Sigma rules | `/nsm/rules/custom-local-repos/local-sigma` | 24 rule files added and committed (16 for endpoint threats, 3 for industrial protocols, 5 for layer 2 notices) |
| Suricata rules | `/nsm/rules/custom-local-repos/local-suricata` | 3 rule files added and committed: 2 general rules (SIDs 1900001 and 1900002), 40 industrial-protocol rules (SIDs 1900101 to 1900186) and 17 flood rules (SIDs 1900301 to 1900325) |
| YARA rules | `/nsm/rules/custom-local-repos/local-yara` | 3 rule files (12 rules) added and committed |
| Which rules are switched on at import | `/opt/so/saltstack/local/pillar/soc/soc_soc.sls`, settings `enabledSigmaRules` and `autoEnabledYaraRules` | The local Sigma and YARA rulesets are added to the platform's own lists (the same settings as Administration, Configuration in the console). Other settings in the file are kept; the file is rewritten in the platform's own format and the previous copy is backed up. Since 0.5.0; skipped with `--no-auto-enable`. |

Applied by `platform/apply-overlay.sh layer2 on`, and only then (since 0.8.0):

| What changes | Where on the platform | How |
| --- | --- | --- |
| A custom Zeek script | `/opt/so/saltstack/local/salt/zeek/policy/custom/techdetechtives/` (the folder Security Onion provides for custom Zeek scripts) | `l2-watch.zeek` and its loader are copied there, and removed again by `layer2 off` and `revert`. The plain `apply` step does not touch this folder, because the platform restarts Zeek whenever it changes. Written for this project; no upstream code. |
| The list of scripts Zeek loads | `/opt/so/saltstack/local/pillar/zeek/soc_zeek.sls`, setting `zeek.config.local.load` | The list in effect is written with `custom/techdetechtives` added (the same setting as Administration, Configuration, zeek in the console). A local value replaces Security Onion's whole default list, so later changes to that default do not arrive while the watch is on. `layer2 off` and `revert` take the entry out and remove the local value when nothing else differs from the default, also when a platform upgrade changed that default in the meantime (the list it started from is remembered in `/nsm/backup/techdetechtives/settings/zeek_load.state`). The previous file is backed up. |
| Zeek | | Restarted by the platform's own Zeek state so that it loads the script. Before any of this, the running Zeek is asked to read the script without running it (`zeek -a`); if it cannot, nothing is changed. Afterwards the command waits for Zeek to be running again and, if it is not within three minutes, switches the watch off and applies the Zeek state once more. |

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

Changed 2026-10-05 (0.9.0, connector 0.4.1): the dashboard no longer lets one visitor who connects and then says nothing hold up everyone else (the TLS handshake now happens in each connection's own thread, with a 30-second limit), and a malformed sign-in header is answered with a refusal instead of an error. Found while reviewing the same code in the network inventory.

## Honeypot

Added in 0.6.0. OpenCanary 0.9.10 is installed unmodified into a container image at the commit in `upstream.lock`. TechDetechtives supplies its settings file (which decoys are on, their banners, where it logs) and runs it on its own Docker network with a reduced privilege list. The shipper is original work.

On the platform, `platform/create-ingest-key.sh --for honeypot` creates one more API key, `techdetechtives-honeypot-ingest`, which can only append to `logs-opencanary.*`, and with `--allow-ip` adds the honeypot machine to the `elasticsearch_rest` firewall group. Honeypot events are written to the data stream `logs-opencanary.alerts-techdetechtives`; first contacts are tagged `alert`, so they appear on the Alerts page and are ticketed.

## Analyst skills

Added in 0.5.0. `skills/community/` holds documents copied **unchanged** from the community cybersecurity skills library (Apache-2.0; commit in `upstream.lock`): `SKILL.md`, `LICENSE`, `references/` and `assets/` for the 26 skills in `skills/selection.txt`. The upstream `scripts/` folders and translations were left out. Checksums are in `skills/MANIFEST.sha256`. The four skills under `skills/techdetechtives/` are original.

## Network inventory

Added in 0.9.0, 2026-10-05. Original work under `network/`; no upstream code. It reads the platform with the existing read-only key and changes nothing there. The one optional addition on the platform is made by `platform/create-ingest-key.sh --for network`: an API key named `techdetechtives-network-ingest` that can only append to `logs-netmap.*`, through which this part's "change since the baseline" alerts arrive in the data stream `logs-netmap.alerts-techdetechtives`.

Changed 2026-10-08 (0.10.0, network inventory 0.2.0): published advisories. The inventory downloads JPCERT/CC's, JVN's and JVN iPedia's feeds, CISA's ICS advisories (CSAF documents listed by CISA's ROLIE feed) and CISA's catalogue of known exploited vulnerabilities, or reads advisory files from `network/advisories/`, and matches them against the CVEs in Greenbone findings on the platform (read with the existing read-only key), the vendor and model devices announce, and a list of the site's products (`TD_ADV_WATCH`). Matches become changes, and so alerts and tickets, through the same data stream. Nothing new is added on the platform. The test fixtures under `network/tests/advisories/` are three of CISA's CSAF advisories and a trimmed copy of its feed, unchanged (public domain, from github.com/cisagov/CSAF).

## Test status

As of 0.10.0.

Confirmed on a live system (Security Onion 2.4.211 standalone, with a second VM; 2026-10-04 and 2026-10-05):

- The login banner and overview page, in the browser.
- `platform/create-readonly-key.sh` and `platform/create-ingest-key.sh` created their keys.
- `scripts/install.sh ticketing`: DFIR-IRIS 2.4.29 came up (5 of 5 services) and sign-in worked; the forwarder image built and started.
- `scripts/verify.sh ticketing`: the forwarder connected to the platform (Elasticsearch 9.0.8) with the read-only key and to DFIR-IRIS.

Tested with automated checks or stand-ins:

- `platform/apply-overlay.sh` apply, re-apply, status, rules, dry-run, `--no-auto-enable`, revert, and `layer2` on, off and status, against a mock of the platform's folders (`platform/tests/test_overlay.sh`, 43 checks). The `layer2` checks cover its refusals, unreadable settings (no script left behind), a Zeek that does not come back (watch switched off again, state re-applied), the status check, and a platform upgrade that changes the default list while the watch is on.
- The helper that edits the list of scripts Zeek loads: 9 unit tests, and `layer2 on`, `status` and `off` run against the real default Zeek settings file of Security Onion 2.4.211 with Zeek 7.0.11 as the checker. The script was also passed through the template step the platform applies to custom Zeek scripts and came out unchanged.
- The layer 2 watch (`platform/tests/test_l2_watch.py`): the script was run by Zeek 7.0.11, built from source for this purpose, against captures generated for the test: ordinary ARP traffic for 40 minutes (no notices), ARP poisoning, an address replaced while in use and after a quiet spell, a flood of 2,000 made-up card addresses, an ARP sweep, one card claiming a segment, a software-set card address after the learning time, address probes, the ignore lists, and 3,000 forged machines against lists limited to 50 entries (poisoning afterwards is still recognised, and an ordinary new machine is not taken for a flood). Each of the 12 scenes produced exactly the notices expected, and deliberately broken copies of the script failed them. Skipped where `zeek` is not installed.
- The rule-settings helper: 8 unit tests, and a run against the real default settings files of Security Onion 2.4.211 and 3.3.0.
- `scripts/install.sh analytics` configuration handling, platform name lookup and the container entrypoint's token check, with a stand-in for Docker. `docker compose config` accepts the Compose files.
- `scripts/fetch-upstream.sh` and `skills/sync-skills.sh` against GitHub; a fresh fetch reproduces `skills/MANIFEST.sha256`.
- `skills/install-skills.sh` install, re-install, skip-existing and remove.
- `platform/detections/validation.yml`: every test id and name was checked against the Atomic Red Team definitions at the pinned commit.
- Detection rules (`platform/tests/test_detection_rules.py`): every Sigma rule evaluated against sample events that must and must not match; Suricata rules checked for structure, their threshold and flag options against the patterns in the Suricata 7.0.11 source, that "outside" is never written as `$EXTERNAL_NET` (which is "any" on the platform), that every flood rule counts packets and not conversations, and the S7, IEC 104 and Honeywell byte patterns against sample requests; YARA rules compiled and run against generated sample files with YARA 4.5.2 (that part is skipped where `yara` is not installed).
- Every Sigma rule was converted with the platform's own conversion command line and pipeline files (Security Onion 2.4.211), using the Sigma library from source, and the resulting queries were read.
- `td_hunt` sample-data loading, flattening, Spark preparation and process-tree functions.
- Every notebook code cell, executed on the sample data with pandas. For the Spark SQL cells, an SQLite stand-in ran the same SQL text.
- Honeypot: 41 automated tests against a stand-in for the platform and log files in OpenCanary's format, covering alert contents, one alert per address and decoy with repeats stored as plain events, escalation, restarts, ignored addresses, withheld passwords, cleaning of visitor-supplied text, outages, partly delivered batches, a wrong key, an event the platform cannot store, log rotation, late delivery, and the generated settings. The generated settings file passes OpenCanary's own settings check. The installer was run with stand-ins for Docker, and `docker compose config` accepts the files. A honeypot alert was passed through the forwarder's ticket builder.
- `platform/create-ingest-key.sh --for honeypot` with stand-ins for the platform's tools.
- `scripts/install.sh` refusing `analytics`, `ticketing`, `vulnerability` and `honeypot` on a machine that has Security Onion's version file.
- Network inventory: 56 automated tests against a stand-in for the platform that answers the same grouped queries over HTTP, with records shaped like Security Onion's Zeek records. They cover building the inventory, totals counted once across passes, sessions written long after they began, protocols with and without named operations, roles, what devices announce about themselves, the learning time (which starts with the first data), each kind of change and its severity, one change per pair of devices however many ports, the cap on changes per pass, accepting a new baseline, an unreachable platform and a failure part-way (nothing half-written), an answer built from only part of the data (refused), more groups than one read carries (read again in smaller windows, nothing counted twice), records that arrive after their time was read (noticed and said), attempts that get no answer (no devices invented), a field the platform cannot group on, delivery of changes as alerts (once, also after a retry, kept when the key may not write, stamped with the delivery time when late), the sign-in, every page, escaping of host names taken from the network, a malformed sign-in header, a visitor who connects and says nothing (others are still served), the CSV export, and the settings. Deliberately broken copies of the code failed the tests. Every field name it reads was checked against the ingest settings of Security Onion 2.4.211, and the operation names it treats as control commands against the protocol analyzers' source.
- Published advisories (network inventory 0.2.0): 20 automated tests, with no feed fetched from the internet. CISA's formats were checked against real files taken from CISA's repositories on 2026-10-08 (the full catalogue of 1,739 exploited vulnerabilities and the full feed of 3,957 ICS advisories read in under a second; three Honeywell advisories, including ICSA-21-278-04 for C300 controllers, read and matched). JVN's security extension was checked against the structure of the live JVN iPedia feed as described by its publisher's page, not against a downloaded copy: this sandbox could not reach jpcert.or.jp, jvn.jp or cisa.gov directly. The tests cover each format, refusal of XML with entities, version ranges (including ones written too differently to compare), matching by scan finding, by announced model and by the list, one change per device or listed product, "not affected" versions raising nothing, a listing that points at another host (not followed), a feed that fails (others still read, retried after half an hour), unchanged feeds (not downloaded again), documents fetched by recency and by vendors seen here with a limit per pass, the import folder, and escaping of advisory text on the pages.
- Network inventory pages: rendered with a simulated plant (35 devices, eight industrial protocols, a rogue station) and checked by eye in light and dark mode and at a narrow width. The two chart colours pass the automated palette check, colour-blind checks included.
- `scripts/install.sh network`, `network --accept`, `network-down` and `network/setup-network.sh` with a stand-in for Docker; `docker compose config` accepts the file; `platform/create-ingest-key.sh --for network` with stand-ins for the platform's tools.
- Forwarder: 17 automated tests against local stand-ins for the platform and DFIR-IRIS, covering severity filtering, one ticket per alert, no duplicates across cycles and restarts, late-arriving alerts, outages, rejected alerts, the per-cycle cap, thousands of alerts sharing one timestamp, ticket contents and credentials.
- Vulnerability connector: 33 automated tests against local stand-ins for Greenbone, the platform and DFIR-IRIS, covering report sync, the "currently open" view, platform delivery without duplicates, ticket rules, outages, sign-in, markup and spreadsheet-formula injection from scan text, CSV export, and branding.
- Dashboard and reports pages: rendered with synthetic scan data and checked by eye in light and dark mode and at a narrow width. The severity colours pass an automated check for colour-blind readers.
- `vulnerability/setup-greenbone.sh`: fetching the pinned setup, the generated override (confirmed with `docker compose config` to publish only port 9443), certificate, secrets and re-runs, with a stand-in for Docker.

Not yet tested:

- The rule-enable setting on a live platform: that the console accepts the rewritten settings file and switches newly imported local rules on.
- `platform/apply-overlay.sh rules` against a live detection list (its query was written from the platform's index mapping).
- Any rule firing on a live install. The Suricata rules have not been loaded into Suricata (no copy of it was available to check them), the YARA rules have not been loaded by the platform's file scanner, and none of the tests in `validation.yml` has been run; each entry says `confirmed: "no"`. The field names used by the three industrial Sigma rules come from the platform's ingest settings and the protocol analyzers' source, not from live records.
- The flood rules and the Honeywell Experion rules, beyond the checks above. Their figures are judgement, not measurement, and the Honeywell rules have never seen real Experion traffic.
- `layer2 on` on a live platform: the read check through `docker exec so-zeek`, the settings file being accepted, Zeek restarting with the script loaded, and a notice reaching the platform and becoming an alert through its Sigma rule. The Zeek version on Security Onion 2.4.211 may differ from the 7.0.11 the script was tried with; the read check is there for that. Behaviour with several Zeek worker processes is unknown.
- No advisory feed has been fetched live by the inventory. Whether the ticketing machine can reach the five addresses (or needs `TD_ADV_PROXY`) is the first thing `scripts/verify.sh network` will show.
- The network inventory has not read from a live platform. Its container image has not been built. How long records take to travel from the sensor to the platform (the inventory waits five minutes by default and says when that was not enough), whether every field can be grouped on as the ingest settings suggest, how the queries perform on a busy platform, and whether the platform creates the alert data stream are all unknown. It was run with a few thousand groups, not hundreds of thousands.
- An alert becoming a DFIR-IRIS ticket end to end (the forwarder is connected, but no alert at medium or above had occurred when it was checked).
- Building the workbench container image, and running Spark and JupyterLab in it. Package versions in `analytics/requirements.txt` are ranges that have not been resolved in a build. `td_hunt` has not read from a live Elasticsearch.
- Greenbone has not been started from this setup. The connector has not read from a real Greenbone: its protocol handling was written from the published protocol and tested against a stand-in, so field names in real responses may need adjusting. Its container image has not been built, and findings have not been written to a real platform data stream.
- Greenbone was started from this setup on a live machine on 2026-10-05: all images downloaded, and the first start stopped when one data container (`notus-data`) missed its start-up check. The setup now retries the start (five tries, two minutes apart) and reports the cause when it still fails; a completed start has not been confirmed yet.
- The honeypot has not been started. The OpenCanary image has not been built, and OpenCanary has not been run under the reduced privilege list in `honeypot/docker-compose.yml`. Whether alerts show the visitor's real address depends on Docker's networking on the machine. The platform has not yet been asked to create the honeypot data stream or to show its alerts.
- The skills have not been tried with an assistant on a live deployment. The community skills are included as their authors wrote them; see `skills/README.md` for their limits.

`scripts/verify.sh analytics` runs a self-test inside the container that covers Spark and the platform connection.
