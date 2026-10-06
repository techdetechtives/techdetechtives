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

## OT IDS

Added in 0.10.0, 2026-10-06, under `ot-ids/`. It does not touch the Security Onion platform or any other part of this repository; it reads `platform/detections/suricata/` and `platform/detections/yara/` and `branding/`.

Changes `ot-ids/build-iso.sh` makes to its build-time copy of Malcolm 26.09.0 (nothing is changed upstream, and the copy is not stored here):

- **Boot menu:** `malcolm-iso/build.sh` is given a product label, so the title and the install entries read "TechDetechtives" and "TechDetechtives Sensor". The boot splash images and the desktop wallpaper are replaced.
- **Web pages:** the logo, icon and banner image files are replaced by TechDetechtives ones of the same names and sizes. The landing page title, the error page heading and the dashboards title are renamed. The landing page footer gains "TechDetechtives, built on" in front of Malcolm's own version and copyright line, which stay.
- **Container images:** seven of Malcolm's published images (`nginx-proxy`, `dashboards`, `file-upload`, `htadmin`, `filescan`, `dashboards-helper`, and since 0.13.0 `suricata`) each get one added layer holding those image and text files, three anomaly detectors and four alert monitors, and are stored under their original names so Malcolm's own configuration finds them. No program code in any image is changed.
- **Detection content** placed in the installed system's `~/Malcolm` folders, which Malcolm provides for the purpose: Suricata rules (the shared sets and `ot-ids/detections/suricata/`), YARA rules, Zeek intelligence files, and the converted external rule sets. The layer 2 watch (`platform/zeek/techdetechtives/`, unchanged) is placed in `~/Malcolm/zeek/custom/` only if Malcolm's own Zeek parses it without error during the build.
- **Operating system:** added files under `/etc/sysctl.d`, `/etc/modprobe.d`, `/etc/profile.d`, a login banner, four lines appended to Malcolm's `sshd_config`, and two scripts in `/usr/local/bin` (`td-hardening-check`, `td-apply-update`). Malcolm's own hardening is left as it is.

Arkime's and NetBox's own screens, Malcolm's user guide, its setup scripts and its operating-system variant name are not changed.

**MITRE ATT&CK for ICS, added in 0.11.0, 2026-10-06.** No file of Malcolm's is changed for it. The copies of the Suricata rules placed in `~/Malcolm/suricata/rules/` (TechDetechtives' own and the imported sets) get metadata naming each rule's ATT&CK for ICS tactic and technique, in the keys Malcolm's own pipeline already reads; the rule files in this repository, which the Security Onion platform also uses, are not changed. A coverage report, a layer file for ATT&CK Navigator and a technique reference are placed in `~/Malcolm/attack-ics/`, and one more alert monitor (switched off, like the others) is added to the `dashboards-helper` layer. The mapping tables and the reference list are in `ot-ids/attack/`; the reference reproduces parts of MITRE ATT&CK (see `NOTICE.md`, section 8).

**Baseline program, added in 0.12.0, 2026-10-06.** No file of Malcolm's is changed for it. One Python file (`ot-ids/baseline/td_baseline.py`) is copied into the added layer of the `dashboards-helper` image, and one line is appended to that container's own crontab so it runs every 15 minutes. It reads industrial protocol records from OpenSearch with the reader's credentials the container already has, keeps its list on the container's existing `/data/init` volume, and sends findings to Malcolm's own alert webhook (`/mapi/alert`), which is the documented way to add alerts. Its alerts are off until an operator runs `td-baseline alerts on`. A host command `td-baseline` is added to `/usr/local/bin`. Sixteen outside projects were read first (`ot-ids/docs/ANOMALY-DETECTION-REVIEW.md`); no code was taken from any, and the ideas that were are credited there and in the program.

**Added and corrected in 0.13.0, 2026-10-07**, after reading nineteen listed projects (`ot-ids/docs/LISTED-REPOSITORIES-REVIEW.md`; no code was taken from any). Changes to the build-time copy of Malcolm and to what is placed on the installed system:

- **One line is appended to Malcolm's `config/suricata.env.example`:** `SURICATA_STREAM_REASSEMBLY_DEPTH=0`. Malcolm's value is 1 MB, after which Suricata's Modbus, DNP3 and EtherNet/IP decoders see no more of a connection. `SURICATA_STREAM_DEPTH` in `ot-ids/build.conf` changes or removes the line.
- **The `suricata` image gets an added layer** that copies in one script and runs it once over the image's rule file (`/var/lib/suricata/rules/suricata.rules`): it removes the comment mark from Suricata's own Modbus and DNP3 event rules and appends its EtherNet/IP event rules from Suricata's own rule files in the image. No other rule is touched and no program is changed. `SURICATA_PROTOCOL_EVENTS="false"` leaves the image as published.
- **Two files are placed in `~/Malcolm/suricata/include-configs/`**, the folder Malcolm provides for extra Suricata configuration: one names a threshold file, the other is that file, holding only commented examples.
- **YARA rule files from eight of the nine repositories Malcolm's own file-scanner image is built with** are fetched when an ISO or update is built and placed in `~/Malcolm/yara/rules/`, one folder per source, each with its licence file (`ot-ids/sources.conf`; none is stored in this repository). The ninth (CAPE Sandbox, GPL-3.0) and Yara-Rules/rules (GPL-2.0, filtered) are listed and switched off. Until this version the TechDetechtives YARA rules placed in that folder took the place of Malcolm's compiled rule set on an installed system with no Internet access, instead of adding to it; that was a fault of this kit, not of Malcolm.
- **`dashboards-helper` layer:** one more Python file (`ot-ids/baseline/td_profile.py`, a report run by hand) and one more alert monitor, switched off. A host command `td-profile` is added to `/usr/local/bin`.

**Corrected in 0.13.0:** Suricata rules 1900103 (in `platform/detections/suricata/techdetechtives-ot.rules`, which the Security Onion overlay installs too), 1900406 and 1900451 used `modbus: function 43, subfunction 14`. Suricata compares `subfunction` for function 8 only, so the three rules loaded and never fired. They now match the request's bytes on port 502 and are revision 2; on Security Onion the corrected rule arrives with the next `platform/apply-overlay.sh`. The shared YARA rule `TechDetechtives_PowerShell_Download_And_Run` no longer fires on a script that downloads an `.msi` and starts the installer.

**Corrected in 0.11.0:** rules 1900503 and 1900504 in `ot-ids/detections/suricata/techdetechtives-ot-control-extra.rules` (Schneider UMAS program download and read-out) had their function numbers exchanged in 0.10.0: 0x30 writes a program to the controller and 0x33 reads it out, not the reverse. Both are now revision 2, and the test that checks them uses the corrected numbers.

`ot-ids/docs/AI-NIDS-REVIEW.md` and `ot-ids/docs/PROJECT-REVIEWS.md` record six more outside projects that were reviewed. One was adopted, as an external source: Aleksi Bovellan's Nmap scan detection rules (8 of 10 rules, thresholds changed to one alert per window). The others were not, with reasons.

## Test status

As of 0.13.0.

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
- Detection rules (`platform/tests/test_detection_rules.py`): every Sigma rule evaluated against sample events that must and must not match; Suricata rules checked for structure, their threshold and flag options against the patterns in the Suricata 7.0.11 source, that "outside" is never written as `$EXTERNAL_NET` (which is "any" on the platform), that every flood rule counts packets and not conversations, that no rule writes the Modbus `subfunction` option with a function other than 8, and the S7, IEC 104, Honeywell and Modbus byte patterns against sample requests; YARA rules compiled and run against generated sample files with YARA 4.5.2 (that part is skipped where `yara` is not installed).
- Every Sigma rule was converted with the platform's own conversion command line and pipeline files (Security Onion 2.4.211), using the Sigma library from source, and the resulting queries were read.
- `td_hunt` sample-data loading, flattening, Spark preparation and process-tree functions.
- Every notebook code cell, executed on the sample data with pandas. For the Spark SQL cells, an SQLite stand-in ran the same SQL text.
- Honeypot: 41 automated tests against a stand-in for the platform and log files in OpenCanary's format, covering alert contents, one alert per address and decoy with repeats stored as plain events, escalation, restarts, ignored addresses, withheld passwords, cleaning of visitor-supplied text, outages, partly delivered batches, a wrong key, an event the platform cannot store, log rotation, late delivery, and the generated settings. The generated settings file passes OpenCanary's own settings check. The installer was run with stand-ins for Docker, and `docker compose config` accepts the files. A honeypot alert was passed through the forwarder's ticket builder.
- `platform/create-ingest-key.sh --for honeypot` with stand-ins for the platform's tools.
- `scripts/install.sh` refusing `analytics`, `ticketing`, `vulnerability` and `honeypot` on a machine that has Security Onion's version file.
- Network inventory: 56 automated tests against a stand-in for the platform that answers the same grouped queries over HTTP, with records shaped like Security Onion's Zeek records. They cover building the inventory, totals counted once across passes, sessions written long after they began, protocols with and without named operations, roles, what devices announce about themselves, the learning time (which starts with the first data), each kind of change and its severity, one change per pair of devices however many ports, the cap on changes per pass, accepting a new baseline, an unreachable platform and a failure part-way (nothing half-written), an answer built from only part of the data (refused), more groups than one read carries (read again in smaller windows, nothing counted twice), records that arrive after their time was read (noticed and said), attempts that get no answer (no devices invented), a field the platform cannot group on, delivery of changes as alerts (once, also after a retry, kept when the key may not write, stamped with the delivery time when late), the sign-in, every page, escaping of host names taken from the network, a malformed sign-in header, a visitor who connects and says nothing (others are still served), the CSV export, and the settings. Deliberately broken copies of the code failed the tests. Every field name it reads was checked against the ingest settings of Security Onion 2.4.211, and the operation names it treats as control commands against the protocol analyzers' source.
- Network inventory pages: rendered with a simulated plant (35 devices, eight industrial protocols, a rogue station) and checked by eye in light and dark mode and at a narrow width. The two chart colours pass the automated palette check, colour-blind checks included.
- `scripts/install.sh network`, `network --accept`, `network-down` and `network/setup-network.sh` with a stand-in for Docker; `docker compose config` accepts the file; `platform/create-ingest-key.sh --for network` with stand-ins for the platform's tools.
- Forwarder: 17 automated tests against local stand-ins for the platform and DFIR-IRIS, covering severity filtering, one ticket per alert, no duplicates across cycles and restarts, late-arriving alerts, outages, rejected alerts, the per-cycle cap, thousands of alerts sharing one timestamp, ticket contents and credentials.
- Vulnerability connector: 33 automated tests against local stand-ins for Greenbone, the platform and DFIR-IRIS, covering report sync, the "currently open" view, platform delivery without duplicates, ticket rules, outages, sign-in, markup and spreadsheet-formula injection from scan text, CSV export, and branding.
- Dashboard and reports pages: rendered with synthetic scan data and checked by eye in light and dark mode and at a narrow width. The severity colours pass an automated check for colour-blind readers.
- `vulnerability/setup-greenbone.sh`: fetching the pinned setup, the generated override (confirmed with `docker compose config` to publish only port 9443), certificate, secrets and re-runs, with a stand-in for Docker.

- The OT IDS additions of 0.13.0 (part of the 152 tests below). The three rewritten Modbus rules against requests that must and must not match. The YARA sources: all ten were fetched from GitHub for real; Malcolm's own start-up script (`strelka/backend/yara_rules_setup.sh`, unchanged apart from one temporary-file path) was then run over the kit's rules and the eight default sources with YARA 4.5.8 and compiled 3,155 of 3,173 files into 10,656 rules in about a minute, with no hit on 7,407 ordinary files of a Linux machine; the same script run over the kit's four rule files alone replaced a stand-in compiled set with 21 rules, which is the fault being corrected. The namespace the kit computes for each file agreed with the script's for every file. The traffic profile (28 tests) against a stand-in for OpenSearch that answers its one search from connection records held in memory, including connections that began before the period and ones still open. The Snort 3 conversions, with the table of 67 IEC 104 type names compared with Snort 3's source. The protocol-event tool on stand-in rule files and on Suricata 8.0's own rule files (18 of 18 added to an empty file). `prepare`, `sources` and `images` were run again against the real Malcolm source, the real sources, and the stand-in for Docker. An independent reviewer then made eleven findings against these additions, among them that a single failed download would still have replaced the product's YARA rules with a part of them and that the traffic profile could not see a connection begun before its period; all are corrected, and listed in `ot-ids/docs/LISTED-REPOSITORIES-REVIEW.md`.

- The OT IDS (`ot-ids/tests`, 152 tests): the structure and reserved numbers of its 38 Suricata rules, that every flag a correlation alert waits for is set by a marker rule, its byte-position rules against sample UMAS, S7, IEC 104, Modbus, BACnet and TFTP packets with look-alikes that must not match, its nine YARA rules compiled and run by YARA 4.5.8 against generated samples, and its tools. The Snort converter was run on the real ELITEWOLF and Quickdraw rule sets (110 of 110 converted) and the Nmap rule set (8 imported, 2 left out on purpose). The step that adds the layer 2 watch was run with a stand-in for Zeek that accepts it and then refuses it; the script is added only in the first case and removed again in the second. `build-iso.sh prepare` and `sources` were run against the real Malcolm 26.09.0 source and the three GitHub-hosted sources; the offline update was built and applied to a mock product folder, including a tampered archive; the `images` stage was run against a stand-in for Docker that checks each added layer's files and destinations. For ATT&CK for ICS: every Suricata rule in the repository has a row in the mapping, every technique and tactic named exists in the reference built from MITRE's data file (ATT&CK for ICS 19.2), tagging adds only the technique to a rule and does it once, the coverage files in `ot-ids/docs/` match what the tool writes, and tagging and the report were run on the real imported rule sets (177 rules given a technique, 38 reviewed and left without one, none left unreviewed); a second reviewer then checked every mapping row against MITRE's descriptions and the rule bodies, and its findings were applied. The baseline program has 54 of those tests, run against a stand-in for the product that answers its one OpenSearch search and takes alerts as the webhook does; an independent review demonstrated fifteen defects in its first version, all fixed and each with a test, and checked its search and its installation against the source of OpenSearch 3.8 and of Malcolm.

Not yet tested:
- The OT IDS additions of 0.13.0 have not been run in the product. Not seen: Suricata loading the three rewritten rules; Suricata running with stream depth 0 (the setting was followed through Malcolm's configuration script and Suricata's source, not watched); the layer on the Suricata image being built, or what the image's rule file really holds (that Suricata's Modbus and DNP3 event rules are commented out there was worked out from three sources, and the layer's change is kept only by Docker's BuildKit, the default since Docker 23; the build reads the file back and reports); Suricata reading the threshold file; the product's file scanner compiling the fetched YARA rules (its YARA is 4.5.5 with two more modules than the 4.5.8 used here, so counts will differ a little; the build runs the product's own script in its own image and reports); the traffic profile reading from a real OpenSearch (its field names and their meanings were read from Malcolm's pipeline and from the long-connections script Malcolm uses); the DNP3 monitor being imported. The count of ordinary files hit is a rough measure from one Linux machine with few Windows programs and Office documents on it.

- The OT IDS has not been built into an ISO, installed or run. None of its rules has been loaded by Suricata or seen plant traffic; the build's `images` stage loads them in the product's own Suricata and writes `out/rule-check.txt`. The layer 2 watch has not been parsed by the Zeek 8.2.2 that Malcolm ships (it was tested with 7.0.11); the build adds it only if that parse succeeds. The baseline program has not read from a real OpenSearch or sent an alert to the real webhook; `td-baseline check` and `td-baseline test-alert` show both on an installed system. No alert carrying an ATT&CK for ICS technique has been seen in the running product: that Malcolm turns the rule metadata into its `threat.*` fields was read in its pipeline, not watched, and the mapping itself is one reviewer's reading of MITRE's descriptions. Its anomaly detectors and monitors have not been imported into OpenSearch, its added image layers have not been built, its hardening files have not been booted, and its downloads from outside GitHub (CISA, Snort, abuse.ch) were blocked where it was written.

- The rule-enable setting on a live platform: that the console accepts the rewritten settings file and switches newly imported local rules on.
- `platform/apply-overlay.sh rules` against a live detection list (its query was written from the platform's index mapping).
- Any rule firing on a live install. The Suricata rules have not been loaded into Suricata (no copy of it was available to check them), the YARA rules have not been loaded by the platform's file scanner, and none of the tests in `validation.yml` has been run; each entry says `confirmed: "no"`. The field names used by the three industrial Sigma rules come from the platform's ingest settings and the protocol analyzers' source, not from live records.
- The flood rules and the Honeywell Experion rules, beyond the checks above. Their figures are judgement, not measurement, and the Honeywell rules have never seen real Experion traffic.
- `layer2 on` on a live platform: the read check through `docker exec so-zeek`, the settings file being accepted, Zeek restarting with the script loaded, and a notice reaching the platform and becoming an alert through its Sigma rule. The Zeek version on Security Onion 2.4.211 may differ from the 7.0.11 the script was tried with; the read check is there for that. Behaviour with several Zeek worker processes is unknown.
- The network inventory has not read from a live platform. Its container image has not been built. How long records take to travel from the sensor to the platform (the inventory waits five minutes by default and says when that was not enough), whether every field can be grouped on as the ingest settings suggest, how the queries perform on a busy platform, and whether the platform creates the alert data stream are all unknown. It was run with a few thousand groups, not hundreds of thousands.
- An alert becoming a DFIR-IRIS ticket end to end (the forwarder is connected, but no alert at medium or above had occurred when it was checked).
- Building the workbench container image, and running Spark and JupyterLab in it. Package versions in `analytics/requirements.txt` are ranges that have not been resolved in a build. `td_hunt` has not read from a live Elasticsearch.
- Greenbone has not been started from this setup. The connector has not read from a real Greenbone: its protocol handling was written from the published protocol and tested against a stand-in, so field names in real responses may need adjusting. Its container image has not been built, and findings have not been written to a real platform data stream.
- Greenbone was started from this setup on a live machine on 2026-10-05: all images downloaded, and the first start stopped when one data container (`notus-data`) missed its start-up check. The setup now retries the start (five tries, two minutes apart) and reports the cause when it still fails; a completed start has not been confirmed yet.
- The honeypot has not been started. The OpenCanary image has not been built, and OpenCanary has not been run under the reduced privilege list in `honeypot/docker-compose.yml`. Whether alerts show the visitor's real address depends on Docker's networking on the machine. The platform has not yet been asked to create the honeypot data stream or to show its alerts.
- The skills have not been tried with an assistant on a live deployment. The community skills are included as their authors wrote them; see `skills/README.md` for their limits.

`scripts/verify.sh analytics` runs a self-test inside the container that covers Spark and the platform connection.
