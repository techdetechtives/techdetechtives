# Architecture

## Layout

```
                 endpoints (Elastic Agent)        network taps
                          |                            |
                          v                            v
        +--------------------------------------------------------+
        |  PLATFORM  (Security Onion 3.x, installed separately)  |
        |  collection - Suricata/Zeek - Elasticsearch - console  |
        |  alerts - hunt - detections - cases                    |
        |                                                        |
        |  + TechDetechtives overlay:                            |
        |      banner and overview page, Sigma/Suricata/YARA     |
        +---------------------------+----------------------------+
                                    | HTTPS 9200, read-only API key,
                                    | CA-verified, firewall host group
                                    v
        +--------------------------------------------------------+
        |  ANALYTICS HOST                                        |
        |                                                        |
        |  Workbench (this repo, derived from HELK)              |
        |    JupyterLab - PySpark (local) - pandas - NetworkX    |
        |    td_hunt library - hunting notebooks                 |
        |                                                        |
        |  Ticketing                                             |
        |    forwarder (this repo) --HTTPS API--> DFIR-IRIS      |
        |    one ticket per alert, medium severity and above     |
        |                                                        |
        |  Vulnerability scanning                                |
        |    Greenbone (OpenVAS) --local socket--> connector     |
        |    connector --> dashboard and reports pages (8444)    |
        |              --> findings to the platform (append-only)|
        |              --> DFIR-IRIS tickets for findings        |
        +--------------------------------------------------------+
```

## Why an overlay and not a fork

A fork that copies Security Onion's code and merges HELK into it was considered and rejected:

1. **Licences.** Security Onion is under the Elastic License 2.0 and HELK under GPL-3.0. A single combined work cannot satisfy both. Two separate programs that talk over a network API can.
2. **Upgrades.** Security Onion upgrades itself in place (`soup`) and expects its own files to be unmodified. Local override folders and local rule repositories are the supported way to customize it and they survive upgrades. A fork would have to be re-merged at every release.
3. **Trademark.** A redistributed modified copy cannot carry the Security Onion name or logo. An overlay does not redistribute anything; it changes your own installation and says so.
4. **Overlap.** HELK's Elasticsearch, Logstash, Kibana and Kafka duplicate what the platform already runs, at much older versions. Only HELK's analytics idea (notebooks and Spark over hunt data) adds something, so only that part is carried over.

If you later need to change platform code itself, fork the upstream repository separately, keep that fork under the Elastic License 2.0 with its notices, and point this overlay at it. `scripts/fetch-upstream.sh` fetches the exact upstream commits for comparison.

## Ticketing flow

1. Every 30 seconds the forwarder searches the platform for events tagged as alerts at or above the configured severity, using the read-only key.
2. For each one it posts an alert to DFIR-IRIS over HTTPS, verified against the certificate generated at install.
3. It records what it sent in a small state file on a Docker volume. It re-reads the last ten minutes on every pass to catch alerts that were indexed late, and the state file stops those being ticketed twice.

DFIR-IRIS is installed on the analytics host from its own repository at a pinned version, unmodified. See `ticketing/README.md`.

## Vulnerability flow

1. Greenbone scans the targets you define in its interface.
2. Every five minutes the connector asks Greenbone, over its local management socket, for finished scan reports it has not copied yet, and stores their findings in a small local database.
3. From that database it serves the dashboard and reports pages, appends each finding to the platform with a key that can do nothing else, and opens a DFIR-IRIS ticket for each new finding at or above the configured score.

The connector shares no network port with Greenbone: it mounts Greenbone's socket volume read-write only to speak the management protocol, and runs with all Linux capabilities dropped except the one needed to open that socket. See `vulnerability/README.md`.

## Honeypot flow

1. OpenCanary runs in a container on a machine of your choice and pretends to offer services. It writes one line per contact to a log file on a Docker volume.
2. The shipper, a second container, reads new lines every ten seconds and appends each contact to the platform with a key that can do nothing else. The first contact from an address to a decoy is tagged as an alert; repeats within 30 minutes are stored as plain events.
3. The alert appears on the platform's Alerts page, and the ticket forwarder opens a DFIR-IRIS ticket for it like any other alert.

Passwords typed into a decoy are left out of what is sent. See `honeypot/README.md`.

## Detections and their tests

Rules live in `platform/detections/` and reach the platform through its local rule repositories. The overlay also adds those repositories to the platform's "enable on import" settings, so new rules arrive switched on. Each Sigma rule is paired in `platform/detections/validation.yml` with a test that should make it fire, mostly Atomic Red Team tests named by id; the tests are run by hand on a lab endpoint. See `docs/DETECTION-VALIDATION.md`.

## Analyst skills

`skills/` holds guidance files for an AI assistant working alongside an analyst. They run nowhere on the platform: the assistant reads them on the analyst's own machine. Four describe this platform and its limits; the rest are a reviewed selection from a community library, copied unchanged and checked against a manifest. See `skills/README.md`.

## Data flow

1. The platform collects and stores events in Elasticsearch data streams (`logs-*`).
2. A notebook calls `td.events("process", since="24h")`. `td_hunt` runs a scroll search with the read-only key and returns a pandas DataFrame.
3. `td.to_spark(df, view="process")` hands the result to Spark as a SQL view for joins and aggregation.
4. Findings go back to the platform by hand: escalate to a case, or turn the logic into a Sigma rule under `platform/detections/sigma/`.

The workbench never writes to the platform. Its key has `read` and `view_index_metadata` on `logs-*` and `so-*`, plus cluster `monitor`.

## Security posture

- Jupyter binds to `127.0.0.1` and refuses to start without an access token of at least 24 characters. It has no TLS of its own: use an SSH tunnel, or put a TLS reverse proxy with authentication in front before exposing it.
- The Elasticsearch connection verifies the platform CA and the host name.
- The API key expires (90 days by default). Re-run `platform/create-readonly-key.sh` to rotate it.
- `config/techdetechtives.env` holds the key and token. It is git-ignored and created with mode 600.
- Anyone with notebook access can read all events the key can read. Treat workbench access like analyst access to the platform.

## Sizing

`td.events()` pulls results into memory on the analytics host, so it is meant for targeted hunts (a `limit` of 10,000 events by default), not for exporting whole indices. For large pulls, narrow the query and `fields`, raise `limit` deliberately, and raise `TD_SPARK_DRIVER_MEMORY`.
