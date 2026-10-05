---
name: techdetechtives-platform
description: How a TechDetechtives deployment is laid out and operated - which machine runs what, the install and check commands, where alerts, tickets and vulnerability findings live, and the limits to respect when working on it. Use for any task on a TechDetechtives system or in the techdetechtives repository, such as installing or checking a part, tracing why an alert did not become a ticket, or before applying a generic security skill (Sigma, YARA, Zeek, Elastic, Greenbone) to this platform.
license: MIT
---

# TechDetechtives platform

TechDetechtives is a detection and threat-hunting platform built as a set of
additions around an installed Security Onion. This skill is the map: read it
before acting on a TechDetechtives system, and before following a generic
security skill there, because several things that are normal on a hand-built
stack are wrong on this one.

## What runs where

There are two machines, and optionally a third for the honeypot. Commands only work on the right one, and running an
installer on the wrong machine is the most common mistake.

| Machine | Runs | Installed with |
| --- | --- | --- |
| Platform (the Security Onion manager) | Collection, storage (Elasticsearch on port 9200), the analyst console, Suricata, Zeek, Strelka, the detection engines | Security Onion's own installer, then `sudo scripts/install.sh platform` |
| Honeypot machine (optional; a small machine used for nothing else) | OpenCanary decoy services and the shipper that turns each contact into a platform alert | `scripts/install.sh honeypot` |
| Second host (any Linux host with Docker and the Compose plugin) | Hunting workbench (Jupyter + Spark, `127.0.0.1:8888`), DFIR-IRIS ticketing (port 8443) with the alert forwarder, Greenbone scanning (port 9443) with the vulnerability dashboard (port 8444) | `scripts/install.sh analytics`, `ticketing`, `vulnerability` |

The repository holds only the additions. Security Onion, DFIR-IRIS and
Greenbone are fetched from their own projects at the versions pinned in
`upstream.lock`; their code is never edited.

## Commands

On the platform:

```bash
sudo scripts/install.sh platform --dry-run     # show what would change
sudo scripts/install.sh platform               # console pages, rules, rule settings
sudo scripts/verify.sh platform                # is everything installed and switched on?
sudo platform/apply-overlay.sh rules           # the rules as the console sees them
sudo platform/apply-overlay.sh revert          # undo the overlay
sudo platform/create-readonly-key.sh --allow-ip <second host>    # key for workbench and forwarder
sudo platform/create-ingest-key.sh                              # key for vulnerability findings
sudo platform/create-ingest-key.sh --for honeypot --allow-ip <honeypot machine>
```

On the second host:

```bash
scripts/install.sh analytics | ticketing | vulnerability | honeypot
scripts/verify.sh  analytics | ticketing | vulnerability | honeypot
```

`scripts/verify.sh repo` runs the repository's own tests anywhere.

Settings for the second host live in `config/techdetechtives.env`. It holds
keys and passwords: read single values when a task needs them, never print
the file, and never paste its contents into a ticket, a notebook or a chat.

## How data moves

- Alerts are documents in the platform's Elasticsearch with `tags: alert` and
  `event.severity` from 1 (low) to 4 (critical). Sigma alerts come from the
  ElastAlert engine, network alerts from Suricata, file alerts from Strelka.
- The forwarder (`td-forwarder`) reads new alerts with a read-only key and
  opens one DFIR-IRIS alert for each at severity 2 (medium) and above. It
  starts from the moment it is first run; older alerts are not ticketed.
- The vulnerability connector (`td-vuln`) reads finished Greenbone reports,
  serves the dashboard and reports pages, writes findings to the data stream
  `logs-greenbone.results-techdetechtives`, and opens tickets for findings at
  medium and above.
- The workbench reads events with the same read-only key. It cannot write to
  the platform.
- The honeypot shipper (`td-honeypot-shipper`) writes each contact with a
  decoy service to `logs-opencanary.alerts-techdetechtives`. A first contact
  is tagged `alert` (rule names start with `Honeypot:`, `event.module` is
  `opencanary`) and is ticketed like any alert; repeats are plain events.
  Nothing legitimate talks to the honeypot, so treat a honeypot alert from an
  internal address as worth investigating, and check first whether the source
  is a known scanner. Passwords tried against it are withheld by default; do
  not go looking for them.

When an alert did not become a ticket, check in this order: is the rule
enabled (`apply-overlay.sh rules`), did an alert appear in the console's
Alerts screen, is its severity at least medium, then
`scripts/verify.sh ticketing` and `docker logs td-forwarder`.

## Limits on this platform

These exist because the platform manages its own parts, and because the
person operating it decides what leaves the network and what gets changed.

- **Sensors and storage are managed by the platform.** Do not edit Suricata,
  Zeek, Elasticsearch or Elastic Agent configuration files by hand, install
  second copies of them, or add rule sources with their own tools. Settings
  go through the console (Administration, Configuration); rules go through
  this repository (see the `techdetechtives-detections` skill). Hand edits are
  overwritten and can stop collection.
- **Read data through the platform.** Query events with the console's Hunt
  screen or the workbench rather than reading sensor log files on disk. Field
  names follow ECS (`process.command_line`, `source.ip`), not the raw Zeek or
  Sysmon names that generic guides use; `docs/FIELD-MAPPING.md` has the table.
- **Nothing leaves the network unless the operator agrees.** Looking up an
  address, domain or file hash on an outside service tells that service what
  you are investigating, and many deployments have no internet access. Ask
  first, and say which service and what would be sent.
- **Recommend actions; let a person take them.** Isolating a host, disabling
  an account, blocking an address, closing tickets in bulk, disabling or
  deleting a rule: describe the action and the reason, and wait for a yes.
- **Tickets live in DFIR-IRIS.** Do not create parallel cases elsewhere.
- **Run each command on its own machine**, and do not install the second
  host's parts on the platform: it manages its own Docker and firewall. The
  installer refuses. The honeypot goes on a machine of its own and gets only
  its own key; never copy the second host's settings file onto it.

Where a generic skill disagrees with this page about how this platform
works, follow this page.

## Related

- `techdetechtives-detections` - writing, deploying and enabling rules
- `techdetechtives-hunting` - the notebook workbench and the `td_hunt` library
- `techdetechtives-detection-validation` - proving a rule fires with Atomic Red Team tests
- `docs/ARCHITECTURE.md`, `MODIFICATIONS.md` (what has and has not been tested)
