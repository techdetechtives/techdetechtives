---
name: techdetechtives-detections
description: How to write, deploy, enable and check custom detection rules on TechDetechtives - Sigma rules for ingested logs, Suricata rules for network traffic, YARA rules for files - using the repository's rule folders and the platform's local rule repositories. Use when adding or changing a detection rule, when a rule is installed but not firing, when choosing which engine fits a detection idea, or when a rule needs tuning.
license: MIT
---

# TechDetechtives detections

Rules are kept in the repository and delivered to the platform by the
overlay. That keeps every rule reviewed, versioned and removable, so add and
change rules here rather than typing them into the console.

## Pick the engine by what the rule looks at

| The rule looks at | Engine | Folder | Runs in |
| --- | --- | --- | --- |
| Ingested logs (process starts, logons, PowerShell script blocks, DNS, anything in Elasticsearch) | Sigma | `platform/detections/sigma/*.yml` | ElastAlert |
| Packets on the wire | Suricata | `platform/detections/suricata/*.rules` | Suricata |
| Files carved out of network traffic | YARA | `platform/detections/yara/*.yar` | Strelka |

A YARA rule never sees logs, and a Sigma rule never sees a file's contents.
When an idea could be either (for example "script that decodes Base64 and runs
it"), write the Sigma rule for the log evidence and, if files matter too, a
YARA companion; the shipped rules do exactly this.

## Conventions

They make the rule set recognisable in the console and keep it from colliding
with the community rule sets.

- **Sigma:** file `techdetechtives_<what_it_detects>.yml`; `title` starts with
  `TechDetechtives - `; a fresh UUID in `id` (`python3 -c "import uuid; print(uuid.uuid4())"`);
  `status`, `description`, `author: TechDetechtives`, `date`, ATT&CK `tags`
  (`attack.t1059.001`), `logsource`, `detection`, `falsepositives`, `level`.
  The level becomes the alert severity: `medium` and above opens a ticket.
- **Suricata:** `msg` starts with `TECHDETECHTIVES`; SIDs 1900001 to 1900999
  are reserved for this rule set, so take the next free one; set `rev:1` and
  raise it on every change.
- **YARA:** rule name starts with `TechDetechtives_`; fill in `meta`
  (description, author, date, severity); bound the cost with a `filesize`
  condition.

Write the false-positive note honestly. It is what the analyst reads at
three in the morning to decide whether the alert is real.

## Deliver and switch on

```bash
scripts/verify.sh repo                         # anywhere: rules parse, ids and SIDs are unique
# then, on the platform:
git pull
sudo scripts/install.sh platform --dry-run
sudo scripts/install.sh platform
sudo platform/apply-overlay.sh rules           # each rule: ENABLED or disabled
```

The overlay commits the files to the platform's local rule repositories
(`local-sigma`, `local-suricata`, `local-yara`) and sets the platform to
switch local Sigma and YARA rules on when it imports them. The import happens
at the next rule sync, or at once from Detections, Options, Full Update.

Two things regularly surprise people:

- The switch-on-at-import setting only applies the first time a rule is
  imported. A rule that was imported earlier keeps its state, so enable it
  once by hand under Detections (or select several and choose Enable).
- A rule fires only if its data is being collected. A `process_creation` rule
  needs endpoint process events (Elastic Agent with Elastic Defend, or
  Sysmon); a `ps_script` rule needs PowerShell Script Block Logging (event
  4104); a Suricata rule needs the traffic to pass a monitored interface.
  Check the data exists in Hunt before deciding a rule is broken.

## Check it fires

A rule that has never fired is a guess. Use the
`techdetechtives-detection-validation` skill: every Sigma rule has an entry in
`platform/detections/validation.yml` naming the test that should trigger it,
and `scripts/verify.sh repo` fails when a rule has none.

## Tune

Change the rule in the repository and redeliver; do not disable a noisy rule
without recording why. Prefer narrowing the detection or adding a named
filter (`filter_inventory_tool`) over lowering the level, and say in the
commit message what was excluded and what blind spot that leaves.

## Removing

Delete the file, redeliver, and remove the detection in the console if it is
still listed. `sudo platform/apply-overlay.sh revert` removes the whole rule
set and restores the previous settings.
