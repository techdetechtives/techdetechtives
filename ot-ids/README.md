# TechDetechtives OT IDS

A network intrusion detection appliance for industrial control networks, built
as two installer ISOs on top of a pinned release of
[Malcolm](https://github.com/idaholab/Malcolm) (v26.09.0, Apache 2.0):

| ISO | Role | Contents |
| --- | --- | --- |
| `techdetechtives-server-26.09.0.iso` | Central server | Zeek with the ICSNPP industrial parsers and ACID, Suricata, OpenSearch Dashboards, Arkime, NetBox |
| `techdetechtives-sensor-26.09.0.iso` | Capture sensor | Zeek, Suricata and Arkime capture, forwarding to the server |

Both are Debian 13 based, carry the TechDetechtives name and logo, ship the
detection content described below, and embed every container image so they
install with no Internet connection.

This folder is separate from the Security Onion based platform in the rest of
the repository. It reuses that platform's Suricata and YARA rules
(`platform/detections/`) and adds its own.

The sensor watches a copy of the traffic. It reports; it cannot block.

## Build

On an x86-64 Linux machine with Internet access, about 80 GB of free disk, and:

- `git`, `rsync`, `xz-utils`, `python3`
- Docker Engine 23 or newer
- one of:
  - **Vagrant** plus VirtualBox, VMware or libvirt (any Linux distribution; the
    build runs inside a Debian 13 VM that Vagrant creates). VirtualBox also
    needs the `vagrant-vbguest` plugin; libvirt needs `vagrant-libvirt` and
    `vagrant-mutate`.
  - a **Debian 13** host or VM with `sudo apt-get install live-build debootstrap
    squashfs-tools xorriso genisoimage xmlstarlet imagemagick jq bc virt-what`.
    Simplest when the build host is itself a VM. The build works under `/root`.

```bash
git clone https://github.com/techdetechtives/techdetechtives.git && cd techdetechtives/ot-ids
./build-iso.sh
```

The ISOs, their checksums, the build logs and four reports land in `out/`.
Expect well over an hour. Settings are in `build.conf`.

| Stage | What it does |
| --- | --- |
| `./build-iso.sh prepare` | Clones the pinned Malcolm release; applies name, logo and artwork; adds the detection content (with each rule's ATT&CK for ICS technique), the Suricata settings and the hardening files |
| `./build-iso.sh sources` | Downloads the rule sets, YARA rule sets and threat feeds enabled in `sources.conf`, converts them, adds them |
| `./build-iso.sh images` | Pulls the container images, adds the branded and detection layers, packs them; checks every rule with the product's own Suricata and compiles the YARA rules with its own file scanner; writes the vulnerability and ATT&CK for ICS coverage reports |
| `./build-iso.sh iso` | Runs the live-build and writes the ISOs to `out/` |

Run `prepare` again after changing `build.conf`, `overlay/`, `detections/`,
`iocs/` or `hardening/`. To rebuild the image bundles, delete
`work/*_images.tar.xz`.

Reports in `out/`:

- `rule-check.txt`: the engine's verdict on each rule file, and any rule it
  refused. Refused rules are commented out (`#PRUNED`) in the ISO, not dropped
  silently. Also here: how many YARA rules the file scanner's image came with
  and how many it compiles from the ISO's files, and how many of Suricata's
  own Modbus, DNP3 and EtherNet/IP event rules are active in its image.
- `vulnerability-coverage.csv` and `.md`: see "Vulnerability coverage" below.
- `attack-ics-coverage.md`, `.csv` and `attack-ics-layer.json`: see "MITRE
  ATT&CK for ICS" below.
- `external-sources.txt`: what was downloaded, from where, under which licence.

## Detection content

### Rules written for TechDetechtives

| File | Rules | Reports |
| --- | --- | --- |
| `platform/detections/suricata/techdetechtives-ot.rules` (shared) | 40 | Single operations that are rare and consequential: Modbus listen-only and firmware functions, DNP3 restarts, CIP stop and reset, S7 stop and block delete, IEC 104 reset, Honeywell Experion engineering ports, industrial protocols crossing the network edge |
| `platform/detections/suricata/techdetechtives-flood.rules` (shared) | 17 | Floods and sweeps by packet rate |
| `platform/detections/suricata/techdetechtives.rules` (shared) | 2 | Dynamic-DNS lookups, PowerShell as a web client |
| `detections/suricata/techdetechtives-ot-behavior.rules` | 10 | **Abnormal behaviour**: Modbus writes at an unusual rate, one address sweeping controller ports, devices answering with errors repeatedly, discovery sweeps (Modbus, EtherNet/IP, BACnet, S7), files pushed by TFTP |
| `detections/suricata/techdetechtives-ot-correlation.rules` | 10 alerts, 6 markers | **Correlation**: an address identifies controllers and then changes or stops one within 15 minutes; a machine under remote control from outside then talks to a controller within 30 minutes |
| `detections/suricata/techdetechtives-ot-control-extra.rules` | 12 | Schneider UMAS stop, start, program download and upload; S7 program download, upload and block activation; IEC 104 stop of data transfer, clock set, parameter activation, file transfer |
| `platform/detections/yara/*.yar` (shared) | 12 | Attack tooling and malware traits in files carved from traffic |
| `detections/yara/techdetechtives_ot_engineering.yar` | 9 | Controller programs and substation configurations in transit (PLCopen XML, Rockwell L5X/L5K, Schneider XEF, STL/SCL source, IEC 61850 SCL); scan plans and the ISF framework; Industroyer and Stuxnet file names |

Signature numbers 1900401 to 1900599 are reserved for the three OT IDS rule
files; the shared files use 1900001 to 1900399.

The rate figures are starting points. An asset-inventory tool, a commissioning
laptop or a busy master can cross them: raise the count or suppress that
address, do not switch the rule off. The two correlation chains need `HOME_NET`
set to your own address ranges (`./scripts/configure`), and chain 2 needs the
sensor to see traffic at the network edge.

**Quieting a rule for one address.** On the installed system,
`~/Malcolm/suricata/include-configs/td-threshold.config` holds commented
examples: suppress one rule for one address or range, or limit a talkative rule
to one alert an hour. Copy a line, remove the `#`, put in the rule's number and
your addresses, and restart the product on the server and each sensor. Nothing
is suppressed as shipped. A `threshold` line there replaces the rate a rule
sets for itself, so for a rule that counts before it alerts, write the count
you want it to have.

**Three rules were rewritten in 0.13.0.** Rules 1900103, 1900406 and 1900451
(Modbus Read Device Identification, alone, repeated, and as the first step of
correlation chain 1) used a decoder option that Suricata compares for one
other function only, so they loaded and never fired. They now match the
request's bytes on port 502. See fault 1 in
[`docs/LISTED-REPOSITORIES-REVIEW.md`](docs/LISTED-REPOSITORIES-REVIEW.md).

### Suricata settings the build changes

| Setting | What it does | In `build.conf` |
| --- | --- | --- |
| Stream depth 0 | The product stops Suricata's decoders 1 MB into each connection. A master's connection lasts days, so every decoder-based rule went blind on it. Now each connection is read to its end, at the price of more work on large transfers. | `SURICATA_STREAM_DEPTH` |
| Suricata's own protocol event rules | A Modbus, DNP3 or EtherNet/IP message that breaks its protocol: a length that does not add up, a read of more registers than the protocol allows, an answer nobody asked for, a flood of unanswered requests. The product's image is built in a way that probably leaves the 16 Modbus and DNP3 rules commented out and the 2 EtherNet/IP rules absent; the build says what it found in `out/rule-check.txt` and switches them on. On a link that loses packets, rule 2250002 will fire: quiet it in the file above. | `SURICATA_PROTOCOL_EVENTS` |

Zeek's side comes with Malcolm: the ICSNPP parsers decode the industrial
protocols into searchable records, and ACID raises MITRE ATT&CK for ICS notices
on EtherNet/IP, S7 and BACnet behaviour.

**Layer 2 watch.** One Zeek script is added: `platform/zeek/techdetechtives/`,
which raises a notice for ARP poisoning, an address taken over by another
network card, MAC flooding and ARP sweeps (see "Layer 2" in
`docs/DETECTION-COVERAGE.md` for its settings and limits). A script Zeek cannot
load stops Zeek, so the `images` stage first has the product's own Zeek parse
it, and adds it only if that succeeds; `out/rule-check.txt` says which
happened. The notices appear in the Notices dashboard. The sensor must receive
the ARP traffic of the segment it watches. `ZEEK_L2_WATCH="false"` leaves it
out.

### MITRE ATT&CK for ICS

The detections are mapped to MITRE's ATT&CK for ICS matrix (version 19.2: 12
tactics, 79 techniques, 18 sub-techniques). Three things come of that.

**Alerts carry the technique.** When content is collected for an ISO or an
update, each mapped Suricata rule gets its tactic and technique written into
its metadata, in the four keys the product reads (`mitre_tactic_id`,
`mitre_tactic_name`, `mitre_technique_id`, `mitre_technique_name`). The product
turns them into the alert's `threat.tactic.*` and `threat.technique.*` fields
and adds the tactic to the alert's category. An S7 STOP alert then reads
Execution, T0858 Change Operating Mode, beside the ACID notices, which carry
theirs already. An alert carries its rule's first technique and every direct
one; `td_attack_fit` in the alert's metadata says whether that first technique
is a direct or a related match (see below), so "Program Download" on a rule
that only sees a programming function in use is not read as more than it is. The rule files in the repository are not changed; the copies
are. `ATTACK_ICS_TAGS="false"` in `build.conf` leaves the copies alone too.

**A coverage page shows what is and is not detected.**
[`docs/ATTACK-ICS-COVERAGE.md`](docs/ATTACK-ICS-COVERAGE.md) covers what is
kept in this repository. The `images` stage writes the same page for what the
ISO really ships (imported rule sets included, rules the engine refused left
out) to `out/attack-ics-coverage.md`, with a table that adds MITRE's
mitigations for each technique (`.csv`) and a layer file for MITRE's ATT&CK
Navigator (`attack-ics-layer.json`). All three are copied to
`~/Malcolm/attack-ics/` on the installed system, with
`attack-ics-techniques.md`: one line on every technique, how MITRE says it is
detected and mitigated, for reading where attack.mitre.org cannot be reached.

| Counted | Direct | Related only | None |
| --- | ---: | ---: | ---: |
| Detections kept in this repository | 20 | 9 | 50 |
| With the three imported rule sets that are on by default, and the layer 2 watch accepted | 22 | 13 | 44 |

"Direct" means a detection matches the network operation the technique is
carried out with; "related" means it matches something that goes with it, or
a wider operation of which the technique is only one use. Of the 50 with none,
12 are effects on the plant (loss of view, damage to property) and 24 show
only in host logs, device alarms or the process itself, which no network
sensor sees. The remaining 14 (21 with sub-techniques) are listed on the page
with what each would take.

**A monitor watches for a chain.** The TechDetechtives ATT&CK for ICS Tactic
Chain Monitor (below) fires when one address appears under three or more ICS
tactics in 24 hours, for example discovery, then a program download, then a
stop command. An engineering station doing a planned change does exactly
that, so expect it during maintenance; outside maintenance it is the alert to
read first. Events that name a tactic but no technique are not counted,
because ACID raises one of those for every session set up with a Rockwell or
Siemens controller.

The mapping is a judgement, kept in four tables in `attack/`, beside the reference:

| File | Holds |
| --- | --- |
| `rule-mapping.csv` | This repository's Suricata rules, by signature number |
| `import-mapping.csv` | Imported rule sets, by source and a pattern in the rule's message |
| `other-detections.csv` | ACID, the layer 2 watch, YARA rules, indicator matches |
| `gap-notes.csv` | What it would take to detect each technique that is not covered |
| `ics-attack.json` | The reference: MITRE's identifiers, names, tactics, data components, mitigations and the first sentence of each description (© The MITRE Corporation, see Licences) |

A new rule needs a row in `rule-mapping.csv`; the tests fail until it has one.
When MITRE publishes a new version, `tools/attack_ics.py update` rebuilds the
reference from MITRE's data file, and any row naming a technique that was
replaced fails with the new identifier in the message. Version 19 replaced
nine, among them T0855 Unauthorized Command Message (now T1692.001) and T0857
System Firmware (now T1693.001); older reports use the old numbers.

Limits: a technique with a detection is not a technique that cannot be done
unseen. Each rule covers one way of doing it on the protocols it understands,
and no alert says by itself that an operation was unauthorised. The product
labels tagged Suricata alerts with the framework name "MITRE ATT&CK", without
"for ICS"; the T0 and TA01 numbers are what mark them as ICS. The layer 2
watch and YARA matches are mapped on the page but do not carry the technique
in the alert.

### Baseline: who talks to whom, and what is new

An industrial network repeats itself, so the most useful anomaly detection
for one is also the simplest: learn who talks to whom with which operations,
then say what is new and what has stopped. `baseline/td_baseline.py` does
that. It is one Python file with no dependencies, runs every 15 minutes inside
the server's own `dashboards-helper` container, and reads the industrial
protocol records the sensors have already decoded.

| Finding | Meaning |
| --- | --- |
| new-master | An address acting as a master of a protocol for the first time: never seen before, or one that only answered until now |
| new-device, new-service | An address never seen before answers an industrial protocol; a known device answers a protocol it never answered |
| new-pair, sweep | A known master talks to a device it never talked to; or to more than five of them |
| new-operation | An operation never used between a master and a device (ranked higher when it changes something) |
| burst | An operation used far more in an hour than in any hour while learning |
| quiet | A device or master that was heard nine hours in ten has stopped for four hours |
| sensor-silent | No industrial traffic at all for four hours: the sensor or its mirror port, not the plant |

Each finding is a sentence a person can act on, for example "10.0.0.99 was
never seen before and is acting as a master by modbus. It talked to: 10.0.1.10
(modbus). Operations: WRITE_SINGLE_COIL."

**It learns by itself and reports nothing until you say so.** From the first
start it reads what is stored (up to 30 days back) and learns until it has seen
14 days' worth of hours with traffic. Its alerts are off. On the server, as the
account that runs the product:

```bash
td-baseline              # where learning stands, and what is known
td-baseline check        # read the last hour and show what was found; changes nothing
td-baseline findings     # what it has found so far (recorded even while alerts are off)
td-baseline test-alert   # send one test alert and look for it in the dashboards
td-baseline alerts on    # from now on, findings become alerts
```

Run `check` and `test-alert` first: they show on your system the two things
that could not be tried where this was written (see "Test status"). Alerts
appear with `rule.name` "TechDetechtives OT Baseline" beside every other
alert, with their ATT&CK for ICS technique where one applies.

For planned work, `td-baseline learn --hours 8` treats the next eight hours as
normal. `td-baseline forget ADDRESS` drops an address so it is reported again;
`td-baseline reset --yes` starts over from now. Settings (learning time, the
four-hour and threefold thresholds, limits) are environment variables named
at the top of the program; put them in `~/Malcolm/config/dashboards-helper.env`.

**Uploaded captures are left out, since 0.14.0.** A capture file uploaded to
the product for study is stored beside the live records, at the times in the
capture. Versions 0.12.0 and 0.13.0 took one with recent times for the plant's
own traffic: an attack capture could have taught the baseline that the attacker
was normal, or raised alerts for a replay. It now reads live records only.
`TD_BASELINE_INCLUDE_UPLOADS=true` restores the old behaviour. **Set it if the
product's Zeek analyses rotated capture files instead of the capture
interface** (not the default): the product marks all of such a system's
records the way it marks an upload, and the baseline would read nothing;
`td-baseline check` says so when it sees it. What an earlier version learned
from an uploaded capture is still in its list; `td-baseline forget ADDRESS`
drops an address. The correction is in the program, which lives in a container
image: a system installed from 0.12.0 or 0.13.0 gets it with an ISO built from
this version, not with an update bundle.

What it cannot tell you: whether something new is wanted. A replaced HMI, a
commissioning laptop and an intruder all arrive as "new master". Broadcast
protocols (BACnet Who-Is, EtherNet/IP I/O to a group address) make the sender
look like a master. What has not been seen for 90 days is dropped from the
list and is new again when it returns. `OT_BASELINE="false"` in `build.conf`
leaves the program out.

Sixteen anomaly-detection projects were read before this was written. None
could be used as it was; seven ideas from four of them are in it. See
[`docs/ANOMALY-DETECTION-REVIEW.md`](docs/ANOMALY-DETECTION-REVIEW.md).

### Traffic profile: what else is on the control network

The baseline watches the industrial protocols. `baseline/td_profile.py`
reports on everything else, when you ask: one search over the connection
records the sensors already stored, one report, no alerts, nothing kept. On
the server:

```bash
td-profile                              # the last 24 whole hours
td-profile --hours 72 --top 25
td-profile --format markdown > profile.md
td-profile --format csv > conversations.csv     # every conversation, one per line
td-profile --from 2026-10-01T02:00 --to 2026-10-01T09:00    # a period in the past (UTC, up to seven days)
td-profile --tag incident7              # an uploaded capture, by a word of its file name
```

It reports on live traffic. Uploaded captures are left out unless asked for
with `--tag`, `--uploads include` or `--uploads only`.

| List | What it shows |
| --- | --- |
| Other protocols reaching controllers | Traffic that is not industrial, answered, to an address the baseline knows as a device: remote desktop, web pages, file sharing |
| Connections opened by controllers | A device that starts conversations of its own. Time and name lookups are usual; little else is |
| Addresses outside the private ranges | One end is a public address. In an isolated network there should be none |
| Longest connections | One connection open an hour or more, including those still open and those that began before the period |
| Largest transfers | By bytes, with the direction |
| Steady repeaters | New connections in three hours out of four, at an even rate (needs a period of four hours or more) |
| Addresses that contacted many services | One address, many destinations and ports: an inventory tool, or a scan |
| Attempts nobody answered | The client sent and the server sent no data back |
| Services | Each port and protocol, with how many servers offer it and how many clients use it |

A period holds every connection that was open at some time in it; one that
began earlier and ended in the period is counted whole. Masters and devices are
named from the baseline's list, so the first two lists are empty until the
baseline has learned something. A steady repeater is time
synchronisation or a monitoring agent far more often than a program calling
home; the report cannot tell which, it only makes sure someone has seen the
list. The measures are the ones RITA reports; none of RITA's code is used
([`docs/LISTED-REPOSITORIES-REVIEW.md`](docs/LISTED-REPOSITORIES-REVIEW.md)).

### Replaying an incident from its packets

The product keeps the packets it captured, and it analyses any capture file
you upload (`https://<server>/upload/`) with every engine again: Zeek and the
industrial decoders, Suricata with the rules installed today, the file
scanner. The result is stored at the times in the capture and tagged with the
words of the file's name. So an incident can be replayed: export its packets
from Arkime, put them in time order, upload the file, and a rule added or
corrected since then shows what it would have said. `baseline/td_replay.py`
reads the outcome as one account. On the server:

```bash
td-pcap-order sessions.pcap incident7.pcap   # an Arkime export is not in time order; this writes one that is
cd ~/Malcolm && ./scripts/restart -s suricata  # before a replay that is to be compared with an earlier one
# upload incident7.pcap at https://<server>/upload/, wait a few minutes, then:
td-replay list                          # uploaded captures, by tag, with when their traffic took place
td-replay report --tag incident7        # one uploaded capture (the file was named incident7.pcap)
td-replay report --from 2026-10-01T02:00 --to 2026-10-01T09:00     # a period of live traffic (UTC, up to seven days)
td-replay report --tag incident7 --format markdown > incident7.md
```

| Part of the report | What it shows |
| --- | --- |
| The course of events | The ATT&CK tactics in the order they first appeared, with the address each came from |
| Detections in order | Rule alerts, Zeek notices and signatures, indicator matches and file-scan hits: first seen, how often, between which addresses, which technique |
| Against the baseline | What this traffic holds that the plant's normal traffic never did: an address that was never a master, a device never spoken to, an operation never used. Works for an attack no rule was written for |
| Other traffic | Other protocols reaching controllers, public addresses, the largest transfers (the traffic profile, cut short) |

It reads and changes nothing; the baseline is only compared with.
[`docs/INCIDENT-REPLAY.md`](docs/INCIDENT-REPLAY.md) has the procedure, a
sample report, what each part of this kit does with a replayed capture, and
the limits. Three things about the product decide whether a replay tells the
truth, all read in its source and none yet tried:

- **An Arkime export is written session by session, not in time order.**
  Replayed as it is, a correlation rule can miss and a rate be miscounted.
  `td-pcap-order` (one Python file, no dependencies; Wireshark's `reordercap`
  does the same) puts it right.
- **The product silently skips a file whose name and size it has processed
  before.** Every replay needs a new file name.
- **Suricata remembers its alert limits from one uploaded file to the next.**
  A rule that allows one alert per address in an hour stays silent on a second
  replay of the same traffic unless the Suricata that analyses uploads was
  restarted (60 of the 97 rules this kit writes limit themselves that way).

And four more:

- Uploading what the sensor already recorded stores it twice, at the same
  times. Filter by the tag, or by `node:*-upload`.
- The product offers no way to remove one upload's records again.
- The correlation rules link events inside one capture file, not across two.
- Packets are never played back onto a network: a replayed stop command would
  stop the controller again. Nothing in this kit or the product does that.

### Anomaly detectors and correlation monitors

Three detectors for the platform's anomaly detection (it learns each plant's
own normal, no attack samples needed) and four alert monitors are added to the
server. Like the platform's own examples they arrive **switched off**:

| Name | Where | What it flags |
| --- | --- | --- |
| `techdetechtives_ot_protocol_activity` | Dashboards > Anomaly Detection | An industrial protocol far busier or quieter than its own history |
| `techdetechtives_ot_operations` | same | An unusual amount of one operation in a protocol, such as a burst of writes |
| `techdetechtives_ot_peers` | same | A machine talking industrial protocols to more devices than it usually does |
| TechDetechtives OT Correlation Alert Monitor | Dashboards > Alerting | Any alert from the correlation rules |
| TechDetechtives Multi-Signal Host Monitor | same | One address with two or more kinds of evidence in 15 minutes: a rule alert, a threat-indicator match, an ATT&CK technique notice, a file signature hit |
| TechDetechtives ATT&CK for ICS Tactic Chain Monitor | same | One address seen under three or more ATT&CK for ICS tactics in 24 hours, counting tagged rule alerts and ACID notices |
| TechDetechtives DNP3 Outstation Trouble Monitor | same | An outstation whose answers carry "Device Trouble", "Configuration Corrupt", "Event Buffer Overflow" or "Digital Outputs in Local" (a restart is rule 1900132) |

Start a detector after a week or two of normal traffic has been recorded, so
it has something to learn from. Enable a monitor and point its action at your
own notification channel (e-mail, webhook).

### File-scanning rules (YARA)

Files taken from the traffic are scanned with YARA, among other engines.
**As shipped, the product takes no files from the traffic**: its File
Extraction Mode is `none`, and with it no YARA rule ever runs, this kit's and
the nine sets below included. Choose a mode in `./scripts/configure` (step 5
of "Installing").

The product is built with nine public rule repositories for that. **Until 0.13.0
this kit's own 21 rules replaced them on an installed system instead of adding
to them**: the scanner compiles its rules again at each start from the files in
`~/Malcolm/yara/rules`, and with no Internet that folder was all it had (fault
3 in [`docs/LISTED-REPOSITORIES-REVIEW.md`](docs/LISTED-REPOSITORIES-REVIEW.md)).

The build now fetches the same nine repositories and puts their rule files in
that folder beside the kit's own:

| Source in `sources.conf` | On by default | Rules fetched | Licence |
| --- | --- | ---: | --- |
| `yara-signature-base` (Florian Roth) | yes | 5,579 | Detection Rule License 1.1; 13 files that state a non-commercial licence and 2 that name the GPL are left out |
| `yara-elastic` | yes | 3,069 | Elastic License 2.0: not an open-source licence, read it before you pass the product on |
| `yara-reversinglabs` | yes | 1,240 | MIT |
| `yara-sekoia` | yes | 791 | Detection Rule License 1.1 |
| `yara-atr` (Trellix) | yes | 167 | Apache-2.0 |
| `yara-volexity`, `yara-bartblaze`, `yara-eset` | yes | 149, 143, 138 | BSD-2-Clause, MIT, BSD-2-Clause |
| `yara-cape` (CAPE Sandbox; also one of the product's nine) | no | 223 | GPL-3.0. On in 0.14.0 only; the owner switched it off again in 0.14.1. One rule file stays left out if you switch it on (its rule, SparkRAT, fires on Docker's own daemon) |
| `yara-rules-legacy` (Yara-Rules/rules, last changed 2022) | no | 1,125 after filtering | GPL-2.0 |

With the defaults the scanner compiles 10,656 rules at start, from 3,155 of
3,173 rule files, which takes about a minute on the server (measured with the
product's own script and YARA 4.5.8; `out/rule-check.txt` has the figure from
the product's own image after a build). A simulation of the product's own
build gave 10,995. The two sets are close, not the same: this kit leaves out
CAPE's rules (224 in the product's build) and the rule files of signature-base
that state a non-commercial licence or name the GPL (they hold some 340 rules;
`skip_noncommercial` and `exclude` in `sources.conf`), and by the count it
must also keep some 220 rules the product's build loses; which those are was
not established. With `yara-cape` switched on the figures are 10,879 rules
from 3,315 of 3,333 files. Each source is pinned to a commit;
delete a `commit` line to take that source's newest rules. Each source's
licence file is copied beside its rules.

**YARA rules go in together or not at all.** If a YARA source that is switched
on cannot be fetched, or `FETCH_SOURCES="false"`, no YARA rule goes into the
ISO, this kit's own included, and the product keeps the set it was built with;
the build says so. A part of the rules would silently replace the whole. To
add YARA rules of your own, put them in `overlay/malcolm/yara/rules/` under
file names nobody else uses; they need the sources above for the same reason.

If the server has Internet access and you switch the product's own rule
updates on (`RULES_UPDATE_ENABLED`), it fetches the nine repositories itself:
turn the `yara-*` sources off then, or every rule is compiled and matches
twice.

### External rule sets, including Snort rules

`sources.conf` lists outside sources. Nothing from them is stored in this
repository; the build downloads the enabled ones.

| Source | On by default | What | Licence |
| --- | --- | --- | --- |
| `elitewolf` | yes | NSA ELITEWOLF: 52 Snort rules for activity on Rockwell, SEL and Siemens device interfaces | CC0 |
| `quickdraw` | yes | Digital Bond Quickdraw: 58 Snort rules for BACnet, DNP3, EtherNet/IP, Modbus, Modicon, Fox, FINS and S7 | MIT |
| `nmap-scans` | yes | Aleksi Bovellan's Nmap scan detection: 8 Suricata rules for SYN, connect, ACK, Xmas, fragmented and UDP scans (two blunt port-4444 rules left out; one alert per window) | MIT |
| `snort-community` | no | Snort community rules: Windows, Linux and server-software exploits | GPL-2.0 |
| `stamus-lateral`, `hunting-rules`, `pt-open` | no | Suricata rule sets for lateral movement, hunting, and named vulnerabilities | GPL-3.0 / custom |

**Snort rules are converted, not loaded blind.** `tools/snort2suricata.py`
replaces variables the sensor does not define, rewrites Snort-only Modbus
keywords, turns `drop` into `alert`, gives every rule a new number (the
original stays in the rule's metadata), limits rules with no rate limit of
their own to one alert per address per five minutes, and sets aside what
Suricata cannot express, with the reason. The engine check in the `images`
stage then comments out anything Suricata still refuses.

**Snort 3 rules** that keep the classic header are converted where the change
is mechanical: content options with their modifiers after commas,
`dnp3_obj: group N, var M`, single-value `cip_class`, `cip_instance`,
`cip_attribute` and `cip_status`, and `iec104_asdu_func`, which becomes a byte
match because Suricata has no IEC 104 decoder. Set aside with the reason:
Snort 3 rules with no addresses in the header, rules that need Snort 3's
S7CommPlus, MMS or OPC UA inspectors, and rules that name a buffer the Snort 3
way (`http_uri;` before the content it applies to), which Suricata would read
the other way round.

To add a Snort or Suricata rule set of your own, add a section to
`sources.conf` (web address or git repository), or convert a file by hand:

```bash
tools/snort2suricata.py --name mysite --sid-base 1950000 --limit-seconds 300 \
    -o overlay/malcolm/suricata/rules/ext-mysite.rules my-snort.rules
```

Imported sets overlap with the TechDetechtives rules in places (Modbus
diagnostics, DNP3 restarts), so one event can raise two alerts.

### Threat indicators (IOCs)

Indicators are loaded into Zeek's intelligence framework. A match on an
address, domain, URL or file hash becomes an "Intelligence" event with a high
severity score, on the server and on each sensor.

- **Public feeds:** `public-threat-feeds` in `sources.conf` takes five lists
  (abuse.ch botnet controllers, ThreatFox addresses, malware hashes, Cobalt
  Strike servers, compromised hosts; about 15,000 indicators) from Critical
  Path Security's daily collection. More lists from the same collection can be
  named in `files =`.
- **Your own:** put addresses, networks, domains, URLs or hashes one per line
  in `iocs/*.txt` (or `.csv`). `hxxp://` and `[.]` forms are understood.
  Private addresses are left out, because they would match ordinary traffic.
- **STIX, TAXII and MISP:** Malcolm reads these directly; see its "Zeek
  Intelligence Framework" page in the built-in user guide.

Indicators age quickly. In an isolated network they are as old as the last
update you carried in.

### Vulnerability coverage ("virtual patching")

A rule that recognises an attempt to use a known vulnerability is often called
a virtual patch. Here it is a detection: you see the attempt, the sensor does
not stop it.

The server already carries the Emerging Threats Open rule set inside its
Suricata image, which names many vulnerabilities in Windows, Linux and
industrial products. The `images` stage reads that rule set, adds every rule
this kit ships or imports, and writes `out/vulnerability-coverage.csv` (one row
per CVE and rule, with a platform guess: windows, linux, ot or other) and a
summary. With the `cisa-kev` source on, the summary also says how many of
CISA's known-exploited vulnerabilities are covered and lists the known-exploited
industrial ones that are not, each with the date it entered the catalogue and
whether the catalogue says ransomware campaigns use it. Both files are copied
to `~/Malcolm/` on the installed system.

For a vendor whose protocols are closed (Honeywell Experion, Yokogawa, parts of
ABB and Emerson) coverage will be thin. The shared OT rules explain what is
watched instead for Experion.

## Offline updates

Rules and indicators change after the ISO is built. On a machine with Internet
access, in a current checkout of this repository:

```bash
ot-ids/tools/make-update-bundle.sh /path/to/usb
```

This writes `td-update-YYYYMMDD.tar.gz` and a `.sha256` file: the current
TechDetechtives rules (with their ATT&CK for ICS techniques), the enabled
external rule sets, the YARA rule sets, indicators and the technique reference.
A system installed from a version before 0.13.0 scans files with this kit's 21
YARA rules alone; applying an update made with this version gives it the
product's rule sets back. If a YARA source cannot be fetched, no bundle is
written. A bundle carries rules, YARA rules and indicators only: the stream
depth, the protocol event rules and the suppression file reach an installed
system with a new ISO, or by hand (`docs/LISTED-REPOSITORIES-REVIEW.md`,
fault 3, says how). Carry
both files to the server and to each sensor and run, as the
account that runs the product:

```bash
td-apply-update /media/usb/td-update-20261006.tar.gz
```

It checks the archive against its checksum and its own manifest, replaces what
the previous update installed, leaves your own files alone, and tells the
running engines to reload. The checksum shows the archive arrived intact, not
who made it: keep the media under your control.

The Emerging Threats rule set inside the Suricata image is not part of the
bundle. It is refreshed when you build new images with this kit, or
automatically if the server can reach the Internet and automatic rule updates
are switched on in `./scripts/configure`.

## Hardening

The base system is already hardened by the Malcolm project against a CIS and
DISA STIG derived baseline: a firewall that refuses everything except HTTPS,
SSH, time sync and a few transfer ports; SSH with keys only and no
root login; audit rules; long, mixed passwords; private file permissions; no
memory dumps. Its documented exceptions are in the built-in user guide under
"Hardening".

This kit adds (`HARDENING="true"` in `build.conf`):

| Addition | File on the installed system |
| --- | --- |
| Kernel settings: hidden kernel addresses, restricted process tracing, no unprivileged eBPF, no kernel replacement without reboot, no SysRq keys, protected links, SYN cookies | `/etc/sysctl.d/98-ot-ids-hardening.conf` |
| Kernel modules that cannot be loaded: DCCP, SCTP, RDS, TIPC, five unused filesystems, FireWire | `/etc/modprobe.d/ot-ids-hardening.conf` |
| SSH: no port or agent forwarding, at most 4 sessions per connection, limits on unauthenticated connections | appended to `/etc/ssh/sshd_config` |
| Login banner: authorised use only, activity is recorded | `/etc/issue`, `/etc/issue.net` |
| Idle SSH and console shells close after 15 minutes (`HARDEN_SHELL_TIMEOUT`); the desktop has its own screen lock, chosen at installation | `/etc/profile.d/ot-ids-session-timeout.sh` |
| Optional: USB sticks blocked (`HARDEN_USB_STORAGE_OFF="true"`) | same modprobe file |

USB storage is left on by default because captures and updates reach an
isolated network by USB. After installing, `sudo td-hardening-check` reports
whether each setting is in effect. It changes nothing.

Not done here, and worth doing on site: a boot loader password (the base
system leaves it off so the appliance restarts unattended), disk encryption
(choose "Encrypted" at the installer's boot menu), and the scheduled file
integrity check (AIDE is installed; the base system leaves scheduling to you).

## Branding

`BRAND_NAME` in `build.conf` sets the boot menu entries and the ISO file names.
The artwork in `overlay/branding/` is generated from `branding/logo.png` and
`branding/banner.png` by `tools/make-artwork.py` (needs Pillow).

| Place | What you see |
| --- | --- |
| Boot menu | Emblem above the menu, "TechDetechtives 26.09.0" title, "Install TechDetechtives" entry ("... Sensor" on the sensor ISO) |
| Desktop | Wallpaper and launcher icon |
| Web landing page | Header band with logo and wordmark, page title, footer line |
| Dashboards | Header logo, mark, loading logo, browser tab icon, title "TechDetechtives Dashboards" |
| Upload, extracted-files, account and error pages | Banner or tab icon, product name |
| Dashboard reports | Put `![TechDetechtives](/assets/img/brand-report-header.png)` in the report definition's Header field |

Arkime and NetBox keep their own logos inside their own screens. The built-in
user guide is Malcolm's, unchanged. The setup scripts and the OS variant name
still say Malcolm or Hedgehog. The landing page footer reads "TechDetechtives,
built on Malcolm ... (c) Battelle Energy Alliance, LLC"; keep that attribution.

Web branding, the anomaly detectors, the monitors, the baseline and profile
programs and the protocol event rules live in thin layers added on top of
seven official images and stored under the official image names. They
need `INCLUDE_IMAGES="true"` (the default), and running `docker compose pull`
on an installed system replaces those images with the plain upstream ones.

## Installing

1. Write the ISO to USB or attach it to a VM, and boot it.
2. Choose **Install TechDetechtives**.
   **The installer partitions and formats every non-removable disk in the
   machine without asking.** Use dedicated hardware or a dedicated VM.
3. Answer the prompts (hostname, user, passwords). No network is needed, and
   the installer asks for no network interface.
4. On first boot, wait for the "loading images" dialog to finish.
5. In a terminal:

   ```bash
   cd ~/Malcolm
   ./scripts/auth_setup     # web admin account and certificates
   ./scripts/configure      # capture interface, HOME_NET, storage, NetBox, retention
   ./scripts/start
   sudo td-hardening-check
   ```

   Two answers in `./scripts/configure` where the product's default is not
   what this kit needs:

   - **File Extraction Mode** is `none` as shipped: no file is taken from the
     traffic, so the file scanner and every YARA rule have nothing to do.
     Choose `interesting` (or `notcommtxt`, `mapped`, `all`) and leave "Scan
     with Strelka" on. Extracted files take disk space; "File Preservation"
     says which are kept.
   - **Arkime PCAP Management**, or on a system installed from the ISO
     **Prune Oldest PCAP**, deletes the oldest captured packets when the disk
     runs full. Both are off as shipped, and the disk then fills. With one of
     them on, how far back an incident can be replayed is the size of the
     capture disk divided by your traffic.

   **Network interfaces.** Nothing asks for a management interface and a
   monitoring interface as a pair. They are set in two places (read in the
   product's source and install guide, not tried here):

   - **Management:** by you, after the first boot, with the network icon in
     the desktop's tray (Edit Connections). No interface gets an address by
     itself, not even by DHCP; the product recommends a static one.
   - **Monitoring:** in `./scripts/configure`, which also opens by itself the
     first time you log in. Answer yes to "Capture Live Network Traffic" (the
     default is no), then name the interface under "Capture Interface(s)";
     several are separated by commas, and nothing is preselected
     (`ip -br link` lists the names). Then choose who reads it: "Analyze Live
     Traffic with Zeek" and "with Suricata", and a packet capture
     (netsniff-ng, tcpdump or Arkime). Leave "Optimize Interface Settings for
     Capture" on for an interface used for capture alone.
   - Give the monitoring interface no address: in the same network editor set
     its IPv4 method to "Disabled". Use two interfaces; capturing on the
     management interface works, and mixes the appliance's own traffic in.
   - With a separate sensor, answer no to live capture on the server and yes
     on the sensor.

6. Browse to `https://<server address>/`.

Server sizing from the Malcolm project: 8 cores and 24 GB RAM minimum, 16+
cores and 32+ GB RAM recommended, and as much SSD storage as you can give it.

## Also in this folder

- `overlay/malcolm/`: anything here is added to `~/Malcolm` on the installed
  system (`suricata/rules/`, `zeek/custom/`, `yara/rules/`, `netbox/preload/`).
- `attack/` and `tools/attack_ics.py`: the ATT&CK for ICS reference, the
  mapping tables, and the tool that tags rules and writes the coverage reports.
- `docs/ATTACK-ICS-COVERAGE.md`, `.csv` and `docs/attack-ics-layer.json`: the
  coverage of the detections kept in this repository. Generated; the tests
  fail if they fall behind the tables.
- `baseline/td_baseline.py`: the baseline program; `attack/baseline-findings.csv`
  maps its findings to ATT&CK for ICS. `baseline/td_profile.py`: the traffic
  profile. `baseline/td_replay.py`: the incident replay report.
- `docs/INCIDENT-REPLAY.md`: what the appliance can do to replay an incident
  from captured packets, how, and where it stops.
- `hardening/rootfs/usr/local/lib/techdetechtives/td_pcap_order.py`: puts the
  packets of a capture file in time order (`td-pcap-order` on the server).
- `tools/yara_sources.py`: lays out external YARA rule files so the product
  compiles them (`check FOLDER` compiles them with the yarac on your machine).
  `tools/protocol_events.py`: says which of Suricata's own industrial event
  rules a rule file has active, and switches them on.
- `docs/AI-NIDS-REVIEW.md`, `docs/PROJECT-REVIEWS.md`,
  `docs/ANOMALY-DETECTION-REVIEW.md` and `docs/LISTED-REPOSITORIES-REVIEW.md`:
  reviews of 40 outside projects (two could not be fetched), and what was and
  was not taken from each.
- `tests/`: run with `python3 -m unittest discover -s ot-ids/tests -v`, or
  through `scripts/verify.sh repo`.

## Licences

Malcolm is Apache 2.0, Copyright Battelle Energy Alliance, LLC. Keep its
`LICENSE.txt` and `NOTICE.txt` with anything you distribute; the build also
drops a `techdetechtives-NOTICE.txt` in `~/Malcolm` saying what was changed.
JA4+ (used by Zeek and Arkime in Malcolm) has its own FoxIO licence; read it
before selling the product. Each external source keeps its own licence, listed
in `sources.conf` and in `EXTERNAL-SOURCES.txt` on the installed system; the
YARA rule sets carry their licence files with them, and one of those that are
on by default, Elastic's, is under the Elastic License 2.0, which is not an
open-source licence.
`attack/ics-attack.json` and the pages made from it reproduce parts of MITRE
ATT&CK, © 2026 The MITRE Corporation, under MITRE's ATT&CK terms of use; the
copyright line and the licence are inside each file and must stay there. The
other files in this folder are MIT, like the rest of the original work in this
repository. See `NOTICE.md` at the top of the repository. This is not legal
advice.

## Test status

Run and passing in the author's environment (2026-10-07):

- `ot-ids/tests` (190 tests): rule structure and reserved numbers; every flag a
  correlation alert waits for is set by a marker; byte-position rules against
  sample UMAS, S7, IEC 104, Modbus, BACnet and TFTP packets, including
  look-alikes that must not match; the nine YARA rules compiled and run by
  YARA 4.5.8 against generated samples; the Snort converter (Snort 2 and the
  Snort 3 forms it takes), pruning, indicator converter, vulnerability index
  and source list; the YARA source handling, on awkward rule text and on a
  repository made for the test; the protocol-event tool; the build's settings
  helper; the shape of the detectors, monitors, suppression file and hardening
  files. For ATT&CK for ICS: every rule in the
  repository has a row in the mapping, every technique and tactic named exists
  in the reference, tagging adds only the technique to a rule and does it
  once, and the coverage files in `docs/` match what the tool writes.
- **New in 0.13.0, measured with the product's own script.** All ten YARA
  sources were fetched from GitHub. Malcolm's start-up script
  (`strelka/backend/yara_rules_setup.sh`, unchanged but for one temporary-file
  path) was run with YARA 4.5.8 over this kit's rule files alone and replaced a
  stand-in compiled set with 21 rules: the fault. Run over the kit's files and
  the eight default sources it compiled 3,155 of 3,173 files into 10,656 rules
  in about a minute; with the two optional sources, 3,665 of 3,691 files and
  11,979 rules. Neither set hit any of 7,407 ordinary files of a Linux machine.
  The namespace this kit computes for each file agreed with the script's for
  every file.
- **Measured again for 0.14.1, with CAPE off.** The product's own script and
  YARA 4.5.8 compiled 3,155 of the 3,173 rule files (this kit's and the eight
  default sources) into 10,656 rules in about a minute. That set hit none of
  a sample of 7,407 files of this Linux machine (programs, libraries, scripts
  and documents under `/usr` and `/opt`) and none of the 1,224 programs in
  `/usr/bin`, `/usr/sbin` and `/usr/libexec`; among the 82 in
  `/usr/local/bin` one rule that names the file-transfer tool rclone found an
  rclone program, which is what it is for. The same scan finds the EICAR test
  file. With CAPE on (0.14.0) the same measurement gave 3,315 of 3,333 files
  and 10,879 rules, with the same hits, after one CAPE rule file was left out:
  its rule fired on Docker's daemon (found by the reviewer; the sample did
  not hold that file).
- The replay report (22 tests) against a stand-in for OpenSearch holding a
  made-up intrusion as records of the shapes the product stores: the list of
  uploaded captures, without the tags the product or a rule adds; a capture
  found by its tag with its period looked up; a period of live traffic with
  uploads left out; a tag with a period; the tactics in order; rule alerts,
  Zeek notices and signatures, indicator matches, file-scan hits and monitor
  alerts; the comparison with a baseline that is only read, or that cannot be
  read; an IPv6 master; hostile text in a rule name, on screen and in
  Markdown; a search that fails; a report that cannot be written; every
  output format. The ordering tool (7 tests) on capture files made byte by
  byte: a session-by-session export, equal times, both byte orders,
  nanosecond times, a packet cut off, 20,000 packets, and what it refuses;
  deliberately broken copies of the tool failed them. That the baseline
  leaves uploaded captures out, takes them when told to, and says when all
  traffic is marked as uploaded (5 tests); the profile's periods and tags
  (3 tests).
- **What the product can do to replay an incident was read, not run**: in the
  source of Malcolm 26.09.0, Suricata 8.0 and Arkime 6.7.0, file by file
  ([`docs/INCIDENT-REPLAY.md`](docs/INCIDENT-REPLAY.md) names them).
- An independent review of the 0.14.0 work confirmed from the same sources
  that Zeek's, Suricata's and Arkime's records of an uploaded capture carry
  the `-upload` node name and the file-name tags, the field names the report
  reads, the settings quoted and the YARA numbers. It made twelve findings
  against the first version, all corrected: three traps of replaying that the
  first version did not know (an Arkime export is not in time order; a
  repeated file is skipped; Suricata keeps alert limits between files); a
  file-scan hit listed four times and an indicator match without a name,
  because the test records had been shaped by belief and not by the product's
  pipeline; a capture mode in which the corrected baseline would read
  nothing; and smaller ones.
- The traffic profile (31 of the 190 tests) against a stand-in for OpenSearch
  that answers its one search from connection records held in memory: each
  list, connections that began before the period, connections still open, a
  search that fails or answers in part, more records than one report takes,
  hostile text, every output format, a period in the past, a capture by tag.
- The Snort 3 conversions; the table of 67 IEC 104 type names was compared with
  Snort 3's source by program. The protocol-event tool against Suricata 8.0's
  own rule files (18 of 18 rules added to an empty file).
- An independent review of the 0.13.0 work confirmed the four faults, the byte
  positions, that the stream-depth setting reaches the engine, the YARA
  numbers, the suppression file's line forms and the DNP3 monitor's field
  names against the sources, and made eleven findings against the first
  version; all are corrected
  ([`docs/LISTED-REPOSITORIES-REVIEW.md`](docs/LISTED-REPOSITORIES-REVIEW.md),
  last section).
- The baseline program (59 of the 190 tests) against a stand-in for the
  product: a small web server that works out the one OpenSearch search the
  program makes from records held in memory, and takes alerts the way the
  product's webhook does. Learning, each kind of finding, late records, a
  sensor outage, a search that fails or answers in part, a webhook that is
  down or refuses, a wrong clock, limits and every command are covered.
- An independent review of the baseline program's first version demonstrated
  fifteen defects; all are fixed and each has a test. The same review checked
  the search against the source and documentation of OpenSearch 3.8 (the
  version the product ships) and the webhook, the container's user, volume,
  environment and crontab against the product's source.
- Every technique identifier and name in the mapping tables was read from
  MITRE's data file (attack-stix-data commit `6cda5ad`, ATT&CK for ICS 19.2),
  not written from memory. Tagging and the coverage report were run on the
  real ELITEWOLF, Quickdraw and Nmap rule sets: 177 rules given a technique,
  38 reviewed and left without one, none left unreviewed.
- A second reviewer, with no part in writing the mapping, checked every row
  against MITRE's descriptions and the rule bodies, rebuilt the reference
  from MITRE's file by its own code (no differences) and recounted the
  figures above. Its findings were applied: mappings that claimed too much
  were lowered or removed, the tagger was made safe for rules with several
  metadata options, and two rules were corrected (next point).
- **Corrected in this version:** the two Schneider UMAS program-transfer rules
  (1900503, 1900504) had their function numbers the wrong way round since
  0.10.0, so a program written to a controller was reported as a read-out and
  the reverse. The public UMAS write-ups name the transfers from the PC's
  side, the opposite of automation practice. Checked against two public
  sources (a Wireshark dissector and Digital Bond's transfer module); both
  rules are now revision 2.
- The Snort converter on the real ELITEWOLF and Quickdraw rule sets: 110 of 110
  rules converted. The Nmap rule set imported from its repository: 8 rules,
  2 left out on purpose.
- `prepare` and `sources` against the real Malcolm v26.09.0 source and the
  twelve GitHub-hosted sources that are on by default (three rule sets, the
  threat feeds, eight YARA sets); the stream-depth line was read back from the
  prepared `config/suricata.env.example`.
- `tools/make-update-bundle.sh`, and `td-apply-update` against a mock product
  folder: install, re-install with a stale file, and a tampered archive.
- The `images` stage against a stand-in for Docker that checks each added
  layer's files and destinations and imitates the engine's refusal of a rule,
  the file scanner's answer and the Suricata image's rule file. The script the
  YARA check runs inside the product's image was also run here, with its paths
  pointed at a copy, against the product's real script: a broken file, and a
  compile that fails.
  The layer 2 watch step with the stand-in accepting it and then refusing it on
  a later run (the script is removed again), and the ATT&CK coverage report
  following suit (Adversary-in-the-Middle covered, then listed as a gap).

Not run, because the author's environment has no Docker, no Suricata, no Zeek
and no VM:

- **No rule here has been loaded by Suricata.** The `images` stage does that on
  your build host; read `out/rule-check.txt` afterwards. That includes the
  three rules rewritten in 0.13.0.
- **Nothing added in 0.13.0 has run in the product.** Not seen: Suricata with
  stream depth 0, or reading the suppression file; the layer on the Suricata
  image, and what that image's rule file really holds (worked out from three
  sources; the build reads it back and reports); the product's file scanner
  compiling the fetched YARA rules (its YARA is 4.5.5 with two more modules, so
  its counts will differ a little from the ones above; the build runs the
  product's own script in its own image and reports); the traffic profile
  against a real OpenSearch (run `td-profile --hours 1` first: an error names
  what OpenSearch refused); the DNP3 monitor being imported.
- **Nothing added in 0.14.0 has run in the product.** No capture has been
  uploaded to it here. Not seen: that an uploaded capture's records carry the
  words of its file name as tags and a node name ending in `-upload` (both
  read in the product's source; the baseline's and the profile's leaving
  uploads out, and `td-replay` finding a capture, rest on them); the fields
  the replay report reads (`event.kind`, `rule.name`, `event.severity`,
  `threat.*`) in real records, and whether OpenSearch accepts each of its
  searches; Suricata forgetting its per-address flags and keeping its alert
  limits between two uploaded files; the product skipping a repeated file;
  the order of a real Arkime export, and what Suricata and Zeek make of one
  before and after `td-pcap-order`; a file-scan hit from a replayed capture;
  the image layer that carries `td_replay.py`. `td-replay list` naming a
  capture you uploaded is the first check; `td-replay report` on a quiet hour
  of live traffic the second; one file replayed under two names, with and
  without the restart of Suricata, the third.
- The count of ordinary files hit by the YARA rule sets is a rough measure from
  one Linux machine, with few Windows programs and Office documents on it.
  Rules that are quiet there can still be noisy on files from a plant.
- Whether one Modbus request can count twice toward rule 1900406's "ten in a
  minute", once on the packet and once on the reassembled stream, was not
  established.
- No rule has been run against plant traffic. Expect to tune.
- The anomaly detectors and monitors have not been imported into OpenSearch.
  If one is refused, the others still load and the platform is unaffected.
- **No tagged alert has been seen in the running product.** That the four
  metadata keys become the `threat.*` fields was read in Malcolm's Logstash
  pipeline (`logstash/pipelines/suricata/11_suricata_logs.conf`), and that
  Suricata accepts any text as metadata was read in its source; neither was
  watched happening. The Navigator layer has not been opened in Navigator.
- **The baseline program has not read from a real OpenSearch or sent an
  alert to the real webhook**, and the image layer that installs it has not
  been built. Its stand-in was written by the same hand, so it cannot catch a
  wrong belief about the product; the review above narrowed that, and
  `td-baseline check` and `td-baseline test-alert` are there to settle it on
  an installed system. How long its search takes on a busy plant, and what the
  decoders really call S7 and BACnet operations, are unknown.
- The mapping is one reviewer's reading of MITRE's descriptions. Nobody else
  has checked it, and it has not been compared with a real incident.
- The download of sources outside GitHub (CISA, Snort, abuse.ch) was blocked
  where this was written; the code path is the same as for the tested ones.
- The layer 2 watch was tested with Zeek 7.0.11 (see `MODIFICATIONS.md`); the
  product ships Zeek 8.2.2, which has not parsed it yet. The build decides.
- The hardening files have not been booted. `td-hardening-check` reports what
  took effect.
- The image downloads, the added image layers, the legacy-BIOS splash
  conversion and the ISO build itself.

If a stage fails, the cause is in the console output or `out/*-build.log`.
