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
| `./build-iso.sh prepare` | Clones the pinned Malcolm release; applies name, logo and artwork; adds the detection content (with each rule's ATT&CK for ICS technique) and the hardening files |
| `./build-iso.sh sources` | Downloads the rule sets and threat feeds enabled in `sources.conf`, converts them, adds them |
| `./build-iso.sh images` | Pulls the container images, adds the branded and detection layers, packs them; checks every rule with the product's own Suricata; writes the vulnerability and ATT&CK for ICS coverage reports |
| `./build-iso.sh iso` | Runs the live-build and writes the ISOs to `out/` |

Run `prepare` again after changing `build.conf`, `overlay/`, `detections/`,
`iocs/` or `hardening/`. To rebuild the image bundles, delete
`work/*_images.tar.xz`.

Reports in `out/`:

- `rule-check.txt`: the engine's verdict on each rule file, and any rule it
  refused. Refused rules are commented out (`#PRUNED`) in the ISO, not dropped
  silently.
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

### Anomaly detectors and correlation monitors

Three detectors for the platform's anomaly detection (it learns each plant's
own normal, no attack samples needed) and three alert monitors are added to the
server. Like the platform's own examples they arrive **switched off**:

| Name | Where | What it flags |
| --- | --- | --- |
| `techdetechtives_ot_protocol_activity` | Dashboards > Anomaly Detection | An industrial protocol far busier or quieter than its own history |
| `techdetechtives_ot_operations` | same | An unusual amount of one operation in a protocol, such as a burst of writes |
| `techdetechtives_ot_peers` | same | A machine talking industrial protocols to more devices than it usually does |
| TechDetechtives OT Correlation Alert Monitor | Dashboards > Alerting | Any alert from the correlation rules |
| TechDetechtives Multi-Signal Host Monitor | same | One address with two or more kinds of evidence in 15 minutes: a rule alert, a threat-indicator match, an ATT&CK technique notice, a file signature hit |
| TechDetechtives ATT&CK for ICS Tactic Chain Monitor | same | One address seen under three or more ATT&CK for ICS tactics in 24 hours, counting tagged rule alerts and ACID notices |

Start a detector after a week or two of normal traffic has been recorded, so
it has something to learn from. Enable a monitor and point its action at your
own notification channel (e-mail, webhook).

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
industrial ones that are not. Both files are copied to `~/Malcolm/` on the
installed system.

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
external rule sets, YARA rules, indicators and the technique reference. Carry
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

Web branding, the anomaly detectors and the monitors live in thin layers added
on top of six official images and stored under the official image names. They
need `INCLUDE_IMAGES="true"` (the default), and running `docker compose pull`
on an installed system replaces those images with the plain upstream ones.

## Installing

1. Write the ISO to USB or attach it to a VM, and boot it.
2. Choose **Install TechDetechtives**.
   **The installer partitions and formats every non-removable disk in the
   machine without asking.** Use dedicated hardware or a dedicated VM.
3. Answer the prompts (hostname, user, passwords). No network is needed.
4. On first boot, wait for the "loading images" dialog to finish.
5. In a terminal:

   ```bash
   cd ~/Malcolm
   ./scripts/auth_setup     # web admin account and certificates
   ./scripts/configure      # capture interface, HOME_NET, storage, NetBox, retention
   ./scripts/start
   sudo td-hardening-check
   ```

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
- `docs/AI-NIDS-REVIEW.md` and `docs/PROJECT-REVIEWS.md`: reviews of six
  outside projects, and what was and was not taken from each.
- `tests/`: run with `python3 -m unittest discover -s ot-ids/tests -v`, or
  through `scripts/verify.sh repo`.

## Licences

Malcolm is Apache 2.0, Copyright Battelle Energy Alliance, LLC. Keep its
`LICENSE.txt` and `NOTICE.txt` with anything you distribute; the build also
drops a `techdetechtives-NOTICE.txt` in `~/Malcolm` saying what was changed.
JA4+ (used by Zeek and Arkime in Malcolm) has its own FoxIO licence; read it
before selling the product. Each external source keeps its own licence, listed
in `sources.conf` and in `EXTERNAL-SOURCES.txt` on the installed system.
`attack/ics-attack.json` and the pages made from it reproduce parts of MITRE
ATT&CK, © 2026 The MITRE Corporation, under MITRE's ATT&CK terms of use; the
copyright line and the licence are inside each file and must stay there. The
other files in this folder are MIT, like the rest of the original work in this
repository. See `NOTICE.md` at the top of the repository. This is not legal
advice.

## Test status

Run and passing in the author's environment (2026-10-06):

- `ot-ids/tests` (46 tests): rule structure and reserved numbers; every flag a
  correlation alert waits for is set by a marker; byte-position rules against
  sample UMAS, S7, IEC 104, Modbus, BACnet and TFTP packets, including
  look-alikes that must not match; the nine YARA rules compiled and run by
  YARA 4.5.8 against generated samples; the Snort converter, pruning, indicator
  converter, vulnerability index and source list; the shape of the detectors,
  monitors and hardening files. For ATT&CK for ICS: every rule in the
  repository has a row in the mapping, every technique and tactic named exists
  in the reference, tagging adds only the technique to a rule and does it
  once, and the coverage files in `docs/` match what the tool writes.
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
  three GitHub-hosted sources.
- `tools/make-update-bundle.sh`, and `td-apply-update` against a mock product
  folder: install, re-install with a stale file, and a tampered archive.
- The `images` stage against a stand-in for Docker that checks each added
  layer's files and destinations and imitates the engine's refusal of a rule.
  The layer 2 watch step with the stand-in accepting it and then refusing it on
  a later run (the script is removed again), and the ATT&CK coverage report
  following suit (Adversary-in-the-Middle covered, then listed as a gap).

Not run, because the author's environment has no Docker, no Suricata, no Zeek
and no VM:

- **No rule here has been loaded by Suricata.** The `images` stage does that on
  your build host; read `out/rule-check.txt` afterwards.
- No rule has been run against plant traffic. Expect to tune.
- The anomaly detectors and monitors have not been imported into OpenSearch.
  If one is refused, the others still load and the platform is unaffected.
- **No tagged alert has been seen in the running product.** That the four
  metadata keys become the `threat.*` fields was read in Malcolm's Logstash
  pipeline (`logstash/pipelines/suricata/11_suricata_logs.conf`), and that
  Suricata accepts any text as metadata was read in its source; neither was
  watched happening. The Navigator layer has not been opened in Navigator.
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
