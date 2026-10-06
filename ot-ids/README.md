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

The ISOs, their checksums, the build logs and three reports land in `out/`.
Expect well over an hour. Settings are in `build.conf`.

| Stage | What it does |
| --- | --- |
| `./build-iso.sh prepare` | Clones the pinned Malcolm release; applies name, logo and artwork; adds the detection content and the hardening files |
| `./build-iso.sh sources` | Downloads the rule sets and threat feeds enabled in `sources.conf`, converts them, adds them |
| `./build-iso.sh images` | Pulls the container images, adds the branded and detection layers, packs them; checks every rule with the product's own Suricata; writes the vulnerability coverage report |
| `./build-iso.sh iso` | Runs the live-build and writes the ISOs to `out/` |

Run `prepare` again after changing `build.conf`, `overlay/`, `detections/`,
`iocs/` or `hardening/`. To rebuild the image bundles, delete
`work/*_images.tar.xz`.

Reports in `out/`:

- `rule-check.txt`: the engine's verdict on each rule file, and any rule it
  refused. Refused rules are commented out (`#PRUNED`) in the ISO, not dropped
  silently.
- `vulnerability-coverage.csv` and `.md`: see "Vulnerability coverage" below.
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
on EtherNet/IP, S7 and BACnet behaviour. No Zeek scripts are added here: a
script that fails to load stops Zeek, and this build has no way to run Zeek
before the ISO exists.

### Anomaly detectors and correlation monitors

Three detectors for the platform's anomaly detection (it learns each plant's
own normal, no attack samples needed) and two alert monitors are added to the
server. Like the platform's own examples they arrive **switched off**:

| Name | Where | What it flags |
| --- | --- | --- |
| `techdetechtives_ot_protocol_activity` | Dashboards > Anomaly Detection | An industrial protocol far busier or quieter than its own history |
| `techdetechtives_ot_operations` | same | An unusual amount of one operation in a protocol, such as a burst of writes |
| `techdetechtives_ot_peers` | same | A machine talking industrial protocols to more devices than it usually does |
| TechDetechtives OT Correlation Alert Monitor | Dashboards > Alerting | Any alert from the correlation rules |
| TechDetechtives Multi-Signal Host Monitor | same | One address with two or more kinds of evidence in 15 minutes: a rule alert, a threat-indicator match, an ATT&CK technique notice, a file signature hit |

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
TechDetechtives rules, the enabled external rule sets, YARA rules and
indicators. Carry both files to the server and to each sensor and run, as the
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
- `docs/AI-NIDS-REVIEW.md`: a review of the AI-Based-Network-IDS project and
  what was and was not taken from it.
- `tests/`: run with `python3 -m unittest discover -s ot-ids/tests -v`, or
  through `scripts/verify.sh repo`.

## Licences

Malcolm is Apache 2.0, Copyright Battelle Energy Alliance, LLC. Keep its
`LICENSE.txt` and `NOTICE.txt` with anything you distribute; the build also
drops a `techdetechtives-NOTICE.txt` in `~/Malcolm` saying what was changed.
JA4+ (used by Zeek and Arkime in Malcolm) has its own FoxIO licence; read it
before selling the product. Each external source keeps its own licence, listed
in `sources.conf` and in `EXTERNAL-SOURCES.txt` on the installed system. The
files in this folder are MIT, like the rest of the original work in this
repository. See `NOTICE.md` at the top of the repository. This is not legal
advice.

## Test status

Run and passing in the author's environment (2026-10-06):

- `ot-ids/tests` (30 tests): rule structure and reserved numbers; every flag a
  correlation alert waits for is set by a marker; byte-position rules against
  sample UMAS, S7, IEC 104, Modbus, BACnet and TFTP packets, including
  look-alikes that must not match; the nine YARA rules compiled and run by
  YARA 4.5.8 against generated samples; the Snort converter, pruning, indicator
  converter, vulnerability index and source list; the shape of the detectors,
  monitors and hardening files.
- The Snort converter on the real ELITEWOLF and Quickdraw rule sets: 110 of 110
  rules converted.
- `prepare` and `sources` against the real Malcolm v26.09.0 source and the
  three GitHub-hosted sources.
- `tools/make-update-bundle.sh`, and `td-apply-update` against a mock product
  folder: install, re-install with a stale file, and a tampered archive.
- The `images` stage against a stand-in for Docker that checks each added
  layer's files and destinations and imitates the engine's refusal of a rule.

Not run, because the author's environment has no Docker, no Suricata, no Zeek
and no VM:

- **No rule here has been loaded by Suricata.** The `images` stage does that on
  your build host; read `out/rule-check.txt` afterwards.
- No rule has been run against plant traffic. Expect to tune.
- The anomaly detectors and monitors have not been imported into OpenSearch.
  If one is refused, the others still load and the platform is unaffected.
- The download of sources outside GitHub (CISA, Snort, abuse.ch) was blocked
  where this was written; the code path is the same as for the tested ones.
- The hardening files have not been booted. `td-hardening-check` reports what
  took effect.
- The image downloads, the added image layers, the legacy-BIOS splash
  conversion and the ISO build itself.

If a stage fails, the cause is in the console output or `out/*-build.log`.
