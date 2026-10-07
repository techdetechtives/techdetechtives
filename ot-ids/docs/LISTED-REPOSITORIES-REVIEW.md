# Nineteen listed projects: what each is, what was adopted, and what the review found wrong here

Reviewed 2026-10-06, at the commits named below. The code was read; nothing
from the nineteen was run, with three exceptions: the YARA rules were compiled
and run with YARA 4.5.8, git fetched the repositories, and one script from the
product itself (Malcolm's `strelka/backend/yara_rules_setup.sh`) was run over
the rule files. Earlier reviews are in `AI-NIDS-REVIEW.md`,
`PROJECT-REVIEWS.md` and `ANOMALY-DETECTION-REVIEW.md`.

**Outcome.** Of the nineteen, two could not be read, eleven had nothing this
appliance can use, and six left something behind: Suricata, Snort 3,
Yara-Rules/rules, RITA, VulnRadar and advanced-port-scanner. No code was
copied from any of them. The most useful result was not an adoption at all.
Reading Suricata's and the product's own source for this review turned up four
faults in the kit as it stood, two of them serious. They come first.

## Four faults this review found in the kit

### 1. Three Modbus rules could never match

Rules 1900103, 1900406 and 1900451 were written as `modbus: function 43,
subfunction 14` (Read Device Identification). Suricata compares the
`subfunction` option for function 8, Diagnostics, and for nothing else
(Suricata 8.0, `rust/src/modbus/detect.rs`, `SCModbusInspect`). With any other
function the rule loads without complaint, `suricata -T` passes, and it never
fires. Rule 1900451 is the marker that starts correlation chain 1, so "an
address identifies controllers, then changes one" could not start from a
Modbus identification either.

**Fixed.** The three rules now read the bytes: Modbus/TCP protocol identifier
zero, then `2b 0e` at bytes 7 and 8. Tests check that an identification
request matches and that the CANopen interface of the same function, a refusal
(function `ab`), a diagnostics request and a register read carrying the same
two bytes do not. A test in both test suites now fails any rule that writes
`subfunction` with a function other than 8.

### 2. Suricata stopped reading each connection after one megabyte

The product sets Suricata's stream reassembly depth to 1 MB
(`STREAM_REASSEMBLY_DEPTH` in its `suricata_config_populate.py`). After that
much of a connection, Suricata's decoders see no more of it. A master keeps
one Modbus, DNP3 or EtherNet/IP connection open for days and passes 1 MB
within a day or so of steady polling, so every rule that uses a decoder keyword (`modbus:`,
`dnp3_func`, `cip_service`, and the rest) went blind on exactly the
connections that matter. Suricata's own configuration file says to set the
depth to 0 for Modbus. The product also sets a Modbus-only depth of 0, but
Suricata's Modbus parser does not read that setting (there is no such lookup in
`rust/src/modbus/modbus.rs`; the SMB parser has one).

**Fixed.** `./build-iso.sh prepare` writes
`SURICATA_STREAM_REASSEMBLY_DEPTH=0` into the product's
`config/suricata.env.example`, which the installed system starts from.
`SURICATA_STREAM_DEPTH` in `build.conf` changes or removes it. The price is
more work and memory on large transfers, because every connection is now
followed to its end.

### 3. The kit's YARA rules took the place of the product's own, thousands for 21

This is the serious one, and it has been true of every version of this kit.

The product's file scanner loads one compiled rule file. Its image is built
with nine public rule repositories compiled into that file, and the rule
sources are then deleted from the image
(`Dockerfiles/strelka-backend.Dockerfile`, lines 78 to 81). At every start the
scanner compiles again from whatever rule files it can find
(`strelka/backend/yara_rules_setup.sh`). With no Internet, those are only the
files in `./yara/rules`. If that folder is empty the script keeps the compiled
file it has ("refusing to generate empty compiled set"). If the folder holds a
single rule file, the script compiles that folder alone and replaces the
compiled file with the result.

This kit put its own 21 rules in that folder. On an installed system with no
Internet, the scanner would therefore have run with those 21 rules and without
the thousands the product is built with.

*Shown by simulation, not on an installed system.* Malcolm's own script was run
here over a stand-in compiled file and the kit's four rule files: the result
was a 21-rule compiled file, with the old one kept beside it as
`rules.compiled.prev`. The image itself was not available.

**Fixed, in three parts.**

- The nine repositories are now sources in `sources.conf` (kind `yara-git`),
  fetched at build time and put in `./yara/rules` beside the kit's rules, each
  file under a unique name. All nine are on by default since 0.14.0. The
  ninth, CAPE Sandbox, is GPL-3.0; in 0.13.0 it was off, like every source
  under the GPL here, and the owner then switched it on. Inside the others,
  files that state a non-commercial licence (13, all in signature-base) or
  name the GPL in their header (2) are left out.
- YARA rules go in together or not at all. If any YARA source that is switched
  on could not be fetched, or none is switched on, no YARA rule goes into the
  ISO, the kit's own included, so the product keeps its compiled set; the build
  says so. An update bundle is not written at all in that case.
- The `images` stage runs the product's own script in the product's own image
  over the rule files going into the ISO, and writes to `out/rule-check.txt`
  how many rules the image came with and how many the scanner will have. It
  warns if the compile of all files together fails (the scanner would then use
  none of them) or if the second number is far below the first.

Measured here, with Malcolm's script and YARA 4.5.8 (built with the hash
module, without the cuckoo and magic modules the product's build has):

| Rule files in `./yara/rules` | Files that compile | Rules | Start-up compile | Hits on 7,407 ordinary files |
| --- | ---: | ---: | ---: | ---: |
| The kit's four files alone (before) | 4 | 21 | under 1 s | 6, all one rule (now corrected, see below) |
| The kit's files and eight sources, without CAPE (the 0.13.0 default) | 3,155 of 3,173 | 10,656 | 60 s | 0 |
| The kit's files and all nine, one CAPE file left out (the default since 0.14.0) | 3,315 of 3,333 | 10,879 | 57 s | 0 |
| The same and the optional `yara-rules-legacy` | 3,665 of 3,691 | 11,979 | 70 s | 0 |

The namespace the kit computes for each file was compared with the one
Malcolm's script gives, for every file the script compiled: no difference, no
duplicate. A start of the file scanner now costs about a minute of compiling
on the server.

Three things to know about the result:

- **It is a little smaller than what the product is built with.** The reviewer
  of this change ran the product's build step over the nine repositories at the
  pinned commits and counted 10,995 rules; the default here gives 10,879
  (10,656 in 0.13.0, before CAPE's rules were switched on). The two sets are
  not the product's minus a few files: the files left out here for their
  licence hold some 340 rules, so this layout must also keep some 220 rules
  the product's build loses. Which those are was not established. Set
  `skip_noncommercial = no` if your use allows.
- **Do not switch the product's own rule updates on as well.** With Internet
  access and `RULES_UPDATE_ENABLED=true` the product fetches the nine
  repositories itself, and every rule would then be compiled, and match, twice.
  In that case turn the `yara-*` sources off.
- **Two rule files of your own with one name in different folders** get one
  namespace from the product; if they also share a rule name the product's
  compile fails and it uses none of the files. The build check reports that.

An installed system built from an earlier version of this kit has the fault.
An update bundle made with this version (`tools/make-update-bundle.sh`) carries
the rule sources and corrects it when applied. A bundle carries rules, YARA
rules and indicators only: the other three corrections here (stream depth, the
event rules, the suppression file) reach an installed system by a new ISO, or
by hand: add `SURICATA_STREAM_REASSEMBLY_DEPTH=0` to
`~/Malcolm/config/suricata.env` and copy the two `td-threshold` files into
`~/Malcolm/suricata/include-configs/`, then restart.

### 4. Suricata's own Modbus and DNP3 event rules are probably switched off in the product

Suricata's decoders raise an event when a message breaks its protocol, and
Suricata ships one rule per event (`modbus-events.rules`, `dnp3-events.rules`,
`enip-events.rules`). The product's Suricata image builds its rule file with
`suricata-update` while Suricata's configuration is still the packaged
default, in which Modbus, DNP3 and EtherNet/IP are disabled. `suricata-update`
comments out every rule for a disabled protocol (`main.py`, "Disabling rules
for protocol"). The product enables the three protocols when it starts and does
not build the rule file again unless rule updates are switched on.

*Read from three sources, not seen in a built image:* Malcolm 26.09.0
`Dockerfiles/suricata.Dockerfile`, Suricata 8.0 `suricata.yaml.in`,
suricata-update 1.3.8. If Debian's package enables the protocols, the rules are
on already.

**Handled either way.** The `images` stage reads the rule file out of the image
and writes to `out/rule-check.txt` how many of the 18 event rules are active,
commented out or missing (the 16 for Modbus and DNP3 are expected commented
out; the two for EtherNet/IP missing, because `suricata-update` does not carry
that file). With `SURICATA_PROTOCOL_EVENTS="true"` (the default) a thin layer
on the Suricata image removes the comment mark from those rules and adds the
missing ones from Suricata's own files; no other rule is touched. On a link
that loses packets, rule 2250002 ("unsolicited response") will fire; the
suppression file below is for that. If rule updates are later switched on with
Internet access, `suricata-update` writes the rule file afresh: Modbus and DNP3
are then active by its doing and the two EtherNet/IP rules are gone again.

`ANOMALY-DETECTION-REVIEW.md` said that reads of too many registers and invalid
coil values were "already covered" by these rules. That was written without
checking that the rules were active. It is true once this version is installed
and `rule-check.txt` shows them active.

## The nineteen

| Project | Commit | Licence | What it is, from its code | Verdict |
| --- | --- | --- | --- | --- |
| **NIDS** | | | | |
| [OISF/suricata](https://github.com/OISF/suricata) | `215961d` (master), `b502742` (8.0.x) | GPL-2.0 | The engine the product already runs | **Faults 1, 2 and 4 found; suppression file added** |
| [snort3/snort3](https://github.com/snort3/snort3) | `14aeb09` | GPL-2.0 | A second engine, with inspectors for S7CommPlus, IEC 104, MMS and OPC UA that Suricata lacks; no rules in the repository | Not run. **The rule converter now reads Snort 3 syntax** |
| [RazEini/NetGuard](https://github.com/RazEini/NetGuard) | `aefa290` | MIT | A Python packet counter with a Grafana board that blocks addresses with iptables (`main.py`, line 112) | Nothing: it blocks, and a sensor on a mirror port must not |
| [pangerlkr/network-intrusion-detection-system](https://github.com/pangerlkr/network-intrusion-detection-system) | `f415629` | none | A web front end around a model whose training is a placeholder (`src/ml_model.py`); its entry point imports a module that is not in the repository | Nothing, and nothing could be copied |
| **Anomaly detection** | | | | |
| [IdahoLabUnsupported/gnn-network-anomaly-detection](https://github.com/IdahoLabUnsupported/gnn-network-anomaly-detection) | `a29c98a` | MIT | A research graph model; archived, and its README says not to use it in production; no trained weights | Nothing to ship |
| hed1ad/goguardml | not read | unknown | Could not be fetched: the address asks for a login (private or removed) | Not reviewed |
| [2024ChenYP/MAD-MulW](https://github.com/2024ChenYP/MAD-MulW) | `ebd4763` | none | A research model for Internet routing (BGP) data | Nothing: other data, and no licence |
| **CVE detection** | | | | |
| [ossf/cve-bin-tool](https://github.com/ossf/cve-bin-tool) | `64bef69` | GPL-3.0-or-later | Finds known-vulnerable components in files on a disk, by version strings; needs a vulnerability database of its own | Not adopted (below) |
| [adhamelsonny014-dot/advanced-port-scanner](https://github.com/adhamelsonny014-dot/advanced-port-scanner) | `c28c351` | MIT | One file that runs `nmap -sV` and looks services up online | Not adopted: it sends packets at devices. **One idea taken** |
| [RogoLabs/VulnRadar](https://github.com/RogoLabs/VulnRadar) | `1298e3f` | Apache-2.0 | A scheduled job that downloads vulnerability lists and opens issues for a watch-list of vendors | Its useful idea was already here; **two columns added** |
| **IOC detection** | | | | |
| [mobinert/HORUS](https://github.com/mobinert/HORUS) | `3ef39f7` | MIT | A Windows program that scores executables and can ask online reputation services | Nothing: Windows, online |
| [Jwaifull/IOCHunter](https://github.com/Jwaifull/IOCHunter) | `bc81c0c` | AGPL-3.0 | A desktop window that sends pasted indicators to four online services | Nothing: online only |
| [spyre-project/spyre](https://github.com/spyre-project/spyre) | `30ed708` | LGPL-3.0 | A YARA scanner for a computer's files and memory | Not for a network sensor |
| [Yara-Rules/rules](https://github.com/Yara-Rules/rules) | `0f93570` | GPL-2.0 | 12,911 YARA rules, last changed April 2022 | **Optional source, filtered, off by default; fault 3 found** |
| **Traffic profiling** | | | | |
| [activecm/rita](https://github.com/activecm/rita) | `1317d70` | GPL-3.0 | Beacons and long connections from Zeek logs; needs its own database | Not run. **Its measures are in the new traffic profile** |
| [kassam-99/Network-Analyzer](https://github.com/kassam-99/Network-Analyzer) | `43fcc75` | none | A script that probes the network and calls Internet services | Nothing: active, online, no licence |
| [GyulyVGC/sniffnet](https://github.com/GyulyVGC/sniffnet) | `85b30d4` | MIT or Apache-2.0 | A desktop traffic monitor with a window; no way to run it without one | Not installed: it is for a person at a screen |
| [dreadl0ck/netcap](https://github.com/dreadl0ck/netcap) | `0354978` | GPL-3.0 | A whole second sensor that turns packets into typed records | Not shipped: the product already has Zeek and Arkime doing that |
| **Related** | | | | |
| security-pr-guardian (PyPI) | not read | unknown | Could not be fetched: PyPI was not reachable where this was written | Not reviewed |

## What was adopted

### From Suricata: a way to quiet a rule for one address

The rule files said "suppress a known address rather than switching a rule
off" and gave no way to do it. There is one now:
`~/Malcolm/suricata/include-configs/td-threshold.config` on the installed
system, with commented examples. Nothing is suppressed as shipped. The line
forms were checked against the patterns in Suricata's
`src/util-threshold-config.c`. One thing to know, and the file says it: a
`threshold` line there replaces the rate a rule sets for itself.

Looked at and not taken: Suricata's `dataset` keyword as a list of allowed
engineering stations (the baseline program's "new master" does that with no
list to keep), and its newer keywords, none of which is for an industrial
protocol. Suricata 8.0 and its master branch have no decoder for IEC 104, S7,
MMS, OPC UA or BACnet. One reviewer's reading, not checked further: the CIP
decoder does not look inside an Unconnected Send (service 0x52), so a Stop or
Reset routed through a gateway that way would pass rules 1900141 and 1900142.

### From Snort 3: its rule syntax, not its engine

Running Snort 3 beside Suricata would give decoders for S7CommPlus, IEC 104,
MMS and OPC UA. It would also mean a second engine to configure, feed and keep
alive on every sensor, with no rule set to give it (the repository has none
for these protocols) and no way to test it here. It was not added.

What was added: `tools/snort2suricata.py` now converts the mechanical part of
a Snort 3 rule that keeps the classic header: content options with their
modifiers after commas, `dnp3_obj: group N, var M`, single-value `cip_class`,
`cip_instance`, `cip_attribute` and `cip_status`, and `iec104_asdu_func`, which
is written as bytes because Suricata has no IEC 104 decoder (it then matches
only a message that starts its packet). Set aside with the reason: rules with
no addresses in the header, rules using an inspector Suricata has no answer to,
and rules that name a buffer the Snort 3 way (`http_uri;` before the content
it applies to), which Suricata would load and read the other way round. The table of 67 IEC 104 type names was compared with Snort 3's
`ips_iec104_asdu_func.cc`: same names, same numbers.

### From Yara-Rules/rules: an optional, filtered source

The collection is a snapshot of April 2022. Measured:

| Folder | Files | Rules | Ordinary files hit (of 7,407) | Use for files taken from plant traffic |
| --- | ---: | ---: | ---: | --- |
| malware | 406 | 2,405 | 32 | yes |
| webshells | 9 | 640 | 0 | yes |
| maldocs | 20 | 71 | 111 | yes, less four rules |
| cve_rules | 14 | 19 | 0 | yes |
| exploit_kits | 11 | 74 | 0 | no: browser kits of 2010 to 2015 |
| packers | 6 | 9,316 | 133 | no: labels every Windows program |
| crypto, capabilities, antidebug_antivm, email | 14 | 247 | 15 to 310 each | no: describe a file, do not accuse it |
| utils | 7 | 24 | 7,402 | no: one rule matches any file with a domain name in it |
| deprecated | 66 | 115 | 512 | no |

Six of ten rules in `malware`, and eight of ten in `webshells`, carry a name
that signature-base (one of the product's nine) already has: much of the
collection is an old copy of what the product ships newer.

So `[yara-rules-legacy]` in `sources.conf` is **off by default**, and when
switched on takes only `malware`, `maldocs`, `cve_rules` and `webshells`,
leaves out two files under a non-commercial licence, cuts nine rules that fired
on ordinary programs, documents and scripts, cuts every rule whose name an
earlier source already supplies, and leaves out a file whole when a rule left
in it depends on one that was cut. Result here: 1,125 rules in 357 files, of
which the product's script refused 8 (seven need a helper rule from another
file, one the cuckoo module), and no hit on the ordinary files.

### From RITA: a traffic profile, written afresh

RITA was reviewed before (`ANOMALY-DETECTION-REVIEW.md`): GPL, its own
database, a second copy of the records, and a default that drops every
conversation between two internal addresses. Its measures are still the right
ones for "what else is on this network". `baseline/td_profile.py` reports them
from the connection records the product already has, on request, with one
search:

| List | What it shows |
| --- | --- |
| Other protocols reaching controllers | Non-industrial traffic, answered, to an address the baseline knows as a device: remote desktop, web, file sharing |
| Connections opened by controllers | A device that starts conversations of its own |
| Addresses outside the private ranges | One end is a public address |
| Longest connections | One hour or more, including connections still open and ones that began before the period |
| Largest transfers | By bytes, with the direction |
| Steady repeaters | New connections in three hours out of four at an even rate (periods of four hours or more) |
| Addresses that contacted many services | One address, many destinations and ports |
| Attempts nobody answered | The client sent, the server sent nothing back |
| Services | Each port and protocol: how many servers, how many clients |

It raises no alerts and keeps nothing. A steady repeater is time
synchronisation far more often than a program calling home, and the report
cannot tell which. Run it with `td-profile` on the server.

Not built: RITA's score from the gaps between single connections. That needs
every connection's time, which one aggregated search does not return.

### From VulnRadar and advanced-port-scanner: two columns

VulnRadar's useful idea is to mark which vulnerabilities are being exploited,
from CISA's catalogue. The vulnerability coverage report already did that. The
port scanner reads one more field of the same catalogue, whether ransomware
campaigns are known to use the vulnerability. The report now carries that and
the date each entry was added.

### Not from any of the nineteen: a DNP3 trouble monitor

While reading for traffic profiling, one reviewer pointed out that the product
already decodes the sixteen status bits every DNP3 outstation sends with each
answer. A fourth alert monitor, switched off like the others, reports an
outstation that says "Device Trouble", "Configuration Corrupt", "Event Buffer
Overflow" or "Digital Outputs in Local".

### Corrected while measuring: one of the kit's own YARA rules

`TechDetechtives_PowerShell_Download_And_Run` fired on six ordinary installer
scripts (they download an `.msi` and start the installer). Fetching a file and
starting it now counts only when the address names a program or script
(`.exe`, `.dll`, `.ps1` and the like) or the window is hidden; a script that
fetches text and executes it as PowerShell matches as before.

## Not adopted, and why

- **cve-bin-tool.** It answers "which known-vulnerable components are in these
  files", for files on a disk. Two uses were considered. Scanning the
  appliance's own container images at build time: its matching by version
  string does not know about Debian's back-ported fixes, and the product's
  maintainers already scan every image (with Trivy, in their build pipeline).
  Scanning files taken from traffic: its unpacker reads package archives, not
  firmware images, and it would put a vulnerability database on the sensor to
  keep current by hand. Its offline mode is real (`--offline`, `--export`,
  `--import`), but neither use earns its place.
- **HORUS, IOCHunter.** Both exist to send indicators to online services. An
  isolated plant cannot, and should not. What they recognise as an indicator is
  less than `tools/ioc2intel.py` already handles.
- **spyre.** A good tool for a computer under investigation. A network sensor
  has no computer to scan.
- **NetGuard, pangerlkr, gnn-network-anomaly-detection, MAD-MulW,
  Network-Analyzer, sniffnet, netcap.** See the table.

## Next candidates, not built

- **A control operation at an hour it never happens.** The baseline knows which
  master sends which operation; it does not know that this master writes
  setpoints only on weekday mornings. Learning hours of the week per master and
  operation needs several weeks of learning.
- **Size and duration of a conversation outside its own band**, per pair.
- **A name-lookup profile**: new names, and addresses asking for many distinct
  names under one domain.
- **CIP Stop and Reset inside Unconnected Send**, by bytes, once the layout is
  checked against a capture.
- **A likelihood-of-exploitation column** (EPSS) in the vulnerability report.
  Its terms of use and file size were not checked.

## Limits of this review

- Two of the nineteen were not read at all, for the reasons in the table.
- The clones were shallow: how long a project has been maintained was judged
  from its last commit only.
- Three reviewers read the code and wrote reports. Their claims were
  spot-checked against the clones (licences, NetGuard's iptables call, the
  placeholder model and missing module in pangerlkr, the archive notice on the
  GNN project, Suricata's `subfunction` code, the product's stream depth and
  YARA script, Snort 3's type table), and the measurements in fault 3 were
  repeated. The rest was not repeated; that includes the per-folder table for
  Yara-Rules and the share of its rule names the product already has.
- The count of ordinary files hit is a rough measure: the files were those of
  one Linux build machine, with few Windows programs and Office documents among
  them. Rules that are quiet there can still be noisy in a plant.
- YARA here was 4.5.8 without two modules the product's build has; the
  product's YARA is 4.5.5. The numbers on an installed system will differ a
  little. `out/rule-check.txt` has the real ones after a build.
- Faults 3 and 4 were established from source code and, for 3, a simulation.
  Neither was watched on an installed system. Fault 2's fix and the layer for
  fault 4 have not been run in the product.
- The rewritten Modbus rules match on the packet and, as Suricata does for
  such rules, may be looked at again on the reassembled stream. Whether one
  request can then count twice toward rule 1900406's "ten in a minute" was not
  established.

## What an independent review of this change found

A reviewer with no part in the work checked it against the sources named above
and re-ran the measurements. It confirmed the four faults, the byte positions,
that the stream-depth setting reaches the engine, the YARA numbers, the
suppression file's line forms, the DNP3 monitor's field names and the Snort 3
tables. It also made eleven findings against the first version of the fixes.
All are corrected, each with a test where a test can show it:

- The YARA guard looked only for "any external rule file", so one source
  failing to download would still have replaced the product's set with a part
  of it. Now all or nothing, by the fetch's own record.
- The traffic profile selected records by the time their connection began, so
  it could not see a connection that began before the period, which is exactly
  the master's days-long session. Now selected by overlap. A still-open
  transfer could also hide behind an older, longer, closed one.
- The build's YARA check reported success when the product's compile had
  failed.
- A Snort 3 rule with `http_uri;` before its content was converted into a rule
  that loads and looks in the wrong buffer. Now set aside.
- The suppression file said a rule keeps its own rate; a `threshold` line
  replaces it.
- A link in a rule repository would have been followed onto the build
  machine's own files, and a file name that is not UTF-8 stopped the fetch.
- Cutting a rule could take a following `import` line with it; tags and
  private helper rules caused whole files to be left out for no reason.
- The corrected PowerShell rule had stopped matching the commonest dropper.
- A YARA source switched off stayed in the ISO from the run before.
- Suricata's DNP3 event rules are written over several lines and could not be
  added from its own files.
- Statements in this page and the README that were wrong or claimed too much,
  corrected above.
