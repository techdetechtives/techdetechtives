# Detection coverage

What TechDetechtives looks for, where each kind of rule runs, and what it cannot see. Read this before deciding that something is covered.

## What happens to mirrored traffic

The platform sensor listens on a network card that receives a copy of the traffic (a SPAN or mirror port, or a tap). It never sits in the path, so it **detects and records; it cannot block, slow or prioritise traffic**. Three things happen to every packet it receives:

| Engine | What it does | Result |
| --- | --- | --- |
| Suricata | Compares traffic with intrusion-detection rules: the Emerging Threats Open set the platform ships with, plus the TechDetechtives rules | Alerts |
| Zeek | Writes a record of every connection and decodes the protocols it knows, including the industrial ones below. With the layer 2 watch switched on, also follows which network card answers for which address | Searchable records; notices that become alerts; the asset inventory and traffic map are built from them |
| Strelka | Scans files carried over unencrypted connections with YARA rules | Alerts on matching files |

Logs from endpoints (Elastic Agent) are checked by Sigma rules. All alerts land on the Alerts page and, at medium severity and above, in DFIR-IRIS.

**Zeek must be running for most of this.** If `sudo so-status` shows Zeek as missing, connection records, protocol decoding, the Sigma rules on network data, the layer 2 watch, the asset inventory and the traffic map all stay empty. Suricata alerts, including the flood rules, still work.

**Set HOME_NET to your own address ranges** (Administration, Configuration, suricata, config, vars, address-groups). The rules that say "from outside the monitored network" compare against it. The platform's default is every private range, which is usually right for a lab and too wide for a site that wants its office network treated as outside its plant network.

## The TechDetechtives rule sets

| Set | Engine | Rules | Looks for |
| --- | --- | --- | --- |
| Endpoint threats | Sigma | 16 | Credential theft (LSASS dump, registry hives, Active Directory database), destroying backups, clearing logs, switching off Defender, Office starting a script, signed-binary abuse (mshta, regsvr32, certutil), suspicious scheduled tasks and services, WMI execution, encoded PowerShell, Linux reverse shells and piped downloads |
| OT, decoded protocols | Sigma | 3 | BACnet devices restarted or silenced, BACnet objects and files changed, Siemens S7 programs downloaded or uploaded |
| Layer 2 | Sigma, on notices from a Zeek script | 5 | ARP poisoning, an address taken over by another network card, unasked ARP answers, MAC flooding, software-set card addresses, ARP sweeps |
| OT, network | Suricata | 40 | Modbus, DNP3, EtherNet/IP-CIP, Siemens S7 and IEC 104 operations that stop, restart or reprogram a device; Honeywell Experion controller engineering ports; industrial protocols crossing the edge of the monitored network |
| Floods | Suricata | 17 | ICMP, TCP SYN and UDP floods from one address or at one host, oversized pings, reflection and amplification, connection floods at controller ports, fragment floods, IPv6 router advertisement floods |
| General network | Suricata | 2 | Dynamic DNS lookups, PowerShell fetching over plain HTTP |
| Files | YARA | 12 | Mimikatz, PowerShell download cradles and encoded launchers, AMSI bypass scripts, web shells, malicious shortcuts, script droppers, reflective loaders; TRITON framework files, SCADA attack modules, scripts that stop or reprogram a controller |

The files are in `platform/detections/`. Every Sigma rule is paired with a test in `validation.yml` ([DETECTION-VALIDATION.md](DETECTION-VALIDATION.md)).

**These sets are a tested core, not the whole of the detection.** Most of the coverage comes from the community rule sets the platform already carries: thousands of Suricata and Sigma rules. See "Turning on more" below.

**None of the rules has fired on a live platform yet.** What has been checked: every Sigma rule was converted with the platform's own conversion settings and evaluated against sample events; the YARA rules were compiled and run against sample files with YARA 4.5.2; the layer 2 Zeek script was run in Zeek 7.0.11 against generated captures of each attack and of ordinary traffic; the Suricata rules were checked for structure, their threshold and flag options against the patterns in the Suricata 7.0.11 source, and the byte positions of the S7, IEC 104 and Honeywell rules against sample requests. **The Suricata rules have not been loaded into Suricata**, so the flood rules in particular are untried: check them in a lab with the commands in `validation.yml` before relying on them.

## Industrial (OT) protocols

"Decoded" means the engine understands the protocol and records or matches individual operations. "Port only" means traffic is recognised by its port number, shown in the inventory and the traffic map, and nothing more.

| Protocol | Typical vendors | Suricata | Zeek | TechDetechtives rules |
| --- | --- | --- | --- | --- |
| Modbus/TCP, including UMAS (function 90) | Schneider Electric, and almost everyone | Decoded | Decoded | Force listen-only, restart communications, firmware and programming functions, broadcast writes, writes from outside, inventory queries |
| DNP3 | Utilities; GE, ABB, SEL, Schneider | Decoded | Decoded | Cold and warm restart, stop/start application, disable unsolicited, file and configuration operations |
| EtherNet/IP and CIP | Rockwell Automation / Allen-Bradley, Omron, Schneider | Decoded | Decoded | Identity reset, stop, network settings changed, List Identity from outside |
| S7comm, S7comm-plus | Siemens | Bytes at fixed positions | Decoded | PLC stop, start, block delete (Suricata); program download and upload (Sigma) |
| PROFINET | Siemens and others | No | Decoded | None yet |
| IEC 60870-5-104 | Utilities; ABB, Siemens, Schneider | Bytes at fixed positions | No | Reset process command |
| BACnet/IP | Honeywell, Johnson Controls, Siemens, Schneider (building systems) | No | Decoded | Device restarted or silenced, objects and files changed |
| OPC UA | Cross-vendor | No | Decoded | None yet |
| EtherCAT | Beckhoff and others | No | Decoded | None yet |
| BSAP | Emerson (Bristol) | No | Decoded | None yet |
| IEC 61850 MMS, ICCP | ABB, Siemens, GE (substations) | No | Connection layer only | Boundary rule |
| GE SRTP, Omron FINS, Mitsubishi MELSEC, CODESYS, Beckhoff ADS, Phoenix Contact, Niagara Fox, HART-IP, KNX, Triconex TriStation, ABB RNRP | As named | Port only | Port only | Boundary rules |
| Experion engineering protocol (TCP 55553, 55555) | Honeywell (C200, C300, ACE) | Port only | Port only | Six rules following the published advisories; see below |

**About proprietary vendor protocols.** Siemens S7 and Rockwell CIP are decoded because open decoders exist. Honeywell Experion, ABB 800xA, Emerson DeltaV and Yokogawa CENTUM use control-network protocols that are not publicly documented, and no open decoder exists for them. TechDetechtives does not pretend otherwise: those systems are recognised by the maker of their network card and by the open protocols they also speak (Modbus, OPC UA, MMS, BACnet), and their proprietary traffic appears as connections without decoded operations.

**Why routine writes do not alert.** Writing a value to a controller is what an operator station does all day. Which machines are allowed to do it differs per plant, so a fixed rule cannot know. That question needs a baseline of who normally talks to each controller, which is the job of the asset inventory (not built yet).

### Honeywell Experion PKS: C300, C200 and ACE controllers

What is published, and what the rules do with it:

| Advisory | What it covers | What TechDetechtives does |
| --- | --- | --- |
| CISA ICSA-21-278-04 (CVE-2021-38395, -38397, -38399; found by Claroty Team82) | Control Builder reaches the controllers on TCP 55553 and 55555. A control library sent there could carry program code that the controller ran without checking it, and a folder path in the request could climb out of its folder. Fixed by signed libraries in later releases. | Rules 1900181 to 1900186: the engineering ports reached from outside the monitored network (high); folder-climbing paths in a request (high); Windows or ELF program code sent to a controller (medium, because a planned library download looks the same); a low-severity note of each address that opens an engineering connection, once a day, so you can see who does |
| CISA ICSA-23-194-06 (the nine "Crit.IX" flaws found by Armis, among them CVE-2023-25770, -25948, -26597, -24480, -25178 for the C300) | Faults in the Control Data Access (CDA) protocol between Experion servers and controllers: crafted messages that crash a controller, leak its configuration or load changed firmware, with no sign-in | No rule recognises these messages: the protocol has never been published and neither have the attack messages, and a rule built on a guess would be decoration. What applies: rule 1900181 (the attacker has to reach the controller first), the connection-flood rule 1900314, and the daily note of who opens engineering connections |
| CISA ICSA-25-205-03 (CVE-2025-2520 to -2523, -3946, -3947) | Further faults in CDA and the engineering protocol, fixed in R520.2 TCU9 HF1 and R530 TCU3 HF1 | As above |

All six rules are untried against real Experion traffic. If the engineering protocol compresses or encrypts what it carries, the two content rules (folder paths, program code) will not see it.

**The CF9 control firewall.** A CF9 connects up to eight controllers (C300, PGM) to the FTE network through a ninth uplink port, one CF9 per FTE segment, and is there to keep storms and unwanted traffic away from them. None of the three advisories above names the CF9, a search in October 2026 found no other advisory that does, and its filtering rules are not published. So there is no CF9-specific rule here and none is claimed. What can be watched is what is aimed at the controllers behind it: the flood rules below (a storm heading for a controller), rule 1900314, the Honeywell rules above, and the layer 2 watch. Take the mirror on the uplink side of the CF9: traffic the CF9 drops is visible there and not behind it.

**Fix the controllers.** Detection is the second line. The first is the release level each advisory names; the advisories also ask that the control network be unreachable from the business network, which rule 1900181 checks continuously.

**OT vulnerabilities.** The rules above detect operations, the Honeywell rules follow three published advisories, and the community Suricata rules cover known exploit attempts against other industrial products. Telling you which of your controllers have known vulnerabilities is a different job. Greenbone can scan for some, but active scanning can crash fragile controllers, so do not point it at a live process network without the plant's agreement. Matching the device models seen in traffic against published advisories, without sending a single packet, is not built yet.

## Floods and denial of service

The flood rules (`techdetechtives-flood.rules`) count packets. Each alerts once every ten seconds while the rate stays above its figure. "From one address" catches a single attacker or a fast scanner; "at one host" catches an attack from many addresses or with forged ones.

| Rule | Looks for | Figure (per 10 seconds) | Severity |
| --- | --- | --- | --- |
| 1900301 | Pings from one address (flood or sweep) | 500 | Medium |
| 1900302 | Pings at one host | 1,000 | Medium |
| 1900303 | Pings larger than 1,000 bytes from one address | 20 | Medium |
| 1900304 | Ping replies at one host (reflection) | 1,000 | Medium |
| 1900305 | A ping to the broadcast address | any, reported once per 5 minutes | Low |
| 1900306 | "Destination unreachable" messages at one host | 1,000 | Medium |
| 1900307 | IPv6 pings at one host | 1,000 | Medium |
| 1900308 | IPv6 router advertisements | 50 | Medium |
| 1900311 | TCP connection attempts (SYN) from one address: flood or fast port scan | 1,000 | Medium |
| 1900312 | TCP connection attempts at one host | 3,000 | Medium |
| 1900313 | A packet whose source and destination address are the same (LAND) | any, once a minute | Medium |
| 1900314 | TCP connection attempts at one host's industrial port (S7, Modbus, IEC 104, DNP3, EtherNet/IP, Experion) | 100 | High |
| 1900321 | UDP packets from one address | 20,000 | Medium |
| 1900322 | UDP packets at one host | 30,000 | Medium |
| 1900323 | DNS answers over 1,000 bytes at one host (amplification) | 500 | Medium |
| 1900324 | Large replies from chargen, portmap, NTP, CLDAP, SSDP, WS-Discovery or memcached at one host (amplification) | 300 | Medium |
| 1900325 | Fragmented packets at one host | 2,000 | Low |

Things to know before trusting them:

- **The figures are starting points**, chosen so that ordinary traffic on a small or industrial network stays below them. They are not measurements of your network. A vulnerability scan with Greenbone is likely to cross 1900311 and perhaps 1900314; so can a backup or a monitoring sweep. Silence a known machine from the rule's Tuning tab in Detections, or duplicate the rule and change its count.
- **The UDP rules skip the ports that are busy by design**: QUIC (443), VPNs (500, 1194, 4500, 51820), VXLAN (4789), EtherNet/IP cyclic data (2222) and PROFINET (34962 to 34964). A flood on one of those ports is not counted.
- **A slow attack is not a flood.** Something that sends one harmful message, or exhausts a server with a few hundred slow connections, stays under every figure here.
- **The sensor reports; it does not stop anything.** It sees a copy of the traffic. Under a flood large enough to fill the mirror port or the sensor, it also loses packets, and what it records about everything else gets thinner.
- **Rate-based detection built on a learned baseline** ("this host normally receives 40 packets a second") is the job of the traffic profile, which is not built yet.

## Layer 2: ARP poisoning, changed card addresses, MAC flooding

Suricata does not read ARP, so this part is a Zeek script (`platform/zeek/techdetechtives/l2-watch.zeek`). It follows which network card (MAC address) answers for which IP address and writes a notice when that changes the way an attack would change it. Five Sigma rules turn the notices into alerts.

| What happened | How it is recognised | Severity |
| --- | --- | --- |
| ARP poisoning (someone is intercepting traffic), or two machines set to the same address | One address claimed by two cards in turn within ten minutes | High |
| MAC flooding (filling a switch's address table so it sends everything everywhere) | 100 card addresses never seen before within a minute | High |
| An address taken over | An address moves to another card while the earlier one was in use during the last half hour | Medium |
| A poisoning tool at work | One card sends 20 ARP answers nobody asked for within a minute | Medium |
| One machine answering for a whole segment | One card claims 10 addresses within five minutes | Medium |
| An address with a new card after a quiet spell | As it says: a replaced device, or DHCP handing the address on | Low |
| A card address set by software | A new card whose address has the "set locally" marking: virtual machines, phones with private addresses, and address-changing tools at their default setting | Low |
| ARP sweep or storm | One card sends 300 ARP requests within a minute | Low |

**It is off until you switch it on**, because it changes the list of scripts Zeek loads and makes Zeek restart:

```bash
sudo platform/apply-overlay.sh layer2 on        # Zeek reads the script first; nothing changes if it cannot
sudo platform/apply-overlay.sh layer2 status
sudo platform/apply-overlay.sh layer2 off
```

`layer2 on` refuses to run while Zeek is not running, and first has the platform's own Zeek read the script without running it, so a script that this Zeek version cannot read never reaches the configuration. Zeek stops recording for a few seconds while it restarts. While the watch is on, the platform's list of Zeek scripts is a local copy, so changes Security Onion makes to its default list in a later version do not arrive; `layer2 off` removes the copy again.

Limits:

- **The sensor must receive the segment's ARP traffic.** A mirror of a routed link shows only the routers' cards. In a VMware lab, the port group the sensor listens on needs promiscuous mode.
- **Spoofing a card address is only visible through its effects.** If an attacker copies a machine's card address and IP address exactly while that machine is switched off, nothing on the wire changes and nothing is reported. What is reported is an address answered by a different card, two cards claiming one address, or a card address of the software-set kind. An address-changing tool told to imitate a real maker's address is not flagged by that last check.
- **The same addresses used in several places.** Plants that reuse one address range in every machine cell will see constant "two cards" alerts if one sensor's mirror covers several cells, because the script cannot tell the cells apart. List those ranges in `l2_ignore_addresses`.
- **Failover pairs** that move an address between two real cards (instead of sharing a virtual one) look like a takeover. List their cards in `l2_ignore_cards`.
- **Memory is lost at each Zeek restart.** The first ten minutes afterwards are spent relearning which cards exist; new cards are not reported in that time.
- **Several Zeek worker processes on one sensor** each keep their own memory. The script was tried with one process. Whether the platform sends all ARP traffic to the same worker has not been checked.
- **IPv6 neighbour discovery** (the IPv6 counterpart of ARP) is not watched.

Exceptions and figures are Zeek settings. Add lines like these under Administration, Configuration, zeek, config, local, redef (each on its own line, with the semicolon):

```
TechDetechtives::l2_ignore_cards += { "00:11:22:33:44:55" };
TechDetechtives::l2_ignore_addresses += { 192.168.0.0/24 };
TechDetechtives::l2_unasked_replies = 40;
```

## What it cannot see

- **Encrypted traffic.** Connections are recorded, contents are not.
- **Anything the mirror does not carry.** A SPAN port on one switch shows that switch. Traffic between two controllers on another switch never reaches the sensor.
- **Serial and fieldbus links** (Modbus RTU, PROFIBUS, HART) unless a gateway puts them on Ethernet.
- **Layer 2 protocols** (PROFINET discovery, GOOSE) unless the mirror includes them and the sensor is on the same segment.
- **Addresses behind a router** by network-card maker: the sensor sees the router's card, not the device's.

## Turning on more of the community rules

The platform enables only part of what it carries, to keep noise down. These are console steps on your own platform; they have not been tried from this repository.

- **Sigma.** In Detections, search `so_detection.language:sigma AND so_detection.severity:high AND so_detection.isEnabled:false`, review, select the ones you want and enable them. To have future imports switched on as well, change `enabledSigmaRules` under Administration, Configuration, soc, config, server, modules, elastalertengine. Expect more alerts and therefore more tickets; raise `TD_TICKET_MIN_SEVERITY` to 3 first if in doubt.
- **Suricata.** The Emerging Threats Open set is on by default and includes its SCADA rules. Search `so_detection.language:suricata AND so_detection.title:*SCADA*` to see them and enable the disabled ones that fit your plant.
- **YARA.** More rule repositories can be added under Administration, Configuration, soc, config, server, modules, strelkaengine, rulesRepos. The platform needs internet access to fetch them, and each repository has its own licence.

Turn things on a batch at a time and watch the Alerts page for a day before the next batch.
