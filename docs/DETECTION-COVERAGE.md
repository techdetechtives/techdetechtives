# Detection coverage

What TechDetechtives looks for, where each kind of rule runs, and what it cannot see. Read this before deciding that something is covered.

## What happens to mirrored traffic

The platform sensor listens on a network card that receives a copy of the traffic (a SPAN or mirror port, or a tap). It never sits in the path, so it **detects and records; it cannot block, slow or prioritise traffic**. Three things happen to every packet it receives:

| Engine | What it does | Result |
| --- | --- | --- |
| Suricata | Compares traffic with intrusion-detection rules: the Emerging Threats Open set the platform ships with, plus the TechDetechtives rules | Alerts |
| Zeek | Writes a record of every connection and decodes the protocols it knows, including the industrial ones below | Searchable records; the asset inventory and traffic map are built from them |
| Strelka | Scans files carried over unencrypted connections with YARA rules | Alerts on matching files |

Logs from endpoints (Elastic Agent) are checked by Sigma rules. All alerts land on the Alerts page and, at medium severity and above, in DFIR-IRIS.

**Zeek must be running for most of this.** If `sudo so-status` shows Zeek as missing, connection records, protocol decoding, the Sigma rules on network data, the asset inventory and the traffic map all stay empty. Suricata alerts still work.

## The TechDetechtives rule sets

| Set | Engine | Rules | Looks for |
| --- | --- | --- | --- |
| Endpoint threats | Sigma | 16 | Credential theft (LSASS dump, registry hives, Active Directory database), destroying backups, clearing logs, switching off Defender, Office starting a script, signed-binary abuse (mshta, regsvr32, certutil), suspicious scheduled tasks and services, WMI execution, encoded PowerShell, Linux reverse shells and piped downloads |
| OT, decoded protocols | Sigma | 3 | BACnet devices restarted or silenced, BACnet objects and files changed, Siemens S7 programs downloaded or uploaded |
| OT, network | Suricata | 34 | Modbus, DNP3, EtherNet/IP-CIP, Siemens S7 and IEC 104 operations that stop, restart or reprogram a device; industrial protocols crossing the edge of the monitored network |
| General network | Suricata | 2 | Dynamic DNS lookups, PowerShell fetching over plain HTTP |
| Files | YARA | 12 | Mimikatz, PowerShell download cradles and encoded launchers, AMSI bypass scripts, web shells, malicious shortcuts, script droppers, reflective loaders; TRITON framework files, SCADA attack modules, scripts that stop or reprogram a controller |

The files are in `platform/detections/`. Every Sigma rule is paired with a test in `validation.yml` ([DETECTION-VALIDATION.md](DETECTION-VALIDATION.md)).

**These sets are a tested core, not the whole of the detection.** Most of the coverage comes from the community rule sets the platform already carries: thousands of Suricata and Sigma rules. See "Turning on more" below.

**None of the rules has fired on a live platform yet.** What has been checked: every Sigma rule was converted with the platform's own conversion settings and evaluated against sample events; the YARA rules were compiled and run against sample files with YARA 4.5.2; the Suricata rules were checked for structure, and the byte positions of the S7 and IEC 104 rules against known requests. The Suricata rules have not been loaded into Suricata.

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

**About proprietary vendor protocols.** Siemens S7 and Rockwell CIP are decoded because open decoders exist. Honeywell Experion, ABB 800xA, Emerson DeltaV and Yokogawa CENTUM use control-network protocols that are not publicly documented, and no open decoder exists for them. TechDetechtives does not pretend otherwise: those systems are recognised by the maker of their network card and by the open protocols they also speak (Modbus, OPC UA, MMS, BACnet), and their proprietary traffic appears as connections without decoded operations.

**Why routine writes do not alert.** Writing a value to a controller is what an operator station does all day. Which machines are allowed to do it differs per plant, so a fixed rule cannot know. That question needs a baseline of who normally talks to each controller, which is the job of the asset inventory (see the README for its status).

**OT vulnerabilities.** The rules above detect operations and, through the community Suricata rules, known exploit attempts against industrial products. Telling you which of your controllers have known vulnerabilities is a different job. Greenbone can scan for some, but active scanning can crash fragile controllers, so do not point it at a live process network without the plant's agreement. Matching the device models seen in traffic against published advisories, without sending a single packet, is not built yet.

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
