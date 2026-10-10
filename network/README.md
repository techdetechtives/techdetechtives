# Network inventory and traffic map

A list of the devices on your network, a map of who talks to whom, and a record of what changed, all built from what the platform's sensor already records. It was written for networks with industrial (OT) equipment, where "which station is allowed to command which controller" is the question that matters, and it works for office networks too.

It **only reads from the platform**. It sends nothing to the monitored network: no scans, no probes, no questions to any device. That makes it safe beside controllers that do not tolerate being scanned, and it also sets its limits (see "What it cannot do").

| Part | What it is |
| --- | --- |
| `td-netmap` | One small container: reads grouped totals from the platform every five minutes, keeps the inventory in a local file, serves the pages over HTTPS, and downloads published security advisories to match against it. Python standard library only. MIT. |

## What you get

- **Devices.** Every address seen inside your networks, with what can be told about it without asking it anything: the protocols it answers and uses, its role (station, controller or field device, gateway), the maker of its network card, its name from DHCP or Windows sign-in traffic, and what it announces about itself (vendor, model, firmware version and serial number from EtherNet/IP identity; vendor and name from BACnet I-Am). Each device also shows how many platform alerts, vulnerability findings and honeypot contacts involve it.
- **Traffic map.** Devices drawn in rows by what they do (stations that start industrial conversations above, the controllers that answer below), grouped by zone, with one line per pair of devices and protocol. Thicker lines carry more data; dashed lines are new since the baseline. Below it, the same information as tables, and a zone-to-zone summary.
- **Industrial operations.** For the protocols the sensor decodes (Modbus, DNP3, Siemens S7comm, EtherNet/IP and CIP, BACnet, PROFINET, OPC UA): which station asked which device to do what, how often, and whether the operation changes the device (write, start, stop, restart, program transfer) or only reads. For S7comm-plus (S7-1200 and S7-1500) the platform records that the protocol was spoken but not the operations, so those controllers appear on the map and in the baseline of who talks to them, without an operations list.
- **Traffic profile.** Data per protocol, per hour and per device, industrial and other traffic kept apart so that a few megabytes of control traffic are not hidden behind gigabytes of office traffic.
- **Changes since the baseline.** For the first 72 hours after records start arriving, everything seen is taken as normal. After that, these are listed, and sent to the platform as alerts if you give it a key:

| Change | Severity |
| --- | --- |
| A station that never sent control commands to a device now does | High |
| An industrial protocol between your network and outside it | High |
| A controller answering from a network card by a different maker | High |
| A known station using a control command it had not used on that device | Medium |
| A new pair of devices talking an industrial protocol | Medium |
| A new kind of connection to a controller (SSH, web, remote desktop, anything) | Medium |
| A device reporting a different model, firmware version or serial number | Medium |
| Another device answering from a card by a different maker | Medium |
| A new device | Low |

Medium and high become tickets through the forwarder you already run. Each pair of devices is reported once, however many ports are involved, and a pass that finds more than 100 changes (a scan, a newly mirrored segment) keeps the most severe and says how many it left out.

## Published advisories (JPCERT/CC, JVN, CISA)

The Advisories page brings in what national CERTs publish and says which of it concerns this site. It downloads, every six hours:

| Source | What it is | Format |
| --- | --- | --- |
| JPCERT/CC | Alerts and reports from Japan's CERT ([feed](https://www.jpcert.or.jp/english/rss/jpcert-en.rdf)) | RSS 1.0 |
| JVN | Vulnerability notes coordinated by JPCERT/CC and IPA, many of them for industrial products ([feed](https://jvn.jp/en/rss/jvn.rdf)) | RSS 1.0 |
| JVN iPedia | The same vulnerabilities with CVE numbers, vendors, products and CVSS scores ([feed](https://jvndb.jvn.jp/en/rss/jvndb.rdf)) | RSS 1.0 with JVN's security extension |
| CISA ICS | Every ICS advisory CISA has published, as machine-readable CSAF documents ([feed](https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/cisa-csaf-ot-feed-tlp-white.json)) | ROLIE listing of CSAF 2.0 |
| CISA KEV | CISA's catalogue of vulnerabilities known to be used in real attacks ([feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)) | JSON |

An advisory concerns this site in one of three ways:

| How | Example | Raised as |
| --- | --- | --- |
| A vulnerability scan sent to the platform found one of its CVEs on a device | Greenbone found CVE-2021-44228 on 10.10.1.20; CISA lists it as exploited | High when the CVE is known to be exploited or scores 9.0 or more; otherwise medium |
| A device announces a vendor and model the advisory names, in a version it says is affected | A Honeywell C300 announces itself over EtherNet/IP; ICSA-21-278-04 names "C300 and ACE controllers", all versions | The same |
| The advisory names a product on the site's own list of what it runs | "Honeywell Experion PKS" is on the list; ICSA-25-205-03 is about Experion PKS | The same |

Each one becomes a change, one per device or listed product however many advisories it gathers, so it reaches the platform as an alert and DFIR-IRIS as a ticket like any other change. A device whose announced version is outside the affected range is shown, marked "not affected", and raises nothing. Software banners (an SSH or web server announcing its name and version) are matched too, but only shown as possible: without a vendor they are too loose to raise alerts on.

Most industrial equipment does not announce its model on the network (see "What it cannot do"), so tell it what you run:

```bash
scripts/install.sh network --watch "Honeywell Experion PKS; Honeywell C300; Honeywell ControlEdge"
```

A product on the list matches an advisory when every word of it appears in the advisory's title, summary or product names. The list says nothing about versions, so these matches read "check version".

CISA has published about 4,000 ICS advisories. All are listed by title at once; the full document (CVE numbers, products, affected versions) is fetched for those updated in the last year, and for older ones about a vendor this site has (from what devices announce, their network cards' makers and the list), up to 150 a pass, so the first day fills in gradually.

### Without internet access

```bash
scripts/install.sh network --advisories off
```

stops all downloads. Files put in `network/advisories/` are read instead, recognised by their contents: RSS or Atom feeds saved from a connected machine, CSAF advisories (CISA's, or a vendor's such as Siemens ProductCERT or Schneider Electric), or the KEV catalogue. Each file is read once, and again when it changes.

When the machine reaches the internet through a proxy, give it for the advisories only (the platform connection never goes through it):

```bash
scripts/install.sh network --advisory-proxy http://proxy.example:3128
```

`scripts/install.sh network --fetch-advisories` fetches now instead of at the next interval. `scripts/verify.sh network` says whether every source could be read.

### Adding a publisher

Any feed in one of the four formats can be added to `TD_ADV_FEEDS` in `config/techdetechtives.env`, as `NAME=FORMAT:https://ADDRESS`, comma separated (`rss`, `kev`, `csaf-feed`, `csaf`). An empty value means the five sources above; listing your own replaces them, so keep the ones you want.

### What the advisories part sends and keeps

Plain downloads from the addresses above, with certificate checks, and nothing else: no device, address or finding leaves the machine. A listing can only send it to documents on the listing's own host. Feeds that declare a DTD or XML entities are refused. Advisories are kept in the inventory's local file.

### Its limits

- **A match by model is as good as what the device says.** Vendors name products in advisories differently from the way devices describe themselves ("ControlLogix 5580" against "1756-L83E/B LOGIX5583E"), so a device can be missed. The list of products covers what the network cannot tell.
- **Versions are compared when both are written alike.** "R520.1" against "below R520.2" is decided; "R530.4" against "below R530 TCU3" is not, and reads "check version".
- **JPCERT/CC's own feed carries few advisories** (mostly reports and alerts); JVN and JVN iPedia carry the vulnerability notes. JVN iPedia's feed holds only recent entries, so the Japanese side covers what was published since this part started, plus whatever you import.
- **The feeds were read from their real formats for the tests, not fetched live**: CISA's advisories and catalogue were checked against copies taken from CISA's repositories; JVN's format against its published structure. The first live fetch is the test; `scripts/verify.sh network` shows its result.

## About "traffic shaping"

Shaping means slowing or prioritising traffic, and that needs a device the traffic passes through. The sensor receives a copy, so nothing built on it can shape, block or prioritise anything. What this part gives instead is the picture you need before you shape or segment on your switches and firewalls: who talks to whom, on which protocol, how much and when.

## Install

It runs on the ticketing machine, next to DFIR-IRIS, and uses the read-only key that machine already has (`TD_ES_API_KEY` in `config/techdetechtives.env`).

```bash
cd techdetechtives && git pull
scripts/install.sh network --name DFIR-VA --ip <this machine's IP>
scripts/verify.sh network
```

The installer prints the address (`https://<name>:8445`) and where the password is. The certificate is self-signed, so the browser asks once.

To have changes arrive on the platform as alerts, and from there as tickets, create one more key **on the platform**:

```bash
sudo platform/create-ingest-key.sh --for network
```

Copy the line it prints into `config/techdetechtives.env` on the ticketing machine yourself (do not paste keys into chats or tickets), and run `scripts/install.sh network` again. The key can append this part's alerts and nothing else.

### Telling it about your network

```bash
scripts/install.sh network --zones "Control=10.10.1.0/24,Stations=10.10.10.0/24,Office=172.16.0.0/16" \
                           --inside "10.10.0.0/16,172.16.0.0/16" --learn-hours 168
```

- `--zones` names parts of your network. Without it, each /24 network is its own zone.
- `--inside` says which networks are yours. Everything else is drawn as one item, "Outside". The default is every private range.
- `--learn-hours` is how long everything is taken as normal. Choose a period that covers your routine work: a week catches the weekly backup and the Monday engineering session; three days does not.

Options are remembered; re-running with one option changes only that one.

### After planned work

A new controller, a replaced HMI or a new engineering laptop will show up as changes. When everything on the Changes page is expected:

```bash
scripts/install.sh network --accept
```

makes the present state the new baseline.

## The first thing to check: is Zeek recording?

Everything here comes from Zeek's connection and protocol records. `scripts/verify.sh network` says so plainly when the platform has none. On the platform:

```bash
sudo so-status          # Zeek must be shown as running, not missing
```

The page shows a notice while there are no records, and the learning time does not start until the first ones arrive, so a sensor that is not recording yet does not use it up.

## What it cannot do

- **It sees what the mirror carries.** Two controllers talking on a switch that is not mirrored never appear.
- **It reads what devices say in passing, and asks nothing.** Model and firmware version are known for devices that announce them over EtherNet/IP or BACnet. For Siemens, Schneider, Honeywell, ABB and others they are not read from traffic by this version, even where the protocol carries them.
- **Protocols known "by port" are a label, not a finding.** "Honeywell Experion engineering" on TCP 55553 means that port was used. The contents were not read, because no open decoder for that protocol exists. The pages mark these.
- **The maker of a network card** is only known for devices on the same network segment as the sensor; behind a router, the sensor sees the router's card. Card addresses themselves are only known from DHCP.
- **A device is something that answered or spoke.** A connection attempt that got no answer, to an address nothing has been seen at, is ignored, so a scan of empty addresses does not fill the list with devices that do not exist. A device that only ever listens and never sends is therefore missing.
- **An address is treated as a device.** Where DHCP hands addresses around, the same machine can appear as several devices over time, and each new address is a low-severity "new device".
- **It does not find vulnerabilities itself.** It matches what it sees against published advisories (above) and against what the vulnerability part's scans found. Scanning is the vulnerability part's job, with care around controllers.
- **It does not measure rates.** A flood is the job of the flood rules in `platform/detections/`; "this device normally receives 40 packets a second" is not learned here.
- **Addresses ending in .255** are taken to be broadcast addresses. In a network larger than /24 a real device can have such an address and will be missing.
- **Volumes start when this part starts** (it reads back 24 hours on its first pass) and are kept across restarts.

## Operating it

```bash
scripts/verify.sh network            # container, platform connection, records, a finished read
docker logs td-netmap                # what each pass read
scripts/install.sh network-down      # stop it; what it learned is kept
```

The container runs without privileges, as the account that first installed it (remembered as `TD_NET_UID` in the settings file), whoever starts it later. It keeps its inventory in the Docker volume `techdetechtives-network_td-netmap-state`. Removing that volume makes it start again from nothing, including the learning time.

Settings are in `config/techdetechtives.env` under "Network inventory"; after changing them, run `scripts/install.sh network` again.

## On a live system

This part was built and tested against a stand-in for the platform (76 automated tests, 20 of them for the advisories, and the pages checked by eye with a simulated plant). On 2026-10-10 it ran against a live Security Onion 2.4.211: the image built, it read more than 10,000 connection records and built an inventory of 39 devices and 482 conversations, with EtherNet/IP decoded, and all five advisory sources were fetched. What that run did not cover, and what to check first if something is wrong:

- **No connection records.** The inventory is built from Zeek's records in the platform. If `scripts/verify.sh network` says there are none while Zeek is running, check on the platform that its own Elastic Agent is installed (`systemctl status elastic-agent`): that agent is what carries Zeek's logs into Elasticsearch. On the live system it was missing, and `sudo salt-call state.apply elasticfleet.install_agent_grid` on the manager installed it.
- **Field names.** They were taken from Security Onion 2.4.211's ingest settings and the protocol analyzers' source. The live run built its inventory with them. A field that the platform cannot group on becomes a warning on the pages, and the rest keeps working.
- **Late records.** Records are picked up by the time the sensor's agent read them, so a session that lasted a day is counted when it is finally written. They are read five minutes after that time (`TD_NET_LAG_SECONDS`), to give them time to reach the platform. A record that takes longer is not in the inventory; the next pass notices, and the pages then say how many and suggest a longer wait.
- **Alerts to the platform** go to the data stream `logs-netmap.alerts-techdetechtives`, which the platform should create on first use. The platform accepted the key, but no change had occurred on the live system, so nothing has been written there yet. `docker logs td-netmap` shows its answer if it refuses.
- **Large networks.** Records are read an hour at a time, and a stretch with more than 200,000 different groups is read again in halves, down to one minute; only beyond that is anything left out, and the pages say so. It has only been run with a few thousand groups.
