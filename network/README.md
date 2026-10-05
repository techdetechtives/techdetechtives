# Network inventory and traffic map

A list of the devices on your network, a map of who talks to whom, and a record of what changed, all built from what the platform's sensor already records. It was written for networks with industrial (OT) equipment, where "which station is allowed to command which controller" is the question that matters, and it works for office networks too.

It **only reads from the platform**. It sends nothing to the monitored network: no scans, no probes, no questions to any device. That makes it safe beside controllers that do not tolerate being scanned, and it also sets its limits (see "What it cannot do").

| Part | What it is |
| --- | --- |
| `td-netmap` | One small container: reads grouped totals from the platform every five minutes, keeps the inventory in a local file, serves the pages over HTTPS. Python standard library only. MIT. |

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
- **It does not find vulnerabilities.** Matching the models and versions it sees against published advisories is not built. Use the vulnerability part for that, with care around controllers.
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

## Not yet run on a live system

This part was built and tested against a stand-in for the platform (56 automated tests, and the pages checked by eye with a simulated plant). On a real platform, these are the first suspects if something is wrong:

- **Field names.** They were taken from Security Onion 2.4.211's ingest settings and the protocol analyzers' source, not from live records. A field that the platform cannot group on becomes a warning on the pages, and the rest keeps working.
- **Late records.** Records are picked up by the time the sensor's agent read them, so a session that lasted a day is counted when it is finally written. They are read five minutes after that time (`TD_NET_LAG_SECONDS`), to give them time to reach the platform. A record that takes longer is not in the inventory; the next pass notices, and the pages then say how many and suggest a longer wait. How long the journey takes on your platform is not known yet.
- **The container image** has not been built, and the pages have not been served from it.
- **Alerts to the platform** go to the data stream `logs-netmap.alerts-techdetechtives`, which the platform should create on first use. `docker logs td-netmap` shows its answer if it refuses.
- **Large networks.** Records are read an hour at a time, and a stretch with more than 200,000 different groups is read again in halves, down to one minute; only beyond that is anything left out, and the pages say so. It has only been run with a few thousand groups.
