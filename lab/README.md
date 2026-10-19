# TechDetechtives VMware ESXi Lab — Build From Scratch

A complete test lab for TechDetechtives on one VMware ESXi host (64 GB RAM or more):

- **The platform:** Security Onion 3.x with the TechDetechtives overlay.
- **The second machine (DFIR-VA):** workbench, DFIR-IRIS ticketing, Greenbone vulnerability scanning, network/OT inventory.
- **The honeypot:** a dedicated VM.
- **An OT segment:** Modbus, S7 and DNP3 simulators.
- **Lab endpoints:** Windows and Linux, plus an attacker VM to run the detection tests.

At the end, every detection path has been exercised: endpoint → alert → DFIR-IRIS ticket, network/OT → alert → ticket, honeypot contact → alert → ticket, scan finding → dashboard → ticket.

> **Version note.** The repository pins Security Onion **3.3.0** (`upstream.lock`). Security Onion 2.4 reaches end of life on 1 October 2026, so use 3.x. 3.x runs on Oracle Linux 9 only. The TechDetechtives parts were live-tested on Security Onion 2.4.211, so this lab is also the first full run on 3.x. Record what you see in `platform/detections/validation.yml` (`confirmed:` fields).

---

## 1. Lab design

### 1.1 Network plan

| Segment | ESXi port group | Subnet | Purpose |
|---|---|---|---|
| WAN | `VM Network` (existing, has uplink) | your home/office LAN (DHCP) | Internet for installs, your analyst laptop |
| MGMT | `TD-MGMT` on `vSwitch-TD-MGMT` | 10.10.10.0/24 | Platform, DFIR-VA |
| IT lab | `TD-IT` (VLAN 20) on `vSwitch-TD-LAB` | 10.10.20.0/24 | Windows/Linux endpoints, honeypot, attacker |
| OT lab | `TD-OT` (VLAN 30) on `vSwitch-TD-LAB` | 10.10.30.0/24 | OT simulators |
| Monitor | `TD-SPAN` (VLAN 4095, **promiscuous**) on `vSwitch-TD-LAB` | no IP | Sensor sniff interface — sees all IT + OT traffic |

The lab switches have **no physical uplink**. Only the router VM connects them to the outside.

### 1.2 Virtual machines

| VM | OS / ISO | vCPU | RAM | Disk | NICs (in order) | IP |
|---|---|---|---|---|---|---|
| `td-router` | OPNsense (current stable) | 2 | 2 GB | 16 GB | VM Network, TD-MGMT, TD-IT, TD-OT | WAN DHCP · .10.1 · .20.1 · .30.1 |
| `td-so` | Security Onion 3.x ISO (Oracle Linux 9) | 8 | 28 GB | 400 GB | TD-MGMT, TD-SPAN | 10.10.10.10 |
| `td-dfirva` | Ubuntu Server 24.04 LTS | 6 | 18 GB | 250 GB | TD-MGMT | 10.10.10.20 |
| `fileserver-02` (honeypot) | Ubuntu Server 24.04 LTS | 1 | 2 GB | 20 GB | TD-IT | 10.10.20.30 |
| `win-victim` | Windows 11 Enterprise or Server 2022 (evaluation) | 2 | 6 GB | 80 GB | TD-IT | 10.10.20.21 |
| `lnx-victim` | Ubuntu Server 24.04 LTS | 1 | 2 GB | 20 GB | TD-IT | 10.10.20.22 |
| `ot-sim` | Ubuntu Server 24.04 LTS | 1 | 2 GB | 20 GB | TD-OT | 10.10.30.10 |
| `kali` (attacker) | Kali Linux (current) | 2 | 4 GB | 40 GB | TD-IT, TD-OT | 10.10.20.66 · 10.10.30.66 |
| **Total** | | **23** | **64 GB** | **~850 GB** | | |

**Exactly 64 GB on the host?** Give `td-so` 24 GB and `td-dfirva` 16 GB (total 58 GB). Then power `kali` and `lnx-victim` on only while testing. With 96 GB or more, give `td-so` 32 GB and add a separate Security Onion sensor node for the OT segment (4 vCPU, 12 GB, 200 GB).

VM settings for every VM:
- NIC type **VMXNET3**, except: use E1000E for `td-so`'s sniff NIC if VMXNET3 drops packets.
- Disk: thin provisioning is fine for a lab; use thick eager-zeroed for `td-so` if the datastore is slow.
- **Guest OS type:** Oracle Linux 9 (64-bit) for `td-so`, FreeBSD 14 (64-bit) for OPNsense, Ubuntu Linux (64-bit) for the Ubuntu VMs, Windows 11 / Server 2022 for Windows, Debian 12 (64-bit) for Kali.
- For `td-so`: **reserve all guest memory** (VM Options → Resources → Memory → Reserve all guest memory). Elasticsearch performs badly under ballooning.
- Install VMware Tools / open-vm-tools on every VM. Ubuntu, Kali and Security Onion include it.

### 1.3 Name resolution

Every Linux VM resolves `td-so` through `/etc/hosts`. `lab/linux/prepare-host.sh` adds the entry. Optionally add host overrides in OPNsense (Services → Unbound DNS → Overrides):

```
td-so          10.10.10.10
td-dfirva      10.10.10.20
fileserver-02  10.10.20.30
ot-sim         10.10.30.10
```

---

## 2. Phase 0 — ESXi preparation

1. Upload ISOs to a datastore (Storage → Datastore browser → `iso/`): OPNsense (dvd, amd64), Security Onion 3.x, Ubuntu Server 24.04, Windows eval, Kali installer.
   - Get the Security Onion ISO from the official download page and **verify its signature/hash** as that page describes.
2. Enable SSH on the host (Host → Actions → Services → Enable Secure Shell).
3. Create the switches and port groups. Copy `lab/esxi/setup-network.sh` to the host, then:

```sh
scp lab/esxi/setup-network.sh root@<esxi>:/tmp/
ssh root@<esxi> 'sh /tmp/setup-network.sh && sh /tmp/setup-network.sh --show'
```

Expected: `TD-MGMT`, `TD-IT` (20), `TD-OT` (30), `TD-SPAN` (4095).
- `TD-SPAN` has promiscuous mode = Accept.
- `TD-IT` allows MAC changes and forged transmits, for the layer 2 tests only.

4. Disable SSH again when the lab is built.

📸 No snapshot yet — nothing to snapshot.

---

## 3. Phase 1 — Router (`td-router`, OPNsense)

1. Create the VM with 4 NICs in this order: `VM Network`, `TD-MGMT`, `TD-IT`, `TD-OT`. Boot the ISO and log in as `installer` / `opnsense` to install to disk.
2. Console → *Assign interfaces*: WAN = `vmx0`, LAN = `vmx1`, OPT1 = `vmx2`, OPT2 = `vmx3`.
3. Console → *Set interface IP*:
   - LAN 10.10.10.1/24
   - OPT1 10.10.20.1/24 (rename it **IT**)
   - OPT2 10.10.30.1/24 (rename it **OT**)
   - DHCP off on all three. The lab uses static IPs, which keeps alerts readable.
4. From a browser on the WAN side, reach the web UI. Temporarily allow WAN access, or connect to it from a VM on TD-MGMT. Then set:
   - **WAN:** uncheck "Block private networks", since your home LAN is private.
   - **Firewall → Rules → LAN (MGMT):** allow any → any. Lab management needs internet for installs.
   - **Firewall → Rules → IT:**
     - allow IT net → `10.10.10.10` TCP **443, 5055, 8220, 9200** (Elastic Agent enrolment and data; 9200 for the honeypot's shipper)
     - allow IT net → any (internet, for Atomic test downloads)
     - block IT → MGMT for everything else (put this rule above the internet rule, with destination MGMT net)
   - **Firewall → Rules → OT:** allow OT → any only during installs, then block. The OT segment needs no route anywhere: the sensor sees it through `TD-SPAN`.
   - **Firewall → Rules → WAN:** allow your laptop's IP → MGMT net TCP 22, 443, 8443, 8444, 8445, 9443.
5. On your laptop, add a route to the lab:
   - Windows: `route add 10.10.0.0 mask 255.255.0.0 <router WAN IP>`
   - macOS / Linux: `sudo route add -net 10.10.0.0/16 <router WAN IP>`

Check: from a VM on TD-MGMT, `ping 1.1.1.1` works.

📸 Snapshot `td-router` → `01-router-ready`.

---

## 4. Phase 2 — Platform (`td-so`, Security Onion standalone)

### 4.1 Install

1. Create the VM: 8 vCPU, 28 GB (reserved), 400 GB. NIC 1 = `TD-MGMT`, NIC 2 = `TD-SPAN`. Boot the Security Onion 3.x ISO.
2. The ISO installs Oracle Linux 9 and asks for an **admin user and password**. Remember them; this is your SSH login. It reboots when done.
3. Log in on the console. Setup starts by itself. Choose:

| Prompt | Answer |
|---|---|
| Install type | **STANDALONE** |
| Licence | Accept the Elastic License 2.0 |
| Install | Standard (has internet) |
| Hostname | `td-so` |
| Management NIC | the TD-MGMT card (usually `ens192`) |
| Address | Static `10.10.10.10/24`, gateway `10.10.10.1`, DNS `10.10.10.1` |
| Monitor NIC(s) | the TD-SPAN card (usually `ens224`) — **no IP** |
| Web admin | your email + a strong password |
| Access by | IP (`10.10.10.10`) |
| Allow web access from | `10.10.10.0/24` (and your laptop's network if you route to it) |

4. Setup runs for 20–40 minutes. When it finishes, browse to `https://10.10.10.10` and sign in.

### 4.2 Check that the sensor sees traffic

From `td-router`'s console shell, run `ping 10.10.20.21` (the address does not need to exist yet). Then in **Hunt**, run `event.dataset:zeek.conn` for the last 15 minutes. You should see connections from 10.10.20.x / 10.10.30.x.

If nothing shows:
- `TD-SPAN` is not promiscuous, or its VLAN is not 4095, or
- the sniff NIC took an IP address.

Check with `sudo so-status` and `ip a`.

### 4.3 Industrial protocol parsing

The TechDetechtives Modbus and DNP3 rules are app-layer rules. Check in the console under **Administration → Configuration → suricata → config → app-layer → protocols** that **modbus** and **dnp3** are `enabled: yes`, with detection ports 502 and 20000. Turn them on if not, and save. Zeek's ICS parsers are part of Security Onion 3.

### 4.4 Allow the lab endpoints

**Administration → Configuration → firewall → hostgroups → `elastic_agent_endpoint`**: add `10.10.20.0/24`. This lets the IT segment enrol and send Elastic Agent data. Save.

### 4.5 Apply the TechDetechtives overlay

```bash
ssh <admin>@10.10.10.10
sudo dnf -y install git            # usually already present
git clone https://github.com/techdetechtives/techdetechtives.git techdetechtives && cd techdetechtives
#   private repository? use a read-only fine-grained token:  git clone https://<token>@github.com/techdetechtives/techdetechtives.git
sudo scripts/install.sh platform --dry-run
sudo scripts/install.sh platform \
     --jupyter-url http://127.0.0.1:8888 \
     --tickets-url https://td-dfirva:8443 \
     --vuln-url https://td-dfirva:8444
sudo scripts/verify.sh platform
```

Then in the console: **Detections → Options → Full Update**. Check the rules are on:

```bash
sudo platform/apply-overlay.sh rules
```

Turn on the layer 2 watch. Zeek restarts briefly.

```bash
sudo platform/apply-overlay.sh layer2 on
sudo platform/apply-overlay.sh layer2 status
```

📸 Snapshot `td-so` → `02-platform-overlay`. Shut it down first for a consistent snapshot, or tick "quiesce".

---

## 5. Phase 3 — DFIR-VA (`td-dfirva`): workbench, ticketing, vulnerability, network inventory

### 5.1 OS

Install Ubuntu Server 24.04:
- static `10.10.10.20/24`, gateway and DNS `10.10.10.1`
- hostname `td-dfirva`
- OpenSSH on

```bash
git clone https://github.com/techdetechtives/techdetechtives.git techdetechtives && cd techdetechtives
lab/linux/prepare-host.sh --role dfirva
newgrp docker        # or log out and back in
cp config/techdetechtives.env.example config/techdetechtives.env && chmod 600 config/techdetechtives.env
```

### 5.2 Read-only key from the platform

On **td-so**:

```bash
cd ~/techdetechtives
sudo platform/create-readonly-key.sh --allow-ip 10.10.10.20
sudo scp /etc/pki/ca.crt <user>@10.10.10.20:techdetechtives/analytics/certs/so-ca.crt
```

On **td-dfirva**, paste the two printed lines (`TD_ES_HOST=td-so`, `TD_ES_API_KEY=…`) into `config/techdetechtives.env`.

### 5.3 Install the parts, in this order

```bash
# Workbench (Jupyter + Spark)
scripts/install.sh analytics && scripts/verify.sh analytics

# Ticketing: DFIR-IRIS + alert forwarder
scripts/install.sh ticketing --name td-dfirva --ip 10.10.10.20 && scripts/verify.sh ticketing
```

On **td-so**, create the ingest keys:

```bash
sudo platform/create-ingest-key.sh                      # vulnerability (default)
sudo platform/create-ingest-key.sh --for network
```

Paste `TD_ES_INGEST_API_KEY=…` and `TD_NET_INGEST_API_KEY=…` into the env file on **td-dfirva**. Then:

```bash
# Vulnerability scanning: Greenbone + connector + dashboards.
# The first feed sync takes 30-60 minutes.
scripts/install.sh vulnerability --name td-dfirva --ip 10.10.10.20 && scripts/verify.sh vulnerability

# Network / OT inventory. --learn-hours 2 is for the lab only; use 72 in production.
scripts/install.sh network --name td-dfirva --ip 10.10.10.20 \
   --inside 10.10.0.0/16 \
   --zones "MGMT=10.10.10.0/24,IT=10.10.20.0/24,OT=10.10.30.0/24" \
   --learn-hours 2 \
   --watch "Honeywell Experion PKS; Honeywell C300; Siemens S7-300" && scripts/verify.sh network
```

### 5.4 Where everything is

| What | URL | Sign-in |
|---|---|---|
| Platform console | `https://10.10.10.10` | the web admin from setup |
| DFIR-IRIS (tickets) | `https://td-dfirva:8443` | `administrator` / `IRIS_ADM_PASSWORD` in `ticketing/iris-web/.env` |
| Vulnerability dashboard | `https://td-dfirva:8444` | `TD_VULN_USER` / `TD_VULN_PASSWORD` in the env file |
| Greenbone | `https://td-dfirva:9443` | `TD_GVM_USER` / `TD_GVM_PASSWORD` |
| Network / OT inventory | `https://td-dfirva:8445` | `TD_NET_USER` / `TD_NET_PASSWORD` |
| Workbench | `ssh -L 8888:127.0.0.1:8888 <user>@10.10.10.20` then `http://127.0.0.1:8888/lab` | `TD_JUPYTER_TOKEN` |

On your laptop, add `10.10.10.20 td-dfirva` to the hosts file so the certificate names match.

Least privilege: in DFIR-IRIS, create a user with only *alerts write*, put its API key in `TD_IRIS_API_KEY`, and re-run `scripts/install.sh ticketing …` (see `ticketing/README.md`).

📸 Snapshot `td-dfirva` → `03-dfirva-ready`.

---

## 6. Phase 4 — Honeypot (`fileserver-02`)

### 6.1 OS

Install Ubuntu Server 24.04 on `TD-IT`:
- static `10.10.20.30/24`, gateway `10.10.20.1`
- hostname `fileserver-02` — a believable server name

### 6.2 Install

On **fileserver-02**:

```bash
git clone https://github.com/techdetechtives/techdetechtives.git techdetechtives && cd techdetechtives
lab/linux/prepare-host.sh --role honeypot && newgrp docker
cp config/techdetechtives.env.example config/techdetechtives.env && chmod 600 config/techdetechtives.env
```

On **td-so**:

```bash
cd ~/techdetechtives
sudo platform/create-ingest-key.sh --for honeypot --allow-ip 10.10.20.30
sudo scp /etc/pki/ca.crt <user>@10.10.20.30:techdetechtives/analytics/certs/so-ca.crt
```

Back on **fileserver-02**, set only these three values in `config/techdetechtives.env`:
- `TD_ES_HOST=td-so`
- the `TD_HONEYPOT_API_KEY=…` line printed on td-so
- `TD_HONEYPOT_IGNORE_IPS=10.10.10.20` — the Greenbone scanner, so scans don't raise honeypot alerts

```bash
scripts/install.sh honeypot --name fileserver-02 --ip 10.10.20.30 --services ftp,http,rdp,mysql,ssh --port ssh=2222
scripts/verify.sh honeypot
```

Never copy the DFIR-VA env file here. The honeypot holds only its own append-only key.

📸 Snapshot → `04-honeypot-ready`.

---

## 7. Phase 5 — OT simulators (`ot-sim`)

Install Ubuntu Server 24.04 on `TD-OT`:
- static `10.10.30.10/24`, gateway `10.10.30.1`
- hostname `ot-sim`

Allow OT → internet in OPNsense for this step only.

```bash
git clone https://github.com/techdetechtives/techdetechtives.git techdetechtives && cd techdetechtives
lab/linux/prepare-host.sh --role otsim && newgrp docker
cd lab/ot-sim && docker compose up -d --build && docker compose logs --tail 20
```

Expected log lines:
- Modbus/TCP on 502
- S7 (snap7) on 102
- DNP3 stand-in on 20000
- Experion listeners on 55553 and 55555

Then block OT → internet again in OPNsense.

📸 Snapshot → `05-ot-sim-ready`.

---

## 8. Phase 6 — Lab endpoints

### 8.1 Windows (`win-victim`)

1. Install Windows on `TD-IT`:
   - static `10.10.20.21/24`, gateway `10.10.20.1`, DNS `10.10.20.1`
   - local admin account; no domain needed
   - VMware Tools installed
2. Copy `lab/windows/prepare-victim.ps1` to the VM. In an elevated PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\prepare-victim.ps1                      # add -AddDefenderExclusion if Defender deletes the atomics folder
Restart-Computer
```

3. **Elastic Agent:** in the platform console, open **Downloads**. Download the **Windows Elastic Agent installer** that Security Onion generates for this deployment. Run it as administrator on `win-victim`.
4. Check in Hunt, from the last 15 minutes: `host.name:"win-victim"`. Look for process events (`event.category:process`) and PowerShell script block events (`event.code:4104`).
5. **detechEDR:** its repository is still a scaffold, with no agent released yet. Leave this VM as its first test endpoint. When the agent ships, install it here next to Elastic Agent and compare detections.

📸 Snapshot → `06-win-clean`. Revert to it after each test day.

### 8.2 Linux (`lnx-victim`)

1. Install Ubuntu Server 24.04 on `TD-IT`, static `10.10.20.22/24`.
2. Run `lab/linux/prepare-host.sh --role victim`.
3. Install the **Linux Elastic Agent** from the console's Downloads page. Check with `host.name:"lnx-victim"` in Hunt.

📸 Snapshot → `06-lnx-clean`.

### 8.3 Attacker (`kali`)

1. Create the VM with NIC 1 = `TD-IT` (`10.10.20.66/24`, gateway `10.10.20.1`) and NIC 2 = `TD-OT` (`10.10.30.66/24`, no gateway).
2. Run:

```bash
git clone https://github.com/techdetechtives/techdetechtives.git techdetechtives && cd techdetechtives
lab/linux/prepare-host.sh --role attacker
```

📸 Snapshot → `06-kali-ready`.

---

## 9. Phase 7 — Validation runbook

Run **one test at a time**. For each test:
1. Wait 2–5 minutes. Sigma rules run on a schedule.
2. Check the console **Alerts** page for the rule.
3. Check that a **DFIR-IRIS ticket** follows (medium and above).
4. Write the date and Security Onion version into the entry's `confirmed:` field in `platform/detections/validation.yml`.

### 9.1 Endpoint rules (on `win-victim`, elevated PowerShell)

| Rule | Command | Expect |
|---|---|---|
| WMI spawning a script interpreter (T1047) | `Invoke-AtomicTest T1047 -TestGuids b3bdfc91-b33e-4c6d-a5c8-d64bee0276b3 -InputArgs @{ "process_to_execute" = "cscript.exe" }` | Alert + ticket |
| PowerShell encoded + hidden (T1059.001) | `powershell.exe -WindowStyle Hidden -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFQAZQBjAGgARABlAHQAZQBjAGgAdABpAHYAZQBzACAAZABlAHQAZQBjAHQAaQBvAG4AIAB0AGUAcwB0ACcA` | Alert + ticket |
| Base64 decode + invoke (T1059.001) | Atomic "PowerShell Fileless Script Execution" (id in `validation.yml`) | Alert (needs Script Block Logging — done by the prep script) |
| Suricata 1900001 dynamic DNS | `nslookup td-test.duckdns.org` | Alert |
| Suricata 1900002 PowerShell UA | `powershell -Command "Invoke-WebRequest http://example.com -UseBasicParsing"` (plain http) | Alert |

Clean up each Atomic test with the same command plus `-Cleanup`.

On `lnx-victim`: run the "Download piped directly into a shell" test from `validation.yml` (T1059.004).

### 9.2 OT rules (from `kali`, OT card; target `ot-sim` 10.10.30.10)

```bash
source ~/otvenv/bin/activate
# Modbus device identification -> 1900103 / 1900104
nmap -Pn -p 502 --script modbus-discover 10.10.30.10
# S7 PLC STOP -> 1900151
python3 -c "import snap7; c=snap7.client.Client(); c.connect('10.10.30.10',0,1); c.plc_stop()"
# DNP3 Cold Restart -> 1900121
python3 ~/techdetechtives/lab/ot-sim/dnp3_cold_restart.py 10.10.30.10
# Experion engineering port, climbing folder path -> 1900186 / 1900182
printf 'AAAA..\\..\\..\\test' | nc -q1 10.10.30.10 55553
```

`docker compose logs` on `ot-sim` shows what arrived.

### 9.3 Network inventory (OT baseline)

After the 2-hour learning window:
1. Open `https://td-dfirva:8445`. Check that `ot-sim`, the Modbus/S7 conversations and the zones are listed.
2. Run `nmap -Pn -p 502 --script modbus-discover 10.10.30.10` from the **IT** card of `kali`. That is a new industrial conversation from a new station.
3. Expect a **change** on the page, then a platform alert (`event.module: netmap`), then a ticket.

### 9.4 Honeypot (from `kali`)

```bash
curl -s http://10.10.20.30/index.html | head
nmap -sT -p 21,80,2222,3306,3389 10.10.20.30
```

Expect one alert per first contact per decoy, then tickets.

### 9.5 Flood and layer 2 (isolated lab segment only, a few seconds each)

```bash
sudo timeout 5 hping3 --icmp --flood 10.10.20.22        # 1900301/1900302 -> alert
ping -c 20 10.10.20.22                                  # must stay quiet
sudo timeout 5 hping3 -S --flood -p 80 10.10.20.22      # 1900311/1900312 -> alert
sudo timeout 30 arpspoof -i eth0 -t 10.10.20.21 10.10.20.1   # layer 2 -> zeek.notice + alert
```

Layer 2 notices appear in Hunt straight away (`event.dataset:zeek.notice AND notice.note:TechDetechtives*`). The alerts follow a few minutes later.

### 9.6 Vulnerability scan

1. In Greenbone (`:9443`), create target `10.10.20.0/24`, excluding `10.10.20.30`, and a *Full and fast* task. Start it.
2. When it finishes, expect:
   - findings on the dashboard (`:8444`)
   - `event.dataset:greenbone.result` in Hunt
   - tickets for medium and above
3. Expect Suricata rule 1900311 to fire during the scan. That is correct, not a fault.

**Do not scan `TD-OT`.** Real controllers can crash; the simulators are there only for the rule tests.

### 9.7 Workbench

Open `01_connect_and_explore`. The connection check should list the data sets. Then run `02_process_creation_hunt` against `win-victim`'s data.

---

## 10. Power-on order, snapshots, resources

**Power-on order:** `td-router` → `td-so` (wait until `so-status` is all green, about 10 minutes) → `td-dfirva` → `fileserver-02` → `ot-sim` → endpoints → `kali`.

**Snapshot plan:**

| VM | Snapshots |
|---|---|
| `td-router` | `01-router-ready` |
| `td-so` | `02-platform-overlay` |
| `td-dfirva` | `03-dfirva-ready` |
| `fileserver-02` | `04-honeypot-ready` |
| `ot-sim` | `05-ot-sim-ready` |
| `win-victim` | `06-win-clean` (revert after test days) |
| `lnx-victim` | `06-lnx-clean` |
| `kali` | `06-kali-ready` |

Before a platform upgrade (`soup`), snapshot `td-so` and `td-dfirva` together.

**Resource tips:**
- Watch `td-so` memory in the ESXi performance tab. Sustained ballooning or swapping means you need more RAM or a shorter retention.
- Greenbone's first feed sync is CPU-heavy. Avoid running tests during it.
- Disk grows fastest on `td-so` (PCAP and Elasticsearch). Set PCAP and retention limits in Administration → Configuration for a 400 GB disk.

---

## 11. Troubleshooting

| Symptom | Check |
|---|---|
| No Zeek/Suricata data | `TD-SPAN` promiscuous + VLAN 4095; sniff NIC has no IP; `sudo so-status` |
| Endpoint not in Hunt | `elastic_agent_endpoint` hostgroup includes 10.10.20.0/24; OPNsense IT → 10.10.10.10 TCP 443/5055/8220 allowed; agent status in Fleet |
| Installer: "cannot find the platform by name" | `/etc/hosts` has `10.10.10.10 td-so` (`prepare-host.sh` adds it) |
| "CA certificate … is missing" | copy `/etc/pki/ca.crt` from td-so to `analytics/certs/so-ca.crt` |
| Alerts but no tickets | `docker logs -f td-forwarder`; `TD_TICKET_MIN_SEVERITY`; IRIS API key |
| Modbus/DNP3 rules silent | app-layer parsers enabled (4.3); traffic crosses `TD-SPAN` (both VMs on `vSwitch-TD-LAB`) |
| Honeypot alerts from the scanner | `TD_HONEYPOT_IGNORE_IPS=10.10.10.20` on the honeypot; exclude it from scan targets |
| Layer 2 tests do nothing | `TD-IT` allows MAC changes/forged transmits; `layer2 status` on td-so; wait 10 min for Zeek to learn |

---

## 12. What this lab does not include

- **TDCaution-CTI** (dark web and threat feeds) is a separate repository. Add its CTI Hub as `td-cti-hub` on `TD-MGMT` (8 vCPU, 16 GB) when the core is stable. Point `tdcti import` at DFIR-IRIS here.
- **detechEDR** — waits for the agent release (8.1).
- **A separate OT sensor node** — added only with 96 GB+ (1.2).
