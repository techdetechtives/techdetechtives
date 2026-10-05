# Honeypot

A decoy machine on your internal network. It offers services that look real (a web sign-in page, FTP, Remote Desktop, databases and more) and has no legitimate users, so **any contact with it is worth looking at**: a port sweep, a curious insider, malware spreading sideways, or an intruder exploring after getting in.

The decoys are [OpenCanary](https://github.com/thinkst/opencanary), the open-source honeypot from Thinkst Applied Research that Security Onion also uses for its own honeypot nodes. TechDetechtives adds a shipper that turns each contact into a platform alert, which the ticket forwarder then opens as a DFIR-IRIS ticket.

| Part | What it is | Where it comes from |
| --- | --- | --- |
| OpenCanary 0.9.10 | The decoy services, in one container | Installed unchanged into a container image at the commit pinned in `upstream.lock`. BSD 3-Clause. |
| Shipper | One small container that reads the honeypot's log and sends each contact to the platform | `honeypot/shipper/` in this repository. MIT. Python standard library only. |

OpenCanary is a *low-interaction* honeypot: it answers enough to look real and records what the visitor tries, but there is nothing behind the sign-in prompts. Nobody can log in to it or run commands on it.

## Where to run it

On a machine of its own, used for nothing else, on the network you want to watch. A decoy is the machine most likely to be attacked, so it should hold nothing of value and sit apart from the platform, the tickets and the scan data.

- **Never on the platform.** `scripts/install.sh honeypot` refuses to run on the Security Onion machine. The only honeypot step done there is creating its key (step 1 below).
- **Not on the ticketing machine either**, unless it is a throwaway lab. It works there, but the decoy then shares a machine with your tickets and vulnerability findings, and port clashes limit which decoys you can offer.
- **Keep it off the internet.** An internet-facing honeypot is contacted constantly and would flood the ticket queue.

### Preparing the machine

A small virtual machine is enough: 1 CPU core, 2 GB RAM and 20 GB disk, with a current Ubuntu Server or Debian. Give it a fixed address and a name that fits in among your servers (`fileserver-02`, `backup-nas`), because that name is what a visitor sees and what alerts show.

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-v2 git
sudo usermod -aG docker "$USER" && newgrp docker
docker compose version          # must print a version
```

The machine needs internet access once, to build the honeypot image. After that it only needs to reach the platform on port 9200. It must also be able to find the platform by name; if it cannot, add a line such as `172.16.101.150  securityon` to `/etc/hosts` (the installer tells you when this is missing).

## Install

**1. On the platform**, create the honeypot's key and let the honeypot machine through the firewall:

```bash
sudo platform/create-ingest-key.sh --for honeypot --allow-ip <honeypot machine IP>
```

The key can only add honeypot events. It cannot read anything, so the machine most likely to be attacked holds nothing that helps an attacker.

**2. On the honeypot machine:**

```bash
git clone https://github.com/techdetechtives/techdetechtives.git techdetechtives && cd techdetechtives
cp config/techdetechtives.env.example config/techdetechtives.env     # skip if the file exists
# In config/techdetechtives.env set TD_ES_HOST to the platform's name and paste
# the TD_HONEYPOT_API_KEY line from step 1. Nothing else in that file is needed here.
```

**3. On the platform**, send its CA certificate (a public file) to the honeypot machine:

```bash
sudo scp /etc/pki/ca.crt <user>@<honeypot machine IP>:techdetechtives/analytics/certs/so-ca.crt
```

**4. On the honeypot machine:**

```bash
scripts/install.sh honeypot --name fileserver-02 --ip <this machine's IP>
scripts/verify.sh honeypot
```

The settings file on this machine holds only the honeypot's own key. Do not copy `config/techdetechtives.env` from the ticketing machine: it contains the read-only key and the ticketing passwords, which have no business on a decoy.

`--name` is the name shown on alerts. `--ip` is this machine's address, shown as the destination.

### Choosing decoys

```bash
honeypot/setup-honeypot.sh --list
scripts/install.sh honeypot --services ftp,http,rdp,mysql,ssh --port ssh=2222
```

| Decoy | Port | Decoy | Port |
| --- | --- | --- | --- |
| `ftp` | 21 | `rdp` (Remote Desktop) | 3389 |
| `ssh` | 22 | `vnc` | 5900 |
| `telnet` | 23 | `redis` | 6379 |
| `http` (sign-in page) | 80 | `httpproxy` | 8080 |
| `https` | 443 | `git` | 9418 |
| `mssql` | 1433 | `mongodb` | 27017 |
| `mysql` | 3306 | | |

The default set is `ftp,http,telnet,mysql,mssql,rdp,vnc,redis`. The SSH decoy is not in it because port 22 is normally the machine's own SSH. On a dedicated machine the convincing arrangement is to move your own SSH to another port (set `Port 2200` in `/etc/ssh/sshd_config`, restart SSH, and confirm you can sign in on the new port before closing your session) and then give the decoy port 22 with `--services ftp,http,telnet,mysql,mssql,rdp,vnc,redis,ssh`. Otherwise add it on another port with `--port ssh=2222`. `--port NAME=PORT` works for any decoy. Re-running the command without options keeps your earlier choices.

## What you get

- **An alert for every first contact.** It appears on the platform's Alerts page as `Honeypot: FTP sign-in attempt`, `Honeypot: Web page requested`, `Honeypot: Remote Desktop sign-in attempt` and so on, with the visitor's address, the decoy and port, and the user name tried.
- **A ticket for each alert**, through the existing forwarder. No extra setup on the ticketing machine.
- **Every contact stored**, searchable in Hunt with `event.module:opencanary`.

| What happened | Severity | Ticket by default |
| --- | --- | --- |
| A sign-in attempt, a command, a file or repository request | High | Yes |
| A connection or page request with nothing further | Medium | Yes |
| Extra detail about a contact already reported | Low | No |

**Repeats do not flood the queue.** After an alert, further contacts from the same address to the same decoy are stored as plain events for 30 minutes (`TD_HONEYPOT_REPEAT_MINUTES`) instead of raising new alerts. A password-guessing run of a thousand attempts is one alert, or two if it began with a bare connection and then got worse, and a thousand searchable events. If it is still going after 30 minutes you get another alert.

**Passwords are withheld.** OpenCanary records the passwords visitors try. A colleague who mistypes into a decoy would otherwise have a real password copied into the platform and a ticket, so the shipper replaces them with `(withheld)`. User names are kept. The passwords stay in the honeypot's own log on this machine (`docker exec td-honeypot cat /var/log/opencanary/opencanary.log`). Set `TD_HONEYPOT_KEEP_PASSWORDS=1` to send them.

## Try it

From **another** machine on the network (not the honeypot itself):

```bash
curl http://<honeypot IP>/index.html             # medium: Web page requested
curl -d 'username=admin&password=test' http://<honeypot IP>/index.html     # high: Web sign-in attempt
ftp <honeypot IP>                                # sign in with anything: high
```

Within about half a minute the alert is on the platform's Alerts page; a minute or two later the ticket is in DFIR-IRIS. This is also the quickest way to see an alert travel the whole path to a ticket.

## Things that will set it off, and what to do

- **Your vulnerability scanner.** A Greenbone scan that includes the honeypot touches every decoy. Either leave the honeypot out of scan targets, or put the scanner's address in `TD_HONEYPOT_IGNORE_IPS` (comma separated addresses or ranges such as `10.20.30.50,10.20.31.0/24`). Ignored addresses leave no record on the platform.
- **Inventory and monitoring tools** that sweep the network. Same choice.
- **People.** Tell nobody the name is a decoy unless they need to know, but do tell the team that owns the address range, so it is not assigned to something else.

After changing settings in `config/techdetechtives.env`, re-run `scripts/install.sh honeypot`.

## Keeping it safe

- The honeypot container runs on its own Docker network, cannot reach other containers, and holds only the three privileges it needs to open low ports and then drop to an unprivileged account.
- The shipper reads the honeypot's log read-only and has no privileges at all.
- The platform key on this machine can append honeypot events and nothing else.
- The decoys can still start outgoing connections through Docker's normal networking. OpenCanary does not need any; if your network allows it, block outgoing traffic from this machine except to the platform on port 9200.
- Treat the machine as untrusted: keep nothing else of value on a dedicated honeypot.

## Operating it

```bash
scripts/verify.sh honeypot          # containers, decoy ports, log, platform connection
docker logs td-honeypot             # OpenCanary's own output
docker logs td-honeypot-shipper     # what was sent
scripts/install.sh honeypot-down    # stop both
```

If the platform is unreachable the shipper waits and sends everything when it returns; nothing is lost or sent twice. Events delivered more than five minutes late are stamped with the delivery time so the forwarder still tickets them; the time they happened is in `event.created`.

## Not yet run on a live system

This part was built and tested against stand-ins. Three things in particular have not been seen working and are the first suspects if something is wrong:

- **The OpenCanary image build and start.** If `td-honeypot` does not stay up, read `docker logs td-honeypot`. A permission error at start points at the reduced privilege list (`cap_drop` / `cap_add`) in `honeypot/docker-compose.yml`.
- **Visitor addresses.** With Docker's default networking the alert shows the visitor's real address. If every alert shows an address like `172.x.x.1` instead, Docker on that machine is rewriting addresses (this happens when you test from the honeypot machine itself, and with some Docker configurations).
- **Storage on the platform.** Events go to the data stream `logs-opencanary.alerts-techdetechtives`, which the platform should create on first use. `docker logs td-honeypot-shipper` shows the platform's answer if it refuses.

A second option exists that needs none of this: Security Onion has its own honeypot node type (an "Intrusion Detection Honeypot"), installed from the Security Onion image onto a dedicated machine and joined to the platform. It is the better choice if you can spare a machine for a full Security Onion node.
