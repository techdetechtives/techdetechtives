# Review of five outside projects

Reviewed 2026-10-06 by reading each repository's code. Nothing was run: the
question for each was whether it works in an isolated network and whether it
would improve the TechDetechtives OT IDS. `AI-NIDS-REVIEW.md` covers a sixth
project reviewed earlier the same day.

| Project | Works isolated? | Verdict |
| --- | --- | --- |
| [aleksibovellan/opnsense-suricata-nmaps](https://github.com/aleksibovellan/opnsense-suricata-nmaps) | Yes | **Adopted**: 8 of its 10 rules, as the `nmap-scans` source |
| [OWASP/SecureTea-Project](https://github.com/OWASP/SecureTea-Project) | Partly | Not adopted. Its layer 2 detections are worth having; the OT IDS now gets them from this repository's own layer 2 watch |
| [HoangNV2001/Real-time-IDS](https://github.com/HoangNV2001/Real-time-IDS) | Mostly | Not adopted, and cannot be: it has no licence |
| [Albertsr/Anomaly-Detection](https://github.com/Albertsr/Anomaly-Detection) | Yes | Not adopted: study notes, not a detector |
| [notsodubeyous/Network-Intrusion-Detection-Using-Machine-Learning](https://github.com/notsodubeyous/Network-Intrusion-Detection-Using-Machine-Learning) | Yes | Not adopted: notebooks on a 1999 dataset |

## opnsense-suricata-nmaps: adopted

Commit `678d850`, MIT licence. Ten Suricata rules that recognise Nmap by the
traits of its own packets (TCP window 1024 with MSS 1460, the Xmas flag set,
empty UDP probes) and by its timing: SYN, connect, ACK, Xmas, fragmented and
UDP scans at speeds T1 to T5. Its author tested them on Suricata 7.0.4 on a
home network. They are static rules, so they work offline.

A port scan is one of the first things an intruder does on a control network,
and nothing else in the OT IDS names the scanner. Two changes are made on
import (`sources.conf`, section `nmap-scans`):

- **One alert per window instead of one every few packets.** As published, the
  rules alert again on every 7th or 20th probe, so one scan raises dozens of
  alerts. The thresholds are switched from "every Nth match" to "once per
  window".
- **The two port-4444 rules are left out.** They alert on every packet to port
  4444, with no rate limit, at the highest priority, as "trojan activity". On a
  plant network that is too blunt to trust.

The rules are renumbered to 1912000 onwards. The build still checks them with
the product's own Suricata. Known limits, from the author: the slowest scans
(T0) and scans of a handful of ports are not seen, and some VPN clients set off
the fragment rule. On a server with Internet access the same rule set can be
switched on from Suricata's own source list instead (`aleksibovellan/nmap`).

## OWASP SecureTea: not adopted

Commit `7a2da87`, MIT licence, last change April 2023.

**What it is.** A security toolkit for one machine: a packet sniffer with
detection rules, a firewall, a web application firewall, an antivirus wrapper,
log monitors, and notifications. 285 Python files and about 100 Python
packages, TensorFlow among them.

**Isolated?** Partly. The sniffer, firewall and log monitors need no Internet.
The antivirus and malware analysis call VirusTotal; the notifiers are Slack,
Telegram, Twitter, Discord, SMS and AWS; other parts call SSL Labs and
emailrep.io. Installing 100 packages without Internet access is its own job.

**Why not.**

- It protects the machine it runs on. The OT IDS watches a network; its own
  host is already covered by a default-deny firewall and the hardening in
  `hardening/`.
- Its network detection is one Python function called for every packet. Next
  to Suricata and Zeek on the same traffic it would be the slowest of three
  and see nothing they do not.
- It knows no industrial protocol.
- Three and a half years without a change, and its package metadata still
  names Python 2.7 and 3.6.

**What was worth having.** Its network rules cover SYN and DNS floods, LAND and
oversized pings, port scans, and layer 2 attacks: ARP spoofing, MAC table
flooding and DHCP exhaustion. The floods and scans are already covered by the
shared flood rules and, now, the Nmap rules. The layer 2 attacks were the gap:
ARP poisoning is how an intruder gets between an operator station and a
controller. This repository already has a tested watch for them
(`platform/zeek/techdetechtives/l2-watch.zeek`: ARP poisoning, an address
taken over by another network card, MAC flooding, ARP sweeps). The OT IDS build
now adds it, on one condition: the product's own Zeek must parse it without
error during the build. A script Zeek cannot load stops Zeek, so in every other
case the build leaves it out and says so in `out/rule-check.txt`. DHCP
exhaustion is not covered.

## Real-time-IDS: cannot be adopted

Commit `c51564c`, June 2025. **It has no licence**, so nobody but its author
may copy, change or ship it.

Apart from that it is the most complete of the machine-learning projects
reviewed: it really captures packets (Scapy), builds its own flow statistics,
scores each flow with a random forest (trained on CIC-IDS2018 and SCVIC-APT)
and an autoencoder, and explains a verdict with LIME, which runs locally.

Other reasons it would not fit:

- Its instructions are for Windows with Npcap and Python 3.9, and its saved
  models only load with the exact library versions it pins (TensorFlow 2.11,
  scikit-learn 1.2).
- For every flow with a public address it asks ipinfo.io for the country, which
  tells an outside service who the plant talks to. Offline the call fails
  quietly, but it has no time limit.
- The web page runs in Flask's debug mode with a fixed secret key. Debug mode
  lets anyone who can reach the page run code on the machine.
- Its models are Python pickles, which run code when loaded.
- Trained on office-network attacks; no industrial traffic.

## Anomaly-Detection (Albertsr): not adopted

Commit `0d8ffd6`, MIT licence. By its own description an educational
collection: 19 short Python files (485 lines) and notes on anomaly detection
for tables of numbers, written around 2018 and kept as a historical record. PCA
and kernel PCA reconstruction error, RobustPCC, Mahalanobis distance, Isolation
Forest, Local Outlier Factor, and two semi-supervised methods. Its README says
some scripts no longer run on current scikit-learn.

It runs offline (NumPy and scikit-learn) and reads no traffic. There is nothing
to deploy: the well-known methods in it are already in scikit-learn, and the
platform's anomaly detection (Random Cut Forest, with the three OT detectors
this folder adds) does the same job on the sensor's own records.

## Network-Intrusion-Detection-Using-Machine-Learning: not adopted

Commit `0c270e5`, GPL-3.0, last change October 2021. Three Jupyter notebooks
that train eight kinds of classifier on NSL-KDD, and 312 MB of dataset and saved
models. No packet capture, no live use.

NSL-KDD is a cleaned copy of the 1999 KDD Cup data: simulated attacks on a
military office network of that time. Its 41 features come from a tool that
the sensors do not run, and nothing in it resembles a control network. A model
trained on it would have to be retrained on site with labelled attacks, which a
plant does not have.

## What this means for machine learning in the OT IDS

Three of the six projects reviewed today are classifiers trained on public
office-network datasets, and a fourth is a set of algorithm notes. None can be dropped into a plant. What transfers is
the method the better ones use, an autoencoder or forest that learns normal
traffic and scores departures from it, and the OT IDS has that in the platform's
anomaly detection. A purpose-built version is described at the end of
`AI-NIDS-REVIEW.md`.
