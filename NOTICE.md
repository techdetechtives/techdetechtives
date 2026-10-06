# Notices

TechDetechtives combines original work with seven upstream projects, refers to an eighth, and carries a reference list drawn from MITRE ATT&CK. Each part keeps its own licence. This file is not legal advice.

## 1. Security Onion (platform base)

- Project: Security Onion, https://github.com/Security-Onion-Solutions/securityonion
- Copyright Security Onion Solutions, LLC
- Licence: Elastic License 2.0 (ELv2), full text in `licenses/Elastic-License-2.0.txt`
- Version this overlay was written against: 3.3.0 (commit in `upstream.lock`)

**This is a modified deployment.** TechDetechtives changes an installed Security Onion in the ways listed in `MODIFICATIONS.md`. Security Onion's source code and installation image are not included in this repository and are not redistributed by it.

What the Elastic License 2.0 requires of anyone using this:

- You may not provide the software to third parties as a hosted or managed service that gives them access to a substantial set of its features.
- You may not move, change, disable or circumvent the licence-key functionality, or remove or obscure functionality protected by it.
- You may not alter, remove or obscure any licensing, copyright or other notices of the licensor.
- If you distribute copies, recipients must receive the licence terms, and modified copies must carry prominent notices that they were modified.

**Trademarks.** "Security Onion" and the Security Onion logos are registered trademarks of Security Onion Solutions, LLC. TechDetechtives uses the name only to state what it is built on. TechDetechtives is not affiliated with, sponsored by or endorsed by Security Onion Solutions, LLC. The overlay leaves the platform's own logo, notices and licence screens in place.

Elasticsearch, Kibana and the other Elastic components shipped with the platform are also under the Elastic License 2.0. Suricata, Zeek and the other bundled tools keep their own licences.

## 2. HELK (analytics base)

- Project: HELK, "The Hunting ELK", https://github.com/Cyb3rWard0g/HELK
- Copyright Roberto Rodriguez (@Cyb3rWard0g) and contributors
- Licence: GNU General Public License v3.0, full text in `analytics/LICENSE` and `licenses/GPL-3.0.txt`
- Commit the derivation started from: see `upstream.lock`

**Everything under `analytics/` is a modified work derived from HELK and is licensed under GPL-3.0.** The modifications and their dates are listed in `MODIFICATIONS.md` and in the header of each file. If you distribute `analytics/` or a container image built from it, you must make the corresponding source available under the same licence.

TechDetechtives is not affiliated with or endorsed by the HELK authors.

## 3. DFIR-IRIS (ticketing)

- Project: DFIR-IRIS, https://github.com/dfir-iris/iris-web
- Copyright DFIR-IRIS and contributors
- Licence: GNU Lesser General Public License v3.0
- Version installed: see `upstream.lock`

DFIR-IRIS is installed unmodified. `ticketing/setup-iris.sh` fetches it from its own repository at install time into `ticketing/iris-web/`, where its licence file stays with it; its code is not included in this repository. The setup script supplies configuration only: generated secrets, a TLS certificate, a host name and a port. The TechDetechtives forwarder is a separate program that talks to DFIR-IRIS over its HTTP API.

TechDetechtives is not affiliated with or endorsed by the DFIR-IRIS project.

## 4. Greenbone Community Edition (vulnerability scanning)

- Project: Greenbone Community Edition, https://github.com/greenbone (OpenVAS scanner, gvmd, GSA and related components)
- Copyright Greenbone AG and contributors
- Licences: GNU Affero General Public License v3.0 for the manager and web interface, GNU General Public License v2.0 for the scanner. The container setup file comes from Greenbone's documentation, which is under Creative Commons Attribution-ShareAlike 4.0.
- Version installed: see `upstream.lock`

Greenbone is installed unmodified from its official container images. `vulnerability/setup-greenbone.sh` fetches its setup file at install time into `vulnerability/greenbone/` and adds a small generated override that publishes the web interface on the internal network; none of Greenbone's code or its setup file is included in this repository. The TechDetechtives connector is a separate program that reads scan results from Greenbone over its management protocol.

"Greenbone" and "OpenVAS" are trademarks of Greenbone AG. TechDetechtives is not affiliated with or endorsed by Greenbone AG.

## 5. Community cybersecurity skills (analyst skills)

- Project: https://github.com/mukul975/Anthropic-Cybersecurity-Skills
- Copyright 2026 mukul975 and contributors
- Licence: Apache License 2.0, full text in `licenses/Apache-2.0.txt` and in each copied skill folder
- Commit copied from: see `upstream.lock`

**A selection of this project's documents is included in this repository**, under `skills/community/`: for each of the skills named in `skills/selection.txt`, its `SKILL.md`, `LICENSE`, `references/` and `assets/` files. The files are unchanged; `skills/MANIFEST.sha256` records their checksums. The upstream `scripts/` folders and translations are not included. Apart from the MITRE ATT&CK reference list in section 8, this is the only upstream material copied into this repository.

The project is an independent community effort. It is not affiliated with Anthropic, and TechDetechtives is not affiliated with or endorsed by its authors or by Anthropic.

Atomic Red Team (https://github.com/redcanaryco/atomic-red-team, Copyright Red Canary, MIT licence) is referred to by `platform/detections/validation.yml`, which names tests by their public identifiers. None of it is included in this repository.

## 6. OpenCanary (honeypot)

- Project: OpenCanary, https://github.com/thinkst/opencanary
- Copyright (c) 2018, Thinkst Applied Research. All rights reserved.
- Licence: BSD 3-Clause, full text in `licenses/BSD-3-Clause-OpenCanary.txt`
- Version installed: see `upstream.lock`

OpenCanary is used unmodified. `honeypot/opencanary/Dockerfile` installs it from its own repository, at the pinned commit, into a container image built on your machine; none of its code is included in this repository. `honeypot/make_config.py` writes a settings file for it, and the TechDetechtives shipper is a separate program that only reads the log file OpenCanary writes.

TechDetechtives is not affiliated with or endorsed by Thinkst Applied Research. Their name is not used to promote this project.

## 7. Malcolm (OT IDS base)

- Project: Malcolm, https://github.com/idaholab/Malcolm
- Copyright Battelle Energy Alliance, LLC
- Licence: Apache License 2.0, full text in `licenses/Apache-2.0.txt`
- Version the OT IDS is built on: 26.09.0 (tag and commit in `upstream.lock`)

Malcolm's source code and container images are **not** included in this repository. `ot-ids/build-iso.sh` clones Malcolm at the pinned commit on the build host, changes that copy in the ways listed in `MODIFICATIONS.md`, downloads Malcolm's published container images, and builds installer ISOs from them. Anyone who distributes those ISOs is distributing a modified Malcolm and must keep Malcolm's `LICENSE.txt` and `NOTICE.txt` with them and state that it was changed; the build places a notice saying so on the installed system, and the landing page reads "built on Malcolm" with Battelle Energy Alliance's copyright line.

Malcolm bundles Zeek, Suricata, Arkime, OpenSearch, NetBox and other tools, each under its own licence, and the Emerging Threats Open rule set (MIT). The JA4+ fingerprinting used by its Zeek and Arkime has its own licence from FoxIO, with conditions on commercial use; read it before selling a product that includes it. "Malcolm", "Hedgehog Linux", "Arkime", "NetBox" and "OpenSearch" are names of their owners' projects; the OT IDS replaces Malcolm's logo with the TechDetechtives emblem on the pages it brands and leaves the other tools' own screens as they are. TechDetechtives is not affiliated with or endorsed by Idaho National Laboratory, CISA or Battelle Energy Alliance.

External rule sets and threat indicators are downloaded when an ISO or an update is built, not stored here. `ot-ids/sources.conf` names each one and its licence: by default NSA ELITEWOLF (CC0), Digital Bond Quickdraw (MIT), Aleksi Bovellan's Nmap scan detection rules (MIT), a selection from Critical Path Security's collection of public threat feeds (MIT collection; each feed keeps its own terms) and CISA's Known Exploited Vulnerabilities catalogue (CC0). Sources under the GPL or custom terms are listed but switched off.

## 8. MITRE ATT&CK for ICS (technique reference of the OT IDS)

- Source: MITRE ATT&CK for ICS 19.2, https://attack.mitre.org, data from https://github.com/mitre-attack/attack-stix-data (commit in `upstream.lock`)
- © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.
- Licence (MITRE's ATT&CK terms of use): The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for research, development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy.

**`ot-ids/attack/ics-attack.json` reproduces parts of ATT&CK for ICS**: the identifiers and names of its tactics, techniques, mitigations, software, groups and campaigns, which technique belongs to which, the data components MITRE lists for detecting each technique, and the first sentence of each technique's description. The wording is MITRE's; citation markers and links are taken out of the sentences. The coverage files under `ot-ids/docs/`, the pages the OT IDS build places in `~/Malcolm/attack-ics/` on an installed system, and the technique names written into rule metadata are made from it. The copyright line and the licence above are inside the reference file and each generated page, and must stay with any copy.

Which TechDetechtives detection is mapped to which technique (`ot-ids/attack/*.csv`) is TechDetechtives' own judgement, not MITRE's. MITRE does not claim ATT&CK lists every possible adversary behaviour, and provides it "as is" without warranty. MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation. TechDetechtives is not affiliated with or endorsed by MITRE.

The ACID package (https://github.com/cisagov/ACID, © The MITRE Corporation, Apache-2.0) is part of Malcolm and is not included here; `ot-ids/attack/other-detections.csv` lists the techniques it reports, as read from its source.

## 9. Original TechDetechtives work

Everything outside `analytics/`, `skills/community/` and `ot-ids/attack/ics-attack.json` (the platform overlay, rules, ticket forwarder, vulnerability connector and dashboard, honeypot shipper and setup, the skills under `skills/techdetechtives/`, the OT IDS build, rules and tools under `ot-ids/`, scripts and documentation) is original work, Copyright (c) 2026 TechDetechtives, under the MIT licence in `LICENSE`.

The TechDetechtives emblem in `branding/` was supplied by the project owner. It contains no other organisation's logo. The images under `ot-ids/overlay/branding/` are made from it by `ot-ids/tools/make-artwork.py`.

## How the parts are kept separate

The platform, the analytics workbench, the ticket forwarder, DFIR-IRIS, Greenbone, the vulnerability connector, OpenCanary and the honeypot shipper are separate programs. The workbench and the forwarder read from the platform only over its Elasticsearch HTTP API, with a read-only key, and the forwarder writes to DFIR-IRIS only over its HTTP API. No GPL-licensed code is combined with Elastic-licensed code, and no Elastic-licensed code is copied into this repository.
