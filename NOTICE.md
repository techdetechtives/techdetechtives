# Notices

TechDetechtives combines original work with four upstream projects. Each part keeps its own licence. This file is not legal advice.

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

## 5. Original TechDetechtives work

Everything outside `analytics/` (the platform overlay, rules, ticket forwarder, vulnerability connector and dashboard, scripts and documentation) is original work, Copyright (c) 2026 TechDetechtives, under the MIT licence in `LICENSE`.

## How the parts are kept separate

The platform, the analytics workbench, the ticket forwarder, DFIR-IRIS, Greenbone and the vulnerability connector are separate programs. The workbench and the forwarder read from the platform only over its Elasticsearch HTTP API, with a read-only key, and the forwarder writes to DFIR-IRIS only over its HTTP API. No GPL-licensed code is combined with Elastic-licensed code, and no Elastic-licensed code is copied into this repository.
