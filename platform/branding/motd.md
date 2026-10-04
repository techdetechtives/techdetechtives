## Welcome to TechDetechtives

TechDetechtives is a detection and threat-hunting platform. This console handles collection, alerting, hunting and case work. The analytics workbench adds notebooks and Spark for deeper analysis of the same data.

## Start here

- [Alerts](/#/alerts): what the platform has detected so far.
- [Dashboards](/#/dashboards): an overview of all collected logs.
- [Hunt](/#/hunt): focused queries across network and host data.
- [Detections](/#/detections): tune rules and manage the TechDetechtives rule set (rules whose titles start with `TechDetechtives`).
- [Cases](/#/cases): escalate findings and collect evidence.
- [Grid](/#/grid): health of every node in the deployment.

## Analytics workbench

Notebook-based hunting with pandas, Spark SQL and process-tree graphs runs on the analytics host: @@TD_JUPYTER_URL@@

It reads from this platform with a read-only key and cannot change data here.

## Tickets and vulnerabilities

- Tickets: every alert at medium severity or above opens a ticket in the ticketing system: @@TD_TICKETS_URL@@
- Vulnerability dashboard and scan reports: @@TD_VULN_URL@@
- Scan findings are also stored here. Open them in [Dashboards](/#/dashboards?q=event.dataset%3Agreenbone.result%20%7C%20groupby%20vulnerability.severity%20%7C%20groupby%20host.ip%20%7C%20groupby%20rule.name%20%7C%20groupby%20vulnerability.id).

## Endpoint coverage

Deploy the Elastic Agent to endpoints from the [Downloads](/#/downloads) page.

## About this build

TechDetechtives is a modified deployment built on [Security Onion](https://securityonion.net), which is licensed under the Elastic License 2.0. The modifications are listed in MODIFICATIONS.md in the TechDetechtives repository. The analytics workbench is derived from HELK (GPL v3).

Security Onion is a registered trademark of Security Onion Solutions, LLC. TechDetechtives is not affiliated with or endorsed by Security Onion Solutions, LLC. Product documentation for the underlying platform is under [Help](/docs/).
