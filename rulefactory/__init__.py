# TechDetechtives rule factory.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Turns a newly exploited critical vulnerability into tested detection rules.

    watch     new remote-code-execution CVEs in CISA's Known Exploited
              Vulnerabilities list -> build each one
    build     one CVE: look for existing community rules, draft TechDetechtives
              rules (Suricata, Sigma, YARA) where none fit, test them, and
              open a pull request for an analyst to approve
    exposure  (on your own network) which of those CVEs your scan findings
              show, raised as DFIR-IRIS alerts

See rulefactory/README.md.
"""
VERSION = "0.1.0"
