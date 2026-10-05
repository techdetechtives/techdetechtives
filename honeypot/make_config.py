#!/usr/bin/env python3
# TechDetechtives: write the honeypot's settings and the list of ports it listens on.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Called by honeypot/setup-honeypot.sh. Standard library only.

    make_config.py --name NODE --services ftp,http,... [--bind ADDRESS]
                   [--port NAME=HOSTPORT ...] --out-dir DIR

Writes two files into DIR:

  opencanary.conf   settings for OpenCanary, with only the chosen decoys on
  ports.yaml        a Compose file fragment that publishes one host port per decoy

and prints the port map (decoy's own port = port on this host) for the shipper.
Inside its container every decoy listens on its usual port; --port changes only
the port on this host, for example --port ssh=2222 when the real SSH uses 22.
"""

import argparse
import ipaddress
import json
import os
import re
import sys

# decoy name: (port inside the container, what an analyst would call it)
SERVICES = {
    "ftp": (21, "FTP"),
    "ssh": (22, "SSH"),
    "telnet": (23, "Telnet"),
    "http": (80, "web sign-in page"),
    "https": (443, "web sign-in page over TLS"),
    "mssql": (1433, "Microsoft SQL Server"),
    "mysql": (3306, "MySQL"),
    "rdp": (3389, "Remote Desktop"),
    "vnc": (5900, "VNC"),
    "redis": (6379, "Redis"),
    "httpproxy": (8080, "web proxy"),
    "git": (9418, "Git"),
    "mongodb": (27017, "MongoDB"),
}
DEFAULT_SERVICES = "ftp,http,telnet,mysql,mssql,rdp,vnc,redis"
LOG_FILE = "/var/log/opencanary/opencanary.log"
NAME_PATTERN = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,62}[A-Za-z0-9])?$")


class ConfigError(Exception):
    pass


def parse_services(text):
    names = [item.strip().lower() for item in text.split(",") if item.strip()]
    if not names:
        raise ConfigError("choose at least one decoy service")
    unknown = sorted(set(names) - set(SERVICES))
    if unknown:
        raise ConfigError("unknown decoy service: %s (available: %s)" % (", ".join(unknown), ", ".join(sorted(SERVICES))))
    return sorted(set(names), key=lambda name: SERVICES[name][0])


def parse_ports(pairs, services):
    """['ssh=2222'] -> {'ssh': 2222}, defaults filled in for the rest."""
    host_ports = {name: SERVICES[name][0] for name in services}
    for pair in pairs or []:
        name, _, value = pair.partition("=")
        name = name.strip().lower()
        if name not in services:
            raise ConfigError("--port %s: '%s' is not one of the chosen decoys" % (pair, name))
        if not value.isdigit() or not 1 <= int(value) <= 65535:
            raise ConfigError("--port %s: the port must be a number between 1 and 65535" % pair)
        host_ports[name] = int(value)
    taken = {}
    for name, port in host_ports.items():
        if port in taken:
            raise ConfigError("%s and %s cannot both use port %d on this host" % (taken[port], name, port))
        taken[port] = name
    return host_ports


def opencanary_settings(node, services):
    """Full OpenCanary settings: every decoy listed, only the chosen ones on."""
    on = set(services)
    settings = {
        "device.node_id": node,
        "ip.ignorelist": [],
        "logtype.ignorelist": [],
        "logger": {
            "class": "PyLogger",
            "kwargs": {
                "formatters": {"plain": {"format": "%(message)s"}},
                "handlers": {
                    "console": {"class": "logging.StreamHandler", "stream": "ext://sys.stdout"},
                    "file": {"class": "logging.FileHandler", "filename": LOG_FILE},
                },
            },
        },
        "ftp.banner": "FTP server ready",
        "ftp.log_auth_attempt_initiated": False,
        "http.banner": "Apache/2.4.58 (Ubuntu)",
        "http.skin": "nasLogin",
        "http.log_unimplemented_method_requests": True,
        "http.log_redirect_request": True,      # a request for "/" is a contact too
        "https.skin": "nasLogin",
        "httpproxy.skin": "squid",
        "ssh.version": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
        "telnet.banner": "",
        "telnet.log_tcp_connection": False,
        "mysql.banner": "5.7.44-0ubuntu0.18.04.1",   # OpenCanary only accepts versions 3 to 6
        "mysql.log_connection_made": False,
        "mssql.version": "2014",     # OpenCanary accepts 2008R2, 2012 and 2014 only
        "mongodb.version": "4.4.6",
        "git.max_connections": 32,
        "git.timeout": 10,
        # Decoys this component does not offer. They stay off; they are listed
        # because OpenCanary wants every port setting to be different.
        "portscan.enabled": False,
        "smb.enabled": False,
        "snmp.enabled": False, "snmp.port": 161,
        "ntp.enabled": False, "ntp.port": 123,
        "tftp.enabled": False, "tftp.port": 69,
        "sip.enabled": False, "sip.port": 5060,
        "llmnr.enabled": False, "llmnr.port": 5355,
        "tcpbanner.enabled": False, "tcpbanner.maxnum": 10,
        "tcpbanner_1.enabled": False, "tcpbanner_1.port": 8001,
    }
    for name, (port, _) in SERVICES.items():
        settings["%s.enabled" % name] = name in on
        settings["%s.port" % name] = port
    return settings


def ports_fragment(bind, host_ports):
    lines = [
        "# Written by honeypot/setup-honeypot.sh. Do not edit: re-run the setup instead.",
        "services:",
        "  td-honeypot:",
        "    ports:",
    ]
    for name, host_port in sorted(host_ports.items(), key=lambda item: item[1]):
        lines.append('      - "%s:%d:%d"   # %s' % (bind, host_port, SERVICES[name][0], name))
    return "\n".join(lines) + "\n"


def port_map(host_ports):
    """'22=2222,80=80': the decoy's own port and the port on this host, for the shipper."""
    return ",".join("%d=%d" % (SERVICES[name][0], port)
                    for name, port in sorted(host_ports.items(), key=lambda item: SERVICES[item[0]][0]))


def build(node, services_text, bind, port_pairs):
    if not NAME_PATTERN.match(node):
        raise ConfigError("--name must be a host name (letters, digits, dots, dashes)")
    try:
        bind = str(ipaddress.IPv4Address(bind))
    except ValueError:
        raise ConfigError("--bind must be an IPv4 address") from None
    services = parse_services(services_text)
    host_ports = parse_ports(port_pairs, services)
    return {
        "services": services,
        "host_ports": host_ports,
        "settings": opencanary_settings(node, services),
        "ports_yaml": ports_fragment(bind, host_ports),
        "port_map": port_map(host_ports),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--name", required=True)
    parser.add_argument("--services", default=DEFAULT_SERVICES)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", action="append", default=[])
    parser.add_argument("--out-dir")
    parser.add_argument("--list", action="store_true", help="list the available decoys and stop")
    args = parser.parse_args(argv)
    if args.list:
        for name, (port, label) in sorted(SERVICES.items(), key=lambda item: item[1][0]):
            print("%-10s %-6d %s" % (name, port, label))
        return 0
    try:
        result = build(args.name, args.services, args.bind, args.port)
    except ConfigError as error:
        print("ERROR: %s" % error, file=sys.stderr)
        return 2
    if args.out_dir:
        os.makedirs(args.out_dir, exist_ok=True)
        with open(os.path.join(args.out_dir, "opencanary.conf"), "w", encoding="utf-8") as handle:
            json.dump(result["settings"], handle, indent=2, sort_keys=True)
            handle.write("\n")
        with open(os.path.join(args.out_dir, "ports.yaml"), "w", encoding="utf-8") as handle:
            handle.write(result["ports_yaml"])
    # One line each, read by the setup script.
    print("SERVICES=%s" % ",".join(result["services"]))
    print("HOST_PORTS=%s" % " ".join(str(port) for port in sorted(result["host_ports"].values())))
    print("PORT_MAP=%s" % result["port_map"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
