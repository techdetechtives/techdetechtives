# TechDetechtives network inventory: protocol and vendor knowledge.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""What a connection is, as far as it can be told from the platform's records.

Two levels of knowledge, kept apart on purpose:

* DECODED: the platform's sensor understands the protocol and records each
  operation (the dataset tables below).
* BY PORT: only the port number is known. The label says what usually runs
  there; nothing inside the connection has been looked at.
"""

from __future__ import annotations

# Datasets the sensor writes for industrial protocols it decodes:
# dataset -> (label, field holding the operation name). The field is None where
# the platform keeps no usable operation name: for S7comm-plus (S7-1200/1500)
# it stores only whether a message was a request or a response.
OT_DATASETS = {
    "zeek.modbus": ("Modbus", "modbus.function"),
    "zeek.dnp3": ("DNP3", "dnp3.fc_request"),
    "zeek.s7comm": ("S7comm", "s7.function.name"),
    "zeek.s7comm_plus": ("S7comm-plus", None),
    "zeek.cip": ("EtherNet/IP", "cip.service"),
    "zeek.enip": ("EtherNet/IP", "enip.command"),
    "zeek.bacnet": ("BACnet", "bacnet.pdu.service"),
    "zeek.profinet": ("PROFINET", "profinet.operation_type"),
    "zeek.opcua_binary": ("OPC UA", "opcua.identifier_string"),
}

# Operations that change a device rather than read from it. Matched without
# regard to case, as a whole name or (where marked *) as a part of one.
CONTROL_OPERATIONS = {
    "Modbus": ["*WRITE", "*PROGRAM", "DIAGNOSTICS", "FIRMWARE_REPLACEMENT", "MASK_WRITE_REGISTER"],
    "DNP3": ["WRITE", "SELECT", "OPERATE", "DIRECT_OPERATE", "DIRECT_OPERATE_NR", "COLD_RESTART", "WARM_RESTART",
             "INITIALIZE_DATA", "INITIALIZE_APPL", "START_APPL", "STOP_APPL", "SAVE_CONFIG", "ACTIVATE_CONFIG",
             "DELETE_FILE", "DISABLE_UNSOLICITED"],
    "S7comm": ["Write Variable", "PLC Stop", "PLC Control", "Request Download", "Download Block", "Download Ended"],
    "EtherNet/IP": ["*Set Attribute", "Set Member", "Insert Member", "Remove Member", "Apply Attributes", "Restore",
                    "Reset", "Start", "Stop", "Create", "Delete", "*Write"],
    "BACnet": ["write_property", "write_property_multiple", "reinitialize_device", "device_communication_control",
               "create_object", "delete_object", "atomic_write_file"],
    "PROFINET": ["*write"],
    "OPC UA": ["*Write", "*Call"],
}


def _plain(text: str) -> str:
    return " ".join((text or "").lower().replace("_", " ").replace("-", " ").split())


def is_control(label: str, operation: str) -> bool:
    name = _plain(operation)
    if not name:
        return False
    for pattern in CONTROL_OPERATIONS.get(label, []):
        wanted = _plain(pattern.lstrip("*"))
        if (pattern.startswith("*") and wanted in name) or name == wanted:
            return True
    return False


# Names the sensor gives a connection when it recognises the protocol.
SERVICES = {
    "modbus": ("Modbus", True), "dnp3": ("DNP3", True), "enip": ("EtherNet/IP", True), "cip": ("EtherNet/IP", True),
    "s7comm": ("S7comm", True), "s7comm-plus": ("S7comm-plus", True), "cotp": ("ISO-TSAP (S7, MMS)", True),
    "bacnet": ("BACnet", True), "profinet": ("PROFINET", True), "opcua-binary": ("OPC UA", True),
    "opcua_binary": ("OPC UA", True), "bsap": ("BSAP", True), "ethercat": ("EtherCAT", True),
    "dns": ("DNS", False), "http": ("HTTP", False), "ssl": ("TLS", False), "ssh": ("SSH", False), "smb": ("SMB", False),
    "rdp": ("Remote Desktop", False), "krb": ("Kerberos", False), "krb_tcp": ("Kerberos", False), "ldap": ("LDAP", False),
    "ldap_tcp": ("LDAP", False), "ldap_udp": ("LDAP", False), "ntp": ("NTP", False), "dhcp": ("DHCP", False),
    "snmp": ("SNMP", False), "ftp": ("FTP", False), "ftp-data": ("FTP", False), "smtp": ("SMTP", False),
    "mysql": ("MySQL", False), "dce_rpc": ("Windows RPC", False), "ntlm": ("NTLM", False), "gssapi": ("Windows sign-in", False),
    "syslog": ("Syslog", False), "rfb": ("VNC", False), "telnet": ("Telnet", False), "tftp": ("TFTP", False),
    "sip": ("SIP", False), "mqtt": ("MQTT", False), "quic": ("QUIC", False), "radius": ("RADIUS", False),
    "imap": ("IMAP", False), "pop3": ("POP3", False), "irc": ("IRC", False), "socks": ("SOCKS", False),
    "ipsec": ("IPsec", False), "openvpn": ("OpenVPN", False), "wireguard": ("WireGuard", False), "tds": ("SQL Server", False),
}

# (transport, port) -> (label, industrial?) for connections the sensor could not name.
# Industrial entries say whose equipment usually uses the port.
PORTS = {
    ("tcp", 102): ("ISO-TSAP (Siemens S7, IEC 61850 MMS)", True),
    ("tcp", 502): ("Modbus", True), ("udp", 502): ("Modbus", True),
    ("tcp", 789): ("Red Lion Crimson", True),
    ("tcp", 1089): ("Foundation Fieldbus HSE", True), ("tcp", 1090): ("Foundation Fieldbus HSE", True),
    ("tcp", 1091): ("Foundation Fieldbus HSE", True),
    ("tcp", 1217): ("CODESYS gateway", True), ("tcp", 2455): ("CODESYS runtime", True), ("tcp", 11740): ("CODESYS runtime", True),
    ("udp", 1502): ("Triconex TriStation (Schneider Electric safety systems)", True),
    ("tcp", 1911): ("Niagara Fox (Tridium)", True), ("tcp", 4911): ("Niagara Fox over TLS (Tridium)", True),
    ("tcp", 1962): ("Phoenix Contact PCWorx", True), ("tcp", 20547): ("ProConOS (Phoenix Contact and others)", True),
    ("tcp", 2222): ("EtherNet/IP I/O or legacy Allen-Bradley", True), ("udp", 2222): ("EtherNet/IP I/O (Rockwell Automation)", True),
    ("tcp", 2404): ("IEC 60870-5-104", True),
    ("udp", 2423): ("RNRP (ABB control network redundancy)", True),
    ("udp", 3671): ("KNXnet/IP", True),
    ("tcp", 4000): ("Emerson ROC Plus", True),
    ("tcp", 4840): ("OPC UA", True), ("tcp", 4843): ("OPC UA over TLS", True),
    ("udp", 5006): ("Mitsubishi MELSEC", True), ("tcp", 5007): ("Mitsubishi MELSEC", True),
    ("tcp", 5094): ("HART-IP", True), ("udp", 5094): ("HART-IP", True),
    ("tcp", 9600): ("Omron FINS", True), ("udp", 9600): ("Omron FINS", True),
    ("tcp", 18245): ("GE SRTP", True), ("tcp", 18246): ("GE SRTP", True),
    ("tcp", 20000): ("DNP3", True), ("udp", 20000): ("DNP3", True),
    ("udp", 34962): ("PROFINET", True), ("udp", 34963): ("PROFINET", True), ("udp", 34964): ("PROFINET", True),
    ("udp", 34980): ("EtherCAT", True),
    ("tcp", 44818): ("EtherNet/IP", True), ("udp", 44818): ("EtherNet/IP", True),
    ("udp", 47808): ("BACnet", True),
    ("tcp", 48898): ("Beckhoff ADS", True), ("udp", 48899): ("Beckhoff ADS", True),
    ("udp", 47837): ("Honeywell FTE status", True), ("udp", 51966): ("Honeywell FTE status", True),
    ("tcp", 55553): ("Honeywell Experion engineering", True), ("tcp", 55555): ("Honeywell Experion engineering", True),
    ("tcp", 1883): ("MQTT", False), ("tcp", 8883): ("MQTT over TLS", False),
    ("tcp", 21): ("FTP", False), ("tcp", 22): ("SSH", False), ("tcp", 23): ("Telnet", False), ("tcp", 25): ("SMTP", False),
    ("udp", 53): ("DNS", False), ("tcp", 53): ("DNS", False), ("udp", 67): ("DHCP", False), ("udp", 68): ("DHCP", False),
    ("udp", 69): ("TFTP", False), ("tcp", 80): ("HTTP", False), ("tcp", 88): ("Kerberos", False), ("udp", 88): ("Kerberos", False),
    ("udp", 123): ("NTP", False), ("tcp", 135): ("Windows RPC", False), ("udp", 137): ("NetBIOS", False),
    ("udp", 138): ("NetBIOS", False), ("tcp", 139): ("NetBIOS / SMB", False), ("udp", 161): ("SNMP", False),
    ("udp", 162): ("SNMP trap", False), ("tcp", 389): ("LDAP", False), ("tcp", 443): ("TLS", False), ("udp", 443): ("QUIC", False),
    ("tcp", 445): ("SMB", False), ("udp", 514): ("Syslog", False), ("tcp", 636): ("LDAP over TLS", False),
    ("tcp", 1433): ("SQL Server", False), ("tcp", 1521): ("Oracle database", False), ("tcp", 3306): ("MySQL", False),
    ("tcp", 3389): ("Remote Desktop", False), ("udp", 3389): ("Remote Desktop", False), ("tcp", 5432): ("PostgreSQL", False),
    ("tcp", 5900): ("VNC", False), ("tcp", 5985): ("Windows Remote Management", False), ("tcp", 5986): ("Windows Remote Management", False),
    ("tcp", 8080): ("HTTP (alternative port)", False), ("tcp", 8443): ("TLS (alternative port)", False),
    ("tcp", 9200): ("Elasticsearch", False), ("udp", 5353): ("mDNS", False), ("udp", 1900): ("SSDP", False),
}


def classify(service: str, transport: str, port: int | None) -> tuple[str, bool, str]:
    """(label, industrial?, how it is known) for one connection.

    'decoded' means the sensor recognised the protocol itself; 'port' means the
    label is only what usually runs on that port.
    """
    transport = (transport or "").lower()
    for name in [part.strip().lower() for part in (service or "").split(",") if part.strip()]:
        if name in SERVICES:
            label, industrial = SERVICES[name]
            return label, industrial, "decoded"
    if port is not None and (transport, port) in PORTS:
        label, industrial = PORTS[(transport, port)]
        return label, industrial, "port"
    if service:
        return service.split(",")[0].strip()[:40], False, "decoded"
    if port is None:
        return transport or "other", False, "port"
    return f"{transport}/{port}", False, "port"


# Words that mark a network-card maker as an industrial-equipment vendor.
OT_VENDOR_WORDS = [
    "siemens", "schneider", "telemecanique", "modicon", "rockwell", "allen-bradley", "allen bradley", "honeywell",
    " abb ", " abb,", "asea brown", "emerson", "fisher-rosemount", "yokogawa", "mitsubishi electric", "omron", "phoenix contact",
    "beckhoff", "wago", "moxa", "hirschmann", "belden", "ge intelligent", "ge fanuc", "ge automation", "bosch rexroth",
    "b&r industrial", "bernecker", "endress", "schweitzer", "advantech", "red lion", "tridium", "johnson controls",
    "pilz", "sick ag", "turck", "weidm", "festo", "lenze", "danfoss", "kuka", "fanuc", "keyence", "pepperl", "prosoft",
    "westermo", "ruggedcom", "triconex", "invensys", "foxboro", "bachmann", "codesys", "3s-smart", "delta electronics",
    "hms industrial", "anybus", "lantronix", "digi international", "opto 22", "automationdirect", "koyo", "unitronics",
    " eaton", "woodward", "krohne", "vega grieshaber", "samson", "metso", "valmet", " nari ", "sifang", "supcon", "hollysys",
]


def industrial_vendor(maker: str) -> bool:
    text = " " + (maker or "").lower() + " "
    return any(word in text for word in OT_VENDOR_WORDS)
