# TechDetechtives: write HTTP conversations into a packet capture.
# Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Builds a classic pcap file of complete TCP conversations (handshake,
request, response, close) so Suricata can be tested on exact requests without
a network. Standard library only.

    write_http_pcap(path, [request, ...]) -> [client port of each request]

A request is {"method", "uri", "headers" (optional), "body" (optional),
"host" (optional)}. Each one gets its own connection from 203.0.113.50 (outside)
to 10.0.0.5:80 (inside), on client port 40000 + its position in the list.
"""
from __future__ import annotations

import struct

CLIENT = bytes([203, 0, 113, 50])
SERVER = bytes([10, 0, 0, 5])
CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _packet(src: bytes, dst: bytes, sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", _checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    macs = (SERVER_MAC + CLIENT_MAC) if src == CLIENT else (CLIENT_MAC + SERVER_MAC)
    return macs + b"\x08\x00" + ip + tcp


def http_bytes(request: dict) -> bytes:
    body = request.get("body", "")
    body = body.encode("utf-8") if isinstance(body, str) else bytes(body)
    headers = {"Host": request.get("host", "10.0.0.5"), "User-Agent": "Mozilla/5.0 (rule test)", "Accept": "*/*"}
    headers.update(request.get("headers") or {})
    if body or request.get("method", "GET").upper() in ("POST", "PUT", "PATCH"):
        headers["Content-Length"] = str(len(body))
    head = f"{request.get('method', 'GET').upper()} {request['uri']} HTTP/1.1\r\n"
    head += "".join(f"{name}: {value}\r\n" for name, value in headers.items()) + "\r\n"
    return head.encode("latin-1") + body


def conversation(request: dict, client_port: int) -> list[bytes]:
    SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01
    c, s = 1000, 5000
    data = http_bytes(request)
    packets = [
        _packet(CLIENT, SERVER, client_port, 80, c, 0, SYN),
        _packet(SERVER, CLIENT, 80, client_port, s, c + 1, SYN | ACK),
        _packet(CLIENT, SERVER, client_port, 80, c + 1, s + 1, ACK),
        _packet(CLIENT, SERVER, client_port, 80, c + 1, s + 1, PSH | ACK, data),
        _packet(SERVER, CLIENT, 80, client_port, s + 1, c + 1 + len(data), ACK),
        _packet(SERVER, CLIENT, 80, client_port, s + 1, c + 1 + len(data), PSH | ACK, RESPONSE),
        _packet(CLIENT, SERVER, client_port, 80, c + 1 + len(data), s + 1 + len(RESPONSE), ACK),
        _packet(CLIENT, SERVER, client_port, 80, c + 1 + len(data), s + 1 + len(RESPONSE), FIN | ACK),
        _packet(SERVER, CLIENT, 80, client_port, s + 1 + len(RESPONSE), c + 2 + len(data), FIN | ACK),
        _packet(CLIENT, SERVER, client_port, 80, c + 2 + len(data), s + 2 + len(RESPONSE), ACK),
    ]
    return packets


def write_http_pcap(path, requests: list[dict]) -> list[int]:
    ports = []
    with open(path, "wb") as out:
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))   # Ethernet
        moment = 1_760_000_000
        for index, request in enumerate(requests):
            port = 40000 + index
            ports.append(port)
            for number, frame in enumerate(conversation(request, port)):
                out.write(struct.pack("<IIII", moment + index, number * 1000, len(frame), len(frame)) + frame)
    return ports
