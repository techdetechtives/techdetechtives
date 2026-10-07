#!/usr/bin/env python3
# TechDetechtives OT IDS. Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
"""Put the packets of a capture file in the order of their times.

Why this exists: a capture exported from Arkime ("PCAP Export") is written one
session after another, in the order the sessions ended, each session's packets
as one block. A connection that stayed open for an hour is written after the
short ones that ended before it, with its first packets an hour "late". An
engine that reads such a file sees events in an order they did not happen in:
a rule that waits for one event and then another can see the second first, and
counts over a time window come out wrong. Upload the ordered file instead.

    td_pcap_order.py EXPORT.pcap incident7.pcap     write the packets in time order to a new file
    td_pcap_order.py --check EXPORT.pcap            only say whether the file is in order (exit status 0 yes, 3 no)

It reads the classic capture format (the one Arkime exports and tcpdump
writes), with microsecond or nanosecond times, in either byte order. It does
not read pcapng; Wireshark's "reordercap" does. It changes nothing in the
packets and never writes over a file that exists. One Python file with no
dependencies: it can be copied to any machine that has Python 3.
"""
import argparse
import mmap
import os
import struct
import sys
import tempfile
import time
from array import array

# first four bytes: (byte order, nanoseconds in one unit of the second time field)
FORMATS = {b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000), b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1)}
PCAPNG = b"\x0a\x0d\x0d\x0a"
HEADER, RECORD = 24, 16
LARGEST_PACKET = 64 * 1024 * 1024       # a record that claims more is a damaged file, not a packet


class Unreadable(ValueError):
    pass


def index(data):
    """(times in nanoseconds, where each record starts, each record's length with its header, bytes left over at the end)."""
    if len(data) < 4:
        raise Unreadable("the file is too short to be a capture file")
    magic = bytes(data[:4])
    if magic == PCAPNG:
        raise Unreadable("this is a pcapng file, which this tool does not read; Wireshark's reordercap does")
    if magic not in FORMATS:
        raise Unreadable("this is not a capture file in the classic pcap format")
    if len(data) < HEADER:
        raise Unreadable("the file ends inside its own header")
    order, unit = FORMATS[magic]
    record = struct.Struct(order + "IIII")
    times, starts, lengths = array("Q"), array("Q"), array("I")
    position, size = HEADER, len(data)
    while position + RECORD <= size:
        seconds, fraction, captured, _ = record.unpack_from(data, position)
        if captured > LARGEST_PACKET:
            raise Unreadable(f"the record at byte {position} claims a packet of {captured} bytes: the file is damaged, or not what it says")
        if position + RECORD + captured > size:
            break                                # the last packet was cut off: leave it out, and say so
        times.append(seconds * 1_000_000_000 + fraction * unit)
        starts.append(position)
        lengths.append(RECORD + captured)
        position += RECORD + captured
    return times, starts, lengths, size - position


def disorder(times):
    """(how many packets come after a later one, the largest step back in nanoseconds)."""
    late, worst, latest = 0, 0, 0
    for when in times:
        if when < latest:
            late += 1
            worst = max(worst, latest - when)
        else:
            latest = when
    return late, worst


def stamp(nanoseconds):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(nanoseconds // 1_000_000_000)) + " UTC"


def describe(path, times, left_over):
    if not times:
        return f"{path}: no whole packet in the file."
    late, worst = disorder(times)
    text = f"{path}: {len(times)} packets, {stamp(min(times))} to {stamp(max(times))}. "
    if late:
        text += (f"NOT in time order: {late} packets come after a later one; the largest step back is "
                 f"{worst / 1_000_000_000:.3f} seconds.")
    else:
        text += "In time order."
    if left_over:
        text += f" The last {left_over} bytes are a packet that was cut off; it is left out."
    return text


def write_ordered(data, times, starts, lengths, target):
    """The header and every whole record, by time; records with the same time keep the order they had."""
    folder = os.path.dirname(os.path.abspath(target))
    handle, temporary = tempfile.mkstemp(prefix=".td-pcap-order-", dir=folder)
    try:
        with os.fdopen(handle, "wb") as out:
            out.write(data[:HEADER])
            for number in sorted(range(len(times)), key=times.__getitem__):
                out.write(data[starts[number]:starts[number] + lengths[number]])
        os.chmod(temporary, 0o644)
        os.link(temporary, target)               # fails if the target appeared meanwhile: never write over a file
    finally:
        os.unlink(temporary)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Put the packets of a capture file (classic pcap) in the order of their times.")
    parser.add_argument("--check", action="store_true", help="only say whether the file is in time order")
    parser.add_argument("source", help="the capture file to read")
    parser.add_argument("target", nargs="?", help="the file to write (must not exist)")
    args = parser.parse_args(argv)
    if args.check == bool(args.target):
        parser.error("give a file to write, or --check")
    try:
        if not args.check and os.path.lexists(args.target):
            raise Unreadable(f"{args.target} exists already; this tool does not write over a file")
        with open(args.source, "rb") as handle:
            if os.fstat(handle.fileno()).st_size == 0:
                raise Unreadable("the file is empty")
            data = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                times, starts, lengths, left_over = index(data)
                print(describe(args.source, times, left_over))
                if args.check:
                    return 3 if disorder(times)[0] else 0
                write_ordered(data, times, starts, lengths, args.target)
            finally:
                data.close()
    except Unreadable as error:
        print(f"{args.source}: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"{error.filename or args.source}: {error.strerror or error}", file=sys.stderr)
        return 1
    print(f"Written in time order to {args.target}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
