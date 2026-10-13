"""Build DNS queries and parse DNS responses by hand (RFC 1035)."""
import random
import socket
import struct
from collections import namedtuple

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}
TYPE_NAMES = {v: k for k, v in TYPES.items()}

Record = namedtuple("Record", "name type ttl data")
Response = namedtuple("Response", "id rcode aa tc answers authority additional")


def build_query(domain, qtype=1, recursion=False):
    """Return (transaction_id, packet_bytes)."""
    tid = random.randint(0, 0xFFFF)
    flags = 0x0100 if recursion else 0x0000
    header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)
    qname = b""
    for label in domain.rstrip(".").split("."):
        if label:
            qname += bytes([len(label)]) + label.encode("ascii")
    qname += b"\x00"
    return tid, header + qname + struct.pack(">HH", qtype, 1)


def parse_name(data, offset):
    """Read a (possibly compressed) name. Returns (name, offset_after_name)."""
    labels, end, jumped, hops = [], offset, False, 0
    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:                 # compression pointer
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            jumped = True
            offset = pointer
            hops += 1
            if hops > 20:
                raise ValueError("compression loop")
        elif length == 0:                         # end of name
            if not jumped:
                end = offset + 1
            break
        else:
            offset += 1
            labels.append(data[offset:offset + length].decode("ascii", "replace"))
            offset += length
    return ".".join(labels), end


def _parse_record(data, offset):
    name, offset = parse_name(data, offset)
    rtype, _cls, ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
    offset += 10
    rdata_start = offset
    if rtype == 1 and rdlen == 4:
        value = socket.inet_ntoa(data[offset:offset + 4])
    elif rtype == 28 and rdlen == 16:
        value = socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])
    elif rtype in (2, 5):                         # NS, CNAME
        value, _ = parse_name(data, offset)
    elif rtype == 15:                             # MX
        pref = struct.unpack(">H", data[offset:offset + 2])[0]
        host, _ = parse_name(data, offset + 2)
        value = f"{pref} {host}"
    elif rtype == 16:                             # TXT
        value = data[offset + 1:offset + 1 + data[offset]].decode("utf-8", "replace")
    else:
        value = data[offset:offset + rdlen].hex()
    return Record(name, rtype, ttl, value), rdata_start + rdlen


def parse_response(data):
    tid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    offset = 12
    for _ in range(qd):                           # skip the question section
        _, offset = parse_name(data, offset)
        offset += 4
    sections = []
    for count in (an, ns, ar):
        records = []
        for _ in range(count):
            rec, offset = _parse_record(data, offset)
            records.append(rec)
        sections.append(records)
    return Response(tid, flags & 0xF, (flags >> 10) & 1, (flags >> 9) & 1,
                    sections[0], sections[1], sections[2])