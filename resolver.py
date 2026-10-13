"""Iterative DNS resolver: root -> TLD -> authoritative."""
import socket
import struct
import time

from dns_packet import TYPES, TYPE_NAMES, build_query, parse_response
from lru_cache import LRUCache

ROOT_SERVERS = ["198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13"]
A, NS, CNAME = 1, 2, 5


class ResolverError(Exception):
    pass


class Resolver:
    def __init__(self, cache=None, trace=False, timeout=3, max_hops=15):
        self.cache = cache if cache is not None else LRUCache(100)
        self.trace = trace
        self.timeout = timeout
        self.max_hops = max_hops

    def log(self, depth, msg):
        if self.trace:
            print("  " * depth + msg)

    # ---------- network ----------
    def _recv_exact(self, sock, n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise OSError("connection closed")
            buf += chunk
        return buf

    def _udp(self, server, tid, packet):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(self.timeout)
            s.sendto(packet, (server, 53))
            while True:
                data, _ = s.recvfrom(4096)
                if len(data) >= 12 and struct.unpack(">H", data[:2])[0] == tid:
                    return data

    def _tcp(self, server, packet):
        with socket.create_connection((server, 53), timeout=self.timeout) as s:
            s.sendall(struct.pack(">H", len(packet)) + packet)
            n = struct.unpack(">H", self._recv_exact(s, 2))[0]
            return self._recv_exact(s, n)

    def _ask(self, servers, name, qtype, depth):
        """Try each server until one answers. Returns (server, Response)."""
        for server in servers[:3]:
            tid, packet = build_query(name, qtype)
            try:
                self.log(depth, f"-> asking {server} for {name} {TYPE_NAMES.get(qtype, qtype)}")
                resp = parse_response(self._udp(server, tid, packet))
                if resp.tc:                       # truncated: retry over TCP
                    self.log(depth, "   (truncated, retrying over TCP)")
                    resp = parse_response(self._tcp(server, packet))
                return server, resp
            except (socket.timeout, OSError, ValueError, IndexError, struct.error) as e:
                self.log(depth, f"   ! {server} failed: {e}")
        raise ResolverError(f"no server answered for {name}")

    # ---------- resolution ----------
    def _start_servers(self, name):
        """Use cached NS info for the closest known zone, else the roots."""
        labels = name.split(".")
        for i in range(len(labels)):
            zone = ".".join(labels[i:])
            cached = self.cache.get((zone, "NS"), track=False)
            if cached:
                return cached, zone
        return list(ROOT_SERVERS), "."

    def resolve(self, name, qtype="A", depth=0):
        name = name.lower().rstrip(".")
        qnum = TYPES[qtype]
        if depth > 8:
            raise ResolverError("too many nested lookups (CNAME / NS loop?)")

        cached = self.cache.get((name, qtype))
        if cached is not None:
            self.log(depth, f"[cache HIT] {name} {qtype}")
            return cached
        self.log(depth, f"[cache MISS] {name} {qtype}")

        servers, zone = self._start_servers(name)
        if zone != ".":
            self.log(depth, f"(starting from cached name servers of '{zone}')")

        for _ in range(self.max_hops):
            server, resp = self._ask(servers, name, qnum, depth)

            if resp.rcode == 3:
                raise ResolverError(f"NXDOMAIN: {name} does not exist")
            if resp.rcode != 0:
                raise ResolverError(f"server returned error code {resp.rcode}")

            if resp.answers:
                wanted = [r for r in resp.answers if r.type == qnum]
                if wanted:
                    self.log(depth, f"<- ANSWER from {server}")
                    self.cache.put((name, qtype), resp.answers, min(r.ttl for r in wanted))
                    return resp.answers
                cnames = [r for r in resp.answers if r.type == CNAME]
                if cnames:
                    self.log(depth, f"<- CNAME {name} -> {cnames[0].data}")
                    rest = self.resolve(cnames[0].data, qtype, depth + 1)
                    result = list(resp.answers) + list(rest)
                    self.cache.put((name, qtype), result, min(r.ttl for r in result))
                    return result

            ns_records = [r for r in resp.authority if r.type == NS]
            if not ns_records:
                self.log(depth, f"<- {server}: no data of this type")
                return []

            zone_name = ns_records[0].name
            glue = {r.name.lower(): r.data for r in resp.additional if r.type == A}
            next_servers = [glue[n.data.lower()] for n in ns_records
                            if n.data.lower() in glue]
            self.log(depth, f"<- REFERRAL to '{zone_name}' name servers: "
                            f"{', '.join(n.data for n in ns_records[:3])}")

            if not next_servers:                  # no glue: resolve NS hostname
                self.log(depth, "   (no glue records, resolving a name server first)")
                for n in ns_records:
                    try:
                        recs = self.resolve(n.data, "A", depth + 1)
                    except ResolverError:
                        continue
                    ips = [r.data for r in recs if r.type == A]
                    if ips:
                        next_servers = ips
                        break
            if not next_servers:
                raise ResolverError("could not find an address for any name server")

            self.cache.put((zone_name.lower(), "NS"), next_servers,
                           min(r.ttl for r in ns_records))
            servers = next_servers

        raise ResolverError("exceeded maximum number of hops")