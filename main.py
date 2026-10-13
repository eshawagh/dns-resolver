"""Command-line interface for the DNS resolver."""
import argparse
import time

from dns_packet import TYPE_NAMES, TYPES
from lru_cache import LRUCache
from resolver import Resolver, ResolverError


def main():
    p = argparse.ArgumentParser(description="Iterative DNS resolver with LRU cache")
    p.add_argument("domains", nargs="+", help="domain name(s) to resolve")
    p.add_argument("--type", default="A", choices=TYPES.keys(), help="record type")
    p.add_argument("--trace", action="store_true", help="show every hop")
    p.add_argument("--capacity", type=int, default=100, help="LRU cache size")
    p.add_argument("--repeat", type=int, default=1,
                   help="resolve the list N times (shows cache hits)")
    args = p.parse_args()

    cache = LRUCache(args.capacity)
    resolver = Resolver(cache=cache, trace=args.trace)

    for round_no in range(args.repeat):
        for domain in args.domains:
            print(f"\n=== {domain} ({args.type})" +
                  (f" round {round_no + 1}" if args.repeat > 1 else "") + " ===")
            start = time.perf_counter()
            try:
                records = resolver.resolve(domain, args.type)
            except ResolverError as e:
                print(f"Error: {e}")
                continue
            ms = (time.perf_counter() - start) * 1000
            for r in records:
                print(f"{r.name:<30} {r.ttl:>6}  {TYPE_NAMES.get(r.type, r.type):<6} {r.data}")
            if not records:
                print("(no records of that type)")
            print(f"Time: {ms:.1f} ms")

    print("\nCache stats:", cache.stats())


if __name__ == "__main__":
    main()