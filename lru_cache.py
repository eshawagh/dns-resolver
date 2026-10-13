"""LRU cache with per-entry TTL (time to live)."""
import time
from collections import OrderedDict


class LRUCache:
    def __init__(self, capacity=100, clock=time.time):
        self.capacity = capacity
        self.clock = clock            # injectable so tests can fake time
        self.data = OrderedDict()     # key -> (value, expiry_time)
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    def get(self, key, track=True):
        item = self.data.get(key)
        if item is None or self.clock() >= item[1]:
            self.data.pop(key, None)  # remove expired entry if present
            if track:
                self.misses += 1
            return None
        self.data.move_to_end(key)    # mark as most recently used
        if track:
            self.hits += 1
        return item[0]

    def put(self, key, value, ttl):
        if ttl <= 0:
            return
        self.data[key] = (value, self.clock() + ttl)
        self.data.move_to_end(key)
        if len(self.data) > self.capacity:
            self.data.popitem(last=False)   # drop least recently used
            self.evictions += 1

    def __len__(self):
        return len(self.data)

    def stats(self):
        total = self.hits + self.misses
        rate = (self.hits / total * 100) if total else 0.0
        return (f"entries={len(self)}/{self.capacity} hits={self.hits} "
                f"misses={self.misses} evictions={self.evictions} "
                f"hit-rate={rate:.0f}%")