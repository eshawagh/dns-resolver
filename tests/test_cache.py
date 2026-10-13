import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from lru_cache import LRUCache


class FakeClock:
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t


class TestLRUCache(unittest.TestCase):
    def test_put_get(self):
        c = LRUCache(2, FakeClock()); c.put("a", 1, 10)
        self.assertEqual(c.get("a"), 1)

    def test_miss(self):
        self.assertIsNone(LRUCache(2).get("zzz"))

    def test_evicts_least_recently_used(self):
        c = LRUCache(2, FakeClock())
        c.put("a", 1, 10); c.put("b", 2, 10)
        c.get("a")                      # a is now most recent
        c.put("c", 3, 10)               # evicts b
        self.assertIsNone(c.get("b"))
        self.assertEqual(c.get("a"), 1)
        self.assertEqual(c.get("c"), 3)

    def test_ttl_expiry(self):
        clk = FakeClock(); c = LRUCache(2, clk)
        c.put("a", 1, 5)
        clk.t += 6
        self.assertIsNone(c.get("a"))

    def test_stats(self):
        c = LRUCache(2, FakeClock()); c.put("a", 1, 10)
        c.get("a"); c.get("x")
        self.assertEqual((c.hits, c.misses), (1, 1))

    def test_zero_ttl_not_cached(self):
        c = LRUCache(2); c.put("a", 1, 0)
        self.assertIsNone(c.get("a"))


if __name__ == "__main__":
    unittest.main()