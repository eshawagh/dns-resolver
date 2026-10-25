import os, struct, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from dns_packet import build_query, parse_name, parse_response, validate_domain


class TestPacket(unittest.TestCase):
    def test_build_query_layout(self):
        tid, pkt = build_query("www.example.com", 1)
        self.assertEqual(struct.unpack(">H", pkt[:2])[0], tid)
        self.assertEqual(pkt[12:], b"\x03www\x07example\x03com\x00\x00\x01\x00\x01")

    def test_parse_response_with_compression(self):
        header = struct.pack(">HHHHHH", 7, 0x8400, 1, 1, 0, 0)
        question = b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
        # answer name is a pointer (0xC00C) back to the question name
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + bytes([93, 184, 216, 34])
        r = parse_response(header + question + answer)
        self.assertEqual(r.rcode, 0)
        self.assertEqual(r.aa, 1)
        self.assertEqual(r.answers[0].name, "example.com")
        self.assertEqual(r.answers[0].ttl, 300)
        self.assertEqual(r.answers[0].data, "93.184.216.34")

    def test_parse_name_pointer_end_offset(self):
        data = b"\x00" * 12 + b"\x03com\x00" + b"\x03www\xc0\x0c"
        name, end = parse_name(data, 17)
        self.assertEqual(name, "www.com")
        self.assertEqual(end, len(data))

    def test_referral_ns_and_glue(self):
        header = struct.pack(">HHHHHH", 9, 0x8000, 1, 0, 1, 1)
        question = b"\x03foo\x03com\x00" + struct.pack(">HH", 1, 1)
        ns_name = b"\x02ns\xc0\x10"          # "ns" + pointer to "com" at offset 16
        auth = b"\xc0\x10" + struct.pack(">HHIH", 2, 1, 3600, len(ns_name)) + ns_name
        add = ns_name + struct.pack(">HHIH", 1, 1, 3600, 4) + bytes([1, 2, 3, 4])
        r = parse_response(header + question + auth + add)
        self.assertEqual(r.authority[0].data, "ns.com")
        self.assertEqual(r.additional[0].data, "1.2.3.4")

    def test_validate_domain_ok(self):
        validate_domain("www.example.com")
        validate_domain("example.com.")

    def test_validate_domain_bad(self):
        for bad in ["", "bad domain!", "a..b", "-" * 64 + ".com", "x" * 300,
                    "exa$mple.com", "\u00e9xample.com"]:
            with self.assertRaises(ValueError):
                validate_domain(bad)


if __name__ == "__main__":
    unittest.main()