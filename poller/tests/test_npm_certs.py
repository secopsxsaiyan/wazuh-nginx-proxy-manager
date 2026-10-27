"""Unit tests for npm_certs.py (no network: the certificate fetch is stubbed).

Run: python3 -m unittest discover -s poller/tests
"""
import json
import os
import socket
import ssl
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import npm_certs as nc  # noqa: E402

NOW = 1_800_000_000.0  # fixed clock
DAY = 86400


def cert(days_left, sans=("app.example.com",), org="Example CA"):
    na = time_str(NOW + days_left * DAY + 3600)
    return {"notAfter": na, "subjectAltName": tuple(("DNS", s) for s in sans),
            "issuer": ((("organizationName", org),),)}


def time_str(ts):
    import time
    return time.strftime("%b %d %H:%M:%S %Y GMT", time.gmtime(ts))


def stub(mapping):
    def fetch(host, th, tp, timeout):
        v = mapping[host]
        if isinstance(v, Exception):
            raise v
        return v
    return fetch


class TestClassify(unittest.TestCase):
    def test_levels(self):
        self.assertEqual(nc.classify(NOW + 56 * DAY, NOW, True, 14, 3), ("ok", 56))
        self.assertEqual(nc.classify(NOW + 13 * DAY + 5, NOW, True, 14, 3), ("expiring", 13))
        self.assertEqual(nc.classify(NOW + 14 * DAY + 5, NOW, True, 14, 3), ("ok", 14))
        self.assertEqual(nc.classify(NOW + 2 * DAY + 5, NOW, True, 14, 3), ("critical", 2))
        self.assertEqual(nc.classify(NOW + 3 * DAY + 5, NOW, True, 14, 3), ("expiring", 3))
        self.assertEqual(nc.classify(NOW - 1, NOW, True, 14, 3), ("expired", -1))

    def test_name_mismatch_only_when_otherwise_ok(self):
        self.assertEqual(nc.classify(NOW + 56 * DAY, NOW, False, 14, 3)[0], "name_mismatch")
        self.assertEqual(nc.classify(NOW + 2 * DAY, NOW, False, 14, 3)[0], "critical")


class TestSan(unittest.TestCase):
    def test_exact_and_wildcard(self):
        self.assertTrue(nc.san_matches("app.example.com", ["app.example.com"]))
        self.assertTrue(nc.san_matches("app.example.com", ["*.example.com"]))
        self.assertFalse(nc.san_matches("a.b.example.com", ["*.example.com"]))
        self.assertFalse(nc.san_matches("example.com", ["*.example.com"]))
        self.assertFalse(nc.san_matches("app.example.com", ["www.example.com"]))


class TestHostSources(unittest.TestCase):
    def test_hosts_file_lines(self):
        got = nc.hosts_from_lines(["# comment", "", "App.Example.com  ", "www.example.com # x",
                                   "203.0.113.10", "*.example.com", "not a host", "localhost"])
        self.assertEqual(got, {"app.example.com", "www.example.com"})

    def test_log_lines(self):
        lines = [
            '[01/Jan/2026:12:00:00 +0000] - 502 502 - GET https app.example.com "/path" [Client 203.0.113.10] [Length 154] [Gzip -] [Sent-to 203.0.113.11] "Mozilla/5.0" "-"',
            '[01/Jan/2026:11:58:27 +0000] - 401 401 - GET https www.example.com \\"/path\\" [Client 203.0.113.10] [Length 13] [Gzip -] [Sent-to 203.0.113.11] "x" "-"',
            '[01/Jan/2026:12:00:04 +0000] 301 - GET http old.example.com "/" [Client 203.0.113.10] [Length 162] [Gzip -] "Mozilla/5.0" "-"',
            '[01/Jan/2026:12:00:05 +0000] - - 400 -  http  "" [Client 203.0.113.60] [Length 150] [Gzip -] [Sent-to -] "-" "-"',
            '[01/Jan/2026:12:00:06 +0000] - 404 404 - GET https 203.0.113.10 "/" [Client 203.0.113.61] [Length 0] [Gzip -] [Sent-to -] "-" "-"',
            '2026/01/01 12:00:00 [error] 31#31: *812 connect() failed, server: app.example.com',
        ]
        self.assertEqual(nc.hosts_from_log_lines(lines), {"app.example.com", "www.example.com", "old.example.com"})

    def test_conf_text(self):
        text = "server {\n  listen 443 ssl;\n  server_name app.example.com www.example.com *.example.com;\n}\n" \
               "server {\n  server_name  api.example.com ;\n}\n"
        self.assertEqual(nc.hosts_from_conf_text(text), {"app.example.com", "www.example.com", "api.example.com"})

    def test_collect_and_tail(self):
        with tempfile.TemporaryDirectory() as d:
            hf = os.path.join(d, "hosts")
            with open(hf, "w") as f:
                f.write("a.example.com\n")
            os.makedirs(os.path.join(d, "logs"))
            lp = os.path.join(d, "logs", "proxy-host-1_access.log")
            with open(lp, "w") as f:
                f.write("x" * 50 + "\n")  # cut-off first line must be ignored safely
                f.write('[01/Jan/2026:12:00:00 +0000] - 200 200 - GET https b.example.com "/" [Client 203.0.113.10] [Length 1] [Gzip -] [Sent-to 198.51.100.20] "u" "-"\n')
            cf = os.path.join(d, "1.conf")
            with open(cf, "w") as f:
                f.write("server_name c.example.com;\n")
            got = nc.collect_hosts([hf], [os.path.join(d, "*.conf")],
                                   [os.path.join(d, "logs", "proxy-host-*_access.log")], log_bytes=400)
            self.assertEqual(got, {"a.example.com", "b.example.com", "c.example.com"})


class TestProbeAndMain(unittest.TestCase):
    def test_probe_ok_and_fields(self):
        ev = nc.probe_host("app.example.com", "198.51.100.5", 443, 5, NOW, 14, 3,
                           fetch=stub({"app.example.com": cert(56)}))
        self.assertEqual(ev["integration"], "npm-certs")
        c = ev["npm_cert"]
        self.assertEqual((c["host"], c["target"], c["status"], c["days_left"], c["issuer"]),
                         ("app.example.com", "198.51.100.5:443", "ok", 56, "Example CA"))
        self.assertRegex(c["not_after"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(c["san"], "app.example.com")

    def test_probe_error(self):
        ev = nc.probe_host("down.example.com", "198.51.100.5", 443, 5, NOW, 14, 3,
                           fetch=stub({"down.example.com": socket.timeout("timed out")}))
        self.assertEqual(ev["npm_cert"]["status"], "probe_error")
        self.assertIn("timed out", ev["npm_cert"]["error"])
        self.assertNotIn("days_left", ev["npm_cert"])

    def test_main_writes_json_lines(self):
        fetch = stub({"app.example.com": cert(56), "soon.example.com": cert(10),
                      "crit.example.com": cert(1), "old.example.com": cert(-5),
                      "other.example.com": cert(56, sans=("www.example.com",)),
                      "bad.example.com": ssl.SSLError("handshake failure")})
        with tempfile.TemporaryDirectory() as d:
            hf = os.path.join(d, "hosts")
            with open(hf, "w") as f:
                f.write("\n".join(["app.example.com", "soon.example.com", "crit.example.com",
                                   "old.example.com", "other.example.com", "bad.example.com"]) + "\n")
            out = os.path.join(d, "out.json")
            rc = nc.main(["--hosts-file", hf, "--target", "198.51.100.5:8443", "--out", out],
                         fetch=fetch, now=NOW)
            self.assertEqual(rc, 0)
            with open(out) as f:
                rows = [json.loads(l) for l in f]
        st = {r["npm_cert"]["host"]: r["npm_cert"]["status"] for r in rows}
        self.assertEqual(st, {"app.example.com": "ok", "soon.example.com": "expiring",
                              "crit.example.com": "critical", "old.example.com": "expired",
                              "other.example.com": "name_mismatch", "bad.example.com": "probe_error"})
        self.assertTrue(all(r["npm_cert"]["target"] == "198.51.100.5:8443" for r in rows))

    def test_main_requires_a_source(self):
        self.assertEqual(nc.main(["--out", os.devnull], fetch=stub({})), 2)

    def test_max_hosts(self):
        with tempfile.TemporaryDirectory() as d:
            hf = os.path.join(d, "hosts")
            with open(hf, "w") as f:
                f.write("a.example.com\nb.example.com\nc.example.com\n")
            out = os.path.join(d, "o")
            nc.main(["--hosts-file", hf, "--out", out, "--max-hosts", "2"],
                    fetch=stub({h: cert(30) for h in ("a.example.com", "b.example.com")}), now=NOW)
            with open(out) as f:
                self.assertEqual(len(f.readlines()), 2)

    def test_parse_target(self):
        self.assertEqual(nc.parse_target("198.51.100.5:8443"), ("198.51.100.5", 8443))
        self.assertEqual(nc.parse_target("npm.example.com"), ("npm.example.com", 443))
        self.assertEqual(nc.parse_target("[2001:db8::1]:443"), ("2001:db8::1", 443))


class TestRealDecode(unittest.TestCase):
    """The private CPython decoder used by fetch_cert must exist on this interpreter."""
    def test_decoder_available(self):
        self.assertTrue(hasattr(ssl._ssl, "_test_decode_cert"))


if __name__ == "__main__":
    unittest.main()
