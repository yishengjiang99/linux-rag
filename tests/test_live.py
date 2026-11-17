import os
import unittest
from unittest import mock

from rag import live

DENIED = [
    "/etc/gbk-composer.env",
    "/etc/linux-rag/secrets",
    "/etc/shadow",
    "/etc/ssh/sshd_config",
    "/etc/nginx/.env",
    "/proc/1/environ",
    "/proc/1/cmdline",
    "/proc/kcore",
    "/proc/self/maps",
    "/home/foo/.ssh/authorized_keys",
    "/etc/sudoers",
]


class LiveTest(unittest.TestCase):
    def setUp(self):
        live.clear_cache()

    def test_denylisted_paths_never_opened(self):
        opened, ran = [], []

        def open_file(path, max_bytes, tail):
            opened.append(path)
            return "listen 80;\nworker_connections 1024;\n"

        def run_cmd(cmd):
            ran.append(cmd)
            if "secrets" in cmd or "gbk-composer" in cmd:
                return "SECRET_FROM_CMD"
            return "nginx started on this host\n"

        paths = [("nginx config", p, False, False) for p in ["/etc/nginx/nginx.conf"] + DENIED]
        commands = [
            ("secrets file", "/etc/linux-rag/secrets", "cat /etc/linux-rag/secrets", False),
            ("env", "/etc/gbk-composer.env", "cat /etc/gbk-composer.env", False),
            ("journal warnings", "journalctl -p warning", "journalctl -p warning -n 10", False),
        ]
        chunks, _ = live.collect(open_file=open_file, run_cmd=run_cmd, paths=paths,
                                 commands=commands, include_snapshot=False)
        self.assertEqual(opened, ["/etc/nginx/nginx.conf"])
        self.assertEqual(ran, ["journalctl -p warning -n 10"])
        text = "\n".join(c[3] for c in chunks)
        self.assertNotIn("SECRET_FROM_CMD", text)
        self.assertTrue(any("nginx.conf" in c[1] for c in chunks))
        self.assertIn("nginx started", text)

    def test_denied_path_skips_os_open(self):
        opened = []
        real = os.open

        def spy(path, *a, **k):
            opened.append(path)
            return real(path, *a, **k)

        with mock.patch("os.open", spy):
            for p in DENIED:
                self.assertIsNone(live.read_allowed(p), p)
        self.assertEqual(opened, [])

    def test_live_chunks_are_redacted(self):
        opened = []

        def open_file(path, max_bytes, tail):
            opened.append(path)
            return ("server_name 203.0.113.9;\n"
                    "DB_PASSWORD=hunter2secret\n"
                    "API_KEY=sk_live_abcdefghijklmnop123456\n"
                    "worker_connections 1024;\n")

        def run_cmd(cmd):
            return "accepted from 198.51.100.9 token=supersecretvalue nginx started\n"

        chunks, _ = live.collect(
            open_file=open_file, run_cmd=run_cmd,
            paths=[("nginx config", "/etc/nginx/nginx.conf", False, False)],
            commands=[("journal warnings", "journalctl -p warning", "journalctl -p warning", False)],
            include_snapshot=False,
        )
        text = "\n".join(c[3] for c in chunks)
        for secret in ("203.0.113.9", "hunter2secret", "sk_live_abcdefghijklmnop123456",
                       "198.51.100.9", "supersecretvalue"):
            self.assertNotIn(secret, text, text)
        self.assertIn("[IP]", text)
        self.assertIn("[REDACTED]", text)
        self.assertIn("worker_connections 1024", text)
        self.assertEqual(opened, ["/etc/nginx/nginx.conf"])

    def test_cache_and_rank(self):
        calls = {"n": 0}

        def collect_fn():
            calls["n"] += 1
            return [("nginx error /var/log/nginx/error.log", "/var/log/nginx/error.log", "L1-1",
                     "upstream zorb_live_backend prematurely closed 502")], 1_000.0

        clock = {"t": 1_000.0}
        hits = live.search("zorb_live_backend 502", collect_fn=collect_fn, clock=lambda: clock["t"])
        self.assertEqual(calls["n"], 1)
        self.assertEqual(hits[0]["corpus"], "live")
        self.assertEqual(hits[0]["path"], "/var/log/nginx/error.log")
        self.assertEqual(hits[0]["read_at"], 1_000.0)
        clock["t"] = 1_029.0
        live.search("zorb_live_backend 502", collect_fn=collect_fn, clock=lambda: clock["t"])
        self.assertEqual(calls["n"], 1)
        clock["t"] = 1_030.1
        live.search("zorb_live_backend 502", collect_fn=collect_fn, clock=lambda: clock["t"])
        self.assertEqual(calls["n"], 2)
        self.assertTrue(live.format_read_at(1_000.0).endswith(" PT"))


if __name__ == "__main__":
    unittest.main()
