"""The committed public sample (samples/sys_snapshot.json) must not describe the machine it came from."""
import json
import os
import re
import socket
import unittest

SAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples", "sys_snapshot.json")

MARKERS = [
    r"cursor", r"sand-?box", r"sand-host", r"anyrun", r"agent-store", r"agent_store", r"fuse\.agent", r"/workspace",
    r"/home/box", r"\bbox\b", r"guest_control", r"setenv", r"/cursor/stores", r"\bstore-[0-9a-f]{6,}", r"orbitd",
    r"\bnova\b", r"0::/(?!\[cgroup path removed\])\S", r"sand-box-runtime", r"virtiofs", r"\b9p\b.*/",
]
HOST_ONLY_FILES = {"/proc/mounts", "/proc/self/mountinfo", "/proc/cmdline", "/proc/self/maps", "/etc/ssh/sshd_config"}


class PublicSampleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(SAMPLE) as f:
            cls.sample = json.load(f)
        cls.lines = [(d["path"], line) for d in cls.sample["files"] for line in d["text"].splitlines()]

    def test_no_host_only_files(self):
        self.assertFalse(HOST_ONLY_FILES & {d["path"] for d in self.sample["files"]})

    def test_no_box_markers(self):
        hits = [(m, p, l[:80]) for m in MARKERS for p, l in self.lines if re.search(m, l, re.I)]
        self.assertEqual(hits, [])

    def test_no_hostname(self):
        host = socket.gethostname().split(".")[0]
        if len(host) > 3:
            self.assertFalse([p for p, l in self.lines if host.lower() in l.lower()])

    def test_only_distro_accounts(self):
        pw = next(d["text"] for d in self.sample["files"] if d["path"] == "/etc/passwd")
        for line in pw.splitlines():
            uid = int(line.split(":")[2])
            self.assertTrue(uid < 100 or uid == 65534, line)


if __name__ == "__main__":
    unittest.main()
