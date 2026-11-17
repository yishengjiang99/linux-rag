"""Collect prod configs and logs, redact, and write data/prod.db (admin-only corpus).

  python3 -m rag.collect_prod --ssh root@HOST data/prod.db   # from a dev box (read-only ssh)
  python3 -m rag.collect_prod --local data/prod.db           # on the server, as root

Only reads. File lists are fetched first and filtered with redact.path_allowed, so denied
files (*.env, keys, certs, secrets) are never opened. Everything is redacted before it is
written to disk.
"""
import argparse
import hashlib
import os
import re
import shlex
import subprocess
import sys

from rag import snapshot
from rag.chunk import nginx_chunks, text_chunks
from rag.index import write_db
from rag.redact import path_allowed, redact

LIST_CMDS = {
    "nginx config": "find /etc/nginx/nginx.conf /etc/nginx/sites-available /etc/nginx/sites-enabled "
                    "/etc/nginx/conf.d /etc/nginx/snippets -maxdepth 1 -type f 2>/dev/null; "
                    "find /etc/nginx/sites-enabled -maxdepth 1 -type l 2>/dev/null",
    "systemd unit": "find /etc/systemd/system -maxdepth 1 -type f \\( -name '*.service' -o -name '*.timer' \\) 2>/dev/null",
    "nginx error log": "find /var/log/nginx -maxdepth 1 -type f -name '*error.log' 2>/dev/null",
}

LOG_CMDS = [
    ("nginx access log", "/var/log/nginx/access.log", "tail -n 4000 /var/log/nginx/access.log", True),
    ("journal warnings", "journalctl -p warning", "journalctl -p warning -n 2500 --no-pager -o short-iso", False),
    ("kernel log", "journalctl -k", "journalctl -k -n 400 --no-pager -o short-iso", False),
    ("syslog", "/var/log/syslog", "tail -n 2000 /var/log/syslog", False),
    ("failed units", "systemctl --failed", "systemctl --failed --no-pager", False),
    ("running services", "systemctl list-units", "systemctl list-units --type=service --no-pager", False),
    ("listening ports", "ss -ltn", "ss -ltn", False),
    ("nginx version", "nginx -v", "nginx -v 2>&1; uname -sr", False),
]


class Runner:
    def __init__(self, ssh):
        self.ssh = ssh

    def __call__(self, cmd):
        argv = ["ssh", "-o", "BatchMode=yes", self.ssh, cmd] if self.ssh else ["bash", "-c", cmd]
        r = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=120)
        return r.stdout


def collect(run):
    chunks, seen = [], set()

    def add(kind, path, text, access=False, lines=60):
        digest = hashlib.sha256(text.encode()).digest()
        if digest in seen:  # sites-enabled symlink == sites-available file
            return
        seen.add(digest)
        clean = redact(text, access_log=access)
        if "nginx" in kind and not kind.endswith("log"):
            parts = nginx_chunks(clean, path, lines, overlap=20)
        else:
            parts = text_chunks(clean, path, lines, overlap=20 if "log" in kind else 0)
        for t, p, loc, body in parts:
            chunks.append((f"{kind} {path}", p, loc, body))

    for kind, cmd in LIST_CMDS.items():
        files = sorted(set(run(cmd).split()))
        for f in files:
            if re.search(r"\.(bak|new|old|orig|save|dpkg-\w+)|~$", f):
                continue  # stale copies add noise
            if not path_allowed(f):
                print(f"skip (denylist): {f}", file=sys.stderr)
                continue
            read = f"tail -n 1500 {shlex.quote(f)}" if kind.endswith("log") else f"head -c 200000 {shlex.quote(f)}"
            add(kind, f, run(read), lines=80 if kind != "nginx error log" else 60)
    for kind, path, cmd, access in LOG_CMDS:
        add(kind, path, run(cmd), access=access)
    # /proc, /sys, /etc snapshot (same set as the public sample; redacted inside snapshot.collect)
    chunks += snapshot.to_chunks(snapshot.collect(run, public=False), "prod")
    return chunks


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--ssh")
    g.add_argument("--local", action="store_true")
    ap.add_argument("out")
    a = ap.parse_args()
    os.umask(0o027)  # prod.db is never world-readable, even while being written
    chunks = collect(Runner(None if a.local else a.ssh))
    n = write_db(a.out, chunks)
    os.chmod(a.out, 0o640)
    print(f"prod: {n} chunks, {os.path.getsize(a.out) / 1e6:.1f} MB -> {a.out}")


if __name__ == "__main__":
    main()
