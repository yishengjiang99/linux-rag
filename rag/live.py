"""Fresh, redacted reads of the prod allowlist at admin ask time.

The HTTP server is unprivileged; on prod a root helper serves redacted chunks
over a unix socket (RAG_LIVE_SOCKET). If the helper is down, the hourly prod
index is the fallback. Public asks never call this module.
"""
import argparse
import hashlib
import json
import os
import re
import socket
import stat
import struct
import subprocess
import threading
import time
from datetime import datetime
from zoneinfo import ZoneInfo

from rag.chunk import text_chunks
from rag.collect_prod import LIST_CMDS, LOG_CMDS
from rag.redact import path_allowed, redact
from rag.search import search_db, upload_db
from rag import snapshot

CACHE_TTL = 30
MAX_FILE_BYTES = 200_000
MAX_TOTAL_BYTES = 2_000_000
LIVE_K = 6
PT = ZoneInfo("America/Los_Angeles")

_lock = threading.Lock()
_cache = None  # (expires, read_at, chunks)


def format_read_at(ts):
    return datetime.fromtimestamp(ts, PT).strftime("%Y-%m-%d %H:%M:%S PT")


def read_allowed(path, max_bytes=MAX_FILE_BYTES, tail=False, open_file=None):
    """Return file text, or None if denied or unreadable. path_allowed is checked before any open."""
    if not path_allowed(path):
        return None
    if open_file is not None:
        return open_file(path, max_bytes, tail)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOCTTY)
    except OSError:
        return None
    try:
        try:
            real = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            real = path
        if real != path and not path_allowed(real):
            return None
        if tail:
            try:
                size = os.fstat(fd).st_size
                if size > max_bytes:
                    os.lseek(fd, -max_bytes, os.SEEK_END)
            except OSError:
                pass
        buf = bytearray()
        while len(buf) < max_bytes:
            chunk = os.read(fd, min(65536, max_bytes - len(buf)))
            if not chunk:
                break
            buf += chunk
        return buf.decode("utf-8", "replace")
    finally:
        os.close(fd)


def _run(cmd, timeout=15):
    try:
        r = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        return r.stdout or r.stderr or ""
    except (subprocess.TimeoutExpired, OSError):
        return ""


def _stale_copy(path):
    return bool(re.search(r"\.(bak|new|old|orig|save|dpkg-\w+)|~$", path))


def collect(open_file=None, run_cmd=None, paths=None, commands=None, include_snapshot=True, clock=time.time):
    """Read the prod allowlist, redact, chunk. Denylisted paths are never opened.

    open_file(path, max_bytes, tail) is only called after path_allowed.
    paths: optional [(kind, path, access_log, tail), ...] (tests / closed world).
    commands: optional [(kind, path, cmd, access_log), ...].
    """
    run = run_cmd or _run
    chunks, seen = [], set()
    used = 0
    read_at = clock()

    def opener(path, max_bytes, tail):
        return read_allowed(path, max_bytes, tail, open_file)

    def add(kind, path, text, access=False, lines=60):
        if not text or not text.strip():
            return
        digest = hashlib.sha256(text.encode()).digest()
        if digest in seen:
            return
        seen.add(digest)
        clean = redact(text, access_log=access)
        for t, p, loc, body in text_chunks(clean, path, lines):
            chunks.append((f"{kind} {path}", p, loc, body))

    def take(text):
        nonlocal used
        room = MAX_TOTAL_BYTES - used
        if room <= 0:
            return None
        if len(text.encode()) > room:
            text = text.encode()[:room].decode("utf-8", "replace")
        used += len(text.encode())
        return text

    given_paths = paths is not None
    if paths is None:
        paths = []
        for kind, cmd in LIST_CMDS.items():
            for f in sorted(set(run(cmd).split())):
                if _stale_copy(f):
                    continue
                paths.append((kind, f, False, kind.endswith("log")))

    for kind, path, access, tail in paths:
        if not path_allowed(path):
            continue
        room = MAX_TOTAL_BYTES - used
        if room <= 0:
            break
        text = opener(path, min(MAX_FILE_BYTES, room), tail)
        if text is None:
            continue
        text = take(text)
        if text is None:
            break
        add(kind, path, text, access=access, lines=60 if tail else 80)

    if commands is None:
        if given_paths:
            commands = []
        else:
            listed = {p for _, p, _, _ in paths}
            commands = [c for c in LOG_CMDS if c[1] not in listed]

    for kind, path, cmd, access in commands:
        if MAX_TOTAL_BYTES - used <= 0:
            break
        if path.startswith("/"):
            if not path_allowed(path):
                continue
            room = MAX_TOTAL_BYTES - used
            text = opener(path, min(MAX_FILE_BYTES, room), True)
            if text is not None:
                text = take(text)
                if text is None:
                    break
                add(kind, path, text, access=access)
                continue
        text = take((run(cmd) or "")[:MAX_FILE_BYTES])
        if text is None:
            break
        add(kind, path, text, access=access)

    if include_snapshot:
        def snap_read(p):
            room = MAX_TOTAL_BYTES - used
            if room <= 0 or not path_allowed(p):
                return ""
            text = opener(p, min(snapshot.MAX_BYTES, room), False) or ""
            take(text)
            return text

        try:
            docs = snapshot.collect(run, public=False, read_file=snap_read)
        except Exception:
            docs = []
        if docs:
            chunks += snapshot.to_chunks(docs, "prod")

    return chunks, read_at


def rank(chunks, query, k=LIVE_K):
    if not chunks:
        return []
    db = upload_db()
    try:
        db.executemany("INSERT INTO chunks(title, path, loc, body) VALUES (?,?,?,?)", chunks)
        return search_db(db, query, k)
    finally:
        db.close()


def _from_cache(clock):
    with _lock:
        if _cache and _cache[0] > clock():
            return _cache[1], _cache[2]
    return None


def _store_cache(read_at, chunks, clock):
    global _cache
    with _lock:
        _cache = (clock() + CACHE_TTL, read_at, chunks)


def clear_cache():
    global _cache
    with _lock:
        _cache = None


def pull_socket(path, timeout=10):
    data = b""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(path)
        s.sendall(b"PULL\n")
        hdr = b""
        while len(hdr) < 4:
            chunk = s.recv(4 - len(hdr))
            if not chunk:
                raise ConnectionError("live socket closed")
            hdr += chunk
        n = struct.unpack("!I", hdr)[0]
        if n > MAX_TOTAL_BYTES * 3:
            raise ValueError("live payload too large")
        while len(data) < n:
            chunk = s.recv(min(65536, n - len(data)))
            if not chunk:
                raise ConnectionError("live socket closed")
            data += chunk
    payload = json.loads(data.decode())
    return [tuple(c) for c in payload["chunks"]], payload["t"]


def collect_local(clock=time.time):
    return collect(clock=clock)


def default_collect(clock=time.time):
    sock = os.environ.get("RAG_LIVE_SOCKET", "")
    if sock:
        return pull_socket(sock)
    return collect_local(clock=clock)


def search(query, k=LIVE_K, collect_fn=None, clock=time.time, open_file=None, paths=None,
           commands=None, run_cmd=None):
    """BM25-rank live chunks against the question. Caches the raw read for CACHE_TTL seconds."""
    cached = _from_cache(clock)
    if cached is None:
        if collect_fn is not None:
            chunks, read_at = collect_fn()
        elif open_file is not None or paths is not None or commands is not None:
            chunks, read_at = collect(open_file=open_file, run_cmd=run_cmd, paths=paths,
                                      commands=commands, include_snapshot=False, clock=clock)
        else:
            chunks, read_at = default_collect(clock=clock)
        _store_cache(read_at, chunks, clock)
    else:
        read_at, chunks = cached
    hits = rank(chunks, query, k)
    for h in hits:
        h["corpus"] = "live"
        h["read_at"] = read_at
    return hits


def _handle(conn):
    try:
        conn.settimeout(30)
        buf = b""
        while b"\n" not in buf:
            chunk = conn.recv(64)
            if not chunk:
                return
            buf += chunk
            if len(buf) > 64:
                return
        if not buf.startswith(b"PULL"):
            return
        cached = _from_cache(time.time)
        if cached is None:
            chunks, read_at = collect_local()
            _store_cache(read_at, chunks, time.time)
            print(f"live collect: {len(chunks)} chunks", flush=True)
        else:
            read_at, chunks = cached
        raw = json.dumps({"t": read_at, "chunks": chunks}, separators=(",", ":")).encode()
        conn.sendall(struct.pack("!I", len(raw)) + raw)
    except Exception as e:
        print(f"live helper error: {type(e).__name__}", flush=True)
    finally:
        conn.close()


def serve(path):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, mode=0o750, exist_ok=True)
    if os.path.exists(path):
        try:
            if stat.S_ISSOCK(os.stat(path).st_mode):
                os.unlink(path)
        except OSError:
            pass
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(path)
    try:
        os.chmod(path, 0o660)
    except OSError:
        pass
    sock.listen(4)
    print(f"linux-rag live helper on {path}", flush=True)
    try:
        while True:
            conn, _ = sock.accept()
            threading.Thread(target=_handle, args=(conn,), daemon=True).start()
    finally:
        sock.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--serve", metavar="SOCKET")
    a = ap.parse_args()
    if not a.serve:
        ap.error("need --serve SOCKET")
    serve(a.serve)


if __name__ == "__main__":
    main()
