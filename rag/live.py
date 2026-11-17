"""Fresh, redacted reads of the prod allowlist at admin ask time.

The HTTP server is unprivileged; on prod a root helper serves redacted chunks
over a unix socket (RAG_LIVE_SOCKET). If the helper is down, the hourly prod
index is the fallback. Public asks never call this module.

Helper config comes from the environment (systemd EnvironmentFile
/etc/linux-rag/live.env, documented in sample.env). These are paths and caps,
not feature flags: every source stays on. Defaults match prod.
"""
import argparse
import hashlib
import json
import os
import queue
import re
import shlex
import socket
import stat
import struct
import subprocess
import threading
import time
from collections import Counter
from datetime import datetime
from zoneinfo import ZoneInfo

from rag.chunk import nginx_chunks, text_chunks
from rag.collect_prod import LIST_CMDS, LOG_CMDS
from rag.redact import path_allowed, redact
from rag.search import search_db, upload_db
from rag import snapshot

CACHE_TTL = 30
MAX_FILE_BYTES = 200_000
MAX_TOTAL_BYTES = 2_000_000
LIVE_K = 12
SERVE_WORKERS = 4
SERVE_QUEUE = 8
PT = ZoneInfo("America/Los_Angeles")

FORBIDDEN_ENV_FILES = ("/etc/gbk-composer.env", "/etc/linux-rag/secrets")
DEFAULT_MYSQL_ENV_FILE = "/home/finalcut/apps/pages/finalcut/.env"
DEFAULT_MYSQL_SOCKET = "/var/run/mysqld/mysqld.sock"
DEFAULT_JOURNAL_UNITS = "linux-rag,linux-rag-live,linux-rag-collect,nginx,mysql,mysqld,finalcut"

STATUS_KEYS = {
    "Uptime", "Threads_connected", "Threads_running", "Threads_created",
    "Connections", "Max_used_connections", "Slow_queries", "Aborted_clients",
    "Aborted_connects", "Questions", "Queries", "Com_select", "Com_insert",
    "Com_update", "Com_delete", "Bytes_received", "Bytes_sent",
    "Innodb_buffer_pool_read_requests", "Innodb_buffer_pool_reads",
    "Innodb_rows_read", "Innodb_row_lock_waits",
}

SQL_TABLE_SIZES = (
    "SELECT table_schema, table_name, engine, table_rows, "
    "ROUND(data_length/1024/1024,1) AS data_mb, "
    "ROUND(index_length/1024/1024,1) AS index_mb "
    "FROM information_schema.tables "
    "WHERE table_schema NOT IN ('mysql','information_schema','performance_schema','sys') "
    "ORDER BY data_length+index_length DESC LIMIT 30"
)
ALLOWED_SQL = frozenset({
    "SHOW GLOBAL STATUS",
    "SHOW PROCESSLIST",
    "SHOW ENGINE INNODB STATUS",
    "SHOW REPLICA STATUS",
    "SHOW SLAVE STATUS",
    SQL_TABLE_SIZES,
})

_lock = threading.Lock()
_collect_lock = threading.Lock()
_cache = None  # (expires, read_at, chunks)


def format_read_at(ts):
    return datetime.fromtimestamp(ts, PT).strftime("%Y-%m-%d %H:%M:%S PT")


def settings(env=None):
    e = os.environ if env is None else env

    def g(name, default):
        v = e.get(name)
        return default if v is None or v == "" else v

    def gi(name, default):
        try:
            return int(g(name, str(default)))
        except ValueError:
            return default

    def csv(name, default):
        return [x.strip() for x in g(name, default).split(",") if x.strip()]

    return {
        "cache_ttl": gi("RAG_LIVE_CACHE_TTL", CACHE_TTL),
        "max_file_bytes": gi("RAG_LIVE_MAX_FILE_BYTES", MAX_FILE_BYTES),
        "max_total_bytes": gi("RAG_LIVE_MAX_TOTAL_BYTES", MAX_TOTAL_BYTES),
        "tail_lines": gi("RAG_LIVE_TAIL_LINES", 4000),
        "live_k": gi("RAG_LIVE_K", LIVE_K),
        "nginx_access": g("RAG_NGINX_ACCESS_LOG", "/var/log/nginx/access.log"),
        "nginx_error": g("RAG_NGINX_ERROR_LOG", "/var/log/nginx/error.log"),
        "log_paths": csv("RAG_LOG_PATHS", ""),
        "auth_log": g("RAG_AUTH_LOG", "/var/log/auth.log"),
        "journal_units": csv("RAG_JOURNAL_UNITS", DEFAULT_JOURNAL_UNITS),
        "mysql_env_file": g("RAG_MYSQL_ENV_FILE", DEFAULT_MYSQL_ENV_FILE),
        "mysql_socket": g("RAG_MYSQL_SOCKET", DEFAULT_MYSQL_SOCKET),
        "mysql_keys": {
            "host": g("RAG_MYSQL_KEY_HOST", "MYSQL_HOST"),
            "user": g("RAG_MYSQL_KEY_USER", "MYSQL_USER"),
            "password": g("RAG_MYSQL_KEY_PASSWORD", "MYSQL_PASSWORD"),
            "database": g("RAG_MYSQL_KEY_DATABASE", "MYSQL_DATABASE"),
        },
    }


def forbidden_env_file(path):
    """True for off-limits secret files. Checked before any open."""
    def bad(p):
        p = os.path.normpath(p or "")
        return p in FORBIDDEN_ENV_FILES or p.endswith("/gbk-composer.env") or p.endswith("/linux-rag/secrets")
    if bad(path):
        return True
    try:
        return bad(os.path.realpath(path))
    except OSError:
        return False


def read_allowed(path, max_bytes=MAX_FILE_BYTES, tail=False, open_file=None):
    """Return file text, or None if denied or unreadable. path_allowed is checked before any open."""
    if forbidden_env_file(path) or not path_allowed(path):
        return None
    if open_file is not None:
        return open_file(path, max_bytes, tail)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOCTTY | os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        try:
            real = os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            real = path
        if forbidden_env_file(real) or (real != path and not path_allowed(real)):
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
            try:
                chunk = os.read(fd, min(65536, max_bytes - len(buf)))
            except BlockingIOError:
                break
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


def last_lines(text, n):
    lines = text.splitlines()
    return text if len(lines) <= n else "\n".join(lines[-n:])


def file_chunks(kind, path, text, lines):
    if "nginx" in kind and "log" not in kind:
        return nginx_chunks(text, path, lines, overlap=20)
    overlap = 20 if ("log" in kind or "nginx" in kind) else 0
    return text_chunks(text, path, lines, overlap=overlap)


def _normalize_sql(sql):
    return " ".join(sql.split()).strip().rstrip(";").strip()


def allow_sql(sql):
    """Raise ValueError unless sql is an allowlisted SELECT/SHOW statement."""
    s = _normalize_sql(sql)
    if not re.match(r"(?i)^(SHOW|SELECT)\b", s):
        raise ValueError("sql not allowed")
    allowed = {_normalize_sql(x) for x in ALLOWED_SQL}
    if s not in allowed and s.upper() not in {x.upper() for x in allowed}:
        raise ValueError("sql not allowed")
    return s


def redact_query_values(text):
    """Replace string literals in SQL/query text so values never leave the helper."""
    text = re.sub(r"'(?:\\'|[^'])*'", "'?'", text)
    text = re.sub(r'"(?:\\"|[^"])*"', "'?'", text)
    return text


def scrub_secrets(text, creds):
    if not text:
        return text
    for v in creds.values() if isinstance(creds, dict) else []:
        if v and len(str(v)) >= 2:
            text = text.replace(str(v), "[REDACTED]")
    return redact(text)


def nginx_summary(access_text, error_text=""):
    """Status counts, top 5xx paths, top upstream errors. No client IPs."""
    req = re.compile(r'"([A-Z]+) (\S+)[^"]*"\s+(\d{3})\b')
    statuses, paths_5xx = Counter(), Counter()
    for line in access_text.splitlines():
        m = req.search(line)
        if not m:
            continue
        method, path, status = m.group(1), m.group(2).split("?", 1)[0], m.group(3)
        statuses[status] += 1
        if status.startswith("5"):
            paths_5xx[f"{method} {path}"] += 1
    upstream = Counter()
    up_re = re.compile(r"(upstream[^,]{0,120}|connect\(\) failed[^,]{0,80})", re.I)
    for line in error_text.splitlines():
        m = up_re.search(line)
        if m:
            upstream[re.sub(r"\s+", " ", m.group(1)).strip()[:160]] += 1
    lines = ["nginx log summary (addresses omitted)"]
    if statuses:
        lines.append("status counts: " + ", ".join(f"{s}={n}" for s, n in sorted(statuses.items())))
    if paths_5xx:
        lines.append("top 5xx paths:")
        for p, n in paths_5xx.most_common(8):
            lines.append(f"  {n} {p}")
    if upstream:
        lines.append("top upstream errors:")
        for p, n in upstream.most_common(8):
            lines.append(f"  {n} {p}")
    if len(lines) == 1:
        lines.append("no parseable access/error lines")
    return redact("\n".join(lines))


def auth_summary(text):
    accepted = len(re.findall(r"\bAccepted (?:password|publickey|keyboard-interactive|none)\b", text))
    failed = len(re.findall(r"\bFailed (?:password|publickey|none)\b", text))
    invalid = len(re.findall(r"\bInvalid user\b", text))
    opened = len(re.findall(r"\bsession opened\b", text))
    closed = len(re.findall(r"\bsession closed\b", text))
    sudo = len(re.findall(r"\bsudo:", text))
    return (
        "auth log summary (counts only; usernames and addresses omitted)\n"
        f"accepted logins: {accepted}\n"
        f"failed logins: {failed}\n"
        f"invalid user attempts: {invalid}\n"
        f"sessions opened: {opened}\n"
        f"sessions closed: {closed}\n"
        f"sudo lines: {sudo}\n"
    )


def load_mysql_creds(path, keys, open_file=None):
    """Read only the configured host/user/password/database key names. Never log values."""
    if forbidden_env_file(path) or not path:
        raise ValueError("mysql env file is off limits")
    wanted = {keys[k] for k in ("host", "user", "password", "database") if keys.get(k)}
    raw = None
    if open_file is not None:
        raw = open_file(path)
    else:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOCTTY | os.O_NONBLOCK
        try:
            fd = os.open(path, flags)
        except OSError:
            raise ValueError("mysql env unavailable") from None
        try:
            try:
                real = os.readlink(f"/proc/self/fd/{fd}")
            except OSError:
                real = path
            if forbidden_env_file(real):
                raise ValueError("mysql env file is off limits")
            raw = os.read(fd, 1_000_000).decode("utf-8", "replace")
        except BlockingIOError:
            raw = ""
        finally:
            os.close(fd)
    found = {}
    for line in (raw or "").splitlines():
        s = line.strip()
        if s.startswith("export "):
            s = s[7:].strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, _, v = s.partition("=")
        k, v = k.strip(), v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        if k in wanted:
            found[k] = v
    return {role: found.get(keys[role], "") for role in ("host", "user", "password", "database")}


def mysql_cli(sql, creds, mysql_bin=None, socket_path=DEFAULT_MYSQL_SOCKET):
    """Run an allowlisted statement over the local unix socket (no TCP, password not on argv)."""
    sql = allow_sql(sql)
    bin_ = mysql_bin or _mysql_bin()
    if not bin_:
        raise ValueError("mysql unavailable")
    env = {k: v for k, v in os.environ.items() if k != "MYSQL_PWD"}
    if creds.get("password"):
        env["MYSQL_PWD"] = creds["password"]
    sock = socket_path or DEFAULT_MYSQL_SOCKET
    argv = [bin_, "--batch", "--raw", "--connect-timeout=5",
            "--protocol=SOCKET", "-S", sock]
    if creds.get("user"):
        argv += ["-u", creds["user"]]
    if creds.get("database"):
        argv += ["-D", creds["database"]]
    argv += ["-e", sql]
    try:
        r = subprocess.run(argv, env=env, capture_output=True, text=True, errors="replace", timeout=15)
        return scrub_secrets(r.stdout or "", creds)
    except (subprocess.TimeoutExpired, OSError):
        raise ValueError("mysql unavailable") from None
    finally:
        env.pop("MYSQL_PWD", None)


def _mysql_bin():
    for name in ("mysql", "mariadb"):
        try:
            r = subprocess.run(["bash", "-c", f"command -v {name}"], capture_output=True, text=True, timeout=3)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip()
        except (subprocess.TimeoutExpired, OSError):
            continue
    return None


def filter_global_status(text):
    rows = {}
    for line in text.splitlines():
        parts = re.split(r"\s+", line.strip())
        if len(parts) >= 2 and parts[0] in STATUS_KEYS:
            rows[parts[0]] = parts[1]
    if "Questions" in rows and "Uptime" in rows:
        try:
            up = float(rows["Uptime"])
            if up > 0:
                rows["Approx_QPS"] = f"{float(rows['Questions']) / up:.2f}"
        except ValueError:
            pass
    if not rows:
        return ""
    return "MySQL global status (selected)\n" + "\n".join(f"{k} {rows[k]}" for k in sorted(rows))


def format_processlist(text):
    lines = [redact_query_values(l) for l in text.splitlines()]
    return "MySQL processlist (query values redacted)\n" + redact("\n".join(lines))


def innodb_summary(text, max_lines=80):
    text = redact_query_values(text)
    keep, take = [], False
    heads = re.compile(r"^[- ]*(BACKGROUND THREAD|SEMAPHORES|TRANSACTIONS|FILE I/O|LOG|"
                       r"BUFFER POOL AND MEMORY|ROW OPERATIONS)\b", re.I)
    for line in text.splitlines():
        if heads.match(line.strip()) or line.startswith("---"):
            take = True
        if take:
            keep.append(line)
    body = "\n".join((keep or text.splitlines())[:max_lines])
    return "MySQL InnoDB status summary\n" + redact(body)


def collect_mysql(cfg, run_sql=None, open_env=None, creds=None):
    """Read-only MySQL status. Credentials never appear in the returned text or in errors."""
    chunks = []
    try:
        if creds is None:
            creds = load_mysql_creds(cfg["mysql_env_file"], cfg["mysql_keys"], open_file=open_env)

        def q(sql):
            try:
                if run_sql is not None:
                    return run_sql(sql) or ""
                return mysql_cli(sql, creds, socket_path=cfg.get("mysql_socket")) or ""
            except ValueError:
                return ""

        status = filter_global_status(q("SHOW GLOBAL STATUS"))
        if status:
            chunks.append(("mysql status", "mysql:status", status))
        proc = q("SHOW PROCESSLIST")
        if proc.strip():
            chunks.append(("mysql processlist", "mysql:processlist", format_processlist(proc)))
        innodb = q("SHOW ENGINE INNODB STATUS")
        if innodb.strip():
            chunks.append(("mysql innodb", "mysql:innodb", innodb_summary(innodb)))
        tables = q(SQL_TABLE_SIZES)
        if tables.strip():
            chunks.append(("mysql table sizes", "mysql:tables", "MySQL table sizes (MB)\n" + redact(tables)))
        repl = q("SHOW REPLICA STATUS") or q("SHOW SLAVE STATUS")
        if repl.strip():
            chunks.append(("mysql replication", "mysql:replication", "MySQL replication status\n" + repl))
        chunks = [(k, pth, scrub_secrets(txt, creds)) for k, pth, txt in chunks]
    except ValueError:
        print("live mysql: unavailable", flush=True)
    except Exception:
        print("live mysql: unavailable", flush=True)
    return chunks


def ssl_certificate_paths(nginx_text):
    return sorted({m.group(1).rstrip(";") for m in re.finditer(r"^\s*ssl_certificate\s+(\S+);", nginx_text, re.M)})


def cert_expiry_text(paths, run):
    lines = ["nginx certificate expiry (dates only)"]
    for p in paths:
        if forbidden_env_file(p):
            continue
        out = run(f"openssl x509 -in {shlex.quote(p)} -noout -startdate -enddate 2>/dev/null") or ""
        dates = [l for l in out.splitlines() if l.startswith("notBefore=") or l.startswith("notAfter=")]
        if dates:
            lines.append(p)
            lines.extend(dates)
    return "\n".join(lines) if len(lines) > 1 else ""


def collect_health(cfg, run, opener):
    parts = []
    up = run("uptime; cat /proc/loadavg 2>/dev/null")
    mem = opener("/proc/meminfo", min(cfg["max_file_bytes"], 8000), False) or ""
    if mem:
        keep = []
        for line in mem.splitlines():
            if re.match(r"^(MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree|Dirty|Shmem):", line):
                keep.append(line)
        mem = "\n".join(keep)
    disk = run("df -h; echo; df -i")
    procs = run("ps -eo pid,user,pcpu,pmem,comm --sort=-pcpu | head -n 16; echo; "
                "ps -eo pid,user,pcpu,pmem,comm --sort=-pmem | head -n 16")
    failed = run("systemctl --failed --no-pager")
    oom = run('journalctl -k --since "7 days ago" --no-pager -o short-iso '
              '-g "Out of memory|Killed process|oom-kill|oom_reaper"')
    ports = run("ss -ltn")
    nginx_txt = ""
    for p in ("/etc/nginx/nginx.conf",):
        t = opener(p, cfg["max_file_bytes"], False)
        if t:
            nginx_txt += t + "\n"
    nginx_txt += run("nginx -T 2>/dev/null")[: cfg["max_file_bytes"]]
    certs = cert_expiry_text(ssl_certificate_paths(nginx_txt), run)

    def block(title, text):
        text = redact((text or "").strip())
        if text:
            parts.append(f"{title}\n{text}")

    block("uptime and load", up)
    block("memory", mem)
    block("disk and inodes", disk)
    block("top processes (command names only)", procs)
    block("failed units", failed)
    block("recent OOM kills", last_lines(oom, 40) if oom else "")
    block("listening ports", ports)
    if certs:
        parts.append(certs)
    return "\n\n".join(parts)


def collect_journals(cfg, run):
    out = []
    warn = run('journalctl -p warning --since "1 hour ago" --no-pager -o short-iso')
    if warn.strip():
        out.append(("journal warnings (last hour)", "journal:warning", warn))
    units = cfg["journal_units"]
    if units:
        args = " ".join(f"-u {shlex.quote(u)}" for u in units)
        text = run(f"journalctl {args} --since \"1 hour ago\" --no-pager -o short-iso -n 400")
        if text.strip():
            out.append(("journal units (last hour)", "journal:units", text))
    return out


def collect(open_file=None, run_cmd=None, paths=None, commands=None, include_snapshot=True,
            include_extras=None, clock=time.time, cfg=None, run_sql=None, open_env=None, mysql_creds=None):
    """Read the prod allowlist, redact, chunk. Denylisted paths are never opened.

    open_file(path, max_bytes, tail) is only called after path_allowed.
    paths: optional [(kind, path, access_log, tail), ...] (tests / closed world).
    commands: optional [(kind, path, cmd, access_log), ...].
    """
    cfg = cfg or settings()
    max_file, max_total, tail_n = cfg["max_file_bytes"], cfg["max_total_bytes"], cfg["tail_lines"]
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
        for t, p, loc, body in file_chunks(kind, path, clean, lines):
            chunks.append((f"{kind} {path}", p, loc, body))

    def take(text):
        nonlocal used
        room = max_total - used
        if room <= 0:
            return None
        if len(text.encode()) > room:
            text = text.encode()[:room].decode("utf-8", "replace")
        used += len(text.encode())
        return text

    given_paths = paths is not None
    if include_extras is None:
        include_extras = not given_paths

    if paths is None:
        paths = []
        for kind, cmd in LIST_CMDS.items():
            for f in sorted(set(run(cmd).split())):
                if _stale_copy(f):
                    continue
                paths.append((kind, f, False, kind.endswith("log")))
        for kind, path, access, tail in (
            ("nginx access log", cfg["nginx_access"], True, True),
            ("nginx error log", cfg["nginx_error"], False, True),
        ):
            if path and path not in {p for _, p, _, _ in paths}:
                paths.append((kind, path, access, tail))

    access_text, error_text = "", ""
    for kind, path, access, tail in paths:
        if not path_allowed(path) or forbidden_env_file(path):
            continue
        room = max_total - used
        if room <= 0:
            break
        text = opener(path, min(max_file, room), tail)
        if text is None:
            continue
        if tail:
            text = last_lines(text, tail_n)
        text = take(text)
        if text is None:
            break
        if path == cfg["nginx_access"] or kind.startswith("nginx access"):
            access_text = text
        if path == cfg["nginx_error"] or kind.startswith("nginx error"):
            error_text = text
        add(kind, path, text, access=access, lines=60 if tail else 80)

    if commands is None:
        if given_paths:
            commands = []
        else:
            listed = {p for _, p, _, _ in paths}
            commands = [c for c in LOG_CMDS if c[1] not in listed]

    for kind, path, cmd, access in commands:
        if max_total - used <= 0:
            break
        if path.startswith("/"):
            if not path_allowed(path) or forbidden_env_file(path):
                continue
            room = max_total - used
            text = opener(path, min(max_file, room), True)
            if text is not None:
                text = last_lines(text, tail_n)
                text = take(text)
                if text is None:
                    break
                add(kind, path, text, access=access)
                continue
        text = take((run(cmd) or "")[:max_file])
        if text is None:
            break
        add(kind, path, text, access=access)

    if include_snapshot:
        def snap_read(p):
            room = max_total - used
            if room <= 0 or not path_allowed(p) or forbidden_env_file(p):
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

    if include_extras:
        summary = nginx_summary(access_text, error_text)
        text = take(summary)
        if text:
            add("nginx summary", "nginx:summary", text, lines=80)
        for p in cfg["log_paths"]:
            if not path_allowed(p) or forbidden_env_file(p):
                continue
            room = max_total - used
            if room <= 0:
                break
            text = opener(p, min(max_file, room), True)
            if text is None:
                continue
            text = take(last_lines(text, tail_n))
            if text is None:
                break
            add("log", p, text, access=False)
        auth_path = cfg["auth_log"]
        if auth_path and path_allowed(auth_path) and not forbidden_env_file(auth_path):
            raw = opener(auth_path, min(max_file, max_total - used), True)
            if raw:
                text = take(auth_summary(raw))
                if text:
                    add("auth summary", "auth:summary", text, lines=40)
        for kind, path, text in collect_journals(cfg, run):
            text = take((text or "")[:max_file])
            if text:
                add(kind, path, text, access=False)
        health = collect_health(cfg, run, opener)
        text = take(health or "")
        if text:
            add("server health", "health:status", text, lines=80)
        for kind, path, text in collect_mysql(cfg, run_sql=run_sql, open_env=open_env, creds=mysql_creds):
            text = take(text)
            if text:
                add(kind, path, text, lines=80)

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


def _store_cache(read_at, chunks, clock, ttl=None):
    global _cache
    if ttl is None:
        ttl = settings()["cache_ttl"]
    with _lock:
        _cache = (clock() + ttl, read_at, chunks)


def clear_cache():
    global _cache
    with _lock:
        _cache = None


def _cached_collect(producer, clock, ttl=None):
    """Single-flight: one collect on a cache miss; waiters reuse the result."""
    cached = _from_cache(clock)
    if cached is not None:
        return cached
    with _collect_lock:
        cached = _from_cache(clock)
        if cached is not None:
            return cached
        chunks, read_at = producer()
        _store_cache(read_at, chunks, clock, ttl=ttl)
        return read_at, chunks


def pull_socket(path, timeout=10):
    data = b""
    cap = settings()["max_total_bytes"]
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
        if n > cap * 3:
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


def search(query, k=None, collect_fn=None, clock=time.time, open_file=None, paths=None,
           commands=None, run_cmd=None, cfg=None, run_sql=None, open_env=None, mysql_creds=None):
    """BM25-rank live chunks against the question. Caches the raw read for CACHE_TTL seconds."""
    cfg = cfg or settings()
    if k is None:
        k = cfg["live_k"]

    def producer():
        if collect_fn is not None:
            return collect_fn()
        if open_file is not None or paths is not None or commands is not None:
            return collect(open_file=open_file, run_cmd=run_cmd, paths=paths,
                           commands=commands, include_snapshot=False, include_extras=False,
                           clock=clock, cfg=cfg)
        return default_collect(clock=clock)

    read_at, chunks = _cached_collect(producer, clock, ttl=cfg["cache_ttl"])
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
        read_at, chunks = _cached_collect(collect_local, time.time)
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
    work = queue.Queue(maxsize=SERVE_QUEUE)

    def worker():
        while True:
            conn = work.get()
            if conn is None:
                return
            try:
                _handle(conn)
            finally:
                work.task_done()

    for _ in range(SERVE_WORKERS):
        threading.Thread(target=worker, daemon=True).start()
    try:
        while True:
            conn, _ = sock.accept()
            try:
                work.put(conn, timeout=10)
            except queue.Full:
                conn.close()
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
