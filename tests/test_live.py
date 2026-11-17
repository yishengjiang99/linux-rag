import os
import re
from pathlib import Path
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
    "/root/.bashrc",
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

    def test_single_flight_on_cache_miss(self):
        import threading
        started, mid, calls = threading.Event(), threading.Event(), {"n": 0}

        def collect_fn():
            calls["n"] += 1
            started.set()
            mid.wait(1)
            return [("t", "/var/log/nginx/error.log", "L1-1", "singleflight zorb_live_backend")], 1_000.0

        clock = lambda: 1_000.0
        threads = [threading.Thread(target=lambda: live.search("zorb_live_backend", collect_fn=collect_fn, clock=clock))
                   for _ in range(3)]
        for t in threads:
            t.start()
        self.assertTrue(started.wait(1))
        mid.set()
        for t in threads:
            t.join(2)
        self.assertEqual(calls["n"], 1)


ACCESS_LOG = (
    '203.0.113.9 - - [16/Nov/2026:20:00:00 +0000] "GET /rag/api/ask HTTP/1.1" 502 157 "-" "curl/8.0"\n'
    '198.51.100.10 - - [16/Nov/2026:20:00:01 +0000] "GET /rag/api/ask HTTP/1.1" 502 157 "-" "Mozilla/5.0"\n'
    '198.51.100.11 - - [16/Nov/2026:20:00:02 +0000] "GET /health HTTP/1.1" 200 2 "-" "curl/8.0"\n'
    '198.51.100.12 - - [16/Nov/2026:20:00:03 +0000] "POST /api/login HTTP/1.1" 500 12 "-" "curl/8.0"\n'
)
ERROR_LOG = (
    "2026/11/16 20:00:00 [error] 1#1: connect() failed (111: Connection refused) while connecting to upstream\n"
    "2026/11/16 20:00:01 [error] 1#1: connect() failed (111: Connection refused) while connecting to upstream\n"
    "2026/11/16 20:00:02 [error] 1#1: upstream prematurely closed connection\n"
)
PROCESSLIST = (
    "Id\tUser\tHost\tdb\tCommand\tTime\tState\tInfo\n"
    "1\tapp\t203.0.113.9:3306\tfinalcut\tQuery\t2\tSending data\t"
    "SELECT * FROM users WHERE email='alice@example.com' AND token='hunter2secret' "
    "AND id=12345 AND uuid='a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'\n"
)
MYSQL_PW = "s3cret-mysql-pw-VALUE"


class LiveExtrasTest(unittest.TestCase):
    def setUp(self):
        live.clear_cache()

    def test_nginx_summary_redacts_and_counts(self):
        out = live.nginx_summary(ACCESS_LOG, ERROR_LOG)
        self.assertIn("502=2", out)
        self.assertIn("200=1", out)
        self.assertIn("500=1", out)
        self.assertIn("GET /rag/api/ask", out)
        self.assertIn("Connection refused", out)
        for ip in ("203.0.113.9", "198.51.100.10", "198.51.100.11"):
            self.assertNotIn(ip, out)

    def test_processlist_redacts_values_and_ips(self):
        out = live.format_processlist(PROCESSLIST)
        self.assertNotIn("alice@example.com", out)
        self.assertNotIn("hunter2secret", out)
        self.assertNotIn("203.0.113.9", out)
        self.assertIn("SELECT", out)
        self.assertIn("'?'", out)
        self.assertNotIn("12345", out)
        self.assertNotIn("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11", out)
        # Id / Time columns on the processlist row are kept; only Info literals are replaced
        self.assertIn("\tQuery\t2\t", out)

    def test_sql_allowlist_rejects_non_select_show(self):
        live.allow_sql("SHOW GLOBAL STATUS")
        live.allow_sql(live.SQL_TABLE_SIZES)
        for sql in (
            "INSERT INTO t VALUES (1)",
            "UPDATE t SET x=1",
            "DELETE FROM t",
            "DROP DATABASE finalcut",
            "LOAD DATA INFILE '/etc/passwd' INTO TABLE t",
            "SELECT 1; DROP TABLE t",
            "SELECT * FROM mysql.user",
            "SET GLOBAL general_log=1",
        ):
            with self.assertRaises(ValueError) as ctx:
                live.allow_sql(sql)
            self.assertEqual(str(ctx.exception), "sql not allowed")
            self.assertNotIn("passwd", str(ctx.exception))
            self.assertNotIn("finalcut", str(ctx.exception))

    def test_mysql_chunks_and_errors_never_include_secrets(self):
        cfg = live.settings()
        creds = {"host": "127.0.0.1", "user": "app", "password": MYSQL_PW, "database": "finalcut"}

        def run_sql(sql):
            live.allow_sql(sql)
            if sql == "SHOW GLOBAL STATUS":
                return "Uptime\t100\nQuestions\t500\nSlow_queries\t3\nThreads_connected\t4\n"
            if sql == "SHOW PROCESSLIST":
                return PROCESSLIST
            if sql == "SHOW ENGINE INNODB STATUS":
                return "====\nTRANSACTIONS\nSELECT x FROM t WHERE pw='" + MYSQL_PW + "'\n"
            if sql == live.SQL_TABLE_SIZES:
                return "table_schema\ttable_name\nfinalcut\tusers\n"
            return ""

        chunks = live.collect_mysql(cfg, run_sql=run_sql, creds=creds)
        text = "\n".join(c[2] for c in chunks)
        self.assertIn("Slow_queries", text)
        self.assertIn("Approx_QPS", text)
        self.assertNotIn(MYSQL_PW, text)
        self.assertNotIn("alice@example.com", text)
        self.assertNotIn("203.0.113.9", text)
        self.assertNotIn("hunter2secret", text)
        self.assertNotIn("12345", text)

        def bad_sql(sql):
            raise ValueError("access denied for '" + MYSQL_PW + "' at 203.0.113.9")

        chunks = live.collect_mysql(cfg, run_sql=bad_sql, creds=creds)
        self.assertEqual(chunks, [])

    def test_mysql_skipped_when_creds_missing(self):
        self.assertIsNone(live.mysql_creds_from_env({}))
        self.assertIsNone(live.mysql_creds_from_env({"MYSQL_USER": "app"}))
        self.assertIsNone(live.mysql_creds_from_env({"MYSQL_PASSWORD": MYSQL_PW}))
        self.assertEqual(live.collect_mysql(live.settings(), env={}), [])
        creds = live.mysql_creds_from_env({
            "MYSQL_HOST": "localhost", "MYSQL_USER": "app",
            "MYSQL_PASSWORD": MYSQL_PW, "MYSQL_DATABASE": "finalcut",
        })
        self.assertEqual(creds["user"], "app")
        self.assertEqual(creds["password"], MYSQL_PW)

    def test_auth_summary_has_counts_not_identities(self):
        raw = ("sshd: Accepted publickey for alice from 203.0.113.9 port 22\n"
               "sshd: Failed password for bob from 198.51.100.10 port 22\n"
               "sshd: Invalid user eve from 198.51.100.11\n")
        out = live.auth_summary(raw)
        self.assertIn("accepted logins: 1", out)
        self.assertIn("failed logins: 1", out)
        self.assertIn("invalid user attempts: 1", out)
        for s in ("alice", "bob", "eve", "203.0.113.9", "198.51.100.10"):
            self.assertNotIn(s, out)

    def test_collect_never_opens_env_paths(self):
        opened = []
        env_paths = [
            "/etc/nginx/.env",
            "/home/finalcut/apps/pages/finalcut/.env",
            "/opt/app/.env.production",
            "/tmp/foo.env",
            "/etc/linux-rag/mysql.env",
            "/etc/gbk-composer.env",
        ]

        def open_file(path, max_bytes, tail):
            opened.append(path)
            if path.endswith("access.log"):
                return ACCESS_LOG
            if path.endswith("error.log"):
                return ERROR_LOG
            if path.endswith("nginx.conf"):
                return "http {\n  server { listen 80; }\n}\n"
            return "SHOULD_NOT_READ"

        cfg = live.settings({"RAG_LOG_PATHS": ",".join(env_paths),
                             "RAG_NGINX_ACCESS_LOG": "/var/log/nginx/access.log",
                             "RAG_NGINX_ERROR_LOG": "/var/log/nginx/error.log",
                             "RAG_AUTH_LOG": "/etc/linux-rag/mysql.env",
                             "RAG_JOURNAL_UNITS": ""})
        paths = [("nginx config", "/etc/nginx/nginx.conf", False, False)] + [
            ("env", p, False, False) for p in env_paths
        ]
        chunks, _ = live.collect(
            open_file=open_file, run_cmd=lambda cmd: "", paths=paths, commands=[],
            include_snapshot=False, include_extras=True, cfg=cfg,
            mysql_creds={"host": "", "user": "app", "password": MYSQL_PW, "database": ""},
            run_sql=lambda sql: "",
        )
        for p in opened:
            self.assertFalse(p.endswith(".env") or ".env." in p or p.endswith("mysql.env"), p)
        text = "\n".join(c[3] for c in chunks)
        self.assertNotIn(MYSQL_PW, text)
        self.assertNotIn("SHOULD_NOT_READ", text)

    def test_subprocesses_do_not_inherit_mysql(self):
        import subprocess
        for k, v in (("MYSQL_PASSWORD", MYSQL_PW), ("MYSQL_USER", "app"),
                     ("MYSQL_HOST", "localhost"), ("MYSQL_DATABASE", "finalcut"),
                     ("MYSQL_PWD", MYSQL_PW)):
            os.environ[k] = v
        try:
            env = live.subprocess_env()
            for k in ("MYSQL_PASSWORD", "MYSQL_USER", "MYSQL_HOST", "MYSQL_DATABASE", "MYSQL_PWD"):
                self.assertNotIn(k, env)
            self.assertNotIn(MYSQL_PW, " ".join(env.values()))
            seen = []

            def capture(*_a, **kw):
                seen.append(dict(kw.get("env") or {}))
                return subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")

            with mock.patch("subprocess.run", side_effect=capture):
                live._run("true")
                self.assertEqual(len(seen), 1)
                got = seen[0]
                for k in ("MYSQL_PASSWORD", "MYSQL_USER", "MYSQL_HOST", "MYSQL_DATABASE", "MYSQL_PWD"):
                    self.assertNotIn(k, got)
                self.assertNotIn(MYSQL_PW, " ".join(map(str, got.values())))
                # mysql client gets MYSQL_PWD only, never MYSQL_PASSWORD
                seen.clear()
                creds = {"host": "localhost", "user": "app", "password": MYSQL_PW, "database": "finalcut"}
                with mock.patch.object(live, "_mysql_bin", return_value="/usr/bin/mysql"):
                    live.mysql_cli("SHOW GLOBAL STATUS", creds)
                self.assertEqual(len(seen), 1)
                menv = seen[0]
                self.assertEqual(menv.get("MYSQL_PWD"), MYSQL_PW)
                self.assertNotIn("MYSQL_PASSWORD", menv)
                self.assertNotIn("MYSQL_USER", menv)
        finally:
            for k in ("MYSQL_PASSWORD", "MYSQL_USER", "MYSQL_HOST", "MYSQL_DATABASE", "MYSQL_PWD"):
                os.environ.pop(k, None)

    def test_sample_env_has_no_secret_looking_values(self):
        root = Path(__file__).resolve().parent.parent
        text = (root / "sample.env").read_text()
        self.assertNotIn("/etc/gbk-composer.env", text)
        self.assertNotIn("/etc/linux-rag/secrets", text)
        self.assertNotIn("/home/finalcut", text)
        secret_val = re.compile(
            r"(?i)(sk[_-]live|sk[_-]test|xai-|ghp_|github_pat_|AKIA|whsec_|-----BEGIN|"
            r"eyJ[A-Za-z0-9_-]{8,}\.)"
        )
        for i, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            self.assertIsNone(secret_val.search(s), f"line {i}: {s}")
            if not s or s.startswith("#"):
                continue
            k, _, v = s.partition("=")
            v = v.strip().strip("'\"")
            self.assertFalse(secret_val.search(v), f"{k}={v}")
            self.assertNotIn("PASSWORD", k)
            self.assertNotRegex(v, r"^[A-Za-z0-9+/=_-]{24,}$")


if __name__ == "__main__":
    unittest.main()
