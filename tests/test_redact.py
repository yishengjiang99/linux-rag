import unittest
from rag.redact import redact, path_allowed, classify_ua


class RedactTest(unittest.TestCase):
    def gone(self, raw, secret, **kw):
        out = redact(raw, **kw)
        self.assertNotIn(secret, out, out)
        return out

    def test_ipv4_ipv6(self):
        out = self.gone("client: 203.0.113.9, server: grepawk.com", "203.0.113.9")
        self.assertIn("[IP]", out)
        self.gone("from 2001:db8:85a3::8a2e:370:7334 port 22", "2001:db8")
        self.gone("addr fe80:0:0:0:200:f8ff:fe21:67cf", "fe21:67cf")
        self.gone("listen [::1]:80", "::1")

    def test_times_and_versions_survive(self):
        ssl = "SSL routines::bad key share; std::map; Foo::Bar"
        self.assertEqual(redact(ssl), ssl)
        line = "Nov 14 02:41:13 host nginx[123]: 1.18.0 started at 10:20:30"
        self.assertEqual(redact(line), line)

    def test_email(self):
        self.gone("from=<alice.smith@example.org> to=bob@x.io", "alice.smith@example.org")

    def test_env_and_systemd(self):
        self.gone("Environment=STRIPE_SECRET_KEY=sk_live_abcdefghijklmnop123456", "sk_live_abc")
        self.gone("XAI_API_KEY=xai-AbCdEf0123456789AbCdEf0123", "xai-AbCd")
        self.gone('DB_PASSWORD="hunter2 two"', "hunter2")
        self.gone('{"password": "s3cr3t!", "user": "x"}', "s3cr3t!")
        out = redact("EnvironmentFile=/etc/foo/app.conf")
        self.assertIn("/etc/foo/app.conf", out)

    def test_headers_and_tokens(self):
        self.gone("Authorization: Bearer abc.def.ghi-123456", "abc.def")
        self.gone("Cookie: sid=deadbeef; theme=dark", "sid=deadbeef")
        self.gone("token ghp_0123456789abcdefghijABCDEFGHIJ0123", "ghp_0123")
        self.gone("jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "eyJhbGci")
        self.gone("aws AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE")
        self.gone("proxy_set_header Authorization \"Basic dXNlcjpwYXNz\";", "dXNlcjpwYXNz")
        self.gone("GET /cb?token=abc123xyz&x=1 HTTP/1.1", "abc123xyz")
        self.gone("mysql://app:p4ssw0rd@localhost/db", "p4ssw0rd")
        self.gone("sess 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "9f86d081")

    def test_pem(self):
        pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\nkqhkiG9w0BAQEF\n-----END PRIVATE KEY-----"
        self.gone("x\n" + pem + "\ny", "MIIEvQIBADANBg")
        self.gone("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl root@box", "AAAAC3Nza")

    def test_access_log_user_agent(self):
        line = ('198.51.100.7 - - [14/Nov/2026:10:00:00 +0000] "GET /api/x?email=a@b.co HTTP/1.1" 502 157 '
                '"https://ref.example/p?uid=42" "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/604.1"')
        out = redact(line, access_log=True)
        for s in ("198.51.100.7", "a@b.co", "iPhone OS 17_0", "uid=42"):
            self.assertNotIn(s, out)
        self.assertIn(" 502 ", out)
        self.assertIn("UA:mobile-browser", out)
        self.assertIn("GET /api/x", out)

    def test_ua_classes(self):
        self.assertTrue(classify_ua("Googlebot/2.1").startswith("UA:bot"))
        self.assertEqual(classify_ua("-"), "-")

    def test_nginx_config_survives(self):
        conf = "server {\n    listen 443 ssl http2;\n    location /api { proxy_pass http://127.0.0.1:3001; }\n}"
        out = redact(conf)
        self.assertIn("listen 443 ssl http2;", out)
        self.assertIn("location /api", out)
        self.assertIn("proxy_pass http://[IP]:3001", out)

    def test_bypass_is_not_a_password(self):
        line = "Speculation_Store_Bypass:\tthread vulnerable"
        self.assertEqual(redact(line), line)
        for line in ("bypass=on", "compass=north", "surpass: yes"):
            self.assertEqual(redact(line), line)
        for raw in ("DB_PASS=x", "DBPASSWORD=y", "MYSQL_PASSWD=q", "DBPASS=hunter2xyz",
                    "Environment=SMTPPASS=hunter2", "ADMINPASS: letmein1", "PGPASSWORD=pw9", "mysql_pass=m"):
            self.assertIn("[REDACTED]", redact(raw), raw)
            self.assertNotRegex(redact(raw), r"hunter2|letmein1|pw9|=m$")

    def test_cgroup_path_not_ipv6(self):
        self.assertEqual(redact("0::/agent"), "0::/agent")
        self.assertIn("[IPV6]", redact("addr 2001:db8:: and fe80::1"))

    def test_path_denylist(self):
        for p in ("/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d/90-cloud", "/etc/ssh/ssh_host_rsa_key",
                  "/root/.ssh/authorized_keys", "/proc/self/environ", "/proc/1/cmdline", "/proc/self/mem",
                  "/proc/1/fd/3", "/etc/security/opasswd", "/etc/ssl/private/k", "/root/.netrc",
                  "/proc/kcore", "/proc/self/maps", "/proc/1234/maps", "/proc/1/task/2/maps", "/etc/ssh/sshd_config",
                  "/etc/ssh/ssh_config.d/x.conf", "/etc/linux-rag/secrets", "/etc/linux-rag/anything","/etc/gbk-composer.env", "/srv/app/.env", "/srv/app/.env.production", "/etc/ssl/private/x.key",
                  "/etc/letsencrypt/live/a/privkey.pem", "/etc/nginx/.htpasswd", "/root/.ssh/id_ed25519"):
            self.assertFalse(path_allowed(p), p)
        for p in ("/etc/nginx/sites-available/finalcut", "/etc/systemd/system/finalcut.service", "/var/log/nginx/error.log",
                  "/proc/cmdline", "/proc/pressure/memory", "/proc/meminfo", "/etc/passwd", "/proc/kcore_like",
                  "/proc/sys/vm/swappiness", "/etc/systemd/system/gbk-composer.service", "/opt/linux-rag/rag/server.py"):
            self.assertTrue(path_allowed(p), p)

    def test_any_key_short_value(self):
        for raw, secret in [("DEPLOY_KEY=ab", "=ab"), ("STRIPE_KEY=x", "=x"), ("APP_SECRET=1", "=1"),
                            ("GH_TOKEN=t0", "=t0"), ("DB_PASSWORD=pw", "=pw"), ("ADMIN_PASS=a", "=a"),
                            ("Environment=SIGNING_KEY=k1", "=k1"), ("export MY_TOKEN='z'", "'z'"),
                            ('deploy.key: abc', ": abc"), ('{"SECRET": "s"}', '"s"'), ("key=v", "=v")]:
            out = redact(raw)
            self.assertNotIn(secret, out, raw)
            self.assertIn("[REDACTED]", out, raw)

    def test_key_names_not_overmatched(self):
        for keep in ("monkey=3", "KeyringMode=private", "turnkey=yes", "ssl_certificate_key /etc/x.pem;",
                     "keepalive_timeout 65;", "hotkeys=on"):
            self.assertEqual(redact(keep), keep)

    def test_phone_numbers(self):
        for raw in ("call +1 415 555 0134 now", "tel +44 20 7946 0958", "+49-30-901820", "+861012345678",
                    "(415) 555-0134", "415-555-0134", "415.555.0134", "1-800-555-0199", "+33 (0)1 23 45 67 89"):
            out = redact(raw)
            self.assertIn("[PHONE]", out, raw)
            self.assertFalse(any(ch.isdigit() for ch in out.replace("[PHONE]", "")), (raw, out))

    def test_phone_no_false_positives(self):
        for keep in ("2026-11-14 18:40:00", "[14/Nov/2026:10:00:00 +0000]", "2026-11-14T18:40:00+08:00",
                     "nginx[148404]: pid 148404#148404: *78895", "nginx/1.18.0 python 3.10.12 kernel 5.15.0-202-generic",
                     "listen 443 ssl; proxy_pass http://localhost:8795;", "293\tcommon\tpipe2\tsys_pipe2",
                     "uptime 1731638400 epoch", "bytes 1048576 2097152", "version 123.456.7890",
                     "GET /api/x/415-555-0134-abc HTTP/1.1", "id=550e8400-e29b-41d4", "size 4155550134"):
            self.assertEqual(redact(keep), keep)


if __name__ == "__main__":
    unittest.main()
