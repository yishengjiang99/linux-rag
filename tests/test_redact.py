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

    def test_path_denylist(self):
        for p in ("/etc/gbk-composer.env", "/srv/app/.env", "/srv/app/.env.production", "/etc/ssl/private/x.key",
                  "/etc/letsencrypt/live/a/privkey.pem", "/etc/nginx/.htpasswd", "/root/.ssh/id_ed25519"):
            self.assertFalse(path_allowed(p), p)
        for p in ("/etc/nginx/sites-available/finalcut", "/etc/systemd/system/finalcut.service", "/var/log/nginx/error.log"):
            self.assertTrue(path_allowed(p), p)


if __name__ == "__main__":
    unittest.main()
