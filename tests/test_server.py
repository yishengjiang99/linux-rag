import http.client
import json
import os
import tempfile
import threading
import unittest

from rag.index import write_db

DATA = tempfile.mkdtemp()
write_db(f"{DATA}/man.db", [("pipe(2) DESCRIPTION", "man2/pipe.2", "", "pipe2 creates a pipe with O_CLOEXEC flags")])
write_db(f"{DATA}/prod.db", [("nginx error log", "/var/log/nginx/error.log", "L1-1", "upstream prematurely closed 502 SECRETPRODLINE")])
os.environ.update(RAG_DATA=DATA, RAG_ADMIN_PASSWORD="correct-horse-battery", RAG_PER_IP_DAILY="3",
                  RAG_GLOBAL_DAILY="100", RAG_REQ_PER_MIN="1000", XAI_API_KEY="test")

from rag import grok, server  # noqa: E402

PROMPTS = []


def fake_chat(messages, model, max_tokens):
    PROMPTS.append(messages[1]["content"])
    return "answer <b>[1]</b>", {"total_tokens": 1}


grok.chat = fake_chat


class ServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def req(self, method, path, body=None, cookie=None, ip="198.51.100.1", raw=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port)
        h = {"X-Real-IP": ip}
        if body is not None or raw is not None:
            h["Content-Type"] = "application/json"
        if cookie:
            h["Cookie"] = cookie
        c.request(method, path, body=raw if raw is not None else (json.dumps(body) if body is not None else None), headers=h)
        r = c.getresponse()
        data = r.read()
        sc = r.getheader("Set-Cookie")
        ck = sc.split(";")[0] if sc else cookie
        try:
            data = json.loads(data)
        except ValueError:
            pass
        return r.status, data, ck, r

    def test_page_under_prefix(self):
        st, body, _, r = self.req("GET", "/rag/")
        self.assertEqual(st, 200)
        self.assertIn(b"Linux RAG", body)
        self.assertIn("script-src 'self'", r.getheader("Content-Security-Policy"))
        st, _, _, r = self.req("GET", "/rag")
        self.assertEqual((st, r.getheader("Location")), (301, "/rag/"))
        self.assertEqual(self.req("GET", "/rag/app.js")[0], 200)

    def test_ask_cites_and_caps(self):
        ip = "198.51.100.20"
        st, d, ck, _ = self.req("POST", "/rag/api/ask", {"q": "pipe with flags"}, ip=ip)
        self.assertEqual(st, 200, d)
        self.assertEqual(d["sources"][0]["label"], "pipe(2) DESCRIPTION — man2/pipe.2")
        self.assertTrue(d["sources"][0]["url"].startswith("https://man7.org/"))
        self.assertNotIn("SECRETPRODLINE", PROMPTS[-1])
        self.req("POST", "/rag/api/ask", {"q": "pipe"}, ip=ip)
        self.req("POST", "/rag/api/ask", {"q": "pipe"}, ip=ip)
        st, d, _, _ = self.req("POST", "/rag/api/ask", {"q": "pipe"}, ip=ip)
        self.assertEqual(st, 429)
        self.assertIn("daily limit", d["error"])

    def test_admin_gate(self):
        ip = "198.51.100.30"
        st, d, ck, _ = self.req("POST", "/rag/api/login", {"password": "nope"}, ip=ip)
        self.assertEqual(st, 403)
        st, d, ck, _ = self.req("POST", "/rag/api/login", {"password": "correct-horse-battery"}, ip=ip)
        self.assertEqual(st, 200)
        st, d, _, _ = self.req("POST", "/rag/api/ask", {"q": "nginx 502 upstream"}, cookie=ck, ip=ip)
        self.assertIn("SECRETPRODLINE", PROMPTS[-1])
        self.assertEqual(d["sources"][0]["corpus"], "prod")
        # prod comes first, so a full context budget of public hits can't crowd it out
        self.assertLess(PROMPTS[-1].index("SECRETPRODLINE"), PROMPTS[-1].index("Question:"))
        self.req("POST", "/rag/api/logout", {}, cookie=ck, ip=ip)
        self.req("POST", "/rag/api/ask", {"q": "nginx 502 upstream"}, cookie=ck, ip=ip)
        self.assertNotIn("SECRETPRODLINE", PROMPTS[-1])

    def test_login_rate_limited(self):
        codes = [self.req("POST", "/rag/api/login", {"password": "x"}, ip="198.51.100.40")[0] for _ in range(7)]
        self.assertEqual(codes[-1], 429)

    def test_uploads_private_and_limited(self):
        st, d, ck_a, _ = self.req("POST", "/rag/api/upload", {"name": "a.log", "text": "zorbulator crashed hard"}, ip="198.51.100.50")
        self.assertEqual(st, 200, d)
        self.req("POST", "/rag/api/ask", {"q": "zorbulator"}, ip="198.51.100.51")  # new session, other visitor
        self.assertNotIn("zorbulator crashed", PROMPTS[-1])
        self.req("POST", "/rag/api/ask", {"q": "zorbulator"}, cookie=ck_a, ip="198.51.100.50")
        self.assertIn("zorbulator crashed", PROMPTS[-1])
        st, d, _, _ = self.req("POST", "/rag/api/upload", {"name": "big.txt", "text": "x" * 1_000_001}, cookie=ck_a, ip="198.51.100.50")
        self.assertEqual(st, 413)
        st, d, _, _ = self.req("POST", "/rag/api/upload", {"name": "b.bin", "text": "a\u0000b"}, cookie=ck_a, ip="198.51.100.50")
        self.assertEqual(st, 400)
        for i in range(2):
            self.req("POST", "/rag/api/upload", {"name": f"f{i}.txt", "text": "hello"}, cookie=ck_a, ip="198.51.100.50")
        st, d, _, _ = self.req("POST", "/rag/api/upload", {"name": "f9.txt", "text": "hello"}, cookie=ck_a, ip="198.51.100.50")
        self.assertEqual(st, 400)
        self.assertIn("max 3 files", d["error"])

    def test_bad_requests(self):
        self.assertEqual(self.req("POST", "/rag/api/ask", raw="{bad")[0], 400)
        self.assertEqual(self.req("POST", "/rag/api/ask", {"q": "x" * 2001})[0], 400)
        self.assertEqual(self.req("GET", "/rag/nope")[0], 404)

    def test_request_rate_limit(self):
        old = server.req_limit.per_minute
        server.req_limit.per_minute = 3
        try:
            codes = [self.req("GET", "/rag/api/health", ip="198.51.100.60")[0] for _ in range(4)]
        finally:
            server.req_limit.per_minute = old
        self.assertEqual(codes, [200, 200, 200, 429])


if __name__ == "__main__":
    unittest.main()
