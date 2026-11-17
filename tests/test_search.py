import tempfile
import unittest

from rag.chunk import c_chunks, man_chunks, nginx_chunks, rst_chunks, text_chunks
from rag.index import write_db
from rag.search import Index, fts_query, search_db, upload_db

C_SRC = """/* create a pipe */
static int __do_pipe_flags(int *fd, struct file **files, int flags)
{
\treturn 0;
}

SYSCALL_DEFINE2(pipe2, int __user *, fildes, int, flags)
{
\treturn do_pipe2(fildes, flags);
}
"""

MAN_SRC = """.TH epoll_ctl 2 2024 "Linux"
.SH NAME
epoll_ctl \\- control interface for an epoll file descriptor
.SH DESCRIPTION
.TP
.B EPOLLEXCLUSIVE
Sets an exclusive wakeup mode for the epoll file descriptor.
"""

RST_SRC = """Pipes
=====

Intro text about pipes and the kernel buffer used for them, long enough to index.

Splice
------

splice moves data between a pipe and a file without copying through user space at all.
"""


class ChunkTest(unittest.TestCase):
    def test_c_functions(self):
        titles = [c[0] for c in c_chunks(C_SRC, "fs/pipe.c")]
        self.assertIn("__do_pipe_flags", titles)
        self.assertIn("SYSCALL_DEFINE pipe2 sys_pipe2", titles)
        body = next(c[3] for c in c_chunks(C_SRC, "fs/pipe.c") if c[0] == "__do_pipe_flags")
        self.assertIn("create a pipe", body)  # leading comment kept

    def test_man(self):
        ch = man_chunks(MAN_SRC, "man2/epoll_ctl.2")
        self.assertEqual(ch[0][0], "epoll_ctl(2) DESCRIPTION")
        self.assertIn("EPOLLEXCLUSIVE", ch[0][3])
        self.assertIn("control interface", ch[0][3])

    def test_rst_sections(self):
        ch = rst_chunks(RST_SRC, "Documentation/x.rst")
        self.assertEqual([c[0] for c in ch], ["Pipes", "Pipes — Splice"])

    def test_nginx_location_not_split(self):
        # location /rag/ starts just before the 80-line window ends; proxy_pass is after L80,
        # so a naive split (the L81-160 cutoff) never keeps the opening and proxy_pass together.
        preamble = "\n".join(f"# filler {i}" for i in range(1, 76))
        block = "\n".join(
            ["location /rag/ {"] +
            [f"    # inside {i}" for i in range(1, 21)] +
            ["    proxy_pass http://127.0.0.1:8795;",
             "    proxy_http_version 1.1;",
             "    proxy_set_header Host $host;",
             "}"]
        )
        src = preamble + "\n" + block + "\n" + "\n".join(f"# after {i}" for i in range(1, 40))
        naive = text_chunks(src, "/etc/nginx/sites-enabled/finalcut-site.conf", 80)
        self.assertFalse(any("location /rag/" in c[3] and "proxy_pass" in c[3] for c in naive))
        ch = nginx_chunks(src, "/etc/nginx/sites-enabled/finalcut-site.conf", 80, overlap=20)
        self.assertTrue(any("location /rag/" in c[3] and "proxy_pass http://127.0.0.1:8795" in c[3] for c in ch),
                        [c[2] for c in ch])

    def test_text_chunks_overlap(self):
        src = "\n".join(f"line {i}" for i in range(1, 101))
        ch = text_chunks(src, "x.log", 60, overlap=20)
        self.assertIn("line 60", ch[0][3])
        self.assertIn("line 41", ch[1][3])  # 60-20+1
        self.assertIn("line 61", ch[1][3])



class SearchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        write_db(f"{cls.dir}/src.db", c_chunks(C_SRC, "fs/pipe.c"))
        write_db(f"{cls.dir}/man.db", man_chunks(MAN_SRC, "man2/epoll_ctl.2"))
        write_db(f"{cls.dir}/kdocs.db", rst_chunks(RST_SRC, "Documentation/x.rst"))
        write_db(f"{cls.dir}/prod.db", [("nginx error log", "/var/log/nginx/error.log", "L1-1",
                                         "connect() failed (111: Connection refused) while connecting to upstream 502")])
        cls.ix = Index(cls.dir)

    def test_query_building(self):
        self.assertEqual(fts_query("What does EPOLLEXCLUSIVE do?"), '"epollexclusive"')
        self.assertEqual(fts_query('a "quoted" OR NEAR('), '"quoted" OR "near" OR "quoted_near"')
        self.assertIn('"transparent_hugepage"', fts_query("is transparent hugepage enabled"))
        self.assertEqual(fts_query("the of"), "")
        self.assertEqual(fts_query("Dirty in /proc/meminfo"), '"proc_meminfo" OR "dirty" OR "proc" OR "meminfo" OR "dirty_proc"')
        self.assertTrue(fts_query("/proc/sys/vm/swappiness").startswith('"proc_sys_vm_swappiness" OR "proc_sys_vm"'))

    def test_finds_identifiers(self):
        hits = self.ix.search("what does EPOLLEXCLUSIVE do")
        self.assertEqual(hits[0]["path"], "man2/epoll_ctl.2")
        hits = self.ix.search("pipe2 syscall")
        self.assertIn("SYSCALL_DEFINE pipe2 sys_pipe2", [h["title"] for h in hits])

    def test_prod_is_admin_only(self):
        q = "upstream connection refused 502"
        self.assertFalse([h for h in self.ix.search(q) if h["corpus"] == "prod"])
        admin_hits = self.ix.search(q, admin=True)
        self.assertEqual(admin_hits[0]["corpus"], "prod")

    def test_live_ahead_of_prod_public_ignores(self):
        live_hits = [{"title": "live nginx", "path": "/etc/nginx/nginx.conf", "loc": "L1-1",
                      "body": "connect() failed (111: Connection refused) while connecting to upstream 502",
                      "score": -1.0, "read_at": 1000.0}]
        q = "upstream connection refused 502"
        public = self.ix.search(q, live=live_hits)
        self.assertFalse([h for h in public if h["corpus"] in ("live", "prod")])
        admin = self.ix.search(q, admin=True, live=live_hits)
        self.assertEqual(admin[0]["corpus"], "live")
        self.assertIn("prod", [h["corpus"] for h in admin])

    def test_uploads(self):
        db = upload_db()
        db.execute("INSERT INTO chunks(title, path, loc, body) VALUES ('u','u.log','L1','kernel panic in foo_driver')")
        hits = self.ix.search("foo_driver panic", uploads=db)
        self.assertEqual([h["corpus"] for h in hits if h["path"] == "u.log"], ["upload"])
        self.assertEqual(search_db(db, "???", 3), [])


if __name__ == "__main__":
    unittest.main()
