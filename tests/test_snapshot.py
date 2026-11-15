import os
import shutil
import tempfile
import unittest

from rag import collect_prod, snapshot
from rag.collect_prod import Runner
from rag.index import write_db
from rag.search import Index
from rag.snapshot import F, T, collect, keep_system_group, keep_system_passwd, net_tcp, to_chunks

PASSWD = """root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
svc:x:998:998::/var/lib/svc:/usr/sbin/nologin
yisheng:x:1000:1000:Yisheng Jiang,,,:/home/yisheng:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin"""


class TransformTest(unittest.TestCase):
    def test_passwd_drops_humans(self):
        out = keep_system_passwd(PASSWD)
        self.assertNotIn("yisheng", out)
        self.assertIn("svc:x:998", out)
        self.assertIn("nobody", out)
        self.assertNotIn("svc", keep_system_passwd(PASSWD, 100))  # public sample keeps distro ids only

    def test_group_empties_members(self):
        out = keep_system_group("sudo:x:27:yisheng,alice\nyisheng:x:1000:\nadm:x:4:syslog,yisheng")
        self.assertEqual(out, "sudo:x:27:\nadm:x:4:")

    def test_net_tcp_masks_addresses(self):
        raw = ("  sl  local_address rem_address   st\n"
               "   0: 0100007F:1F90 00000000:0000 0A\n"
               "   1: 0000000000000000FFFF00000100007F:0016 00000000000000000000000000000000:0000 0A\n")
        out = net_tcp(raw)
        self.assertNotIn("0100007F", out)
        self.assertIn("[IPHEX]:1F90", out)
        self.assertIn("[IPHEX]:0016", out)


class CollectTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        files = {
            "etc/passwd": PASSWD,
            "etc/hosts": "127.0.0.1 localhost\n203.0.113.5 db.internal",
            "etc/shadow": "root:$6$SHADOWHASH:19000:0:99999:7:::",
            "etc/gshadow": "root:*::",
            "etc/sudoers": "root ALL=(ALL) ALL SUDOERSLINE",
            "etc/app.env": "XAI_API_KEY=ENVSECRET",
            "etc/gbk-composer.env": "COMPOSERSECRET=1",
            "etc/ssh/ssh_host_ed25519_key": "HOSTKEY",
            "etc/cron.d/backup": "0 3 * * * root DB_PASSWORD=pw backup.sh",
            "etc/cron.d/backup.bak": "old",
            "sys/vm/swappiness": "60",
            "sys/vm/dirty_ratio": "20",
            "sys/kernel/hostname": "box1",
        }
        for rel, text in files.items():
            p = os.path.join(self.root, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w").write(text)
        r = self.root
        self.specs = [
            F(f"{r}/etc/passwd", ["man5/passwd.5"], "passwd"),
            F(f"{r}/etc/hosts", ["man5/hosts.5"]),
            F(f"{r}/etc/*", []),             # glob that would reach shadow, sudoers, *.env
            F(f"{r}/etc/ssh/*", []),
            F(f"{r}/etc/cron.d/*", []),
            T("/proc/sys/vm", f"{r}/sys/vm/*", ["man5/proc_sys_vm.5"], "vm."),
        ]
        self.cmds = []
        local = Runner(None)

        def run(cmd):
            self.cmds.append(cmd)
            return local(cmd)
        self.run = run

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_denylisted_files_are_never_opened(self):
        docs = collect(self.run, public=False, specs=self.specs)
        read_script = self.cmds[-1]
        for name in ("shadow", "gshadow", "sudoers", "app.env", "gbk-composer.env", "ssh_host_ed25519_key", "backup.bak"):
            self.assertNotIn(name, read_script, name)
        text = "\n".join(d["text"] for d in docs)
        for secret in ("SHADOWHASH", "SUDOERSLINE", "ENVSECRET", "COMPOSERSECRET", "HOSTKEY", "=pw", "203.0.113.5", "yisheng"):
            self.assertNotIn(secret, text, secret)
        self.assertIn("vm.swappiness = 60", text)
        self.assertIn("vm.dirty_ratio = 20", text)

    def test_chunks_carry_path_and_docs(self):
        chunks = to_chunks(collect(self.run, public=True, specs=self.specs), "sample")
        vm = next(c for c in chunks if c[1] == "/proc/sys/vm")
        self.assertIn("sample snapshot", vm[0])
        self.assertIn("Docs: man5/proc_sys_vm.5", vm[3])
        prod = to_chunks(collect(self.run, public=False, specs=self.specs), "prod")
        self.assertIn("snapshot from this server", prod[0][0])

    def test_real_spec_paths_pass_denylist(self):
        from rag.redact import path_allowed
        for s in snapshot.SPECS:
            self.assertTrue(path_allowed(s.get("glob", s["path"])), s["path"])

    def test_prod_collector_includes_snapshot(self):
        seen = {}
        orig = snapshot.collect
        snapshot.collect = lambda run, public=True: seen.setdefault("public", public) and [] or []
        try:
            collect_prod.collect(lambda cmd: "")
        finally:
            snapshot.collect = orig
        self.assertIs(seen["public"], False)


class PairingTest(unittest.TestCase):
    def test_snapshot_pulls_its_doc_section(self):
        d = tempfile.mkdtemp()
        write_db(f"{d}/sys.db", [("/proc/meminfo sample snapshot", "/proc/meminfo", "L1-3",
                                  "/proc/meminfo — sample snapshot\nDocs: man5/proc_meminfo.5; Documentation/filesystems/proc.rst\n\n"
                                  "MemTotal: 16 kB\nDirty: 120 kB")])
        write_db(f"{d}/man.db", [("proc_meminfo(5) DESCRIPTION", "man5/proc_meminfo.5", "",
                                  "Dirty %lu Memory which is waiting to get written back to the disk."),
                                 ("proc_meminfo(5) SEE ALSO", "man5/proc_meminfo.5", "", "free(1)")])
        write_db(f"{d}/kdocs.db", [("The /proc Filesystem — meminfo", "Documentation/filesystems/proc.rst", "L1-9",
                                    "meminfo Provides information about distribution and utilization of memory.")])
        hits = Index(d).search("Dirty meminfo")
        order = [(h["corpus"], h["path"]) for h in hits]
        i = order.index(("sys", "/proc/meminfo"))
        self.assertIn(("man", "man5/proc_meminfo.5"), order)
        self.assertIn(("kdocs", "Documentation/filesystems/proc.rst"), order)
        man = next(h for h in hits if h["corpus"] == "man")
        self.assertIn("Dirty", man["body"])
        self.assertGreater(len(order), i)
        # a snapshot that only matched incidentally gets no doc pairing
        unrelated = Index(d).search("dirty pages writeback")
        self.assertFalse([h for h in unrelated if h.get("paired_with")])
        shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
