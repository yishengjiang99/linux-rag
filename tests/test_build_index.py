"""update_checkout in scripts/build_index.sh: fetch failures are loud, never silent."""
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "build_index.sh")
ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t",
           GIT_COMMITTER_EMAIL="t@t", GIT_CONFIG_GLOBAL="/dev/null")


def sh(*args, cwd=None):
    return subprocess.run(args, cwd=cwd, env=ENV, capture_output=True, text=True)


def update(dir_, need):
    return sh("bash", "-c", f'source "{SCRIPT}"; update_checkout "$1" "$2"', "_", dir_, need)


class UpdateCheckoutTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.remote = os.path.join(self.tmp, "remote")
        os.makedirs(self.remote)
        sh("git", "init", "-q", "-b", "main", cwd=self.remote)
        open(os.path.join(self.remote, "a.txt"), "w").write("v1")
        sh("git", "add", ".", cwd=self.remote)
        sh("git", "commit", "-q", "-m", "v1", cwd=self.remote)
        self.clone = os.path.join(self.tmp, "clone")
        sh("git", "clone", "-q", "--depth", "1", "file://" + self.remote, self.clone)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_fetches_new_commit(self):
        open(os.path.join(self.remote, "a.txt"), "w").write("v2")
        sh("git", "commit", "-qam", "v2", cwd=self.remote)
        r = update(self.clone, "a.txt")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(open(os.path.join(self.clone, "a.txt")).read(), "v2")

    def test_fetch_failure_warns_and_keeps_checkout(self):
        shutil.rmtree(self.remote)
        r = update(self.clone, "a.txt")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("WARNING: fetch failed", r.stderr)
        self.assertEqual(open(os.path.join(self.clone, "a.txt")).read(), "v1")

    def test_missing_content_fails(self):
        shutil.rmtree(self.remote)
        r = update(self.clone, "fs/pipe.c")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("ERROR", r.stderr)

    def test_no_commit_fails(self):
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        sh("git", "init", "-q", cwd=empty)
        r = update(empty, "a.txt")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no commit", r.stderr)


if __name__ == "__main__":
    unittest.main()
