"""Build SQLite FTS5 indexes.

  python3 -m rag.index man   MAN_PAGES_DIR  data/man.db
  python3 -m rag.index kdocs LINUX_DIR      data/kdocs.db
  python3 -m rag.index src   LINUX_DIR      data/src.db
  python3 -m rag.index sys   samples/sys_snapshot.json data/sys.db
(prod logs/configs: python3 -m rag.collect_prod)
"""
import os
import sqlite3
import sys
from pathlib import Path

from rag.chunk import c_chunks, man_chunks, rst_chunks, split_long, text_chunks

SCHEMA = """CREATE VIRTUAL TABLE chunks USING fts5(
  title, path, body, loc UNINDEXED, tokenize = "porter unicode61 tokenchars '_'")"""

MAN_SECTIONS = ["man2", "man2const", "man2type", "man3", "man3const", "man3type", "man3head",
                "man4", "man5", "man7", "man8"]

SRC_DIRS = ["include/uapi", "kernel", "mm", "net/core", "arch/x86/entry",
            "fs/proc", "fs/notify", "fs/iomap", "fs/kernfs", "fs/ramfs"]
SRC_TOP = ["fs"]  # top-level files only (fs/*.c holds the VFS, pipe, eventpoll, exec, ...)
SRC_EXT = {".c", ".h", ".S", ".tbl"}


def write_db(path, chunks):
    tmp = str(path) + ".tmp"
    if os.path.exists(tmp):
        os.remove(tmp)
    db = sqlite3.connect(tmp)
    db.execute(SCHEMA)
    n = 0
    for batch_start in range(0, len(chunks), 5000):
        db.executemany("INSERT INTO chunks(title, path, loc, body) VALUES (?,?,?,?)",
                       chunks[batch_start:batch_start + 5000])
        n += len(chunks[batch_start:batch_start + 5000])
    db.execute("INSERT INTO chunks(chunks) VALUES('optimize')")
    db.commit()
    db.execute("VACUUM")
    db.close()
    os.replace(tmp, path)
    return n


def read(p):
    return p.read_text(encoding="utf-8", errors="replace")


def build_man(root):
    root = Path(root) / "man"
    out = []
    for sec in MAN_SECTIONS:
        for f in sorted((root / sec).glob("*")):
            src = read(f)
            if src.lstrip().startswith(".so ") or not f.is_file():
                continue
            out += man_chunks(src, f"{sec}/{f.name}")
    return out


def abi_chunks(src, rel):
    """Documentation/ABI files: one chunk per `What:` entry (sysfs/procfs attribute docs)."""
    out, cur = [], []
    for line in src.split("\n") + ["What:"]:
        if line.startswith("What:") and cur and not cur[-1].startswith("What:"):
            body = "\n".join(cur).strip()
            what = " ".join(l[5:].strip() for l in cur if l.startswith("What:"))
            if what:
                out += split_long(what[:200], rel, "", body)
            cur = []
        cur.append(line)
    return out


def build_kdocs(root):
    root = Path(root)
    out = []
    for f in sorted((root / "Documentation").rglob("*")):
        rel = f.relative_to(root).as_posix()
        if not f.is_file() or "/translations/" in rel:
            continue
        if rel.startswith("Documentation/ABI/") and not f.suffix:
            out += abi_chunks(read(f), rel)
        elif f.suffix in (".rst", ".txt"):
            out += rst_chunks(read(f), rel)
    return out


def build_sys(snapshot_json):
    from rag.snapshot import to_chunks
    import json
    return to_chunks(json.loads(Path(snapshot_json).read_text())["files"], "sample")


def build_src(root):
    root = Path(root)
    files = []
    for d in SRC_DIRS:
        files += [f for f in (root / d).rglob("*") if f.is_file()]
    for d in SRC_TOP:
        files += [f for f in (root / d).iterdir() if f.is_file()]
    extra = root / "extra" / "syscalls.h"
    out = []
    for f in sorted(set(files)) + ([extra] if extra.exists() else []):
        if f.suffix not in SRC_EXT:
            continue
        rel = "include/linux/syscalls.h" if f == extra else f.relative_to(root).as_posix()
        src = read(f)
        if f.suffix == ".tbl":
            for t, path, loc, body in text_chunks(src, rel, 40):
                names = [l.split()[2] for l in body.split("\n") if len(l.split()) > 2 and l[0].isdigit()]
                out.append((f"{rel} " + " ".join(names), path, loc, body))
        else:
            out += c_chunks(src, rel)
    return out


def main(argv):
    kind, src, dst = argv[1:4]
    chunks = {"man": build_man, "kdocs": build_kdocs, "src": build_src, "sys": build_sys}[kind](src)
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    n = write_db(dst, chunks)
    print(f"{kind}: {n} chunks, {os.path.getsize(dst) / 1e6:.1f} MB -> {dst}")


if __name__ == "__main__":
    main(sys.argv)
