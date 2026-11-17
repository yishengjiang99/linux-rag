"""BM25 retrieval over the FTS5 indexes."""
import os
import re
import sqlite3

STOP = set("""a an and are as at be by can do does did for from has have how i if in into is it its me my
no not of on or so than that the their them then there these this to was what when where which who why
will with you your about explain tell show give find use used using get way would should could also any
some all more most other such only own same very just here please".split()
""".split())

# corpus name -> (db file, results to take)
PUBLIC = [("man", 3), ("kdocs", 2), ("src", 3), ("sys", 2)]
ADMIN = [("prod", 6)]


def fts_query(text, max_terms=16):
    terms = []
    # /proc/meminfo -> proc_meminfo, /proc/sys/vm -> proc_sys_vm (man page names)
    for m in re.findall(r"/proc/([\w/]+)", text):
        parts = [x for x in m.split("/") if x and x not in ("self",) and not x.isdigit()]
        for n in range(len(parts), 0, -1):
            t = "proc_" + "_".join(parts[:n]).lower()
            if t not in terms:
                terms.append(t)
    words = []
    for t in re.findall(r"[A-Za-z0-9_]+", text):
        t = t.lower()
        if len(t) < 2 or t in STOP:
            continue
        words.append(t)
        if t not in terms:
            terms.append(t)
    # identifiers are single tokens (tokenchars '_'): "transparent hugepage" -> transparent_hugepage
    for a, b in zip(words, words[1:]):
        if "_" not in a + b and f"{a}_{b}" not in terms:
            terms.append(f"{a}_{b}")
    return " OR ".join(f'"{t}"' for t in terms[:max_terms])


def search_db(db, query, k):
    q = fts_query(query)
    if not q:
        return []
    rows = db.execute(
        "SELECT title, path, loc, body, bm25(chunks, 8.0, 3.0, 1.0) AS s FROM chunks "
        "WHERE chunks MATCH ? ORDER BY s LIMIT ?", (q, k)).fetchall()
    return [{"title": r[0], "path": r[1], "loc": r[2], "body": r[3], "score": r[4]} for r in rows]


def search_path(db, query, path):
    """Best chunk of one document for this query, else its first chunk."""
    cols = "title, path, loc, body"
    q = fts_query(query)
    row = None
    if q:
        row = db.execute(f"SELECT {cols}, bm25(chunks, 8.0, 3.0, 1.0) AS s FROM chunks WHERE chunks MATCH ? "
                         "AND path = ? ORDER BY s LIMIT 1", (q, path)).fetchone()
    if not row:
        row = db.execute(f"SELECT {cols}, 0 FROM chunks WHERE path = ? LIMIT 1", (path,)).fetchone()
    return {"title": row[0], "path": row[1], "loc": row[2], "body": row[3], "score": row[4]} if row else None


def doc_refs(body):
    """The `Docs: a; b` line that snapshot chunks carry."""
    m = re.search(r"^Docs: (.+)$", body[:600], re.M)
    return [r.strip() for r in m.group(1).split(";")] if m else []


class Index:
    """Read-only connections; a db file replaced on disk (new index) is reopened on next search."""

    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.dbs, self.mtimes = {}, {}
        self.reload()

    def reload(self):
        for name, _ in PUBLIC + ADMIN:
            path = f"{self.data_dir}/{name}.db"
            try:
                mtime = os.stat(path).st_mtime
            except OSError:
                continue
            if self.mtimes.get(name) == mtime:
                continue
            try:
                db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, check_same_thread=False)
                db.execute("SELECT 1 FROM chunks LIMIT 1")
            except sqlite3.Error:
                continue
            old = self.dbs.get(name)
            self.dbs[name], self.mtimes[name] = db, mtime
            if old:
                old.close()

    def search(self, query, admin=False, uploads=None, live=None):
        self.reload()
        # order matters: the prompt is filled in this order until the context budget runs out,
        # so the visitor's own uploads, live server reads, then hourly prod, then public docs
        hits = []
        if uploads is not None:
            for h in search_db(uploads, query, 3):
                h["corpus"] = "upload"
                hits.append(h)
        if admin and live:
            for h in live:
                h = dict(h)
                h["corpus"] = "live"
                hits.append(h)
        for name, k in (ADMIN if admin else []) + PUBLIC:
            if name in self.dbs:
                for h in search_db(self.dbs[name], query, k):
                    h["corpus"] = name
                    hits.append(h)
        # drop weak matches relative to the best one in the same corpus (bm25: lower is better)
        best = {}
        for h in hits:
            best[h["corpus"]] = min(best.get(h["corpus"], 0), h["score"])
        hits = [h for h in hits if h["score"] <= best[h["corpus"]] * 0.5]
        return self.pair_docs(query, hits)

    def pair_docs(self, query, hits, max_snapshots=2, max_refs=2):
        """Put each snapshot (sys/prod) next to the man page / kernel doc section that explains it."""
        out, seen, paired = [], {(h["corpus"], h["path"], h["loc"], h["title"]) for h in hits}, 0
        qwords = set(re.findall(r"[a-z0-9]+", query.lower())) - STOP - {"proc", "sys", "etc", "linux"}
        for h in hits:
            out.append(h)
            if h["corpus"] not in ("sys", "prod", "live") or paired >= max_snapshots:
                continue
            if not qwords & set(re.findall(r"[a-z0-9]+", h["path"].lower())):
                continue  # only pair snapshots the question is actually about
            refs = doc_refs(h["body"])[:max_refs]
            if refs:
                paired += 1
            for ref in refs:
                corpus = "man" if ref.startswith("man") else "kdocs"
                if corpus not in self.dbs:
                    continue
                d = search_path(self.dbs[corpus], query, ref)
                if d and (corpus, d["path"], d["loc"], d["title"]) not in seen:
                    seen.add((corpus, d["path"], d["loc"], d["title"]))
                    d["corpus"] = corpus
                    d["paired_with"] = h["path"]
                    out.append(d)
        return out


def upload_db():
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("""CREATE VIRTUAL TABLE chunks USING fts5(
      title, path, body, loc UNINDEXED, tokenize = "porter unicode61 tokenchars '_'")""")
    return db
