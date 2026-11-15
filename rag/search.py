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
PUBLIC = [("man", 3), ("kdocs", 2), ("src", 3)]
ADMIN = [("prod", 6)]


def fts_query(text, max_terms=12):
    terms = []
    for t in re.findall(r"[A-Za-z0-9_]+", text):
        t = t.lower()
        if len(t) < 2 or t in STOP or t in terms:
            continue
        terms.append(t)
    return " OR ".join(f'"{t}"' for t in terms[:max_terms])


def search_db(db, query, k):
    q = fts_query(query)
    if not q:
        return []
    rows = db.execute(
        "SELECT title, path, loc, body, bm25(chunks, 8.0, 3.0, 1.0) AS s FROM chunks "
        "WHERE chunks MATCH ? ORDER BY s LIMIT ?", (q, k)).fetchall()
    return [{"title": r[0], "path": r[1], "loc": r[2], "body": r[3], "score": r[4]} for r in rows]


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

    def search(self, query, admin=False, uploads=None):
        self.reload()
        hits = []
        for name, k in PUBLIC + (ADMIN if admin else []):
            if name in self.dbs:
                for h in search_db(self.dbs[name], query, k):
                    h["corpus"] = name
                    hits.append(h)
        if uploads is not None:
            for h in search_db(uploads, query, 3):
                h["corpus"] = "upload"
                hits.append(h)
        # drop weak matches relative to the best one in the same corpus (bm25: lower is better)
        best = {}
        for h in hits:
            best[h["corpus"]] = min(best.get(h["corpus"], 0), h["score"])
        return [h for h in hits if h["score"] <= best[h["corpus"]] * 0.5]


def upload_db():
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("""CREATE VIRTUAL TABLE chunks USING fts5(
      title, path, body, loc UNINDEXED, tokenize = "porter unicode61 tokenchars '_'")""")
    return db
