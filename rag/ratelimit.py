"""In-memory rate limits: per-key sliding minute window and per-day counters."""
import threading
import time


class Limiter:
    def __init__(self, per_minute, clock=time.time):
        self.per_minute = per_minute
        self.clock = clock
        self.hits = {}
        self.lock = threading.Lock()

    def allow(self, key):
        now = self.clock()
        with self.lock:
            q = [t for t in self.hits.get(key, ()) if now - t < 60]
            ok = len(q) < self.per_minute
            if ok:
                q.append(now)
            self.hits[key] = q
            if len(self.hits) > 50000:  # drop idle keys
                self.hits = {k: v for k, v in self.hits.items() if v and now - v[-1] < 60}
            return ok


class DailyCap:
    """Per-key and global caps that reset at UTC midnight."""

    def __init__(self, per_key, global_cap, clock=time.time):
        self.per_key = per_key
        self.global_cap = global_cap
        self.clock = clock
        self.day = None
        self.counts = {}
        self.total = 0
        self.lock = threading.Lock()

    def take(self, key):
        """Returns None if allowed (and counts it), else a reason string."""
        day = int(self.clock() // 86400)
        with self.lock:
            if day != self.day:
                self.day, self.counts, self.total = day, {}, 0
            if self.total >= self.global_cap:
                return "global daily limit reached, try again tomorrow"
            if self.counts.get(key, 0) >= self.per_key:
                return f"daily limit of {self.per_key} questions reached, try again tomorrow"
            self.counts[key] = self.counts.get(key, 0) + 1
            self.total += 1
            return None

    def remaining(self, key):
        day = int(self.clock() // 86400)
        with self.lock:
            if day != self.day:
                return self.per_key
            return max(0, min(self.per_key - self.counts.get(key, 0), self.global_cap - self.total))
