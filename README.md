# Linux RAG

Ask questions about Linux and get answers that cite the man page, kernel doc or source lines they came from. Live at https://grepawk.com/rag.

- **Retrieval:** SQLite FTS5 with BM25. No embeddings, no vector DB, nothing to pay for except the model call.
- **Answers:** Grok (`grok-4.20-0309-non-reasoning`) via the xAI API, given only the retrieved chunks.
- **Stack:** Python 3.10+ standard library only (`http.server`, `sqlite3`, `urllib`). No dependencies.

## What it's good for

- **Which syscall does X?** "Which syscall creates a pipe with flags?" gives `pipe2`, its x86_64 number from `syscall_64.tbl`, and `do_pipe2` in `fs/pipe.c`.
- **What does this flag do?** `EPOLLEXCLUSIVE`, `MAP_POPULATE`, `O_TMPFILE`, `SO_REUSEPORT`, `MSG_ZEROCOPY`.
- **Explain a kernel panic:** upload the oops text and ask "explain this panic". It pulls the matching mm/fault code and the docs on taint flags and KASAN.
- **Why is nginx returning 502?** (admin) Searches this server's live, redacted nginx configs, error/access logs and journal.
- **Where in the kernel does X happen?** "Where does execve copy argv?", "How does the OOM killer pick a victim?"
- **What failed on the server last night?** (admin) Searches journal warnings, failed units and the kernel log.
- **What does this /proc or /sys field mean?** "What does Dirty in /proc/meminfo mean?", "How do I read /proc/pressure/memory?", "What does vm.swappiness do?" Each answer puts a real sample of the file next to the proc(5) page or kernel doc section that explains it.
- **What is this server actually set to?** (admin) "Is THP enabled on prod?", "What's net.core.somaxconn here?", "Which sysctl.d files override defaults?" These are answered from a live, redacted read of the server's own /proc, /sys and /etc at ask time (hourly index as fallback).
- **Read your own config or log:** upload a systemd unit or nginx conf and ask what it does or why it breaks.

## Corpora

| corpus | source | granularity | size |
|---|---|---|---|
| `man` | man-pages project, sections 2, 3, 4, 5, 7, 8 (+2const/2type/3const/3type/3head) | one man page section | 11.8k chunks, 14 MB |
| `kdocs` | kernel `Documentation/**/*.rst` (no translations) | rst section | 28.7k chunks, 57 MB |
| `src` | kernel `include/uapi`, `kernel/`, `mm/`, `net/core`, `fs/*.c` + `fs/{proc,notify,iomap,kernfs,ramfs}`, `arch/x86/entry` (incl. syscall tables), `include/linux/syscalls.h` | one function, or a ~60-line region of structs/macros | 47.7k chunks, 66 MB |
| `sys` | sample snapshot of ~55 /proc, /sys and /etc files from a Linux 6.12 box (`samples/sys_snapshot.json`, redacted, reviewable in git), each tagged with its man page and kernel doc | one file, or one sysctl subtree (`vm.*`, `net.ipv4.*`, ...) | 67 chunks, 0.2 MB |
| `prod` (admin only) | this server's nginx configs, systemd units, nginx error/access log tails, journal warnings, kernel log, syslog tail, plus the same /proc, /sys, /etc snapshot, collected hourly | 60–80 lines | ~590 chunks, 2.3 MB |
| `live` (admin only) | the same allowlist, read from this server at ask time, redacted, BM25-ranked in memory (cached ~30s). Hourly `prod` is the fallback if the live helper is down | 60–80 lines | in memory |
| uploads | your text files, max 3 × 1 MB, per session | 50 lines | in memory |

`kdocs` also includes `Documentation/ABI` (one chunk per sysfs/procfs attribute). When a snapshot chunk matches, retrieval adds the matching section of its man page and kernel doc (the `Docs:` line on each snapshot) to the context.

The public indexes add up to about 145 MB on disk. The kernel sparse checkout is about 180 MB and man-pages about 21 MB.

## Privacy and safety

- **Redaction:** `prod` text passes through `rag/redact.py` before anything is written to disk (tests: `tests/test_redact.py`). It removes IPv4/IPv6/MAC addresses, emails, secrets in `key=value` / `KEY: value` / JSON form (password, token, secret, api key, cookie, session, ...), sensitive query parameters, `user:pass@` URLs, Authorization/Cookie headers, Bearer tokens, PEM and SSH keys, JWTs, and GitHub/xAI/Stripe/AWS/Slack/Google tokens. It also removes long hex and base64 blobs. In access logs, user agents become a coarse class (`UA:bot(curlbot)`, `UA:mobile-browser`) and referer query strings are dropped.
- **Files that are never read:** the collectors list files first and drop anything matching the denylist before opening it: `*.env`, keys, certs, `letsencrypt`, `htpasswd`, `shadow`/`gshadow`, `sudoers`, SSH host keys, `authorized_keys`, `/proc/<pid>/{environ,cmdline,mem,fd}`, and anything named secret/credential/password/token.
- **Snapshots:** `/etc/passwd` and `/etc/group` keep system accounts only, and group member lists are emptied. The public sample keeps only the distro's static ids (< 100). `/proc/net/tcp` addresses are masked. The public sample also replaces the box's hostname.
- **`prod` / `live` access:** results come back only for a session that logged in with the admin password. Everyone else never searches the prod index or triggers a live read. Live sources are labeled with the read time. Denylisted paths are never opened; text is redacted before it is ranked or sent to the model.
- **Uploads:** stored in an in-memory SQLite database per session. Nobody else can see them, and they're dropped when the session idles out (2 h).
- **Limits:** 40 requests/min per IP on every endpoint, 5 login attempts/min, 10 uploads/min, 20 questions/day per IP and 400/day overall. Each answer gets ~14k characters of context and 700 max tokens.
- **Untrusted text:** the UI writes all text with `textContent` and the CSP allows no inline script. The system prompt treats sources and questions as untrusted text.

## Build and run locally

```sh
scripts/build_index.sh                              # clones linux (sparse) + man-pages into corpora/, builds data/*.db (incl. sys.db from samples/)
python3 -m rag.snapshot --local samples/sys_snapshot.json  # optional: refresh the public sample from this machine, then review the diff
python3 -m rag.collect_prod --ssh root@HOST data/prod.db   # optional: read-only ssh, redacted
export XAI_API_KEY=...  RAG_ADMIN_PASSWORD=...       # admin login needs >= 12 chars
python3 -m rag.server                                # http://127.0.0.1:8795/rag/
python3 -m unittest discover -s tests -t .           # redactor, rate limits, chunking, retrieval, server
```

Config (env): `RAG_PORT` (8795), `RAG_DATA` (./data), `RAG_MODEL`, `RAG_MAX_TOKENS` (700), `RAG_PER_IP_DAILY` (20), `RAG_GLOBAL_DAILY` (400), `RAG_REQ_PER_MIN` (40).

## Deploy (grepawk.com)

```sh
XAI_API_KEY=... deploy/deploy.sh root@64.23.239.208
```

What it does (idempotent):
1. Runs the tests and rsyncs the code to `/opt/linux-rag`.
2. Creates the `linux-rag` system user, `/var/lib/linux-rag` (data, 0750) and `/etc/linux-rag/secrets` (root:root 0600).
3. Generates `RAG_ADMIN_PASSWORD` into `/etc/linux-rag/secrets` if it isn't there yet, without printing it. If the server has no `XAI_API_KEY`, it writes yours there, sent over ssh stdin.
4. Builds the public indexes on the server as `linux-rag`.
5. Installs `linux-rag.service` (127.0.0.1:8795), `linux-rag-live.service` (root helper: redacted live reads over a unix socket at ask time), plus `linux-rag-collect.service` and an hourly `.timer` that rebuilds the admin index as root (read-only, redacted).
6. Restarts the service and checks `/rag/api/health`.

nginx: the `/rag/` location lives in finalcut's `nginx/finalcut-site.conf`, installed by finalcut's deploy. Deploy this service before that route goes live.

To read the admin password on the server: `grep RAG_ADMIN_PASSWORD /etc/linux-rag/secrets` (root only).
