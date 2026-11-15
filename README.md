# Linux RAG

Ask questions about Linux and get answers that cite the man page, kernel doc or source lines they came from. Live at https://grepawk.com/rag.

- **Retrieval:** SQLite FTS5 with BM25. No embeddings, no vector DB, nothing to pay for except the model call.
- **Answers:** Grok (`grok-4.20-0309-non-reasoning`) via the xAI API, given only the retrieved chunks.
- **Stack:** Python 3.10+ standard library only (`http.server`, `sqlite3`, `urllib`). No dependencies.

## What it's good for

- **Which syscall does X?** "Which syscall creates a pipe with flags?" gives `pipe2`, its x86_64 number from `syscall_64.tbl`, and `do_pipe2` in `fs/pipe.c`.
- **What does this flag do?** `EPOLLEXCLUSIVE`, `MAP_POPULATE`, `O_TMPFILE`, `SO_REUSEPORT`, `MSG_ZEROCOPY`.
- **Explain a kernel panic:** upload the oops text and ask "explain this panic". It pulls the matching mm/fault code and the docs on taint flags and KASAN.
- **Why is nginx returning 502?** (admin) Searches this server's redacted nginx configs, error/access logs and journal.
- **Where in the kernel does X happen?** "Where does execve copy argv?", "How does the OOM killer pick a victim?"
- **What failed on the server last night?** (admin) Searches journal warnings, failed units and the kernel log.
- **Read your own config or log:** upload a systemd unit or nginx conf and ask what it does or why it breaks.

## Corpora

| corpus | source | granularity | size |
|---|---|---|---|
| `man` | man-pages project, sections 2, 3, 4, 5, 7, 8 (+2const/2type/3const/3type/3head) | one man page section | 11.8k chunks, 14 MB |
| `kdocs` | kernel `Documentation/**/*.rst` (no translations) | rst section | 28.7k chunks, 57 MB |
| `src` | kernel `include/uapi`, `kernel/`, `mm/`, `net/core`, `fs/*.c` + `fs/{proc,notify,iomap,kernfs,ramfs}`, `arch/x86/entry` (incl. syscall tables), `include/linux/syscalls.h` | one function, or a ~60-line region of structs/macros | 47.7k chunks, 66 MB |
| `prod` (admin only) | this server's nginx configs, systemd units, nginx error/access log tails, journal warnings, kernel log, syslog tail | 60–80 lines | ~500 chunks, 2 MB |
| uploads | your text files, max 3 × 1 MB, per session | 50 lines | in memory |

The public indexes add up to about 140 MB on disk. The kernel sparse checkout is about 180 MB and man-pages about 21 MB.

## Privacy and safety

- **Redaction:** `prod` text passes through `rag/redact.py` before anything is written to disk (tests: `tests/test_redact.py`). It removes IPv4/IPv6/MAC addresses, emails, secrets in `key=value` / `KEY: value` / JSON form (password, token, secret, api key, cookie, session, ...), sensitive query parameters, `user:pass@` URLs, Authorization/Cookie headers, Bearer tokens, PEM and SSH keys, JWTs, and GitHub/xAI/Stripe/AWS/Slack/Google tokens. It also removes long hex and base64 blobs. In access logs, user agents become a coarse class (`UA:bot(curlbot)`, `UA:mobile-browser`) and referer query strings are dropped.
- **Files that are never read:** the collector lists files first and drops anything matching the denylist before opening it: `*.env`, keys, certs, `letsencrypt`, `htpasswd`, anything named secret/credential/password/token.
- **`prod` access:** results come back only for a session that logged in with the admin password. Everyone else never searches that index.
- **Uploads:** stored in an in-memory SQLite database per session. Nobody else can see them, and they're dropped when the session idles out (2 h).
- **Limits:** 40 requests/min per IP on every endpoint, 5 login attempts/min, 10 uploads/min, 20 questions/day per IP and 400/day overall. Each answer gets ~14k characters of context and 700 max tokens.
- **Untrusted text:** the UI writes all text with `textContent` and the CSP allows no inline script. The system prompt treats sources and questions as untrusted text.

## Build and run locally

```sh
scripts/build_index.sh                              # clones linux (sparse) + man-pages into corpora/, builds data/*.db
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
5. Installs `linux-rag.service` (127.0.0.1:8795), plus `linux-rag-collect.service` and an hourly `.timer` that rebuilds the admin index as root (read-only, redacted).
6. Restarts the service and checks `/rag/api/health`.

nginx: the `/rag/` location lives in finalcut's `nginx/finalcut-site.conf`, installed by finalcut's deploy. Deploy this service before that route goes live.

To read the admin password on the server: `grep RAG_ADMIN_PASSWORD /etc/linux-rag/secrets` (root only).
