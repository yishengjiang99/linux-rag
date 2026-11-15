#!/usr/bin/env bash
# Deploy linux-rag to the grepawk.com server. Run from a checkout on a machine with root ssh.
#   deploy/deploy.sh root@64.23.239.208
# Idempotent. Creates nothing outside /opt/linux-rag, /var/lib/linux-rag, /etc/linux-rag and
# three systemd units. Never prints secrets. If XAI_API_KEY is set in your shell and the
# server has none, it is sent over ssh stdin (never argv) into /etc/linux-rag/secrets.
set -euo pipefail
TARGET="${1:?usage: deploy/deploy.sh user@host}"
cd "$(dirname "$0")/.."

python3 -m unittest discover -s tests -t . >/dev/null

rsync -az --exclude .git --exclude data --exclude corpora --exclude '__pycache__' ./ "$TARGET:/opt/linux-rag/"

ssh "$TARGET" bash -s <<'REMOTE'
set -euo pipefail
id linux-rag >/dev/null 2>&1 || useradd --system --home /var/lib/linux-rag --shell /usr/sbin/nologin linux-rag
install -d -m 755 -o root -g root /opt/linux-rag
install -d -m 750 -o linux-rag -g linux-rag /var/lib/linux-rag
install -d -m 700 -o root -g root /etc/linux-rag
touch /etc/linux-rag/secrets
chmod 600 /etc/linux-rag/secrets
chown root:root /etc/linux-rag/secrets
if ! grep -q '^RAG_ADMIN_PASSWORD=' /etc/linux-rag/secrets; then
  echo "RAG_ADMIN_PASSWORD=$(openssl rand -base64 30 | tr -dc 'A-Za-z0-9' | head -c 32)" >> /etc/linux-rag/secrets
  echo "generated admin password in /etc/linux-rag/secrets"
fi
REMOTE

if [[ -n "${XAI_API_KEY:-}" ]]; then
  printf '%s' "$XAI_API_KEY" | ssh "$TARGET" 'grep -q "^XAI_API_KEY=" /etc/linux-rag/secrets || { printf "XAI_API_KEY=%s\n" "$(cat)" >> /etc/linux-rag/secrets; echo "stored XAI_API_KEY"; }'
fi

ssh "$TARGET" bash -s <<'REMOTE'
set -euo pipefail
grep -q '^XAI_API_KEY=' /etc/linux-rag/secrets || { echo "XAI_API_KEY missing in /etc/linux-rag/secrets" >&2; exit 1; }
cd /opt/linux-rag
# public indexes (kernel + man-pages clones live in /var/lib/linux-rag/corpora)
runuser -u linux-rag -- env PYTHONDONTWRITEBYTECODE=1 scripts/build_index.sh /var/lib/linux-rag/corpora /var/lib/linux-rag
cp deploy/linux-rag.service deploy/linux-rag-collect.service deploy/linux-rag-collect.timer /etc/systemd/system/
systemctl daemon-reload
systemctl start linux-rag-collect.service   # admin index (root, read-only, redacted)
systemctl enable --now linux-rag-collect.timer
systemctl enable linux-rag.service
systemctl restart linux-rag.service
for i in $(seq 1 20); do
  curl -fsS http://127.0.0.1:8795/rag/api/health && echo && exit 0
  sleep 1
done
echo "linux-rag did not become healthy" >&2
journalctl -u linux-rag -n 30 --no-pager >&2
exit 1
REMOTE
