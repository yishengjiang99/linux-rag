#!/usr/bin/env bash
# Fetch public corpora and build data/{man,kdocs,src}.db + data/meta.json.
#   scripts/build_index.sh [CORPORA_DIR] [DATA_DIR]
set -euo pipefail
cd "$(dirname "$0")/.."
CORPORA="${1:-corpora}"
DATA="${2:-data}"
mkdir -p "$CORPORA" "$DATA"

if [[ ! -d "$CORPORA/linux/.git" ]]; then
  git clone --depth 1 --filter=blob:none --sparse https://github.com/torvalds/linux.git "$CORPORA/linux"
fi
git -C "$CORPORA/linux" sparse-checkout set Documentation include/uapi kernel fs mm net/core arch/x86/entry
git -C "$CORPORA/linux" pull --ff-only --depth 1 -q || true
mkdir -p "$CORPORA/linux/extra"
git -C "$CORPORA/linux" show HEAD:include/linux/syscalls.h > "$CORPORA/linux/extra/syscalls.h"

if [[ ! -d "$CORPORA/man-pages/.git" ]]; then
  git clone --depth 1 https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git "$CORPORA/man-pages"
fi
git -C "$CORPORA/man-pages" pull --ff-only --depth 1 -q || true

python3 -m rag.index man "$CORPORA/man-pages" "$DATA/man.db"
python3 -m rag.index kdocs "$CORPORA/linux" "$DATA/kdocs.db"
python3 -m rag.index src "$CORPORA/linux" "$DATA/src.db"

cat > "$DATA/meta.json" <<JSON
{"linux_commit": "$(git -C "$CORPORA/linux" rev-parse HEAD)",
 "man_pages_commit": "$(git -C "$CORPORA/man-pages" rev-parse HEAD)",
 "built": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
JSON
du -h "$DATA"/*.db
