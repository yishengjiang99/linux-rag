#!/usr/bin/env bash
# Fetch public corpora and build data/{man,kdocs,src}.db + data/meta.json.
#   scripts/build_index.sh [CORPORA_DIR] [DATA_DIR]
# If a fetch fails, the existing checkout is used with a WARNING on stderr; with no usable
# checkout the script exits non-zero.
set -euo pipefail

warn() { echo "WARNING: $*" >&2; }
die() { echo "ERROR: $*" >&2; exit 1; }

# update_checkout DIR NEEDED_PATH: fetch the remote tip (depth 1) and check it out; on failure
# keep the current checkout, loudly. Fails if there is no commit or NEEDED_PATH is missing.
update_checkout() {
  local dir="$1" need="$2" old
  old="$(git -C "$dir" rev-parse -q --verify HEAD 2>/dev/null)" || die "$dir has no commit; delete it and rerun to clone again"
  if git -C "$dir" fetch -q --depth 1 origin HEAD && git -C "$dir" checkout -q --detach FETCH_HEAD; then
    echo "$dir: $(git -C "$dir" rev-parse --short HEAD)"
  else
    warn "fetch failed for $dir; building from the existing checkout $(git -C "$dir" rev-parse --short "$old")"
  fi
  [[ -e "$dir/$need" ]] || die "$dir/$need is missing; checkout is unusable"
}

main() {
  cd "$(dirname "$0")/.."
  local corpora="${1:-corpora}" data="${2:-data}"
  mkdir -p "$corpora" "$data"

  if [[ ! -d "$corpora/linux/.git" ]]; then
    git clone --depth 1 --filter=blob:none --sparse https://github.com/torvalds/linux.git "$corpora/linux"
  fi
  git -C "$corpora/linux" sparse-checkout set Documentation include/uapi kernel fs mm net/core arch/x86/entry
  update_checkout "$corpora/linux" fs/pipe.c
  mkdir -p "$corpora/linux/extra"
  git -C "$corpora/linux" show HEAD:include/linux/syscalls.h > "$corpora/linux/extra/syscalls.h"

  if [[ ! -d "$corpora/man-pages/.git" ]]; then
    git clone --depth 1 https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git "$corpora/man-pages"
  fi
  update_checkout "$corpora/man-pages" man/man2/pipe.2

  python3 -m rag.index man "$corpora/man-pages" "$data/man.db"
  python3 -m rag.index kdocs "$corpora/linux" "$data/kdocs.db"
  python3 -m rag.index src "$corpora/linux" "$data/src.db"

  cat > "$data/meta.json" <<JSON
{"linux_commit": "$(git -C "$corpora/linux" rev-parse HEAD)",
 "man_pages_commit": "$(git -C "$corpora/man-pages" rev-parse HEAD)",
 "built": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
JSON
  du -h "$data"/*.db
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
