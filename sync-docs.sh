#!/usr/bin/env bash
# ============================================================================================
# sync-docs.sh — refresh docs/reference/ from the source repo (single, reproducible step).
#
# The public site's reference pages are CURATED COPIES of the private repo's docs/ and paper.
# They drift whenever the source is edited. Run this after any source-doc change, then
# `mkdocs build` (or push, which triggers the Pages Action). Idempotent.
#
# Usage:  ./sync-docs.sh [path-to-source-repo]
#   default source repo: ../LMSA-ML-DSA
# ============================================================================================
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${1:-$HERE/../LMSA-ML-DSA}"
REF="$HERE/docs/reference"

if [[ ! -d "$SRC/docs" ]]; then echo "source docs/ not found at $SRC/docs" >&2; exit 1; fi
mkdir -p "$REF"

n=0
# every docs/NN-*.md → reference/NN-*.md (same filename)
for f in "$SRC"/docs/*.md; do
  cp -f "$f" "$REF/$(basename "$f")"
  n=$((n+1))
done
# the research paper → reference/paper.md
cp -f "$SRC/paper/ml-adsa.md" "$REF/paper.md"; n=$((n+1))

echo "synced $n files into $REF"
echo "reminder: counts on the landing page (docs/index.md) are maintained by hand —"
echo "verify them against: (cd $SRC/formal && zsh count-artifacts.sh)"
