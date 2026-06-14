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

# the research paper is BOTH readable (this page) and downloadable (PDF). Refresh the PDF from the
# source build and prepend a download banner to the rendered page (re-applied on every sync).
if [[ -x "$SRC/paper/eprint/build.sh" ]]; then
  TZ=UTC0 SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1700000000}" "$SRC/paper/eprint/build.sh" >/dev/null 2>&1 || true
fi
if [[ -f "$SRC/paper/eprint/ml-adsa.pdf" ]]; then
  cp -f "$SRC/paper/eprint/ml-adsa.pdf" "$REF/ml-adsa.pdf"
fi
banner=$'!!! note "Research paper"\n    [**Download the full paper (PDF)**](ml-adsa.pdf){ .md-button .md-button--primary } &nbsp; The complete paper is reproduced, readable, below.\n\n'
printf '%s' "$banner" | cat - "$REF/paper.md" > "$REF/paper.md.tmp" && mv "$REF/paper.md.tmp" "$REF/paper.md"

echo "synced $n files into $REF"
echo "reminder: counts on the landing page (docs/index.md) are maintained by hand —"
echo "verify them against: (cd $SRC/formal && zsh count-artifacts.sh)"
