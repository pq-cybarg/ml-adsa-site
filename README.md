# ML-ADSA — project site

Source for the public documentation site at
**https://pq-cybarg.github.io/ml-adsa-site/**, built with
[MkDocs Material](https://squidfunk.github.io/mkdocs-material/).

ML-ADSA is a trapdoor-free, post-quantum, BLS-like aggregate signature over ML-DSA-87 (FIPS-204),
machine-checked in EasyCrypt, Coq, and Gobra. This repository contains only the published
documentation; it is a defensive publication and independent cryptanalysis is invited.

## Local preview

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
mkdocs serve
```

Pushing to `main` builds and deploys via GitHub Actions (`.github/workflows/deploy.yml`).
