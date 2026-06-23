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
NO_MKDOCS_2_WARNING=true mkdocs serve     # the env var silences Material's "MkDocs 2.0" advisory banner
```

Pushing to `main` builds and deploys via GitHub Actions (`.github/workflows/deploy.yml`).

> **Tooling note.** Pinned to **mkdocs 1.6.1 + mkdocs-material 9.7.6** (the latest supported line on PyPI —
> there is no usable MkDocs/Material 2.0 to upgrade to). The build prints a Material advisory *against* a
> future/hostile "MkDocs 2.0" that would remove the plugin system Material depends on; we suppress it with the
> official `NO_MKDOCS_2_WARNING=true` env var (set in CI; prepend it to local `mkdocs` commands as above).
