# Trapdoor-free scaling: head-to-head comparison

> **Historical / iteration note (2026-06-11).** This document is part of the research/design trail and reflects an **earlier iteration**; some counts, status labels, and construction details predate the current Construction F. The authoritative current specification is **`docs/30`**, the verification status and tallies are in **`docs/31`** and reproducible via **`formal/count-artifacts.sh`** (29 artifacts, 134 lemmas, 33/33 genuineness, 6 Gobra), and the cross-document reconciliation is **`docs/35`**. Numbers below are preserved as the historical record.

All options here are **trapdoor-free and transparent** (no CRS, no toxic waste, no
secret-holder) and **zero-leakage** (Model-1 rejection or a ZK proof) — so the comparison is
purely on *size / verifier / cohort / coordination / cost*, not on trust. Numbers are
labeled **[measured]** (run in this repo), **[cited]** (primary source), or **[estimate]**
(reasoned, unbuilt — flagged, never fabricated).

## The four approaches
- **(0) Naive concat** — baseline: send all N signatures.
- **(A) Tiling** — `⌈N/k⌉` independent zero-leakage Model-1 aggregates (`prototype/mladsa_tiling.py`).
- **(B) Multi-nonce 2-round multisig** — MuSig-L / DualMS / Toothpicks-class: rejection-free
  multi-nonce so cohort `k` per aggregate scales without the `exp(-n)` abort.
- **(C) Transparent proof** — hash-based STARK or Module-SIS LaBRADOR proving "I know N valid
  ML-DSA-87 signatures."

## Comparison

| axis | (0) concat | (A) tiling | (B) rejection-free multi-nonce | (C) transparent proof |
|---|---|---|---|---|
| aggregate size (N sigs) | `N·4627 B` | `⌈N/k⌉·4627 B` | `⌈N/k⌉·4627 B` (1 sig / k-cohort) | ~const/polylog in N |
| concrete size | 4627·N | **[measured]** below | k≈thousands ⇒ ~`N/k` sigs **[measured]** | ~100–300 KB total **[est]**, Falcon=73 KB@1024 **[cited]** |
| verifier | exact FIPS-204 | **exact FIPS-204** | **exact FIPS-204** (pqcrypto-verified) | custom **transparent** verifier (NOT FIPS-204) |
| cohort per aggregate | 1 | k≈4 (perfect-zero leak) | k≈thousands (k=128 demo'd) | unbounded |
| keys | independent ρ ok | **shared ρ** | **shared ρ** | **independent ρ ok** |
| coordination at signing | none | 2 rounds/tile (preproc→1) | 2 rounds | **none (public, post-hoc)** |
| messages | arbitrary | common per tile | common per cohort | **arbitrary** |
| leakage | zero | **zero** (Model 1) | **negligible** (~2⁻¹²⁸, not bit-zero) | zero (ZK optional) |
| verify cost | N·(1 verify) | `⌈N/k⌉`·(1 verify) | `⌈N/k⌉`·(1 verify) | 1 proof verify (heavier) |
| maturity | trivial | **working, pqcrypto-verified** | **working, pqcrypto-verified** | real build (months) |
| status | — | **[measured]** | **[measured]** (full concurrent-security proof = build) | **[estimate/cited]** |

## The decision the table makes explicit
Two clusters, and the split is exactly *exact-verifier vs public-non-interactive*:

- **(A)/(B) — exact-or-near-exact ML-DSA verifier**, but require **shared ρ + signing-time
  coordination + common message per cohort**, and size shrinks only by the per-cohort factor
  `k` (A: k≈4 today; B: k≈hundreds). Best when the cohort is a known, coordinating set
  signing the same thing — i.e. **validators/consensus**.
- **(C) — the only one that does public, non-interactive aggregation of arbitrary,
  independent, distinct-key/message signatures** (no shared ρ, no coordination, unbounded N)
  — i.e. the original "BLS-like" dream — at the cost of a **custom (but transparent)
  verifier** and a larger, costlier-to-verify proof. Best for **arbitrary user transactions**.

So, trapdoor-free, the design isn't "pick the winner" — it's **two products for two
workloads**: (A)/(B) for the validator layer (exact verifier), (C) for the tx layer
(public aggregation). QRL can ship both; they share the byte-exact ML-DSA-87 core already built.

## Cited / estimated bases (so estimates are auditable)
- LaBRADOR: **58 KB for 2²⁰ R1CS constraints** [cited, eprint 2022/1341]; Greyhound PCS
  `O(√N)` verifier [cited, 2024/1293].
- Falcon+LaBRADOR aggregate: **73 KB @ 1024 sigs, 0.6 s prover; 72 KB @ 100k** [cited, LaZer
  CCS 2024]. ML-DSA's FSwA verify circuit (UseHint/norm/SampleInBall/SHAKE) is **heavier**
  than Falcon's Gaussian-norm check ⇒ (C) for ML-DSA is **estimated** larger (~100–300 KB),
  no published ML-DSA number exists [docs/02 caveat].
- Chipmunk lattice multisig: **118 KB @ 1024** [cited] — a (hash-based) point of reference
  for (B)-class.
- (A) tiling and the brute-force cohort cap k≈4: **[measured]** in this repo.

## Measured tiling result (`prototype/mladsa_tiling.py`)
```
N=12 signers, tile k=4 (zero-leakage Model 1):
  3 tiles, every tile accepted by pqcrypto.ml_dsa_87.verify (and our verifier)
  aggregate bytes = 13881  vs naive 55524  =>  4.0x compression
  trapdoor-free, transparent, setup-free; zero leakage; EXACT FIPS-204 verifier
```
So tiling gives exactly `k`-fold compression (k=4 here, brute-force limit) with the
unmodified verifier. Lifting `k` to hundreds (option B) turns this into ~hundred-fold
compression with the same structure and trust model.

## Measured (B) — rejection-free wide-mask (`prototype/mladsa_multinonce.py`, `mladsa_rejfree.py`)
Rejection-free avoids the `exp(-n)` abort (so `k` scales) by using wide masks; the price is
leakage that is **negligible, not bit-zero**. Two measured facts:

1. **Leakage → noise floor as σ grows** (TV of `z*` cond. on `c`, floor ≈0.014):
   `σ=1β:0.068`, `σ=2β:0.035`, `σ=4β:0.019`, `σ=8β:0.013`, `σ=12β:0.016`, `σ=16β:0.011`
   ⇒ σ ≳ 4–12·β gives negligible (floor-level) leakage.
2. **`‖z*‖∞` stays in the EXACT `γ1−β` box at σ=12β**: k=64→5.3%, 256→10.9%, 1024→21.1%,
   4096→43.3% of budget ⇒ exact verifier holds to ~k=20000.
3. **End-to-end**: rejection-free aggregates for **k=8,16,64,128** are accepted by
   `pqcrypto.ml_dsa_87.verify` (2592 B / 4627 B, trapdoor-free).

**The decision this forces (yours to make):**
- **Perfect-zero leakage** (= ML-DSA's bit-exact ZK) ⇒ rejection ⇒ k≈4 (tiling).
- **Negligible leakage** (≈2⁻¹²⁸, standard "secure"; ML-DSA already carries negligible
  slack in its MLWE/QROM bounds) ⇒ rejection-free ⇒ k≈thousands, **exact verifier**,
  trapdoor-free.

Honest caveats on (B): the *deciding tradeoff* (leakage/norm/end-to-end verify) is measured;
the full MuSig-L-class **2-round concurrent-security protocol** (multi-nonce commitments) and
its formal Rényi bound over the whole vector and Q queries are not yet built — σ may need a
mild `√(log Q)` bump for many signatures. So: the construction is demonstrated; the security
*proof* is the remaining work.

## Build order to turn estimates into measurements
1. **(A) tiling** — done/measured (this doc).
2. **(B) multi-nonce multisig** — implement a MuSig-L/DualMS-class round on the byte-exact
   core; measure the real `k` and whether the output stays FIPS-204-exact. Biggest
   exact-verifier win.
3. **(C) transparent proof** — arithmetize ML-DSA-87 verify into LaBRADOR (Module-SIS) or a
   STARK; measure the real ML-DSA proof size/verify cost (the missing number in the field).
