# MLADSA — Masking / Zero-Knowledge Analysis (the real secure-cohort limiter)

Goal: replace the earlier hand-waved "secure cohort ≈ tens / ≈ hundreds" with a precise,
*measured* statement. The headline correction: **leakage is a property of the rejection
model, not a simple ratio.** With the right model the aggregate `z*` is secret-independent
(zero leakage at any n); the practical cohort limit is then the **abort rate**, not
leakage — and that is where the known advanced techniques buy scale.

## What the verifier publishes and what must stay hidden
The aggregate signature exposes `z* = y* + c·s1*` (with `y* = Σ y_i`, `s1* = Σ s1_i`).
Zero-knowledge requires the distribution of `z*` to be independent of `s1*` (a simulator
must produce it from public data alone). Three rejection models behave very differently.

### Model 0 — single-signer Dilithium (baseline): perfect ZK
`z = y + c·s1`, `y` uniform on `(-γ1, γ1]`, accept iff `z ∈ box = [-(γ1-β), γ1-β]`. For
each coefficient the map `y ↦ z` is a bijection and `|c·s1| ≤ β`, so the accepted `z` is
**exactly uniform on the box, independent of `s1`** — statistical distance 0. The ratio
`γ1/β ≈ 4369` governs only the *abort rate* (≈ `exp(-256·β/γ1)` per poly), not leakage.

### Model 1 — per-signer rejection (the secure aggregate): zero leakage
Each signer resamples `y_i` until `z_i = y_i + c·s1_i ∈ box_i = [-(γ1'-β), γ1'-β]`. By the
Model-0 argument each `z_i` is uniform-on-`box_i` and **secret-independent**, hence
`z* = Σ z_i` is secret-independent for *every* n — perfect ZK, no leakage at any cohort
size. Cost: the `z_i` are uniform on `box_i`, so `‖z*‖∞` concentrates at `≈ √n·γ1'` (a sum
of n bounded-uniforms), and the verifier needs `‖z*‖∞ < γ1-β`. So set `γ1' ≈ (γ1-β)/(c√n)`
(c ≈ 2–3). The limiter is then the **abort rate**, see below — not leakage.

### Model 2 — reject on `z*` only (the naive aggregate): LEAKS
Sample `y* = Σ y_i` (an Irwin–Hall sum, peaked at 0, **not** uniform), `z* = y* + c·s1*`,
reject the whole thing if `‖z*‖∞ ≥ γ1-β`. Because `y*` is non-uniform, the accepted `z*`
samples different parts of the IH density depending on the shift `c·s1*`, so the accepted
`z*` **depends on the secret**. Leakage shrinks as `γ1'` grows (IH flattens over the box)
but is nonzero. This is what a naive "sum then reject" aggregate pays — and it is the model
the first end-to-end prototype (`mladsa_aggregate.py`) used for simplicity.

## Abort rate (the real cohort limiter under Model 1)
Per signer, acceptance ≈ `((γ1'-β)/γ1')^{256·ℓ} ≈ exp(-256·ℓ·β/γ1')`. If the protocol
restarts the whole cohort on any single signer's abort, joint acceptance ≈
`(per-signer)^n ≈ exp(-Θ(n))` — exponential in n. **This joint-restart is the true
bottleneck**, not leakage. Gaussian masks only improve the per-signer *constant* (≈1/M,
dimension-independent, vs uniform's dimension-degrading rate), nudging brute-force
feasibility from n≈4 to ≈8–10 — they do **not** beat `exp(-n)`.

### Trapdoors are rejected (trust-model constraint, not a technical one)
The textbook way to "decouple aborts from n" is equivocable/trapdoor commitments (commit to
`w_i`, then locally resample). **We do not use these.** A trapdoor is a structural backdoor:
its destruction is unverifiable (toxic waste), it reintroduces a coercible secret-holder,
and it contradicts trustlessness/transparency — especially off-brand for QRL. So the only
admissible ways to beat `exp(-n)` are trapdoor-free:

- **Rejection-free / multi-nonce 2-round lattice multisignatures** (MuSig-L, DualMS,
  Toothpicks): trapdoor-free by design, transparent, zero-leakage; each signer sends several
  nonce commitments and the challenge selects a combination, avoiding the abort
  amplification. The principled path to large cohorts. Caveat: making the output
  *byte-exact FIPS-204-accepted* is real engineering (parameter care), not a drop-in.
- **Tiling**: emit `⌈N/k⌉` independent zero-leakage Model-1 aggregates of small `k`. Fully
  trustless, transparent, setup-free, shippable now; size `⌈N/k⌉·4627` B (guaranteed
  compression, no new assumptions). The safe default while the multi-nonce path matures.
- **Transparent proof** (hash-based STARK or Module-SIS LaBRADOR) *iff* a single
  constant-size aggregate over a huge cohort is mandatory. These are transparent (no
  trapdoor/toxic waste) → value-consistent; the trade is not-the-exact-ML-DSA-verifier in
  exchange for trustless unbounded aggregation.

## HARD REQUIREMENT (from QRL): leakage ≤ normal ML-DSA-87 under its least-leakage paradigm
Normal ML-DSA-87's least-leakage paradigm is **perfect ZK (zero leakage)** — uniform-`y`
rejection gives statistical distance 0. So the bar is **zero leakage**, which:
- **rules out Model 2 entirely** (it leaks; non-uniform `y*`), and
- **mandates Model 1** (per-signer rejection), whose zero-leakage is the *same theorem* as
  ML-DSA's own perfect ZK applied per-signer ⇒ MLADSA leakage = ML-DSA leakage = 0.

The first end-to-end prototype used Model 2 and therefore did **not** meet this bar; it has
been replaced by `aggregate_m1` (Model 1) in `prototype/mladsa_aggregate.py`. That
zero-leakage aggregate is **accepted end-to-end by `pqcrypto.sign.ml_dsa_87.verify` for
n=2,3,4** (2592B pk / 4627B sig; tampering rejected) — i.e. a genuine, zero-leakage,
third-party-verified ML-DSA-87 aggregate at small cohort. n≥~5 is abort-limited (below).

## Certified statement
- **Leakage:** Model 1 = **zero** at any n, by ML-DSA's own perfect-ZK proof (each accepted
  `z_i` is uniform-on-box, secret-independent; sum of secret-independent is secret-
  independent). This is a proof, not a measurement. Model 2 is non-zero → disallowed.
- **Cohort:** under Model 1 the limiter is the **abort rate**. Naive joint-restart gives
  joint acceptance `≈ exp(-Θ(n))` — feasible by brute force only for n≈2–4 (≈8–10 with
  Gaussian). Larger cohorts require a **trapdoor-free** route (trapdoors are rejected on
  trust-model grounds, see below): a rejection-free multi-nonce 2-round multisignature
  (MuSig-L/DualMS/Toothpicks-class) for large `n`, or **tiling** small zero-leakage
  aggregates for guaranteed compression now, or a transparent proof if a single
  constant-size aggregate over a huge cohort is mandatory. All preserve zero leakage.
- Supersedes the earlier "ratio → leakage" framing, which wrongly conflated abort with leak.

## Measured results (`prototype/leak_test.py`) — and an honest caveat
TV distance of a fixed `z*` coefficient between two independent secrets:

| model | n | γ1' | TV(secA,secB) |
|---|---|---|---|
| per-signer (M1) | 4 | 131042 | 0.110 |
| per-signer (M1) | 8 | 92660 | 0.101 |
| per-signer (M1) | 16 | 65521 | 0.104 |
| reject-on-z* (M2) | 4 | 32760 | 0.060 |
| reject-on-z* (M2) | 8 | 23165 | 0.056 |

**This measurement is UNDERPOWERED and inconclusive.** At 2000 samples / 120 bins the
finite-sample TV noise floor is `√(bins/(π·trials)) ≈ 0.14`, which exceeds every value in
the table. So these numbers reflect sampling noise, not a leakage signal (M1's larger
support → emptier bins → higher apparent TV). The zero-leakage claim for Model 1 therefore
rests on the **proof** (= ML-DSA's perfect-ZK argument), not on this run. A conclusive
empirical check (≥10⁵ samples, ~32 bins, or a per-coefficient uniformity χ² on a single
`z_i`) is future work; it is a sanity check, not the certification.
