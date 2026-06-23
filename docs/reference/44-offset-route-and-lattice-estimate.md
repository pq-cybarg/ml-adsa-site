# Option C — the offset / RLWE-phase route, and the decisive lattice estimate

**Status: leading concrete candidate (no setup). The decisive lattice estimate (#99) has now been RUN and comes
back FAVORABLE (offset ≥ native in a wide window) — pending Sage/dual-attack confirmation.** Companion to
[docs/43](43-aggregate-nonce-hiding-catalog.md) and the verified-claims ledger [docs/46](46-findings-ledger.md).
This unifies tasks #82/#83/#93/#95.

## #99 RESULT (estimator99.py, self-validating; ledger F7/I5) — supersedes the "easier-than-native" analysis below

The instance is `b = M·s1 + e` (M=A·c, secret s1∈{−2..2}, error e~±R), recover s1. The estimator **asserts** it
reproduces published core-SVP (Kyber-512=118.6, -768=181.9, -1024=254.9, ML-DSA-87=252.0) before reporting:

| instance | classical core-SVP | quantum |
|---|---|---|
| **native ML-DSA-87 MLWE** (bar) | **252** | 229 |
| offset R=2¹ | 248 | 225 |
| offset R=2² | 262 | 237 |
| offset R=2⁸ | 374 | 340 |
| **offset R=2¹¹** (carry-viable) | **464** | 421 |
| offset R=2¹² (carry-viable) | 502 | 455 |

**Read (Tier-2, ledger I5):** the offset instance is *harder* than native for R≥~4 and far harder in the
carry-viable window. The attacker's *combined* view (native key `t` + offset `b`) is no easier than native
because extra same/higher-noise samples don't lower β (native β is flat from m=2048→8192). So **req G (≥ native)
holds for R ∈ [~4, 2¹²]** — the carry caps the top (R≤2¹², 60 misses ≤ ω), and ≥-native caps the bottom (R≥~4).
A wide window. **This OVERTURNS the "tax / easier-than-native" analysis that previously appeared below.**
**Caveats (do not declare victory):** core-SVP **primal only** — the **dual/kernel attack** and hybrid are not
yet run (need the real Sage estimator); module modelled as plain LWE; pin the `A`-conditioning so the deployed
published quantity matches `b=M·s1+e`.

### CONFIRMED by the REAL lattice-estimator (Sage 10.7, full attack suite) — ledger F10

The caveats above are now **resolved**. Albrecht et al.'s `lattice-estimator` run (usvp/bdd/bdd_hybrid/
bdd_mitm_hybrid/dual/dual_hybrid/bkw) gives:

| instance | best bits | best attack |
|---|---|---|
| native ML-DSA-87 MLWE | **267** | dual_hybrid |
| offset R=2¹¹ | **455** | dual_hybrid |
| offset R=2¹² | **489** | dual_hybrid |
| aggregate native | 367 | bdd |
| aggregate offset R=2¹¹ / 2¹² | 867 / 938 | bdd |

The **best attack is dual_hybrid for both native and offset**, so the dual/kernel/hybrid concern is met head-on
and offset still beats native by **+188/+222 bits**. Pure-Python core-SVP (464 @R=2¹¹) agrees with the real
dual_hybrid (455). The `A`-conditioning caveat is independently closed by the model-pin test (`TestTask109`,
ledger F8). What remains is purely engineering: wire the offset mechanism (#95) and the forward-secret refresh
ratchet (#101, built) as modelled.

---

### ⚠️ The analysis below is SUPERSEDED by the #99 result above (kept for the record / reasoning trail)

## The route (unified)

Replace "publish full `wᵢ`" (leaks `y`) with: each signer publishes `HighBits(wᵢ)` + a **noised low part**
`qᵢ = LowBits(wᵢ) + rᵢ`, where `rᵢ` is a **secret, independent** small offset (`~±R`) **tolerated as noise,
never subtracted**. Then:

- **No setup / no shared secret / no combiner / non-interactive / multi-attempt-safe** (fresh `wᵢ` and `rᵢ`
  per content ⇒ no accumulation).
- The cohort forms the (standard) challenge over `HighBits(W*)`, recovering the **aggregate carry** from
  `Σqᵢ = Σ LowBits + Σrᵢ`, tolerating `Σr` as noise → sparse misses (`≤ω`) bridged by the hint. **Byte-exact-
  compatible** (standard challenge), so it composes with plain ML-DSA sigs and aggregates.
- **Hiding is RLWE-computational** — exactly the *kind* of security native ML-DSA already relies on (not a new
  trust model). The noised low part is an RLWE sample (the "PQ lattice phase" of #93; `rᵢ` = its small error).
  "Partial-readability": the coarse aggregate carry survives the noise; the fine `s1` stays hidden.

**Measured viable window** (`option_c_95_offset_test.go`, n=64): `R=2¹¹` → 27/2048 misses (≤ω), `w0` hidden to
`17β`; `R=2¹²` → 60 misses, `34β`. `R` is a **security knob**, tunable up to the `≤ω`-miss ceiling.

## The decisive instance (run this on the lattice estimator)

Per response polynomial `ℓ ∈ [L]`, an adversary that sees `HighBits(wᵢ)`, `qᵢ`, and `zᵢ` knows `wᵢ` (hence
`yᵢ`) only to `±R`, so it faces — to recover the secret `s1ℓ`:

> **Recover `s1 ∈ {−η,…,η}^N` (η=2, N=256) from a single Ring-LWE sample `o = c·s1 + δ` over
> `R_q = Z_q[x]/(x^N+1)`, `q = 8 380 417` (`≈2^23`), `c = SampleInBall` (fixed, weight τ=60, coeffs ∈{−1,0,1}),
> error `δ` ≈ uniform/Gaussian of width `R` (e.g. `R = 2^11…2^13`), with `m = 1` ring sample (≈ N scalar samples).**

Estimator settings to report: primal-uSVP and dual bit-security vs ML-DSA-87's own MLWE/SelfTargetMSIS level
(target ≥ Cat-5). Sweep `R ∈ {2^10,2^11,2^12,2^13}` (the carry-miss budget allows up to ~`2^12`–`2^13` at n≤64;
re-derive the ceiling per parameter set from `ω` and cohort size). **The bar is met iff the recovered
bit-security is ≥ native ML-DSA at the chosen `R`.**

## Honest analysis (CORRECTED — earlier draft had the wrong baseline)

**Baseline correction.** The right native comparison is *not* ML-DSA's secret-error `η=2`. It is how well
native hides the **nonce**: a native signature exposes `HighBits(w)` (`w` to `±α/2 ≈ 2¹⁸`) + `z`, so native's
`y`-uncertainty is `±α/2`. The offset route reveals `w` to `±R` with **`R ≪ α/2`** (forced — larger `R`
destroys the carry). So the offset LWE has **smaller error than native ⇒ EASIER than native, not harder.**
My earlier "`R≫η` ⇒ harder" was the wrong comparison.

**Two bar readings, two verdicts:**
- **Strict "≥ native exactly":** the offset route **fails** — revealing low bits to `≪α` is strictly more than
  native (which reveals nothing below `α`). Only *reveal-only-the-carry* routes (threshold / one-way #88) can
  meet strict-≥-native.
- **"Maintain Cat-5 / ≥128-bit absolute":** the attainable bar — *is the error-`R` LWE still ≥128 bits?* This
  is the estimator question (the estimator IS needed; but the claim is ≥Cat-5-absolute, NOT ≥native).

**"Valid LWE on a remappable lattice" (the design lever).** The offset is a *valid* LWE, and the lattice is a
free parameter — absolute hardness at fixed `R` depends on *which* lattice it lives on. Frame it as
**Module-LWE on `A`** (ML-DSA's own lattice, dim `L·N=1792`, `K·N=2048` samples) — NOT the `L` isolated
single-ring samples of the earlier draft. Levers to push the error-`R` instance to ≥128: (i) full Module-LWE
dimension on `A`; (ii) Gaussian/structured error shaping; (iii) a remapped basis where `R` sits in the
lattice's hard regime. **Design target: maximize absolute hardness at the largest `R` the `≤ω` carry-budget
allows.** The decisive computation is the estimator on the **Module-LWE-on-`A`, error `R`** instance — not the
single-sample Ring-LWE first written here.

## Differential-privacy footing (task #103) — CORRECTED: sensitivity verified, ε is conditional (NOT proven)

> **Correction (docs/46 ledger).** An earlier version of this section claimed a "provable (ε≈0.78)-DP bound."
> That overstated it. What is **machine-verified** (Tier-1, `option_c_103_dp_test.go`,
> `TestTask103_DPSensitivity`) is only the **L2-sensitivity Δ₂≈429.7** (≤ Young bound 3840, τ=60). The ε values
> below are the **Gaussian-mechanism formula**, which is **NOT satisfied by the deployed mechanism**: #95 uses
> **uniform** offsets (not Gaussian), and the noise σ on `o` is not pinned to `R` (the `A`-conditioning gap). So
> ε here is a **conditional reference, not a guarantee.**

**Tier-1 (verified):** Δ₂ (full-secret neighbor `v=all+2η`) = 429.7; respects Young's convolution bound;
per-coefficient neighbor sensitivity is strictly smaller.

**Tier-2 (conditional reference — assumes Gaussian offsets σ=R, which the current scheme does NOT use):**

| R | ε_ref (full-secret, Gaussian-mech, δ=2⁻⁴⁰) | ε_ref (per-coeff) |
|---|---|---|
| 2¹¹ | 1.57 | 0.113 |
| 2¹² | 0.78 | 0.057 |
| 2¹³ | 0.39 | 0.028 |

To make any of these a *real* bound requires: (1) switch #95 to **discrete-Gaussian** offsets; (2) pin the
`q→y→o` noise propagation (the `A`-conditioning factor) so σ is justified. Until then, DP is **not** an
established footing for this route — the lattice estimator (#99) remains the decisive, separate gate. (Carry-miss
counts for the offset mechanism are measured in `option_c_95_offset_test.go`, not here.)

## This is NOT the sole route (breadth)

Independent routes with a *different* security basis stay open (do not collapse the search):
- **#73/#74 registration-setup / PQ-NIKE** — EC→lattice transform of BLS-style aggregation; reveal only
  `HighBits(W*)` via registration-derived correlated randomness → meets the bar **by construction** (not
  estimator-gated). The open piece is a practical PQ-NIKE or a one-time registration KEM.
- **#84 untried transforms** (mixed-radix/CRT, `A`-structure), **#79 full-set-only encodings**, **#88 one-way
  structure**.

The offset/RLWE route is the leading *concrete, no-setup* candidate; the estimator is its single decisive gate;
the registration-setup route is the leading *meets-by-construction* alternative. Push both.
