# Tightness-adjusted security of ML-ADSA — classical/quantum split, apples-to-apples with Fusion

**Task #131.** ML-ADSA's headline numbers (252 classical / 229 quantum) are **core-SVP of the underlying problem,
NOT tightness-adjusted**; Fusion's headline (128 base / 256 option) **is** tightness-adjusted. This document puts
both on the same footing — a classical/quantum *guaranteed-forgery* split after accounting for the reduction loss —
so the comparison is honest. Computed by `formal/tightness_adjust.py` (self-validating; reproduces published
ML-DSA core-SVP) and cross-checked against the real Sage lattice-estimator (`/tmp/hint_estimate_out.log`).

## 1. The load-bearing point: ML-ADSA's reduction is *tight*; Fusion's is not

| | ML-ADSA (F-OFFSET) | Fusion |
|---|---|---|
| Aggregate object | a **byte-exact ML-DSA signature** under `pk*=Σtᵢ` | a weighted **linear combination** `Σαᵢξᵢ`, own `AggVf` |
| Forgery extraction | native ML-DSA **SelfTargetMSIS** — **tight**, no forking (`eq_exact`/`extract_sound`, machine-checked) | **lossy** witness extractor from the linear combination |
| Signing-oracle loss | **none** — deployed key-leak model leaks the one-time key, so no HVZK simulation / no QROM reprogramming (F20/F22, machine-checked) | rejection/HVZK handled in the OTS proof |
| Net tightness loss | `adv_prf` (≈0, a 2λ-bit PRF) + multi-instance `Q` (removable by MLWE/SIS random self-reducibility) | provisions **underlying ≈ 2× the target** (e.g. ~521 → 256), i.e. loses ≈ **half the bits** |

Because ML-ADSA's aggregate *is* a native ML-DSA signature, its forgery proof inherits ML-DSA's tight
SelfTargetMSIS step, and the deployed key-leak model removes any signing-simulation loss. So **ML-ADSA's
guaranteed forgery security ≈ its underlying core-SVP**, whereas **Fusion provisions ~2× underlying** for its
guaranteed target.

## 2. Two cost models — do NOT conflate them

ML-DSA-87 has **two commonly-cited classical numbers, both correct**, under different attack-cost models:

| metric | ML-DSA-87 classical | ML-DSA-87 quantum | what it is |
|---|---|---|---|
| **core-SVP** (`0.292·b` / `0.265·b`, b=863) | **252** | **229** | the conservative lower-bound convention used for NIST category mapping; gives a clean classical/quantum split |
| **gate-count** (real lattice-estimator, `dual_hybrid` rop) | **267** | 217 (ChaLoy21 quantum sieve) | the realistic RAM/gate cost; always ≥ core-SVP |

Both describe the *same* lattice; gate-count just adds the per-BKZ-operation cost on top of the block count, so
**267 (gate-count) and 252 (core-SVP) are not in conflict** — 267 is the higher, more realistic figure;
252/229 is the conservative floor. The tightness *analysis below is identical in either model* (the reduction
loss is a number of bits subtracted from whichever underlying figure you choose).

### 2a. Split in the **core-SVP** model (conservative; clean c/q)

| Level | underlying (c / q) | **tight-adjusted (c / q)** | conservative (c / q, −log₂Q=40) |
|---|---|---|---|
| ML-ADSA-44 (Cat 2) | 122.9 / 111.6 | **122.9 / 111.6** | 82.9 / 71.6 |
| ML-ADSA-65 (Cat 3) | 181.9 / 165.1 | **181.9 / 165.1** | 141.9 / 125.1 |
| ML-ADSA-87 (Cat 5) | 252.0 / 228.7 | **252.0 / 228.7** | 212.0 / 188.7 |

### 2b. Split in the **gate-count** model (realistic; real estimator)

| Level | underlying (c / q) | **tight-adjusted (c / q)** |
|---|---|---|
| ML-ADSA-87 (Cat 5) | **267 / 217** | **267 / 217** (no forking/HVZK loss) |

> Note the quantum **gate-count** (217, ChaLoy21) is *lower* than the quantum **core-SVP** (229): different quantum
> models, both standard, both intrinsic to ML-DSA-87 (F-OFFSET inherits them tightly, not lowered by aggregation).
> The honest conservative quantum figure for ML-DSA-87 is therefore **~217–229** depending on the quantum sieve model.

(ML-ADSA-44/65 gate-counts run similarly above their core-SVP figures; the 87 row is the binding one for Cat 5.)

- **tight-adjusted** = underlying − `adv_prf` (≈0), multi-instance factor removed by MLWE/SIS random
  self-reducibility (standard) ⇒ guaranteed ≈ underlying, *in either cost model*, because the reduction has no
  forking/HVZK loss.
- **conservative** = charging the full `log₂Q = 40` multi-instance factor with no self-reduction credit — a
  deliberately pessimistic floor.
- Cross-check (gate-count): native ML-DSA-87 = 267; the single published hint at σ=3β = **387** (≥ native), so the
  offset/aggregation exposure does not lower the bar.
- **Comparison metric caveat:** when comparing to Fusion, use the SAME model on both sides. Fusion's stated
  128/256 and ~521 underlying must be confirmed as core-SVP vs gate-count before a numeric head-to-head
  ([[fusion-facts]] / [[raccoon-chipmunk-facts]]); the *structural* result (ML-ADSA tight vs Fusion ~2× loss) holds
  in either model.

## 3. Fusion, on the same footing (their stated numbers — re-verify vs their param table before publishing)

| Fusion param | underlying (post-quantum) | guaranteed forgery | tightness loss |
|---|---|---|---|
| Light / base | ~256 | **128** | ~128 (≈50%) |
| Heavy 256-option | ~521 | **256** | ~265 (≈51%) |

Fusion loses ≈ **half** its underlying bits to the reduction; ML-ADSA loses ≈ **0** (tight) to ~40 (pessimistic).

## 4. Apples-to-apples verdict

- **At equal *underlying* hardness, ML-ADSA delivers ~2× Fusion's guaranteed forgery security**, because its
  aggregate is a byte-exact ML-DSA signature (tight native extraction + no signing-simulation loss), while
  Fusion's linear-combination aggregate needs a lossy extractor provisioned at ~2× underlying.
- **ML-ADSA-87 tight-adjusted = 252 classical / 229 quantum** — i.e. its honest guaranteed numbers are essentially
  its core-SVP, *not* halved. In the conservative (full-Q, no-self-reduction) floor it is 212 / 189.
- **The ML-ADSA ceiling is the FIPS-204 *parameter* limit (Cat 5), not the reduction.** To reach **256-bit quantum
  guaranteed (tight)**, ML-ADSA needs BKZ block **b ≈ 966 — only ~1.12× ML-DSA-87's 863** (a modest custom
  "ML-ADSA-256", non-FIPS; Direction B). Fusion-256 provisions underlying ~521 ≈ **2.28×** in core-SVP terms.
  So *if* we drop byte-exact FIPS-204, ML-ADSA reaches 256-bit with a **substantially smaller lattice than
  Fusion** — a direct consequence of the tighter reduction.

## 5. Context: verification status (researched 2026-06-20)

The honest comparison is not only bits but assurance:
- **ML-ADSA: 42 machine-checked artifacts** (EasyCrypt + Coq), admit-free, incl. the σ-independent deployed EUF
  (F20) and the Hint-MLWE tighter-model reduction (F22).
- **Fusion: paper proof only — no formal verification after ~3 years**; its reference code is unaudited alpha
  Python (its README: *"still undergoing security analysis and this codebase has not been independently audited"*).
  QRL's most recent audit (Halborn, 2026-04-03) covers its **NIST-approved** packages (ML-DSA family), not Fusion.

So the byte-exact ML-ADSA direction is aligned with QRL's *actually deployed* NIST crypto and is far ahead on
machine-checked assurance; Fusion offers higher *parameter* targets but, today, neither FV nor an audit.

## 6. Honest caveats

1. Core-SVP (0.292/0.265·b) is the standard conservative convention; gate-count models give *higher* numbers
   (estimator: ML-DSA-87 = 267 classical). The classical/quantum *split* and the *ML-ADSA-vs-Fusion ratio* are the
   robust reads, not the absolute third digit.
2. Fusion's underlying/guaranteed numbers (256→128, 521→256) are taken from the paper/blog and **must be checked
   against their parameter table** before publication ([[raccoon-chipmunk-facts]]).
3. The multi-instance `Q` factor is shown removed by random self-reducibility (standard for MLWE/SIS); the
   conservative column shows the pessimistic alternative. Neither path is a square-root/forking loss.
4. "Tight-adjusted = core-SVP" assumes the deployed key-leak model (F20) — the operationally correct one. The
   atomic-masking route would carry the masking term (docs/48), but the deployed scheme does not use it.
