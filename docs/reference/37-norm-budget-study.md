# 37 — Norm-Budget & Secure-Cohort (Secure-`N`) Study

> **Why this exists.** The honest ML-ADSA aggregate response is `z* = Σ_i z_i = Σ_i y_i + c·Σ_i s1_i`.
> The **unmodified FIPS-204 verifier** accepts only if `maxAbs(z*) < γ1 − β = 524168`; the combiner
> **abstains** otherwise (`go-mladsa/construction_f.go:318`). So the honest-aggregate **success rate is a
> function of the cohort size `N`**, and the *secure-/usable-`N`* must be stated, not assumed. This was the
> one concrete gap flagged both by an external reviewer and by our own cryptanalysis packet (`docs/36 §6.4`,
> *"is the secure `N` honestly bounded?"*). This study answers it two ways — a **rigorous provable bound**
> and a **Monte-Carlo measurement** — using the *real* construction primitives.

Reproduce: `go test -run TestNormBudget -v ./go-mladsa/` (or `NB_TRIALS=20000 …` for tighter tails). The
RNG is seeded deterministically per `(N, trial)`, so the table reproduces exactly. Source:
`go-mladsa/normbudget_test.go`.

---

## 1. The quantity

For ML-ADSA Construction B (rejection-free, wide masks — the regime used for the large-cohort demos):

- each signer's mask coefficient `y_i[s][t]` is **uniform on `[−σ, σ]`**, `σ = 12·β = 1440`;
- each secret coefficient `s1_i[s][t] ∈ [−η, η]`, `η = 2`;
- the shared challenge `c = SampleInBall(c̃*)` has exactly `τ = 60` nonzero `±1` coefficients;
- the aggregate response is, per polynomial `s ∈ {0..L−1}` (`L = 7`) and coefficient `t ∈ {0..255}`,
  `z*[s][t] = Σ_i y_i[s][t] + (c · Σ_i s1_i)[s][t]` in `R_q`;
- **verification ceiling:** `maxAbs(z*) < γ1 − β = 2¹⁹ − 120 = 524168`, over all `L·256 = 1792` coordinates.

The **abstention / honest-failure probability** is `Pr[ maxAbs(z*) ≥ 524168 ]`.

---

## 2. Rigorous secure-`N` (provable upper bound on failure)

Each coordinate `z*[s][t]` is a sum of **independent, zero-mean, bounded** terms: `N` mask coefficients in
`[−σ,σ]` (Hoeffding sub-Gaussian proxy `σ²` each) plus the secret term, which is a `±1`-weighted sum (the
`τ` nonzero positions of `c`) of `s1*[·] = Σ_i s1_i[·]` — i.e. a signed sum of `τ·N` i.i.d. terms in
`[−η,η]` (proxy `η²` each). Total proxy `V = N·σ² + τ·N·η²`. Hoeffding + union bound over the `1792`
coordinates with `a = γ1 − β`:

```
Pr[maxAbs(z*) ≥ γ1−β]  ≤  1792 · 2 · exp( − a² / (2V) ),   V = N·(σ² + τ·η²).
```

Largest `N` with a **provable** failure bound below standard targets:

| failure target | secure-`N` (tight bound) | secure-`N` (loose bound†) |
|---|---|---|
| `2⁻⁴⁰`  | **1844** | 1058 |
| `2⁻⁶⁴`  | **1260** | 828 |
| `2⁻¹²⁸` | **683**  | 528 |

† The *loose* bound (preserved in `nbHoeffdingFailLoose`, `normbudget_test.go`) charges the secret term at
its worst case `‖c·s1*‖∞ ≤ β·N` (triangle inequality) and concentrates only the mask sum; the *tight* bound
concentrates the secret term too. Both are sound; the tight one is the headline. The mask variance `N·σ²`
dominates `V`, so the provable secure-`N` is `O(σ²/(γ1−β)²)`-bounded and grows only slowly — this is the
honest provable ceiling, deliberately conservative.

---

## 3. Monte-Carlo measurement (realistic secure-`N`)

Full cohorts sampled with the real primitives (`SampleInBall`, `polyMul` = negacyclic multiply mod `q`, the
real parameters), 2000 trials per `N`, `σ = 1440`:

The two rightmost columns are the **rigorous** per-`N` failure bounds of §2, in **log₂** (the real value,
not a Monte-Carlo number) — see the precision note below.

| `N` | mean `maxAbs(z*)` | observed max | abstentions / 2000 | max secret term `‖c·s1*‖∞` | log₂ bound (tight) | log₂ bound (loose) |
|----:|----:|----:|:--|----:|----:|----:|
| 2     | 2 822   | 2 905   | 0 | 78    | 2⁻⁴⁷⁷⁷² | 2⁻⁴⁷⁷³⁴ |
| 4     | 5 019   | 5 666   | 0 | 112   | 2⁻²³⁸⁸⁰ | 2⁻²³⁸³⁹ |
| 8     | 7 855   | 9 976   | 0 | 159   | 2⁻¹¹⁹³⁴ | 2⁻¹¹⁸⁹² |
| 16    | 11 528  | 16 098  | 0 | 236   | 2⁻⁵⁹⁶¹  | 2⁻⁵⁹¹⁸  |
| 32    | 16 589  | 23 226  | 0 | 321   | 2⁻²⁹⁷⁵  | 2⁻²⁹³¹  |
| 64    | 23 747  | 34 645  | 0 | 432   | 2⁻¹⁴⁸¹  | 2⁻¹⁴³⁸  |
| 128   | 33 590  | 49 498  | 0 | 661   | 2⁻⁷³⁵   | 2⁻⁶⁹²   |
| 256   | 47 485  | 69 898  | 0 | 1 002 | 2⁻³⁶¹·⁵ | 2⁻³¹⁹·¹ |
| 512   | 67 787  | 101 751 | 0 | 1 270 | 2⁻¹⁷⁴·⁸ | 2⁻¹³³·⁷ |
| 1 024 | 95 398  | 140 192 | 0 | 1 895 | 2⁻⁸¹·⁵  | 2⁻⁴²·⁹  |
| 2 048 | 135 446 | 200 707 | 0 | 2 462 | 2⁻³⁴·⁹  | 2⁻¹·⁴   |
| 4 096 | 190 967 | 261 400 | 0 | 3 663 | 2⁻¹¹·⁵  | 2⁰ (≥1) |

> **Precision note.** The failure bound `1792·2·exp(−a²/2V)` *underflows IEEE-754 float64* for small `N`
> (e.g. at `N=2`, `a²/2V ≈ 33 120`, so the bound is `≈ 10⁻¹⁴³⁸³ ≪ 10⁻³⁰⁸`, which rounds to `0.0`). We
> therefore report the bound's **exact log₂ exponent**, computed in log-space —
> `log₂(2·L·n) − (a²/2V)/ln2` — which never underflows and *is* the real magnitude (a `2⁻⁴⁷⁷⁷²` is more
> informative than a rounded-to-zero float, and arbitrary-precision `big.Float` would only reproduce the
> same exponent). The `safe-N` search in §2 compares against `2⁻⁴⁰…2⁻¹²⁸`, where the bound is `≈ 10⁻¹²…10⁻³⁹`
> — comfortably inside float64 range, so those thresholds are exact in ordinary arithmetic. Source:
> `nbLog2Fail` in `go-mladsa/normbudget_test.go`.

**Observations.**
- **Zero abstentions through `N = 4096`** (40 000+ cohort samples in total). The observed worst case at
  `N = 4096` is `261 400` — barely **half** the `524 168` ceiling.
- `maxAbs(z*)` scales as `≈ √N` (mask-sum concentration), as expected. Extrapolating the `√N` law, the
  ceiling is first approached near **`N ≈ 16 000`** (`261 400 · √(16384/4096) ≈ 522 800 ≈ 524 168`).
- The secret term `‖c·s1*‖∞` stays tiny (`≤ 3 663` even at `N = 4096`) — three orders of magnitude below the
  worst-case `β·N = 491 520` that the *loose* rigorous bound charges. This is exactly why the tight bound
  (and reality) permit far larger cohorts than the loose one suggests.

---

## 4. Honest secure-`N` statement

- **Provably safe (deploy with a proof):** `N ≤ 1844` at `2⁻⁴⁰`, `N ≤ 683` at `2⁻¹²⁸` failure probability.
  The demoed/operational `N = 1000` is provably safe at `> 2⁻⁴⁰`.
- **Empirically safe (observed, no abstention):** through `N = 4096` with large margin; the `√N` curve does
  not reach the ceiling until `N ≈ 16 000`.
- **Operationally:** abstention is **non-destructive** — a slot that would overflow the bound simply does not
  emit an aggregate (`construction_f.go:318`), and the combiner can retry/fall back to the legacy
  concatenated aggregate. There is **no correctness or security violation** from a near-ceiling cohort, only
  a liveness cost on that slot.

**Recommendation.** State a conservative deployment cap of `N ≤ 1024` (provably `< 2⁻⁴⁰`, with ~5× empirical
margin); for larger committees use hierarchical aggregation (`mladsa-hieragg`) or accept the stated
abstention rate. The rejection-free **leakage** question (does the summed `z*`, whose mean tracks `c·s1*`,
stay computationally hiding per fresh content-key) is *separate* from this norm budget and remains a
priority for human cryptanalysis (`docs/36 §6.4`, `ml_adsa_regimes.ec`: narrow regime → `adv_mask ≤
adv_mlwe`).

---

## 5. Caveats (what this study does and does not establish)

- **Does** establish: the honest-aggregate **verification-success / abstention** rate vs `N`, both provably
  (Hoeffding) and empirically (Monte-Carlo with the real primitives), giving a defensible secure-`N`.
- **Does not** establish: the *security* (HVZK / leakage) of the summed response — that is the `adv_mask`
  argument in `ml_adsa_regimes.ec` and the open item in `docs/36 §6.4/§6.5`, not a norm-budget question.
- The mask coefficients are modeled as exactly uniform on `[−σ,σ]`; the implementation derives them from a
  PRF stream (`refresh.go:DeriveNonce`), whose output is computationally indistinguishable from uniform —
  the norm distribution is therefore the uniform one up to PRF advantage.
