# MLADSA — Security Analysis (task 2)

> **Historical / iteration note (2026-06-11).** This document is part of the research/design trail and reflects an **earlier iteration**; some counts, status labels, and construction details predate the current Construction F. The authoritative current specification is **`docs/30`**, the verification status and tallies are in **`docs/31`** and reproducible via **`formal/count-artifacts.sh`** (29 artifacts, 134 lemmas, 33/33 genuineness, 6 Gobra), and the cross-document reconciliation is **`docs/35`**. Numbers below are preserved as the historical record.

Honest analysis: what is proven (by code), what reduces to standard assumptions, and what
remains open. No "no security failures" hand-waving — the central tension (masking vs norm)
is stated and quantified, because it is the real cohort-size limiter.

## 1. Model
- **n-of-n multisignature** over a **shared** `A = ExpandA(ρ)` (global/epoch `ρ`).
- Aggregate key `t* = Σ t_i = A·s1* + s2*`, `s1*=Σs1_i`, `s2*=Σs2_i`; `(t1*,t0*)=Power2Round(t*)`.
- Adversary controls the network and up to `n−1` co-signers; ≥1 honest signer. Goal:
  MS-UF-CMA — forge an aggregate under `t*` on a message the honest signer never signed.
- Output is a **plain ML-DSA-87 signature** under `pk*=(ρ,t1*)`; verification is the
  unmodified FIPS-204 verifier.

## 2. Correctness / completeness — PROVEN by code
Identity (`docs/06`): `w' = A·z* − c·t1*·2^d = w − c·s2* + c·t0*`. With the three signer
rejection conditions, `UseHint(h*,w') = HighBits(w−c·s2*) = HighBits(w) = w1`, so
`c̃ = H(μ‖w1)` and `‖z*‖∞<γ1−β`, hint-weight `≤ω` hold ⇒ the FIPS-204 verifier accepts.
`prototype/mladsa_ref.py` and `mladsa_experiments.py` exhibit this for n=1..256 (n=1 is
vanilla ML-DSA-87, round-trips; tampering rejected; PoPs verify).

## 3. The central tension: MASKING vs NORM (the real cohort limiter)
Each partial response is `z_i = y_i + c·s1_i`; the aggregate is `z* = Σ z_i = y* + c·s1*`.
Two opposing pressures on the per-signer mask bound `γ1'`:

- **Norm (verifier):** `‖z*‖∞ < γ1−β`. Since `y* = Σ y_i`, worst case `‖y*‖∞ ≲ n·γ1'`, so
  roughly `n·γ1' < γ1 ⇒ γ1' < γ1/n`. Smaller `γ1'` ⇒ larger cohort. **Floor:** `γ1' ≳ β`
  (else `c·s1_i` dominates `y_i` and `z_i` is neither short nor hiding) ⇒ a hard
  norm-feasibility ceiling `n ≲ (γ1−β)/(2β) ≈ 2180`. (Measured in `mladsa_experiments.py`.)

- **Masking (zero-knowledge):** the response distribution must hide the secret. As in
  Dilithium, rejection sampling makes `z` (statistically) uniform on a box **independent of
  `s1`** only when `γ1' ≫ β`; the per-coefficient leakage shrinks with the ratio `γ1'/β`
  (Dilithium ships `γ1/β ≈ 4369`). Large `γ1'` ⇒ **small** cohort.

These pull opposite ways. With the **naive uniform-sum** construction the *secure* cohort
is therefore **much smaller than the norm-feasible ~2180** — for a comfortable masking
ratio `γ1'/β ≈ 100` you get `n ≈ γ1/(100·β) ≈ 40`. This is the honest headline number for
the simplest MLADSA, and it is set by *masking*, not by the norm wall.

**Pushing `n` higher (known techniques, future work):** (a) hide partials — don't
broadcast `z_i`, aggregate via hiding commitments so only `z*` is public and only `z*`'s
distribution must be analyzed (Rényi-divergence bound, tighter than statistical distance);
(b) **Gaussian** masks instead of uniform (Dilithium-G / Lyubashevsky) for sharper
tail/leakage tradeoffs; (c) trapdoor/lossy commitments (Damgård et al., MuSig-L, DOOM,
Toothpicks). These push the secure cohort into the hundreds. Selecting among them is the
key cryptographic design decision and must precede deployment.

## 4. Unforgeability — reduction sketch (standard structure)
Claim: MS-UF-CMA of MLADSA reduces to ML-DSA-87 unforgeability (i.e. SelfTargetMSIS +
MLWE in the (Q)ROM) plus binding of the round-1 commitment.

Reduction outline:
1. **Rogue-key removed by PoP.** Each `t_i` carries a proof-of-possession (a single-key
   signature over `t_i`, implemented + verified in `mladsa_experiments.py`). Extracting the
   PoP gives the adversary's `s1_j` for every controlled key, so `s1* = Σ s1_i` has a known
   decomposition; the adversary cannot pick `t_j = t_target − Σ_{others} t_i` adaptively
   (it wouldn't know the secret). This collapses n-of-n to **one honest signer**.
2. **Simulate the honest signer without its secret.** Standard Σ-protocol HVZK: sample
   `c, z` first, set the honest `w_i = A·z_i − c·t_i` (so the transcript is consistent),
   and program the RO at `(μ‖w1)` to output `c̃`. The round-1 commitment `H(w_i)` is opened
   to this simulated `w_i` by programming `H` (commit-then-equivocate in the ROM). This is
   exactly why the commit/reveal round is load-bearing — it stops the adversary from
   choosing its `w_j` adaptively after seeing the honest `w_i`.
3. **Extract on forgery.** A forging adversary, rewound/forked on the RO challenge `c̃`,
   yields two valid transcripts with the same commitment and different `c` ⇒ a short
   solution to the underlying SelfTargetMSIS/MSIS instance, or a key distinguisher for
   MLWE. This is the same extraction that underlies ML-DSA's own proof.

**Honesty about tightness:** the forking step and the QROM SelfTargetMSIS←MLWE reduction
are **non-tight** (the research pinned the QROM bound at `Ω(ε²/Q⁴)`, EUROCRYPT 2024). So
MLADSA inherits ML-DSA-87's non-tight QROM security, not better. No new hardness
assumption is introduced beyond MLWE/MSIS/SelfTargetMSIS + ROM commitment.

## 5. Status table
| Property | Status | Basis |
|---|---|---|
| Correctness / FIPS-204 acceptance | **proven (code)** | identity §2 + `mladsa_ref.py` |
| Norm-feasibility ceiling (~2180) | **measured** | `mladsa_experiments.py` |
| Rogue-key resistance | reduces to PoP soundness | §4.1 (implemented) |
| Unforgeability | reduces to ML-DSA + ROM commitment | §4 (sketch; non-tight) |
| Zero-knowledge / masking | **bounded, n-limited** | §3 (the real limiter) |
| Secure cohort size (naive) | ~tens (`n≈40` at ratio 100) | §3 |
| Secure cohort size (advanced masking) | hundreds (future) | §3 (a)/(b)/(c) |

## 6. Open items before deployment
1. Formal masking bound: Rényi/statistical-distance proof for `z*` (and for hidden
   partials) → the *certified* secure cohort cap.
2. Full forking proof with the commitment scheme (and its hiding/binding in the ROM).
3. Choose the masking technique (uniform-hidden-partial vs Gaussian vs trapdoor-commit)
   to hit the target cohort size for QRL 2.0's validator set.
4. Byte-exact FIPS-204 codec + cross-check vs a reference ML-DSA-87 (interop).
5. Machine-checked proof (EasyCrypt/Lean) of §2 identity and §4 reduction — matches the
   project's formal-verification goal.
