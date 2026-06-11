# MLADSA — Module-Lattice Aggregate DSA (the real, buildable scheme)

> **Historical / iteration note (2026-06-11).** This document is part of the research/design trail and reflects an **earlier iteration**; some counts, status labels, and construction details predate the current Construction F. The authoritative current specification is **`docs/30`**, the verification status and tallies are in **`docs/31`** and reproducible via **`formal/count-artifacts.sh`** (29 artifacts, 134 lemmas, 33/33 genuineness, 6 Gobra), and the cross-document reconciliation is **`docs/35`**. Numbers below are preserved as the historical record.

The aggregate is a **genuine ML-DSA-87 signature** under an aggregate key, accepted by the
**unmodified** FIPS-204 verifier. No ZK argument, no correction δ, no "absorption into the
hint," no compensator. Those only appear when one tries to avoid coordination; MLADSA pays
coordination instead, which is the only sound currency for an exact-verifier aggregate
(see `docs/04`, `docs/05`).

## Exact NIST ML-DSA-87 parameters (corrected)
`q = 8380417`, `n = 256`, `(k,ℓ) = (8,7)`, `η = 2`, `τ = 60`,
`β = τ·η = 120`, `γ1 = 2^19 = 524288`, `γ2 = (q−1)/32 = 261888`, `α = 2γ2`,
`d = 13`, `ω = 75`. (Grok's 131072 / 78 were wrong.)

## Requirements
1. **Shared `ρ`** for the aggregating cohort ⇒ one shared `A = ExpandA(ρ)`. Still a
   FIPS-204-valid key (the verifier never checks `ρ` was fresh). Removes Wall 1.
2. **Coordination** (one commit/reveal round, pre-processable offline) so all signers use
   **one shared challenge `c`**. Removes the challenge-collapse obstruction.
3. **Rogue-key defence**: each signer publishes a proof-of-possession of its `(s1_i,s2_i)`
   at registration (one-time), so we aggregate with unit coefficients (`z* = Σ z_i`) and
   the norm stays controlled.

## Scheme
- **KeyGen(i):** `s1_i,s2_i` with `‖·‖∞ ≤ η`; `t_i = A·s1_i + s2_i`; publish `t_i` (+PoP).
- **Aggregate key:** `t* = Σ t_i = A·s1* + s2*`, `s1* = Σ s1_i`, `s2* = Σ s2_i`;
  `(t1*, t0*) = Power2Round(t*, d)`. Note `t0* ∈ [−2^{d−1}, 2^{d−1}]` **independent of n**
  (it is the rounding remainder of the *sum*), so `‖c·t0*‖∞ ≤ τ·2^{d−1} = 245760 < γ2`
  for every cohort size — the hint stays well-formed.
- **Sign(M), cohort of n:** loop
  - each i: `y_i`, `‖y_i‖∞ < γ1'` (reduced mask); `w_i = A·y_i`; (commit `H(w_i)`, reveal)
  - `w = Σ w_i = A·y*`,  `y* = Σ y_i`;  `w1 = HighBits(w, α)`
  - `μ = H(H(pk*) ‖ M)`;  `c̃ = H(μ ‖ w1)`;  `c = SampleInBall(c̃)`  (sparse — exact V2/V3)
  - `z* = y* + c·s1*`
  - reject unless `‖z*‖∞ < γ1−β`  and  `‖LowBits(w − c·s2*, α)‖∞ < γ2−β`  and
    `‖c·t0*‖∞ < γ2`  and  weight(`h*`) ≤ ω
  - `h* = MakeHint(−c·t0*, w − c·s2* + c·t0*, α)`
  - output `σ* = (c̃, z*, h*)` under `pk* = (ρ, t1*)`.
- **Verify:** the **unmodified** ML-DSA-87 verifier on `(pk*, M, σ*)`.

## Why the standard verifier accepts (identity)
`w' = A·z* − c·t1*·2^d = w + c·(A·s1*) − c·t1*·2^d = w + c·(t* − s2*) − c·t1*·2^d
    = w − c·s2* + c·t0*`. The aggregate hint makes `UseHint(h*, w') = HighBits(w − c·s2*)`,
and the `LowBits` rejection guarantees `HighBits(w − c·s2*) = HighBits(w) = w1`, so
`c̃ = H(μ‖w1)` holds and the signature verifies — byte-identical path.

## The only real cost: norm budget (cohort cap)
`‖z*‖∞ = ‖y* + c·s1*‖∞`. `‖c·s1*‖∞ ≤ τ·‖s1*‖∞ ≤ τ·n·η = 120n` (small); the binding term
is `‖y*‖∞` with `y* = Σ y_i`. Smaller per-signer mask `γ1'` ⇒ larger cohort but more
aborts and weaker masking. The hint weight and the `LowBits(w−c·s2*)` condition (`120n < γ2
⇒ n < ~2180`) also bound `n`. The exact `(n, γ1', accept-rate)` surface is **measured**,
not asserted — see `prototype/mladsa_ref.py`.
