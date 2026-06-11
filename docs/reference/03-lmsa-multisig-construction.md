# LMSA — Aggregate that verifies under the UNMODIFIED ML-DSA-87 verifier

> **Historical / iteration note (2026-06-11).** This document is part of the research/design trail and reflects an **earlier iteration**; some counts, status labels, and construction details predate the current Construction F. The authoritative current specification is **`docs/30`**, the verification status and tallies are in **`docs/31`** and reproducible via **`formal/count-artifacts.sh`** (29 artifacts, 134 lemmas, 33/33 genuineness, 6 Gobra), and the cross-document reconciliation is **`docs/35`**. Numbers below are preserved as the historical record.

Goal met here: from N signers, produce **one** `σ* = (c̃*, z*, h*)` under an aggregate
key `pk* = (ρ, t1*)` on message `M` such that the **standard, byte-identical FIPS-204
ML-DSA-87 Verify accepts it**, it is **unforgeable**, and its signing power is **exactly
the collective power of the N keys** (n-of-n; no new capability). The price — and the
*only* price — is that co-signers coordinate (shared `A`, plus a commit/reveal that can
be pre-processed offline). This is a lattice multisignature, derived from scratch below;
the arithmetic is pure ring convolution (NTT-friendly), honoring the transform-domain
direction.

Params: `R_q = Z_q[X]/(X^256+1)`, `q=8380417`, `(k,ℓ)=(8,7)`, `η=2`, `τ=60`,
`β=τη=120`, `γ1=2^19`, `γ2=(q-1)/32=261888`, `ω=75`, `d=13`.

## 1. Setup (your "shared global is the context parameter")
Fix one global seed `ρ` (a protocol/epoch parameter; rotate per epoch via the context
tag to deny precomputation). `A = ExpandA(ρ) ∈ R_q^{8×7}` is then shared by all signers.
This is what removes Wall 1 — there is now a single matrix, so no cross terms.

## 2. Keygen + rogue-key defense
Signer `i`: `s1_i ∈ R_q^7`, `s2_i ∈ R_q^8`, `‖·‖∞ ≤ η`. `t_i = A·s1_i + s2_i`.
At registration, signer `i` publishes a **proof of possession** of `s1_i,s2_i` for `t_i`
(a one-time ordinary ML-DSA-style signature over `t_i`). PoP lets us aggregate with
unit coefficients (`a_i = 1`) — keeping `z*` short — while preventing the rogue-key
attack on `t* = Σ t_i`. (Coefficient-weighted aggregation `Σ a_i t_i` with dense `a_i`
would blow the norm via convolution; PoP avoids that.)

Aggregate key: `t* = Σ_i t_i = A·(Σ_i s1_i) + (Σ_i s2_i) = A·s1* + s2*`,
with `s1* = Σ s1_i`, `s2* = Σ s2_i`. Publish `pk* = (ρ, t1*)`, `t1* = HighBits(t*)`.
`pk*` is a **legitimate ML-DSA public key** (it is `A s1* + s2*` split the normal way).

## 3. Signing (common message `M`)
**Round 1 — commit (pre-processable offline, message-independent).** Each `i` samples
`y_i ∈ R_q^7`, `‖y_i‖∞ < γ1'` (reduced bound, see §5), sets `w_i = A·y_i`, broadcasts
`g_i = H(w_i)`.
**Round 2 — reveal + respond.** Reveal `w_i`; everyone forms
`w = Σ_i w_i = A·y*`, `y* = Σ_i y_i`, and
```
w1   = HighBits(w, 2γ2)
μ*   = H( H(pk*) ‖ M' )            # M' = FIPS-204 message rep incl. ctx
c̃*  = H( μ* ‖ w1 )
c*   = SampleInBall(c̃*)           # SPARSE, exactly τ ±1 — a real challenge
z_i  = y_i + c*·s1_i               # same c* for all i
```
Each checks its local norm/abort; broadcasts `z_i`. Aggregator forms
`z* = Σ_i z_i = y* + c*·s1*` and the aggregate hint `h*` from the revealed `t0*`,`w`,`c*`
(exactly the single-signer MakeHint, on the summed quantities). Output `σ* = (c̃*, z*, h*)`.

## 4. Why the STANDARD verifier accepts it (the load-bearing computation)
Verify(`pk*=(ρ,t1*)`, `M`, `σ*`) computes `A=ExpandA(ρ)`, `c*=SampleInBall(c̃*)`, and
`w' = A·z* − c*·t1*·2^d`. Substitute `z* = y* + c* s1*` and `A s1* = t* − s2* =
t1*·2^d + t0* − s2*`:
```
w' = A y* + c*·A s1* − c*·t1*·2^d
   = w + c*(t1*·2^d + t0* − s2*) − c*·t1*·2^d
   = w + c*·t0* − c*·s2*
   = w − c*·s2* + c*·t0*
```
This is **exactly** the single-signature identity (`w − c s2 + c t0`) with the aggregate
secrets. So `UseHint(h*, w', 2γ2) = HighBits(w − c*·s2*) = HighBits(w) = w1`, hence
`c̃* = H(μ* ‖ w1)` holds, `c*` is a valid `SampleInBall` output, and the signature
verifies — **no modification to the verifier, no extra data, no relaxed equation.** The
cross terms that killed the public-folding approach never appear because there is one
shared `A` and one shared `c*`.

## 5. The one real constraint: norm budget (Wall 2, quantified)
`‖z*‖∞ = ‖y* + c* s1*‖∞`. Bounds (convolution: `‖c*·x‖∞ ≤ ‖c*‖_1·‖x‖∞ = τ‖x‖∞`):
```
‖y*‖∞ ≤ N·γ1'              ,   ‖c*·s1*‖∞ ≤ τ·‖s1*‖∞ ≤ τ·N·η = 120·N
require  ‖z*‖∞ < γ1 − β = 524168
```
With reduced masks `γ1' = 2^12` (ratio `γ1'/β ≈ 34`, moderate abort rate):
`N·4096 + 120N = 4216N < 524168 ⇒ N ≲ 124` signers inside **native** ML-DSA-87.
- Smaller `γ1'` → more signers, higher abort/weaker masking.
- The low-bits/hint conditions give `120N < γ2 ⇒ N < ~2180` — looser; `z`-norm binds.
- For cohorts beyond ~100, enlarge `γ1` → still an ML-DSA verifier, but an **adjusted
  parameter set**, not the L5 default binary. (This is the honest boundary of "exact.")

Empirical: a prototype will give the true `(N, γ1', abort-rate)` surface; the bound above
is a conservative worst-case (typical sums concentrate well below `N·γ1'`).

## 6. Security (sketch, to be formalized)
- **Unforgeability** reduces to single-key ML-DSA EUF-CMA + MLWE/MSIS, via the standard
  multisignature simulation (simulate honest co-signers' `w_i` by programming `H`;
  extract via rewinding on `c*`). PoP closes rogue-key. No new assumption.
- **No new power**: the only signable object is under `pk*` with `s1* = Σ s1_i`, which
  requires all N partials — strictly the cohort's collective ability. The aggregate
  cannot sign anything outside what the cohort jointly authorizes.
- **PQ**: inherits ML-DSA-87 L5 (same ring, same `A`, same hash), modulo the global-`A`
  precomputation note (mitigate by epoch rotation of `ρ`).

## 7. Rounds → practical
Round 1 is message-independent, so signers pre-publish batches of `(g_i, w_i)`
commitments offline (FROST-style). Online signing is then **one round** (reveal `z_i`),
and the block producer aggregates. Fits validator/consensus signing directly.

## 8. What this is and isn't
- **Is**: a genuine ML-DSA-87 signature, accepted by any ML-DSA verifier, unforgeable,
  collective-power-bounded, recursively usable (an aggregate key is just an ML-DSA key,
  so cohorts of cohorts work). Convolution-native (NTT throughout).
- **Isn't**: zero-coordination public combination of pre-existing, distinct-message,
  independent signatures. That specific combination is the genuine forbidden corner
  (it would let a public party produce a valid signature under a key whose secret no one
  authorized = forgery). Everything else you asked for is met.

## 9. Build next
1. Reference Rust: keygen+PoP, 2-round (and pre-processed 1-round) signing, aggregate,
   and **verification against an independent ML-DSA-87 verifier** to prove byte-level
   acceptance. Property test: random cohorts up to the norm bound all verify.
2. Measure the real `(N, γ1', abort)` surface and the max `N` under native L5 params.
3. Formal-verification track: model the aggregate-key correctness identity (§4) and the
   unforgeability game (EasyCrypt/Lean) — the §4 identity is small and machine-checkable.
