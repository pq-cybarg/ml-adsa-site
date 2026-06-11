# Unified verifier form + synchronized aggregation via deterministic H(tx)

> **Historical / iteration note (2026-06-11).** This document is part of the research/design trail and reflects an **earlier iteration**; some counts, status labels, and construction details predate the current Construction F. The authoritative current specification is **`docs/30`**, the verification status and tallies are in **`docs/31`** and reproducible via **`formal/count-artifacts.sh`** (29 artifacts, 134 lemmas, 33/33 genuineness, 6 Gobra), and the cross-document reconciliation is **`docs/35`**. Numbers below are preserved as the historical record.

This captures two user-driven results: (1) a single *standard form* that subsumes ML-DSA
and the aggregate; (2) deterministic `H(tx)` as the domain that enables **non-interactive**
aggregation — which is the synchronized-aggregate paradigm (Chipmunk/Squirrel-class) and the
true lattice analog of BLS.

## 1. One standard form (generalized Module-SIS signature)
`Verify(vk, m, σ)`: parse `σ=(x, aux)`; compute target `T = Φ(vk, m, aux)` (public coins);
**accept iff `A·x ≈ T` (mod gadget/hint) and `‖x‖ ≤ B`.**
- **ML-DSA single sig** = FS-target instance: `A=ExpandA(ρ)`, `x=z`, `T=c·t1·2^d`,
  `c=H(μ‖w1)` (challenge binds the *commitment*), `B=γ1−β`. This is unchanged FIPS-204.
- **Aggregate** = domain-target instance: `x =` folded sum of short vectors,
  `T = Σ_i Φ_dom(m_i, key_i)`, `B =` gadget-refreshed bound.
The "second verifier" is rational because it is a *generalization* of FIPS-204 (ML-DSA is the
FS-target special case), not a replacement.

## 2. Why the lattice form looks like this (BLS analogy)
- BLS: `σ=sk·H(m)` (hash-and-sign, **no challenge**) + **bilinear pairing** ⇒ linear-sum
  aggregation with no growth; verify `e(σ_agg,g)=∏ e(H(m_i),pk_i)`.
- Lattice analog: target `T=Φ_dom(m)` (the "hash-to-domain"), signature = short `x`,
  aggregate = **linear sum** `Σx_i`, verify `A·Σx_i ≈ ΣT_i`. The linear map `A·x` plays the
  role of the pairing; `T` plays `H(m)`.
- A pairing is *bilinear* (free aggregation, no growth); lattices have only the *linear*
  map, so the sum **grows in norm (√N)** — the lattice's tax for having no pairing. The
  **gadget `G/G⁻¹`** pays that tax (refresh the grown sum to small norm, relation preserved).
  FSwA's challenge `c` is the one element with **no BLS analog** — which is exactly why
  Dilithium resists and a domain-target (hash-and-sign-like) leaf "just works."

## 3. Deterministic H(tx) ⇒ non-interactive (synchronized) aggregation
A defined-shape tx has a deterministic `H(tx)`. Signers sign w.r.t. `H(tx)` independently,
submit to a pool; anyone aggregates submissions matched by `H(tx)`. `H(tx)` is the
BLS-analog domain and the cohort tag. This is the **synchronized aggregate signature** model
(Chipmunk/Squirrel): non-interactive, public, PQ.

### Crucial subtlety (located precisely)
`H(tx)` makes the *message* common, but does **not** make a *FSwA challenge* common:
`c_i = H(μ ‖ w1_i)` depends on each signer's distinct commitment `w_i`, so `c_1≠c_2` and
`Σ c_i s_i ≠ c·Σ s_i`. **Common message ≠ common challenge.** Hence independent *vanilla
ML-DSA* sigs on the same tx still do not aggregate; the per-commitment challenge is the
blocker, and `H(tx)` doesn't touch it. (Strong structural barrier — not asserted as an
absolute theorem; if `H(tx)` can also pin the commitment without breaking FS, that's the
breakthrough to test.)

### What makes it work: drop the per-signer commitment-challenge
Use a leaf that binds to `H(tx)` without an FS commitment-challenge — a homomorphic /
one-time-ish lattice signature (Chipmunk/Squirrel-class). Then same-`H(tx)` independent sigs
aggregate non-interactively. Costs (the non-interactivity tax):
- special leaf scheme (not literal FSwA/ML-DSA);
- one-time / few-time per sync-period (each key signs a block/period once);
- ~100 KB aggregate over ~1000 signers (Chipmunk [cited]); verified by an instance of §1's
  unified form (`T = Φ_dom(H(tx))`).

## 4. Where each lands for QRL
- **Consensus / validators** (sign each block once, independently): **synchronized aggregate
  via H(block)** — non-interactive, PQ, ~100 KB over thousands, unified-form verifier. The
  genuine BLS-analog for consensus. Cost vs vanilla ML-DSA: the special one-time leaf scheme.
- **Arbitrary user txs, vanilla ML-DSA leaves**: still needs interaction (commit-reveal) or a
  proof — the commitment-challenge barrier. The unified form still describes the verifier.

## 5. Build hook
Spec the synchronized leaf (the `H(tx)`-bound one-time lattice signature) in the unified
`A·x ≈ T` form, with ML-DSA as the sibling FS-target instance ⇒ "one standard form, two
instances (synchronized-aggregate + ML-DSA)."
