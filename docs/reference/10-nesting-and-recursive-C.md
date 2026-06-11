# Nesting / recursion, buffering, and the deep (C) architecture

## 1. Does nesting extend total aggregation? Only where the norm is *refreshed*.
A nested ("tree") aggregate helps **iff** each layer compresses without inheriting the
previous layer's growth. That happens only in a **proof system**:

- **(A) tiling / (B) rejection-free — NO extension from nesting.** A tree over the same N
  leaves still computes `z*_top = Σ_all y_i + c·Σ_all s1_i`: the norm grows like
  `√(total leaves)` **independent of tree shape** (measured: `prototype/mladsa_multinonce.py`
  `norm_vs_k`, `‖z*‖∝√k`). So a 2-layer tree over N hits the *same* `γ1−β` ceiling as flat
  aggregation (~k≈20000 at σ=12β). And re-aggregating *already-emitted* aggregates fails the
  challenge-collapse wall (each carries its own `c̃`; one ML-DSA sig has one challenge), so
  you'd have to re-coordinate from scratch = flat again. **No norm refresh ⇒ nesting is a
  no-op for compression on the exact-verifier paths.**
- **(C) transparent proof — nesting is the whole point.** A LaBRADOR/STARK proof *refreshes*
  the norm every layer (decompose witness → re-prove) and is itself a short Module-SIS
  object. Proving "I verified k proofs" yields a constant/polylog proof-of-proofs ⇒ a
  log-depth tree compresses **unbounded N** to ~constant size.

## 2. Buffering / periodic emit (the streaming pattern)
Buffer streamed signatures; emit when the buffer hits `k` (or on a timer).
- **(A)/(B):** one-layer — each full buffer → one k-fold ML-DSA-87 aggregate (measured:
  `prototype/mladsa_buffer.py`, exact verifier, pqcrypto-checked). Stacking a 2nd layer does
  not compress further (§1). Use when you want streaming throughput at the exact verifier.
- **(C):** buffer → prove batch → buffer the batch-proofs → prove those → … This is the
  **multi-layer / nested** compression you want: unbounded N, ~constant root, public,
  any keys/messages, trapdoor-free.

## 3. Deep (C): recursive NATIVE-LATTICE folding (the build) — NOT a STARK
Terminology (corrected): "transparent" ⊋ {STARK, lattice-folding}.
- **STARK** = hash-based (Merkle + FRI), transparent, PQ-from-hash. We are **not** using this.
- **Native-lattice folding** (LaBRADOR-class, Module-SIS): transparent (no CRS, **no toxic
  waste, no trapdoor**), **not a STARK**, native `R_q` arithmetic; the residual is a **short
  module-lattice vector** that re-folds. This is the build.

Goal: a native-lattice, transparent argument that "these N ML-DSA-87 signatures all verify,"
recursively composable so N is unbounded at ~constant size. Honest invariant: scalable
compression beating the `√N` norm wall is, by the binding theorem (docs/04), an *argument of
knowledge* — the gadget/base-`b` decomposition that refreshes the norm needs a short
consistency check (commit to digits + verify recomposition), or it is forgeable. Native
lattice folding is the lightest way to pay this; it is not free algebra. (A claimed
no-consistency-object native compression fails the `z*=0`/Module-SIS litmus.)

### 3a. Leaf statement (one signature) as `R_q` constraints
ML-DSA-87 `Verify(pk,M,σ)` arithmetized over `R_q` (the native ring — no field embedding):
- `ŵ' = Â∘ẑ − ĉ∘(t̂1·2^d)` (NTT-domain linear algebra): k·ℓ=56 pointwise products, ℓ=7 NTTs.
- `w1' = UseHint(h,w')`: per-coefficient decompose/select over k·n=2048 coeffs.
- `‖z‖∞ < γ1−β`: ℓ·n=1792 range checks (~20-bit each) → lookups.
- `c = SampleInBall(c̃)`: sparsity (τ=60 ±1) + derivation from `c̃`.
- `c̃ = H(μ ‖ w1Encode(w1'))`: a SHAKE-256 (keccak-f) evaluation — **the dominant cost.**

Rough per-signature constraint budget: keccak-f + NTT + UseHint + range ≈ **2¹⁷–2¹⁸**
constraints (keccak dominates; ML-DSA's FSwA verify is heavier than Falcon's Gaussian-norm
check, which is why published Falcon aggregates don't transfer).

### 3b. Batch proof
LaBRADOR (Module-SIS) over the batch R1CS; reference point: **58 KB @ 2²⁰ constraints**
[cited]. So a batch of ~`2²⁰/2¹⁷ ≈ 8` signatures ≈ one 58 KB proof; larger batches grow
sublinearly (LaBRADOR `O(√·)`, Greyhound PCS `O(√N)` verifier). **Estimate** for an ML-DSA
batch of ~1000: ~**100–300 KB** (no published ML-DSA number exists — building this *is* the
contribution).

### 3c. Recursion (the nesting that refreshes norm)
Each layer's circuit = {verify the child LaBRADOR proof} + {fold in a new batch}. The
"verify-a-proof" sub-circuit is fixed-size, so per-layer cost is bounded and the **root proof
size is constant in N** (log-depth tree). This is the buffer→prove→prove-of-proofs pipeline,
and it is *trapdoor-free/transparent* (hash-based FS + Module-SIS), preserving the cypherpunk
posture. Verifier: one (heavier) proof check; keys independent; messages arbitrary; no
signing coordination, no shared ρ — the genuine BLS-like public aggregation.

### 3d. Honest scope
This is a multi-week research-engineering build: a correct `R_q` arithmetization of the FSwA
verifier (esp. keccak + UseHint), a LaBRADOR/Greyhound prover, and the recursion circuit.
Pure-Python is far too slow for real sizes; the real prover wants Rust/GPU (ICICLE-LaBRADOR
exists). Deliverables in order:
1. Constraint system for one ML-DSA-87 `Verify` (counts + layout) — turns 3a into exact numbers.
2. Single-signature LaBRADOR proof — the first real **ML-DSA** proof size (the missing datapoint).
3. Batch proof (k signatures) + size/verify measurements.
4. Recursion circuit → measured constant-size root over a nested tree (the unbounded-N demo).

## 3e. "Refreshing (A)" — it *is* (C)
Can we add a norm-refresh to (A) so its aggregates nest? Yes — and the refresh operation is
exactly a (transparent) proof, so refreshing (A) constructs (C). The three ways to get a
smaller-norm equivalent of a valid short `z*`:
1. **Publicly shrink `z*`** = find a shorter Module-SIS preimage = **hard by assumption**
   (the scheme's own security). Blocked.
2. **Re-sign** with one fresh small nonce: `z_top = y_top + c·Σs1ᵢ`; the secret term is only
   `~120√N` (tiny), but in a trustless multisig the nonce must be a *sum* of per-signer
   nonces (else a party extracts the secret) ⇒ `y_top ~ √N·σ`, regrowing the wall. Blocked
   (a single-nonce re-sign needs a trusted party / trapdoor — rejected).
3. **Replace `z*` by a proof** that a short `z*` exists — norm set by the proof system, not
   the witness. The cheapest trustless form is a lattice decomposition/folding proof = the
   **LaBRADOR core**. This is the genuine refresh.

⇒ **(C) = (A) tiling + a per-layer transparent norm-refresh proof + recursion.** "Refresh
A so it nests" and "build C" are the same milestone. Each recursion layer = {refresh the
child's norm via a LaBRADOR proof} + {fold in the next buffer}. Refreshed norm ⇒ nesting
extends ⇒ buffer + periodic + multi-layer ⇒ unbounded N at ~constant size.

## 4. Summary
- Nesting **extends** aggregation only for **(C)** (norm-refreshing proof); for **(A)/(B)**
  it does not (measured `√N` norm + challenge collapse).
- Buffering is a clean streaming pattern for all; **multi-layer compression is a (C)-only
  capability**, and it is exactly the unbounded-N, public, BLS-like endgame.
- ⇒ Building **(C)** deeply is what realizes "buffer + periodic + multiple layers." Step 1
  (the ML-DSA `Verify` constraint system) is the next concrete artifact.
