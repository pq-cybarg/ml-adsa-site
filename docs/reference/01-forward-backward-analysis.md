# LMSA — Forward/Backward Analysis of ML-DSA-87 Aggregation

> **Historical / iteration note (2026-06-11).** This document is part of the research/design trail and reflects an **earlier iteration**; some counts, status labels, and construction details predate the current Construction F. The authoritative current specification is **`docs/30`**, the verification status and tallies are in **`docs/31`** and reproducible via **`formal/count-artifacts.sh`** (29 artifacts, 134 lemmas, 33/33 genuineness, 6 Gobra), and the cross-document reconciliation is **`docs/35`**. Numbers below are preserved as the historical record.

> Goal: determine, from first principles (not by citation), whether many independent
> ML-DSA-87 signatures can be combined into one object accepted by the **standard
> ML-DSA verifier**, while remaining unforgeable and granting no power beyond the
> original keys. We work *backward* from the verifier and *forward* from known
> mechanisms, and we test the transform-domain (NTT / FFT / convolution-theorem) idea
> directly.

## 0. Exact setup (so every claim below is checkable)

Ring `R_q = Z_q[X]/(X^256 + 1)`, `q = 8380417 = 2^23 - 2^13 + 1`, `n = 256`.

ML-DSA-87 (Dilithium5): `(k, ℓ) = (8, 7)`, `η = 2`, `τ = 60`, `β = τη = 120`,
`γ1 = 2^19 = 524288`, `γ2 = (q-1)/32 = 261888`, `ω = 75`, `d = 13`.

**Key.** `ρ` is a 32-byte seed. The matrix is `A = ExpandA(ρ) ∈ R_q^{8×7}`, where
`ExpandA` is a SHAKE-based **hash expansion** (this single fact is load-bearing —
see §3). Secret `s1 ∈ R_q^7`, `s2 ∈ R_q^8`, both with `‖·‖∞ ≤ η`.
`t = A·s1 + s2`; split `t = t1·2^d + t0`. Public key `pk = (ρ, t1)`.

**Sign(μ).** Sample `y`, `‖y‖∞ < γ1`. `w = A·y`; `w1 = HighBits(w, 2γ2)`.
`c̃ = H(μ ‖ w1)`, `c = SampleInBall(c̃)` (sparse, exactly τ coeffs in ±1).
`z = y + c·s1`. Reject unless `‖z‖∞ < γ1 − β` and the low-bits/hint conditions hold.
`h = MakeHint(...)`. Signature `σ = (c̃, z, h)`.

**Verify(pk, μ, σ).** `A = ExpandA(ρ)`, `c = SampleInBall(c̃)`,
`w' = A·z − c·t1·2^d`, `w1' = UseHint(h, w', 2γ2)`. **Accept iff**

```
(V1)  ‖z‖∞ < γ1 − β
(V2)  c = SampleInBall(c̃)   is sparse ±1, weight τ
(V3)  c̃ = H( μ ‖ w1' )       (Fiat–Shamir fixed point)
(V4)  #ones(h) ≤ ω
```

The identity that makes honest signatures verify:
`w' = A(y+cs1) − c t1 2^d = w + c(t − s2) − c t1 2^d = w − c·s2 + c·t0`, and
`UseHint` strips the `c·t0` term so `w1' = HighBits(w − c s2) = HighBits(w) = w1`.
Note **`w1` is fixed by `w = A·y` alone, before `c` exists.** That ordering is the
whole game.

---

## 1. Track B — backward from the verifier

For the standard verifier to accept an aggregate `(c̃*, z*, h*)` under some
`pk* = (ρ*, t1*)` and message `μ*`, all of (V1)–(V4) must hold for `A* = ExpandA(ρ*)`.

Rearrange (V3): the aggregator must exhibit `c̃*` such that

```
c̃* = H( μ* ‖ UseHint(h*, A*·z* − SampleInBall(c̃*)·t1*·2^d, 2γ2) )
```

`c̃*` appears **on both sides** (right side through `c* = SampleInBall(c̃*)`). With `H`
a random oracle, the only way to satisfy this is to fix everything that feeds the hash
*before* querying it — i.e. fix `w1*` first, then define `c̃* = H(μ* ‖ w1*)`. But `w1*`
is derived from `w'* = A*z* − c* t1* 2^d`, which depends on `c*`, which is
`SampleInBall(c̃*)`. The loop closes only if there is a way to choose `z*` **after**
`c*` is known that (a) keeps `‖z*‖∞ < γ1−β` and (b) leaves `HighBits(w'*)` equal to the
pre-committed `w1*`. In honest signing this is done by `z = y + c·s1`: the secret `s1`
absorbs `c` while rejection sampling keeps `z` short. **A public aggregator holds no
`s1*` for `pk*`.** So Track B reduces to: *produce `(z*, c*)` short and FS-consistent
for a key whose secret you don't have.* That is exactly the ML-DSA forgery problem for
`pk*` (§3 makes the reduction precise).

This is not lattice-specific. The identical wall exists for **classical Schnorr**:
nobody can publicly combine independent Schnorr signatures into one Schnorr signature,
because Schnorr is also Fiat–Shamir and `s = k + e·x` needs the secret `x`. BLS
escapes only because it is *not* Fiat–Shamir — it is pairing-based and deterministic
(`σ = x·H(m)`), so `Σσ_i` is itself a signature under `Σ pk_i`. The property the
project wants is a **pairing property**, and ML-DSA is a Fiat–Shamir scheme. So "no one
did this before" is not a gap in cleverness; FS signatures structurally do not
self-aggregate, classically or post-quantum.

---

## 2. Track A — forward from known mechanisms

**(a) Random-linear-combination batch verification.** With hash-derived small `e_i`,
`Σ_i e_i ( A_i z_i − c_i t1_i 2^d ) = Σ_i e_i w_i'` holds and Schwartz–Zippel/forking
gives soundness. This compresses *verifier work*, **not size**: every `A_i, z_i, c_i,
h_i` is still needed. Each `A_i` multiplies *its own* `z_i`; there is no single matrix.

**(b) The short vector is real.** `z_agg = Σ_i e_i z_i` with bounded-weight `e_i` is
genuinely short: `‖z_agg‖∞ ≤ (Σ_i ‖e_i‖_1)·γ1`, linear in M. Never disputed.

**(c) Folding with cross-term commitments (Bulletproofs/LaBRADOR style).** When you
collapse toward one object you incur cross terms (§3). The standard fix commits the
cross terms with short Module-SIS commitments (`L/R`), the verifier subtracts the
openings, completeness holds, and forking on the challenges extracts the leaf
witnesses. **What this builds is a self-contained PoK with a *relaxed*, ML-DSA-shaped
verifier** — its own check (linear relation + relaxed norm + hash-binding of the
residual). It is NOT the standard verifier: the extra openings are inputs the FIPS-204
verifier has no slot for, and (V1)/(V2) are not met (see §3). This is the strongest
object **public, non-interactive** aggregation of independent sigs can reach.

---

## 3. The two walls, derived (and why the transform domain cannot move them)

### Wall 1 — the matrix is pinned to a seed by a hash

To use the standard verifier you must hand it `pk* = (ρ*, t1*)`; it then computes
`A* = ExpandA(ρ*)`. So **`A*` is forced to be a hash expansion of one 32-byte seed.**
You cannot set `A* = Σ_i e_i A_i`, because that is not in the image of `ExpandA` (it is
a SHAKE output). The only way several signers can *share* matrix structure under the
standard verifier is to **share one `ρ`** (one global `A`). Distinct keys ⇒ distinct
`ExpandA(ρ_i)` ⇒ no single `A*` respects the products `A_i z_i`.

The cross terms make this concrete. Even ignoring Wall 1, forming `A_agg = Σ_i e_i A_i`
and `z_agg = Σ_j e_j z_j`:

```
A_agg · z_agg = Σ_{i,j} e_i e_j (A_i z_j)
              = Σ_i e_i^2 (A_i z_i)  +  Σ_{i≠j} e_i e_j (A_i z_j)
                 └ the part you want ┘   └ off-diagonal garbage ┘
```

The off-diagonal `A_i z_j` mix one signer's matrix with another's response; they are
full-norm and do not cancel. (Same failure in `(Σe_i c_i)(Σe_i t1_i)` vs the needed
`Σ e_i c_i t1_i`.)

**Does NTT / the convolution theorem dissolve this?** No — and this is worth being
exact about, since it was the motivating hope. NTT is a *ring isomorphism*
`R_q ≅ (F_q)^256` (or over an extension to get all roots), and it is **linear**. It
turns one convolution into pointwise products — wonderful for *speed* (this is exactly
why ML-DSA and FN-DSA compute in the transform domain). But per NTT slot `k`:

```
NTT(A_agg)[k] · NTT(z_agg)[k]
   = ( Σ_i e_i[k] A_i[k] ) ( Σ_j e_j[k] z_j[k] )
   = Σ_{i,j} e_i[k] e_j[k] A_i[k] z_j[k]      ← cross terms in EVERY slot
```

A linear, invertible change of basis cannot remove a **bilinear** mismatch: the map
`(A_i, z_j) ↦ A_i z_j` is quadratic in the data, and the obstruction is that we are
trying to express a *sum of M distinct products* as a *single product*. The convolution
theorem (its continuous cousin is the Laplace transform turning `f∗g` into `F·G`) helps
when you have **one** convolution to diagonalize; it does nothing when the problem is
that you have `Σ_i A_i ∗ z_i` and want `A_agg ∗ z_agg`. The control-theory framing
("treat each signer as a plant, design a compensator") is mathematically the same
linear-systems view and runs into the same fact: superposition holds within one LTI
channel, but the M signers are M *different* channels (different `A_i`), and no input
filter built from public data makes `Σ_i A_i z_i` equal `A_agg z_agg` for a single
seed-consistent `A_agg`. Transform domain is the right *implementation* tool, not a
soundness-barrier breaker.

### Wall 2 — norm growth vs. a fixed acceptance radius

Even with a shared `A` (Wall 1 satisfied), summing responses grows the norm:
`z_agg = Σ y_i + c·Σ s1_i` has `‖Σ y_i‖∞` up to `~M·γ1`, which violates (V1)
`‖z‖∞ < γ1 − β` for `M ≥ 2`. Schnorr/BLS have **no norm bound**, so their aggregates
stay valid; lattice FS-with-aborts has one, so aggregation either (a) enlarges `γ1`
(then it is an ML-DSA verifier with *different parameters*, not the deployed
ML-DSA-87), or (b) uses interaction + careful joint rejection sampling to keep the sum
in range for small M. This wall is pure arithmetic and, again, transform-invariant
(`‖·‖∞` is not simplified by NTT).

### The reduction (so this is a theorem, not an assertion)

A standard-verifier-accepting `(c̃*, z*, h*)` under `(ρ*, t1*)`, `μ*` is, in the ROM,
a short `z*` plus sparse `c*` with `c̃* = H(μ* ‖ HighBits(A* z* − c* t1* 2^d))` for
`A* = ExpandA(ρ*)`. For an honestly-derived `ρ*` (any combination of real seeds run
through a hash), `A*` is computationally MSIS-hard. Producing such `(z*, c*)` for a
fresh `μ*` without the trapdoor is precisely EUF-CMA forgery against `pk*`; embedding
the EUF-CMA challenge key as one component of the derivation turns any public,
non-interactive, distinct-key aggregator with this property into an ML-DSA forger.
Hence:

> **Trilemma (derived).** For aggregation of *independently produced, distinct-key*
> ML-DSA signatures you can have at most two of:
> **(1)** output accepted by the standard ML-DSA-87 verifier,
> **(2)** aggregation public & non-interactive,
> **(3)** unforgeability.
> The forbidden corner is `(1)+(2)+(3)` — it yields an MSIS solver.

What a genuine break would require (the exact lock to pick, if one insists): a public
map sending `{short z_i : A_i z_i ≈ u_i}` over **distinct** `A_i = ExpandA(ρ_i)` to a
single short `z*` with `ExpandA(ρ*) z* ≈ u*` and an FS-consistent sparse `c*` — i.e. a
norm-preserving homomorphism across independent hash-expanded matrices. That object
would itself break the MSIS/ROM structure ML-DSA's own security rests on. So the wall
is not borrowed from literature; it is the *same* assumption that makes ML-DSA a
signature at all.

---

## 4. What this BUYS us — the constructive results

The trilemma says *drop one corner*. Each drop is a real, buildable scheme.

### Path A (drop 1): public, non-interactive, unforgeable — **relaxed ML-DSA-shaped verifier**
This is LMSA-as-PoK: small-coefficient folding (`z_agg = Σ e_i z_i`) + per-level
Module-SIS cross-term commitments + hash-binding of the residual to the batch `S`.
Self-contained (extractor → leaf witnesses, no fraud window), recursively
re-aggregatable, PQ via Module-SIS, ~tens of KB. Verifier is *structurally* ML-DSA
(linear check → high-bits reconstruction → hash binding) but a thin new routine with
relaxed norm and the openings. **Best for: arbitrary distinct-key, distinct-message,
already-signed transactions.**

### Path B (drop 2): exact-shaped verifier under an aggregate key — **shared-`A` lattice multisignature**
Make `A = ExpandA(ρ)` a **global system parameter** (one `ρ` for the whole of QRL 2.0).
Then Wall 1 is gone. Signers run an interactive (2–3 round) protocol on a common
message: agree on joint commitment `w = A·Σy_i`, derive one challenge
`c = H(μ ‖ HighBits(w))` (sparse — satisfies V2/V3!), each returns `z_i = y_i + c s1_i`,
and the aggregate is `z* = Σ z_i = Σy_i + c·(Σ s1_i)` under aggregate key
`t1* = HighBits(Σ t_i)`, secret `s1* = Σ s1_i`. This is a *genuine* response to a
*sparse* challenge — (V2),(V3) hold by construction. Remaining cost is Wall 2: `‖z*‖∞`
grows with the number of signers, so you need joint rejection sampling and, for large
cohorts, an enlarged `γ1` (⇒ an ML-DSA verifier of a *new parameter set*, not byte-
identical FIPS-204). **Best for: many validators signing the same block / epoch
(consensus)** — the exact niche BLS fills in Ethereum, and where interaction is already
present. Satisfies "capabilities strictly derived from the keys" literally (`s1* =
Σ s1_i`; n-of-n grants no new power) and "the aggregate key is derived from and bounded
by the component keys."

### Path C (drop 2, non-interactive flavor): **synchronized aggregation**
If all signers share `A` *and* a per-slot common challenge derivation (e.g. one message
per round/epoch, `c` from the round's public data), responses can be combined with
small `e_i` without a live protocol, at the cost of the synchronization assumption and
the same Wall-2 norm budget. A middle point between A and B.

---

## 5. Mapping to QRL 2.0 (recommendation)

- **Consensus / validator set signing the same block** → **Path B (or C)**: a shared-`A`
  lattice multisignature is the true PQ analog of BLS-in-consensus, and the aggregate is
  verified by an ML-DSA-shaped verifier under an aggregate key. Decide explicitly whether
  "ML-DSA verifier" means *the algorithm at adjusted params* (achievable) or *the exact
  FIPS-204 ML-DSA-87 binary* (only for tiny cohorts within the norm slack).
- **Arbitrary user transactions (distinct keys, distinct messages, already signed)** →
  **Path A**: relaxed-verifier folding PoK. No interaction, succinct, recursive.
- A system can ship **both**: B for the validator layer, A for the tx layer.

## 6. "Can the proof be used as a key?"
The aggregate (residual + commitments) is a **capability object whose power is exactly
the collective signing ability of the inputs and no more** — it re-enters the next fold
(Path A) or is the aggregate key/signature (Path B), but it cannot sign anything the
original set could not jointly sign. It is *not* fresh secret-key material: public
aggregation yields combined *responses/commitments*, never new *trapdoors*. In Path B,
the derived `s1* = Σ s1_i` is a real aggregate secret, but it exists only as the
distributed sum across the signers — no single party (and no public aggregator) holds
it. That is the precise, sound reading of "used as a key": an aggregate **public** key
under which only the cohort, acting together, can sign.

---

## 7. Immediate next artifacts
1. **Path A folding step**, written out over `R_q`: exact relaxed relation, the
   cross-term (L/R) Module-SIS commitment, per-level norm accounting (ε-weight, fan-in),
   extraction sketch, and the standalone relaxed verifier. → Rust prototype proving
   honest completeness + measuring norms/sizes.
2. **Path B protocol**, written out: shared-`A` parameter generation, the 2–3 round
   joint-signing with norm-controlled rejection sampling, aggregate-key derivation, and
   the exact verifier parameters needed (and the max cohort size that stays inside
   ML-DSA-87's native `γ1`).
3. Fold in background-research concrete sizes (LaBRADOR cross-term costs, lattice
   multisig norm/round bounds) when the workflow lands.
