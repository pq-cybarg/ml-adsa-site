# ML-ADSA — Formal Specification (Construction F)

**Module-Lattice Aggregate Digital Signature Algorithm over ML-DSA-87**

Specification version 1.0 · authoritative reference for the scheme. Companion documents: the end-to-end
verification dossier (`docs/31`) and the publication / NIST-submission roadmap (`docs/32`). This document
is written in the structural style of NIST **FIPS-204** (ML-DSA) so that every object, algorithm, and
security claim maps onto the format a NIST PQC / additional-signatures / MPTC submission expects.

> Status note (honest): the scheme's security is established by 156 machine-checked lemmas (124 EasyCrypt
> + 32 Coq) across 31 prover artifacts, plus 6 Gobra code-level theorems (tallies reproducible via
> `formal/count-artifacts.sh`; see the cross-consistency audit `docs/35`), reducing to the same assumptions
> as ML-DSA, plus a CIRCL/go-qrllib-anchored
> reference implementation, KATs, and live demonstrations. It has **not** yet received independent
> third-party cryptanalysis; that is a prerequisite for standardization and is tracked in `docs/32`.

---

## 1. Scope and design goals

ML-ADSA is a **non-interactive, decentralized, trapdoor-free aggregate signature** scheme: many signers,
each holding an ordinary ML-DSA-87 key, jointly produce a **single, constant-size** signature `σ*` over a
common message that the **unmodified FIPS-204 verifier** accepts against an aggregate public key `pk*`.

Design constraints (all met):

- **Post-quantum.** Security reduces to Module-LWE (MLWE), Module-SIS, and SelfTargetMSIS — the *same*
  assumptions as ML-DSA — at NIST security **Category 5**, in both the ROM and the QROM.
- **No trapdoors, no trusted setup, no SNARK/STARK/ZK proof system, no TEE, no trusted/intermediary
  aggregator.** Every value the combiner needs is public; any party reconstructs the identical `σ*`.
- **Byte-compatible output.** `σ*` is a syntactically valid ML-DSA-87 signature (4627 bytes) and `pk*` a
  valid ML-DSA-87 public key (2592 bytes); verification is `ML-DSA.Verify` verbatim.
- **Many-time.** A long-lived master key signs an unbounded number of contents via per-content key
  refresh, with the per-signature security of single ML-DSA preserved (no aggregation-count blow-up).
- **Auditable / accountable.** An epoch key-tree commits each signer's per-content keys; provenance and
  fraud-detection layers attribute every contribution and detect equivocation.

### 1.1 Relationship to BLS aggregation (informative)

BLS aggregates by the **group product** `σ* = Π σᵢ` in a pairing group — a homomorphic operation that is
commutative and associative. ML-ADSA aggregates by **module summation** `z* = Σ zᵢ`, `t* = Σ tᵢ`,
`W* = Σ wᵢ` in the ring `R_q = Z_q[X]/(X²⁵⁶+1)` — the *same* homomorphic-aggregation algebra. This yields
the BLS-like properties: **order- and grouping-independence** and, for deterministic signers,
**byte-identical** aggregates regardless of how sub-aggregates were combined (§7.6). The one structural
difference: ML-DSA is a Fiat-Shamir-with-aborts scheme whose challenge `c̃*` binds the **entire**
participant commitment `W*`; consequently **finished aggregates cannot be merged** (BLS can) — aggregation
is a single-shot combine over the participants' contributions. ML-ADSA is thus *homomorphic but not
freely mergeable*. See `docs/29 §4.5–4.7` and the paper.

---

## 2. Notation and parameters

### 2.1 Base ring and ML-DSA-87 parameters (inherited verbatim from FIPS-204)

| Symbol | Value | Meaning |
|---|---|---|
| `q` | `8380417` (=2²³−2¹³+1) | modulus |
| `n` | `256` | ring degree; `R = Z[X]/(X²⁵⁶+1)`, `R_q = R/qR` |
| `(k, ℓ)` | `(8, 7)` | dimensions of the public matrix `A ∈ R_q^{k×ℓ}` |
| `η` | `2` | secret-key coefficient bound (`s1∈S_η^ℓ`, `s2∈S_η^k`) |
| `τ` | `60` | # of ±1 coefficients in the challenge `c` |
| `β` | `τ·η = 120` | |
| `γ1` | `2¹⁹` | nonce/`y` coefficient range |
| `γ2` | `(q−1)/32` | low-order rounding range |
| `(α, d, ω)` | `(2γ2, 13, 75)` | decompose modulus, `Power2Round` drop bits, max hint weight |
| `ζ` | `1753` | 512-th root of unity (NTT) |
| Public key | `2592` bytes | `pk = (ρ, t1)` |
| Signature | `4627` bytes | `σ = (c̃, z, h)` |
| Security category | **5** | core-SVP ≈ 2²⁸⁵ (MLWE) / 265-bit (MSIS) |

`SHAKE256`/`SHAKE128` are the FIPS-202 XOFs used by ML-DSA for `ExpandA`, `ExpandS`, `SampleInBall`,
`H = mu/challenge` derivation. `Power2Round`, `Decompose`, `HighBits`, `LowBits`, `MakeHint`, `UseHint`,
`pkEncode/Decode`, `sigEncode/Decode`, `w1Encode`, NTT/NTT⁻¹ are exactly as in FIPS-204.

### 2.2 ML-ADSA parameters

ML-ADSA adds no new lattice parameters; it reuses ML-DSA-87 verbatim (hence Category 5). It introduces:

| Symbol | Default | Meaning |
|---|---|---|
| `PRF` | `SHAKE256` keyed | pseudorandom function for key/nonce refresh (§4) |
| `Hmt` | `SHA3-256` (domain-separated) | collision-resistant hash for Merkle trees (§6) |
| epoch | `E ∈ {0,1,…}` | refresh epoch index |
| content label | `C` | predictable per-decision identifier (e.g. `(slot, committee)`) |
| domain tags | `"F.refresh","F.nonce","F.mt","F.kt","F.pop","F.onetime",…` | domain separation strings |

This document specifies **ML-ADSA-87** (Category 5). ML-ADSA-44 (Cat 2) and ML-ADSA-65 (Cat 3) are
defined identically over the corresponding ML-DSA parameter sets and are future deliverables (`docs/32`).

---

## 3. Objects

- **Master secret** `msk_i`: a 32-byte PRF seed (the only long-term secret of signer `i`).
- **Registration keypair** `(regsk_i, regpk_i)`: an ordinary ML-DSA-87 keypair used only to authenticate
  L2/L3 commitments (epoch roots, proofs-of-possession) — never to sign decisions directly.
- **Per-content signer** `sk_{i,C} = (s1, s2, t)`: derived deterministically from `msk_i` and content `C`.
- **Public per-content key** `t_{i,C} = A·s1 + s2 ∈ R_q^k`.
- **Aggregate public key** `pk* = (ρ, Power2Round(Σ_i t_{i,C}).t1)` — a valid ML-DSA-87 public key.
- **Aggregate signature** `σ* = (c̃*, z*, h*)` — a valid ML-DSA-87 signature.
- **Epoch key tree** `KT_{i,E}`: Merkle commitment to all of signer `i`'s `t_{i,C}` for the epoch's
  content range, with root signed by `regsk_i`.
- **Registry** `Reg`: the set of recognized signers `{(id_i, regpk_i, PoP_i)}`, summarized by `regRoot`.

---

## 4. Layer L1 — content-key refresh (many-time security)

All refresh is deterministic from the master seed; no per-signature randomness (RFC-6979/EdDSA style).

```
PRF(seed, label, content, outLen):                 # SHAKE256(seed ‖ label ‖ content), outLen bytes
ContentKeyDerive(msk, A, C):                        # → sk_{i,C} = (s1, s2, t)
    r   = PRF(msk, "F.refresh", C, 64)
    s1  = ExpandS_partial(r, 0 .. ℓ-1)             # each poly via 2-byte domain index, η-bounded
    s2  = ExpandS_partial(r, ℓ .. ℓ+k-1)
    t   = NTT⁻¹(A∘NTT(s1)) + s2
    return (s1, s2, t)

DeriveNonce(msk, C, σ):                             # deterministic masking nonce y ∈ R_q^ℓ
    for s in 0..ℓ-1:
        stream = PRF(msk, "F.nonce", C ‖ s, 4·256)
        y[s]   = centered( stream, range = 2σ+1 ) - σ     # γ1-style range; σ is the attempt index
    return y
```

**Soundness (F-C2):** distinct contents `C ≠ C'` yield independent keys/nonces, because `PRF` is a secure
PRF (modeled as a random oracle in the proofs); this is what makes aggregation across many contents safe.
**Many-time (F-C4, keystone):** the adversary's advantage is independent of the number of contents/queries
`Q`; each content is an independent single-ML-DSA instance.

**One-time discipline (N1/N2):** for a fixed `(signer, C)`, the nonce `y` is deterministic; signing two
*different* messages under the same `(signer, C)` would reuse `y` under two challenges and leak the secret.
Implementations MUST enforce at-most-once release per `(signer, C)` (durable, restart-safe; §9.3). With a
predictable content label `C = (slot, committee)`, this is exactly the one-attestation-per-slot rule, and
equivocation is both self-punishing (key leak) and externally slashable.

---

## 5. Layer L0 — the core aggregate and the §7.7 decentralized combine

### 5.1 Single-signer signing (reduces to ML-DSA)

`SignSingle` is ML-DSA-87 signing with the content-refreshed key and deterministic nonce; for one signer
the output is byte-identical to vanilla ML-DSA-87 over the same message/context.

### 5.2 Per-signer public contributions (round material)

```
ContentParts(A, msk, C, σ):                         # all public except sk
    sk = ContentKeyDerive(msk, A, C)
    y  = DeriveNonce(msk, C, σ)
    w  = NTT⁻¹( A ∘ NTT(y) )                        # commitment  w = A·y ∈ R_q^k
    return (sk, y, w)
ContentResponse(sk, y, ĉ):                          # z = y + c·s1     (only secret-dependent output)
    return [ y[s] + NTT⁻¹( ĉ ∘ NTT(sk.s1[s]) )  for s in 0..ℓ-1 ]
```

### 5.3 The decentralized combine (Construction F §7.7)

Given the participants' **public** `(t_{i,C}, w_{i,C}, z_{i,C})`, any party reconstructs the identical
`σ*` with **no secret and no privileged aggregator**:

```
Aggregate(A, ctx, msg, {(id_i, t_i, w_i, z_i)}):
    t*  = Σ_i t_i ;  (t1*, t0*) = Power2Round(t*) ;  pk* = pkEncode(ρ, t1*)
    W*  = Σ_i w_i
    μ   = H( H(pk*) ‖ ctx ‖ msg )                                     # FIPS-204 mu
    c̃* = H( μ ‖ w1Encode(HighBits(W*)) ) ;  ĉ = NTT(SampleInBall(c̃*))
    z*  = Σ_i z_i
    # public hint identity:  rr2 = A·z* − ĉ·t1*·2^d  (= W* − c·s2* + c·t0*, computable from public data)
    rr2 = NTT⁻¹(A∘NTT(z*)) − NTT⁻¹(ĉ ∘ NTT(t1*·2^d))
    h*  = MakeHint( −ĉ·t0* , rr2 )
    if ‖z*‖_∞ ≥ γ1−β  or  ‖ĉ·t0*‖_∞ ≥ γ2  or  weight(h*) > ω:  reject (retry with σ+1)
    if  UseHint(h*, rr2) ≠ HighBits(W*):  reject
    return σ* = sigEncode(c̃*, z*, h*)
```

`Aggregate` is **byte-identical** to the secret-key procedure (proved by `TestDecentralized_EqualsAggregateF`):
it merely sources `rr2` from the public identity `A·z* − c·t1*·2^d` instead of from the secret `s2*`. The
non-interactive 2-round flow is: (R1) each signer publishes `(t_i, w_i)`; everyone derives the same `c̃*`;
(R2) each signer publishes `z_i`; any party combines.

### 5.4 Verification

```
Verify(pk*, msg, σ*, ctx):  return  ML-DSA-87.Verify(pk*, msg, σ*, ctx)      # FIPS-204 verbatim
```

The verifier reconstructs `pk*` from the attesting signers' epoch-tree-committed `t_{i,C}` (§6), which are
public; it needs no per-signer interaction and no ML-ADSA-specific logic beyond summing the committed `t_i`.

---

## 6. Layer L2/L3 — epoch key tree, registry, proof-of-possession

### 6.1 Merkle commitment (domain-separated, F-C9)

```
mthLeaf(x)      = Hmt(0x00 ‖ x)
mthNode(l, r)   = Hmt(0x01 ‖ l ‖ r)
MerkleRoot(leaves) = root over pad-to-power-of-two(leaves)
ktLeaf(id, C, t)   = mthLeaf( lenPrefixed(id, C, encodeVecQ(t)) )
```

### 6.2 Epoch key tree (F-C8/C9, non-equivocation)

```
EpochKeyTreeBuild(msk, regsk, A, ρ, E, contents):
    for each C in contents:  leaf_C = ktLeaf(id, C, ContentKeyDerive(msk,A,C).t)
    root  = MerkleRoot({leaf_C})
    sigReg = SignSingle(regsk, ctx="F.kt", msg=frame("F.kt" ‖ E ‖ root))
    return KT = (root, sigReg, {C → (leaf index, audit path)})
```

A signer publishes `KT` at epoch start. A verifier accepts a per-content key `t_{i,C}` iff:
`VerifyEpochRoot(regpk_i, E, root, sigReg)` **and** `MerkleVerify(ktLeaf(id_i,C,t_{i,C}), idx, path, root)`.
This binds every `t_{i,C}` used in an aggregate to a single, registration-signed commitment — defeating
injected or equivocating keys (the H4 binding; §9.4).

### 6.3 Registry and proof-of-possession (F-C5, rogue-key defense)

Each signer registers `(id, regpk, PoP)` with `PoP = SignSingle(regsk, ctx="F.pop", msg=H("F.pop"‖id‖regpk))`.
`regRoot = MerkleRoot({mthLeaf(id‖regpk)})`. Signers failing PoP are not recognized; their weight is 0.

---

## 7. Decisions, decoys, and aggregate equivalence

### 7.1 Decision/aggregation modes (F-DEC)

The aggregate is decision-agnostic; tally policy is a layer above signature validity. Defined modes:
YES/NO (D1), multi-choice (D2), approval-sets (D3), threshold k-of-N (D4), subset-select N-of-M (D5),
weighted/homomorphic tally (D6). A sub-threshold aggregate is a *valid signature*; whether a decision is
enacted is a tally-layer predicate.

### 7.2 Decoys (privacy, ZKP-free) — F-C7

A decoy is a non-registered (invalid) signer whose registry weight is **0**, included to disguise the real
signer set via content refresh. Because recognized weight is determined by the public registry, decoys
cannot change any decision outcome (decision integrity, F-C7), and they require no zero-knowledge proof.
A separate optional hidden-value tally mode uses a homomorphic commitment `commit(v,r)=⟨B,r⟩+v·ONE`
(hiding = Module-LWE, proved; binding = Module-SIS).

### 7.3 Aggregate equivalence and partiality

Two aggregates are **equivalent** iff they are valid signatures certifying the same statement — same signer
set (same `pk*`) over the same message — *without* requiring byte-equality (ML-DSA is not unique-signature).
For deterministic signers over the same final set this strengthens to **byte-identity** (§7.6). A **partial**
aggregate is recognizable as such: `AggregationBits ⊊ committee` (the bits are cryptographically bound to
the actual signer set — an inflated bit set fails verification). See `docs/29 §4.5`.

### 7.6 Order/grouping independence (the BLS parallel, machine-relevant)

Because `pk*`, `W*`, `z*` are sums over a fixed multiset of `R_q` elements (associative + commutative under
mod-`q`), and nonces are deterministic, aggregating the same final signer set in any order or sub-group
partition yields **byte-identical** `pk*` and `σ*`. Sub-group "aggregate of aggregates" is associative
summation of partial sums. (Live multi-process proof: `cmd/mladsa-hieragg`.) This is the analogue of BLS's
order-independent group product; the difference is that the challenge binds the full `W*`, so finished
aggregates are not mergeable across *different* sets.

---

## 8. Security definitions and theorems

All games are over the same primitives as ML-DSA. Each theorem below is **machine-checked**; lemma names and
provers are in `docs/31` (the verification dossier). `Adv^X` denotes the adversary's advantage in game `X`.

### 8.1 Assumptions

- **MLWE** (decisional Module-LWE) — key indistinguishability; `Adv^MLWE ≤ adv_mlwe`.
- **SelfTargetMSIS** — fresh-challenge forgery hardness (FIPS-204's own assumption).
- **Module-SIS** — strong-unforgeability collision term.
- **PRF security** and **collision-resistant `Hmt`** — refresh independence and Merkle binding.

`pk*` is a bona fide ML-DSA-87 key: a sum of MLWE samples is an MLWE sample, so the aggregate inherits
Category-5 hardness exactly.

### 8.2 Core theorems (ROM)

- **T1 (EUF-CMA, keystone).** For any forger `A` with one honest signer and a signing oracle:
  `Adv^MSUFCMA(A) ≤ adv_mlwe + Adv^SelfTargetMSIS(B(A))` — a **tight** reduction to ML-DSA's two
  assumptions. *(EasyCrypt `ml_adsa_euf.ec : msufcma_uncond`, admit-free.)*
- **T2 (SUF-CMA).** `Adv^SUFCMA ≤ adv_mlwe + Adv^StrongSIS` (StrongSIS = SelfTargetMSIS ∨ Module-SIS for the
  same-`(μ,c)`-new-`(z,h)` collision). *(`ml_adsa_suf.ec : sufcma_uncond`.)*
- **T3 (rogue-key / A4).** `Pr[Rogue] ≤ Pr[SingleForge]` via PoP knowledge-soundness + key-agg linearity.
  *(`ml_adsa_rogue_proof.ec`.)*
- **T4 (no-new-power / A5).** A verifying aggregate extracts to per-member valid leaves or a Module-SIS
  solution: `Pr[NewPower] ≤ Pr[SISBreak]`. *(`ml_adsa_nnp_proof.ec` + Coq reconstruction identity.)*
- **T5 (many-time / F-C4).** `Adv` independent of `Q` via content refresh. *(`ml_adsa_F_manytime.ec`,
  `ml_adsa_F_refresh.ec`.)*
- **T6 (concurrent / ROS-resistance).** `Adv^concurrent = Adv^single-session` — no ROS/AGM/OMDL assumption,
  via commitment-bound unbiasable challenge. *(`ml_adsa_F_concurrent.ec`.)*
- **T7 (hiding).** Decoy/value hiding reduces to Module-LWE: `|Pr[H(v0)]−Pr[H(v1)]| ≤ 2·adv_mlwe`.
  *(`ml_adsa_F_hiding.ec`.)*
- **T8 (decision integrity / F-C7).** Weight-0 decoys cannot bias an outcome. *(Coq `ml_adsa_F_decisions.v`,
  EC.)*
- **T9 (equivalence-class hardness).** Producing **any** member of `{σ : Verify(pk*,m,σ)}` for an
  un-queried `m` is an EUF-CMA win, so it inherits T1's bound — the multiplicity of valid signatures gives
  the adversary **no** advantage; bits = Category 5. *(`ml_adsa_euf.ec : equiv_class_guess_bound`.)*

### 8.3 Post-quantum theorems (QROM)

- **T10 (QROM EUF-CMA, Construction A — tight).** `Adv^{QROM-EUFCMA} ≤ adv_mlwe + Adv^{QROM-SelfTargetMSIS}`
  with **no** reprogramming/O2H loss for the perfect-masking construction. *(`ml_adsa_qrom.ec :
  qrom_eufcma_uncond`.)*
- **T11 (QROM EUF-CMA, Construction B — lossy).** A self-contained capstone keeping the masking +
  adaptive-reprogramming loss explicit. *(`ml_adsa_qrom.ec : qrom_eufcma_lossy`.)*
- **T11′ (DERIVED distinct-per-query GHHM21 reprogramming bound).** The Construction-B reprogramming
  loss is now derived, not imported: `reprog_ghhm qs qh = qs·(qh+1)/|from|` (tight, linear), built from
  the **proven** per-round perfect-resampling equivalence (`FunSamplingLib.LambdaReprogram.main_theorem`,
  advantage 0 — the tightness mechanism of GHHM21) composed with the elementary distinct-query search
  bound (`T_QROM.T_Distinct.bound_distinct`, Thm 6.1) over qs distinct commitment points. *(`ml_adsa_qrom_ghhm.ec :
  ghhm_hybrid`, `reprog_single_perfect`, `distinct_detect_bound`, `reprog_ghhm_ge0`.)* This **replaces**
  importing the whole Zhandry semi-constant-distribution reprogramming theorem `(2q+2)⁴/6·λ²` as an
  axiom; that coarser bound is retained only as a cross-check (`ml_adsa_qrom_reprog.ec : reprog_at_our_types`).
- **T12 (QROM equivalence-class hardness).** The quantum analogue of T9. *(`ml_adsa_qrom.ec :
  qrom_equiv_class_uncond`.)*

**Residual (honest).** Nothing about the *bound* is assumed: the per-round hypothesis of `ghhm_hybrid` is
discharged by `ghhm_multiround_perfect` (hypothesis-free) — `reprog_single_perfect` proves each resampling
round's gap is exactly 0, so the qs-round total is 0, within budget. The **signing-round program-equivalence**
(real-RO signer ~ reprogramming HVZK simulator) is itself machine-checked — `ml_adsa_qrom_ghhm.ec :
reprog_round_equiv` / `reprog_round_pr_eq` (concrete `ReprogRound` modules, advantage 0). The remaining
input — the lattice response `z = y + c·s1` being HVZK-simulatable — is **not a gap and not
aggregation-specific**: it is ML-DSA's *own* perfect-HVZK property `masking_ok` (= `masking_perfect`),
whose consequences are machine-checked classically (`zero_leakage_perfect_A`, admit-free) **and** quantumly
(`sq_perfect`), with the aggregate→single-signer reduction also machine-checked (`F_zk_per_content` F-C13,
`session_simulatable`). Moreover the **rejection-sampling change-of-variables that underlies it is now
DERIVED from first principles** in `ml_adsa_masking.ec` (`reject_uniform`, `masking_perfect_concrete`):
the accepted response is uniform on the norm window, independent of the secret shift, resting only on
`0 ≤ β ≤ γ1-1`. The only thing left to the shared lattice-arithmetic boundary is the bit-level NTT/rounding
*functional correctness* (byte-cross-checked against two FIPS-204 implementations). Standing axioms on the
reprogramming path: the elementary distinct-query bound (Thm 6.1) and `LambdaReprogram.Ynontriv`. Off the
critical path for Construction A (perfect masking, `reprog = 0`). See `docs/14`, `docs/32`.

---

## 9. Implementation requirements

### 9.1 Reference implementation

The Go reference implementation (`go-mladsa/`, vendored byte-identically into the QRL 2.0 `qrysm` fork) is
cross-checked against **CIRCL** and **theQRL/go-qrllib** as FIPS-204 anchors: every aggregate is a
byte-exact `(pk 2592, sig 4627)` triple their unmodified verifiers accept.

### 9.2 Input validation (mandatory)

- `Verify` MUST reject wrong-length `pk`/`sig` before decoding (DoS hardening).
- Any deserialized `R_q` vector MUST be shape/range-validated (`len`, coeff `∈ [0,q)`) before entering NTT/sum.
- A committed `t_{i,C}` MUST be (a) authenticated via `VerifyEpochRoot` and (b) proven member via
  `VerifyContentInTree` before contributing to `pk*` (the H4 binding).

### 9.3 One-time state (mandatory, security-critical)

Implementations MUST maintain a durable, fsync'd, mark-before-sign used-set keyed by
`SHAKE256("F.onetime" ‖ lenPrefixed(id, C))` so that a `(signer, C)` is never signed twice across restarts
(prevents deterministic-nonce reuse → key recovery).

### 9.4 Constant-time / side-channel

Secret-dependent operations (key refresh, response `z = y + c·s1`) MUST be constant-time; verification is on
public data and need not be. A full side-channel analysis + optimized constant-time implementation is a
standardization deliverable (`docs/32`).

---

## 10. Known-answer tests and conformance (ACVP-aligned)

### 10.1 KATs (present)

Deterministic KATs are pinned under fixed conditions (fixed `ρ`, fixed PCG seed; `AggregateF` uses
deterministic PRF nonces so outputs are reproducible): primitive KATs (`ContentKeyDerive`, `DeriveNonce`,
`ExpandS`, `MerkleRoot`), aggregate KATs (`pk*`/`σ*` pinned for `N = 1, 4, 16, 64, 128`), and **rotation**
KATs (subsequent contents → distinct fresh aggregates, per-content keys independent, reuse refused — the
no-leak property). Cross-implementation conformance: the standalone (CIRCL) and qrysm (go-qrllib) copies
produce identical hashes. See `docs/25`.

### 10.2 Conformance test types (to produce for submission)

| ACVP-style test | Status |
|---|---|
| keyGen (master → registration; deterministic) | KAT present; ACVP-JSON format TODO |
| contentKeyDerive / nonceDerive | KAT present |
| aggSigGen (N-signer combine) | KAT present (`N=1..128`) |
| aggSigVer (accept/reject, malformed-input) | tests present |
| epochTree (build/verify/membership) | tests present |
| rotation/no-leak | KAT present |
| ACVP-style JSON vector files | **DONE** — `vectors/` (generated by the reference impl, digests match the pinned KATs); official ACVP registration + exact prompt/expectedResults wire-split still TODO |
| measured benchmarks + size/compression | **DONE** — `docs/33` |

---

## 11. Conformance statement

An implementation conforms to ML-ADSA-87 v1.0 iff: (a) it produces aggregates accepted byte-for-byte by an
unmodified FIPS-204 ML-DSA-87 verifier against the reconstructed `pk*`; (b) it matches the pinned KATs
(§10.1); (c) it enforces the mandatory validation (§9.2), one-time state (§9.3), and epoch-tree binding
(§6.2/9.4). The authoritative algorithm definitions are §§4–6; the authoritative security claims are §8 with
machine-checked evidence enumerated in `docs/31`.

---

## Appendix A — algorithm index → code → proof (summary; full matrix in docs/31)

| Algorithm/property | Code (Go) | Machine-checked |
|---|---|---|
| ContentKeyDerive / DeriveNonce | `refresh.go` | F-C2/C4 (`ml_adsa_F_refresh.ec`, `ml_adsa_F_manytime.ec`) |
| Aggregate / CombineFromPublic | `mladsa.go`, `decentralized.go`, `consensus.go` | T1/T2 (`ml_adsa_euf.ec`, `ml_adsa_suf.ec`), Coq identity |
| Verify (= FIPS-204) | `mldsa87.go` | T1/T10 |
| EpochKeyTree | `construction_f.go`, `merkle.go` | F-C8/C9 (`ml_adsa_F_provenance.v`, EC) |
| One-time guard | `onetime_durable.go` | N1 (Gobra `integrity.go`) |
| Decisions/decoys | `decoy.go`, `construction_f.go` | F-C7/F-DEC (Coq + EC) |
| QROM security | — | T10–T12 (`ml_adsa_qrom*.ec`) |

*End of specification v1.0.*
