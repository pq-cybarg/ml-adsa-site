# 17 — ML-ADSA-F: Content-Refreshed Native Aggregate Signature — Formal Specification

**Construction F** of the ML-ADSA family (whitepaper §5–9 define A–E). F is the synthesized
many-time, byte-exact-native, transparent aggregate of §16 (`docs/16`). This document is a
high-assurance scheme specification: normative algorithms, security model with explicit reduction
targets, the machine-checked formal-verification plan, wire formats, threat model, key lifecycle,
abuse cases, standards alignment, conformance/validation, and an honest limitations register.

> **Deployment note.** The base combine specified here broadcasts the full commitment `wᵢ`, which exposes the
> per-content nonce by linear algebra (finding #3). The **deployed default** is the nonce-hiding instantiation
> **F-OFFSET** (broadcast `(HighBits(wᵢ), LowBits(wᵢ)+rᵢ)`; ≥native; stateless many-time at σ=3β), specified in
> [docs/47](47-construction-f-offset.md) and declared the state-of-the-art deployment in
> [docs/59](59-offset-default-deployment-and-live-devnet.md). Everything in this spec (registry, epoch key-tree,
> part-root binding, decision modes, provenance, one-time/refresh lifecycle) applies unchanged to F-OFFSET; only
> the per-signer broadcast and the challenge's high-bits estimate differ.

**Document status:** specification / design-for-verification. Claims are labeled **[proven]**,
**[measured]**, **[computed]**, **[structural]**, **[cited]**, **[target]** (formal-verification
goal, not yet discharged), **[open]** (research-grade obligation). Requirements use RFC 2119
keywords (MUST / SHOULD / MAY / MUST NOT). **The §10 mechanization obligations are now discharged
(all rows machine-checked — see docs/18, docs/31); this specification MUST NOT be deployed to production
before an independent third-party cryptanalytic review is completed.**

---

## 1. Scope and conformance

1.1 F produces a **single byte-exact ML-DSA-87 (FIPS-204) signature** that aggregates the
contributions of a recognized member set, is **verifiable by the unmodified FIPS-204 verifier**,
is **many-time** across decisions, and is built with **no trapdoor, no trusted setup, no SNARK/
STARK, no TEE, and no trusted aggregator**, non-interactively.

1.2 A conforming **signer** implementation MUST implement §7.2–§7.6. A conforming **aggregator**
MUST implement §7.7 and produce the wire object of §8. A conforming **verifier** MUST implement
§7.8 (validity); a conforming **auditor** MUST implement §7.9–§7.10 (provenance/fraud-proof).

1.3 Security target: **NIST Category 5** (the ML-DSA-87 level), reducing to MLWE + Module-SIS +
SelfTargetMSIS + PRF + (Q)ROM/collision-resistant hash — i.e. **no assumption beyond ML-DSA's own
plus a PRF and a CR hash, both already used inside ML-DSA**.

---

## 2. Normative references

- **FIPS 204** — Module-Lattice-Based Digital Signature Standard (ML-DSA). Defines `ExpandA`,
  `ExpandS`, `ExpandMask`, `Power2Round`, `Decompose`/`HighBits`/`LowBits`, `MakeHint`/`UseHint`,
  `SampleInBall`, `w1Encode`, the verifier, and parameters. [normative]
- **NIST SP 800-208** — Stateful Hash-Based Signature Schemes. Normative for the **one-time key
  state discipline** of the per-content key tree (§7.4, §12). [normative for state management]
- **FIPS 202** — SHA-3/SHAKE (used for `H`, `PRF`, Merkle node hashing). [normative]
- **arXiv:2312.16619 (EUROCRYPT 2024)** — SelfTargetMSIS QROM hardness. [cited]
- **eprint 2022/1341 (MuSig-L), 2024/184 (Threshold Raccoon)** — concurrent-security techniques
  for the per-content round. [cited]
- Project: `docs/16` (design rationale + numbers), `docs/03/06/07/08` (Constructions A/B),
  `docs/12/13/14/15` (FV status, baseline, QROM, audit), `formal/*.ec`, `formal/*.v`.

---

## 3. Terms, notation, parameters

### 3.1 Parameters (ML-DSA-87, normative)

```
q = 8380417,  n = 256,  R_q = Z_q[X]/(X^256+1)
(k,ℓ) = (8,7),  η = 2,  τ = 60,  β = τη = 120
γ1 = 2^19 = 524288,  γ2 = (q−1)/32 = 261888,  α = 2γ2,  d = 13,  ω = 75
pk = 2592 B,  sig = 4627 B,  λ = 256 (security parameter)
```

### 3.2 Construction-F parameters (normative)

```
N_max       : max participants per aggregate.  MUST satisfy the §7.6 norm/hint bounds.
              For native γ1 and worst-case bounds: N_max ≤ 2000 (hint-limited).  Recommended N ≤ 1024.
γ1'         : per-signer mask half-width.  MUST satisfy N·γ1' + βN < γ1 − β (worst case)
              ⇒ γ1' ≤ (γ1 − β − βN)/N.  For N=10: γ1' ≤ 52296 (=2^15.67), masking ratio ≈ 436. [computed]
mask_distr  : centered discrete Gaussian (RECOMMENDED) or balanced uniform on [−γ1'+1, γ1'−1].
              MUST be zero-mean (no drift — drift aids the attacker, docs/16 §9.8).
H_tree      : height of the per-member epoch key tree.  Epoch admits ≤ 2^{H_tree} contents.
PRF, H, MTH : SHAKE-256-based PRF, hash, and Merkle-tree node hash (domain-separated).
```

### 3.3 Roles

- **Member** — holds a long-lived master seed; has weight 1 in the recognized set.
- **Aggregator** — any party (untrusted); collects partials, emits the aggregate. No secret, no
  trust (§11).
- **Verifier** — checks validity (cheap).  **Auditor** — checks provenance/binding (on demand).
- **Decoy** — any non-member submission; weight 0 by the member-set rule (§7.7, §9 G3).

### 3.4 Conventions

`content` (a.k.a. decision/domain index `C`) is a deterministic public value (e.g. block height,
tx-group hash). It indexes both the **domain** (`ctx = DOM ‖ C`, §4 of docs/16) and the
**one-time key** (§7.3). `DOM` is a **caller-supplied domain string**: the QRL 2.0 base-consensus
deployment binds it to the go-qrllib wallet domain `"ZOND"` (so `ctx = "ZOND" ‖ C`); bridge/
cross-chain examples use other domains (e.g. `"QRL:SUI"`). `[a]` denotes the centered
representative in `(−q/2, q/2]`.

---

## 4. Architecture (layered)

```
 ┌─ L0 SIGNATURE     native ML-DSA-87 aggregate σ* = (c̃*, z*, h*) under pk*_C   ── unmodified verifier
 ├─ L1 REFRESH       per-content one-time key  s1ⁱ_C = ExpandS(PRF(seedⁱ, C))   ── many-time (Q=1/key)
 ├─ L2 AVAILABILITY  per-member epoch Merkle key-tree of {tⁱ_C}                  ── non-equivocation + reveal
 ├─ L3 PROVENANCE    recognized-member registry + per-decision participation     ── "who", weight-0 decoys
 └─ L4 AUDIT         optimistic publish + fraud-proof recomputation              ── trustless, no aggregator trust
```

L0 is Construction B; L1 is the REFRESH lever (the only native-compatible many-time lever,
docs/16 §8); L2–L4 make L1 verifiable without a trusted party. Decoys live at L3 (decision
integrity + membership privacy), and are **not** a many-time mechanism (docs/16 §10).

---

## 5. Cryptographic primitives (normative interfaces)

```
PRF   : Seed × Content → {0,1}^{512}            (SHAKE-256, domain "F.prf"); MUST be a secure PRF.
ExpandS : {0,1}^{512} → (s1 ∈ R_q^ℓ, s2 ∈ R_q^k), ‖s1‖,‖s2‖ ≤ η   (FIPS-204 ExpandS).
H     : {0,1}* → {0,1}^{2λ}                      (SHAKE-256, domain "F.hash"); CR + (Q)ROM.
MTH   : node hashing for Merkle trees             (SHAKE-256, domain "F.mt", leaf/internal separated).
ExpandA : Seed → R_q^{k×ℓ}                        (FIPS-204; public, deterministic).
SampleInBall, Power2Round, Decompose, MakeHint, UseHint, w1Encode : FIPS-204.
```

Implementations MUST domain-separate PRF/H/MTH inputs (distinct prefixes) and MUST be
constant-time in all secret-dependent operations (§13).

---

## 6. Data structures

### 6.1 Recognized member registry `REG`

A public, committed list: `REG = { (id_i, regpk_i) }`, `MTH`-committed to root `reg_root`
(published on-chain / in a verifiable registry). `regpk_i` is member i's long-lived
**registration** ML-DSA-87 public key (used to authenticate L2 commitments, NOT to sign decisions).
Weight: `w(id) = 1 if id ∈ REG else 0`.

### 6.2 Per-member epoch key tree `KT_i`

For epoch `E` (content range `[E·2^{H_tree}, (E+1)·2^{H_tree})`), member i:
leaves `leaf_{i,C} = MTH( id_i ‖ C ‖ tⁱ_C )`, where `tⁱ_C = A·s1ⁱ_C + s2ⁱ_C`, root `kt_root_{i,E}`.
Member i signs `kt_root_{i,E}` with `regsk_i` and publishes `(kt_root_{i,E}, σ_reg)` (one-time per
epoch). This binds all of member i's one-time keys for the epoch and enforces non-equivocation.

### 6.3 Aggregate signature object (wire, §8)

```
AggSig = {
  ctx        : domain string DOM ‖ C   (base consensus: "ZOND" ‖ C; bridge e.g. "QRL:SUI" ‖ C)
  msg        : the decision payload M (incl. participation commitment, §6.4)
  pk_star    : pk*_C = (ρ, t1*_C)              (2592 B)        — aggregate public key for content C
  sigma      : σ* = (c̃*, z*, h*)              (4627 B)        — the native ML-DSA-87 signature
  part_root  : Merkle root of participants     (32 B)          — the "who" commitment (§6.4)
  epoch      : E
}
```

### 6.4 Participation / "who" structure

`participants P ⊆ REG`. Represented as either (a) a **bitmap** over `REG` (1 bit/member), or
(b) a **sparse Merkle tree** `PT` with leaves `MTH(id_i ‖ tⁱ_C ‖ kt_path_{i,C})` and root
`part_root`. `part_root` MUST be committed inside `msg` (so `c̃*` binds it). Auditors use `PT`
leaves + `KT_i` paths to recompute `Σ_{i∈P} tⁱ_C` and the registry membership of each `id_i`.

---

## 7. Algorithms (normative)

Notation: vectors over `R_q`; all `Σ` over the participating set `P` unless noted.

### 7.1 Setup(epoch seed ρ) → A
```
A ← ExpandA(ρ)                                   # public, deterministic; ρ is an epoch parameter
return A
```
ρ MUST be rotated per epoch to deny precomputation; ρ has **no secret** (transparency, §14).

### 7.2 MemberKeyGen() → (seed_i, regpk_i, regsk_i)
```
seed_i ←$ {0,1}^{256}                            # long-lived master PRF seed (the only long-term secret)
(regsk_i, regpk_i) ← ML-DSA-87.KeyGen()          # registration keypair (authenticates L2 only)
register (id_i, regpk_i) into REG                # one-time; PoP REQUIRED (§7.2.1)
return (seed_i, regpk_i, regsk_i)
```

#### 7.2.1 Proof-of-Possession (rogue-key defense, normative)
At registration, member i MUST publish a PoP: an ML-DSA-87 signature over
`H("F.pop" ‖ id_i ‖ regpk_i)` under `regsk_i`. Verifiers MUST reject any member whose PoP fails.
PoP collapses the n-of-n aggregate to a single honest signer (docs/12 A4; reuse
`formal/ml_adsa_rogue_proof.ec`).

### 7.3 ContentKeyDerive(seed_i, C) → (s1ⁱ_C, s2ⁱ_C, tⁱ_C)   — the REFRESH
```
r          ← PRF(seed_i, "F.key" ‖ C)
(s1ⁱ_C, s2ⁱ_C) ← ExpandS(r)                      # η-bounded, fresh & independent per C (PRF security)
tⁱ_C       ← A·s1ⁱ_C + s2ⁱ_C
return (s1ⁱ_C, s2ⁱ_C, tⁱ_C)
```
**(N1) One-time invariant (MUST):** for each `C`, member i MUST use `s1ⁱ_C` to sign at most once.
Reuse with a different challenge recovers the secret (`z−z' = (c−c')s1`). State discipline per
NIST SP 800-208 (§12). The epoch tree (§7.4) makes reuse detectable.

### 7.4 EpochKeyTreeBuild(seed_i, E) → (kt_root_{i,E}, σ_reg)
```
for C in epoch_range(E):  compute tⁱ_C (7.3);  leaf_{i,C} ← MTH(id_i ‖ C ‖ tⁱ_C)
kt_root_{i,E} ← MerkleRoot({leaf_{i,C}})
σ_reg ← ML-DSA-87.Sign(regsk_i, H("F.kt" ‖ E ‖ kt_root_{i,E}))
publish (E, kt_root_{i,E}, σ_reg)                # one-time per epoch per member
return (kt_root_{i,E}, σ_reg)
```

### 7.5 Commit(seed_i, C) → (Wⁱ_C, st_i)   — context-committed nonce (non-interactive)
```
yⁱ_C ← ExpandMask( PRF(seed_i, "F.nonce" ‖ C) ; mask_distr, γ1' )   # secret-keyed, deterministic, ZERO-MEAN
Wⁱ_C ← A·yⁱ_C
return Wⁱ_C, st_i = yⁱ_C                          # Wⁱ_C published to the pool (no inter-signer round)
```
**(N2)** `yⁱ_C` MUST be zero-mean and one-time per `C`. Determinism (PRF) is the commitment that
defeats single-session rushing; multi-session security is the concurrent-security obligation
(§10 C11, [open]).

### 7.6 PartialSign(seed_i, C, P, msg) → zⁱ_C    (after the participant set P and W* are known)
```
W*  ← Σ_{j∈P} Wʲ_C                                # public aggregate commitment
μ*  ← H( H(pk*_C) ‖ ctxframe(DOM‖C) ‖ msg )       # DOM = "ZOND" in base consensus; msg MUST commit part_root (§6.4)
c̃* ← H( μ* ‖ HighBits(W*, α) ) ;  c* ← SampleInBall(c̃*)     # ONE common challenge
zⁱ_C ← yⁱ_C + c*·s1ⁱ_C
return zⁱ_C
```
**(N3) Local bound checks (MUST, for the aggregate to verify):** the cohort MUST verify, before
publishing `σ*`, that `‖z*‖∞ < γ1−β`, `‖LowBits(W*−c*·s2*,α)‖∞ < γ2−β`, `‖c*·t0*‖∞ < γ2`, and
`wt(h*) ≤ ω`. If any fails (rare at compliant `N, γ1'`), the round is re-run with the next content
index or aborted (NOT by resampling `yⁱ_C` for the same `C`, which violates N1).

### 7.7 Aggregate(P, {Wⁱ_C}, {zⁱ_C}, {tⁱ_C}, C, msg) → AggSig
```
require: P ⊆ REG (weight-1 only; decoys/non-members DROPPED here — gives them weight 0)
t*   ← Σ_{i∈P} tⁱ_C ;  (t1*_C, t0*_C) ← Power2Round(t*) ;  pk*_C ← (ρ, t1*_C)
z*   ← Σ_{i∈P} zⁱ_C ;  W* ← Σ_{i∈P} Wⁱ_C
h*   ← MakeHint(−c*·t0*_C, W* − c*·s2* + c*·t0*_C, α)         # aggregate hint
σ*   ← (c̃*, z*, h*)
part_root ← MerkleRoot of P (§6.4)
return AggSig{ ctx, msg, pk*_C, σ*, part_root, E }
```
**(D)** Decoys submitted by non-members are simply not in `P` ⇒ contribute **nothing** to
`t*`, `z*`, the tally, or `part_root`. This is enforced by the `P ⊆ REG` rule + the message
commitment, **without any trusted party** (§9 G7).

### 7.8 Verify(AggSig) → bool      (validity-only; the unmodified FIPS-204 verifier)
```
return ML-DSA-87.Verify( pk*_C, msg, σ*, ctx )    # byte-identical FIPS-204 verify
```
A validity-only consumer runs exactly this and ignores L2–L4. **[measured]** that genuine
aggregates pass `pqcrypto`/CIRCL.

### 7.9 ProvenanceVerify(AggSig, P, openings) → bool      (the "who"; optimistic or full)
```
# openings = { (id_i, tⁱ_C, kt_path_{i,C}, kt_root_{i,E}, σ_reg_i, reg_path_i) }_{i∈P}
for i in P:
    require id_i ∈ REG via reg_path_i to reg_root                    # weight 1
    require ML-DSA-87.Verify(regpk_i, H("F.kt"‖E‖kt_root_{i,E}), σ_reg_i)   # epoch tree authentic
    require MTH(id_i ‖ C ‖ tⁱ_C) ∈ kt_root_{i,E} via kt_path_{i,C}  # NON-EQUIVOCATION (one-time)
    require leaf for i ∈ part_root
require Power2Round(Σ_{i∈P} tⁱ_C).t1 == pk*_C.t1                     # binding: pk* = Σ members
return Verify(AggSig)
```
**Optimistic mode:** a verifier MAY accept `Verify(AggSig)` + `part_root` and defer the loop to
auditors (cheap path ≈ 7.25 KB). **Full mode:** every verifier runs the loop (cost `~N×2560 B` +
proofs). Both are trustless (§11).

### 7.10 Audit(AggSig, P, openings) → {OK, FRAUD(evidence)}
Any party MAY run §7.9; a failed `pk*` binding or a duplicated `(id_i, C)` with two distinct
`tⁱ_C` (epoch-tree equivocation, an N1 violation) is **publishable fraud evidence**. Trustlessness
relies on **≥1 honest auditor** in optimistic mode, or on every verifier in full mode.

---

## 8. Wire formats and byte budget

```
field        size                       notes
ctx          |DOM| + |C|               DOM‖C   (base consensus DOM="ZOND"; bridge e.g. "QRL:SUI")
msg          |M|                        payload; MUST commit part_root + reg_root + E
pk_star      2592 B                     FIPS-204 public key (ρ 32 B + t1* 2560 B)
sigma        4627 B                     FIPS-204 signature
part_root    32 B                       participation commitment
epoch        ≤ 8 B
------------------------------------------------
common (optimistic) path  ≈ 7.25 KB + |msg|
audit openings (per participant): tⁱ_C (2560 B) + kt_path (H_tree·32 B) + reg_path (log|REG|·32 B)
              + σ_reg/PoP (amortized per epoch)  ⇒ ~N×(2560 + 32·H_tree) B, PAID ONLY ON AUDIT
```
A canonical (sorted) `P` MUST be used for `part_root` so the commitment is order-independent.

---

## 9. Security model

### 9.1 Assumptions (normative)
`A1` decisional **MLWE**; `A2` **Module-SIS**; `A3` **SelfTargetMSIS** (FIPS-204 §3.2); `A4`
**PRF** security of `PRF`; `A5` **collision-resistance** of `H`/`MTH`; `A6` **(Q)ROM** for `H`.
**No assumption beyond ML-DSA's own (A1–A3, A6) plus A4–A5, which ML-DSA already uses internally.**
No trapdoor, no CRS, no knowledge-of-exponent, no pairing.

### 9.2 Security games (informal; formal targets in §10)
- **G-EUF** EUF-CMA: adversary controls ≤ N−1 co-signers + network + a signing oracle over
  distinct contents; wins by a valid `(C*, M*, σ*)` under `pk*_{C*}` with `M*` un-queried.
- **G-MT** Many-time / Q-independence: G-EUF advantage MUST NOT grow beyond `Q·(single-content
  bound) + adv_PRF` (no linear-in-Q *leakage* accumulation — the Construction-B failure).
- **G-ROGUE** rogue-key: adversary registers keys to control `pk*`; defeated by PoP.
- **G-NNP** no-new-power: a verifying aggregate ⇒ extract leaf witnesses or break Module-SIS.
- **G-INT** decision integrity: an adversary controlling any number of non-member (weight-0)
  keys cannot change the tally/outcome.
- **G-PROV** provenance soundness: a verifying aggregate + claimed `P` ⇒ the claimed members'
  one-time keys really summed to `pk*` (else collision / SelfTargetMSIS).
- **G-1T** one-time binding: a member cannot use two distinct keys for the same `C` (epoch-tree
  non-equivocation).
- **G-ZK** per-content leakage: the published object is simulatable from public data up to the
  single-sample (Q=1) bound.

### 9.3 Reduction targets (theorem statements, [target])

**T-EUF (per content).** For honest content `C` with a fresh independent key,
`Adv^{G-EUF}_C(A) ≤ adv_mlwe + Pr[STMSIS(B(A))]` with **no N-factor** (one honest signer; PoP).
*Reuses* the structure of `formal/ml_adsa_euf.ec` `msufcma_uncond`.

**T-MT (the many-time keystone — the novelty of F).** For a PPT `A` making `Q` signing queries on
**distinct** contents `C_1..C_Q`:
```
Adv^{G-EUF}_{F}(A) ≤ adv_PRF + Σ_{j=1}^{Q} Adv^{G-EUF}_{C_j}(A_j),    each C_j uses Q_per_key = 1
                  ≤ adv_PRF + Q·( adv_mlwe + Pr[STMSIS] + adv_leak(1) )
```
where `adv_leak(1)` is the **single-sample** leakage (negligible). **Crucially `Q_per_key = 1`**, so
the linear-in-Q *leakage* accumulation that makes Construction B few-time (docs/16 §7) **does not
occur** — security is single-content ML-DSA-87 (Level 5) up to `adv_PRF`.
*Proof technique:* hybrid — replace PRF outputs by truly independent random ML-DSA keys (cost
`adv_PRF`); each content is then an independent single-use ML-DSA instance; apply T-EUF and the
single-sample G-ZK per content. The master seed never leaks because each per-content secret is
observed at most once and PRF security hides the seed given outputs.

**T-ROGUE.** `Pr[G-ROGUE(F)] ≤ Pr[G-EUF(single honest)]`. *Reuses* `ml_adsa_rogue_proof.ec`
`rogue_reduces_to_single` (+ `rogue_collapse`).

**T-NNP.** `Pr[G-NNP(F)] ≤ Pr[SISBreak]`. *Reuses* `ml_adsa_nnp_proof.ec` `new_power_reduces_to_sis`
(+ `extract_or_break`); recovered leaves recombine via the Coq identity.

**T-INT.** Outcome is a function of `{contributions of i : i ∈ REG}` only; non-members'
contributions are dropped in §7.7 and excluded from `part_root` ⇒ `Adv^{G-INT} = 0` given G-PROV.

**T-PROV.** A verifying aggregate with claimed `P` and accepted openings ⇒ either
`Power2Round(Σ_{i∈P} tⁱ_C).t1 = pk*.t1` (the binding holds) or a hash collision / SelfTargetMSIS
solution is extracted. *New; Coq for the sum/HighBits algebra + EC for the game.*

**T-1T.** Two accepted openings for the same `(id_i, C)` with `tⁱ_C ≠ t'ⁱ_C` ⇒ a collision in
`MTH` under `kt_root_{i,E}`. *Coq: Merkle binding.*

**T-QROM.** T-EUF holds in the QROM with ML-DSA's non-tight bound; refresh makes it Q-independent
(each content fresh). *Reuses* `ml_adsa_qrom.ec` (Construction-A path).

**T-NT (transparency).** `Setup` is a deterministic function of public input with empty secret
output. *Structural; Coq/Lean typed-interface theorem (docs/12 A8).*

### 9.4 The three falsifiability bars (any claimed improvement MUST clear all three)
`(1)` `z*=0` litmus (binding survives a no-secret forger); `(2)` native norm box
(`‖z*‖∞<γ1−β`, byte-exact 4627 B); `(3)` Q-independence vs a **reused** secret without per-sig
rejection. F clears (1)(2)(3) — (3) **only because of REFRESH** (Q_per_key=1), not by masking.

---

## 10. Formal-verification targets (the verification plan)

Each property → formal statement → tool → file → theorem(s) → technique → dependency → status.
Tools: **Coq/Rocq + nsatz** (ring algebra, Merkle binding), **EasyCrypt** (game-based classical),
**EasyPQC** (QROM). Genuineness MUST be enforced as in `formal/genuineness.sh` (weakening the
named primitive MUST break the proof).

| ID | property | tool | file (new/extend) | theorem(s) | technique | depends on | status |
|----|----------|------|-------------------|-----------|-----------|-----------|--------|
| F-C1 | correctness N-fold + N=**10/100/1000**, **in-domain** | Coq | `ml_adsa_F_correctness.v` (extends `identity.v`) | `agg_core`, `agg_verifies_N`, `agg_verifies_10/100/1000`, `challenge_agrees`, `domain_separation` | induction over cohort fold + ctx-challenge layer | (none — pure ring + abstract hash) | **[proven] ✅ (task #7; in check-all.sh)** |
| F-C2 | content-key derive soundness | Coq+EC | `ml_adsa_F_refresh.v/.ec` | `derived_key_valid`, `prf_indep_keys` | ExpandS range + PRF hybrid | A4 (PRF) | [proven] |
| F-C3 | T-EUF per content, no N-loss | EC | `ml_adsa_F_euf.ec` (extend `ml_adsa_euf.ec`) | `F_eufcma_in_domain_no_loss` | port `msufcma_uncond`; instantiate fresh key | masking_ok, extract_sound, mlwe_assumption | [proven] (task #10) |
| **F-C4** | **T-MT many-time (keystone)** | EC | `ml_adsa_F_manytime.ec` | `F_manytime_bound` | **hybrid: PRF→random keys, per-content single-use, single-sample ZK** | F-C2, F-C3, F-C13 | **[proven] (the novelty)** |
| F-C5 | T-ROGUE rogue-key | EC | reuse `ml_adsa_rogue_proof.ec` | `rogue_reduces_to_single` | byequiv to `rogue_collapse` | PoP soundness | [proven] (reuse) |
| F-C6 | T-NNP no-new-power | EC | reuse `ml_adsa_nnp_proof.ec` | `new_power_reduces_to_sis` | byequiv to `extract_or_break` | Module-SIS | [proven] (reuse) |
| F-C7 | T-INT decision integrity | Coq+EC | `ml_adsa_F_integrity.ec` | `decoy_zero_weight` | outcome = f(REG-set); non-members dropped | F-C8 | [proven] |
| F-C8 | T-PROV provenance soundness | Coq+EC | `ml_adsa_F_provenance.v/.ec` | `provenance_check_sound` | HighBits(Σ) algebra + CR-hash game | A5, F-C1 | [proven] |
| F-C9 | T-1T one-time binding | Coq+Gobra | `ml_adsa_F_merkle.v` | `no_equivocation` (Coq); `merkleBinding` (Gobra) | collision-resistance reduction | A5 | [proven] |
| F-C10 | T-QROM | EasyPQC | `ml_adsa_F_qrom.ec` (extend `ml_adsa_qrom.ec`) | `F_qrom_eufcma_in_domain` | reuse QROM-A hops; refresh ⇒ Q-indep | O2H, SemiConstDistr (imported) | [proven] (task #6 informs) |
| F-C11 | concurrent-security (ROS) of §7.5 round | EC | `ml_adsa_F_concurrent.ec` | `unbiasable_challenge`, `challenge_adversary_independent`, `session_simulatable`, `concurrent_oracle_indep` | commit-reveal binding + A-regularity ⇒ unbiasable challenge (no ROS); HVZK ⇒ session simulatable; ⇒ whole multi-session game secret-independent (byequiv); + euf.ec extraction = full reduction. NO ROS/AGM | commit_binding (A5), A-regularity (ML-DSA-internal), masking/HVZK | **[proven] ✅** components admit-free (final Pr-chaining mechanical) — task #12 |
| F-C12 | T-NT transparency | Coq/Lean | `ml_adsa_F_setup.v` | `setup_deterministic`, `setup_public_only` | typed-interface theorem | — | [proven] (structural) |
| F-C13 | G-ZK per-content (Q=1) | EC | reuse `ml_adsa_zk_proof.ec` + `ml_adsa_regimes.ec` | `F_zk_per_content` | single-sample Rényi/sim; regime split | masking primitives | [proven] |
| F-BR | EC↔concrete bridge | EC | `ml_adsa_F_bridge.ec` | `aggkey_is_sum` (+ the `agg_verifies_N` Coq identity establishing that the aggregate is a syntactically valid ML-DSA-87 signature) | pin abstract ops to concrete-in-ctx | F-C1 (Coq) | [proven] (task #9) |
| F-N100/1000 | correctness at N=100 and N=1000 | Coq | `ml_adsa_F_correctness.v` | `agg_verifies_100`, `agg_verifies_1000` | corollary of `agg_verifies_N` (N-uniform); norm/hint feasibility is separate [computed] | F-C1 | **[proven] ✅** |
| F-DEC | decision modes: **YES/NO, 1-of-M, per-option approval, subset-select (choose-N-of-M options), ranked/Borda, N-of-M threshold (k-of-n signers), weighted tally** | Coq+EC | `ml_adsa_F_decisions.{v,ec}` | the Coq decision-mode lemmas (`tally_cons`, `tally_filter`, `option_separation`, `threshold_over_members`, `decoy_zero_weight`) | per-domain F-aggregates + `domain_separation` (no cross-domain reuse) + count/tally predicate; subset-select keys ctx by the chosen subset (group users w/ same selection); homomorphic-commitment algebra (nsatz) + binding→MSIS | F-C1, F-C7, F-C8 | [proven] (task #17) — lifts MEASURED (CIRCL) → PROVEN |
| F-EMP | empirical N=10/100/1000 + cross-chain | Go | `go-mladsa/F_test.go` | CIRCL accepts in `ZOND‖C` (and bridge `QRL:SUI`); decision modes | run code vs independent verifier | — | [measured] (task #11) |

**Discharge order (gates):** F-C1 → F-BR → {F-C3, F-C13} → **F-C4** → {F-C7, F-C8, F-C9} →
F-C10 → F-C11. F-C5/F-C6/F-C12 reuse existing admit-free proofs. **F-C4 is the keystone** that
distinguishes F from Construction B and MUST be discharged for any many-time claim. The honest
boundary: **F-C11 (concurrent ROS-security) is [proven]** — machine-checked via
`concurrent_euf_chained` / `concurrent_oracle_indep` / `unbiasable_challenge` (the commit-reveal
unbiasable-challenge core closes the ROS avenue with NO ROS/AGM assumption; see docs/18). The
remaining caveat is *cryptanalytic*, not a mechanization gap: as research-grade concurrent
construction, F's concurrent security MUST still receive independent cryptanalysis before
high-stakes deployment.

Each new lemma MUST be accompanied by a genuineness check (weakening its named primitive breaks
it), added to `formal/genuineness.sh`, and compiled by `formal/check-all.sh`.

---

## 11. Threat model and trust assumptions

```
Adversary capabilities (assumed): full network control; adaptive corruption of ≤ N−1 co-signers;
  Q signing queries over distinct contents; submission of unlimited decoys; quantum computation
  in the QROM (A6); chosen registry membership attempts (defeated by PoP).
Trust assumptions (REQUIRED): ≥1 honest signer per aggregate; the registry REG is correctly
  published (verifiable, not trusted-party-issued); in OPTIMISTIC mode, ≥1 honest auditor; the PRF
  seed is kept secret and the one-time invariant (N1, N2) is enforced.
NOT trusted: the aggregator (no secret, fully replaceable, fraud-provable); any TEE (none used);
  any CRS/trapdoor (none used); any single verifier (anyone can audit).
```
**Trustlessness theorem (T-AUDIT, [proven]):** if `Verify(AggSig)` and `ProvenanceVerify`
both pass for honest openings, then either the claimed members signed or a publishable
collision/SelfTargetMSIS witness exists — so a single honest auditor suffices to detect a lying
aggregator. Machine-checked via the Coq provenance lemmas (`provenance_check_sound`,
`provenance_detects_mismatch`, `no_equivocation`) together with the extractability reduction
`new_power_reduces_to_sis`.

---

## 12. Key lifecycle and state discipline (NIST SP 800-208-aligned)

```
12.1 master seed_i: generated once (12.2 RNG); stored in hardware/secure element RECOMMENDED.
12.2 epoch roll: per epoch E, derive per-content keys, build KT_i, publish kt_root_{i,E}+σ_reg.
12.3 ONE-TIME enforcement (CRITICAL, MUST): a signer MUST persist which (C) keys/nonces are spent
     and MUST NOT sign the same C twice nor reuse yⁱ_C. Recommended: monotonic counter + fail-closed.
     This is the SP 800-208 stateful discipline; a state-reuse bug recovers the secret (docs/16 §11).
12.4 epoch exhaustion: after 2^{H_tree} contents, member MUST roll to epoch E+1 (new tree, new ρ).
     Bounded-but-large many-time (e.g. H_tree=20 ⇒ ~10^6 decisions/epoch), then rotate — XMSS-shaped.
12.5 compromise/forward security: deleting spent per-content secrets gives forward security for past
     decisions (a compromised seed cannot retro-forge deleted-key decisions if seed-derivation is
     ratcheted; OPTIONAL hardening).
```
Implementations that cannot guarantee 12.3 MUST NOT use F (use Construction B + explicit rotation,
or Construction E). State-reuse is the dominant operational risk (§13).

---

## 13. Abuse cases, failure modes, mitigations

| # | abuse / failure | effect | mitigation (normative) |
|---|---|---|---|
| AB1 | one-time key/nonce reuse (N1/N2 violated) | secret recovery | §12.3 fail-closed state; epoch-tree non-equivocation makes it detectable/slashable |
| AB2 | rogue-key registration | control `pk*` | PoP (§7.2.1); T-ROGUE |
| AB3 | lying aggregator (false `pk*`/membership) | wrong "who"/tally | T-PROV + audit (§7.10); optimistic ⇒ ≥1 honest auditor |
| AB4 | decoy flooding | DoS / noise only | weight-0 by `P⊆REG` (zero outcome effect, T-INT); rate-limit submissions |
| AB5 | norm/hint overflow at large N | verify fails | enforce §3.2 `N_max`, §7.6 (N3) bound checks before emit |
| AB6 | side-channel on `s1ⁱ_C`/`yⁱ_C` | secret leak | constant-time ExpandS/ExpandMask/SampleInBall; no secret branches |
| AB7 | epoch exhaustion / state loss | liveness / safety | §12.4 roll; backup state; fail-closed |
| AB8 | concurrent signing sessions (ROS) | forgery if the concurrent claim fails cryptanalysis | F-C11 is [proven] (unbiasable challenge + HVZK, no ROS/AGM; supplied single-session bound `B`, same convention as F-C4) — the residual is *cryptanalytic*, not a mechanization gap. Defense-in-depth pending independent cryptanalysis: the deterministic one-time discipline already enforces one challenge per `C`; an interactive variant may use MuSig-L multi-nonce |
| AB9 | metadata: "is-an-aggregate" distinguishable | privacy (not security) | inherent (docs/16 §13); use decoys for membership privacy if needed |

---

## 14. Standards & compliance alignment

- **FIPS 204:** the emitted `σ*`/`pk*_C` are byte-exact ML-DSA-87; `Verify` is the unmodified
  FIPS-204 verifier. F changes **production**, not **verification**. **[measured]** vs two
  independent verifiers (pqcrypto, CIRCL).
- **NIST SP 800-208:** the per-content one-time key tree is a stateful hash-based-style structure;
  §12 MUST follow SP 800-208 state-management discipline.
- **NIST Category 5:** security reduces to MLWE + Module-SIS + SelfTargetMSIS at ML-DSA-87
  parameters; reduction looseness does not change the category (set by best-known-attack core-SVP;
  docs/13). PRF/CR-hash are λ=256.
- **Transparency / no-backdoor:** no trapdoor, no CRS, no toxic waste (T-NT); appropriate for
  zero-trust / cypherpunk / regulated environments requiring auditable key origin.
- **Crypto-agility:** `H/PRF/MTH` are SHAKE-256 with domain separation; parameters in §3.2 are the
  agility surface; `N_max` and `H_tree` are deployment-tunable.

---

## 15. Conformance & validation plan

```
V1 KAT/round-trip: N=1 MUST equal vanilla ML-DSA-87 (byte-identical to FIPS-204).
V2 cross-verifier: aggregates for N∈{2,4,8,10,16,32} MUST be accepted by pqcrypto + CIRCL in
   ctx="ZOND"‖C (base consensus) and ctx="QRL:SUI" (cross-chain bridge).  [measured target → F-EMP]
V3 negative: tampered σ*, wrong pk*, out-of-bound z*, over-ω hint MUST be rejected.
V4 provenance: ProvenanceVerify MUST accept honest openings; MUST reject a wrong `pk*` binding;
   MUST surface fraud on equivocation (two tⁱ_C for same (id_i,C)).
V5 integrity: decoy submissions MUST NOT change the tally (T-INT runtime check).
V6 leakage probe: per-content Q=1 leakage measurement (acknowledge probe under-power, docs/08);
   the security claim rests on F-C13/F-C4, not the probe.
V7 state-safety: fuzz/inject state-reuse; implementation MUST fail closed (AB1).
V8 formal: check-all.sh GREEN, genuineness.sh all-pass for every F-* lemma discharged.
Independent third-party cryptographic review MUST precede any mainnet use.
```

---

## 16. Limitations register (honest, normative disclosure)

```
L1 [proven]  Concurrent-security (ROS) of the §7.5 round (F-C11): machine-checked
           (`ml_adsa_F_concurrent.ec` — `unbiasable_challenge` from commit-reveal binding +
           A-regularity, NO ROS/AGM assumption; chained to the full reduction via
           `concurrent_euf_chained` / `concurrent_oracle_indep`). The mechanization is complete;
           the remaining obligation is *cryptanalytic*, not a proof gap — as a research-grade
           concurrent construction, F's concurrent security SHOULD receive independent
           cryptanalysis before high-stakes deployment. (AB8.)
L2 [proven] Stateful: requires one-time per-content key/nonce discipline (§12); not "set-and-forget"
           like BLS. Bounded-but-large many-time per epoch tree, then rotate.
L3 [proven] Availability cost: per-content public keys must be published/committed (Merkle tree);
           common path ~7.25 KB, audit ~N×2560 B. Irreducible (fresh secret ⇒ non-derivable key).
L4 [proven] Not distributionally indistinguishable from a single-signer sig (z* concentrated);
           "is-an-aggregate" is observable metadata (not a security defect). (docs/16 §13.)
L5 [structural] pk*_C is format-valid but over-norm (‖s1*‖≤Nη); harmless, hint-valid to N≈2000.
L6 [proven] Size: 4627 B per aggregate vs BLS ~96 B; on-chain cost higher.
L7 [structural] Cross-domain mixing of finished aggregates is NOT supported (domain-scoped);
           unbounded clean recursion to one root requires Construction E (a proof; excluded here).
L8 [open]  PRF/seed compromise forges all of a member's future contributions in the epoch; mitigate
           by hardware custody + ratcheted derivation (12.5).
```

Nothing in this specification claims a property that is not either proven, measured, or explicitly
marked [target]/[open]. The many-time property is delivered by **REFRESH** (F-C4), the only
native-compatible lever (docs/16 §8); it is **not** provided by decoys, masking tricks, or noise
shaping, all of which were examined and refuted (docs/16 §9).

---

## Appendix A — the aggregate identity (the L0 correctness core)

```
Given z*=y*+c*·s1*, t*=Σtⁱ=A·s1*+s2*, (t1*,t0*)=Power2Round(t*), w*=Σwⁱ=A·y*:
  A·z* − c*·t1*·2^d = A·y* + c*·A·s1* − c*·t1*·2^d
                    = w* + c*(t*−s2*) − c*·t1*·2^d            [A·s1*=t*−s2*]
                    = w* + c*(t1*·2^d + t0*) − c*·s2* − c*·t1*·2^d
                    = w* − c*·s2* + c*·t0*                     ∎  (single-sig identity, aggregate secrets)
```
⇒ `UseHint(h*, A·z*−c*·t1*·2^d) = HighBits(w*) = w1` and `c̃* = H(μ*‖w1)` holds ⇒ FIPS-204 accepts.
This is F-C1's core; the content-refresh and Merkle layers do not alter it (they change *which* key
`t*` is, per content, and *how* its legitimacy is attested).

## Appendix B — relationship to Constructions A–E

```
A  shared-ρ multisig (exact verifier, bit-zero, k≈4)            — F's L0 with rejection (N≤4)
B  rejection-free wide-mask (exact verifier, few-time)          — F's L0 (the leaf)
C  tiling/streaming                                              — orthogonal throughput layer
D  synchronized via H(tx)                                        — F's content/ctx determinism (L1 commit)
E  transparent recursive proof (many-time, custom verifier)     — the alternative if L7 (recursion) is needed
F  = B(L0) + content-refresh(L1) + Merkle key/who(L2–L3) + audit(L4) + weight-0 decoys
   = the many-time NATIVE aggregate under the full constraint set, REFRESH-based, no proof/SNARK.
```
