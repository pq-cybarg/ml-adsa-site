# 21 — ML-ADSA: Unified Formal Specification (All Implemented & Tested Approaches)

The single normative specification spanning **every approach the project implements and tests**, with,
for each, its formal definition, security property, and the exact evidence at three levels —
**algorithm-proof** (Coq/EasyCrypt/EasyPQC), **code-proof** (Gobra), **measurement** (Go vs the
independent CIRCL ML-DSA-87). It supersedes nothing; it *indexes and unifies* docs/16 (design),
docs/17 (Construction F), docs/18 (verification summary), docs/19 (whitepaper), docs/20 (impl
conformance), docs/22 (Gobra). It ends with a **completeness assessment** and the residual work.

Project: **pq-cybarg** (module `github.com/pq-cybarg/ml-adsa`); deployment target QRL 2.0 (ML-DSA-87).

---

## 1. Scope and conformance

This document specifies the aggregate-signature and decision constructions over **ML-DSA-87**
(FIPS-204) that are realized in `go-mladsa/` and verified in `formal/`. An implementation conforms
if, for each approach it offers, it satisfies the algorithms of §4 and the security properties of
§5, on the assumption base of §6. Evidence levels (§7) are labelled honestly throughout:
**[proven]** machine-checked; **[code-proven]** Gobra; **[measured]** CIRCL; **[assumed]** named
standard primitive; **[open]** not yet discharged.

Keywords MUST/SHOULD/MAY per RFC 2119.

---

## 2. Shared parameters and primitives (normative)

ML-DSA-87: `q=8380417, n=256, (k,ℓ)=(8,7), η=2, τ=60, β=τη=120, γ1=2^19, γ2=(q−1)/32, α=2γ2,
d=13, ω=75, ζ=1753`; `pk=2592 B, sig=4627 B`; NIST Category 5. These are identical across the
specification, the proofs, and `go-mladsa/mldsa87.go` (audited, docs/18 §1).

Primitives (FIPS-204 unless noted): `ExpandA, ExpandS, SampleInBall, Power2Round, Decompose/
HighBits/LowBits, MakeHint/UseHint, w1Encode, NTT`; `PRF, H, MTH` are SHAKE-256, domain-separated
(`"F.prf","F.key","F.nonce","F.mt","F.pop","F.kt"`; MTH leaf/internal tagged `0x00`/`0x01`).
Framing `lenPrefixed` is injective (§5 P9, code-proven).

---

## 3. Approach catalog (what exists)

| # | approach | what it is | Go entry point |
|---|---|---|---|
| **A** | Construction A (`M1`) | per-signer rejection, **bit-zero leakage**, small cohort; native ML-DSA-87 aggregate | `AggregateM1` |
| **B** | Construction B (`Rejfree`) | rejection-free wide masks, large cohort, negligible leakage; native aggregate | `AggregateRejfree` |
| **F** | Construction F | **many-time** native aggregate: B-leaf + L1 refresh + L2 Merkle key-tree + L3 registry/PoP + one-time + provenance/audit | `AggregateF` (+ `construction_f.go`, `refresh.go`, `merkle.go`) |
| **D1** | YES/NO consensus | two domain-separated aggregates + tally | `TestVoting_YesNo` |
| **D2** | 1-of-M multi-choice | one domain-separated aggregate per option + tally | `TestMultiChoice` |
| **D3** | approval sets | per-option aggregate of approvers (voter in many) | `TestApprovalSets` |
| **D4** | k-of-n threshold | aggregate approvers; pass iff tally ≥ k | `TestThreshold_KofN` |
| **D5** | subset-select N-of-M | aggregate users picking the same option-subset; subsets domain-separated | `TestSubsetSelect_NofM` |
| **D6** | weighted / continuous tally | additively-homomorphic Module-SIS commitment; sum hidden values, open only the total | `commit.go`, `TestContinuousValueTally` |
| **X** | cross-chain / domain portability | same accounts sign in any agreed domain (`"QRL:SUI"`) without new keys | `TestF_EMP_CrossChain`, `TestTxDomain` |
| **S** | single-signer | n=1 aggregate = vanilla ML-DSA-87 (used for PoP/σ_reg) | `SignSingle` |
| **E** | Construction E (LaBRADOR-class) | succinct proof-of-knowledge of many sigs; unbounded, custom verifier | *designed only* (docs/16) — **not implemented/tested** |

---

## 4. Algorithms (normative, by approach)

### 4.1 Base aggregate identity (A, B, F share this core)
With shared `A=ExpandA(ρ)`, a single common challenge `c*=SampleInBall(H(μ*‖HighBits(W*)))`, and
sums `s1*=Σs1ᵢ, s2*=Σs2ᵢ, t*=Σtᵢ, y*=Σyᵢ, z*=y*+c*·s1*`, the aggregate satisfies the **single-sig
identity with summed secrets**:
```
A·z* − c*·t1*·2^d = W* − c*·s2* + c*·t0*        (= the FIPS-204 verify relation for pk*=(ρ,t1*))
```
so the **unmodified FIPS-204 verifier accepts σ*=(c̃*,z*,h*)**. [proven Coq `agg_verifies_N`;
measured CIRCL]. Bound checks: `‖z*‖∞<γ1−β`, `‖c*·t0*‖∞<γ2`, `wt(h*)≤ω`, self-verify gate.

- **A (`AggregateM1`)** adds **per-signer** rejection (each `zᵢ` in a box of width `(γ1−β)/n`),
  yielding **bit-zero** leakage; joint-restart caps cohort size (small n).
- **B (`AggregateRejfree`)** uses wide masks `σ=12β`, no rejection; scales to N=1000; leakage
  negligible (two-regime analysis).

### 4.2 Construction F (the many-time aggregate) — docs/17 §7 (normative)
`Setup` `A←ExpandA(ρ)` (ρ public, per-epoch). `MemberKeyGen` → master seed + registration keypair +
**PoP** over `H("F.pop"‖id‖regpk)`. **Refresh** (L1, keystone): `(s1ⁱ_C,s2ⁱ_C)=ExpandS(PRF(seedᵢ,
"F.key"‖C))`, `tⁱ_C=A·s1ⁱ_C+s2ⁱ_C` — fresh, one-time per content C. **Nonce** (L1):
`yⁱ_C=ExpandMask(PRF(seedᵢ,"F.nonce"‖C))` (deterministic, zero-mean, one-time). **EpochKeyTree**
(L2): leaves `MTH(id‖C‖tⁱ_C)`, root signed by regkey (non-equivocation). **Aggregate** (§7.7):
require `P⊆REG`; `t*←Σtⁱ_C; z*←Σzⁱ_C`; `part_root←MerkleRoot(P)`; `msg` commits part_root+reg_root+E.
**Verify** (§7.8): unmodified FIPS-204. **ProvenanceVerify** (§7.9): registry membership, σ_reg,
kt-path non-equivocation, part-root, `Power2Round(Σtⁱ_C).t1==pk*.t1`, then Verify. **Audit** (§7.10):
two distinct keys for one (i,C) = publishable fraud.

### 4.3 Decision modes (D1–D6) — domain-separated aggregates + tallies
A decision selects a participant set per option/branch and aggregates it under a **domain-separated
context**; the tally is the per-domain count (D1–D5) or a homomorphic sum (D6). Weight-0 decoys
(non-members) are dropped (`P⊆REG`), so they cannot bias any tally. Canonical (sorted) labels make
subset/participant commitments order-independent.

### 4.4 Cross-chain (X) and single-signer (S)
The domain (context) is part of the signed message; the **same** accounts sign in any agreed domain
without new keys (`key_indep_of_ctx`). `SignSingle` is the n=1 aggregate (a vanilla ML-DSA-87 sig).

---

## 5. Security properties (normative)

| id | property | applies to |
|---|---|---|
| P1 | **correctness** — aggregate verifies under FIPS-204 in its domain (N-fold; N=10/100/1000) | A,B,F |
| P2 | **EUF-CMA, no N-loss, Level 5** | A,B,F |
| P3 | **SUF-CMA** | base |
| P4 | **zero-leakage / HVZK** (perfect for A; two-regime for B) | A,B,F |
| P5 | **rogue-key → single signer** (PoP) | F |
| P6 | **no-new-power → Module-SIS** | A,B,F |
| P7 | **many-time** (Q-independence via refresh) | F |
| P8 | **concurrent / ROS-resistant** (commit-reveal + A-regularity ⇒ unbiasable; no ROS/AGM) | F |
| P9 | **injective framing** ⇒ domain separation | F + all domains |
| P10 | **QROM** security | A,B,F |
| P11 | **transparency** (no trusted setup) | all |
| P12 | **provenance + one-time (non-equivocation)** | F |
| P13 | **decision integrity** — weight-0 decoys cannot bias outcome | D1–D6 |
| P14 | **option separation** — distinct option-subsets are domain-isolated | D2,D3,D5 |
| P15 | **threshold** — pass iff k ≤ tally | D4 |
| P16 | **homomorphic tally** — Σ(commits) opens to Σ(values), individuals hidden | D6 |
| P17 | **domain portability / cross-chain** | X |

---

## 6. Unified assumption base (normative)

Nothing beyond ML-DSA-87's own plus a PRF and a CR-hash:
```
MLWE, Module-SIS, SelfTargetMSIS         -- ML-DSA-87's own (FIPS-204)
HVZK/masking, A-regularity               -- ML-DSA-internal lattice properties
PRF security                             -- a PRF (ML-DSA already uses one)
collision-resistance of H/MTH            -- a hash (SHAKE-256)
(Q)ROM for H                             -- for the QROM results
```
**No** ROS/AGM/OMDL, **no** trapdoor/toxic-waste, **no** SNARK/STARK, **no** TEE, **no** trusted
setup or aggregator. (Construction E, if ever built, would add LaBRADOR's knowledge-soundness — out
of current scope.)

---

## 7. Evidence — the completeness matrix

Per property × approach: **A**=algorithm-proof, **C**=code-proof (Gobra), **M**=measured (CIRCL),
**N**=named/assumed primitive. Artifact names in docs/18 §1, docs/20 §1, docs/22 §1.

| property | A (alg-proof) | C (code-proof) | M (measured) |
|---|---|---|---|
| P1 correctness | ✅ Coq `agg_verifies_{N,10,100,1000}` | ✅ Gobra `sumHom` (linearity) | ✅ CIRCL N=10/100/1000 |
| P2 EUF-CMA no-loss | ✅ EC `msufcma_uncond` | — (security, not code-shape) | ✅ forgery/ tamper-reject |
| P3 SUF-CMA | ✅ EC `sufcma_uncond` | — | ✅ tamper-reject |
| P4 zero-leakage | ✅ EC `zero_leakage_perfect_A`, regimes | — | n/a |
| P5 rogue-key (PoP) | ✅ EC `rogue_reduces_to_single` | — | ✅ `TestF_PoP_AndRegistry` |
| P6 no-new-power | ✅ EC `new_power_reduces_to_sis` | — | n/a |
| P7 many-time | ✅ EC `F_manytime_bound` | — | ✅ `TestF_ManyTime` (distinct pk*) |
| P8 concurrent/ROS | ✅ EC `unbiasable_challenge`+chain | — | ✅ det-nonce `TestF_OneTime` |
| P9 framing/domain sep | (structural) | ✅ Gobra `framingRoundTrip` | ✅ cross-domain reject |
| P10 QROM | ✅ EasyPQC `qrom_eufcma_uncond/_lossy` | — | n/a |
| P11 transparency | ✅ Coq `setup_public_only` | — | ✅ public ρ |
| P12 provenance/one-time | ✅ Coq `no_equivocation`,`provenance_check_sound` | ✅ Gobra `merkleBinding`,`reuseRejected` | ✅ `TestF_Provenance`,`TestF_Audit` |
| P13 decoy integrity | ✅ Coq `decoy_zero_weight`,`tally_filter` | ✅ Gobra `filterRecognized` | ✅ `TestF_DecoysHaveZeroWeight` |
| P14 option separation | ✅ Coq `option_separation` | — | ✅ `TestSubsetSelect_NofM`,`TestMultiChoice`,`TestApprovalSets` |
| P15 threshold | ✅ Coq `threshold_over_members` | — | ✅ `TestThreshold_KofN` |
| P16 homomorphic tally | ✅ Coq `commit_hom_N` | ✅ Gobra `sumHom` | ✅ `TestContinuousValueTally` |
| P17 cross-chain | ✅ Coq `key_indep_of_ctx` | — | ✅ `TestF_EMP_CrossChain` |
| Merkle pad well-formed | (structural) | ✅ Gobra `nextPow2` | ✅ `TestF_Merkle` |

Totals: **32 algorithm-proof artifacts** (22 EC + 5 EasyPQC + 5 Coq), all green, 45/45 EC
genuineness; **6 Gobra code-proof theorems**, 5/5 Gobra genuineness; **Go**: `go test ./...` PASS,
`go vet` clean, every signing path CIRCL-verified.

---

## 8. Completeness assessment (the verdict)

**For the implemented & tested surface (A, B, F, D1–D6, X, S): the specification is COMPLETE.**
Every approach has (i) a normative algorithm (§4), (ii) a stated security property (§5) with at least
one **[proven]** algorithm-level artifact, and (iii) an executable **[measured]** CIRCL-verified
test; the F structural backbone additionally has **[code-proven]** Gobra theorems. The audit of the
Go ↔ proofs correspondence passed (docs/20, docs/18 §1). The proven↔tested gap found during this
assessment (threshold P15, option-separation/ subset-select P14 were Coq-proven but not Go-tested)
**has been closed** by adding `TestThreshold_KofN`, `TestSubsetSelect_NofM`, `TestApprovalSets`.

**Residual items (explicitly NOT claimed complete):**
1. **QROM-B tight GHHM21** distinct-per-query adaptive reprogramming — **[open]** (tracker #6); off
   Construction-F's critical path (F uses the tight Construction-A QROM, P10 via `qrom_eufcma_uncond`).
   The lossy-B capstone with GHHM21 as a named cited bound is done.
2. **Lattice-arithmetic functional proof** (NTT/SHAKE/`UseHint`/`ExpandS` byte semantics) — **[named
   + measured]**, not functionally verified (Gobra covers the *structural* logic; the arithmetic is
   the formosa-crypto multi-year effort, treated as a named primitive + CIRCL measurement).
3. **Construction E (LaBRADOR-class)** — **designed only**; not implemented or tested, hence outside
   the "implemented/tested" completeness claim. Listed for completeness of the design space.
4. **Independent cryptographic review** — required before any deployment (standard for new crypto).

These four are the entire residual. Items 1–3 are scoped and labelled; none is a hidden gap. With
them stated, the specification covers all implemented and tested approaches at all three evidence
levels.

---

## 9. Conformance checklist (for an implementer/auditor)

```
[ ] parameters == §2 (q,n,k,ℓ,η,τ,β,γ1,γ2,α,d,ω,ζ)        -> mldsa87.go consts
[ ] base identity §4.1 + bound checks                       -> AggregateM1/Rejfree, CIRCL
[ ] F refresh/nonce/tree/PoP/one-time/provenance §4.2       -> refresh.go, merkle.go, construction_f.go
[ ] decision modes D1–D6 domain-separated + tally §4.3      -> *_test.go (all CIRCL)
[ ] assumption base §6 (no ROS/AGM/trapdoor/SNARK/TEE/setup)
[ ] evidence §7 reproduces: formal/check-all.sh, formal/genuineness.sh,
    formal/gobra/run.sh, formal/gobra/genuineness.sh, (cd go-mladsa && go test ./...)
```

Run all evidence:
```
formal/check-all.sh            # 32 algorithm-proof artifacts GREEN
formal/genuineness.sh          # 45/45 EC genuineness
formal/gobra/run.sh            # Gobra code-proofs GREEN
formal/gobra/genuineness.sh    # 5/5 Gobra genuineness
cd go-mladsa && go test ./...  # all approaches, CIRCL-verified
```

---

## 10. Deployment context (QRL 2.0: QRVM / Hyperion) — informative

ML-ADSA itself is **VM-agnostic** (its proofs and `go-mladsa/` make no VM assumption). The deployment
target, QRL 2.0 ("Zond"), is — per QRL's own documentation — **EVM-compatible**: the **QRVM** is "an
EVM-friendly VM **forked from the EVM**" with post-quantum modifications (modified opcode logic,
24-byte "Q"-prefixed addresses), and **Hyperion** is a **Solidity-derived** contract language ("most
valid Solidity is valid Hyperion") plus lattice primitives. (So QRL 2.0 *is* an EVM fork, not a
non-EVM design; this does not change ML-ADSA, which targets only the ML-DSA-87 verify interface.)

- **On-chain verification** is exactly a **byte-exact ML-DSA-87 verify** of `σ*` against `pk*` and the
  domain-framed message (§4.1/§4.2). ML-DSA-87 is integrated across QRL 2.0 at the protocol/account
  layer; for **contract-level** verification QRL states the Hyperion compiler "supports lattice-based
  primitives (ML-DSA-87, XMSS), enabling smart contracts to natively verify quantum-secure
  signatures." Because an aggregate **is** a standard ML-DSA-87 signature (the point of Technique 1),
  that native verify path validates an ML-ADSA aggregate **unchanged** — no custom verifier.
- **Decision / provenance / tally logic** (registry `REG`, `part_root`, `reg_root`, thresholds,
  option-subsets, homomorphic tallies, optimistic provenance + fraud `Audit`) is ordinary contract
  logic — implementable as **Hyperion** contracts. The aggregate object (§6.3) is plain bytes + Merkle
  roots, consumable by any VM.

**Two deployment integration items to confirm against QRL's current sources** (zond-docs.theqrl.org /
the go-zond testnet-v2 branch / Hyperion docs), as the public mechanism is not fully pinned:
1. **Parameter set & mechanism.** Confirm the contract-level verify primitive is **ML-DSA-87** (not
   the ML-DSA-44 of Ethereum's EIP-8051 precompile) and whether it is exposed as a precompile, a new
   opcode, or a Hyperion builtin. (The go-zond `main` precompile set — `0x01` depositroot, `0x02`
   sha256, `0x04` dataCopy, `0x05` bigModExp — does not yet include an ML-DSA precompile.)
2. **Encoding.** Confirm the expected `pk`/`sig` byte layout. ML-ADSA emits the **standard FIPS-204**
   `pk*` (2592 B) / `σ*` (4627 B); if QRL adopts an EIP-8051-style **pre-expanded** public key
   (`A_hat‖tr‖t1`, ~20512 B), `pk*` must be re-encoded to that form before the call.

(Tooling note: the code-level proofs use **Gobra** from **ETH Zürich** — a Go static verifier —
which is unrelated to Ethereum and introduces no chain dependency. Full deployment/integration
research, sources, and the EVM-fork correction are documented in **docs/23**.)
