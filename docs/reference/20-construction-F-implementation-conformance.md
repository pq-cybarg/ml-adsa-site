# 20 — Construction F: Implementation Conformance (Refinement Map)

The definitive, honest answer to *"is the running Go code without question the exact construction we
proved?"* This document maps **every** Construction-F proof artifact (docs/17 §10, docs/18) to the
Go symbol that realizes it, names the test that exercises it, and states the epistemic boundary
exactly.

## 0. Bottom line (read this first)

**Before this pass:** the Go implemented only **L0** — the base native aggregate (`AggregateRejfree`
/ `AggregateM1`) with *fixed long-term* keys and a *random* nonce sum. That is the core proven by
F-C1/F-C3, but it is **not** Construction F: it lacked L1 refresh (the many-time keystone), L2 the
Merkle key-tree, L3 PoP/registry, the deterministic PRF nonce, the one-time discipline, and
provenance/audit. The newer F proofs (F-C2/C4/C5/C7/C8/C9/C11) are *about that missing machinery*.
So the honest status was: **the running code was the L0 subset, not the proven Construction F.**

**After this pass:** the Go now contains the **full Construction F** — `AggregateF` plus L1–L4 —
added **additively** (the L0 routines are untouched and still back the F-C1/F-C3 base proofs and
their tests). Every proven property now has a running, CIRCL-validated counterpart. The L0 routines
remain as the proven *core* that `AggregateF` builds on.

## 1. Refinement map (proof artifact → Go symbol → test)

| docs/17 target | property | §  | Go symbol(s) (file) | test (all CIRCL-checked where applicable) |
|---|---|---|---|---|
| **F-C1** | N-fold correctness: `t*=Σtᵢ`, one common `c*`, `z*=Σzᵢ`, hint recovery | 7.7 | `AggregateF`, `aggKeyAndMu` (`construction_f.go`, `mladsa.go`) | `TestF_AggregateF_CIRCL` (n=8/16/64), `TestF_EMP_Scale_CIRCL` (10/100/1000) |
| **F-C2** | content-key derive soundness: `t_C=A·s1_C+s2_C`, η-bounded | 7.3 | `ContentKeyDerive`, `ExpandS`, `rejBoundedPoly`, `coeffFromHalfByte` (`refresh.go`) | `TestF_ContentKeyDerive_Valid` |
| **F-C4** | **many-time keystone**: PRF → fresh independent key per content | 7.3 | `prf("F.key")` → `ContentKeyDerive` per content (`refresh.go`) | `TestF_ManyTime_CIRCL`, `TestF_Refresh_DeterministicAndIndependent` |
| **F-C5** | rogue-key defense via Proof-of-Possession | 7.2.1 | `popMsg`, `MemberKeyGen`, `VerifyPoP`, `BuildRegistry` (rejects bad PoP) (`construction_f.go`) | `TestF_PoP_AndRegistry` |
| **F-C7** | decision integrity: weight-0 decoys cannot bias outcome | 7.7 | `Registry.Weight`, `Registry.FilterRecognized` (`construction_f.go`) | `TestF_DecoysHaveZeroWeight_CIRCL` (20 decoys → byte-identical aggregate) |
| **F-C8/C9** | provenance soundness + one-time (non-equivocation) Merkle binding | 6.2,7.4,7.9 | `mthLeaf/mthNode`, `MerkleRoot/Proof/Verify`, `ktLeaf`, `EpochKeyTreeBuild`, `ProvenanceVerifyF` (`merkle.go`, `construction_f.go`) | `TestF_Provenance_AcceptAndReject`, `TestF_Merkle_ProofRoundTripAndTamper` |
| **F-C11** | concurrent/ROS round: context-committed deterministic nonce | 7.5 | `DeriveNonce` (PRF `"F.nonce"`, zero-mean, one-time) (`refresh.go`) | `TestF_OneTime_ReuseRejected` (det. nonce + guard) |
| **N1/N2** | one-time discipline (SP 800-208) | 7.3,7.5 | `OneTimeGuard`, `DeriveNonce` (no resample for same C; index advance on N3) (`construction_f.go`) | `TestF_OneTime_ReuseRejected` |
| **§7.10** | audit / publishable fraud on equivocation | 7.10 | `Audit` (`construction_f.go`) | `TestF_Audit_DetectsEquivocation` |
| **F-C12** | transparency: ρ public, no secret setup | 7.1 | `ExpandA(ρ)`; ρ is a public epoch parameter (`mldsa87.go`) | (all; ρ is `QRLrho`, public) |
| **F-EMP** | empirical scale + cross-chain, byte-exact 4627-B sig | 7.8 | `VerifyF` == `Verify` (unmodified FIPS-204) (`mldsa87.go`) | `TestF_AggregateF_CIRCL`, `TestF_EMP_CrossChain_CIRCL` (`QRL`, `QRL:SUI`) |
| domain framing | `msg` commits `part_root`+`reg_root`+`E` | 6.3,7.6 | `bindMsg`, `AggSigF.SignedMsg` (`construction_f.go`) | (all F tests) |
| single-signer | n=1 aggregate = vanilla ML-DSA-87 (used for PoP/σ_reg) | — | `SignSingle` (`construction_f.go`) | `TestF_SignSingle_IsVanillaMLDSA_CIRCL` |

All algorithm primitives (`SampleInBall`, `Power2Round`, `Decompose`, `HighBits`, `MakeHint`,
`UseHint`, `ExpandA`, `w1Encode`, NTT) were independently reviewed against FIPS-204 and are
CIRCL-cross-validated (`TestCoreVsCIRCL`: our `Verify` ≡ CIRCL's, both directions).

## 2. The exact-correspondence statement

For each participant the Go computes exactly the §7.3/§7.5/§7.6/§7.7 quantities:

```
s1ⁱ_C,s2ⁱ_C  = ExpandS(PRF(seedᵢ,"F.key"‖C))                 # L1 refresh   (ContentKeyDerive)
tⁱ_C         = A·s1ⁱ_C + s2ⁱ_C                                # public key   (ContentKeyDerive)
yⁱ_C         = ExpandMask(PRF(seedᵢ,"F.nonce"‖C))            # det. nonce   (DeriveNonce)
t*           = Σ_{i∈P} tⁱ_C ;  (t1*,t0*)=Power2Round(t*)      # agg key      (aggKeyAndMu)
W*           = A·Σyⁱ_C ;  c̃*=H(μ*‖HighBits W*) ; c*=SampleInBall   # common challenge
z*           = Σ_{i∈P}(yⁱ_C + c*·s1ⁱ_C)                       # response     (AggregateF loop)
σ*           = (c̃*, z*, h*)                                   # byte-exact ML-DSA-87 signature
part_root    = MerkleRoot{ MTH(idᵢ‖C‖tⁱ_C) }_{i∈P (sorted)}  # the "who"    (AggregateF)
```

This is byte-for-concept the spec, and the `z* = y* + c*·s1*`, `A·z* − c*·t1*·2^d = w* − c*·s2* +
c*·t0*` identity is the Coq-proven `agg_verifies_N` (F-C1). The participation set is committed in the
signed message (`bindMsg`), so `c̃*` binds `part_root` (§6.4). `P ⊆ REG` is enforced by
`FilterRecognized`, giving decoys weight 0 (§7.7 / F-C7).

## 3. Honest epistemic boundary (not overclaimed)

- **What is proven (machine-checked):** the *algorithm/math* — 32 Rocq/EasyCrypt/EasyPQC artifacts,
  41/41 genuineness, zero admits (docs/18).
- **What is validated (measured):** the *Go code* realizes that algorithm — every layer round-trips
  and, where a signature is produced, the **independent Cloudflare CIRCL** ML-DSA-87 verifier accepts
  it and rejects tampering (this §1 test column). This is the field-standard for implementation
  correctness.
- **What is NOT claimed:** a *full code-level formal proof* of the Go itself. Code-level formal
  proofs now partly exist — delivered via Gobra (6 theorems, docs/22); the lattice arithmetic
  remains named-primitive + CIRCL-measured (per docs/17 §10 / docs/12). The refinement map + CIRCL +
  property tests are the bridge between the proven algorithm and the running code — they are strong
  evidence, complementing (not replacing) the Gobra code-proofs.
- **Two routines, by design:** `AggregateRejfree`/`AggregateM1` (L0, random nonce, fixed keys) remain
  as the proven *base* (F-C1/F-C3) and back the original tests; `AggregateF` is the full Construction
  F (L0 core + L1–L4) and is what a deployment uses. Both are CIRCL-verified.

## 4. Verification commands

```
cd go-mladsa && go test ./...                 # ALL PASS (incl. all TestF_* CIRCL cross-checks)
go test -run TestF_ -v ./...                  # the Construction-F conformance suite, per §1
go test -run TestCoreVsCIRCL -v ./...         # our Verify ≡ CIRCL (FIPS-204 conformance)
```

Conclusion: the running Go is now **the exact Construction F** at the level the proofs specify —
each proven property (F-C1/C2/C4/C5/C7/C8/C9/C11, N1/N2, audit, transparency, validity, cross-chain)
has a named Go symbol and a passing, independently-cross-checked test — with the one honest caveat
that this is algorithm-proof + code-measurement, not a formal proof of the Go source itself.
