# 27 — ML-ADSA complete code formal specification (3 surfaces) + completeness audit

The single conformance map across the **three implementation surfaces** — the **proofs**
(Coq/EasyCrypt/EasyPQC + Gobra), **standalone Go** (`go-mladsa/`), and **qrysm-vendored Go**
(`qrl-integration/ml-adsa/qrysm/mladsa/`) — with formal-verification status per component, followed by
a **completeness audit** of the specification. Consolidates docs/17 (spec), docs/18 (artifact ledger),
docs/20 (proof↔Go refinement map), docs/21 (unified spec), docs/22 (Gobra), docs/25 (KATs). Honest
labels: **[proven]** machine-checked · **[code-proven]** Gobra · **[KAT]** pinned vector · **[measured]**
CIRCL/go-qrllib · **[named]** assumed primitive · **[—]** not applicable.

## 1. The three surfaces and how they relate

- **Proofs** (`formal/`): the algorithm is verified abstractly — 32 machine-checked artifacts (22 EC +
  5 EasyPQC + 5 Coq), 40/40 EC genuineness; plus **Gobra** code-level proofs of the structural logic
  (`formal/gobra/`, 6 theorems, 5/5 genuineness).
- **Standalone Go** (`go-mladsa/`): the reference implementation; CIRCL-cross-checked; the KAT source of
  truth. `go test ./...` PASS.
- **qrysm-vendored Go** (`.../qrysm/mladsa/`): a **byte-identical** copy used in the consensus
  integration; verified by **go-qrllib** (QRL's own ML-DSA-87) and pinned by the **same KATs** ⇒ proven
  identical to standalone (docs/25 cross-conformance). `go test ./mladsa/` PASS.

Relationship: **proofs ⊳ standalone (refinement, docs/20) ≡ qrysm (KAT-identical)**, with two
independent FIPS-204 anchors (CIRCL, go-qrllib).

## 2. Per-component verification matrix

| component | proof artifact | go-mladsa symbol | qrysm symbol | KAT | FV status |
|---|---|---|---|---|---|
| parameters (q,n,k,ℓ,η,τ,β,γ1,γ2,α,d,ω,ζ) | docs/17 §2 | `mldsa87.go` consts | identical | — | [proven]=spec, audited equal |
| NTT / ExpandA / SampleInBall / rounding / hint | docs/17 §5 ([named] in EC) | `mldsa87.go` | identical | `MerkleRoot`/primitive KATs | [named]+[measured] (CIRCL/go-qrllib) |
| aggregate identity `A·z*−c·t1*2^d = w*−c·s2*+c·t0*` | Coq `agg_verifies_N` (F-C1) | `AggregateRejfree`/`AggregateF` | identical | `TestKAT_Aggregates` | **[proven]+[KAT]+[measured]** |
| content-key refresh `ExpandS(PRF(seed,C))` | EC `ml_adsa_F_refresh` (F-C2), Coq `agg_verifies` | `ContentKeyDerive`,`ExpandS`,`prf` | identical | `TestKAT_Primitives` | **[proven]+[KAT]** |
| many-time (Q-independence) | EC `F_manytime_bound` (F-C4) | refresh per content in `AggregateF` | identical | `TestKAT_Rotation` | **[proven]+[KAT]** |
| deterministic nonce / one-time (N1/N2) | EC `F_concurrent` round | `DeriveNonce`, `OneTimeGuard`, **`DurableOneTimeGuard`** | identical | `TestKAT_Rotation` + `TestDurableOneTime_SurvivesRestart` | **[proven]+[KAT]+[measured]**; durable across restarts (audit M2 fixed) |
| EUF-CMA no-loss / SUF-CMA | EC `msufcma_uncond`,`sufcma_uncond` (F-C3) | (security of `Verify`) | identical | tamper-reject in tests | **[proven]+[measured]** |
| rogue-key / PoP (F-C5) | EC `rogue_reduces_to_single` | `MemberKeyGen`/`VerifyPoP`/`BuildRegistry` | identical | — | **[proven]+[measured]** |
| no-new-power → Module-SIS (F-C6) | EC `new_power_reduces_to_sis` | (extraction) | identical | — | **[proven]** |
| Merkle non-equivocation / provenance (F-C8/9) | Coq `no_equivocation`; Gobra `merkleBinding` | `merkle.go`,`EpochKeyTreeBuild`,`ProvenanceVerifyF`,`VerifyContentInTree` | identical | `MerkleRoot` KAT | **[proven]+[code-proven]+[measured]** |
| decentralized §7.7 combine (no aggregator) | = `AggregateF` (byte-identical) | `decentralized.go CombineFromPublic` | identical | (devnet) | **[proven]≡ (TestDecentralized_EqualsAggregateF)** |
| decoy weight-0 integrity (F-C7) | Coq `decoy_zero_weight`/`tally_filter`; Gobra `filterRecognized` | `Registry.Weight`,`FilterRecognized`,`MakeDecoySigner` | identical | — | **[proven]+[code-proven]+[measured]** |
| decoy/value-tally hiding (F-C7 privacy) | EC `commit_hiding ≤ 2·adv_mlwe` | `commit.go`,`decoy.go CommitWeight/OpenTally` | (go-mladsa only) | — | **[proven]+[measured]**; computational (Module-LWE) |
| decision modes (YES/NO,1-of-M,approval,k-of-n,subset,tally) | Coq `option_separation`,`threshold_over_members`,`commit_hom_N` | decision tests | (go-mladsa) | — | **[proven]+[measured]** |
| transparency / cross-chain | Coq `setup_public_only`,`key_indep_of_ctx` | `ExpandA(ρ)`,`ctx` | identical | — | **[proven]+[measured]** |
| QROM (post-quantum) | EasyPQC `qrom_eufcma_uncond/_lossy`,`F_qrom` (F-C10) | (verify) | identical | — | **[proven]** (A tight; B lossy/named) |
| validity verify (unmodified FIPS-204) | docs/17 §7.8 | `Verify` (+ H1/H2 length guard) | identical | all KATs | **[measured]** (CIRCL+go-qrllib) |
| consensus aggregation (attestation) | — | — | `cmd/mladsa-devnet`, `AggregateF` | (devnet) | **[measured]** live (8/16/128×, all-agree); proto/SSZ Phase-2 shrink **[implemented]** (docs/29) |

## 3. Completeness audit of the specification

**Specified & verified (complete):** all Construction-F targets F-C1…C13 + F-DEC have a normative
algorithm (docs/17), ≥1 machine-checked artifact, a Go implementation on both surfaces, and (for the
core) pinned KATs. The proof↔code refinement is documented (docs/20) and the two Go surfaces are
KAT-identical (docs/25). Decoy integrity **and** privacy are both machine-checked (Coq/Gobra + EC).

**Specification gaps / residuals (explicitly incomplete):**
1. **Byte-level ML-DSA internals** (NTT/SHAKE/UseHint/ExpandS exact semantics) are **[named]** in the
   proofs and **[measured]** (CIRCL/go-qrllib), not functionally proven — the formosa-crypto multi-year
   effort; out of scope by design (docs/17 §10).
2. **QROM-B tight** (GHHM21 distinct-per-query) — **[open]** research item #6; off Construction-F's
   critical path (F uses tight Construction-A QROM).
3. **Operational invariants not in the math:** durable **one-time-nonce state** (audit M2) is now
   **implemented** (`DurableOneTimeGuard`, restart-safe); per-content key availability (epoch tree) and
   cohort/norm cap remain operational constraints (docs/17 §16) not all enforced in code yet.
4. **Consensus integration semantics** (SSZ shape change, slashing, fork-choice, batch-verify) —
   specified as the next milestone (docs/23, audit H5/H6), not yet implemented.
5. **Value-tally range soundness** — the optional hidden-value mode lacks a range proof; the **mainline
   avoids it** (registry weights, ZKP-free), so this is only relevant to that optional mode (docs/24).
6. **Input-validation hardening** beyond `Verify` (audit H3/M5/M6/M7) — partially [open] (H1/H2 patched).

**Verdict:** the specification is **complete for the proven aggregate/decision construction** across all
three surfaces, with the six residuals above named and bounded. None is a hidden gap; items 1–2 are
fundamental/known, 3–6 are integration/hardening tracked in docs/23 and docs/26.

## 4. Reproduce (all three surfaces)

```
formal/check-all.sh            # proofs: 32 artifacts GREEN
formal/genuineness.sh          # 40/40
formal/gobra/run.sh + genuineness.sh   # Gobra: 6 theorems, 5/5
cd go-mladsa && go test ./...                    # standalone (incl. TestKAT_*)
cd qrl-integration/ml-adsa/qrysm && go test ./mladsa/   # qrysm (same KATs, go-qrllib)
```
