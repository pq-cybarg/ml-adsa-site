# 26 — qrysm ML-ADSA integration: security & operational audit

Read-only audit of the ML-ADSA additions to the QRL 2.0 qrysm fork (the vendored `mladsa` package, the
`mladsa-devnet` command) and the upstream qrysm surfaces the integration touches. Each finding is
classified: **severity**, **security vs operational**, and **easily patchable** (localized fix) **vs
not** (design-level/cross-cutting). The crypto core (NTT, rounding, Merkle domain separation, hint
value-validation) is carefully written and CIRCL/go-qrllib-cross-checked; the exploitable gaps are at
the **trust boundaries** (decode/deserialize/public-input acceptance) and **integration semantics**.

Status legend: **[PATCHED]** fixed in this pass · **[EASY]** localized fix, recommended · **[DESIGN]**
cross-cutting, not a quick patch.

## High

| # | Finding (file:line) | Sec/Ops | Easy? | Status |
|---|---|---|---|---|
| **H1/H2** | `Verify` decoded `pk`/`sig` with **no length check** → adversarial short input panics in `PkDecode`/`SigDecode`/`unpack`/`hintUnpack` (`mldsa87.go` Verify/278/322/259/370). Remote-DoS / node-crash primitive in consensus. | Security | **EASY** | **[PATCHED]** — added `len(pk)==2592 && len(sig)==4627` guard at the top of `Verify` (both go-mladsa & qrysm copies) + regression `TestVerify_RejectsMalformedInput`. Valid-input behavior unchanged ⇒ proofs/KATs/CIRCL still pass. |
| **H3** | Devnet/wire deserialize `[][]int64` polynomials (`commitMsg.T/W`, `respMsg.Z`, `UnmarshalMember`) with **no dimension/range check** before NTT/`coeffSum` → remote panic or cross-node divergence; unbounded JSON size → memory-amplification DoS. | Security/Ops | **EASY** (shape/range gate) / **DESIGN** (size cap) | **[EASY]** add `validateVec(v, dim, N)` + coeff∈[0,Q) before any deserialized poly enters the math; cap message size. (Size-cap properly = SSZ wire format, see H5.) |
| **H4** | Decentralized combine trusts committed `t_i` with **only Merkle membership**, no well-formedness/norm bound (`decentralized.go` SharedChallenge/CombineFromPublic). A registered-but-malicious member can commit an arbitrary `t_i` shifting `pk*`. Bound (`Power2Round(Σtᵢ).t1==pk*.t1`) is only in the **optimistic** `ProvenanceVerifyF`, not the hot path. | Security | done | **[DONE]** — the consensus verify path now reconstructs `pk*` ONLY from epoch-key-tree-committed, registration-authenticated keys via `mladsaconsensus.EpochKeyTreeStore.Resolve` (wired into `attestation.AggregateAttestationPubkey`): per attester it checks `VerifyEpochRoot` (root signed by the reg key) + regpk==beacon-state pubkey + `VerifyContentInTree` (F-C9 membership for the predictable (slot,committee) label) + coeff-range, then `AggPkStar`. An injected/equivocating `tᵢ` therefore cannot enter `pk*`. (Earlier coeff-range gate in `VerifyAggregatedAttestation` closed the DoS panic.) Test `TestEpochKeyTreeResolver_EndToEnd` + 4 negative controls. Remaining: populate the store from beacon-state/p2p at epoch boundaries (state plumbing). |
| **H5** | Replacing `repeated bytes signatures` (per-attester list, invariant `len(sigs)==len(bits)` enforced at `attestation_utils.go:68/138/150`, `signature.go:203`) with one ML-ADSA aggregate changes **SSZ hash-tree-root shape**, per-index verification, **slashing/equivocation** detection, fork-choice, and the aggregator gossip topic. | Security/Ops | **NOT** | **[PHASE 1+2 DONE]** — Phase 1: `mladsa/consensus.go` + `mladsaconsensus/`. **Phase 2 (docs/29): the proto/SSZ field is now a single fixed 4627 B `bytes signature` by construction** (proto×4 + regenerated `pb.go`/`generated.ssz.go` — new HTR layout, hard fork), and the verification (`VerifyIndexedAttestationSigs`/`createAttestationSignatureBatch` → one aggregate vs reconstructed `pk*`, ctx `"ZOND"`) and aggregation (`AggregatePair`/max-cover → single-aggregate dedup, distinct-merge errors) are rewritten. **Whole non-test module builds clean.** Tests: SSZ+proto round-trip, real-crypto verify-path (accept + nil-resolver/wrong-pk*/tamper reject). Remaining: H4-full epoch-tree `pk*` wiring, H6 batch-verify, slasher load-path, `_test.go` suite migration. |
| **H6** | Each slot every node runs a full ML-ADSA `Verify` (NTT-heavy, 4627 B) — materially costlier than BLS; attacker-floodable gossip with no batch-verify / rate-limit ⇒ DoS surface. (Core ordering is OK: `Verify` does cheap z-bound/weight checks before `ExpandA`; `CombineFromPublic` checks `maxAbs` first.) | Ops/Security | **NOT** | **[DESIGN]** — batch verification + gossip rate-limiting are integration work. |

## Medium

| # | Finding | Sec/Ops | Easy? | Status |
|---|---|---|---|---|
| **M2** | `OneTimeGuard` was an **in-memory map** (`construction_f.go`). On node restart it reset → the same `(id, content)` could be re-signed with the same deterministic nonce → **two sigs, same y, different c ⇒ secret recovery**. (`Audit` only catches *distinct* `t` for the same `(id,C)`, not same-`t` nonce reuse.) | Security | **EASY** (turned out localized) | **[PATCHED]** — added `DurableOneTimeGuard` (`onetime_durable.go`, both copies): append-only **fsync'd** used-set with **mark-before-sign** (write-ahead) and torn-record-safe replay, so reuse is refused **across restarts**. `AggregateF` now takes the `oneTime` interface (in-mem or durable). Tests `TestDurableOneTime_SurvivesRestart`, `TestAggregateF_DurableReuseAcrossRestart`. (Optional bounded variant — a monotonic per-epoch content counter à la SP 800-208 — remains a future optimization; the durable used-set is correct for arbitrary contents.) |
| **M5** | On `maxAttempts` exhaustion `AggregateF` errors and the devnet calls `die()` (crash); `AggregateRejfree`/`AggregateM1` return `(nil,nil)` which callers (`SignSingle`/`MemberKeyGen`/`EpochKeyTreeBuild`) don't nil-check. | Ops | **EASY** | **[PATCHED]** — the devnet's combine-bounds failure (the cited liveness event) now **abstains** from the slot (`return` + log) instead of `die()`; the signing root is fresh next slot. A self-produced aggregate that *fails verification* (a correctness violation, not liveness) stays loud in the devnet (prod would log+abstain+alert). The `n==0` `(nil,nil)` paths are unreachable here (committee always non-empty) and already guarded upstream (M6/M7). |
| **M6** | `AggregateM1`: `box := (GAMMA1-BETA)/n` → **division-by-zero panic if `n==0`** (reachable if all participants are filtered/excluded). | Security | **EASY** | **[EASY]** guard `if n==0 { return nil,nil }` (and reject empty participant sets upstream). |
| **M7** | Empty participant set: `SharedChallenge`/`CombineFromPublic` over empty `ids/ts/zs` produce a **degenerate all-zero aggregate** ("aggregate of nobody") rather than rejecting. | Security | **EASY** | **[EASY]** require `len(participants) > 0` in `AggregateF`/`CombineFromPublic`. |
| **M1** | `highbits` is not reduced mod `m` while `useHint` is; consistency relies on `decompose` never returning `r1==m` (the `q−1` special case prevents it) — fragile, unasserted. | Security | **EASY** | **[EASY]** add `% m` to `highbits` or an assertion + test. |

## Low

| # | Finding | Sec/Ops | Easy? | Status |
|---|---|---|---|---|
| **L1** | `rejNTTPoly` uses a fixed 4096-byte SHAKE buffer; on (astronomically rare) heavy rejection it over-reads → panic. Deterministic in `ρ` (fixed/honest), so not attacker-triggerable. (`rejBoundedPoly` already grows its buffer correctly.) | Ops | **EASY** | **[EASY]** stream or grow the buffer like `rejBoundedPoly`. |
| **L2** | `wire.go MarshalMember` serializes the **master seed + s1/s2** (secrets) to JSON; `UnmarshalMember` does no validation. Unused on the devnet wire (only public data is gossiped) but a loaded gun. | Security | **EASY** | **[EASY]** restrict to public fields / remove; never serialize secrets. |
| **L3** | Devnet file-bulletin: `commit`/`resp`/`agg` files are **not individually authenticated** (only `reg` is PoP-bound); fine as a P2P stand-in, does **not** translate to production. | Sec/Ops | n/a | **[DESIGN]** production needs authenticated p2p (sender-auth, equivocation handling). |
| **L4** | Verification comparisons are non-constant-time — **benign** (public data). | Security | n/a | acceptable. |
| **L5** | `epochBytes` (big-endian) vs `slotBytes`/upstream `IsAggregator` (little-endian) — consistent per use but mixing BE/LE across shared hashes is fragile. | Ops | **EASY** | **[EASY]** standardize endianness. |

## Disposition

- **Patched now:** **H1/H2** (remote-DoS `Verify` guard), **M2** (durable one-time state), **M6**
  (n==0 div-0 guard in AggregateM1/Rejfree), **M7** (empty-participant guard in AggregateF/
  CombineFromPublic), **L1** (rejNTTPoly streaming — no over-read; byte-identical output, KATs
  unchanged), **L2** (removed dead `wire.go` that serialized the master seed), **H3** (shape/range
  `ValidVec` gate added + wired into the devnet commit/response path), and **M1** (full-sweep test
  proving `highbits(r)∈[0,m)` — the useHint/highbits invariant). Tests: `TestVerify_RejectsMalformedInput`,
  `TestHighbits_InRange`, `TestValidVec`, `TestDurableOneTime_*`. KATs unchanged (no behavior drift).
- **Also patched this pass:** **M5** (devnet combine-bounds failure now **abstains** per slot instead of
  `die()`), **H4 partial** (coeff-range/shape gate on committed `tᵢ` at the consensus verify boundary —
  closes the `AggPkStar` remote-DoS panic; tests `TestMalformedAttesterKey_RejectedNotPanic`).
- **Still recommended (localized, not yet applied):** L5 (BE/LE endianness standardization — deferred:
  changing `epochBytes` would churn the pinned KATs for no functional gain), H3 message **size cap**
  (structural once the Phase-2 fixed-size `bytes signature` field lands, H5/docs/29).
- **H5 Phase 1 implemented (docs/29):** a single ML-ADSA aggregate now occupies the existing
  `signatures` field of the real `qrysmpb.Attestation` (`mladsa/consensus.go`, `mladsaconsensus/`),
  proven to compress 12–128× with intact SSZ hash-tree-root and an unmodified FIPS-204 verifier, and to
  reject tampering / sybil key-substitution. Phase 2 (proto/SSZ hard-fork to a single `bytes signature`,
  verification + aggregation + slasher rewrite) remains design-level and is gated on H4/H6.
- **Design-level (not quick patches):** H4 (`t_i` well-formedness binding), H5 **Phase 2**
  (proto/SSZ/slashing/fork-choice swap — see docs/29), H6 (batch-verify/rate-limit), L3 (authenticated
  p2p). These are the real integration milestones, tracked in `qrl-integration/README.md` and docs/23.

**Bottom line:** the inner cryptography is sound and cross-checked; the audit's actionable surface is
input validation (mostly easy — the critical `Verify` panic now fixed) and the consensus-integration
semantics (design-level). The most dangerous item, **M2** (durable one-time state — deterministic-nonce
reuse on restart ⇒ key recovery), is now **fixed** with a fsync'd, mark-before-sign durable used-set.
**H5 Phase 1** is implemented (single aggregate in the real `Attestation`, docs/29) and **H4** has its
DoS-panic surface closed; the remaining substantial work is the Phase-2 consensus-integration design
items: **H4-full** (mandatory provenance binding of `tᵢ`), **H5 Phase 2** (proto/SSZ hard-fork +
verification/aggregation/slasher rewrite), **H6** (batch-verify/rate-limit), and **L3** (authenticated p2p).
