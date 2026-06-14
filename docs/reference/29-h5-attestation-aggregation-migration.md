# 29 — H5: migrating qrysm attestation aggregation from a signature-list to one ML-ADSA aggregate

Audit finding **H5** (docs/26): qrysm carries a *list* of per-attester ML-DSA-87 signatures and the
invariant `len(signatures) == len(attesting_indices)` is load-bearing across SSZ, indexed-attestation
conversion, signature verification, slashing, fork-choice, and the aggregator gossip topic. Replacing
that list with a single ML-ADSA aggregate is the real integration milestone behind the project goal —
[[project-goal]] BLS-like aggregation for QRL 2.0. This document specifies the migration in two phases,
with **Phase 1 implemented and tested now** (`mladsaconsensus/`), and **Phase 2** scoped as the
proto/SSZ-codegen effort.

## 0. Why a list exists at all

ML-DSA-87 signatures do **not** concatenate-combine: there is no public operation that takes
`{σ_1,…,σ_n}` over the same message and yields one short signature an unmodified verifier accepts. So
upstream qrysm — like every naïve PQ port of a BLS pipeline — simply keeps every signature:

```
proto/qrysm/v1alpha1/attestation.pb.go:32
  Signatures [][]byte  `ssz-max:"128" ssz-size:"?,4627"`   // up to 128 × 4627 B ≈ 592 KB
```

Construction F's decentralized §7.7 combine (docs/17; `mladsa/decentralized.go`) *does* produce one
byte-exact ML-DSA-87 signature from the committee's **public** per-content contributions, verifiable
against a reconstructed aggregate key `pk*`. That is what makes the list collapsible to a single
element. The combine is the proven path — `CombineFromPublic` is byte-identical to `AggregateF`
(`TestDecentralized_EqualsAggregateF`), and is non-interactive ([[ml-adsa-noninteractive]]) and has no
intermediary aggregator (every value is public, so each validator self-combines).

## 1. The load-bearing invariant (what must change)

`len(signatures) == len(attesting_indices)`, enforced at:

| Site | Line | Role |
|---|---|---|
| `proto/.../attestation/attestation_utils.go` `ConvertToIndexed` | 68–69 | rejects unless `len(att.Signatures) == len(attestingIndices)`; pairs each sig with an index |
| `proto/.../attestation/attestation_utils.go` `(indexed) verify` | 138–139, 150–153 | `len(indexedAtt.Signatures) == len(pubKeys)`; loops, decoding `Signatures[index]` per attester |
| `beacon-chain/core/blocks/signature.go` `createAttestationSignatureBatch` | 187–226 | builds a **parallel** batch: `sigs[i]=ia.Signatures`, one pubkey per index, message = `ComputeSigningRoot(ia.Data, domain)`; verifies each (sig_j, pk_j, msg) |
| `proto/.../generated.ssz.go` `Attestation.HashTreeRootWith` | 158–177 | merkleizes the signature **list** (each element must be 4627 B; ≤128) into the attestation root |

So the signature list is woven into: indexed-attestation conversion, the per-index verification batch,
and the SSZ hash-tree-root (hence block roots, fork-choice, and the slasher, which keys on the indexed
attestation). Any swap must preserve a verifier that, given the **public** attesting set, accepts.

## 2. The replacement primitive

`mladsa/consensus.go` (new) provides the consensus-flavoured §7.7 combine over an **explicit** message
(the attestation signing root) with `ctx = domain` — no decision-mode `bindMsg` wrapper, because for an
attestation the "who" is the public `AggregationBits` and the "what" is the signing root:

```
AggPkStar(rho, ts)                       -> pk* = (rho, Power2Round(Σ tᵢ).t1)         // verifier side
ConsensusContentKeys(rho, msg, members)  -> [tᵢ = ContentKeyDerive(seedᵢ,A,msg).t]   // epoch-tree data
ConsensusAggregate(rho, ctx, msg, members, σ) -> (pk*, σ*, [tᵢ], ok)                  // aggregator side
```

`ConsensusAggregate` runs the proven combine: per member `ContentParts → (skᵢ, yᵢ, wᵢ)` (per-message
key + deterministic nonce refresh, F-C4), `pk* = AggPkStar`, `W*=Σwᵢ`, `c̃* = H(μ ‖ w1Encode(HighBits W*))`,
`zᵢ = ContentResponse(skᵢ,yᵢ,ĉ)`, `σ* = CombineFromPublic(...)`. Tests `TestConsensusAggregate_RoundTrip`
(N∈{1,4,16,64}, unmodified `Verify(pk*,msg,σ*,ctx)` accepts; verifier independently rebuilds the same
`pk*` from `tᵢ`) and `TestConsensusAggregate_Refresh` (different message ⇒ different `pk*`/`σ*`;
cross-message verification fails — no leak).

**One-time discipline.** The signing root is unique per `(slot, committee, data)`, so the deterministic
nonce `DeriveNonce(seed, root)` is one-time per attestation; production must guard re-aggregation of the
*same* root with the `DurableOneTimeGuard` (audit M2, `onetime_durable.go`) — the same restart-safe,
fsync'd, mark-before-sign used-set already shipped for `AggregateF`.

## 3. Phase 1 — single aggregate in the existing field (IMPLEMENTED)

`mladsaconsensus/attestation.go` wires the primitive onto the **real** `qrysmpb.Attestation` with **no
proto/SSZ regeneration**: the `Signatures [][]byte` field is kept but holds **exactly one** element —
the aggregate.

```
AggregateAttestation(rho, domain, signingRoot, data, committee, bits)
    -> (*qrysmpb.Attestation{AggregationBits: bits, Data: data, Signatures: [][]byte{σ*}}, [tᵢ for set bits], err)
VerifyAggregatedAttestation(att, attesterKeys, rho, domain, signingRoot) bool
    // requires len(att.Signatures)==1; pk* = AggPkStar(rho, attesterKeys); mladsa.Verify(pk*, signingRoot, σ*, domain)
```

The Phase-1 invariant `len(att.Signatures)==1` **replaces** `len(sigs)==len(bits)`. `attesterKeys` are
the attesting members' public per-content keys (set-bit order) — in production sourced from the epoch
key-tree (§6.2, `VerifyContentInTree`), so the verifier needs no secret.

**What the tests prove** (`mladsaconsensus/attestation_test.go`, all green):
- `TestAggregateAttestation_SingleSigCompression`: 16-member committee, 12 attesters → **one** 4627 B
  aggregate (vs. 12 × 4627 = 55 524 B); the populated `*Attestation` produces a non-zero **SSZ
  HashTreeRoot** (still a valid hashable consensus object); bits preserved; verification accepts.
  Measured: **12.0× signature-payload reduction** — no needed information lost (the public signer set
  is exactly the `AggregationBits`, and `pk*` is reconstructible from the epoch-tree `tᵢ`).
- `TestVerify_RejectsTampering`: wrong signing root, wrong domain, truncated/altered attester-key set,
  flipped signature byte, and a 2-signature (non-Phase-1) attestation are all rejected.
- `TestSybil_WrongKeySetCannotForge`: substituting a fabricated member's per-content key into the
  reconstructed set fails to verify — `pk*` binds the exact attesting set (fakes can't change the
  result).
- `TestEmptyBits_Rejected`: no attesters ⇒ `ErrNoAttesters` (audit M7 discipline).

Phase 1 is buildable in isolation today: `go build ./proto/qrysm/v1alpha1/`, `go build ./mladsa/`,
`go build ./mladsaconsensus/` all succeed; the proto's committed `generated.ssz.go` hashes the
single-element list unchanged.

### 3.1 Compression accounting (no lost information)

| Committee attesters n | Upstream list | ML-ADSA Phase 1 | Reduction |
|---|---|---|---|
| 16 | 74 032 B | 4 627 B | 16.0× |
| 64 | 296 128 B | 4 627 B | 64.0× |
| 128 (max) | 592 256 B | 4 627 B | 128.0× |

The aggregate is **constant-size** (4627 B) regardless of committee size. The only per-attester data
that remains is the `AggregationBits` (≤16 B for 128 members) — which is *already* present upstream and
is exactly the public information the verifier needs to select the `tᵢ` and rebuild `pk*`. Nothing
needed is dropped: signer set = bits, key = Σ epoch-tree `tᵢ`, validity = one FIPS-204 `Verify`.

## 4. Phase 2 — proto/SSZ shrink to a single `bytes signature` (IMPLEMENTED)

Phase 2 makes the type honest: `Attestation`/`IndexedAttestation` now hold ONE fixed-size
`bytes signature = 3 [ssz_size 4627]` by construction, not a `repeated bytes` list. The entire qrysm
module (every non-test package) **builds clean** with the change.

### 4.1 Toolchain reproduction (no Bazel)

The repo's codegen is Bazel-driven (`protoc-gen-go-cast` + fastssz `sszgen`), and Bazel is unavailable
here. Both generators were reproduced standalone:

- **`pb.go`**: the repo's committed files are `protoc-gen-go v1.36.5`, but the go.mod-pinned
  `protoc-gen-go-cast` (v0.0.0-20230228) bundles an old `internal_gengo` (v1.26.0) whose output a modern
  `protoc` (libprotoc 34.1) makes `format.Source` reject on the larger files. Fix: **rebuilt the cast
  plugin against `google.golang.org/protobuf v1.36.5`** (it imports `internal_gengo` as a regular
  package), which regenerates the two small `attestation.pb.go` faithfully (v1.36.5 style + the
  `ssz-size:"4627"` tag, single field + `GetSignature`). For the two large `beacon_block.pb.go` (which
  still tripped the plugin's `format.Source`), the change is surgically **spliced**: start from the
  committed cast-correct file, swap the `IndexedAttestation` field + getter, and replace the embedded
  `rawDesc` literal with one from a clean `protoc --go_out` regen of the edited proto (the rawDesc is a
  self-contained serialized `FileDescriptorProto`; field/dep indices are unchanged because only a scalar
  `bytes` field's cardinality changed). Verified: `proto.Marshal`/`Unmarshal` round-trips at runtime
  (the spliced descriptor matches the struct — see `TestPhase2_SSZAndProtoRoundTrip`).
- **`generated.ssz.go`**: regenerated with go-installed `sszgen` (from the pinned fastssz dep) over a
  temp dir of just the package's `.pb.go` files (sszgen chokes on the package's `context`-importing
  `.pb.gw.go` gateway files, which Bazel sandboxes out). Result: field (2) is now a **fixed 4627-byte
  vector** (`buf[132:4759]`), not a merkleized list with mixin — the attestation now has exactly ONE
  variable field (the bitlist). This **changes the attestation hash-tree-root layout** → a hard fork.

### 4.2 What changed (done)

1. **Proto** (4 files: `attestation.proto` + `beacon_block.proto` in both `qrysm/v1alpha1` and `qrl/v1`):
   `repeated bytes signatures = 3 [ssz_max 128, ssz_size "?,4627"]` → `bytes signature = 3 [ssz_size "4627"]`.
2. **IndexedAttestation** mirrors the change; `ConvertToIndexed` (`attestation_utils.go`) drops the
   `len(sigs)==len(indices)` check, sorts the attesting indices, and carries the single aggregate.
3. **Verification** (`attestation_utils.go:VerifyIndexedAttestationSigs`, `signature.go:createAttestationSignatureBatch`):
   the per-index parallel loop is replaced by ONE aggregate verify — `pk*` is reconstructed from the
   attesting validators' epoch-key-tree per-content keys via the new seam
   `attestation.AggregateAttestationPubkey`, message = `ComputeSigningRoot(data, domain)`, ctx = `"ZOND"`
   (the hardcoded go-qrllib wallet domain constant — unchanged by the Zond→QRL 2.0 rename), one
   `ml_dsa_87` verify (the aggregate σ* is a byte-exact ML-DSA-87 signature under pk*). The
   `SignatureBatch` now carries one entry per attestation (σ* vs pk*), not one per attester. The resolver
   is **nil by default** so verification never silently accepts without the epoch key tree (the
   **H4-full** binding); deployments/tests wire it.
4. **Aggregation** (`aggregation/attestations/{attestations,maxcover}.go`): the BLS-style
   `AggregatePair`/max-cover **signature-list splice is removed** — finished ML-DSA-87 aggregates cannot
   be byte-merged. The bit/coverage selection is kept; the merged `Signature` is the *common* aggregate
   (dedup of identical σ*), and merging *distinct* aggregates returns the new
   `ErrMLADSADistinctAggregates` (the union aggregate must come from the single-shot §7.7 combine over
   per-validator contributions, i.e. `mladsaconsensus`/`mladsa.CombineFromPublic`).
5. **Conversions / API** migrated: `cloners.go`, `proto/migration/v1alpha1_to_v1.go`, the
   `beacon-chain/rpc/qrl/shared` JSON structs (`signatures []string` → `signature string`), validator
   client beacon-api helpers, slasher simulator, test utils — the whole module compiles.

### 4.3 Remaining (Phase 2 follow-on, design-level)

- **H4-full**: implement `attestation.AggregateAttestationPubkey` against the real beacon-state epoch
  key tree (the static validator registration pubkey carries only `t1`; the full per-content `tᵢ` live in
  the epoch key tree). Until then the hot path refuses (honest, not silently-accepting).
- **Slashing**: surround/double-vote detection keys on `(indices, data)` — shape-unaffected — but the
  slasher's signature check uses the aggregate-verify path (now wired through `VerifyIndexedAttestationSigs`).
- **H6**: batch ML-ADSA verify + gossip rate-limiting (heavier than BLS). **H3** size-cap is now
  structural (fixed 4627 B field).
- **Test suite**: the production code builds clean; the `_test.go` suite across the tree still uses the
  old `.Signatures` field and needs the same mechanical migration (and the aggregation tests need
  rewriting to the single-aggregate semantics — `AggregatePair` now dedups/errors instead of splicing).

## 4.4 Backward compatibility + aggregate equivalence (`mladsalegacy/`)

ML-ADSA loses BLS's commutativity/free mergeability, and the Phase-2 wire change drops the per-attester
list. Two consequences are handled by the new `mladsalegacy` package so the transition is non-destructive:

- **Legacy concatenated aggregates stay valid, in parallel.** `mladsalegacy.VerifyLegacyConcatenated`
  reproduces the EXACT former upstream verification (extracted from the pristine `upstream/qrysm`
  `attestation_utils.go`: `len(signatures)==len(pubKeys)`, `messageHash=ComputeSigningRoot(data,domain)`,
  each per-attester ML-DSA-87 `sig.Verify(pubkey, root)`), operating on a self-contained
  `LegacyConcatenatedAttestation` (the proto type itself no longer carries the list).
  `UnmarshalLegacyAttestationSSZ` decodes the OLD wire layout (fixed part 136, two offsets — bitlist +
  signature list), and `DetectFormat` distinguishes legacy bytes (first offset == 136) from new
  single-aggregate bytes (first offset == 4759), so a node runs BOTH validators and routes
  historical/in-flight aggregates correctly. So a larger aggsig that came from concatenation (former
  work) is still validated.
- **Aggregate equivalence ("say the same thing").** Now that byte-canonicality no longer holds across
  aggregation paths, `mladsalegacy` provides a statement-equivalence: `SameStatement` / `EquivalentNew` /
  `EquivalentAcross` decide whether two aggregates certify the same **signer set** (AggregationBits) over
  the same **AttestationData** (by SSZ hash-tree-root) — across legacy-concat and ML-ADSA forms.
  `ByteIdentical` captures the STRONG case: because `ConsensusAggregate` is deterministic (PRF nonces +
  sorted participants), identical (signer set, message) inputs yield a byte-identical σ* (dedup).
  Tests: `TestLegacyConcatenated_VerifyAndDecode` (verbatim verify + old-format decode/round-trip +
  tamper/len/domain rejection), `TestDetectFormat_NewVsLegacy`, `TestEquivalence` (cross-format
  equivalence, signer-set/data discrimination, byte-identity). See [[h5-legacy-and-equivalence]].

## 4.5 Order-independence, equivalence, partiality, and equivalence-class hardness

Four properties requested for the transition (all implemented + tested/proven):

- **Order / collection-path independence (byte-identical).** The §7.7 combine is built entirely on
  commutative coefficient sums (`pk* = AggPkStar(Σ tᵢ)`, `W* = Σ wᵢ`, `z* = Σ zᵢ`) and Construction-F
  uses deterministic PRF nonces, so aggregating the SAME final component set in ANY input order (or any
  incremental collection order) yields a **byte-identical** `pk*` and `σ*`. Two groups aggregating the
  same components independently with differently-ordered lists therefore always agree and cross-validate.
  Test `TestAggregate_OrderInvariant` (12 members × 11 permutations: reverse, rotations, seeded shuffles
  → identical bytes + mutually equivalent + valid). NOTE: this is input-order independence within ONE
  combine; it is distinct from BLS-style *merging of finished aggregates*, which ML-ADSA cannot do (the
  challenge `c̃*` depends on the full `W*`).
- **Aggregate equivalence (no byte-equality required).** `mladsaconsensus.SignaturesEquivalent` decides
  whether two aggregates are EQUIVALENT = both valid signatures certifying the SAME statement (same
  `pk*`, which deterministically encodes the signer set, over the same message/ctx). ML-DSA-87 is not a
  unique-signature scheme, so this is the right general notion; it is the safety net for aggregates
  assembled by different parties/paths. Plus `mladsalegacy.SameStatement`/`EquivalentAcross` for the
  cross-format (legacy-concat ↔ ML-ADSA) statement equivalence. Test
  `TestSignaturesEquivalent_Discrimination` (same set ⇒ equivalent; different/partial set ⇒ different
  `pk*` ⇒ not equivalent; tampered ⇒ not equivalent).
- **Partial recognizable as partial.** `AggregationBits` is the explicit, cryptographically-BOUND record
  of exactly who signed (`pk*` is reconstructed from precisely the epoch-tree keys the set bits select,
  and `σ*` verifies only under that `pk*` — an aggregator cannot inflate the bits to pass a partial off
  as complete without those members' real contributions). So `mladsaconsensus.IsPartial` / `IsComplete` /
  `Coverage` / `MeetsQuorum` decide partiality from the bits relative to committee size / quorum, and it
  is tamper-evident. Test `TestPartialRecognizable`.
- **Equivalence-class guessing is as hard as normal ML-DSA (machine-checked).** For a fixed `(pk*, m)`
  the equivalence class is `{σ : verify pk* m σ}`; it may hold >1 element. `formal/ml_adsa_euf.ec` now
  proves `equiv_class_guess_bound`: producing ANY class member (un-queried `m`, PoP-valid cohort) is —
  by definition of the class — exactly the MSUFCMA win, so it inherits the SAME tight bound
  `adv_mlwe + Pr[STMSIS]`. The multiplicity of valid signatures gives the adversary **no advantage**, and
  the bits of security equal ML-DSA-87 Cat 5 (`pk*` is a bona fide ML-DSA key — sum of MLWE samples is
  MLWE — and `verify` is the unmodified FIPS-204 verifier). Lemmas `in_equiv_classE`,
  `equiv_class_guess_eq_forge`, `equiv_class_guess_bound`; whole formal suite green (26 classical EC +
  5 quantum + 5 Coq = 36 artifacts).

## 4.6 Live local-net proof: aggregate-of-aggregates is order-independent (`cmd/mladsa-hieragg`)

A real, multi-process local net demonstrating — beyond a shadow of a doubt, no mocks/string-print fakes
— that ML-ADSA "aggregate of aggregates" is order- and grouping-independent:

- **Roles (separate OS processes, real crypto):** `user` (a real random ML-DSA key; publishes a real
  §7.7 commitment `w_i` then response `z_i` over the real shared challenge), `aggregator` (performs a
  genuine HIERARCHICAL combine — sums each sub-group's responses into a partial sum via
  `mladsa.CoeffSumL`, then sums the partials in its assigned order, then `mladsa.CombineFromPublic`),
  and `judge` (trusts nothing: independently re-derives `pk*`+signed-message from the public
  commitments, byte-compares both aggregators' `σ*`/`pk*`, and RE-VERIFIES both `σ*` with go-qrllib's
  native `ml_dsa_87.Verify`; exits non-zero on any mismatch).
- **Result.** Two aggregators with DIFFERENT partitions and DIFFERENT orders (Alice
  `[[1,2,3],[4,5],[6,7,8]]` / `0,1,2`; Bob `[[6,7],[8,1,2],[3,4,5]]` / `2,1,0`) produce the
  BYTE-IDENTICAL `σ*` and `pk*`, both go-qrllib-native-verified — judge exit 0.
- **Negative controls (prove the judge has teeth).** (a) a byzantine aggregator that DROPS a signer →
  the combine fails its FIPS-204 bounds (defense in depth) → rejected; (b) one that publishes a
  TAMPERED `σ*` → the judge's independent native re-verification fails + byte-mismatch → rejected. Both
  exit non-zero.
- **Why this is the only sound "aggregate of aggregates":** finished aggregates cannot be merged (the
  Fiat-Shamir challenge `c̃*` depends on the full `Σ wᵢ`); hierarchical aggregation is done on the
  CONTRIBUTIONS via associative/commutative mod-q coefficient summation, hence byte-identical regardless
  of grouping/order. Run: `zsh cmd/mladsa-hieragg/run-hieragg.sh` (positive + both negatives, asserted).

## 4.6b H4-full: AggregateAttestationPubkey wired to the real epoch key tree (DONE)

The verification seam `attestation.AggregateAttestationPubkey` is now backed by an **authenticated
epoch-key-tree resolver** (`mladsaconsensus/epochtree.go`), closing the H4-full gap (a static validator
registration pubkey only carries `t1`; the full per-content `tᵢ` live in the signed epoch tree).

- **Predictable content label.** The per-content KEY refresh is keyed by `AttestationContentLabel(data)
  = (slot, committee_index)` — predictable at epoch start, so the epoch tree can pre-commit it — while
  the Fiat-Shamir message μ binds the full signing root. `mladsa.ConsensusAggregateLabeled` separates
  the key label from the signed message; `AggregateAttestation` now uses it (one-time per
  (validator, slot, committee), so the deterministic nonce is never reused — §4.7).
- **`EpochKeyTreeStore` + `Resolve`.** Maps validator index → its signed epoch commitment (root +
  `SigReg` + per-label key + Merkle path). For each attester the resolver enforces: (1) the epoch root
  is authentic — `mladsa.VerifyEpochRoot` (signed by the registration key); (2) the committed registration
  key matches the beacon-state pubkey (defense in depth); (3) the key is a proven member of that root for
  the content label — `mladsa.VerifyContentInTree` (F-C9); plus a coeff-range gate. Only then
  `pk* = AggPkStar(rho, Σ tᵢ)`. `store.Install()` activates it across the consensus verify path.
- **Test** `TestEpochKeyTreeResolver_EndToEnd`: real epoch trees built + committed; the aggregate verifies
  through `VerifyIndexedAttestationSigs` with pk* from the authenticated tree; **four negative controls
  rejected** — uncommitted/injected key (membership fails), forged epoch root (authenticity fails),
  regpk mismatch vs beacon state, and an attester with no commitment.

This means an injected or equivocating `tᵢ` cannot shift `pk*` (the original H4 risk): only
epoch-tree-committed, registration-authenticated keys enter the aggregate key.

**Epoch-boundary population from beacon state (`mladsaconsensus/epochpopulate.go`, DONE).** The store is
populated at each epoch boundary directly from the REAL `state.ReadOnlyBeaconState`:
`BuildEpochKeyTreeStore` iterates the **active** validator set (`ReadFromEveryValidator` +
`helpers.IsActiveValidatorUsingTrie`), reads each validator's on-chain **registration pubkey**
(`val.PublicKey()`), pulls that validator's published epoch commitment (root + `σ_reg` + per-content
keys + Merkle paths) from an `EpochKeyProvider` (the p2p/gossip cache), and **authenticates the root
against the on-chain pubkey** via `mladsa.VerifyEpochRoot` before recording it. `InstallEpochKeyTreeStore`
builds + installs it and returns the EXCLUDED validators (those with a missing/unauthentic commitment —
they simply can't contribute to any `pk*`). Key design point: **no new beacon-state field is required** —
the on-chain registration pubkey is the trust anchor, and `σ_reg` binds the (off-chain, p2p-published)
epoch-key root to that on-chain identity (§7.4). Test `TestPopulateFromBeaconState_EndToEnd` constructs a
real `BeaconStateZond` whose validators' pubkeys are the members' registration keys, populates from it,
verifies a real aggregate through the consensus path using the state-resolved `pk*`, and confirms an
uncommitted validator is excluded (and that including it fails verification).

**Production glue + live proof (`mladsaconsensus/epochcache.go`, `cmd/mladsa-epochnet`, DONE).** The
remaining pieces are now concrete and proven end to end:
- **Publish:** `PublishEpochKeyBundle` builds a validator's epoch tree and returns the gossip
  `EpochKeyBundle` (root + σ_reg + per-content keys + Merkle paths).
- **Validating gossip cache:** `GossipEpochKeyCache` implements `EpochKeyProvider`; `Ingest` REJECTS
  (never caches) a bundle whose root isn't signed by the claimed reg key or any of whose content keys
  isn't a committed member of the root — the gossip-validation gate.
- **Epoch hook:** the node calls `InstallEpochKeyTreeStore(ctx, state, rho, epoch, cache, labels)` at the
  boundary (binding each cached commitment to the on-chain reg pubkey again).
- **Integration test** `TestGlue_PublishIngestRefreshVerify`: publish → validating ingest (with forged-root
  and tampered-key ingest rejections) → real beacon state → refresh → aggregate → verify.
- **Live multi-process** `cmd/mladsa-epochnet` (`run-epochnet.sh`): N validator processes publish bundles
  + contributions; a node process ingests/validates into the cache, builds a real `BeaconStateZond` from
  the published reg keys, installs the resolver, combines the decentralized aggregate, and verifies via
  `attestation.VerifyIndexedAttestationSigs` (pk* from the epoch tree) AND go-qrllib native — node exit
  code is the verdict. **Proven live:** all-honest → verified (exit 0); with a forged validator → its
  bundle is rejected at ingest and it is excluded, and the honest set STILL produces a valid verified
  aggregate (resilience). The end-to-end trust chain runs unbroken: on-chain reg pubkey → VerifyEpochRoot
  → VerifyContentInTree → AggPkStar → FIPS-204/go-qrllib verify.

## 4.7 Determinism, nonces, and equivalence-class hardness in BOTH ROM and QROM

The byte-identity of §4.6 comes from deterministic per-content nonces (`DeriveNonce(seed, C, σ)`, a PRF),
not randomness. This is the modern *defensive* default (RFC 6979 deterministic ECDSA, EdDSA, FIPS-204
ML-DSA itself derive the nonce from the key+message) — it eliminates the single biggest real-world
signature failure mode (biased/backdoored RNG leaking the key). The one inherent risk of determinism —
the same nonce under two *different* challenges yields `z−z' = (c−c')·s1` ⇒ key recovery — is closed by
three layers, the core machine-checked:

1. **Per-content one-time release (N1/N2 + audit M2):** each validator emits exactly one `z_i` per
   content label; the restart-safe fsync'd `DurableOneTimeGuard` refuses a second release, so a
   malicious aggregator presenting a different participant subset (hence a different `c̃*`) cannot
   extract a second `z_i` from the same `y_i`.
2. **Commitment-bound unbiasable challenge (ROS defense — proven):** `formal/ml_adsa_F_concurrent.ec`
   proves the aggregate challenge is independent of the adversary's nonce (`unbiasable_challenge`,
   `challenge_adversary_independent`), so the Drijvers/ROS linear system is unsolvable and concurrent
   EUF-CMA collapses to the single-session bound — **no ROS/AGM/OMDL assumption**.
3. **Equivocation is slashable** (and self-punishing: it *is* the nonce reuse that leaks the key).

**Operational rule this imposes:** one content label = one canonical participant set = one challenge =
one response per validator. This is exactly why §4.6's two aggregators used the SAME signer set (same
`c̃*`, each validator releases `z_i` once) — order/grouping differed, the challenge did not. Producing
two *different-subset* aggregates of the same content from the same validators is correctly impossible
(the one-time guard refuses the second response).

**Equivalence-class guessing = ML-DSA hardness, ROM and QROM.** Because ML-DSA-87 is not a
unique-signature scheme, the set `class(pk*, m) = {σ : verify pk* m σ}` may hold >1 element; producing
ANY member without the secret is, by definition, the EUF-CMA win, so it inherits the tight bound with no
advantage from multiplicity. Machine-checked in **both** models, per the project's ROM+QROM goal:
`ml_adsa_euf.ec` (`equiv_class_guess_bound` ≤ `adv_mlwe + Pr[STMSIS]`) and `ml_adsa_qrom.ec`
(`qrom_equiv_class_uncond`, quantum adversary, ≤ `adv_mlwe + Pr[QROM_STMSIS(BqCMA)]`). Bits = ML-DSA-87
Cat 5 (`pk*` is a bona fide ML-DSA key — sum of MLWE samples is MLWE — and `verify` is the unmodified
FIPS-204 verifier). Residuals: deterministic signatures are more exposed to *fault/side-channel*
attacks (shared with EdDSA; mitigated by constant-time + fault countermeasures, not a protocol vuln),
and the whole argument rests on the one-time guard being enforced at every validator. See
[[deterministic-nonce-security]].

## 4.8 Future option (documented, NOT implemented): subnet randomness via drand

If a future variant ever needs *true* randomness (e.g. a randomized-nonce mode, or a beacon for
committee selection), one approach: a **drand**-style threshold randomness beacon run as a validator
**subnet**, with the per-round randomness **encrypted between subnet members** (so third parties cannot
learn the values) and the recent series **encrypted at rest**. Trade-off to weigh: losing the stored
series could itself create risks (e.g. inability to reproduce/verify past rounds, or — if randomness fed
nonces — the same nonce-reuse danger determinism avoids). Deliberately left as an idea for now; the
current design needs no external randomness (deterministic nonces, §4.7).

## 5. Status & cross-references

- **Implemented (Phase 1 + Phase 2):** `mladsa/consensus.go`, `mladsaconsensus/` (aggregate + verify on
  the real `Attestation`), the proto/SSZ shrink (single fixed 4627 B `signature`), and the consumer
  rewrites (verification, aggregation, conversions). Whole non-test module **builds clean**. Tests green:
  `TestPhase2_SSZAndProtoRoundTrip` (SSZ marshal/unmarshal + HashTreeRoot stability + `proto.Marshal`
  round-trip + IndexedAttestation SSZ), `TestVerifyIndexedAttestationSigs_MLADSA` (the rewritten consensus
  verify accepts a real §7.7 aggregate via the pk* resolver against the **real** go-qrllib crypto, and
  rejects nil-resolver / wrong-pk* / tampered-sig), plus the Phase-1 compression/tamper/sybil/empty tests.
- **Remaining:** H4-full beacon-state wiring / test-suite migration (the epoch-tree pk* resolver
  itself is DONE — see §4.6b), H6 (batch-verify/rate-limit), slasher
  signature-path validation under load, and the `_test.go` suite migration.
- Related: docs/17 (§7.7 combine), docs/23 (QRL 2.0 deployment), docs/26 (audit; H4/H5 rows), docs/27
  (3-surface code spec), `mladsa/decentralized.go` (`CombineFromPublic`), `cmd/mladsa-devnet` (live
  decentralized consensus devnet).

**Bottom line:** the wire is now honestly single by construction — one constant-size 4627 B ML-DSA-87
aggregate replaces the per-attester list across proto, SSZ (new hash-tree-root layout), verification, and
aggregation; the whole module builds; the aggregate verifies through the real qrysm crypto; and
fakes/sybils/tampering are rejected. The compression is 12–128× with no lost needed information (signer
set = `AggregationBits`, key = Σ epoch-tree `tᵢ`, validity = one FIPS-204 verify). What remains is the
epoch-tree pk* wiring (H4-full), batch-verify (H6), and migrating the test suite.
