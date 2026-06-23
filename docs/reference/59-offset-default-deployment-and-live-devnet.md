# 59 — F-OFFSET is the deployed default: live decentralized devnet + state-of-the-art recommendation

**Status: F-OFFSET (the nonce-hiding, message-bound, σ=3β instantiation) is now the RECOMMENDED, default,
state-of-the-art ML-ADSA construction for deployment.** This document records the decision, the live
multi-node QRL-style devnet that exercises it end-to-end, and the requirement-by-requirement evidence. It
supersedes the "alternative instantiation" framing of [docs/47](47-construction-f-offset.md): F-OFFSET is no
longer an option *alongside* the base full-`w` combine — it is the default, and the base combine is retained
only as a reference/fallback and as the algebraic anchor for the byte-exactness proof.

Source of truth for all verification counts: **`formal/count-artifacts.sh`** (43 prover artifacts, 274
machine-checked lemmas [242 EasyCrypt + 32 Coq], 53/53 genuineness, 6 Gobra). Security framing chain:
[docs/44](44-offset-route-and-lattice-estimate.md) (lattice estimate) → [docs/47](47-construction-f-offset.md)
(construction) → [docs/48](48-offset-euf-small-sigma.md) (EUF, small σ) →
[docs/49](49-sigma3beta-deployment-security.md) (σ=3β default) →
[docs/50](50-tightness-adjusted-security-vs-fusion.md) (tightness, c/q split) →
[docs/51](51-leakage-to-bit-security.md) (leakage register) →
[docs/54](54-key-leak-elimination-and-live-round-safety.md) (key-leak elimination) →
[docs/55](55-message-bound-nonce-few-time.md) / [docs/56](56-toward-stateless-many-time.md) (stateless) →
[docs/57](57-large-cohort-safety-and-noise-flooding-soundness.md) (scale/soundness) →
[docs/58](58-validation-regression-scale-pentest.md) (validation/pentest) → **this doc** (deployment default).

---

## 1. Why F-OFFSET is the default

The base decentralized combine broadcasts the **full** commitment `wᵢ`. With the response `zᵢ` and the tall
matrix `A`, anyone recovers `yᵢ` and then `s1ᵢ` by linear algebra (finding #3; demonstrated empirically,
1792/1792 nonce coefficients recovered exactly). That is a **nonce-exposure** that ML-DSA itself does not have,
and for QRL it is disqualifying: before finalization a thief who recovers a live one-time key could target it.

F-OFFSET removes the exposure at the source. Each signer broadcasts only

- `hiᵢ = HighBits(wᵢ)` — exactly what native ML-DSA already reveals, and
- `qᵢ = LowBits(wᵢ) + rᵢ`, with `rᵢ` a fresh, secret, independent offset of width `±R`,

so recovering `s1ᵢ` is the lattice problem `b = M·s1 + e` (`|e| ≤ R`), which the real lattice-estimator places
at **≥ native** ML-DSA-87 hardness (Cat-5). The output is still a **byte-exact** 4627-byte ML-DSA-87 signature
under the 2592-byte aggregate key, accepted by the unmodified FIPS-204 verifier and by QRL's own go-qrllib
`ml_dsa_87.Verify`.

Combined with the **message-bound deterministic nonce** (`DeriveNonceMB`, σ=3β default, `SigmaOffsetDefault =
3·β`), F-OFFSET is **stateless many-time**: a fixed committee signs unlimited *distinct* decisions with no key
rotation and no one-time guard — reusable like an ordinary ML-DSA key — because distinct decisions get distinct
nonces, so the `(z−z')/(c−c')` reuse attack cannot fire. This is the property the whole research arc was for,
and F-OFFSET is the construction that has it while keeping every original locked requirement.

**Decision: deploy F-OFFSET. The base full-`w` combine is kept as the byte-exactness reference and a
last-resort fallback, not as a deployment option.**

## 2. Live decentralized devnet (the deployment proof, #139)

`cmd/mladsa-devnet` runs a live, decentralized, QRL-testnet-shaped network: every process is a node
(beacon+validator), gossiping public contributions over a shared bulletin; aggregation is the rotating,
permissionless qrysm duty (`IsAggregator`). The **only** change vs current QRL 2.0 is that the per-attester
4627-byte signatures are no longer concatenated (`O(N)` blowup) — instead nodes run the ML-ADSA combine and
emit **one** 4627-byte aggregate. Run the F-OFFSET path with:

```sh
go build -o /tmp/mladsa-devnet ./cmd/mladsa-devnet/
OFFSET=1 N=8 SLOTS=4 ./cmd/mladsa-devnet/run-devnet.sh        # new default path
OFFSET=1 N=8 SLOTS=2 EQUIV=2 SYBILS=2 ./cmd/mladsa-devnet/run-devnet.sh   # with adversaries
```

The offset slot duty (`runSlotOffset`):

1. **Commit (hiding):** each validator runs `OffsetCommitMB(A, seed, C, μ, σ=3β, R, rng)` and publishes only
   `(tᵢ, hiᵢ, qᵢ)` plus the epoch-tree Merkle path for `tᵢ,C`. The nonce is **message-bound** (`μ` = the
   slot's decision/payload), so the same committee key serves every decision with no rotation. The full `wᵢ`
   is never published.
2. **Authenticate:** every node verifies each `tᵢ,C` against the publisher's signed epoch key-tree root
   (F-C9). Uncommitted/equivocating keys are excluded; rogue (bad-PoP) registrations are excluded (F-C5).
3. **Challenge:** every node self-derives the common Fiat–Shamir challenge from the *offset-estimated* high
   bits `w1* = HighBits(Σ(hiᵢ·α + qᵢ))` via `OffsetSharedChallenge` — the full `Σw` is never formed, yet the
   binding (part-root, pk*, μ) is identical to the base path, so `σ*` stays byte-exact.
4. **Respond + combine:** each validator gossips `zᵢ`; every node runs `OffsetCombine`, building the hint to
   target `w1*`. A carry/bound miss triggers a **lockstep retry** with a fresh attempt byte
   (`C = slot‖attempt`). Because `OffsetCombine` is *deterministic* in the published `(hiᵢ, qᵢ, zᵢ)`, every
   node observes the same miss and advances to the same next attempt with no extra coordination round — the
   determinism itself is the consensus.

### 2.1 Measured result (8 nodes × 4 slots, the new default path)

| property | requirement | measured |
|---|---|---|
| byte-exact FIPS-204 | LOCKED | every slot accepted by **both** our verifier and go-qrllib `ml_dsa_87.Verify` — **32/32 true, 0 false** |
| decentralized / no privileged aggregator | LOCKED | per slot, **exactly 1 distinct σ\*** across all 8 nodes (every node reconstructs the identical aggregate) |
| non-interactive | LOCKED | one commit + one response gossip per attempt; no handshake/MuSig rounds |
| hide ≤ native | LOCKED | only `(hiᵢ, qᵢ)` broadcast; full `wᵢ` never on the wire (≥native LWE to recover `s1`) |
| order-independent | LOCKED | canonical sort-by-id; all nodes agree regardless of gossip arrival order |
| post-quantum Cat-5 | LOCKED | ML-DSA-87, σ=3β; binding = native 252c/229q (core-SVP), 267c/217q (gate) |
| **stateless many-time, no rotation** | NEW | one fixed committee, message-bound nonce; **4 distinct slots → 4 distinct byte-exact σ\***, no rotation, no one-time guard |
| compression | — | 8/8 → **8×** (37016 B list → 4627 B); 6/8 (with adversaries) → **6×** |
| Sybil resistance (F-C5) | — | bad-PoP node excluded by every honest node; cannot influence σ\* |
| equivocation resistance (F-C9) | — | uncommitted `tᵢ,C` excluded by every honest node (participants drop 8→6), σ\* still agreed + byte-exact |

The cross-node check (`grep` over all eight node logs) confirms `distinct_sigma = 1` for every slot with all 8
nodes reporting, and 0 verification failures. Adversarial runs show the equivocators (ids 7,8) and sybils
excluded while the honest cohort, the equivocator process, and the sybil process all derive the **same**
`σ*` — decentralized agreement is preserved under attack. The base full-`w` path remains green
(`OFFSET=0`, regression intact).

## 3. Implementation map (deployed default)

| layer | symbol | file |
|---|---|---|
| message-bound nonce | `DeriveNonceMB(seed, C, μ, σ)` | `go-mladsa/refresh.go`, `qrysm/mladsa/refresh.go` |
| hiding per-content parts | `ContentPartsMB(A, seed, C, μ, σ)` | `go-mladsa/decentralized.go`, `qrysm/mladsa/decentralized.go` |
| end-to-end stateless aggregate | `AggregateOffsetFMB`, `AggregateOffsetFDefault` (σ=3β) | `construction_offset.go` |
| devnet glue | `OffsetCommitMB`, `OffsetSharedChallenge`, `OffsetContribution.Hi()/Q()`, `NewOffsetContribution` | `qrysm/mladsa/offset_devnet_export.go` |
| live runner (offset mode) | `runSlotOffset`, `--offset` flag, `OFFSET=1` launcher | `qrysm/cmd/mladsa-devnet/main.go`, `run-devnet.sh` |
| defaults | `SigmaOffsetDefault = 3·β` | `construction_offset.go` |

Deployment note (gotcha for reviewers): the hiding `(hiᵢ, qᵢ)` are **not** reduced mod q (`hi` is small
HighBits; `q = LowBits + r` is centered and can be negative), so a deserialized-vector gate must check
**shape only** (`validShape`), not the `[0,q)` range check (`ValidVec`) used for the reduced public-key vector
`tᵢ`.

## 4. What did not change

Every original LOCKED requirement is preserved verbatim — byte-exact FIPS-204, non-interactive, no trusted
setup, no privileged party, hide ≤ native, order-independent, post-quantum Cat-5 — and the new statelessness
adds no new assumption beyond the lattice hardness already underlying ML-DSA (the offset reveals an LWE
instance; the message-bound nonce is a deterministic PRF discipline). The formal corpus is unchanged and
admit-free (43/274/53-53/6); F-OFFSET's security is attested by `ml_adsa_F_offset.ec` (noise-flooding
reduction), `ml_adsa_F_keyonly.ec` (σ-independent deployed EUF), `ml_adsa_F_hintmlwe.ec` (KLSS tighter-model
route), `ml_adsa_F_nonce.ec` (message-bound nonce safety), and `ml_adsa_F_rootsafe.ec` (root key safe across
unlimited cycles).
