# Eliminating one-time key leakage — live-round safety for QRL deployment (#135)

**Why this is a deployment blocker.** The per-content key is a *one-time ML-DSA key*. If it leaks **while the round
is unfinalized**, a thief/liar/threat actor can use it to authorize a **competing decision** before the honest
decision finalizes. The "a recovered *spent* key only re-signs the already-agreed message (a no-op)" containment
holds **only after finalization** — it does NOT protect the live window. So for QRL the requirement is strict: the
one-time key must be **non-extractable from anything published during a live round**.

## 1. The leak in the base (full-w) construction — and why it is fatal pre-finalization

The base decentralized combine publishes the full commitment `wᵢ = A·yᵢ`. Because ML-DSA's `A` is **tall**
(k≥ℓ: 8×7 / 6×5 / 4×4, full column rank), `wᵢ = A·yᵢ` has a **unique preimage** `yᵢ = A⁺wᵢ` recoverable by plain
`F_q` Gaussian elimination — **no shortness, no Module-SIS**. Then `s1ᵢ = c⁻¹(zᵢ − yᵢ)` from the public response.
This is demonstrated decisively in `recover_nonce_test.go` (recovers a uniformly-random nonce exactly). **Published
during a live round, full-w hands a thief the live one-time key.** Full-w must NOT be used for live QRL consensus.

## 2. F-OFFSET eliminates the trivial leak (machine-checked + empirical)

F-OFFSET never publishes full `wᵢ`. It publishes `HighBits(wᵢ)` (what a native signature already reveals) and a
**noised** low part `qᵢ = LowBits(wᵢ) + rᵢ`, with `rᵢ` a fresh secret offset (±R). The attacker's best
reconstruction of the commitment is `w_est = HighBits·α + qᵢ = wᵢ + rᵢ` — off by the secret offset on **every**
coordinate. The same Gaussian elimination then returns `y' = yᵢ + A⁺rᵢ ≠ yᵢ`, and `s1' = c⁻¹(zᵢ − y') ≠ s1ᵢ`.

- **Empirical (`construction_offset_noleak_test.go`):** full-w recovers `y` with **0** mismatches; F-OFFSET
  corrupts the recovery on **1792/1792** nonce coordinates. The trivial linear-algebra leak is **eliminated**.
- **Reduction (machine-checked, `ml_adsa_F_offset.ec : noise_flood_reduction`):** extracting `s1ᵢ` from
  `(HighBits(wᵢ), qᵢ, zᵢ)` is the LWE instance `b = (A·c)·s1ᵢ + e`, `|e|≤R`, which is the native key-recovery
  instance plus fresh noise ⇒ **≥ native against any attack**.
- **Estimator:** that instance is **455 / 489 bits** at R=2¹¹/2¹² (native 267) — extracting the live key requires
  breaking Cat-5 lattice hardness, i.e. breaking ML-DSA itself.

So with F-OFFSET, the one-time key is **not leaked**: recovering it is as hard as breaking ML-DSA-87 (Cat-5).

## 3. Live-round (pre-finalization) safety — phase by phase

| Phase | What is public | What it reveals about `s1ᵢ` |
|---|---|---|
| Commitment | `HighBits(wᵢ)`, `qᵢ = LowBits(wᵢ)+rᵢ` | **nothing** — `wᵢ = A·yᵢ` is a function of the *nonce only*, not `s1ᵢ` |
| Response | `zᵢ = yᵢ + c·s1ᵢ` | only the **≥native LWE** view (§2); and `c` is over the *agreed* decision's `μ*` |

- During the **commitment** phase the secret is untouched (commitments are nonce-only). 
- The **response** `zᵢ` is published *only when signer i chooses to authorize this decision* (the self-computed
  challenge `c = H(μ*(payload), …)` binds the decision), and even then `s1ᵢ` is ≥native-hidden.
- **No equivocation window:** the one-time guard keys on `(signer, content/slot)`, so a signer cannot be made to
  authorize two decisions for one slot; and the deterministic nonce forbids the reuse attack `s1=(z−z′)/(c−c′)`.

⇒ At **no point** in a live/unfinalized round is the one-time key extractable below Cat-5, and no second decision
can be produced for the slot. The live window is safe.

## 3b. "If it doesn't leak, isn't it no longer one-time?" — proved: NO, they are different events

This is a natural objection and the resolution is exact. **The single-use non-leak and the one-time property
concern two DIFFERENT events**, both demonstrated:

| Event | What happens | Test |
|---|---|---|
| **ONE** honest use | publishing one transcript `(HighBits(w), q, z)` does **not** reveal `s1` — extracting it is ≥native LWE | `TestOffset_NoTrivialKeyLeak` (full-w leaks 1792/1792; F-OFFSET corrupts all) |
| A **SECOND** use under the **same deterministic nonce** | `s1 = (z−z′)·(c−c′)⁻¹` recovers `s1` **exactly**, and F-OFFSET's hiding of `w` is **irrelevant** to it | `TestOffset_ReuseStillLeaks_OneTimeNecessary` (256/256 slots, exact) |

So one-time is **necessary because of the deterministic nonce**, *not* because a single use leaks. A many-time
scheme (native ML-DSA) avoids the second event by drawing a **fresh nonce per message**. Our scheme **cannot**:
non-interactive aggregation requires the nonce/commitment to be **fixed and pre-committable before** the
message-dependent challenge (else the challenge↔commitment dependency is circular and the commitments can't be
pre-published). Hence the nonce is fixed per content ⇒ one message per content ⇒ one-time.

**F-OFFSET removes the single-use leak (event 1); it cannot remove the deterministic-nonce constraint (event 2) —
that is the price of non-interactivity.** Therefore the scheme is simultaneously *single-use-non-leaking* and
*one-time*, with no contradiction: the first honest use is Cat-5-safe; a second use under the same nonce is
forbidden (one-time guard) precisely because it would leak. (Formal: `ml_adsa_F_nonce.ec : reuse_iff_collision` —
reuse leaks **iff** the nonce collides; one-time + content-bound challenge + PRF nonce forbid the collision.)

This is exactly the XMSS / hash-based model QRL already uses: the **wallet (root) is many-time**, signing many
decisions via **fresh per-content one-time keys** from the forward-secret ratchet; each per-content key is
one-time. One-time-per-content is not a limitation here — it is the same discipline QRL's stateful PQ signatures
already adopt, now with the single-use leak additionally eliminated by F-OFFSET.

## 4. Optional strengthening — computational key-independence (Hint-MLWE ZK-parity)

Beyond ≥native *recovery* hardness, the deployment may enable the Hint-MLWE configuration (docs/49 §3a,
`ml_adsa_F_hintmlwe.ec`): under the published Hint-MLWE assumption the entire transcript is **computationally
indistinguishable from a key-independent simulation**, i.e. it leaks *nothing* about `s1ᵢ` computationally
(`leakage ≤ Adv_HintMLWE`). This is the strongest attainable hiding; the default does not require it (the ≥native
reduction already eliminates extractable leakage).

## 5. QRL deployment mandate

1. **Use F-OFFSET (`AggregateOffsetFDefault`, σ=3β) for all live consensus** — never the base full-w `AggregateF`,
   which leaks the live one-time key by linear algebra (§1).
2. **Forward-secret refresh + one-time guard** stay mandatory (confine any post-finalization exposure; forbid
   reuse/equivocation).
3. **Optionally enable Hint-MLWE ZK-parity** for computational key-independence of the transcript.
4. Combined with the MitM/replay lockdown (docs/53) and the leakage register (docs/51), this closes the
   credential-theft / fake-request / impersonation fronts at the scheme level, with only the universal
   application-layer residuals (WYSIWYS, anti-DoS, unique decision id).

**Net:** the one-time key does not leak under F-OFFSET — extracting it during a live round is Cat-5-hard
(machine-checked reduction + empirical 1792/1792-coordinate failure of the full-w attack), and equivocation is
blocked. This is the property required for QRL to actually deploy.
