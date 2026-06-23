# Message-bound / hedged nonce — removing the reuse cliff, relaxing one-time → few-time (#136)

**Idea.** Strict one-time-per-slot comes entirely from the nonce being keyed on the **slot/content only**
(`y = PRF(seed, C)`), so two decisions at one slot reuse it and leak `s1=(z−z′)/(c−c′)`. Bind the **message**
into the nonce — `y = PRF(seed, C, μ*)` (`DeriveNonceMB`), the FIPS-204 `ExpandMask(K, μ‖κ)` discipline — so two
*different* decisions get *different* nonces. This is non-interactive (μ* is the agreed decision, known before
signing; the challenge `c = H(μ*, ΣW)` is still self-computed; no circularity).

## What it changes (demonstrated)

- **Reuse cliff removed** (`construction_offset_mbnonce_test.go`): with the message-bound nonce, the
  `(z−z′)/(c−c′)` attack on two different decisions at one slot recovers **0/256** coordinates (vs 256/256 for the
  slot-only nonce). Re-signing the **same** decision is idempotent (same nonce ⇒ same `z`, zero new info).
- **Robustness:** an implementation bug or forced re-sign that would catastrophically leak the key under the
  slot-only nonce is now either a no-op (same message) or leak-safe (different message). This is a strict safety
  upgrade **even if one decision per slot is still the policy.**

## Few-time, not unbounded (the honest bound)

Removing nonce *reuse* does not make a single content-key infinitely reusable: each signature is an LWE view
`z = c·s1_C + y` of the **same** `s1_C`, so `Q` decisions accumulate `Q·(L·N)` noisy equations. Recovering `s1_C`
gets easier as `Q` grows. Estimator (`estimator99.py` #136 block, σ=3β, `m = Qd·1792`):

> **Few-time bound (primal-uSVP, estimator99):** recovery of `s1_C` is **flat at 386.9 bits** for **Qd = 1…32**
> decisions per content-key — i.e. ≥ native (252 core-SVP / 267 gate) across the whole tested range. This is the
> same "flat-in-m" behaviour native MLWE shows (the optimal primal attack saturates the useful sample count).
> `Qd=1` reproduces the single-hint figure (386.9), which is **Sage-confirmed** (dual_hybrid 387.2).
>
> **Sage dual+hybrid cross-check — CONFIRMED.** Because the dual attack benefits from more samples, the primal
> "flat" was not by itself conclusive. The real `lattice-estimator` (full attack suite) gives **best = 387.2 via
> dual_hybrid, flat for Qd = 1, 4, 16** (`/tmp/run_fewtime_sage.py`): the dual attack does **not** erode hardness
> with more decision-batches — the high-error hint instance saturates. So few-time recovery is **≥ native (387 ≥
> 252) confirmed by both primal (estimator99) and dual+hybrid (Sage) up to Qd = 16** decisions per content-key.
> (A modulus-shadowing bug in the first pass produced spurious "NO FEASIBLE BETA" rows — caught by the
> `Qd=1`-must-match-387 sanity assert and fixed.)

Beyond the confirmed `Qd`, refresh the content-key. The forward-secret ratchet still gives **unbounded total** at
the wallet level (fresh `s1_C` per content).

So the property is: **few-time per content-key (≥native up to the bound above), unbounded total via refresh** —
a relaxation of strict one-time, not an unbounded many-time key.

## Costs / policy shifts (do not hide)

1. **Loses pre-publishable commitments.** With the slot-only nonce, `w_i = A·PRF(seed,C)` is computable (and
   pre-publishable in the epoch tree) before the decision is known. A message-bound nonce needs `μ*` first, so
   commitments are computed per-decision (still non-interactive — commit-then-respond broadcasts, no handshake —
   but not amortizable into the epoch tree). Latency/comms trade.
2. **Equivocation is no longer cryptographically self-punishing.** Today signing two slot-decisions self-destructs
   the key; with a message-bound nonce it does not, so **the consensus layer must slash equivocation** (it is
   detectable: two valid signatures for the same slot). This is the standard PoS model — a policy shift to make
   explicit, arguably cleaner than relying on key-suicide.
3. **Needs a few-time security extension of the proofs.** The deployed bound (`deployed_open`) is per-content
   one-time; the few-time case is the LWE-accumulation argument above (estimator-measured) and would benefit from
   an EC few-time bound (open task).

## Recommendation

Offer message-bound/hedged nonce as a **configuration**:
- **Default (consensus):** keep the slot-only nonce *or* adopt message-bound for the robustness upgrade (no
  accidental-reuse key-suicide), with equivocation slashed at the consensus layer.
- **Hedged variant** `y = PRF(seed, C, μ*, ρ)` (+ fresh randomness) for additional fault-injection resistance,
  at the same pre-publication cost.

This directly addresses the deployment concern: even a buggy/forced re-sign cannot leak the live key. It does not
remove the need for the forward-secret refresh (which provides unbounded total and confines any post-finalization
exposure).
