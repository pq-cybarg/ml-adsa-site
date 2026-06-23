# Toward stateless, many-time aggregation — reusable like normal ML-DSA (#137)

**Goal.** A fixed key that signs unlimited messages with **no state/refresh**, exactly as native ML-DSA is reused.

## The two barriers, and where each stands

**Barrier 1 — reuse cliff (one-time-per-content).** Came from the slot-only deterministic nonce. **Knocked down**
by the message-bound nonce (#136, `DeriveNonceMB`: `y = PRF(seed, C, μ*)` — FIPS-204's own `ExpandMask(K, μ‖κ)`
discipline): different messages get different nonces, so the `(z−z′)/(c−c′)` leak vanishes; this needs **no
counter/state** (the nonce is a deterministic function of the message, like ML-DSA). Test: reuse attack 0/256.

**Barrier 2 — accumulation under no-perfect-HVZK.** The aggregate cannot use ML-DSA's wide γ1 mask (`Σz` overflows
the norm wall at n≥2), so each use publishes a *high-error* hint `z = c·s1 + y` (σ=3β) of the fixed `s1`. ML-DSA is
many-time because its wide mask makes `z` *perfectly* hiding; ours is only ≥native-hiding per use. The decisive
question: **does recovering `s1` from `Q` such hints stay ≥native as `Q` grows?**

## Decisive finding: the accumulation SATURATES (recovery stays ≥native, flat in Q)

| metric | result |
|---|---|
| estimator99 (primal-uSVP, pure-Python, reliable) | **386.9 bits, flat for Qd = 1…32** (m = 1792…57 344) |
| Sage `lattice-estimator` dual+hybrid | **387.2 bits, flat for Qd = 1, 4, 16, 64, 256** (m up to 458 752) |
| many-sample attacks on this high-error instance | `arora-gb: ∞`, `bkw: 546` — **far above native; they do not threaten it** |

The **reuse** half is now also machine-checked: `formal/ml_adsa_F_nonce.ec : mb_different_msg_no_leak` proves that
with a message-bound nonce, two different decisions at one slot have distinct nonces, so the `(z−z′)/(c−c′)` reuse
attack cannot recover `s1` (it leaks **iff** the nonces collide — `reuse_iff_collision` — and message-injectivity
forbids that). Both halves covered: **reuse → EC-proven** (message-binding); **accumulation → estimator-measured**
saturation, confirmed by the real dual+hybrid estimator to **Qd=256**.

**Why it's flat (not a heuristic artifact):** the optimal attack on a high-error LWE instance uses a *bounded*
number of samples (~`m_opt`, a few thousand); beyond that, extra samples don't lower the required BKZ block (native
MLWE is itself "flat in m"). The high error (σ=360 ≫ secret η=2) is exactly what kills the many-sample attacks
(`arora-ge`/`BKW`). So **additional uses of a fixed key provide no usable new samples** ⇒ recovery saturates at
~387 (≥ native 267) for any realistic `Q`.

## Verdict (honest)

- **Practical stateless many-time is SUPPORTED for the reuse dimension:** a fixed key + message-bound nonce signs
  unbounded messages (any realistic `Q`) with `s1`-recovery saturated ≥native — no refresh needed for the
  single-key reuse barrier. EUF follows: `msufcma_hintmlwe` (multi-query, machine-checked) bounds EUF by
  `adv_hint(Q) + adv_mlwe + STMSIS`, and `adv_hint(Q)` is exactly this saturated (flat-≥native) recovery term.
- **Honest caveats:** (a) information-theoretically, *exponentially* many samples eventually solve any LWE — not
  claimed; the saturation is for realistic `Q` (a wallet signs ≪ 2^40 times). (b) The result rests on the named
  Hint-MLWE assumption for the *computational* EUF; the *recovery* saturation is estimator-measured (primal + Sage
  dual/hybrid). (c) An **EC few-time bound** (machine-checking `adv_hint(Q)` flat) is the remaining formal step.
- **Remaining items are deployment costs, not security walls:** message-bound nonce loses pre-publishable
  commitments (still non-interactive); equivocation moves to consensus-slashable; the norm wall limits n *per
  aggregate* (orthogonal to statelessness; sharding gives unbounded total).

**Net:** the north star is reachable. The empirical accumulation barrier — the one thing that forced refresh/state
— appears to **saturate rather than erode**, so a fixed key behaves as a practically-many-time key. The path to a
fully *stateless* deployment is: message-bound nonce (done) + the saturation result (measured) + an EC few-time
bound (next) + accept the deployment-cost tradeoffs. Refresh becomes an optional defense-in-depth, not a
requirement.
