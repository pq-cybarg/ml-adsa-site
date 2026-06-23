# Confining the per-content nonce/key exposure ("Option C")

**Status: design exploration.** This note answers a precise question raised in review: *the per-content
one-time key `s1*` is recoverable post-signature — is that an issue, and can we prevent it?* It (1) localizes
exactly **where** the exposure lives, (2) proves a **trilemma** that bounds what any fix can achieve, (3)
records the half that is **already free** (machine-checked-adjacent, test-backed), and (4) lays out the
constructions that would hide it further and what each one **costs**.

It is a companion to the security narrative in [docs/41 §6](41-visual-methods-and-security.md) and the
cryptanalysis packet [docs/36 §6.7–6.8](36-cryptanalysis-review-packet.md).

---

## 1. The exposure, stated exactly

Non-interactive aggregation must publish each signer's **full** commitment `wᵢ = A·yᵢ`, because the shared
Fiat–Shamir challenge `c* = H(μ ‖ HighBits(W*))` needs `W* = Σ wᵢ` in full (HighBits is **non-additive** —
carries cross the `γ2` boundary, so `Σ HighBits(wᵢ) ≠ HighBits(Σ wᵢ)`). ML-DSA's `A` is **tall** (`k ≥ ℓ`,
full column rank), so `wᵢ = A·yᵢ` has a unique preimage: `yᵢ` is recoverable by `F_q` linear algebra (not
Module-SIS-hidden). With the public response `zᵢ = yᵢ + c·s1ᵢ`, the one-time key follows:
`s1ᵢ = c⁻¹(zᵢ − yᵢ)`. Summed, the aggregate one-time key `s1*` is recoverable.

The proof already **assumes this**: the deployed reduction's first hop (`transcript_le_keyleak`,
`formal/ml_adsa_F_open.ec`) hands the adversary the entire one-time key and still proves EUF-CMA, because the
key is one-time, message-bound, and a forgery needs a fresh independent key. So the exposure is a **modeled,
contained fact**, not a gap. The question Option C asks is whether we can do better than *contain* it — can we
*hide* it?

---

## 2. The trilemma (what no fix can do)

> A party that **non-interactively computes the shared challenge** (so it holds full `W*`) **and** sees the
> published signature (so it holds `z*`) can **always** recover `s1* = c⁻¹(z* − A⁺W*)`.

There is no per-signer "private component" that escapes this for such a party: it is forced to hold both
`W*` (to evaluate `HighBits` for the challenge) and `z*` (the signature), and those two linearly determine
`s1*`. Therefore you cannot simultaneously have all three of:

1. **Non-interactive** aggregation (every party derives `c*` itself from public commitments),
2. **Byte-exact ML-DSA output** (the unmodified FIPS-204 verifier accepts `σ* = (c̃*, z*, h*)`),
3. **`s1*` hidden** from the parties that compute the challenge.

Any fix must relax one of the three. This is the lattice analogue of why interactive Schnorr multisigs use a
commitment round: to avoid revealing the nonce, *someone* must not see it until after the challenge is fixed.

---

## 3. The half that is already free: the **signature** does not leak

The exposure is **not** in the persistent artifact. From `(pk*, σ*)` alone, any holder can form only

```
rr2 = A·z* − c·t1*·2^d  =  W* + c·(t0* − s2*)
```

which differs from the true `W*` by the **secret** `c·(t0* − s2*)` (`t0*`, `s2*` are secret-key material).
The hint exposes only `HighBits(W*)` (= `w1*`); the low bits of `W*` stay masked by that secret term, exactly
as in a standalone ML-DSA signature where `y` is never recoverable. So:

- **A late / external observer** (downloading only the chain, i.e. `pk*` and `σ*`) **cannot** recover
  `y*`/`s1*`. The persistent artifact is as private as vanilla ML-DSA.
- The nonce is recoverable **only** by a party that saw the transient full-`wᵢ` **broadcasts**.

This is verified in `go-mladsa/option_c_test.go` (`TestOptionC_SignatureAloneDoesNotLeakNonce`): recovery
from the published signature matches the true nonce in **0/1792** coefficients (noise floor), versus **exact**
recovery when the `wᵢ` broadcasts are available.

**Immediate mitigation (no crypto change): treat `wᵢ` as ephemeral.** Do not persist or gossip the full
`wᵢ` beyond the live combination step. Then the leak surface shrinks from "anyone, forever" to "validators
online during the slot" — and for *them* the leak is already harmless (binding makes `pk*_C` single-purpose,
the one-time guard forbids reuse; [docs/36 §6.7](36-cryptanalysis-review-packet.md)). The chain, light
clients, and all future observers see only the ML-DSA-private signature.

---

## 4. Hiding it from the live combiners too — the options and their cost

To remove the exposure for the challenge-computing parties as well, one of the trilemma's legs must give:

| Option | What it hides | What it gives up | Maturity |
|---|---|---|---|
| **A. Interactive commit–reveal** (DOTT/MuSig-style: broadcast `H(wᵢ)` or a hiding commitment first, reveal after `c*` is fixed) | `yᵢ` never public in full | **non-interactivity** (the BLS-like property); reopens ROS/concurrency analysis | known (lattice 2-round multisigs) |
| **B. ZK proof-of-aggregation** (LaBRADOR/Greyhound-class: prove knowledge of valid signatures; never publish `wᵢ`/`zᵢ`) | all per-signer secrets | **byte-exact ML-DSA output** (it's a SNARK, not a FIPS-204 sig); proof size + verify cost | known, heavier |
| **C-arch. Designated / rotating combiner** (signers send `wᵢ` point-to-point to the slot's combiner; only `σ*` is published) | `wᵢ` from the validator set at large | confines (does not eliminate) the leak to one rotating party; mild transport assumption | architectural, cheap |
| **C-carry. Homomorphic-carry commitment** (publish `HighBits(wᵢ)` + an additively-homomorphic commitment to `LowBits(wᵢ)`; reveal only the aggregate carry needed to correct `Σ HighBits` → `HighBits(Σ)`) | `wᵢ` low bits (hence `yᵢ`) | adds a (small) carry-range argument; partially interactive / proof-bearing | research |

Notes:

- **C-arch** is the lowest-cost lever and composes with everything already built: pair it with the
  **forward-secure epoch rotation** (`grouptree_rotation.go`) so the combiner role rotates and old material is
  erasable. It does not need new cryptography — it is a gossip/transport policy plus the ephemeral-`wᵢ` rule of
  §3. Residual trust: the current slot's combiner (who, even if malicious, only learns a spent one-time key).
- **C-carry** is the candidate that keeps byte-exact output while hiding `yᵢ`, by exploiting that the
  HighBits non-additivity is purely a bounded carry. **The decomposition is verified in the real ML-DSA
  `Decompose`** (`go-mladsa/option_c_carry_test.go`, `TestOptionC_CarryDecomposition_Works`):

  > `HighBits(W*) = (Σ HighBits(wᵢ) + carry) mod 16`, **exact in all 2048 coefficients**, with
  > **`max|carry| = 8`** (∈ (−8, 8], ~4 bits/coeff vs a full `wᵢ` coefficient's ~23 bits). Publishing only
  > `{HighBits(wᵢ), carry}` recovers the true nonce in **0/1792** coefficients (noise floor) — `LowBits(W*)`
  > stays hidden, so `y*` is no more recoverable than from a plain ML-DSA signature.

  So the cohort needs only the *carry*, not the low bits, and revealing the carry does **not** leak `yᵢ`.
  The remaining obstacle is that the carry is a function of the **secret** `Σ LowBits(wᵢ)`: computing it
  without revealing that sum (which would re-expose `W*`) needs a secure sub-protocol. A concrete construction
  reuses the **additively-homomorphic commitment already in the codebase** (`commit.go`, Module-SIS binding /
  Module-LWE hiding):

  1. each signer publishes `HighBits(wᵢ)` + `Com(LowBits(wᵢ); rᵢ)` (no full `wᵢ`);
  2. the cohort homomorphically **sums** the commitments → `Com(Σ LowBits(wᵢ))`;
  3. a **threshold/MPC reveal** outputs *only* `carry = round(Σ LowBits / ALPHA)`, never `Σ LowBits`;
  4. everyone forms `HighBits(W*) = Σ HighBits(wᵢ) + carry` → the challenge; signers release `zᵢ`; combine to
     the byte-exact `σ*`.

  This **hides `yᵢ` from every party** (no one ever sees `Σ LowBits`), keeps the **byte-exact ML-DSA output**,
  and costs one threshold carry-reveal step (a DKG setup + one reveal round) — far lighter than a full 2-round
  MuSig (A) or a SNARK (B). Cost/footprint: ~`K·N·4 bits` of carry data plus the commitments. **Open items
  to cryptanalyze before any claim:** (i) does the threshold reveal of `round(Σlow/ALPHA)` leak more than the
  carry across many slots; (ii) the `q-1` decompose edge case and the rare per-coefficient carry at the band
  boundary (hint interaction); (iii) whether the reveal can be made non-interactive with deterministic
  openings + DKG. This is the natural next prototype.

---

## 5. Recommendation

1. **Adopt §3 now.** Ephemeralize `wᵢ`; never persist the combination transcript. This makes the on-chain
   artifact and every external observer exactly as private as ML-DSA, for free. (Test-pinned.)
2. **Adopt C-arch for the live window.** Confine `wᵢ` to a rotating combiner over point-to-point channels;
   compose with epoch rotation for forward security. The residual leak is one spent one-time key to one
   rotating party — already provably harmless.
3. **Prototype C-carry** if full hiding (byte-exact output, `yᵢ` hidden from every party) is desired. The
   carry decomposition is now **test-validated** in the real `Decompose` (exact, `max|carry|=8`, privacy at
   the noise floor); the remaining build is the **carry-reveal sub-protocol** over the existing homomorphic
   commitment (`commit.go`) + a threshold/DKG. It is research-grade and must be cryptanalyzed before any
   claim, but it is the genuine "private per-signer component" and now has a concrete, tested foundation.
4. **Do not pursue A or B** unless a defining property (non-interactivity, byte-exact output) is willingly
   traded — they hide `s1*` but at the cost of what makes ML-ADSA a drop-in BLS analogue.

The bottom line: `s1*` exposure is **not an issue for safety** (the proof assumes it; binding + one-time
contain it), the **persistent signature already leaks nothing**, and the residual live-window exposure is
**confinable** architecturally. Eliminating it entirely is a deliberate property trade, bounded by the §2
trilemma.
