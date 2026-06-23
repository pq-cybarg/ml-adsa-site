# Construction F-OFFSET — a nonce-hiding instantiation of ML-ADSA

**Status: DEPLOYED DEFAULT / state-of-the-art.** F-OFFSET is now the recommended ML-ADSA construction for
deployment (see [docs/59](59-offset-default-deployment-and-live-devnet.md) for the deployment decision and the
live decentralized devnet that exercises it). It is built, byte-exact-verified, ≥-native-secure (real
lattice-estimator), forward-secret, **stateless many-time** (message-bound nonce, σ=3β default), scale-mapped
(to 2¹⁷ signers), provenance-checkable, and formally attested (core lemmas). It does not modify the proven core
(`construction_f.go`, `decentralized.go`); the base full-`w` combine is retained as the byte-exactness
reference and a fallback, **not** as a deployment option (the base broadcast leaks the nonce by linear
algebra — finding #3 — which F-OFFSET eliminates). Source of truth for every claim below: the verified-claims
ledger [docs/46](46-findings-ledger.md) (facts F1–F13, with backing assertions). Security framing:
[docs/44](44-offset-route-and-lattice-estimate.md); requirements: locked, see
[docs/45 §1a banner](45-necessity-audit.md).

## 1. What it adds over the base combine

The base decentralized combine has each signer broadcast the **full** commitment `wᵢ`. With the response `zᵢ`
and a tall `A`, anyone can recover `yᵢ` then `s1ᵢ` (finding #3). F-OFFSET removes that exposure: each signer
broadcasts only

- `hiᵢ = HighBits(wᵢ)` — exactly what native ML-DSA already reveals, and
- `qᵢ = LowBits(wᵢ) + rᵢ`, with `rᵢ` a **fresh, secret, independent** offset of width `±R`.

Recovering `s1ᵢ` from `(hiᵢ, qᵢ, zᵢ)` is the LWE instance `b = M·s1 + e` (`M = A·c`, `e = −rᵢ`, `|e| ≤ R`).

## 2. Protocol (per content C, current forward-secret epoch)

1. **Keys** (`ForwardSecretRatchet`, #101): `s1ᵢ,C`, nonce `yᵢ,C`, `wᵢ = A·yᵢ` from the epoch seed; `Rotate()`
   ratchets `seed ← PRF(seed)` and **erases** the old seed (spent-epoch keys unrecoverable).
2. **Broadcast**: `(hiᵢ, qᵢ)` (public), keep `rᵢ` secret.
3. **Challenge** (`OffsetChallenge`, any party): `t* = Σtᵢ → (t1*,t0*), pk*`; estimate the aggregate high bits
   `w1* = HighBits(Σ(hiᵢ·α + qᵢ))` (the noised carry; a few ≤ω coords differ ±1 from the ideal `HighBits(Σwᵢ)`);
   `c̃* = H(μ* ‖ w1Encode(w1*))`.
4. **Response**: `zᵢ = yᵢ + c*·s1ᵢ`; `z* = Σzᵢ`.
5. **Combine** (`OffsetCombine`): `rr2 = A·z* − c·t1*·2^d`; build the hint to **target `w1*`** (per coord: `h=0`
   if `HighBits(rr2)` already hits `w1*`, else `h=1` if the one-step `UseHint` hits it, else **fail → retry**
   with the next attempt byte). If total hint weight ≤ ω and norms hold, emit `σ* = (c̃*, z*, h*)`.

The unmodified FIPS-204 verifier computes `w1' = UseHint(h*, rr2)`, which by construction equals `w1*`, the value
hashed into `c̃*` — so it **accepts byte-exact**. `σ*` is an ordinary 4627-byte ML-DSA-87 signature under the
2592-byte `pk*`.

## 3. Security (req G: lose no more than native ML-DSA)

| Layer | Result | Ledger |
|---|---|---|
| Hardness, attack-independent | `b = M·s1 + e` is ≥ native by a **noise-flooding reduction** (more error ⇒ ≥-hard, vs any attack) for R ≥ ~3 | I5 |
| Hardness, real tool | **Sage `lattice-estimator`, full suite** (usvp/bdd/dual/dual_hybrid/hybrid): native 267, offset **455 @R=2¹¹ / 489 @R=2¹²**, best attack dual_hybrid for both | F10 |
| Exact instance | deployed view = `b = M·s1 − r` exactly, noise scale exactly R (no A-conditioning) | F8 |
| Aggregate `s1*` | ≥ native every route (agg-native 367, agg-offset 867/938) | F9 |
| Multi-attempt | fresh `s1_C`+`rᵢ` per content + forward-secret erase ⇒ no cross-content accumulation | #111, #101 |

Carry budget: R is bounded above by the ≤ω carry-miss constraint (`R ≤ ~2¹²`), and below by ≥native (`R ≥ ~3`)
— a wide window. The offset is a **fresh-random** mask (this is what the reduction needs; #82's deterministic
quantization does **not** qualify, ledger I6).

## 4. Engineering envelope (F12)

Succeeds 8/8 within the retry budget for n ∈ {2..32}, R ∈ {2⁶..2¹⁰}. Hint-weight ≈54–60 (≤ ω=75) and **flat in
n** (the `c·t0*` term is bounded by power2round, n-independent); carry-misses small (≤~8 at n=16/R=2¹⁰) and
absorbed by ≤1 retry on average. The offset's marginal cost over the base combine is just the misses.

## 5. Provenance (`ProvenanceVerifyOffset`)

Re-runs the deterministic combine and byte-compares `(pk*, σ*)`: the exact contribution set verifies; a tampered
`zᵢ`, a dropped/added member, or a wrong message all fail.

## 6. Artifacts

- Go: `construction_offset.go`, `forward_secret_ratchet.go`; tests `construction_offset_test.go`,
  `_scale_test.go`, `_provenance_test.go`, `forward_secret_ratchet_test.go`.
- Estimator: `estimator99.py` (self-validating pure-Python core-SVP); real run via Sage `lattice-estimator`.
- Formal: `formal/ml_adsa_F_offset.ec` (compiles green, 0 admits; `noise_flood_reduction`,
  `choose_reproduces`/`offset_combine_correct` over the real `Ml_adsa_rounding` high-bits model).

## 7. Honest residuals (not cryptographic gaps)

- Formal: the one-step ±1 feasibility of the hint correction (the bridgeability the Go combine checks-and-
  retries) is abstracted at the rounding-model level; the **full** `OffsetChallenge`/`OffsetCombine` procedures
  are not yet ported (only the core lemmas).
- Absolute estimator numbers use the tool's gate-count model; the **relative** ≥-native claim is reduction-backed
  and robust to calibration.
- Deployment must wire the offset broadcast (#95) and the ratchet (#101) as modelled.
