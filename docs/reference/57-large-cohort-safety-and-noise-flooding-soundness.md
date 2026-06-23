# Large-cohort safety (to 8192 signers) and why noise flooding does NOT break soundness

Two questions, answered together: **(A)** is the aggregate safe and byte-exact for thousands of signers? **(B)**
does the noise flooding used in the security argument break the scheme's soundness? Short answers: **(A) yes,
≥native (Cat-5) and byte-exact to ≥8192 signers with large margin; (B) no.**

## 1. Noise flooding does not break soundness — three precise points

**"Noise flooding" is a proof technique, not a change to the scheme.** The claim "recovering `s1` from the offset
broadcast `b = M·s1 + e` is ≥native" is a *reduction*: take a native MLWE instance and **add fresh noise** to make
it look like the offset instance; an offset-solver then solves native. You can always add noise (never remove it),
so this is a standard, sound lossiness/flooding reduction — a **hardness lower bound** over instances. It never
runs in the deployed scheme, so it cannot affect correctness or verification.

**The actual added noise / larger summed secret do not break the FIPS-204 verifier.** In the aggregate the offset
`r` (in the broadcast `q = LowBits(w)+r`) and the summed secret `s1*=Σs1ᵢ`, `s2*=Σs2ᵢ` (norm √(2·nc) ≫ η) both
grow. Verification is unaffected because:
1. **The verifier never bounds the secret** — it checks only `‖z*‖∞ < γ1−β` and the self-consistency
   `UseHint(h*, A·z*−c·t1*·2^d) = w1*` hashed into `c̃*`. It sees `t1*` (public high bits), never `s1*`/`s2*`.
2. **`power2round` bounds `t0*` to `≤ 2^{d-1}` regardless of secret size**, so the `c·t0*` term the hint bridges
   is bounded the same as native — the MakeHint/UseHint mechanism works unchanged.
3. **The combine rejects/retries** anything outside the norm wall (`‖z*‖≥γ1−β`) or the hint budget (`>ω`) — the
   *same* Fiat-Shamir-with-aborts rejection ML-DSA itself uses — so it only ever outputs byte-exact-verifying
   aggregates. The offset `r` feeds only the challenge *estimate* `w1*` (a few ±1 carry-misses, bridged or
   rejected); it is **never subtracted into `z*`**, so it does not enter the verification norm.

**Forgery soundness is unchanged.** A forgery is any verifying `(z*,c,h*)` with `‖z*‖<γ1−β` — the *same* bound for
n=1 or n=8192 (β=120 is the FIPS constant). So SelfTargetMSIS extraction (`eq_exact`) is the native SIS instance;
the larger `c·s1*` does not loosen the forger's target.

**No tension:** flooding *raises* recovery hardness while the verifier's checks (norms + self-consistency,
secret-blind) keep correctness intact. The two are about different objects.

## 2. Safety to 8192 signers — measured

**Correctness (the only n-dependent constraint) — `construction_offset_safety8192_test.go`, σ=3β, byte-exact:**

| n | R | byte-exact `Verify` | ‖Σz‖∞ vs γ1−β=524168 | hint ≤ ω |
|---|---|---|---|---|
| 256 | 128 | ✅ (1 attempt) | 12 514 (2.4%) | 52 ≤ 75 |
| 1024 | 64 | ✅ (1 attempt) | 22 051 (4.2%) | 51 ≤ 75 |
| 2048 | 32 | ✅ (1 attempt) | 35 112 (6.7%) | 51 ≤ 75 |
| 4096 | 32 | ✅ (1 attempt) | 48 564 (9.3%) | 70 ≤ 75 |
| 8192 | 16 | ✅ (1 attempt) | 66 454 (**12.7%**) | 58 ≤ 75 |

At 8192 signers the norm wall is only **12.7% used** — the rejection-aware ceiling at σ=3β is ≈262 144 (docs/49),
so there is large headroom beyond 8192 (and committee sharding, #117, gives unbounded total regardless).

**Security is n-INDEPENDENT (machine-checked).** The deployed EUF bound (`ml_adsa_F_open.ec : deployed_open_uncond`,
F20) is `adv_prf + Q·(adv_mlwe + STMSIS)` — none of these depends on the cohort size n (the forgery target is a
*fresh* content; the aggregate is one byte-exact ML-DSA-87 signature under `pk*` whichever n). So unforgeability at
n=8192 = unforgeability at n=1 = ML-DSA-87 (Cat-5).

**The aggregate key is HARDER than native (estimator, reliable pure-Python `estimator99`):** the summed secret
`s1*`/error `s2*` raise the key-recovery MLWE by noise flooding —

| cohort nc | s1* stddev | classical | quantum | ≥ native (252/229)? |
|---|---|---|---|---|
| 64 | 11.3 | 352 | 320 | yes |
| 1000 | 44.7 | 458 | 416 | yes |
| 3000 | 77.5 | **515** | **467** | yes |

**Per-signer key hiding is also n-independent** — each signer's offset instance `(HighBits(wᵢ), qᵢ, zᵢ)` is the
single-signer ≥native LWE (docs/51 L1/L2), regardless of cohort size.

## 3. Verdict

To **≥8192 signers** the aggregate is **byte-exact (Cat-5 verifier accepts, large margin)** and **≥native secure**:
forgery is n-independent at ML-DSA-87, the aggregate key is *harder* than native, and per-signer keys stay
≥native-hidden. Noise flooding *strengthens* the recovery bound and does not touch verification soundness (the
verifier is secret-blind; the combine only emits verifying aggregates). "Safe up to 3000/8192 signers" holds with
comfortable headroom on every axis.
