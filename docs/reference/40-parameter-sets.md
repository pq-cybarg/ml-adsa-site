# 40 — ML-ADSA parameter sets (Categories 2, 3, 5)

Companion to the spec (`docs/30 §2`) and roadmap item #8 (`docs/32 §5`). ML-ADSA is defined over each
of the three FIPS-204 ML-DSA parameter sets; the aggregate construction is parameter-agnostic (it uses
only the base ML-DSA operations), so a parameter set is fully determined by the base ML-DSA parameters.

## The three sets (FIPS-204 values)

All sets share `q = 8380417`, `n = 256`, `d = 13`, `ζ = 1753` (so the NTT and Power2Round are
parameter-independent). Source of truth: `go-mladsa/params.go` (`Params44`/`Params65`/`Params87`).

| | ML-ADSA-44 (Cat 2) | ML-ADSA-65 (Cat 3) | ML-ADSA-87 (Cat 5) |
|---|---|---|---|
| `(k, ℓ)` | (4, 4) | (6, 5) | (8, 7) |
| `η` | 2 | 4 | 2 |
| `τ` | 39 | 49 | 60 |
| `β = τη` | 78 | 196 | 120 |
| `γ1` | 2¹⁷ | 2¹⁹ | 2¹⁹ |
| `γ2` | (q−1)/88 | (q−1)/32 | (q−1)/32 |
| `ω` (hint) | 80 | 55 | 75 |
| `c̃` bytes (λ/4) | 32 | 48 | 64 |
| z bit-width (1+bitlen(γ1−1)) | 18 | 20 | 20 |
| w1 bit-width | 6 | 4 | 4 |
| t1 bit-width (bitlen(q−1)−d) | 10 | 10 | 10 |
| **pk size** | **1312** | **1952** | **2592** |
| **sig size** | **2420** | **3309** | **4627** |

The pk/sig sizes are *derived* from the parameters in `params.go` and asserted equal to the FIPS-204
values (`TestParamSizes`); `Params87` is asserted equal to the legacy `-87` consts.

## Verification — cross-validated against an independent implementation

`go-mladsa/verify_param.go` is a parameterized FIPS-204 verifier (`VerifyP(p, pk, msg, sig, ctx)`)
exercising every parameter-dependent path: matrix dims `K×L`, challenge weight `τ` (SampleInBall),
rounding modulus `α = 2γ2` (Decompose/UseHint), the `z` and `w1` bit-widths, the `c̃` length, and the
hint weight `ω`. `param_test.go` (`TestParamVerifyVsCIRCL`) validates it against **CIRCL's independent
mldsa44/65/87** at all three sets: for each, it accepts a valid CIRCL signature and rejects a tampered
signature and a wrong message; for `-87` it further confirms `VerifyP` agrees bit-for-bit with the
legacy reference `Verify`. This is an independent-implementation conformance check, not a self-test.

```
go test ./ -run 'TestParamSizes|TestParamVerifyVsCIRCL' -v
```

## Signing & aggregation — fully instantiated, CIRCL-validated

- `sign_param.go` — parameterized FIPS-204 **KeyGenP + SignP** (η-sampler, ExpandMask, the sign-with-
  aborts loop, hint generation, all per-set). `TestParamSignVerify`: our signatures are accepted by
  CIRCL's independent mldsa44/65/87 (and our VerifyP); tamper rejected.
- `aggregate_param.go` — the ML-ADSA **aggregate core math** parameterized: members share `A` (one
  `ρ`); `pk* = (ρ, Power2Round(Σ tᵢ).t1)`; `z* = Σ yᵢ + c*·Σ s1ᵢ` under one commitment-bound `c*`.
  `TestAggregateParam`: a 4-signer aggregate `(pk*, sig*)` is accepted by CIRCL's verifier at Cat 2/3/5
  (and VerifyP); tamper rejected; the combiner abstains on norm-budget overflow.

So ML-ADSA-44/65/87 are each instantiated end-to-end (keygen → sign → aggregate → verify), with the
output a byte-exact ML-DSA(pk*,sig*) an unmodified FIPS-204 verifier accepts. The orthogonal
accountability layers (registry/Merkle/PoP/refresh in `construction_f.go`) are parameter-independent in
structure and reuse these primitives; the byte-exact legacy -87 reference path is untouched.
