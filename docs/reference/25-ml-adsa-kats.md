# 25 — ML-ADSA Known Answer Tests (KATs): conditions and rationale

Deterministic test vectors for ML-ADSA, the aggregate analog of FIPS-204's ACVP vectors. They pin the
exact byte-level behavior of the implementation so any change is caught and any second implementation
can be checked for conformance. Code: `go-mladsa/kat_test.go` and the byte-identical copy
`qrl-integration/ml-adsa/qrysm/mladsa/kat_test.go`. Run: `go test -run TestKAT_ ./...`.

## Why ML-ADSA can have KATs at all (the determinism condition)

A KAT requires a deterministic function of fixed inputs. The base aggregates `AggregateRejfree`/
`AggregateM1` draw **random** nonces, so they are *not* KAT-able. The **mainline Construction F**
(`AggregateF`) is: its per-content key and nonce are **PRF-derived** (`ContentKeyDerive`,
`DeriveNonce`), so for fixed `(ρ, master-seeds, ctx, content, payload, reg_root, epoch)` the entire
aggregate — `pk*` and `σ*` — is reproducible. The committee keys are generated from a **fixed PCG seed**
(`rand.NewPCG(0x4d4c41445341, 0x4b4154)` = "MLADSA","KAT"), making `MemberKeyGen` deterministic too.
**This is also why the KATs use the refresh construction**: the same property (deterministic per-content
keys) that defeats leakage (F-C4) is what makes the scheme testable.

## Fixed conditions (the "knowns")

```
ρ (epoch matrix seed)  = "ml-adsa-KAT-rho-v1-0000000000000"   (32 bytes)
master seed (member 0) = "ml-adsa-kat-master-seed-00000000"   (32 bytes)
ctx (domain)           = "QRL"
content (baseC)        = "kat/content/0"  (rotation KAT: "kat/rot/0".."kat/rot/4")
payload                = "ml-adsa-kat-payload-v1"
committee key stream   = rand.NewPCG(0x4d4c41445341, 0x4b4154)   (re-seeded per N)
sigma                  = 12·β  (rejection-free regime)
epoch                  = 0 (aggregates) / j (rotation j)
```

## Vector classes (and why each)

| KAT | what is pinned | why this condition |
|---|---|---|
| **Primitives** (`TestKAT_Primitives`) | SHA-256 of `ContentKeyDerive.t`, `DeriveNonce`, `ExpandS(s1‖s2)`, `MerkleRoot(3 leaves)` | pins the FIPS-204-derived refresh primitives + the Merkle layer at the byte level — the building blocks every aggregate depends on; catches any drift in PRF/ExpandS/rounding/hash framing |
| **Aggregates** (`TestKAT_Aggregates`) | SHA-256 of `pk*` and `σ*` for **N = 1, 4, 16, 64, 128** | N=1 is the degenerate case (= a vanilla ML-DSA-87 signature); 4/16/64 cover scale; **128** is the qrysm attestation cap (`ssz_max`). Each is **CIRCL-verified** (go-mladsa) / **go-qrllib-verified** (qrysm) as a FIPS-204 anchor |
| **Rotation** (`TestKAT_Rotation`) | SHA-256 of `pk*`/`σ*` for **5 subsequent contents** C0..C4 by the same committee, + independence + reuse-refusal | the no-leak guarantee for *subsequent signatures*: each rotation must be a **fresh, distinct** aggregate (asserted all pk* distinct), per-content keys **PRF-independent** (max\|corr\| = 0.16 ≈ noise floor), and the **one-time discipline refuses re-signing the same content** (deterministic-nonce reuse blocked). This is the KAT form of F-C4 (rotation ⇒ no accumulation) |

## Cross-implementation conformance

`go-mladsa/kat_test.go` and `qrl-integration/.../qrysm/mladsa/kat_test.go` pin the **same** hash
constants. Both pass ⇒ the standalone and qrysm-vendored implementations are **byte-identical**, and
both are anchored to FIPS-204 (CIRCL on one side, **QRL's own go-qrllib** on the other). This is the
ML-ADSA analog of ACVP cross-validation.

## Pinned values (abridged; full set in the test files)

```
ContentKeyDerive.t   9f0a0b7d…97b031      DeriveNonce  1de3c04f…f7bd04
ExpandS(s1|s2)       383ab60a…7f37a2      MerkleRoot3  b141de6c…877053
N=1   pk ba80982b…14229e  sig bc027cdd…80d4bc
N=128 pk 95df4d8c…51a4cc  sig 45f667dc…77bd14
rot0  pk 17086715…d4767d  …  rot4 pk 96b81373…db7528   (all distinct)
```

## Honest scope / relation to FIPS-204 ACVP

- These are **aggregate-specific** KATs (pk*/σ* of an N-party aggregate). The **base** ML-DSA-87 KeyGen/
  Sign/Verify KATs are NIST's ACVP vectors (`usnistgov/ACVP-Server` ML-DSA-keyGen/sigGen/sigVer); our
  core is cross-checked against those via CIRCL/go-qrllib (FIPS-204-conformant), not re-pinned here.
- Like ACVP's `deterministic:true` mode, these vectors fix all randomness (here via PRF + a fixed PCG
  seed). The hedged/random base aggregates are intentionally not KAT-pinned (no fixed answer).
- Vectors are versioned by the `-v1` tags in ρ/seed/payload; a parameter or encoding change ⇒ bump to
  `-v2` and regenerate (the test fails loudly on any drift, which is the point).
