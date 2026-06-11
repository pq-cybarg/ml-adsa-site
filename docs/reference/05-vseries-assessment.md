# LMSA — Assessment of the v0.3–v0.14 ("keep pushing") line

> **Historical / iteration note (2026-06-11).** This document is part of the research/design trail and reflects an **earlier iteration**; some counts, status labels, and construction details predate the current Construction F. The authoritative current specification is **`docs/30`**, the verification status and tallies are in **`docs/31`** and reproducible via **`formal/count-artifacts.sh`** (29 artifacts, 134 lemmas, 33/33 genuineness, 6 Gobra), and the cross-document reconciliation is **`docs/35`**. Numbers below are preserved as the historical record.

Verdict: **no new construction.** Stripped of framing, every version is the same two
objects already rejected — an **argument of knowledge** (renamed "correction proof",
"disjunctive argument", "zk component") plus a **Module-SIS cross-term commitment** —
re-introduced under new names and bolted to two claims that are provably false. The
genuine kernel underneath is exactly **LaBRADOR-aggregation of ML-DSA** (real, but a
SNARK, verified by a SNARK verifier — not FIPS-204).

## The three load-bearing claims, each checkable

### Claim A — "rephrase so normal ML-DSA also has a zk component → functional equivalence"
True, but the equivalence runs the wrong way. To give both a shared verifier you add the
proof to BOTH; the shared object is then a **new scheme** (ML-DSA + proof) with a **new
verifier**. It is not FIPS-204, the existing ecosystem won't accept it, and single
signatures become larger/slower. You drag plain ML-DSA *up* into the proof-world, not the
aggregate *down* to ML-DSA. "ML-DSA + a proof of knowledge" is exactly the SNARK path
that was vetoed. Relocates the problem; doesn't dissolve it.

### Claim B — "absorb the correction/proof into h_final" — IMPOSSIBLE vs the unmodified verifier
ML-DSA-87's hint is a **fixed** object: `k=8` polynomials of {0,1} coefficients, total
weight `≤ ω = 75`, encoded canonically in exactly **`ω + k = 83` bytes**. FIPS-204
`HintBitUnpack` **returns ⊥** on any non-canonical / over-weight / non-monotone encoding.
There is no spare capacity. A correction polynomial `δ ∈ R_q` is multi-kilobyte; a proof
`π` is hundreds of bytes to KBs. Neither fits in 83 bytes of fixed-format hint, and
appending bytes makes the decoder reject. "Extended but compatible hint" is a
contradiction: extend it and it is no longer the FIPS-204 verifier. This single fact
kills the "functional equivalence with the unmodified verifier" claim.

### Claim C — "constant size by recursively folding the proof too" — IS a recursive argument system
Folding a proof so its size stays constant across depth with binding preserved is the
*definition* of recursive proof composition (Nova/Halo/LaBRADOR). There is no
"fold the proof to constant size soundly" that is not an argument system — it is the
rejected primitive by definition. The v-series never closes the regress (folding the
proof creates new cross-terms → new corrections → new proof …); it asserts closure. The
schemes that actually close it (LaBRADOR) are SNARKs whose output is verified by a SNARK
verifier, not ML-DSA.

## The litmus that ties it together
Run the v0.14 aggregator with `z = 0` and **fabricated** leaves. If the verifier only
checks UseHint + hash + norm + linear relation on the final tuple, it **accepts** — the
§3 forgery (`docs/04`), unchanged. The only thing that stops it is *actually verifying a
binding proof* — the SNARK that is either "absorbed into the hint" (impossible, B) or
"folded away" (a recursive SNARK, C). Every path returns to the rejected primitive,
because of the theorem in `docs/04`: **binding comes only from commitment, proof, or
secret — never from the equation merely passing.**

## Decorations doing no work
- "Control-theoretic / Laplace compensator / notch filters on UseHint basins": UseHint is
  a nonlinear per-coefficient rounding, not an LTI system. No actual `δ`, influence
  matrix, or acceptance probability is ever produced. Metaphor, not math.
- "NTT makes cross-terms cleaner": true and irrelevant — NTT is a linear basis change; it
  cannot dissolve a bilinear obstruction (`docs/04` §3).
- "Limited rejection sampling to hit exact UseHint + sparse c": finds a *self-consistent*
  tuple = the §3 forgery; self-consistency ≠ binding to real leaves.

## What is actually real here
Strip claims B and C and the v-series = **LaBRADOR-aggregation of ML-DSA**: constant-size,
recursive, zero-knowledge-able, Module-SIS-secure. Good and novel for ML-DSA — but (a) it
is a SNARK, and (b) its verifier is a LaBRADOR verifier, not FIPS-204. Claims B and C were
the only things making it look like it output an ML-DSA signature.

## Recommendation
Stop iterating version numbers; build a real endpoint:
- **MLADSA** (`docs/03`): non-SNARK, exact FIPS-204, unforgeable, capped cohort — for
  consensus/bounded signer sets.
- **LaBRADOR-aggregation of ML-DSA** (`docs/02`): constant-size, recursive, arbitrary
  messages — a SNARK (the price of constant-size unbounded binding, which is a theorem),
  verified by a compact PQ verifier, not FIPS-204.
