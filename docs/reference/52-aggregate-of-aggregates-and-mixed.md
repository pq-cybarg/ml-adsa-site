# Aggregate-of-aggregates and mixed (aggregates + individual signatures) — feasibility (#130)

Demonstrated in `go-mladsa/construction_offset_hierarchy_test.go` (byte-exact, all binding one decision).

## What IS feasible

1. **Single byte-exact super-aggregate over all signers** = the **flat** `AggregateOffsetF`. "Aggregate of
   aggregates" as *one* signature is just the flat aggregate whose commitment `ΣW = Σ(hiᵢ·α+qᵢ)` is computed by a
   partial-sum **tree** — associativity of `+` means a hierarchy of partial commitments yields the **identical**
   byte-exact `σ*`. Capped by the per-committee norm-wall ceiling (≈262k at σ=3β; docs/49). *(Test:
   `TestHierarchy_SingleSuperAggregate_IsFlat`, n=12 → one 4627 B ML-DSA-87 sig.)*

2. **List super-aggregate** (= `ShardedAggregate`, #117): a set of committee aggregates, each byte-exact, all
   binding the same decision — "aggregate of aggregates" as a recursive **container**. Unbounded total; size
   linear in #committees.

3. **Mixed: aggregates + individual signatures together.** An individual signature **is** an aggregate of `n=1`
   (same machinery, `SignSingle`/`AggregateOffsetFDefault` with one member). A `ShardedAggregate` may therefore
   have **heterogeneous committee sizes including 1**, freely mixing multi-signer aggregates and standalone
   individual signatures; all verify byte-exact and bind one decision. *(Test:
   `TestHierarchy_MixedAggregatesAndIndividuals`, sizes [8,1,5,1], verified; wrong-decision on the lone
   individual rejected.)*

## What is NOT feasible (documented, not hidden)

You **cannot fold two already-finalized aggregates** `σ*_1, σ*_2` (with their fixed Fiat–Shamir challenges
`c_1 ≠ c_2`) into a **new single byte-exact aggregate** under a fresh global challenge `c_top`: the responses
`z*_j` were computed for `c_j`, not `c_top`, so `Σ z*_j` has the wrong algebraic form for `c_top`. A
single-signature super-aggregate must be **planned** (every signer responds to the *global* challenge) — which is
exactly the flat aggregate of shape (1), with the commitment optionally tree-computed. Therefore **recursion
after-the-fact is the LIST form (2)/(3)**, not a re-folded single signature. This is the same structural reason
the combine is non-interactive only via determinism + a shared challenge ([[ml-adsa-noninteractive]]).

## Security

Every component (aggregate or individual, at any level) is a byte-exact ML-DSA-87 signature, so each inherits the
same bit-security and leakage analysis as a single aggregate (docs/50, docs/51): forging any of them, or recovering
any live/future/root key, stays at ML-DSA-87. The mixed/list container adds only the requirement that all
components bind the **same** decision (`ShardedAggregate.Verify` checks payload/regRoot/epoch equality), which is
enforced and tamper-tested.
