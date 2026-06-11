# 22 — Gobra Code-Level Proofs of Construction F

Earlier docs marked code-level (Go source) formal proof "out of scope." It no longer is. This
document records the **Gobra** (Viper-based Go verifier) proofs of Construction-F's structural
backbone — machine-checked at the level of the running Go logic — plus the honest boundary of what
Gobra does and does not establish.

Artifacts: `formal/gobra/integrity.go` (the proofs), `formal/gobra/run.sh` (verify),
`formal/gobra/genuineness.sh` (each proof's "not vacuous" check). Toolchain: ETH Gobra image
`ghcr.io/viperproject/gobra` (bundles Gobra + Viper/Silicon + Z3), Java 21, Z3 4.15.4.

## 1. What Gobra verifies (all GREEN — `Gobra found 0 errors`)

Each theorem mirrors a named algorithm-level proof target and is verified against `//@`
separation-logic specifications (pre/postconditions, loop invariants, termination measures):

| Go symbol (`integrity.go`) | code-level theorem | mirrors |
|---|---|---|
| `nextPow2` (+ `isPow2`, `lemmaPow2Double`) | padded Merkle size is a power of two ≥ n (well-formed fixed-depth tree) | merkle.go `nextPow2`/`padLeaves` |
| `isMember` + `filterRecognized` | **decoy weight-0**: every survivor is a recognized member; non-members are dropped | **F-C7** (Coq `tally_filter`/`decoy_zero_weight`); Go `Registry.FilterRecognized` |
| `merkleBinding` (+ `vfold`, `node`, `nodeInjective`) | **non-equivocation**: a fixed (path, direction-bits) binds at most one leaf to a root | **F-C9** (Coq `no_equivocation`); Go `MerkleVerify` |
| `framingRoundTrip` (+ `encode1`) | **injective framing**: a decoder recovers each field + exact remainder ⇒ `lenPrefixed` is injective ⇒ domain separation sound | **F-C2** (PRF input separation); Go `lenPrefixed` |
| `sumHom` (+ `sumSeq`, `zipPlus`) | **aggregate/tally linearity**: Σ(a+b)=Σa+Σb | **F-C1/F-DEC** (Coq `commit_hom_N`/`agg_core`); Go `coeffSum`/`SumCommit` |
| `reuseRejected` (+ `accept`, `memberOf`) | **one-time (N1)**: once a key is recorded, the same key is rejected | Go `OneTimeGuard` |

`make`/index-fill is used in `filterRecognized` instead of `append` (Gobra's `append` has a weak
value contract); the logic — keep members only — is identical to the deployed code. Hashes are
modelled as opaque pure functions and collision-resistance as injectivity (`nodeInjective`,
discharged by an explicit `assume` labelled assumption A5) — exactly how the Coq/EC proofs treat
H/MTH as named CR primitives.

## 2. Genuineness (the proofs are not vacuous)

`formal/gobra/genuineness.sh` runs a positive control (the real file verifies) and weakens each
proof's key ingredient, asserting Gobra then **fails**:

- remove `nodeInjective` from `merkleBinding` → **fails** (binding genuinely rests on CR);
- over-claim `nextPow2` as `ensures res == n` → **fails** (false for non-powers of two);
- make `filterRecognized` insert a non-member → **fails** (it provably adds only members);
- delete the witness in `reuseRejected` → **fails** (N1 needs the "k is now recorded" witness).

This is the Gobra analogue of `formal/genuineness.sh` for the EasyCrypt proofs.

## 3. Honest boundary (what this is and is NOT)

- **IS:** machine-checked, at the level of the actual Go logic, of the *structural* invariants the
  security arguments rest on — memory-safety/termination of these functions plus the functional
  properties in §1. Faithful: the verified functions are line-for-line the deployed logic, with ids
  abstracted to `int` and hashes to opaque CR functions (the same idealization as the proofs).
- **IS NOT:** a functional proof of the lattice arithmetic (NTT/SHAKE/`UseHint`/`ExpandS` byte
  semantics). That is the formosa-crypto person-years effort; it remains covered at the algorithm
  level by Coq/EasyCrypt + CIRCL measurement (docs/18, docs/20). The Gobra layer closes the
  *structural/logic* half of the old "no code-level proof" caveat; the *arithmetic* half stays as
  named-primitive + measured, and is stated as such.
- **Model vs deployment:** `integrity.go` is a self-contained proof package (`package fproof`); it
  re-states the structural functions of `merkle.go`/`construction_f.go`/`refresh.go` so Gobra can
  verify them without the unsupported `crypto`/`rand` imports. The correspondence is 1:1 and
  documented per symbol in §1.

## 4. Reproduce

```
formal/gobra/run.sh            # verify integrity.go  -> "Gobra found 0 errors"
formal/gobra/genuineness.sh    # positive + 4 weakening probes -> "ALL n GOBRA GENUINENESS CHECKS PASS"
```

Net effect on the project's epistemic ledger: the decoy-integrity (F-C7), Merkle non-equivocation
(F-C9), injective domain-separation framing (F-C2), aggregate/tally linearity (F-C1/F-DEC), and
one-time (N1) properties are now machine-checked **both** at the algorithm level (Coq/EC) **and** at
the Go code level (Gobra) — with the lattice-arithmetic internals the one explicitly-named residual.
