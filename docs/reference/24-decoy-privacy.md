# 24 — Decoys: privacy capability (who makes them, where from, how many)

Decoys are ML-ADSA's privacy mechanism for **decisions/voting**: without them the participant set and
vote leak *who* participated and *how*. This resolves the three open questions and records what is
built. (Consensus attestations deliberately make participation public for rewards/slashing, so they do
**not** use decoys; this is for private decisions.) Code: `go-mladsa/decoy.go`,
`go-mladsa/decoy_test.go`. Proofs: F-C7 (`decoy_zero_weight`, `tally_filter`, Coq; `filterRecognized`,
Gobra).

> **Framing (read first).** The **mainline** (Construction F) decoy is an **invalid (non-registered)
> signer**: its weight is 0 *because it is an invalid signer* (the public registry, F-C7), it disguises
> the signer set across **refreshes**, and it is **ZKP-free** (the aggregate construction uses no
> SNARK/STARK/ZK). The **hidden-weight commitment** that everything below describes — and what
> `commit_hiding` proves — is a **separate, optional mode** for *value*-confidential tallies: useful,
> but **not** the mainline decoy mechanism, and the mainline decisions don't need it (weights come from
> the registry, range-sound and ZKP-free). Read the "Two sides / Privacy / Q1–Q2 / hiding" material
> below as that **optional value-tally mode**; the mainline decoy is the invalid-signer one above.
> (LaBRADOR is **Construction E**, a separate tested technique — not this.)

## Two sides — both required

- **Integrity (proven, built):** a decoy has **weight 0**, so *no number of decoys can change the
  outcome*. Enforced by the public registry (`Registry.Weight`) and the **binding** commitment
  (Module-SIS) — publicly checkable, no trusted party. (F-C7.)
- **Privacy (built here):** decoys must be **indistinguishable** from real participants. Public-registry
  non-members give integrity but are publicly identifiable (membership is public), so privacy uses
  **hidden weights**: each participant commits its per-decision weight (1 = real, 0 = decoy/abstain)
  with the additively-homomorphic commitment (`commit.go`). Hiding = **Module-LWE** (the same
  assumption as ML-DSA keys). An observer cannot tell a `w=1` commitment from a `w=0` one; the tally
  `Σ commitments` opens **only the total**.

## Q1 — Who makes the decoys?

**No special or trusted party.** Two trustless sources:
- **Natural decoys (default):** every eligible (registered) member submits a weight commitment each
  decision, `w=0` if abstaining — so **abstainers *are* the decoys** and the anonymity set = the
  eligible set. No separate producer exists.
- **Extra cover (optional):** any member may add its own `w=0` "cover" commitments to enlarge the set.
  Permissionless and self-produced.

## Q2 — Where do they come from / who ensures zero weight?

**Publicly verifiable, no trust.** A decoy is weight-0 either by (a) **not being in the recognized
registry** (public `Weight`, F-C7) or (b) a **commitment that opens to 0** (binding = Module-SIS).
Anyone verifies the tally opening (`OpenTally`); a decoy **cannot acquire weight** without a registry
opening it does not have. So "who ensures zero weight" is *the math*, not a party.

## Q3 — Minimum number needed

For **k-anonymity** of a participant (an observer cannot narrow it below k candidates), the anonymity
set (real + decoys) must be ≥ k, so:

```
decoys = max(0, k − real)        # MinDecoys(k, real)
```

- **Default policy:** anonymity set = the full eligible set (turnout + abstainers) ⇒ `k = |REG|` at
  **zero extra cost** (abstainers supply the decoys). Add explicit cover only to exceed `|REG|` or to
  hide the *turnout size* itself.
- Examples (tested): hide 4 voters among ≥10 ⇒ 6 decoys; a lone voter needs 63 decoys for 64-anonymity.

## What is built & measured (`decoy_test.go`, all pass)

- **Private ballot:** 4 real YES among 10 (6 decoys) → tally opens to total=4; individuals hidden.
- **Binding:** the tally opens to exactly one total — a decoy cannot gain weight, count cannot be
  inflated/deflated (Module-SIS).
- **Indistinguishability:** `TV(commit(1), commit(0)) = 0.0498` vs the sampling-noise floor
  `TV(commit(0), commit(0')) = 0.0491` over 8000 trials — **equal within noise**, so the weight is
  statistically invisible (hiding = Module-LWE).
- **Decoy flood:** +1000 decoys → tally unchanged (F-C7).
- **Sizing:** `MinDecoys` matches `max(0, k−real)`.

API: `CommitWeight`, `OpenTally`, `MinDecoys`, `MakeDecoySigner` (`decoy.go`).

## Hiding is machine-checked (Module-LWE)

The privacy half is now **machine-checked in EasyCrypt** — `formal/ml_adsa_F_hiding.ec`:
`commit_hiding` proves the left-or-right hiding advantage `| Pr[Real(v0)] − Pr[Real(v1)] | ≤ 2·adv_mlwe`
via two hops — `mlwe_assumption` (real mask ≈ uniform mask = Module-LWE) and the proven `rand_indep`
(a uniform mask perfectly hides the value, from the structural `uniform_mask_hides`, the analog of
A-regularity). So the **optional value-tally** is machine-checked on both fronts: **binding**
(Module-SIS) and **hiding** (`commit_hiding`). This is *not* the mainline decoy's privacy — the
mainline decoy's integrity is F-C7 `decoy_zero_weight`/`tally_filter` (+ Gobra `filterRecognized`) and
its signer-set privacy is the invalid-signer + refresh disguise; neither uses `commit_hiding`.
Genuineness-checked (weakening `uniform_mask_hides`, or the `2·adv_mlwe` bound, breaks the proof).

## Honest scope

- Hiding is **computational (Module-LWE)** at the commitment-randomness scale (`decoyRandBound = η`),
  not information-theoretic; this is the same assumption ML-DSA already makes. Wider randomness trades
  toward statistical hiding at a cost; the default matches the LWE error regime.
- The **mainline decoy's** privacy is *unlinkability*: the aggregate is non-deaggregatable and keys
  refresh per content, so the recurring signer set can't be tracked — it does **not** rely on hidden
  weights. (A full auditor opening `part_root` + the registry can still separate members from decoys,
  so this protects the validity-only/optimistic path and across-content tracking, given enough cover
  per Q3.) The hidden-weight tally above is the separate way to hide *values*.
