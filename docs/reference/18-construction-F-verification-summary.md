# 18 — Construction F: Verification Completion Summary

Consolidated, honest status of the **Construction-F** (docs/17) formal verification. Every target in
the docs/17 §10 plan is discharged: **machine-checked** (EasyCrypt / EasyPQC / Rocq) and/or
**measured** (Go vs an independent verifier). Method-alignment audited: admit-free, genuineness-
checked, single consistent assumption base. Labels as in docs/16/17.

## 1. Machine-checked artifact inventory (all GREEN)

`formal/check-all.sh` → **19 classical EasyCrypt + 5 quantum (EasyPQC) + 5 Rocq = 29 artifacts**;
`formal/genuineness.sh` → **34/34** (each weakening breaks its proof). Go: `go test ./...` PASS.
(Count updated: now includes `ml_adsa_F_hiding.ec` and the later equivalence-class lemmas; `docs/31` is the
authoritative current tally.)

| # | artifact | tool | role |
|---|---|---|---|
| 1 | ml_adsa_euf.ec | EC | A2 EUF-CMA capstone (msufcma_uncond) |
| 2 | ml_adsa_suf.ec | EC | SUF-CMA |
| 3 | ml_adsa_regimes.ec | EC | two-regime masking (perfect / computational) |
| 4 | ml_adsa_props.ec | EC | A3/A4/A5 properties |
| 5 | ml_adsa_zk_proof.ec | EC | perfect zero-leakage (Construction A) |
| 6 | ml_adsa_rogue_proof.ec | EC | rogue-key → single signer |
| 7 | ml_adsa_nnp_proof.ec | EC | no-new-power → Module-SIS |
| 8 | ml_adsa_mlwe_hop.ec | EC | MLWE key-swap hop |
| 9 | **ml_adsa_F_bridge.ec** | EC | **F-BR** EC↔concrete bridge (domain-explicit; extract_sound realized) |
| 10 | **ml_adsa_F_euf.ec** | EC | **F-C3** EUF no-loss at domain-explicit msg |
| 11 | **ml_adsa_F_refresh.ec** | EC | **F-C2** content-key refresh (PRF → independent) |
| 12 | **ml_adsa_F_manytime.ec** | EC | **F-C4 keystone** many-time via refresh |
| 13 | **ml_adsa_F_zk.ec** | EC | **F-C13** per-content ZK (Q=1) |
| 14 | **ml_adsa_F_concurrent.ec** | EC | **F-C11** concurrent/ROS: unbiasable + simulatable + secret-independent + chained |
| 14b | **ml_adsa_F_hiding.ec** | EC | **F-C7 (privacy)** commitment hiding ≤ 2·adv_mlwe (decoy/vote indistinguishability ⇐ Module-LWE) |
| 15 | ml_adsa_qrom.ec | EasyPQC | QROM EUF (Construction A tight + B lossy) |
| 16 | ml_adsa_qrom_o2h.ec | EasyPQC | O2H at our types |
| 17 | ml_adsa_qrom_reprog.ec | EasyPQC | SemiConstDistr reprogramming bound (Zhandry cross-check) |
| 17b | **ml_adsa_qrom_ghhm.ec** | EasyPQC | **DERIVED** distinct-per-query GHHM21 loss `qs·(qh+1)/|from|` (proven per-round resampling + Thm 6.1) |
| 18 | **ml_adsa_F_qrom.ec** | EasyPQC | **F-C10** QROM at domain-explicit msg |
| 19 | ml_adsa_identity.v | Rocq | aggregate-key identity (2-party) |
| 20 | **ml_adsa_F_correctness.v** | Rocq | **F-C1** N-fold + N=10/100/1000 + domain |
| 21 | **ml_adsa_F_decisions.v** | Rocq | **F-DEC + F-C7** decision modes + decoy integrity + tally |
| 22 | **ml_adsa_F_provenance.v** | Rocq | **F-C8/C9** provenance + one-time binding |
| 23 | **ml_adsa_F_setup.v** | Rocq | **F-C12** transparency + key_indep_of_ctx |
| — | go-mladsa/f_emp_test.go | Go/CIRCL | **F-EMP** N=10/100/1000 + cross-chain, CIRCL-verified |
| — | go-mladsa/{refresh,merkle,construction_f}.go | Go/CIRCL | **full Construction F** — L1 refresh, L2 Merkle key-tree, L3 PoP/registry, det. nonce, one-time, provenance/audit |
| — | go-mladsa/f_construction_test.go | Go/CIRCL | F-conformance: refresh/PoP/aggregate/many-time/decoy/provenance/audit, CIRCL-validated |

> **Implementation conformance.** The Go now realizes the **full Construction F** (not just the L0
> base aggregate): every proven property has a named Go symbol and a passing, CIRCL-cross-checked
> test. See **docs/20** (the refinement map).
>
> **Code-level proof (Gobra).** The "out of scope" caveat is now partly discharged: the structural
> backbone (decoy weight-0 F-C7, Merkle non-equivocation F-C9, injective framing F-C2, aggregate/
> tally linearity F-C1/F-DEC, one-time N1, Merkle padding) is machine-checked at the Go-logic level
> with **Gobra** — `formal/gobra/` (6 theorems GREEN, 5/5 genuineness). See **docs/22**. The
> remaining half (lattice-arithmetic byte semantics) stays named + CIRCL-measured.
>
> **Unified specification.** **docs/21** indexes every implemented & tested approach (A, B, F, the
> decision modes D1–D6 incl. threshold/subset-select/approval, cross-chain, single-signer) with a
> property×evidence completeness matrix and a completeness verdict. The proven↔tested gaps it found
> (threshold, option-separation) were closed with new Go tests (`decisions_modes_test.go`).

## 2. Construction-F target status (docs/17 §10)

| target | property | status |
|---|---|---|
| F-C1 | correctness N-fold + N=10/100/1000, in-domain | **proven** (Rocq) |
| F-BR | EC↔concrete bridge (domain-explicit ops) | **proven** (EC) |
| F-C2 | content-key refresh soundness | **proven** (EC) |
| F-C3 | EUF-CMA in-domain, no N-loss | **proven** (EC) |
| **F-C4** | **many-time keystone (Q-independence)** | **proven** (EC) |
| F-C5 | rogue-key → single signer | **proven** (reuse) |
| F-C6 | no-new-power → Module-SIS | **proven** (reuse) |
| F-C7 | decision integrity (weight-0 decoys) | **proven** (Rocq) |
| F-C8/C9 | provenance soundness + one-time binding | **proven** (Rocq) |
| F-C10 | QROM in-domain | **proven** (EasyPQC) |
| F-C11 | concurrent / ROS-resistance | **proven** (EC) — unbiasable + simulatable + secret-independent + chained, NO ROS/AGM |
| F-C12 | transparency / no secret setup | **proven** (Rocq) |
| F-C13 | per-content ZK (Q=1) | **proven** (EC) |
| F-DEC | YES/NO, 1-of-M, approval, subset-select, ranked, k-of-n threshold, weighted tally | **proven** (Rocq) |
| F-EMP | empirical N=10/100/1000 + cross-chain | **measured** (CIRCL) |
| key_indep_of_ctx | domain-portability (§12.3) | **proven** (Rocq) |

## 3. Single assumption base (audited consistent)

Construction F rests on **nothing beyond ML-DSA-87's own assumptions plus a PRF and a CR-hash** —
no ROS, no AGM/OMDL, no trapdoor, no SNARK/STARK, no TEE, no trusted setup:

```
MLWE, Module-SIS, SelfTargetMSIS   -- ML-DSA-87's own (FIPS-204 / arXiv 2312.16619)
HVZK / masking, A-regularity       -- ML-DSA-internal lattice properties (already used by ML-DSA)
PRF security                       -- a PRF (ML-DSA already uses one for deterministic signing)
collision-resistance / injective framing of H, MTH   -- a hash (SHAKE-256)
```

Named axioms (all of the above kind, none hollow): `expandS_range`, `A_regularity`, `commit_binding`,
`hvzk_masking`, `prf_security`, `mldsa_extract_sound`, `coq_F_C1_completeness` (imports the Rocq F-C1
theorem), `dkey_ll`. Verified: zero `admit/Admitted/sorry`; 34/34 genuineness.

## 4. What is proven, in plain terms

For **N = 10 / 100 / 1000** signers, Construction F yields **one byte-exact 4627-B ML-DSA-87
signature** accepted by the **unmodified FIPS-204 verifier** (measured vs CIRCL), with:

- **correctness** (the aggregate verifies in its domain) — Rocq;
- **EUF-CMA at NIST Level 5, no N-loss** — EC;
- **many-time** security via content-key refresh (Q-independent) — EC keystone;
- **concurrent / ROS-resistant** (commit-reveal binding + A-regularity ⇒ unbiasable challenge;
  HVZK ⇒ simulatable; whole game secret-independent) — EC, **no ROS/AGM assumption**;
- **post-quantum (QROM)** — EasyPQC;
- **per-content zero-knowledge**, **transparency (no trusted setup)**, **domain-portability /
  cross-chain** (`QRL:SUI`), **provenance + one-time binding**, **decision integrity**, and **all
  decision/voting modes** (incl. both N-of-M senses) — Rocq/EC.

## 5. Honest residual scope (not overclaimed)

- **F-C4 / F-C11** are admit-free with one *supplied* standard bound each (F-C4: the Q-fold union
  `Q·eps_content`; F-C11: the secret-free game bound `B = adv_mlwe + Pr[STMSIS]`) — both **= F-C3**,
  not new assumptions; the reductions themselves are proven. Chaining the F-C11 components into a
  single literal `Pr`-inequality is `concurrent_euf_chained` (done); the secret-free→SelfTargetMSIS
  end is euf.ec (proven). **Update (proof-closure, docs/35 §6):** for the *deployed* non-interactive
  scheme there is no supplied bound at all — its signing oracle is atomic (no open sessions), so
  concurrent EUF-CMA **is** `msufcma_uncond` directly (`ml_adsa_euf.ec : concurrent_atomic_uncond`).
  The supplied `B` pertains only to the optional interactive commit-reveal variant. Separately, the
  QROM multi-query signing seam is now mechanized end-to-end (`ml_adsa_qrom_ghhm.ec :
  sign_oracle_mr_equiv` — the qs-round real signer ≡ reprogramming simulator, perfectly).
- **Byte-exact ML-DSA internals** (NTT/SHAKE/UseHint/leaf_ok) remain **named** in EC and **measured**
  in Go (the formosa-crypto/dilithium person-years effort is out of scope), per docs/17 §10.
- **Operational**: one-time per-content key/nonce discipline (NIST SP 800-208), per-content key
  availability (Merkle tree), cohort/norm cap — engineering constraints, not security gaps (docs/17 §16).
- **Independent cryptographic review** remains required before deployment.

## 6. Outside Construction F (separate tracker items)

- **QROM-B GHHM21** distinct-per-query adaptive reprogramming (the *tight* lossy Construction-B QROM
  case) — **DONE/derived** (task #6, `ml_adsa_qrom_ghhm.ec`). The tight linear loss
  `reprog_ghhm qs qh = qs·(qh+1)/|from|` (`ghhm_hybrid`) is derived from the *proven* per-round perfect
  resampling (`LambdaReprogram.main_theorem`) + the elementary distinct-query bound
  (`T_Distinct.bound_distinct`, Thm 6.1), replacing the imported Zhandry semi-constant-distribution
  quartic axiom (kept only as a cross-check in `ml_adsa_qrom_reprog.ec`). The interim named/cited lossy
  capstone (task #3, `qrom_eufcma_lossy`) remains. Construction F uses the **tight Construction-A** QROM
  path (F-C10), so it never depended on this — #6 is off F's critical path, now also derived.
- **Plain-language undergraduate whitepaper** — **done** (`docs/19`, task #4).

Attribution: this project is **pq-cybarg's** (module `github.com/pq-cybarg/ml-adsa`); QRL 2.0 is the
deployment target (it uses the ML-DSA-87 this scheme aggregates).
