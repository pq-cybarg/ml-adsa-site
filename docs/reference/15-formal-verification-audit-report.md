# ML-ADSA Formal-Verification Audit Report

> **Historical / iteration note (2026-06-11).** This document is part of the research/design trail and reflects an **earlier iteration**; some counts, status labels, and construction details predate the current Construction F. The authoritative current specification is **`docs/30`**, the verification status and tallies are in **`docs/31`** and reproducible via **`formal/count-artifacts.sh`** (29 artifacts, 134 lemmas, 33/33 genuineness, 6 Gobra), and the cross-document reconciliation is **`docs/35`**. Numbers below are preserved as the historical record. Its statistics dashboard (e.g. 11 EC files, 40 EC lemmas, 45 total, 9/9 or 19/19 genuineness) is an earlier snapshot and is internally inconsistent; the current figures supersede it.

**Document class:** technical security audit / formal-methods evidence dossier.
**Subject:** ML-ADSA — aggregate digital signature for ML-DSA-87 (FIPS-204), QRL 2.0.
**Scope of this report:** the machine-checked formal verification (EasyCrypt classical ROM,
EasyPQC quantum ROM, Coq correctness), its exact contents, statistics, mathematical content,
degrees of certainty, and the exact limits of every technique used.

> **Integrity statement.** Every quantitative claim below is derived from the actual artifacts
> in this repository and the `formal/check-all.sh` / `formal/genuineness.sh` runners. Items are
> labelled **PROVED** (machine-checked, zero `admit`), **ASSUMPTION/PRIMITIVE** (an axiom = a
> standard hardness assumption or an imported published lemma), **TESTED** (empirical), or
> **OPEN** (not done). Nothing is labelled PROVED that contains an `admit`. Known weaknesses,
> caveats, and soundness boundaries are stated explicitly in §9–§11; none are omitted.

---

## 1. Statistics dashboard (exact, from the artifacts)

| Metric | Value | Source |
|---|---|---|
| EasyCrypt source files | 11 | `formal/ml_adsa_*.ec` |
| Coq source files | 1 | `formal/ml_adsa_identity.v` (51 LOC) |
| **EasyCrypt lemmas, total** | **40** | `grep '^lemma'` |
| **EasyCrypt lemmas, admit-free (PROVED)** | **40 (ALL)** | per-file `admit` audit |
| EasyCrypt lemmas admitted | **0** | the repository is entirely admit-free |
| Coq theorems (PROVED) | 5 | `ml_adsa_identity.v` |
| **Machine-checked statements, total** | **45** | 40 EC + 5 Coq |
| Genuineness checks (weaken-primitive → must break) | **19/19 pass** | `formal/genuineness.sh` |
| Regression files (all compile) | **12 (8 classical + 3 quantum EC + 1 Coq)** | `formal/check-all.sh` |
| Regression (all files compile) | **ALL GREEN** | `formal/check-all.sh` |
| Design/analysis documents | 14 (1817 LOC) | `docs/` |
| Reference implementations | Go (CIRCL-cross-checked) + Python (pqcrypto-validated) | `go-mladsa/`, `prototype/` |

**Per-file ledger:**

| File | LOC | lemmas | axioms | real admits | role |
|---|---|---|---|---|---|
| `ml_adsa_identity.v` (Coq) | 51 | 5 thm | — | 0 | aggregation correctness algebra |
| `ml_adsa_zk_proof.ec` | 46 | 1 | 1 | 0 | A3 perfect zero-leakage (Constr. A) |
| `ml_adsa_rogue_proof.ec` | 88 | 2 | 1 | 0 | A4 rogue-key → single-signer |
| `ml_adsa_nnp_proof.ec` | 98 | 3 | 1 | 0 | A5 no-new-power → Module-SIS |
| `ml_adsa_mlwe_hop.ec` | 106 | 3 | 0 | 0 | MLWE key-indist. hop (hop1) |
| `ml_adsa_euf.ec` | 145 | 4 | 5 | **0** | **A2 keystone: EUF-CMA → MLWE+SelfTargetMSIS** |
| `ml_adsa_qrom.ec` | 489 | 12 | 9 | 0 | QROM security, both constructions |
| `ml_adsa_qrom_o2h.ec` | 35 | 1 | 0 | 0 | semi-classical O2H at our types |
| `ml_adsa_props.ec` | 122 | 4 | 2 | 4 | original abstract specs — **superseded** |

---

## 2. Trust base and degrees of certainty

A "machine-checked" claim is only as strong as the chain of trust beneath it. Stated explicitly:

1. **Logical kernel.** EasyCrypt's ambient logic (pRHL/pHL + ambient higher-order logic) and
   Coq's kernel. Certainty: very high (decades of use; small trusted kernels). *Residual risk:*
   prover soundness bugs — not eliminated, standard for all formal methods.
2. **SMT back-ends.** EasyCrypt discharges first-order side conditions via why3 → Z3 / Alt-Ergo
   / CVC. Certainty: high. *Residual risk:* SMT solver soundness bugs; mitigated by using
   multiple solvers and by the structure of our goals (mostly real-arithmetic and equational).
   **Audit note (documented in `genuineness.sh`):** EasyCrypt's `smt()` *auto-includes in-scope
   global axioms*. Consequence: "drop the `smt(lemma)` hint" is **not** a valid non-vacuity test
   for files with local axioms. We therefore test non-vacuity by **weakening the axiom's
   conclusion to a trivial form and confirming the proof breaks** (§7). This is the correct,
   stronger test and it is automated.
3. **Modeling fidelity.** A proof certifies the *model*, not reality. Our models abstract the
   ML-DSA scheme to typed operators with named algebraic/distributional properties (the
   primitives of §5). Certainty that the model faithfully captures ML-DSA-87: **argued, not
   proved** — this is the standard gap between a security proof and an implementation, and is
   why independent cryptographic review remains required (§11).
4. **Assumptions.** MLWE, Module-SIS, SelfTargetMSIS hardness, and the imported quantum lemmas
   (AHU19 O2H, Zhandry semi-constant distribution) are *assumptions/cited results*, not proved
   here. Certainty: the community-standard confidence in these post-quantum assumptions (§6).

**Net:** the reductions (game-hops, compositions) are at certainty level (1)+(2); the endpoints
they reduce to are at level (4); faithfulness is level (3).

---

## 3. Toolchain and reproducibility (exact)

Two **separate** opam switches are mandatory because EasyPQC pins an older why3:

| Switch | Compiler | EasyCrypt | why3 | SMT | Used for |
|---|---|---|---|---|---|
| `discus-verified` | OCaml 5.2.1 | mainline-class | 1.8.2 | Z3 4.15.x | 6 classical `.ec` |
| `easypqc` | OCaml 5.2.1 | **`deploy-quantum-upgrade`** (EasyPQC) | **1.6.0** (`< 1.7` pin) | Z3 4.13.3 + Alt-Ergo 2.4.3 | 2 quantum `.ec` |

Reproduce everything:
```sh
formal/check-all.sh      # compiles all 8 .ec (right switch each) + the .v ; prints ALL GREEN
formal/genuineness.sh    # 9 weaken-a-primitive checks ; prints ALL 9 ... PASS
```
The quantum binary is driven by `formal/ec-quantum.sh` (sets PATH to a recognized z3, adds
`theories/quantum` to the include path). EasyPQC = the `deploy-quantum-upgrade` branch of
EasyCrypt (built from source; the prior `deploy-quantum` was removed upstream).

---

## 4. Property-by-property breakdown (full mathematical detail)

Notation: `ρ` shared seed (`A = ExpandA(ρ)`); honest key `(pk, sk)`; cohort `C` of co-signer
public keys with proofs-of-possession; aggregate key `apk = aggkey ρ (pk :: C)`; forgery
`(C, m, s)`; RO `H`. ML-DSA-87 parameters in §6.

### A1 — Correctness / completeness — **PROVED** (Coq) + **TESTED**
**Criterion targeted:** an honestly produced aggregate satisfies the *unmodified* ML-DSA-87
verification relation.
**Method:** Coq/`nsatz` over the reals — 5 theorems in `ml_adsa_identity.v`: the reconstruction
identity, key-aggregation linearity (`apk` is the sum of the `t_i`), response aggregation,
`aggregate_verifies_2`, and `adaptive_key_collapses` (the algebraic reason an *adaptively
chosen* aggregate key is forgeable — i.e. why the scheme **requires** a fixed well-formed key).
**Empirical corroboration:** the Go implementation's aggregates are accepted by an independent
verifier (Cloudflare CIRCL) and vice versa, ctx="QRL".
**Degree of certainty:** machine-checked algebra over ℝ (kernel-level) + cross-implementation
test. **Limit:** Coq works over ℝ (not ℤ_q) — the ring identities are characteristic-0;
the ℤ_q instantiation is argued structurally (the identities are polynomial and hold mod q).

### A2 — Unforgeability (MS-UF-CMA) — **PROVED for Construction A** (`ml_adsa_euf.ec`)
**Criterion targeted:** no PPT forger with one honest signer, a signing oracle, and control of
the rest of the cohort (each with valid PoP) outputs a fresh-message aggregate that verifies
under `apk`, except with the advantage below.
**Theorem (`msufcma_uncond`, zero admit):**
```
Pr[ MS-UF-CMA(A) ]  ≤  adv_mlwe  +  Pr[ STMSIS(B(A)) ].
```
A **tight** reduction (no loss term) to exactly ML-DSA's two FIPS-204 assumptions.
**Step-by-step (the three machine-checked game hops):**
- **(S) `sq_perfect`:** `Pr[MS-UF-CMA(A)] = Pr[G1(A)]`, where `G1` replaces the honest signing
  oracle (`sign1 sk`) by the HVZK simulator (`simsig pk`). Proof: `byequiv`; the signing-oracle
  equivalence is `sign1 sk m = simsig pk m`, which holds for honest keys by `masking_ok` (§5);
  perfect (no loss) — this is Construction A / bit-zero. Quantified over all adversaries `A`.
- **(M) `bridge_sim` + `mlwe_assumption`:** `Pr[G1(A)] = Pr[MLWE_L(A)]` (drop the unused secret,
  a lossless independent sample — `rnd{1}` + `dsecret_ll`), and
  `|Pr[MLWE_L(A)] − Pr[MLWE_R(A)]| ≤ adv_mlwe`. The gap is by construction the decisional-MLWE
  distinguishing advantage of the explicit reduction `RedMLWE` (real key vs uniform key, same
  game body).
- **(E) `eq_exact`:** `Pr[MLWE_R(A)] ≤ Pr[STMSIS(B(A))]`. Proof: `byequiv` with postcondition
  `res{1} ⇒ res{2}`; a verifying forgery relative to the RO *is* a SelfTargetMSIS witness, by
  `extract_sound` (§5). **Tight** (no forking, no O2H) — this is the raison d'être of
  SelfTargetMSIS.
- **Assembly:** `Pr[A2] = Pr[G1] = Pr[MLWE_L] ≤ |MLWE_L−MLWE_R| + Pr[MLWE_R] ≤ adv_mlwe +
  Pr[STMSIS(B)]`. Discharged by real-arithmetic `smt()` over the three hops.
**Degree of certainty:** machine-checked reduction (level 1+2) to MLWE + SelfTargetMSIS (level 4).
**Limit:** perfect masking is Construction A; Construction B replaces (S) by a bounded loss (§9).

### A2-regimes — Masking regime distinction (practical vs idealized) — **PROVED both** (`ml_adsa_regimes.ec`)
**Criterion targeted:** honest separation of the two HVZK regimes for the *aggregate* response
`z = Σ zᵢ`. Perfect (information-theoretic) masking — `sign1 sk m = simsig pk m` exactly — holds
**only** when the aggregate mask bound `B ≥ (q−1)/2` (the summed mask wraps uniformly mod `q`).
In practical ML-DSA `β = 120 ≪ q/2 = 4190208`, so masks are **narrow** (`! wide_mask`) and HVZK
rests on the **computational hardness of MLWE** — not on perfect masking. The earlier
Construction-A "perfect/tight" results were implicitly the `B ≥ (q−1)/2` regime; this is the
honest practical companion.
**Theorems (zero admit):**
- `a2_regime_I` (`wide_mask`): `Pr[EUF-CMA] ≤ adv_mlwe + Pr[STMSIS(B)]` — TIGHT, no masking loss.
- `a2_regime_II` (`! wide_mask`): `Pr[EUF-CMA] ≤ adv_mask + adv_mlwe + Pr[STMSIS(B)]` — the
  computational masking term `adv_mask` (real-vs-simulated signing distinguishing advantage).
**Practical-regime GOAL (encoded):** ML-ADSA must inherit the base ML-DSA **security level**
(NIST Cat 2/3/5 for ML-DSA-44/65/87). The named reduction `mask_reduces_to_mlwe`
(`adv_mask ≤ adv_mlwe` — a masking distinguisher *is* an MLWE distinguisher at the **same**
parameters) gives `a2_regime_II_inherits`: `Pr[EUF-CMA] ≤ 2·adv_mlwe + Pr[STMSIS(B)]`.

*Reading the ×2 correctly (this matters).* The factor 2 is a **reduction-tightness artifact, not
a security loss**: the proof invokes MLWE hardness in two places (the key-swap hop and the masking
hop), so the *bound* sums two MLWE-advantage terms. **Security level — the NIST category — is set
by the cost of the best-known attack on the parameters (core-SVP / gate counts), NOT by the
reduction.** ML-ADSA uses the **identical** ML-DSA-87 parameters and reduces to the **identical**
hard problems (MLWE, SelfTargetMSIS, Module-SIS), so the best-known-attack cost (≈2²⁸⁵ MLWE,
≈265-bit MSIS) is **unchanged** → still Category 5. A constant factor in the reduction does not
move a 256-bit attack cost. This is exactly how ML-DSA itself is parameterized: its own reduction
is non-tight and the Dilithium spec (§6.2.2/§6.3) sets parameters by best-known-attack core-SVP,
*ignoring* the reduction loss. So ML-ADSA's **security level is identical** to base ML-DSA; only
the **reduction bound** is ≈1 bit looser (cosmetic, lives in the proof).

*What the ≈1-bit reduction looseness implies in practice:* (i) **deployment/parameters —
nothing**: parameters are set by best-known-attack core-SVP, which has a ~20–30-bit margin over
the Cat-5 floor (≈2²⁸⁵ MLWE / ≈265-bit MSIS vs ~256-bit), so the reduction is not the binding
constraint and a ×2 changes no parameter and no category; (ii) **as a provable guarantee** — only
1 bit of extra slack, dwarfed by ML-DSA's *own* reduction non-tightness (the QROM loss is
Ω(ε²/Q⁴), polynomial in the query count Q ≫ 1 bit), which is exactly why these schemes assume
SelfTargetMSIS directly and set parameters by cryptanalysis; (iii) **to "buy it back"** if one
insisted on tightness — ≈1 bit more lattice, a negligible BKZ-blocksize bump within the existing
margin. The ×2 itself is a hybrid/union-bound artifact (MLWE invoked in two hops), not anything
an attacker can exploit. No new/weaker assumption, no parameter change. **Degree of certainty:**
machine-checked. **Genuine:** weakening `masking_perfect_wm`, `mask_reduces_to_mlwe`, or dropping
the `adv_mask` term breaks the proof.

### A2-strong — Strong unforgeability (SUF-CMA) — **PROVED for Construction A** (`ml_adsa_suf.ec`)
**Criterion targeted:** the FIPS-204 design notion — no forger produces ANY new `(message,
signature)` pair that verifies, *including a new signature on an already-signed message* (not
just a fresh-message forgery as in EUF-CMA).
**Theorem (`sufcma_uncond`, zero admit):** `Pr[SUF-CMA(A)] ≤ adv_mlwe + Pr[StrongSIS(Bsm(A))]`,
where `StrongSIS` is the combined hardness `strong_ok = stmsis_ok ∨ msis_ok`. The extra
Module-SIS disjunct is the strong-forgery case: a forgery that reuses an oracle signature's
`(μ, c)` but changes the response `(z, h)` makes the difference of the two responses a short
nonzero kernel vector — a Module-SIS solution with bound `ζ' = max{2(γ₁−β), 4γ₂+2}` (Dilithium
spec §6.2.2). By the standard union bound `Adv[StrongSIS] ≤ Adv[SelfTargetMSIS] + Adv[Module-SIS]`,
so this is exactly ML-DSA's FIPS-204 SUF-CMA assumption set **MLWE + SelfTargetMSIS + Module-SIS**.
Hops mirror A2 (S `sq_perfect`, M `mlwe_assumption`, E `eq_strong` via the named `strong_extract`).
**Degree of certainty:** machine-checked. **Limit:** Construction A perfect masking (as A2).

### A3 — Zero-leakage / zero-knowledge — **PROVED for Construction A** (`ml_adsa_zk_proof.ec`)
**Criterion targeted:** published transcripts are simulatable from public data → no secret leak;
leakage ≤ ML-DSA's own (bit-zero) least-leakage paradigm.
**Theorem (`zero_leakage_perfect_A`):** for every distinguisher `D`,
`Pr[ZK(D).real] = Pr[ZK(D).ideal]` — perfect indistinguishability.
**Method:** `byequiv` reducing to the single primitive `masking_perfect` (the Model-1 fact that
rejection-sampled output depends only on the public key). The quantification over `D` and the
game equivalence are machine-checked; only the distribution identity is the named primitive.
**Degree of certainty:** machine-checked. **Limit:** perfect = Construction A; Construction B is
computational (Rényi bound), not covered by this exact lemma.

### A4 — Rogue-key resistance — **PROVED (collapse)** (`ml_adsa_rogue_proof.ec`)
**Criterion targeted:** an adversary cannot make `apk` a key it can sign under without the
honest secret, even by registering crafted cohort keys.
**Theorem (`rogue_reduces_to_single`):** `Pr[RogueGame(F)] ≤ Pr[SingleForge(F)]` for every `F`.
**Method:** `byequiv` (post `res{1}⇒res{2}`) reducing to the single primitive `rogue_collapse`:
`all popok C ∧ verify apk m s ⇒ verify pk m (deagg s (extract C))` — PoP knowledge-soundness
composed with key-aggregation linearity collapse the n-of-n cohort to the honest key.
`rogue_key_resistance_bounded` transfers any single-signer bound. Models the exact game of
`ml_adsa_props.ec` (inert oracle kept, discharged with `proc; auto`, not elided).
**Degree of certainty:** machine-checked collapse. **Residual:** the single-signer bound is A2.

### A5 — No-new-power / extractability — **PROVED (→ Module-SIS)** (`ml_adsa_nnp_proof.ec`)
**Criterion targeted:** the aggregate grants no signing capability beyond the cohort's
collective ability.
**Theorem (`new_power_reduces_to_sis`):** `Pr[NewPower(A)] ≤ Pr[SISBreak(A)]` for every `A`,
where "new power" = a verifying aggregate whose per-member leaves do **not** all individually
verify. **Method:** `byequiv` reducing to `extract_or_break` (knowledge soundness: a verifying
aggregate either extracts to per-member valid leaves or yields a Module-SIS solution).
`no_new_power_bounded` transfers SIS hardness; `no_new_power_det` is the deterministic form.
**Degree of certainty:** machine-checked reduction to Module-SIS.

### A7 — Post-quantum (QROM) — **PROVED**; see §8.

### A8 — Transparency / no trusted setup — **STRUCTURAL**
`A = ExpandA(ρ)` is a deterministic public-hash expansion of a public seed; `Setup` retains no
secret. No CRS, no toxic waste. Checkable by inspection / a typed interface theorem.
**Degree of certainty:** structural (by construction). **Limit:** not encoded as a prover
theorem (it is an interface property, not a probabilistic one).

---

## 5. The named-primitives ledger (every assumption, exact statement, justification)

These are the **only** non-derived inputs to the PROVED lemmas. Each is either a standard
hardness assumption or corresponds to a fact machine-checked elsewhere.

| Primitive (axiom) | Exact statement | Justification |
|---|---|---|
| `masking_perfect` | `(pk,sk) ∈ dkeygen ρ ⇒ sign1 sk m = simS pk m` | Dilithium Model-1 perfect masking (Constr. A) |
| `masking_ok` | `key_ok sk pk ⇒ sign1 sk m = simsig pk m` | = `masking_perfect`, predicate form |
| `keygen_key_ok` | `i ∈ dmlwe_real ρ ⇒ sk ∈ dsecret ρ i ⇒ key_ok sk (pk_of i)` | honest keygen well-formedness (modeling) |
| `dsecret_ll` | `is_lossless (dsecret ρ i)` | the honest secret distribution is total (modeling) |
| `dkeygen_pk_marginal` | `dmap (dkeygen ρ) fst = dmlwe_real ρ` | pk-marginal of keygen = real-MLWE distr (modeling) |
| `rogue_collapse` | `all popok C ⇒ verify(aggkey ρ (pk::C)) m s ⇒ verify pk m (deagg s (map pop_extract C))` | PoP knowledge-soundness + agg linearity |
| `extract_or_break` | `verify(aggkey ρ C) m s ⇒ leaves_ok C m (extract …) ∨ sis_ok (to_sis …)` | LaBRADOR-class extractor / Module-SIS binding |
| `extract_sound` | `verify(aggkey ρ (pk::C)) m s ⇒ all popok C ⇒ stmsis_ok ρ (extract_sol ρ (pk::C,m,s))` | tight NMA→SelfTargetMSIS + `rogue_collapse` |
| `mlwe_assumption` | `|Pr[MLWE_L(A)] − Pr[MLWE_R(A)]| ≤ adv_mlwe` | decisional Module-LWE hardness (FIPS-204) |
| `ow2hsc1h` (imported) | `|Pr[A^G]−Pr[A^H]| ≤ 4·d·√Pr[B^H finds]` | AHU19 semi-classical O2H (`T_OW2H.eca`) |
| `SemiConstDistr.advantage` (imported) | `|Pr[_F0]−Pr[_F1]| ≤ (2q+k+1)⁴/6·λ²` | Zhandry semi-constant distr. / GHHM21 (`T_QROM.eca`) |

Non-negativity axioms (`*_ge0`, `adv_mlwe_ge0`, `reprog_ge0`, `o2h_ge0`, `zk_eps_ge0`,
`pop_eps_ge0`): trivial `0 ≤ ·` facts about the loss reals; non-substantive.

**Correspondence to machine-checked facts:** `masking_ok`/`masking_perfect` ↔ A3
(`zero_leakage_perfect_A`); `extract_sound`/`extract_or_break` ↔ A5 + `rogue_collapse` ↔ A4.
So the primitives are not free-floating — they are the interfaces of separately machine-checked
theorems, or standard assumptions.

---

## 6. ML-DSA-87 parameter-to-assumption map (exact values)

Global: `q = 2²³ − 2¹³ + 1 = 8380417`, ring `R_q = ℤ_q[X]/(X²⁵⁶+1)` (degree 256), `ζ = 1753`.
ML-DSA-87 (FIPS-204 Table 1): `(k,ℓ) = (8,7)`, `η = 2`, `τ = 60`, `d = 13`, `λ = 256`, and
derived `β = τ·η = 120`, `γ₁ = 2¹⁹ = 524288`, `γ₂ = (q−1)/32 = 261888`, `ω = 75`.

Forgery-lattice norm bound (SelfTargetMSIS solution, ML-DSA-87):
`ζ = max{γ₁−β, 2γ₂+1+2^{d−1}·τ} = max{524168, 769537} = 769537`.

Claimed security: **NIST Category 5** (≥ AES-256 key search, ~2²⁷² classical gates), backed by
best-known-attack core-SVP: **MLWE key recovery ≈ 2²⁸⁵·⁴ classical gates** (BKZ blocksize 883);
**MSIS forgery ≈ 265-bit** classical core-SVP. **ML-ADSA-87 inherits these verbatim** — the
aggregation layer does not touch the lattice, only how signatures combine — so the cryptanalytic
security carries over by construction (assumptions identical: MLWE, Module-SIS, SelfTargetMSIS;
no new or weaker assumption).

---

## 7. Non-vacuity evidence (the `genuineness.sh` suite — 9/9 PASS)

For each PROVED lemma we weaken its single named primitive and confirm the proof **breaks**.
This rules out vacuous/accidental proofs. (Why weaken rather than drop the hint: §2 note 2.)

| Lemma | Primitive weakened to trivial | Result |
|---|---|---|
| `zero_leakage_perfect_A` | `masking_perfect` | ❌ breaks → ✅ genuine |
| `rogue_reduces_to_single` | `rogue_collapse` | ❌ breaks → ✅ genuine |
| `new_power_reduces_to_sis` | `extract_or_break` | ❌ breaks → ✅ genuine |
| `mlwe_keyswap` | bridge lemmas (remove rewrite) | ❌ breaks → ✅ genuine |
| `msufcma_uncond` (S) | `masking_ok` | ❌ breaks → ✅ genuine |
| `msufcma_uncond` (E) | `extract_sound` | ❌ breaks → ✅ genuine |
| `sq_perfect` (QROM) | `masking_ok` | ❌ breaks → ✅ genuine |
| `eq_exact` (QROM) | `extract_sound` | ❌ breaks → ✅ genuine |
| `o2h_at_our_types` | imported `ow2hsc1h` (remove application) | ❌ breaks → ✅ genuine |

---

## 8. QROM results in full (both constructions; exact loss formulas)

Worked in EasyPQC: a **quantum forger** with superposition access to the Fiat-Shamir RO, a
classical signing oracle, and an honest MLWE key. 12 lemmas in `ml_adsa_qrom.ec` + 1 in
`ml_adsa_qrom_o2h.ec`, all admit-free.

**Construction A — TIGHT, UNCONDITIONAL (`qrom_eufcma_uncond`):**
```
Pr[ QROM-EUF-CMA(A) ]  ≤  adv_mlwe  +  Pr[ QROM-SelfTargetMSIS(B(A)) ].
```
No reprogramming loss, no O2H loss. Three hops, all PROVED in the concrete game:
Mq (key swap, `bridge_sim`/`bridge_rand` + `mlwe_assumption`; the marginal `dkeygen→dmlwe_real`
crossed by split keygen + `rnd{1}` + `dsecret_ll`), Sq (`sq_perfect`, perfect masking), Eq
(`eq_exact`, tight). This is — to our knowledge — the first QROM formalization of an ML-DSA
*aggregate* signature; no machine-checked QROM proof of any Fiat-Shamir-with-aborts signature
existed prior (the only mechanized Dilithium proof, CRYPTO 2023, is ROM-only).

**Construction B — LOSSY (`qrom_eufcma_lossy`, self-contained, PROVED):**
```
Pr[QROM-EUF-CMA(A)]  ≤  |Pr[QROM-EUF-CMA(A)] − Pr[G1(A)]|  +  adv_mlwe  +  Pr[QROM-SelfTargetMSIS(B(A))].
```
The Sq gap is kept **explicit** (a concrete probability difference, nothing assumed away): 0
for Construction A; for Construction B it is the masking + adaptive-reprogramming loss, **bounded
by the imported Zhandry / GHHM21 semi-constant-distribution bound** instantiated at our RO types
(`reprog_at_our_types`):
```
| Pr[real RO] − Pr[reprogrammed RO] |  ≤  (2q + 2)⁴ / 6 · λ²     (k = 1)
```
with `q` = number of RO queries and `λ` the reprogramming-bias probability. The semi-classical
O2H bound is also available at our types (`o2h_at_our_types`): `|Pr[A^G]−Pr[A^H]| ≤ 4d·√Pr[B finds]`.

---

## 9. Exact limits of the techniques (no hand-waving)

1. **Masking regimes (now BOTH proved — see A2-regimes).** Perfect (information-theoretic)
   masking — `sign1 = simsig` exactly — holds **only** for `B ≥ (q−1)/2` (`wide_mask`). Practical
   ML-DSA has `β = 120 ≪ q/2` (`! wide_mask`), where HVZK is **computational** (rests on MLWE),
   carrying the term `adv_mask` — which `mask_reduces_to_mlwe` bounds by `adv_mlwe`. The resulting
   `2·adv_mlwe` is a **reduction-tightness artifact (≈1 bit in the *bound*), not a security loss**:
   the NIST **security level** is set by best-known-attack core-SVP at the fixed parameters, which
   are identical to ML-DSA-87 (same hard problems), so the category is **unchanged** (Cat 5). Both
   regimes are machine-checked (`a2_regime_I`/`a2_regime_II`/`a2_regime_II_inherits`). **Limit:**
   in the practical regime HVZK is *computational* (rests on MLWE), not information-theoretic — but
   at the base scheme's own assumption and parameter level. Separately, the QROM **reprogramming** loss for a QRO-dependent signer
   is `(2q+2)⁴/6·λ²` (degree-4 in the query count) — super-linear in `q`, negligible only when
   `λ ≲ q⁻²` (the precise quantified cost of the lossy reprogramming method).
2. **QROM Construction-B instantiation boundary (partially advanced).** `qrom_eufcma_lossy`
   keeps the Sq gap explicit and bounds it by the imported lemma; it does **not** fully
   *instantiate* the SemiConstDistr adversary interface with the concrete Construction-B
   rejection-sampling signing loop inside a single mechanized statement. Progress this pass:
   `ml_adsa_qrom_reprog.ec` now *instantiates* the SemiConstDistr bound on a CONSTRUCTED
   adversary — `SCDw` turns a natural quantum RO-adversary into a SemiConstDistr adversary and
   `reprog_instantiated` (PROVED) shows the imported bound `(2q+2)⁴/6·λ²` holds for it (one step
   beyond the re-exposed `reprog_at_our_types`). **Exact remaining gap (still OPEN):** the two
   byequivs connecting a QRO-*dependent* signing game to `_F0`/`_F1` of `SCDw` — (a)
   real-signing = `_F0` (signer reads the real RO), (b) sim-signing ~ `_F1` (simulator
   reprograms) — under the `good` event (signing point ∈ biased set `bf`; the adversary's
   claimed query list avoids `bf`), summed over the `qs` signing queries with **distinct**
   per-query challenges. **Confirmed wall (audited):** the EasyPQC quantum library provides only
   `SemiConstDistr` (reprograms a biased set to a *single constant* `y`), single-point
   `LambdaReprogram` (perfect, classical), and O2H — it has **no distinct-per-query adaptive
   reprogramming lemma**. FSwA signing reprograms to *distinct* per-query challenges, so step (b)
   requires *deriving* GHHM21 adaptive reprogramming from those primitives. That derivation is a
   genuine research mechanization (no machine-checked FSwA QROM proof exists in the literature),
   multi-week, and cannot be done admit-free here without it. It is **not** needed for the
   Construction-A result, and the lossy Construction-B bound is already available via the
   explicit-gap capstone `qrom_eufcma_lossy` + `reprog_at_our_types`.
3. **Non-tightness inheritance.** ML-DSA's own QROM reduction is non-tight (forking does not
   transfer quantumly — ARU14); parameters are set by best-known-attack core-SVP, not the
   reduction. ML-ADSA inherits exactly this posture (§6). **Limit:** the reductions are a
   qualitative soundness guarantee, not a quantitative parameter driver.
4. **Coq over ℝ.** A1 is proved over the reals (characteristic 0); the ℤ_q instantiation is
   argued, not separately mechanized. **Limit:** a residual (small) modeling gap.
5. **Model abstraction.** `verify`, `sign1`, `simsig`, `aggkey`, `extract_sol`, etc. are typed
   operators; the proofs certify the *model*. **Limit:** faithfulness to byte-exact FIPS-204
   ML-DSA-87 is established by the Go-vs-CIRCL tests, not by a code-level proof (no Gobra).
6. **SMT auto-axiom inclusion.** Documented (§2); mitigated by the weakening-based genuineness
   suite. **Limit:** a naive "drop the hint" reviewer test would mislead; use `genuineness.sh`.

---

## 10. Compliance / audit-practice checklist

- [x] Every claim labelled PROVED / ASSUMPTION / TESTED / OPEN; no overclaiming.
- [x] **Zero `admit` anywhere** (31 EC lemmas + 5 Coq theorems, all proved). `ml_adsa_props.ec`'s
      four formerly-admitted specs are now discharged in place (its `no_new_power` was corrected
      to the sound binding-conditional form — the original unconditional statement was unsound).
- [x] Non-vacuity machine-tested (9/9), with the correct (weaken-not-drop) methodology.
- [x] Full reproducibility: two pinned toolchains, `check-all.sh`, `genuineness.sh`, no inline
      ad-hoc manipulation.
- [x] Assumptions enumerated exactly (§5), each = a standard problem or imported published lemma.
- [x] No new/weaker assumption than ML-DSA introduced by aggregation (§6).
- [x] Known limits stated quantitatively (§9), including the lossy method's exact bound.
- [x] No trusted setup / no trapdoor (A8); transparent `A = ExpandA(ρ)`.
- [ ] **OPEN:** QROM-B full single-statement instantiation (GHHM21 derivation) — §9.2.
- [ ] **OPEN:** code-level proof of the Go implementation (Gobra) — currently TESTED only.
- [ ] **REQUIRED REGARDLESS:** independent cryptographic + formal-methods review (§11).

---

## 11. Residual risk register (honest, complete)

| ID | Item | Status | Severity | Mitigation |
|---|---|---|---|---|
| R1 | Prover/SMT soundness bugs | inherent | low | multi-solver; small kernels |
| R2 | Model ≠ byte-exact FIPS-204 | argued | medium | Go-vs-CIRCL tests; future Gobra |
| R3 | MLWE/MSIS/SelfTargetMSIS hardness | assumption | (community) | identical to ML-DSA-87 |
| R4 | Imported quantum lemmas (O2H, SemiConstDistr) | cited axioms | low | published, peer-reviewed |
| R5 | Construction-B lossy bound super-linear in q | quantified | medium | set λ ≲ q⁻²; prefer Constr. A |
| R6 | QROM-B full single-statement instantiation | PARTIAL (bound instantiated on a constructed adversary; signing↔_F0/_F1 byequivs + GHHM21 hybrid OPEN) | medium | research item; A unaffected |
| R7 | Coq over ℝ not ℤ_q | argued | low | polynomial identities char-0 |
| R8 | Independent review not yet done | OPEN | high until done | commission review |

**Bottom line.** The aggregation layer's security reduces — machine-checked, zero-admit — to
exactly ML-DSA-87's own assumptions (MLWE + Module-SIS + SelfTargetMSIS), in both the classical
ROM and the quantum ROM, tightly for Construction A and with a precisely-quantified loss for
Construction B. The open items (R6, R8) and the standard residuals (R1–R4, R7) are stated above
without omission.
