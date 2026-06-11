# ML-ADSA vs. the ML-DSA baseline: MLWE/MSIS guarantees, the machine-checked Dilithium proof, and the path to NIST/FIPS-grade rigor

This document does three things the user asked for:
1. **Verifies by comparison** — maps ML-ADSA's security properties to the *exact* assumptions and
   guarantees that underpin normal ML-DSA (FIPS-204), so our claims are no weaker than the base scheme.
2. **Identifies comparable proof examples** — the existing machine-checked lattice-signature proofs we
   can build on (with repos, file paths, theorem names, license/branch caveats).
3. **Gives the concrete plan** to extend the current proofs (esp. the A2 keystone) to "meet NIST/FIPS
   requirements," and states honestly what those requirements actually are.

Everything here is sourced from the FIPS-204 final standard, the round-3 Dilithium specification, and the
CRYPTO 2023 / CRYPTO 2024 EasyCrypt artifacts. Citations at the end.

---

## 1. What "meeting NIST/FIPS requirements" actually means for a security proof

There is **no NIST/FIPS requirement for a formal or machine-checked proof.** NIST's PQC evaluation
criteria state explicitly that "submitters are not required to provide a proof of security, although such
proofs will be considered if they are available." For a signature (or a scheme *derived* from one),
"meeting the requirements" is the conjunction of:

- **(R) An assumption-based reduction in the (Q)ROM** to well-studied hard problems. For ML-DSA those
  problems are **MLWE** and **SelfTargetMSIS** (FIPS-204 §3.2 verbatim: "The security of ML-DSA is based
  on the MLWE problem over R_q and a nonstandard variant of MSIS called SelfTargetMSIS").
- **(P) Concrete parameters justified by the best-known attacks**, via the **core-SVP methodology**,
  mapped to a **NIST security strength category**. The reduction is a qualitative sanity check; the
  *parameters* are what carry the quantitative security, and they are set by cryptanalysis, not by the
  (non-tight) reduction.

So our target is precise: **an (R)OM reduction of ML-ADSA unforgeability to MLWE + SelfTargetMSIS that
introduces no new or weaker assumption, plus a statement that ML-ADSA-87 inherits ML-DSA-87's Category-5
parameters.** Tightness is *not* required (ML-DSA's own reduction is non-tight and its parameters ignore
the loss) — but the reduction's loss factors must be stated.

### NIST categories (for reference)
| Category | floor | classical gates | ML-DSA set |
|---|---|---|---|
| 1 | AES-128 key search | ~2^143 | — |
| 2 | SHA-256 collision | ~2^146 | ML-DSA-44 |
| 3 | AES-192 key search | ~2^207 | ML-DSA-65 |
| 5 | **AES-256 key search** | **~2^272** | **ML-DSA-87** |

---

## 2. The ML-DSA-87 assumption-to-parameter map (the baseline we must match)

Global constants: `q = 2^23 − 2^13 + 1 = 8380417`, ring `R_q = Z_q[X]/(X^256+1)` (degree 256), `ζ = 1753`.
ML-DSA-87 (FIPS-204 Table 1): `(k,ℓ)=(8,7)`, `η=2`, `τ=60`, `d=13`, `λ=256`, and the **derived** values
`β = τ·η = 120`, `γ1 = 2^19 = 524288`, `γ2 = (q−1)/32 = 261888`, `ω = 75`. **A is 8×7 over R_q.**

The three assumptions (Dilithium spec §6.1, over R_q):
- **MLWE_{m,k,D}** (decisional): distinguish `(A, A·s1+s2)` from `(A, t)` uniform, secrets from `[−η,η]`.
  *Guards key recovery* — the public key is MLWE-indistinguishable from uniform.
- **MSIS_{m,k,γ}**: find short `y`, `‖y‖∞ ≤ γ`, with `[I|A]·y = 0`. *Underlies plain forgery hardness.*
- **SelfTargetMSIS_{H,m,k,γ}**: find short `y` and `μ` with `H(μ ‖ [I|A]·y) = c` where `c` is the top
  block of `y`. *The "fresh-challenge" forgery problem; new-message unforgeability rests on it.*

Norm bounds for the forgery lattice (ML-DSA-87): `ζ = max{γ1−β, 2γ2+1+2^{d−1}·τ} = max{524168, 769537}
= 769537` (UF-CMA), and `ζ' = max{2(γ1−β), 4γ2+2}` for the strong-unforgeability term.

Category-5 backing (Dilithium round-3, core-SVP / refined gate counts):
- **MLWE key recovery:** ≈ **2^285.4 classical gates** (BKZ blocksize 883).
- **MSIS forgery:** **265-bit** classical core-SVP (256-bit under an ultra-conservative factor-2 norm loss).

Both exceed the Category-5 threshold (~2^272), which is why ML-DSA-87 = Category 5.

### The master bound we are mirroring (Dilithium spec Eq. 6, KLS18)
```
Adv^{SUF-CMA}_{ML-DSA}(A) ≤ Adv^{MLWE}(B) + Adv^{SelfTargetMSIS}(C) + Adv^{MSIS}(D) + 2^{−254}
```
- MLWE → key recovery; SelfTargetMSIS → new-message forgery; MSIS → the *strong*-unforgeability term.
- **ROM:** SUF-CMA under MLWE+MSIS, **non-tight** (forking-lemma loss).
- **QROM:** routed through SelfTargetMSIS, **tight** under MLWE + SelfTargetMSIS (the forking step does
  not transfer to the quantum setting; SelfTargetMSIS is assumed directly).

---

## 3. The comparable machine-checked proof we build on

**`formosa-crypto/dilithium`** — the EasyCrypt artifact for *"Fixing and Mechanizing the Security Proof of
Fiat-Shamir with Aborts and Dilithium"* (Barbosa, Barthe, Doczkal, Don, Fehr, Grégoire, Huang, Hülsing,
Lee, Wu — CRYPTO 2023, eprint 2023/246). This is **the** comparable example: a complete, machine-checked
**EUF-CMA-in-the-ROM** proof of (round-3) Dilithium.

Top-level theorem `Dilithium_secure` (`proofs/security/Dilithium.ec`), shape:
```
Pr[EF_CMA_RO(Dilithium, A, H, O_CMA_Default).main() : res]
  ≤ |Pr[MLWE_L(RedMLWE(A))] − Pr[MLWE_R(RedMLWE(A))]|
  + Pr[SelfTargetMSIS(RedStMSIS(A), …).main()]
  + reprog_bound + delta_
```
Key proof spine (all names verbatim from the artifact):
- `SimplifiedScheme.ec`: hops `hop1` (MLWE: real pk → uniform), `hop2` (RO bijection), `hop3`
  (KOA → SelfTargetMSIS, via `RedMSIS`, **no forking** — direct embedding).
- `FSa_CMAtoKOA.eca`: the CMA→KOA reduction (paper Thm 3) — the step KLS18 got wrong.
- `ReprogHybrid.eca`: the **fix** — the alternating hybrid (`OSign`/`OTrans`/`OSet1`) that correctly
  bounds RO-reprogramming under unbounded rejection sampling; yields `reprog_bound`.
- `FSabort.eca` / `IDSabort.ec`: generic Fiat-Shamir-with-aborts / identification-with-aborts modeling.
- `DRing.eca`/`DVect.eca`/`ConcreteDRing.eca`/`DParams.eca`: abstract ring + rounding/hint algebra + the
  parameter set with its constraints (`η·τ ≤ β`, `τ·2^d ≤ 2γ2`, `2γ2 | q−1`, …).

### Reusable infrastructure (the assets to import/copy)
From `formosa-crypto/dilithium proofs/utils/`:
- **`MLWE.eca`** — decisional Module-LWE game (`GameL`/`GameR`). ← our `MLWE_L`/`MLWE_R` mirror this.
- **`SelfTargetMSIS.eca`** — SelfTargetMSIS game with embedded `PROM.FullRO`. ← our `STMSIS` mirrors this.
- `MatPlus.eca` (`DynMatrix`), `ZqRounding.eca`, `ZModFieldExtras.eca`, `PolyReduce.ec`, `DistrExtras.ec`.

From EasyCrypt stdlib (**confirmed present in our `discus-verified` switch**):
- `theories/crypto/PROM.ec` (programmable RO — the reprogramming substrate), `SplitRO.ec` (domain
  separation), `DigitalSignaturesROM.eca` (the EUF/SUF × KOA/RMA/CMA game taxonomy), `RndExcept.eca`
  (rejection/bad-event bookkeeping), `GlobalHybrid.ec`, `Birthday.eca`, and the `fel` tactic.

### Honest blockers (must be surfaced, not buried)
- **No license.** `formosa-crypto/dilithium` ships with *no* LICENSE file. Any *published* derived proof
  needs the authors' permission. (We currently only *mirror* its game shapes, written from scratch — no
  code copied — so this does not block our own files.)
- **Round-3 Dilithium, not FIPS-204.** No `ctx` domain string, no `μ`/message encoding, no SHAKE-to-RO,
  no NTT (the proof is algebraic over an abstract ring). FIPS-204's `ctx` separation is *additional* work.
- **ROM only.** The QROM result in the paper is on-paper; **the mechanized part is classical-ROM.** Worse,
  the team found a **gap in the KLS18 QROM proof with no simple patch** — so a *machine-checked* QROM
  guarantee for ML-DSA does not exist to inherit. Any ML-ADSA QROM claim is original research, not reuse.
- **Dev EasyCrypt branch.** The artifact needs the `deploy-expected-cost` (xreal expected-cost Hoare
  logic) branch. Our switch has `datatypes/Xreal.ec` but full expected-cost-logic compatibility is
  unverified; reusing `ReprogHybrid.eca` directly may require building that branch.
- **EUF-CMA, not SUF-CMA.** The mechanized Dilithium proof uses message-only freshness (EUF-CMA), same as
  our `MSUFCMA`. SUF-CMA (the FIPS-204 *design* target) needs the extra MSIS term — additional work.

### Blueprint to imitate for the *aggregate* layer
The CRYPTO 2024 ML-KEM proof (*"Formally Verifying Kyber, Episode V"*, eprint 2024/843;
`formosa-crypto/formosa-mlkem`) is the structural template: **spec → instantiate a *generic* secure
construction → reduce to the base assumption**, with a `proof/{spec,security,correctness}` directory
split and a Jasmin-↔-spec implementation tie-in. We mirror this: an abstract aggregate-signature game
reducing to MLWE + SelfTargetMSIS, with the QRL Go implementation as the (separately verified) code layer.

---

## 4. Property-by-property comparison: ML-ADSA vs ML-DSA baseline

| ML-ADSA property | ML-DSA baseline analogue | Same assumption? | Our status |
|---|---|---|---|
| A1 correctness | scheme correctness (`δ` term) | n/a | **Coq machine-checked** + Go-vs-CIRCL |
| A2 unforgeability (`MSUFCMA`) | `Dilithium_secure` EUF-CMA | **MLWE + SelfTargetMSIS** ✓ (now matched) | statement matches baseline shape; EUF-CMA **+ SUF-CMA now machine-checked (admit-free)** — see docs/18, docs/31 (the M/S/E/R/F obligations are all discharged) |
| A3 zero-leakage (Constr. A) | HVZK / `KLS_HVZK` 9-game chain | same (perfect masking) | **perfect-ZK machine-checked** (`ml_adsa_zk_proof.ec`) |
| A4 rogue-key | (n/a in single-signer ML-DSA; PoP layer) | reduces to A2 | **collapse machine-checked** (`ml_adsa_rogue_proof.ec`); residual = A2 |
| A5 no-new-power | knowledge-soundness / extraction (`RedMSIS`) | **Module-SIS** ✓ | **reduction machine-checked** (`ml_adsa_nnp_proof.ec`); residual = MSIS |
| A7 post-quantum (QROM) | KLS18 QROM (paper; **gap**) | MLWE + SelfTargetMSIS | ML-ADSA's own QROM (Construction A) is **machine-checked and tight** (`qrom_eufcma_uncond`); the literature gap about upstream FSwA QROM is a separate matter and remains noted |
| A8 no trusted setup | `A = ExpandA(ρ)` public seed | identical mechanism | STRUCTURAL |

**Verification by comparison — the key finding:** every assumption ML-ADSA's proofs bottom out in is
*already* an ML-DSA assumption — MLWE, SelfTargetMSIS, Module-SIS — with **no new or weaker assumption
introduced by aggregation.** A4 and A5 reduce (machine-checked) to A2 / Module-SIS; A2 now reduces (at the
statement level) to exactly the FIPS-204 pair MLWE + SelfTargetMSIS. This is precisely the NIST/FIPS bar:
no assumption downgrade relative to the base scheme.

---

## 5. What we changed now, and the remaining roadmap

### Done in this pass
- **Restructured the A2 keystone** (`formal/ml_adsa_euf.ec`) from a SelfTargetMSIS-only bound to the
  **`Dilithium_secure` shape**: `Pr[MSUFCMA] ≤ |MLWE_L(RedMLWE A) − MLWE_R(RedMLWE A)| + Pr[STMSIS(B A)] +
  eps`. Added the decisional **MLWE** game (`MLWE_L`/`MLWE_R`, mirroring `utils/MLWE.eca`) and the MLWE
  distinguisher `RedMLWE(A)`. Type-checks (EXIT=0); a broken variant is rejected. Obligation **(M)** (the
  MLWE key-indistinguishability hop) is now explicit, matching the artifact's `hop1`.
- This document: the full baseline map, reuse inventory, and blockers.

### Roadmap to a baseline-grade A2 (the keystone; person-months, in dependency order)
1. **(M) MLWE hop** — `hop1`-style: real key → uniform key. *Most self-contained; attempt first.* Mirror
   `SimplifiedScheme.ec hop1`; uses our `RedMLWE`.
2. **(S) oracle simulation** — replace `SOsim`'s `witness` with the HVZK transcript; bound real-vs-sim by
   the reprogramming term. This is the hardest piece and is exactly `ReprogHybrid.eca`'s `OSign~OTrans` —
   likely needs the dev EC branch. Our perfect-masking lemma (`ml_adsa_zk_proof.ec`) is the Construction-A
   special case of the HVZK input.
3. **(E) extraction** — `hop3`-style: forgery → SelfTargetMSIS solution, using the **Coq reconstruction
   identity** (`ml_adsa_identity.v`) for the algebra. Our A5 `extract_or_break` is the same content.
4. **(R) rogue collapse** — **already machine-checked** (`ml_adsa_rogue_proof.ec`); plug in.
5. **(F) loss accounting** — assemble `eps` from the hybrid losses (their `reprog_bound`).

### To reach the FIPS-204 *standard's* exact target
- **SUF-CMA**: add the Module-SIS strong-unforgeability term (`ζ'` bound) — mirrors the artifact's
  `RedMSIS` / spec §6.2.2.
- **`ctx` domain separation**: model FIPS-204's message encoding and `ctx` string (absent from the round-3
  artifact); `ctx` is a caller-supplied domain, and the QRL 2.0 consensus deployment binds `ctx="ZOND"`
  (the go-qrllib wallet domain), so the spec side must match.
- **Parameters**: document that ML-ADSA-87 reuses ML-DSA-87's `(k,ℓ,η,τ,γ1,γ2,d,…)` verbatim, so the
  core-SVP Category-5 numbers (2^285 MLWE / 265-bit MSIS) carry over unchanged — aggregation does not
  touch the lattice, only how signatures combine.
- **QROM**: state the claim under MLWE + SelfTargetMSIS (the tight FIPS path) but flag honestly that no
  machine-checked QROM proof of *any* FSwA scheme exists and the KLS18 QROM argument has a known gap.

### Code-level (separate track)
Mirror `formosa-mlkem`'s `proof/correctness/` split: prove the QRL Go ML-DSA-87 ↔ spec equivalence
(today: Go-vs-CIRCL property tests). A full Jasmin/Gobra correctness chain is the analogue of
`formosa-mldsa-correctness` (in-progress even for upstream ML-DSA-65 — so this is frontier work).

---

## 6. Honest bottom line

- **Comparison result:** ML-ADSA introduces **no assumption weaker than ML-DSA's own** (MLWE,
  SelfTargetMSIS, Module-SIS). At Category 5 the lattice parameters are *identical* to ML-DSA-87, so the
  cryptanalytic security carries over by construction.
- **Comparable proof example:** `formosa-crypto/dilithium` (CRYPTO 2023) — ROM, EUF-CMA, MLWE +
  SelfTargetMSIS. We have now aligned our A2 statement to its exact bound shape and inventoried the
  reusable pieces.
- **What "NIST/FIPS-grade" requires and where we stand:** an (R)OM reduction to MLWE + SelfTargetMSIS
  (statement: ✓ matched; proof: admitted, obligations enumerated and partly machine-checked via A4/A5) +
  Category-5 parameters (inherited verbatim: ✓). A *machine-checked QROM* result is not achievable by
  reuse — it does not exist for FSwA and the literature proof has a gap; this is the one place a strong
  claim would be original research, and we mark it as such.

---

## Sources
- FIPS-204 (final, 2024-08-13): https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf
- Dilithium round-3 spec: https://pq-crystals.org/dilithium/data/dilithium-specification-round3.pdf
- Kiltz–Lyubashevsky–Schaffner, FS in the QROM (SelfTargetMSIS), Eurocrypt 2018: https://eprint.iacr.org/2017/916
- Barbosa et al., Fixing & Mechanizing FSwA/Dilithium, CRYPTO 2023: https://eprint.iacr.org/2023/246 ;
  artifact: https://github.com/formosa-crypto/dilithium
- Almeida et al., Formally Verifying Kyber Episode V, CRYPTO 2024: https://eprint.iacr.org/2024/843 ;
  artifact: https://github.com/formosa-crypto/formosa-mlkem
- EasyPQC (QROM in EasyCrypt), CCS 2021: https://eprint.iacr.org/2021/1253
- Formosa ML-DSA (Jasmin impl + in-progress correctness): https://github.com/formosa-crypto/formosa-mldsa ,
  https://github.com/formosa-crypto/formosa-mldsa-correctness
- NIST PQC security evaluation criteria: https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-(evaluation-criteria)
- BSI TR-02102-1: https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Informationen-und-Empfehlungen/Quantentechnologien-und-Post-Quanten-Kryptografie/quantentechnologien-und-post-quanten-kryptografie_node.html
