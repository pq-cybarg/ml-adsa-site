# LMSA — Research Synthesis (deep-research workflow, 101 agents, 19 primary sources)

> **Historical / iteration note (2026-06-11).** This document is part of the research/design trail and reflects an **earlier iteration**; some counts, status labels, and construction details predate the current Construction F. The authoritative current specification is **`docs/30`**, the verification status and tallies are in **`docs/31`** and reproducible via **`formal/count-artifacts.sh`** (29 artifacts, 134 lemmas, 33/33 genuineness, 6 Gobra), and the cross-document reconciliation is **`docs/35`**. Numbers below are preserved as the historical record.

Cross-check of the from-scratch derivation in `01-forward-backward-analysis.md` against
the fact-checked literature sweep. Verified claims are marked with their adversarial
vote (e.g. 3-0 = all three verifiers confirmed).

## A. The wall is confirmed independently (not just "literature says")
- **True BLS-style algebraic aggregation of ML-DSA is ruled out** by Fiat–Shamir-with-
  Aborts: the norm-gated rejection loop (`‖z‖∞ < γ1−β`) destroys the linear-homomorphic
  closure BLS relies on. (FIPS 204; verified 3-0.) This is exactly Track B / Wall 2 of
  doc 01, reached here from the scheme structure rather than the verifier algebra.
- ML-DSA security = MLWE + MSIS + **SelfTargetMSIS** over `R_q`; QROM reduction from
  MLWE is **non-tight** (`Ω(ε²/Q⁴)`, EUROCRYPT 2024, arXiv 2312.16619; 3-0). Any
  aggregate's security argument must preserve these.
- ML-DSA-87 = NIST L5: **2^285 classical gates / 229-bit quantum Core-SVP**; pk 2592 B,
  sig 4627 B (the per-sig baseline to beat). (3-0.)

## B. Correction to my last turn (own it)
I claimed a shared global `A` turns Path A into "clean half-aggregation" that folds the
`z`-bulk into one short vector. **That was over-optimistic.** The literature shows native
FSwA half-aggregation for the Dilithium family is **non-compact**:
- Boudgoust–Takahashi (ESORICS 2023, eprint 2023/159): first FSwA sequential half-
  aggregate `σ = (u, z₁,…,z_N)` — it aggregates only the `u`-parts and **keeps every
  `z_i`**; compression ≈ **1%** over concatenation (rate → 0.9927 at N=10⁶). (3-0.)
- Boudgoust–Roux-Langlois (eprint 2021/263), GLP/FSwA, public aggregation: aggregates
  come out **larger than concatenation** — explicitly pedagogical. (neg. result 3-0.)

**Why** (this is the mechanism I under-weighted): each signature's Fiat–Shamir binding
`c̃_i = H(μ_i ‖ w1_i')` is per-signer and nonlinear, and `w1_i' = UseHint(h_i, A z_i −
c_i t1_i 2^d)` needs the **individual** `A z_i`. So the verifier must keep each `z_i` to
re-check each hash binding; a folded `Σ e_i z_i` cannot be unfolded for those checks.
`z` is ≈5/8 of a Dilithium signature, so not compressing `z` ⇒ ≈no compression. A shared
`A` does **not** rescue this. → **Folding/half-aggregation is a dead end for compact
distinct-message ML-DSA aggregation.** Shared `A` still helps elsewhere (below).

## C. The achievable compact path: SNARK-of-knowledge (LaBRADOR/Greyhound)
State of the art realizes aggregation as a succinct **argument of knowledge** of N
witnesses each satisfying `Ver(pk_i, m_i, σ_i)=1` — not an algebraically combined sig.
- **LaBRADOR** (CRYPTO 2023, eprint 2022/1341): proofs for R1CS / dot-product &
  quadratic constraints **natively over `R_q`**, from Module-SIS; **58 KB for 2²⁰
  constraints**, ~10× smaller than hash-based PCPs. NI knowledge-soundness proven CRYPTO
  2024 via "predicate special soundness." (3-0.)
- **Greyhound** (CRYPTO 2024, eprint 2024/1293): first concretely-efficient lattice
  polynomial commitment (Module-SIS), `O(√N)` verifier; composed with LaBRADOR →
  polylog proof, sublinear verifier. (3-0.)
- **GPU**: ICICLE-LaBRADOR exists (ingonyama-zk/icicle-labrador).

**Two of my earlier instincts are vindicated by this:**
1. *Lattice-native is the right call.* LaBRADOR's constraint system **is** over `R_q` —
   the exact ring ML-DSA verification lives in. The "no field-embedding / no NTT
   impedance-mismatch" property from the original Module-STARK template is real, but the
   right engine is **LaBRADOR (Module-SIS), not a hash+FRI STARK** — same lattice-native
   benefit, ~3–4× smaller proofs, and recursive (residual is itself a Module-SIS object
   that re-aggregates — the "residual aggregates further" property, rigorously).
2. *Shared global `A` helps* — but as a **prover-cost optimization**, not a compressor:
   a global `ρ` makes `A` a circuit constant, removing per-signer in-circuit `ExpandA`
   (SHAKE-128) expansions. Real savings; just not the folding win I claimed.

## D. The genuinely novel frontier (this project)
**Every demonstrated, benchmarked lattice SNARK-aggregate targets FALCON** (GPV hash-
then-sign), **not ML-DSA/Dilithium**:
- Aardal et al. (CRYPTO 2024) + LaZer (CCS 2024, eprint 2024/1846): Falcon-512 + LaBRADOR
  → **73 KB @ 1024 sigs (0.6 s prover)**, **72 KB @ 100,000 sigs (65 s, 25.5 GB)**;
  93/120/165 KB at N=500/1000/2000. Beats STARK-Winternitz (165 KB) and the Chipmunk
  lattice multisig (118 KB @ 1024). (3-0.)

**No primary source benchmarks an ML-DSA-87 aggregate.** Falcon arithmetizes cheaply
(one Gaussian-norm check). ML-DSA's FSwA verifier is **heavier to arithmetize**:
`UseHint` (w0/w1 decomposition), the `‖z‖∞ < γ1−β` range check, the hint-weight check,
`SampleInBall`, and the `SHAKE-256` challenge hash. So **Falcon's KB/seconds do NOT
transfer** — the core open work is the ML-DSA-87 verification *circuit* over `R_q`.

## E. Formal-verification gap (matches the project's stated goal)
No machine-checked (Coq/Lean/EasyCrypt) proof exists of: LaBRADOR knowledge-soundness,
the predicate-special-soundness framework, or an end-to-end ML-DSA aggregation circuit.
The original brief ("provably solves … by formal verification") therefore aims at
genuinely open territory — a real contribution, not a re-implementation.

## F. Mapping to QRL 2.0 (updated, with numbers)
- **Validators signing the same block (consensus)** → **shared-`A` lattice
  multisignature** (Path B). Reaches an ML-DSA-*shaped* verifier under an aggregate key;
  exact FIPS-204 only for cohorts inside native `γ1` (Wall 2), else adjusted `γ1`.
  Data point: Chipmunk-class = 118 KB @ 1024 (synchronized).
- **Arbitrary distinct-key/message transactions** → **LaBRADOR/Greyhound SNARK of N
  ML-DSA-87 sigs** (Path A, corrected). Verified by a LaBRADOR verifier, *not* ML-DSA.
  Novel for ML-DSA; lattice-native; recursive. Target sizes: expect *larger* than
  Falcon's 73–165 KB pending the FSwA-circuit arithmetization, but still
  near-constant in N and orders below concatenation.
- Folding/half-aggregation: **dropped** (non-compact, per §B).

## G. Open questions to drive (from the sweep, prioritized)
1. Concrete proof size / prover time / verifier cost of LaBRADOR+Greyhound over the
   **ML-DSA-87 verification relation** (arithmetizing UseHint, norm, SampleInBall,
   SHAKE), vs the Falcon-512 numbers.
2. Do the Module-SIS params for a sound aggregate over ML-DSA-87 statements **preserve
   L5** (LaBRADOR uses its own MSIS instances)?
3. GPU (ICICLE) + recursion ceiling for 10⁴–10⁶ ML-DSA-87 sigs.
4. A machine-checked soundness path (EasyCrypt/Lean) for the chosen stack.

Sources (primary): FIPS 204; Dilithium round-3 spec; arXiv 2312.16619; eprint 2022/1341
(LaBRADOR), 2024/1293 (Greyhound), 2024/1846 (LaZer), 2024/311 = hal-04700114 (Falcon+
LaBRADOR), 2023/159 (FSwA SAS), 2021/263 (GLP half-agg); ingonyama-zk/icicle-labrador.
