# ML-ADSA

**A trapdoor-free, post-quantum, BLS-like aggregate signature over ML-DSA-87 (FIPS-204) — machine-checked.**

ML-ADSA (Module-Lattice Aggregate Digital Signature Algorithm) lets a committee of signers, each holding
an ordinary **ML-DSA-87** key, jointly produce **one constant-size signature** that the **unmodified
FIPS-204 verifier accepts** against an aggregate public key. No trusted setup, no trapdoors, no
SNARK/STARK/ZK proof system, no TEE, and no trusted or intermediary aggregator — every value the combiner
uses is public, so any party reconstructs the identical aggregate.

---

## The idea in one line

BLS aggregates by the **homomorphic product** of signatures in a pairing group, `σ* = Π σᵢ`.
ML-ADSA is the **homomorphic sum** of Fiat–Shamir responses in the module `R_q = Z_q[X]/(X²⁵⁶+1)`:

$$ z^* = \sum_i z_i,\qquad t^* = \sum_i t_i,\qquad W^* = \sum_i w_i. $$

Same homomorphic-aggregation algebra — instantiated in a **module lattice** instead of a pairing group. It
inherits BLS's **order- and grouping-independence** and (for deterministic signers) **byte-identical**
aggregates regardless of the sub-aggregation schedule. The one structural difference: the Fiat–Shamir
challenge binds the *entire* participant commitment, so finished aggregates are *homomorphic but not freely
mergeable* — and that binding is exactly what defeats the ROS attack, giving concurrent security with **no
ROS/AGM/OMDL assumption**.

The aggregate public key is itself a bona fide ML-DSA key (a sum of Module-LWE samples is a Module-LWE
sample), so security reduces — in **both the ROM and the QROM** — to the *same* assumptions as ML-DSA
(Module-LWE, SelfTargetMSIS, Module-SIS) at **NIST Category 5**.

---

## What's proven (machine-checked)

| | |
|---|---|
| **Prover artifacts** | **35** — 25 classical EasyCrypt + 5 quantum (EasyPQC) + 5 Coq/Rocq, all green |
| **Machine-checked lemmas** | **234** (202 EasyCrypt + 32 Coq) + **6** Gobra code-level theorems |
| **Genuineness** | **49/49** — each proof's named primitive is weakened and the proof confirmed to break |
| **Implementation** | reference impl byte-anchored to **CIRCL** and **theQRL/go-qrllib** FIPS-204 verifiers; KATs + ACVP-shaped vectors |

Highlights of the formal development:

- **EUF-CMA / SUF-CMA** tight reductions to MLWE + SelfTargetMSIS(+Module-SIS), ROM.
- **QROM** capstone (Construction A tight/unconditional); the lossy-variant **distinct-per-query GHHM21
  adaptive-reprogramming** bound *derived in-prover* (not imported) from a proven per-round perfect
  resampling + the elementary distinct-query bound.
- **Many-time** security via content-key refresh (advantage independent of the number of signed contents).
- **Concurrent / ROS-resistance** with no ROS/AGM.
- **Equivalence-class hardness** (ROM + QROM): producing *any* valid signature for a fixed `(pk*, m)` is as
  hard as a single ML-DSA forgery.
- **Lattice arithmetic from first principles:** perfect-HVZK masking change-of-variables, FIPS-204
  rounding/hint decomposition, and the **NTT as a complete ring isomorphism** — the convolution theorem
  (`NTT(p·q) = NTT(p) ⊙ NTT(q)`) *and* the CRT inversion (`INTT∘NTT = id`).
- **The whole NTT algorithm, not just the math:** the multi-level Cooley–Tukey transform = the DFT
  (`ct_correct`), the **flat-array** butterfly layout (`polyL_cat`, `polyL_bfly`), the factor-tree transform
  computes the per-root evaluation vector (`ntt_tree_correct`), **FIPS-204's own bit-reversed `ζ=1753`
  schedule satisfies the well-formedness predicate** (`negtree_wf`), and the **iterative, level-by-level loop
  the code actually uses equals the recursion** — BFS = DFS (`forest_step_inv`, `forest_loop_correct`), with
  **termination proved** (`tdepth_negtree` + `forest_iter_leaves`, so the end-to-end `fips_ntt_loop` is
  unconditional); the literal `a[j]`/`a[j+len]` index arithmetic is machine-checked too (`jloop_eq`, tied to a
  `forest_step` by `jloop_forest`); the int32 Montgomery reduction is source-proved too (`q·qinv ≡ 1 mod 2³²`).
  The only residual is the `while`-loop control-flow scaffolding (bounds + the `k`-counter over `zetas[k]`) —
  the most mechanical model↔code transcription, byte-validated against CIRCL + go-qrllib.

See the **[Verification Dossier](reference/31-ml-adsa-verification-dossier.md)** for the full
specification ↔ code ↔ proof ↔ test traceability matrix, and an honest statement of every assumption and
boundary.

---

## Start here

- **[Research paper](reference/paper.md)** — the full write-up (the BLS additive-dual framing, security,
  decentralized combine, performance).
- **[Plain-language whitepaper](reference/19-ml-adsa-F-plain-language-whitepaper.md)** — the same ideas, no
  cryptography background assumed.
- **[Formal specification](reference/30-ml-adsa-formal-specification.md)** — FIPS-204-structured
  authoritative spec.
- **[Verification dossier](reference/31-ml-adsa-verification-dossier.md)** — what is proven, where, and what
  it does and does not establish.
- **[Publication & NIST roadmap](reference/32-publication-and-nist-submission-roadmap.md)** — the path to
  standardization (publish first; independent cryptanalysis is the decisive gate).
- **[Benchmarks](reference/33-ml-adsa-benchmarks.md)** — measured sizes and timings.

### For reviewers / cryptanalysts

- **[Cryptanalysis review packet](reference/36-cryptanalysis-review-packet.md)** — what is claimed, what is
  proven and how, what is **not** proven, the priority attack surfaces, and what would falsify the scheme.
- **[Norm-budget & secure-cohort study](reference/37-norm-budget-study.md)** — the honest secure-`N`:
  provable (Hoeffding) and measured (Monte-Carlo) bounds on the cohort size at which the summed response
  stays inside the unmodified FIPS-204 verifier's norm ceiling.
- **[Cross-consistency audit](reference/35-cross-consistency-audit.md)** — the single reproducible source of
  truth for all counts (`formal/count-artifacts.sh`) and a repo-wide text↔code↔proof reconciliation.

---

!!! warning "Status"
    This is new cryptography. The machine-checked proofs verify the reductions to ML-DSA's own assumptions
    as modeled; they do **not** replace independent human cryptanalysis, which is a prerequisite for any
    real-world deployment or standardization. This site is a **defensive publication** — feedback and
    cryptanalysis are explicitly invited.
