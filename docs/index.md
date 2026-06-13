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
| **Prover artifacts** | **31** — 21 classical EasyCrypt + 5 quantum (EasyPQC) + 5 Coq/Rocq, all green |
| **Machine-checked lemmas** | **174** (142 EasyCrypt + 32 Coq) + **6** Gobra code-level theorems |
| **Genuineness** | **39/39** — each proof's named primitive is weakened and the proof confirmed to break |
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

---

!!! warning "Status"
    This is new cryptography. The machine-checked proofs verify the reductions to ML-DSA's own assumptions
    as modeled; they do **not** replace independent human cryptanalysis, which is a prerequisite for any
    real-world deployment or standardization. This site is a **defensive publication** — feedback and
    cryptanalysis are explicitly invited.
