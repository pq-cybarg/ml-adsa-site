# ML-ADSA — Publication & NIST-Submission Roadmap

Companion to the formal specification (`docs/30`) and the end-to-end verification dossier (`docs/31`).
This document answers "do I publish first?" (yes), maps ML-ADSA against the *requirements pattern* of
NIST's relevant programs, and gives a realistic phased path with an honest separation of **done** vs
**needed**.

> **Time-sensitive facts are tagged `[VERIFY]`.** They reflect standing knowledge through 2025 and the
> canonical NIST/IACR landing pages; confirm current round/draft status before acting, because NIST
> program states change. There is, as of this writing, **no standing "ML-DSA signature aggregation
> contest"**; the realistic homes are the additional-signatures on-ramp and the Multi-Party Threshold
> Cryptography project, plus ordinary peer-reviewed publication. Do not plan around a contest that does
> not exist.

---

## 1. Executive answer

1. **Publish first — yes, in this order.** (a) **IACR ePrint** immediately (no review, public timestamp =
   priority + defensive publication); optionally **arXiv**. (b) Submit to a **peer-reviewed venue**
   (CRYPTO / EUROCRYPT / ASIACRYPT / PKC / CHES / Real World Crypto) for credibility and scrutiny.
   (c) Actively solicit **independent cryptanalysis** — the single decisive gate.
2. **NIST is not a single "contest" you enter.** The relevant tracks are: the PQC standards (FIPS-203/204/
   205, done `[VERIFY]`), the **Additional Digital Signature Schemes** on-ramp `[VERIFY]`, and the
   **Multi-Party Threshold Cryptography (MPTC, NIST IR 8214 series)** project `[VERIFY]`. Aggregate/
   multi-signatures most plausibly fit MPTC or a future dedicated call. The value of preparing now is that
   the *submission artifacts* (spec, reference + optimized implementation, KAT/ACVP vectors, concrete
   security analysis, IP statements) are the same artifacts a top-tier paper needs.
3. **What is already in hand** is substantial (machine-checked proofs, anchored reference implementation,
   KATs, live demos). **What is missing** is chiefly external review, ACVP-format vectors, additional
   parameter sets, an optimized constant-time implementation with side-channel analysis, and the tight
   QROM-B derivation. See §5.

---

## 2. The NIST landscape (verify before acting)

### 2.1 PQC standards `[VERIFY]`
FIPS-203 (ML-KEM), **FIPS-204 (ML-DSA)**, FIPS-205 (SLH-DSA) were finalized in 2024. ML-ADSA targets
ML-DSA-87 and produces signatures the FIPS-204 verifier accepts unmodified — so it composes with, rather
than replaces, the standard. Landing: `https://csrc.nist.gov/projects/post-quantum-cryptography`.

### 2.2 Additional Digital Signature Schemes (the "on-ramp") `[VERIFY]`
NIST issued a call for *additional* PQC signatures to diversify beyond lattices; multiple candidates
advanced through evaluation rounds. **What such submissions require** (the durable pattern): a complete
written **specification**; a **reference implementation** and an **optimized implementation**; **KAT /
known-answer test** vectors in the prescribed format; a **written security analysis** stating the claimed
NIST security category and the underlying assumptions; **intellectual-property statements** (signed
statements by submitters/owners, and a statement of no undisclosed patents / licensing terms); and a
**cover sheet** with point-of-contact. Landing:
`https://csrc.nist.gov/projects/pqc-dig-sig`. *Aggregation is not the on-ramp's stated focus*, so this is a
"requirements template," not necessarily the destination.

### 2.3 Multi-Party Threshold Cryptography (MPTC) — IR 8214 series `[VERIFY]`
NIST's MPTC project (NIST IR 8214, 8214A "Notes on Threshold EdDSA/Schnorr…", 8214B/8214C drafts) is the
home for multi-party / threshold signatures and has issued calls for feedback and for schemes. Aggregate
signatures with a decentralized combine are squarely in this conversation. Landing:
`https://csrc.nist.gov/projects/threshold-cryptography`. **Action:** track MPTC calls; ML-ADSA's
"decentralized, no-trusted-aggregator, public combine" framing is a natural fit and should be presented in
MPTC's terminology (it is a *non-interactive aggregate*, adjacent to but distinct from *threshold*).

**Positioning vs. recent lattice schemes (for the submission's related-work).** The closest lattice peers
are **Threshold Raccoon** (del Pino et al., **EUROCRYPT 2024**, ePrint 2024/184 — a `t`-of-`n` *threshold*
signature over a *new* Raccoon-style scheme: 3-round interactive, ~13 KiB sig, ~40 KiB comms per signer,
trusted dealer, new verifier, Hint-MLWE+SelfTargetMSIS) and **Chipmunk** (Fleischhacker–**Herold**–Simkin–
Zhang, CCS 2023 — a *synchronized same-message multi-signature*, ~118–136 KB aggregate at 1024–8192
signers, large per-signer secret-key state, new verifier, ring-SIS+ROM). ML-ADSA differs on the three axes a reviewer will probe: (i) its output is a **bona-fide
ML-DSA-87/FIPS-204 signature** the *unmodified* verifier accepts (no new verifier); (ii) it is
**non-interactive and unsynchronized** (no signing rounds, no per-period slots); (iii) it reduces to
**ML-DSA's own assumptions** at Category 5. The trade-off is single-common-message, "homomorphic-but-not-
freely-mergeable" aggregation. Full head-to-head table: `docs/35` §4; paper `paper/ml-adsa.md` §2.

### 2.4 ACVP (validation) `[VERIFY]`
The Automated Cryptographic Validation Program defines JSON test-vector formats used for FIPS validation.
ML-ADSA KATs exist (`docs/25`) but not yet in ACVP-JSON; producing those is a concrete deliverable.
Landing: `https://pages.nist.gov/ACVP/`.

---

## 3. The publish-first path

| Step | Venue/mechanism | Provides | Effort/timeline (typical) |
|---|---|---|---|
| 3.1 | **IACR ePrint** (`eprint.iacr.org`) | immediate public timestamp (priority + defensive publication), citable | days |
| 3.2 | **arXiv** (cs.CR) | broader visibility, citable | days |
| 3.3 | **Peer-reviewed venue** — CRYPTO/EUROCRYPT/ASIACRYPT (IACR), PKC, CHES (impl/side-channel), Real World Crypto (deployment) | independent review, credibility | 6–14 months/cycle |
| 3.4 | **Solicited cryptanalysis** — workshops, bounties, direct outreach to lattice cryptanalysts | the decisive security signal | ongoing, 12+ months |
| 3.5 | **NIST engagement** — respond to MPTC calls / a future aggregation call with the prepared artifacts | standardization track | depends on a call existing `[VERIFY]` |

The machine-checked proofs are a strong *positive* signal but **do not substitute for human
cryptanalysis**: they verify the reductions to MLWE/MSIS as modeled; they do not rule out a modeling gap
or a novel attack on the construction's composition. State this plainly in the paper.

---

## 4. Defensive publication & IP

ML-ADSA is deliberately **trapdoor-free, setup-free, and proof-system-free** ("cypherpunk"): it uses only
ML-DSA's own operations plus a PRF and a hash. Strategy: **defensive publication** via ePrint/arXiv
establishes prior art and a public timestamp, supporting an open, royalty-free posture and a clean IP
statement for any NIST submission (which require disclosure of patents/licensing). If the owner wants
patent protection instead, file before public disclosure — but that conflicts with the open posture and
with NIST's preference for royalty-free; recommend the defensive-publication route. `[VERIFY]` exact NIST
IP-statement wording at submission time.

---

## 5. Requirements traceability (submission pattern → status)

Status: **DONE** / **PARTIAL** / **MISSING**, mapped to artifacts in this repo.

| # | Requirement (PQC / additional-sig / MPTC pattern) | Status | Evidence / gap |
|---|---|---|---|
| 1 | Complete written specification | **DONE** | `docs/30` (FIPS-204-structured), `docs/17`, `docs/21` |
| 2 | Security analysis: assumptions + claimed category | **DONE** | `docs/30 §8`, `docs/31`, `docs/28`; Category 5, MLWE+SelfTargetMSIS(+M-SIS), ROM+QROM |
| 3 | Machine-checked proofs (beyond required, a differentiator) | **DONE** | 234 lemmas (202 EC + 32 Coq) across 35 artifacts + 6 Gobra; `formal/count-artifacts.sh`, `docs/31`, `docs/35` |
| 4 | Reference implementation | **DONE** | `go-mladsa/`, CIRCL + go-qrllib byte-anchored |
| 5 | KAT / known-answer test vectors | **DONE (ACVP-shape)** | KATs (`docs/25`) + **ACVP-style JSON vectors** generated by the reference impl in `vectors/` (digests match the pinned KATs); official ACVP algorithm-registration + exact prompt/expectedResults wire-split still TODO |
| 6 | Optimized + constant-time implementation | **PARTIAL** | branchless **constant-time** reduction (`modQ`/`cabs`) + allocation-fused arithmetic applied & benchmarked (`docs/33 §4b`, `docs/34`); byte-identical. **AVX2 asm** designed but not shipped (needs x86-64 CI — `docs/34 §3`) |
| 7 | Side-channel analysis | **PARTIAL** | secret path is straight-line/branchless (`docs/34 §2`); automated CT verification (dudect/ctgrind) + microarch evaluation still TODO |
| 8 | Multiple parameter sets (Cat 2/3/5) | **PARTIAL** | ML-ADSA-87 (Cat 5) done; **-44/-65 MISSING** |
| 9 | IP statements (signed) | **MISSING** (process) | defensive-publication plan in §4 |
| 10 | Cover sheet / point of contact | **MISSING** (process) | trivial at submission |
| 11 | Independent third-party cryptanalysis | **MISSING** | **the decisive gate** (§3.4) |
| 12 | Tight QROM bound (rejection-free variant) | **DONE (derived)** | Construction A tight/unconditional; Construction B's distinct-per-query GHHM21 reprogramming loss now DERIVED in-prover (`ml_adsa_qrom_ghhm.ec : ghhm_hybrid`, `reprog_ghhm = qs·(qh+1)/\|from\|`) from proven per-round resampling + the Thm 6.1 distinct-query bound — replaces the imported Zhandry quartic axiom. Per-round bound discharged hypothesis-free (`ghhm_multiround_perfect`); the signing-round program-equivalence is itself machine-checked (`reprog_round_equiv`). The only remaining input is ML-DSA's *own* HVZK (`masking_ok` = `masking_perfect`) — not a gap and not aggregation-specific: consequences machine-checked classically (`zero_leakage_perfect_A`) and quantumly (`sq_perfect`), aggregate→single reduction proven (F-C13), and its rejection-sampling change-of-variables kernel now DERIVED from first principles (`ml_adsa_masking.ec : reject_uniform`); only bit-level NTT/rounding functional correctness is left to the shared lattice-arithmetic boundary (byte-cross-checked vs two FIPS-204 impls). `docs/14`, `docs/30 T11′` |
| 13 | Public, reproducible test harness | **DONE** | `check-all.sh`, `go test`, live demos (`docs/31 §7`) |
| 14 | Peer-reviewed publication | **MISSING** | §3 path |
| 15 | Performance/size comparison vs alternatives | **DONE (reference)** | measured benchmark + size/compression tables in `docs/33` (reference impl; optimized/constant-time build still TODO, item #6) |

---

## 6. Phased timeline (realistic, honest)

- **Phase 0 — finalize artifacts (now):** polish `docs/30` spec + `paper/ml-adsa.md`; add the benchmark
  table; produce ACVP-JSON vectors; (optionally) ML-ADSA-44/65 parameter instances. *(Most is in hand.)*
- **Phase 1 — publish (weeks):** IACR ePrint + arXiv. Establishes priority and invites scrutiny.
- **Phase 2 — review & cryptanalysis (6–18 months):** submit to a venue; solicit cryptanalysis; add an
  optimized constant-time implementation + side-channel analysis; derive the tight QROM-B bound.
- **Phase 3 — NIST engagement (when a call exists `[VERIFY]`):** respond to an MPTC call or a future
  aggregation call with the full artifact set + IP statements. **This phase is gated on (a) surviving
  cryptanalysis and (b) a NIST call actually existing** — neither is guaranteed, and that should be stated
  to stakeholders.

---

## 7. Bottom line

The hard, unusual work is already done: a complete spec, a security argument machine-checked against
ML-DSA's own assumptions in ROM and QROM, an anchored reference implementation, KATs, and live
decentralized demonstrations. The path to "NIST-quality" is now mostly **process and external scrutiny**:
publish on ePrint (priority + defensive IP), get peer review and — above all — **independent
cryptanalysis**, fill the engineering deliverables (ACVP vectors, optimized constant-time implementation,
side-channel analysis, extra parameter sets), and engage NIST through MPTC or a future call. The
machine-checked proofs make ML-ADSA an unusually strong *starting* position, but they do not replace human
cryptanalysis, and no responsible roadmap claims standardization before that scrutiny exists.
