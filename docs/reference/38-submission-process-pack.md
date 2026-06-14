# 38 — Submission Process Pack (IP statement · cover sheet · point of contact)

Companion to the publication/NIST roadmap (`docs/32`). These are **drafts/templates** for the
*process* deliverables a peer-reviewed-venue or NIST-program submission requires (`docs/32 §5`
items #9, #10). They are not legal advice; have counsel review the IP statement before signing.

> **Posture (decided, `docs/32 §4`): defensive publication, royalty-free, open.** ML-ADSA is
> deliberately trapdoor-free, setup-free, and proof-system-free — it uses only ML-DSA's own
> operations plus a PRF and a hash. Establishing prior art via IACR ePrint/arXiv (`docs/62`* package)
> supports a clean, royalty-free IP statement and avoids the patent route, which conflicts with the
> open posture and NIST's royalty-free preference.

> **Identity:** all public-facing submission identity is the pseudonymous **`pq-cybarg`**
> (`resistant@tuta.com`), consistent with the repository/opsec discipline. Real legal-entity details
> are filled in **only** on the privately-submitted signed forms, never in any public artifact.

---

## 1. Intellectual-property statement (template)

> Adapt to the exact wording the target program demands at submission time (`[VERIFY]` the current
> NIST "Statements" PDFs / venue camera-ready forms). The substance below is the royalty-free,
> defensive-publication commitment.

**Statement by the Submitter(s).**

I/we, the submitter(s) of **ML-ADSA (Module-Lattice Aggregate Digital Signature Algorithm over
ML-DSA-87 / FIPS-204), "Construction F",** do hereby declare:

1. **Ownership & authority.** I/we are the owner(s) of, or otherwise have the right to make this
   submission of, the ML-ADSA cryptosystem and all reference and optimized implementations submitted
   herewith.

2. **No undisclosed patents.** To the best of my/our knowledge, the ML-ADSA construction as submitted
   is **not covered by any patent or pending patent application owned or controlled by the
   submitter(s)**. ML-ADSA is constructed entirely from operations already specified in **FIPS-204
   (ML-DSA)** — modular-lattice arithmetic, a PRF (SHAKE-256), and a collision-resistant hash — plus
   public, additive (BLS-analogue) aggregation; it introduces no new trapdoor, no trusted setup, and
   no proof system.

3. **Royalty-free license.** Should ML-ADSA be selected for standardization (or to the extent any
   claim the submitter(s) may hold reads on it), the submitter(s) hereby commit to grant a
   **worldwide, non-exclusive, royalty-free, irrevocable** license to make, use, and distribute
   implementations of ML-ADSA for the purpose of implementing the standard, on reasonable and
   non-discriminatory terms, with no requirement of payment or of a reciprocal license beyond what is
   necessary to practice the standard.

4. **Defensive publication / prior art.** ML-ADSA has been publicly disclosed (IACR ePrint
   `[fill in report number/date]`; arXiv `[fill in id]`), establishing prior art as of that date.

5. **Third-party rights.** I/we are not aware of any third-party patent, copyright, or other
   intellectual-property right that would be infringed by the practice of ML-ADSA as submitted.
   ML-ADSA composes with the unmodified FIPS-204 verifier and asserts no rights over FIPS-204 itself.

6. **Implementation license.** The reference implementation (`go-mladsa/`) and test artifacts are
   released under a permissive open-source license (`[MIT / Apache-2.0 / CC0 — choose]`); the formal
   proofs (`formal/`) and documentation are released under `[CC-BY-4.0 / CC0 — choose]`.

Signed: __________________________  Date: ____________   (legal name & entity on the private form only)

---

## 2. Cover sheet / submission metadata

| Field | Value |
|---|---|
| **Scheme name** | ML-ADSA — Module-Lattice Aggregate Digital Signature Algorithm |
| **Variant** | Construction F (non-interactive, decentralized aggregate over ML-DSA-87) |
| **Parameter sets** | ML-ADSA-87 (Cat 5) — primary; ML-ADSA-65 (Cat 3), ML-ADSA-44 (Cat 2) `[VERIFY status — docs/32 #8]` |
| **Type** | Non-interactive aggregate signature (homomorphic, not freely mergeable); composes with FIPS-204 verifier |
| **Security category** | NIST Category 5 (ML-ADSA-87); 3 / 2 for -65 / -44 |
| **Assumptions** | MLWE + SelfTargetMSIS (+ Module-SIS), ROM **and** QROM — the *same* as ML-DSA |
| **Output** | A syntactically valid ML-DSA-87 signature (4627 B) under an aggregate public key (2592 B) |
| **Specification** | `docs/30` (FIPS-204-structured); dossier `docs/31` |
| **Reference implementation** | `go-mladsa/` (Go), byte-anchored to CIRCL + theQRL/go-qrllib FIPS-204 verifiers |
| **Optimized implementation** | branchless constant-time core + allocation-fused arithmetic (`docs/34`); AVX2 path `docs/34 §3` |
| **KAT / test vectors** | `docs/25`; ACVP-format JSON in `vectors/` |
| **Machine-checked proofs** | 36 artifacts / 244 lemmas (212 EasyCrypt + 32 Coq) / 50 genuineness / 6 Gobra — `formal/count-artifacts.sh` (beyond-required differentiator) |
| **Point of contact** | `pq-cybarg` — `resistant@tuta.com` (public, pseudonymous) |
| **IP** | Royalty-free, defensive publication (§1) |
| **Publication** | IACR ePrint `[id]`, arXiv `[id]` |
| **Patents** | None claimed (§1.2) |

---

## 3. Submission checklist (map to `docs/32 §5`)

- [x] Complete written specification — `docs/30`
- [x] Security analysis + claimed category + assumptions — `docs/30 §8`, `docs/31`, `docs/28`
- [x] Reference implementation — `go-mladsa/`
- [x] Machine-checked proofs (differentiator) — `formal/`
- [x] KAT vectors — `docs/25`; ACVP-format JSON — `vectors/` (`docs/32 #5`)
- [x] Optimized + constant-time implementation — branchless CT reductions + allocation fusion + full AVX2 NTT/INTT (byte-identical, validated under docker emulation, enabled on AVX2 CPUs); native-x86 perf measurement pending via `bench-avx2.sh` (`docs/32 #6`, `docs/34 §3`)
- [ ] Side-channel analysis — source-level done; automated dudect + microarch eval pending (`docs/32 #7`, `docs/34 §2`)
- [x] Multiple parameter sets — all three (-44/-65/-87, Cat 2/3/5) instantiated & CIRCL-cross-validated; official ACVP-vector submission for -44/-65 remains (`docs/32 #8`, `docs/40`)
- [ ] **IP statement (signed)** — template §1; sign privately
- [ ] **Cover sheet / PoC** — §2
- [ ] Independent third-party cryptanalysis — `docs/39` solicitation packet (`docs/32 #11`, the decisive gate)
- [ ] Peer-reviewed publication — `docs/32 §3`
- [x] Public reproducible test harness — `formal/check-all.sh`, `go test`, demos

\* "`docs/62`" above refers to the ePrint package task; the built package lands under `paper/eprint/`.
