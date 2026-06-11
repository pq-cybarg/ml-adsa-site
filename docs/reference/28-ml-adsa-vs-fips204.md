# 28 — ML-ADSA documentation vs NIST FIPS-204 (ML-DSA-44/65/87)

Gap analysis of the ML-ADSA documentation/spec against the NIST baseline it builds on — **FIPS-204**
(Module-Lattice Digital Signature Standard, ML-DSA), pub. 2024-08-13. ML-ADSA is **not** a NIST
standard; this maps what a NIST-grade aggregate spec would contain, what we have, what exceeds the
baseline, and what is missing. Sources at the end (FIPS-204 PDF, NIST ACVP, pq-crystals).

## 1. Document-structure mapping (FIPS-204 §→ ML-ADSA coverage)

| FIPS-204 section | ML-ADSA coverage | gap |
|---|---|---|
| §1 Introduction / scope | docs/16 (design), docs/17 §1 scope | — |
| §2 Glossary / notation / NTT repr | docs/17 §3; inherits FIPS-204 notation | minor: no standalone glossary |
| §3 Overview (security props, assumptions, hedged/deterministic, requirements) | docs/17 §9; docs/18; **machine-checked** security (docs/27) | deterministic vs hedged: ML-ADSA mainline is deterministic-nonce (refresh) — documented, but no "hedged" variant spec |
| §4 Parameter sets | docs/17 §2 (ML-DSA-87 params) + §3.2 (Construction-F params) | **only the Cat-5 (ML-DSA-87) set** — no 44/65 aggregate variants (§2 below) |
| §5 External functions (KeyGen/Sign/Verify, pre-hash) | docs/17 §7 (Setup/MemberKeyGen/Aggregate/Verify); §7.8 = unmodified FIPS-204 Verify | no **pre-hash (HashML-ADSA)** variant specified |
| §6 Internal functions | go-mladsa/qrysm code + docs/20 refinement map | internal fns are code+KAT, not a NIST-style pseudocode listing for every algorithm |
| §7 Auxiliary (encoding, sampling, rounding, NTT) | inherited from ML-DSA-87 verbatim; `mldsa87.go` | **[named]**+**[measured]**, not re-specified (same as FIPS, which fully specs them) |
| Appendix (Montgomery, zetas, loop bounds, diffs) | inherited; not reproduced | minor |

**Net:** ML-ADSA documents the *aggregate-specific* layers (Construction F §7.3–7.10) to spec depth and
**inherits the FIPS-204 ML-DSA-87 base verbatim**; it does not re-specify the base byte-level functions
(it reuses them and anchors via CIRCL/go-qrllib).

## 2. Parameter sets

FIPS-204 defines **three** sets (shared n=256, q=8380417, d=13):

| | τ | λ | γ1 | γ2 | (k,ℓ) | η | β | ω | Cat | sk | pk | sig |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ML-DSA-44 | 39 | 128 | 2¹⁷ | (q−1)/88 | (4,4) | 2 | 78 | 80 | 2 | 2560 | 1312 | 2420 |
| ML-DSA-65 | 49 | 192 | 2¹⁹ | (q−1)/32 | (6,5) | 4 | 196 | 55 | 3 | 4032 | 1952 | 3309 |
| **ML-DSA-87** | 60 | 256 | 2¹⁹ | (q−1)/32 | (8,7) | 2 | 120 | 75 | **5** | 4896 | 2592 | 4627 |

**ML-ADSA targets only ML-DSA-87 (Category 5).** It inherits the 87 parameters **verbatim**, so the
core-SVP / Cat-5 hardness carries over unchanged (no parameter was altered by aggregation). It **adds**
Construction-F parameters (epoch-tree height `H_tree`; PRF/H/MTH = SHAKE-256 with domain separation).
**Gap:** no ML-ADSA-44/65 (Cat 2/3) variants — straightforward to instantiate (same construction over
those param sets) but not built/tested. **Aggregate sizes:** `σ*` is **4627 B constant in committee
size N** (the whole point); `pk*` 2592 B; plus `aggregation_bits` (⌈N/8⌉ B) and amortized provenance
on audit. (Contrast the status-quo qrysm list: up to 128×4627 ≈ 578 KB.)

## 3. Known-Answer Tests / validation vectors

FIPS-204 conformance uses **NIST ACVP** (`usnistgov/ACVP-Server`): test types **keyGen / sigGen /
sigVer**, modes `deterministic`(rnd=0³²) vs hedged, interfaces internal/external/pre-hash, with fields
`seed, sk, pk, message, mu, rnd, context, signature, testPassed`.

ML-ADSA (docs/25, `kat_test.go`):
- **Base ML-DSA-87 KATs:** not re-pinned — the base is conformance-checked against **CIRCL** and **QRL's
  go-qrllib**, both FIPS-204 implementations (go-qrllib is ACVP-tested per QRL). So the base inherits
  ACVP conformance transitively.
- **Aggregate-specific KATs:** pinned `pk*`/`σ*` for N=1/4/16/64/128, refresh-primitive vectors, and a
  **rotation** KAT (subsequent contents, no-leak) — deterministic via the refresh + a fixed PCG seed.
  Cross-validated: standalone and qrysm-vendored produce **identical** vectors.
- **Gap vs ACVP:** our KATs are **Go-pinned**, not emitted in **ACVP JSON** format, and there is no
  ACVP test-type taxonomy for aggregates (a hypothetical ML-ADSA ACVP would need `aggGen`/`aggVer`/
  `rotation`/`provenance` types). Producing ACVP-format JSON + a harness is a clear, scoped follow-up.

## 4. Security & validation expectations

| aspect | FIPS-204 | ML-ADSA |
|---|---|---|
| target property | **SUF-CMA** (cited to literature) | SUF-CMA **machine-checked** (`sufcma_uncond`) — *exceeds* FIPS (FIPS references the proof; we mechanize it) |
| assumptions | MLWE + SelfTargetMSIS, Fiat-Shamir-with-aborts | same + PRF + CR-hash (for refresh/provenance) — **no new hardness vs ML-DSA** |
| (Q)ROM | cited (KLS18); not in the FIPS text | **machine-checked** QROM (EasyPQC): Construction-A tight `qrom_eufcma_uncond`; Construction-B lossy/named |
| param justification | core-SVP in the Dilithium spec | **inherited verbatim** (no param change) ⇒ same core-SVP/Cat-5 |
| validation | **CAVP/ACVP** (prerequisite for FIPS 140-3) | **none** (research scheme); base inherits ACVP via CIRCL/go-qrllib; code-level Gobra proofs + 24 algorithm proofs + KATs are stronger-than-typical evidence but are **not** CAVP validation |
| independent review | NIST process | **required, not yet done** (stated in docs/18 §5, docs/21 §8) |

## 5. Gap summary — what a NIST-grade ML-ADSA spec would still need

1. **Parameter-set breadth:** ML-ADSA-44/65 (Cat 2/3) instantiations + sizes/KATs (we have only Cat-5).
2. **ACVP-format vectors + an aggregate test taxonomy** (`aggGen`/`aggVer`/`rotation`/`provenance`),
   emitted as JSON like `usnistgov/ACVP-Server` (we have Go-pinned KATs, docs/25).
3. **Pre-hash / hedged variants** spec (HashML-ADSA; a randomized-nonce mode) — mainline is
   deterministic-refresh only.
4. **Full byte-level internal-function listing** to FIPS depth (currently inherited + named + measured).
5. **CAVP/ACVP validation + independent cryptographic review** (process, not a document).
6. The **operational/integration** items (durable one-time state, SSZ/slashing wiring) — docs/23, docs/26.

**What ML-ADSA already meets or exceeds vs the baseline:** verbatim Cat-5 parameters (so Cat-5 security
carries over), SUF-CMA + QROM **machine-checked** (FIPS only cites these), an honest assumption base
with no new hardness, dual independent FIPS-204 verifiers (CIRCL + go-qrllib), and code-level (Gobra)
proofs — none of which a typical FIPS submission provides.

## Sources

- FIPS-204 (PDF): https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf · landing: https://csrc.nist.gov/pubs/fips/204/final · DOI 10.6028/NIST.FIPS.204
- NIST ACVP: https://pages.nist.gov/ACVP/ · ML-DSA draft: https://pages.nist.gov/ACVP/draft-celi-acvp-ml-dsa.html · vectors: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
- CRYSTALS-Dilithium (core-SVP params): https://pq-crystals.org/dilithium/
