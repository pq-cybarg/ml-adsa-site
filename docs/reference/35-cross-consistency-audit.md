# 35 — Cross-Sectional Consistency Audit (text ↔ implementation ↔ analysis)

> **Purpose.** A one-shot, repo-wide audit reconciling every prose document against the
> *actual* formal artifacts, the Go implementation, and each other. It establishes a single
> reproducible **source of truth** for all tallies, classifies every document by iteration,
> and records the remediation applied. Re-run `formal/count-artifacts.sh` after any change to
> `formal/` and update the canonical-current surface to match.

Compiled 2026-06-11.

---

## 1. Source of truth (reproducible)

`formal/count-artifacts.sh` derives the canonical tallies from `check-all.sh` (the one place the
artifact set is defined) plus the source files. Current output:

```
Prover artifacts : 29   (19 classical EasyCrypt + 5 quantum EasyPQC + 5 Coq/Rocq)
Machine-checked lemmas : 134   (102 EasyCrypt + 32 Coq)
Genuineness checks : 33/33
Gobra theorems : 6   (5/5 Gobra genuineness)
```

Counting conventions (adversary-checkable): an **artifact** is one `.ec`/`.v` file in
`check-all.sh` that compiles green; an **EasyCrypt lemma** is a top-level `lemma` declaration
(excludes `axiom` and clones); a **Coq lemma/theorem** is a top-level
`Lemma|Theorem|Corollary|Proposition`; a **genuineness check** is one `CHECKS` entry in
`genuineness.sh`; a **Gobra theorem** is a lemma-style proof function in
`formal/gobra/integrity.go`. **Zero `admit`/`Admitted`/`sorry`** tactics exist (every textual
match is inside a comment such as "admit-free" / "no admit").

The deprecated tallies seen in older prose — **77** (= 72 EC + 5 Coq), **39**, **45**, **23**
(= 14 + 4 + 5), **24** — are all superseded by the figures above. The **77** conflated *5 Coq
files* with *5 Coq lemmas* (Coq actually has 32 lemmas/theorems) and predates the masking /
rounding / NTT / NTT-inversion / GHHM additions.

---

## 2. Document classification

| Class | Documents | Treatment |
|---|---|---|
| **Canonical-current** (must match §1) | docs/18, 22, 23, 24, 25, 26, 30, 31, 32, 33, 34; `paper/ml-adsa.md`; `README.md` | Counts/ctx/status corrected to source of truth. |
| **Mixed** (current content, stale labels/counts) | docs/13, 14, 17, 20, 21, 27, 28, 29 | Counts + stale status labels corrected; target/legacy lemma names reconciled where they name a now-shipped result. |
| **Historical-iteration** (research trail) | docs/01–12, 15, 16, 19; `ML-ADSA-whitepaper.md` | Dated provenance banner added pointing here + to docs/30/31; numbers left as the historical record they are; only genuinely *misleading* superseded security claims annotated. |

---

## 3. Findings & remediation ledger

### 3.1 Stale / contradictory counts (canonical-current — corrected to 29/134/33/6)
- `paper/ml-adsa.md` — **internal contradiction**: "77 machine-checked proofs" (:37, :387) vs "39 machine-checked proofs" (:117). → unified to 134 lemmas / 29 artifacts.
- `docs/30:10` "77 machine-checked proofs" → 134 / 29.
- `docs/31:67,69` "72 EC + 5 Coq = 77" / "lemma count is 77" → 102 EC + 32 Coq = 134.
- `docs/31:190` "**15 classical** + 5 + 5" **contradicts** docs/31:62,73 "19 classical" (and the file's own total 29). → 19.
- `docs/32:105` "77 lemmas + 6 Gobra" → 134 + 6.
- `docs/27:13` "24 artifacts (15+4+5), 26/26" **contradicts** docs/27:77 "29 artifacts". → 29 / 33.
- `README.md:33-37` "23 artifacts (14+4+5), 24/24, 14 QROM lemmas" → 29 / 134 / 33 (full refresh).
- Mixed docs: `docs/19:243` "23", `docs/20:66` "23 / 24-24", `docs/21:165,212,215` "23 (14+4+5) / 24-24", `docs/28:68` "24", `docs/29:242` "15+4+5". → 29 / 33 (or historical banner for docs/19).

### 3.2 Other internal contradictions
- `docs/15` (historical): genuineness 19/19 (:29) vs 9/9 (:292,:399); EC files 11 (:24) vs 8 (ledger); quantum 3 (:30) vs 2 (:87); EC lemmas 40 (:26) vs 31 (:396). → banner (historical audit snapshot).
- `docs/12` (historical): EasyCrypt "not installed" (:12) vs "yes installed" (:22). → banner.
- `docs/17` (mixed): F-C11 `[proven]` (:382) vs `[open]` (:393) vs `[partly proven]` (:495). → reconcile to proven (per docs/18 `concurrent_euf_chained`).
- `docs/14` (mixed): "main reduction admitted" (:60) vs `qrom_eufcma_uncond` "PROVED unconditional" (:108). → fix :60.
- `ml_adsa_props.ec:3` header comment "proofs are `admit`-ted" vs the file's own ":72/:136/:179 PROVED below (no admit)". → fix header comment.

### 3.3 ctx ("ZOND" vs "QRL") — *not a typo; a layer/illustration mismatch*
`ctx` is a **caller-supplied parameter** to `Verify`/`AggregateF` (`go-mladsa/mldsa87.go:454`,
`construction_f.go:238`); the construction's internal sub-domains are `"F.pop"`/`"F.kt"`. The
**QRL 2.0 consensus deployment** binds `ctx="ZOND"` — the hard-coded go-qrllib wallet domain
(`wallet/common/context.go`, `context_test.go` expects `{'Z','O','N','D',…}`,
`qrysm/cmd/mladsa-epochnet/main.go:47`). Deployment docs (26, 29) correctly say **ZOND**.
The spec docs (13/15/16/17), README, whitepaper, and the `construction_f.go:216` comment use
illustrative **`"QRL"||C`** / `"QRL:SUI"`, which misrepresents the real deployed constant.
→ Standardize: state ctx is caller-supplied, and the **QRL 2.0 deployment uses `"ZOND"`**;
fix `construction_f.go:216`. (KAT domain in docs/25 is a separate test input — left as-is, noted.)

### 3.4 GHHM21 "imported" vs "derived"
Ground truth: **derived in-prover** (`ml_adsa_qrom_ghhm.ec` header: "NOT imported as the loose
Zhandry semi-constant-distribution axiom"; `ghhm_hybrid` proven; Zhandry quartic retained only
as a cross-check). Stale "imported" claims: `README.md:81`, `paper/ml-adsa.md §1.5:124`
("currently imports"). → corrected to "derived" (paper §6.6/§10 already say derived).

### 3.5 `masking_perfect` is an axiom, not a lemma
`masking_perfect` (`ml_adsa_props.ec:22`, `ml_adsa_zk_proof.ec:21`) and `masking_perfect_wm`
(`ml_adsa_regimes.ec:46`) are **axioms**; the **lemma** that discharges the underlying fact is
`masking_perfect_concrete` (`ml_adsa_masking.ec:115`). Docs citing `masking_perfect` as a
"proven lemma" (docs/30, paper, docs/32) → reframed as "axiom discharged by the
`masking_perfect_concrete` change-of-variables lemma."

### 3.6 Lemma-name drift (cited name ≠ shipped name)
Publication surface (docs/30, 31, paper) citations all RESOLVE. Stale citations to fix in mixed/
historical docs: `msufcma_reduction`→`msufcma_uncond` (docs/12); `mask_reduces_to_mlwe`,
`masking_perfect_wm`-as-lemma (docs/15); docs/17 `[target]` names renamed before landing —
`F_eufcma_C`→`F_eufcma_in_domain_no_loss`, `F_qrom_eufcma`→`F_qrom_eufcma_in_domain`,
`F_leakage_per_content`→`F_zk_per_content`, `setup_no_secret`→`setup_deterministic`/`setup_public_only`,
`provenance_sound`→`provenance_check_sound`, plus six F-DEC `*_sound` names →
`tally_cons`/`tally_filter`/`threshold_over_members`/`option_separation`. docs/24
`uniform_mask_hides` (structural analog, not a checked lemma) — labeled as such.

### 3.7 Benchmark / size harmonization
- Committee-bloat figure: "≈578 KB" (docs/26, 28, KiB) vs "~592 KB / 592 256 B" (docs/19, 29, 33).
  Same byte count (128×4627 = 592 256 B). → standardize on **592 KB (592 256 B)**.
- Compression floor: paper says "12–128×" (§8) and adds an N=8 (8×) row (§A.3) absent from
  docs/33 (smallest row 16×). → add N=8 row to docs/33 and reconcile the "12×" phrasing.
- Secondary security number: docs/30:68 "265-bit (MSIS)" vs whitepaper:53 "229-bit quantum
  Core-SVP" — different quantities; → state both explicitly where cited.

### 3.8 Related-work gap — **Threshold Raccoon & Chipmunk** (new requirement)
Threshold Raccoon appears only in `ML-ADSA-whitepaper.md` (Appendix B) and Chipmunk/Squirrel only
in the whitepaper (§8). They are **absent** from `paper/ml-adsa.md §2` and the canonical docs.
→ Add a Threshold Raccoon + Chipmunk comparison to `paper/ml-adsa.md §2`, the plain-language
whitepaper (docs/19), and a positioning note in docs/32 (NIST/MPTC). See §4.

---

## 4. Threshold Raccoon & Chipmunk vs ML-ADSA-87 (comparison)

| | **Threshold Raccoon** (del Pino–Katsumata–Maller–Mouhartem–Prest–Saarinen, CRYPTO 2024) | **Chipmunk** (Fleischhacker–Simkin–Zhang, CCS 2023) | **ML-ADSA-87** (this work) |
|---|---|---|---|
| Primitive | `t`-of-`n` **threshold** signature (one joint signature) | **synchronized** aggregate signature (one slot per time period) | **aggregate** signature over an existing per-signer scheme |
| Base scheme | Raccoon (masking-friendly FSwA lattice sig) — a *new* scheme | hash-based/lattice synchronized multisig (successor to Squirrel) | **ML-DSA-87 (FIPS-204)** unchanged |
| Verifier | new Raccoon verifier | new Chipmunk verifier | **unmodified FIPS-204 verifier** accepts `σ*` |
| Interaction | **3 rounds**, interactive signing with shares | non-interactive aggregate, but **one signature per period** (synchronized) | **non-interactive**, no per-signer interaction; order/grouping independent |
| Trust / setup | distributed key generation; threshold trust | trusted-ish per-period key tree (one-time, evolving) | **no trusted setup, no trapdoor, no aggregator** |
| Aggregate / sig size | ~**13 KiB** signature (independent of `n`); ~40 KiB comms | ~**~5 KiB** aggregate (logarithmic), large per-signer keys | **4627 B constant** in `N` (a real FIPS-204 sig) |
| Participants | up to ~**1024** | large (Merkle-indexed) | committee `N` up to deployment cap (qrysm: 128) |
| Assumptions | MLWE + MSIS (Raccoon) | (synchronized) lattice + CR-hash | **MLWE + SelfTargetMSIS (+Module-SIS)** — identical to ML-DSA |
| Formal verification | paper proofs | paper proofs | **134 machine-checked lemmas** (EasyCrypt+Coq) + 6 Gobra |
| Key distinction | jointly *produces* one signature under a shared key (threshold) | aggregates **one message per period** (synchronized) | aggregates **independent** signatures into a key/scheme the existing verifier already accepts |

**Positioning.** Threshold Raccoon answers a different question (a `t`-of-`n` *threshold* over a
*new* scheme, interactive, ~13 KiB) and Chipmunk answers another (a *synchronized* aggregate, one
slot per period). ML-ADSA's distinguishing properties are (i) the output is a **bona-fide
ML-DSA-87 signature** the *unmodified* FIPS-204 verifier accepts, (ii) **non-interactive,
many-time, decentralized** aggregation with **no trusted aggregator/setup/trapdoor**, and (iii) it
inherits ML-DSA's exact assumptions and Category-5 parameters. The cost is the structural
"homomorphic-but-not-freely-mergeable" property (the FS challenge binds the full participant
commitment), which is also what gives ROS-resistance with **no AGM/OMDL**.

---

## 5. Remediation status — **COMPLETE** (2026-06-11)

All findings in §3 discharged:

- **Source of truth** locked: `formal/count-artifacts.sh` → 29 artifacts / 134 lemmas (102 EC + 32 Coq) /
  33-33 genuineness / 6 Gobra. Re-verified green; `ml_adsa_props.ec` (only proof file touched —
  comment-only) recompiles GREEN, `go-mladsa` builds.
- **Counts** corrected on the canonical-current surface (paper, README, docs/18/30/31/32) and mixed docs
  (13, 14, 17, 20, 21, 27, 28, 29). Internal contradictions resolved: paper 39/77→134; docs/31
  19-vs-15→19; docs/27 24-vs-29→29; docs/17 F-C11 [proven]/[open]/[partly] → proven; docs/29 H4-full
  DONE-vs-Remaining clarified.
- **ctx** standardized: caller-supplied; QRL 2.0 deployment = `"ZOND"`; `construction_f.go:216` comment
  fixed (both copies); spec docs updated.
- **GHHM21** "imported"→"derived" fixed (README, paper §1.5). **`masking_perfect`** reframed as the
  axiom discharged by `masking_perfect_concrete`. **Admit-free** confirmed; stale `props.ec:3` header fixed.
- **Lemma-name drift** fixed in docs/17 (target names → shipped names).
- **Benchmarks** harmonized: 578→592 KB (592 256 B); paper 12–128×→8–128×; docs/33 N=8 (8×) row added.
- **Threshold Raccoon + Chipmunk** added: paper §2 (+refs [dPKM⁺24], [FSZ23], [Squirrel]), docs/19
  (plain language), docs/32 (MPTC positioning), and §4 above.
- **Historical-iteration docs** (01–03, 05–12, 15, 16, whitepaper) carry dated provenance banners pointing
  here + to docs/30/31/`count-artifacts.sh`; their body numbers are preserved as the historical record.
  (docs/04 is a still-current standalone impossibility result — not bannered.)
- **Public site** re-synced via the new `ml-adsa-site/sync-docs.sh` (36 reference copies refreshed + docs/35
  added to nav; landing-page lemma count 77→134). **Not pushed** — outward publication awaits explicit
  go-ahead (opsec).
