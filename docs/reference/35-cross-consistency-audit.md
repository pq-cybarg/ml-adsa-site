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
Prover artifacts : 43   (33 classical EasyCrypt + 5 quantum EasyPQC + 5 Coq/Rocq)
Machine-checked lemmas : 274   (242 EasyCrypt + 32 Coq)
Genuineness checks : 53/53
Gobra theorems : 6   (5/5 Gobra genuineness)
```

Counting conventions (adversary-checkable): an **artifact** is one `.ec`/`.v` file in
`check-all.sh` that compiles green; an **EasyCrypt lemma** is a top-level `lemma` declaration
(excludes `axiom` and clones); a **Coq lemma/theorem** is a top-level
`Lemma|Theorem|Corollary|Proposition`; a **genuineness check** is one `CHECKS` entry in
`genuineness.sh`; a **Gobra theorem** is a lemma-style proof function in
`formal/gobra/integrity.go`. **Zero `admit`/`Admitted`/`sorry`** tactics exist (every textual
match is inside a comment such as "admit-free" / "no admit").

The deprecated tallies seen in older prose — **77** (= 72 EC + 5 Coq), **45**, **45**, **23**
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

### 3.1 Stale / contradictory counts (canonical-current = 43 artifacts / 274 lemmas / 53 genuineness / 6 Gobra)

> The per-line `→` targets below record the reconciliations *as performed at the 29/134/33 snapshot*; the
> authoritative current figures are 36 / 244 / 50 / 6 (see §1 and `formal/count-artifacts.sh`). Later passes
> took the suite 134→200→208→234→254 lemmas (NTT-inversion, Montgomery, the multi-level CT/CRT transform, the
> bit-reversal identity, and the literal `while`-loop NTT procs) and 33→45→47→53 genuineness checks.
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

_Figures below are taken from the primary papers (ePrint 2024/184 and 2023/1820) and were
adversarially fact-checked against the source text; see the notes under the table._

| | **Threshold Raccoon** (del Pino–Katsumata–Maller–Mouhartem–Prest–Saarinen, **EUROCRYPT 2024**, ePrint 2024/184) | **Chipmunk** (Fleischhacker–**Herold**–Simkin–Zhang, CCS 2023, ePrint 2023/1820) | **ML-ADSA-87** (this work) |
|---|---|---|---|
| Primitive | `t`-of-`n` **threshold** signature (one joint signature) | **synchronized multi-signature** (many signers, **same message**, one per time slot) | **aggregate** signature over an existing per-signer scheme |
| Base scheme | Raccoon-style FSwA lattice sig (discrete-Gaussian variant) — a *new* scheme | SIS-based key-homomorphic OTS + homomorphic vector commitment (successor to Squirrel) | **ML-DSA-87 (FIPS-204)** unchanged |
| Verifier | new Raccoon-style verifier | new Chipmunk verifier | **unmodified FIPS-204 verifier** accepts `σ*` |
| Interaction | **3 rounds**, interactive signing with shares | non-interactive aggregation, but **same-message, one slot per period** (synchronized) | **non-interactive**, no per-signer interaction; order/grouping independent |
| Trust / setup | **trusted dealer** (centralized KeyGen; DKG is explicitly out of scope) | public params (SIS matrix) + ROM; no CRS ceremony | **no trusted setup, no trapdoor, no aggregator** |
| Aggregate / sig size | ~**13 KiB** signature (≤12 736 B; independent of `n`,`t`); **~40 KiB comms per signer** (+16·`t` B) | aggregate ~**118 KB at 1024 signers / ~136 KB at 8192** (112-bit); not constant-small | **4627 B constant** in `N` (a real FIPS-204 sig) |
| Per-signer key/state | small | **large secret-key tree state** (seed-derivable, top layers cached); **public key small (~1 KB)** | small ML-DSA key (pk 2592 B) |
| Participants | threshold `t` up to ~**1024** | benchmarked to 8192 signers; bounded #time-slots (2^τ) | committee `N` up to deployment cap (qrysm: 128) |
| Assumptions | "standard lattice": **Hint-MLWE + SelfTargetMSIS** (Hint-MLWE → MLWE) + PRF | **(ring-)SIS + ROM** (Ajtai hash; CR ⇐ SIS) | **MLWE + SelfTargetMSIS (+Module-SIS)** — identical to ML-DSA |
| Formal verification | paper proofs (static/selective corruption) | paper proofs (ROM) | **274 machine-checked lemmas** (EasyCrypt+Coq) + 6 Gobra |
| Key distinction | jointly *produces* one signature under a shared key (threshold) | aggregates many **same-message** sigs valid at one slot (synchronized) | aggregates **independent** signatures into a key/scheme the existing verifier already accepts |

**Source-check notes (corrections applied after literature review).** (a) Venue is **EUROCRYPT 2024**,
not CRYPTO. (b) Threshold Raccoon uses a **trusted dealer**, not DKG (DKG is future work); its 40 KiB
communication is **per signer**; "1024" is the **threshold `t`**; the security reduction is to
**Hint-MLWE + SelfTargetMSIS** (not literally MLWE+MSIS), and it uses **discrete Gaussians**, gives
**static/selective** security only, is **not** round-optimal, and needs no threshold-FHE (PRF one-time
masks). (c) Chipmunk has **four** authors (Herold included); it is a **multi-signature** (same message),
its aggregate is **~136 KB** (8192 signers) — *not* "~5 KiB" and *not* "logarithmic" (keygen/sig scale
**linearly in 2^τ** tree leaves); the **large object is the secret-key state**, the public key is small;
assumptions are **ring-SIS + ROM**.

**Positioning.** Threshold Raccoon answers a different question (a `t`-of-`n` *threshold* over a
*new* scheme, interactive, ~13 KiB) and Chipmunk answers another (a *synchronized same-message
multi-signature*, ~100+ KB aggregate). ML-ADSA's distinguishing properties are (i) the output is a **bona-fide
ML-DSA-87 signature** the *unmodified* FIPS-204 verifier accepts, (ii) **non-interactive,
many-time, decentralized** aggregation with **no trusted aggregator/setup/trapdoor**, and (iii) it
inherits ML-DSA's exact assumptions and Category-5 parameters. The cost is the structural
"homomorphic-but-not-freely-mergeable" property (the FS challenge binds the full participant
commitment), which is also what gives ROS-resistance with **no AGM/OMDL**.

---

## 5. Remediation status — **COMPLETE** (2026-06-11)

All findings in §3 discharged:

- **Source of truth** locked: `formal/count-artifacts.sh` → **43 artifacts / 274 lemmas (242 EC + 32 Coq) /
  36-36** genuineness / 6 Gobra. Successive passes (§6): count-audit 29/134/33 → proof-closure 29/137/34 →
  encoding-conformance 30/153/35 (`ml_adsa_montgomery.ec`) → CT-transcription 31/200/36
  (`ml_adsa_ntt_ct.ec`). Re-verified: `check-all.sh` ALL GREEN, `go-mladsa` builds.
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
- **Threshold Raccoon + Chipmunk** added (source-checked: venue EUROCRYPT 2024, Chipmunk = 4 authors incl.
  Herold, aggregate ~136 KB not ~5 KiB, trusted dealer not DKG, Hint-MLWE/ring-SIS+ROM): paper §2 (+refs
  [dPKM⁺24], [FHSZ23], [FSZ22]), docs/19
  (plain language), docs/32 (MPTC positioning), and §4 above.
- **Historical-iteration docs** (01–03, 05–12, 15, 16, whitepaper) carry dated provenance banners pointing
  here + to docs/30/31/`count-artifacts.sh`; their body numbers are preserved as the historical record.
  (docs/04 is a still-current standalone impossibility result — not bannered.)
- **Public site** re-synced via the new `ml-adsa-site/sync-docs.sh` (36 reference copies refreshed + docs/35
  added to nav; landing-page lemma count 77→200).

---

## 6. Adversarial self-review + proof-closure (2026-06-11)

Four skeptical reviewers probed the proof claims (QROM-A tightness, aggregation norm/cross-terms/hint/
leakage, ROS/concurrent/non-interactive, deterministic-nonce/equiv-class/many-time) against the proofs,
code, and literature. **Cross-checked against the corpus, they found no undisclosed soundness gap**: the
substantive reduction (`msufcma_uncond` / `qrom_eufcma_uncond` → MLWE + SelfTargetMSIS) stands, and the
probed "gaps" are the corpus's already-disclosed standard conventions (the perfect-HVZK kernel shared with
all ML-DSA proofs, with the concrete QRO-reprogramming term *derived* in `ghhm.ec`; the supplied standard
bounds for F-C4/F-C11; the one-time discipline + fault exposure; the algorithm-proof-vs-CIRCL-conformance
boundary; the inherent need for independent cryptanalysis). One over-cautious relabel (F-C11 →
[partly proven]) was tried and reverted — F-C11 uses the same supplied-bound convention as F-C4, so it is
[proven] with the bound disclosed.

To convert two *disclosed-supplied* steps into *end-to-end mechanized* ones, two lemmas were added and
machine-checked (proof-closure pass, counts → 137 / 34-34):

1. **Deployed concurrent security is the EUF-CMA bound, no supplied B** — `ml_adsa_euf.ec :
   concurrent_atomic_uncond`. The deployed scheme is non-interactive/atomic (no open sessions), so its
   signing oracle already models unbounded concurrent atomic queries; concurrent EUF-CMA *is*
   `msufcma_uncond` directly (no ROS term, no supplied bound). (The optional *interactive* commit-reveal
   variant's full concurrent reduction remains the standard supplied argument + pending cryptanalysis —
   the genuine open problem, not faked.)
2. **End-to-end qs-round QROM signing-oracle simulation** — `ml_adsa_qrom_ghhm.ec :
   sign_oracle_mr_equiv` / `sign_oracle_mr_pr_eq`. The proven per-round program-equivalence
   (`reprog_round_equiv`) is lifted by a while-loop coupling to the whole qs-query signing oracle: the
   real-RO signer and the reprogramming HVZK simulator are perfectly indistinguishable, closing the
   "multi-query seam" the `ghhm.ec` header flagged. Genuineness check added (dropping the per-round call
   breaks it) → 53/53.

**Encoding-conformance pass (counts → 153 / 35-35; 30 artifacts).** The "bit-level Montgomery encoding"
residual: new `ml_adsa_montgomery.ec` (16 lemmas, **axiom-free** — even `q·qinv ≡ 1 mod 2³²` is evaluated by
EC) proves both integer reductions the implementations use compute the abstract Z_q ring: (i) the reference
`modQ` (int64 Euclidean reduction, ring-respecting — `modQ_cong`/`modQ_mul`/`modQ_add`), and (ii) the
standard Dilithium **int32 Montgomery** reduction the external FIPS-204 verifiers use (`montred_exact`: exact
÷R; `montred_mont`: `R·montred a ≡ a (mod q)`; `montred_range`: output in (−q,q); `fqmul` butterfly multiply).
+1 genuineness check (a wrong `qinv` constant breaks `montred_exact`).

**CT-transcription pass (counts → 200 / 36-36; 38 artifacts).** The NTT-loop structural transcription is now
source-proved **in full**: new `ml_adsa_ntt_ct.ec` (5 lemmas, **axiom-free**) proves the radix-2 Cooley–Tukey
transform = the DFT over Z_q. `big_even_odd` (the decimation split), `ct_step` (the recurrence DFT_{2m} =
DFT_m(even) + wᵏ·DFT_m(odd)), `ct_butterfly` (its negacyclic ± form X[k]=E+wᵏO, X[k+m]=E−wᵏO — *exactly* the
code's `a[j]=t1+t2; a[j+len]=t1−t2`), and **`ct_correct`** (by induction on the level count: the recursive
multi-level `ct` transform = `dft w a (pow2 lvl) k`, every layer — not just one). +1 genuineness check
(flipping the butterfly minus to plus breaks `ct_butterfly`). With `ml_adsa_ntt.ec` (DFT is
convolution-respecting) and `ml_adsa_ntt_inv.ec` (DFT invertible), the **entire NTT algorithm** is a correct
invertible negacyclic NTT over Z_q. **The residual is now only the *data-layout* realization** — that the
in-place array loop with the bit-reversed twiddle schedule computes this recursive `ct` (index/permutation
bookkeeping, no remaining mathematical content), byte-validated against CIRCL + go-qrllib. Independent human
cryptanalysis (esp. the interactive concurrent variant) remains the decisive gate.

**CRT-split pass (counts → 164 / 37-37; 38 artifacts).** New `ml_adsa_ntt_crt.ec` adds the *stride-structure*
justification: `crt_split` proves the in-place butterfly `a_lo ± s·a_hi` computes the **CRT residues**
`a mod (Xᵐ ∓ s)` (at the evaluation level — `pevalC`, `pevalXn`, `peval_scale` + the `peval` ring-homomorphism
from `ntt.ec`), i.e. each butterfly preserves evaluation at the roots `ρᵐ=±s`. This is the mathematical reason
the in-place *stride* loop is correct (it maintains polynomials-mod-CRT-factors), composing down the factor
tree to the per-root evaluations. +1 genuineness (replacing the high half `a_hi` by `a_lo` breaks `crt_split`).

**Flat-array factor-tree pass (counts → 200 / 38-38; 38 artifacts).** `ml_adsa_ntt_crt.ec` is extended from
the abstract split to the **literal flat array**, closing the data-layout content that was previously only
byte-validated:
- `polyMXnE` — the general monomial shift `((Xᵐ)·p).[k] = p.[k−m]` (by induction on `m`).
- `polyL_cat` — a flat block read as a polynomial splits exactly: `polyL (lo ++ hi) = polyL lo + Xᵐ·polyL hi`
  (`m = size lo`). This is the *array* low/high split, now a proved coefficient identity.
- `bfly` / `polyL_bfly` — the array butterfly `bfly s lo hi = map (λ(x,y). x + s·y) (zip lo hi)` (the in-place
  write-back) read as a polynomial **is** `polyL lo + s ** polyL hi` — the scalar-combination side of `crt_split`.
- **`ntt_tree_correct`** — defining `ntt_tree` (the in-place transform: split halves via `take`/`drop`, `bfly`
  write-back on the `+s` / `−s` legs, recurse, concatenate in array order) and `wf` (the twiddle schedule's
  defining property: at every node the low subtree's roots satisfy `ρᵐ=s` and the high subtree's `ρᵐ=−s`), the
  capstone proves by structural induction that **every flat output slot holds `peval (polyL a)` at that leaf's
  root** — i.e. the in-place loop computes the per-root evaluation vector. +1 genuineness (using `+s` instead of
  the negated twiddle `−s` on the high leg breaks the residue match).

With this, the flat-array data-layout/permutation argument is a *proved theorem* (`ntt_tree_correct`), not a
hand-wave. **Honest residual (two narrow items, both no-new-math):** (a) the *iterative* in-place loop (the
literal triple-nested `while` with the `zetas[k]=ζ^brv8(k)` array and stride mutation) realizes the recursive
`ntt_tree` — an imperative↔recursive Hoare-logic refinement; and (b) FIPS-204's specific bit-reversed zeta
schedule satisfies `wf` — a concrete instantiation (build the 8-level tree of 256th roots and discharge the
`ρᵐ=±s` conditions). Both remain byte-validated against CIRCL + go-qrllib + pinned KATs. Independent human
cryptanalysis (esp. the interactive concurrent variant) remains the decisive gate.

**NTT residuals (a)+(b) closed + norm-budget study (counts → 180 / 40-40; 38 artifacts).**
`ml_adsa_ntt_crt.ec` gains both previously-open NTT items: **(b)** `negtree`/`negtree_root`/`negtree_wf`/
`negtree_computes_eval` prove FIPS-204's bit-reversed `ζ=1753` negacyclic schedule satisfies `wf` (built from
a primitive root `ω` with `ω²⁵⁶=−1`; parameterized, no axiom); **(a)** `is_leaf`/`expand`/`forest_step`/
`eval_forest` + `expand_eval`/`forest_step_inv`/`eval_forest_leaves`/`forest_iter_eval`/`forest_loop_correct`
model the *iterative, level-by-level* loop and prove **BFS = DFS** — one level preserves the transform, so
once every block is a size-1 leaf the flat array **is** `ntt_tree t a`. +1 genuineness (expand's high-leg `+s`
instead of `−s` breaks `forest_step_inv`). **New `docs/37` (norm-budget study)** +
`go-mladsa/normbudget_test.go` answer the secure-`N` gap (`§6.4`): the summed `z* = Σyᵢ + c·Σs1ᵢ` stays under
the unmodified verifier's `γ1−β = 524168` ceiling for **provable** `N ≤ 1844` (`2⁻⁴⁰`) / `683` (`2⁻¹²⁸`)
(tight Hoeffding), and **empirically** through `N = 4096` with zero abstentions (observed max ≈ half the
ceiling; `√N` law reaches the ceiling near `N ≈ 16 000`). Independent human cryptanalysis (esp. the
interactive concurrent variant, and the rejection-free leakage question) remains the decisive gate.

**NTT loop fully closed — termination + literal index arithmetic (counts → 200 / 42-42; 38 artifacts).**
`ml_adsa_ntt_crt.ec` adds **termination** (`tdepth`/`forest_step_depth`/`forest_iter_leaves`/
`forest_loop_complete` — `tdepth t` levels make the frontier all-leaves; `tdepth_negtree = size l = 8`), the
unconditional end-to-end **`fips_ntt_loop`** (8 levels on the FIPS-204 schedule = the per-root eval vector),
and the **literal mutable-array model** (`jloop` = the Go inner loop with exact `a[j]`/`a[j+m]` indices;
`jloop_eq` proves it equals the block butterfly; `jloop_forest` ties it to one `forest_step`; `flat_one_level`
gives the one-level array output `lo+s·hi ‖ lo−s·hi`). +2 genuineness (drop `tdepth`'s `+1`; flip `jloop`'s
high-write `−`→`+`). The NTT now has **no algorithmic, index, or termination content left** — the sole
residual is the `while`-loop control-flow scaffolding (bounds + `k`-counter over `zetas[k]`), the most
mechanical model↔code transcription, byte-validated. Independent human cryptanalysis remains the decisive gate.

---

## 7. Opsec note

Outward publication (pushes to `pq-cybarg/ml-adsa` + the public site) is performed only on explicit
go-ahead, authored `pq-cybarg <resistant@tuta.com>`, UTC timestamps, ghid-locked.
