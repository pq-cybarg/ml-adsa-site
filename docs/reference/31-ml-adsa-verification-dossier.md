# ML-ADSA — End-to-End Verification Dossier

Companion to the formal specification (`docs/30`) and the publication/NIST roadmap (`docs/32`). This
dossier ties **specification ↔ code ↔ machine-checked proofs ↔ tests** into a single auditable argument —
"verification of the entire process" — and states, honestly, what each piece of evidence does and does not
establish.

> Reproduce everything: `formal/check-all.sh` (36 prover artifacts, ALL GREEN), `formal/genuineness.sh`
> (50 weaken-and-break checks), `formal/gobra/run.sh` (6 code-level theorems), `go test ./...` in
> `go-mladsa/` and the qrysm fork, and the three live demos (`cmd/mladsa-devnet`, `mladsa-hieragg`,
> `mladsa-epochnet`).

---

## 1. The assurance argument (three surfaces, with boundaries)

ML-ADSA's correctness/security assurance rests on three deliberately distinct surfaces. None alone is
sufficient; together they cover algorithm, implementation, and code structure. We state each boundary
explicitly so reviewers are not misled.

| Surface | What it establishes | What it does NOT establish |
|---|---|---|
| **A. Algorithm-level machine-checked proofs** (`formal/*.ec`, `*.v`) | The *scheme/algorithm*, as modeled, has the claimed security: tight EUF-CMA/SUF-CMA reductions to MLWE+SelfTargetMSIS(+Module-SIS) in ROM, a QROM capstone, many-time, ROS-resistance, hiding, decision integrity, equivalence-class hardness. Each rests on named axioms isolating exactly the cryptographic content. | That the **Go source** implements the model line-for-line; that lattice arithmetic is functionally correct at the bit level (that is surface B/C). |
| **B. Implementation conformance** (`go-mladsa/`, qrysm copies, KATs) | Every aggregate is a **byte-exact** ML-DSA-87 `(pk 2592, sig 4627)` triple that the **unmodified** CIRCL and theQRL/go-qrllib FIPS-204 verifiers accept; pinned KATs reproduce across both implementations; rotation KATs show no leak. | A *proof* of the Go source (this is testing + cross-implementation measurement, except where surface C applies). |
| **C. Code-level structural proofs** (`formal/gobra/integrity.go`) | Six Gobra theorems prove the *structural* invariants of the Go logic: Merkle pad-to-pow2, decoy weight-0 membership (F-C7), Merkle non-equivocation binding (F-C9), injective framing/domain separation (F-C2), aggregation linearity (F-C1/F-DEC), one-time rejection (N1). | Bit-level *functional correctness of the Montgomery NTT* (the fast polynomial multiply) — see boundary note below. |

**The lattice-arithmetic content is now PROVEN from first principles (not just cross-checked).** The
historically "axiomatized lattice content" had three parts; all three mathematical cores are now
machine-checked:
- **Perfect-HVZK masking change-of-variables** — `ml_adsa_masking.ec` (`reject_uniform`,
  `masking_perfect_concrete`): the accepted rejection-sampled response is uniform on the norm window,
  independent of the secret. Rests only on `0 ≤ β ≤ γ1-1`.
- **Rounding / hint decomposition correctness** — `ml_adsa_rounding.ec` (`decompose_reconstruct`,
  `power2round_correct`, `rlow_bound`, `highlow_id`, `usehint_makehint`): the FIPS-204 §2.4 Euclidean
  decomposition identities the verifier relies on. Rests only on integer arithmetic.
- **NTT convolution theorem** — `ml_adsa_ntt.ec` (`peval_add`, `peval_mul`, `ntt_add_nth`,
  `ntt_mul_nth`): the evaluation map is a ring homomorphism, so `NTT(p·q) = NTT(p) ⊙ NTT(q)`
  coordinatewise. Built over EC's real polynomial ring `Poly.PolyComRing`, derived from the coefficient
  Cauchy product `polyME` + the bigop calculus (exchange/shift) — **no axiom**.
- **NTT inversion (CRT / DFT round-trip)** — `ml_adsa_ntt_inv.ec` (`geo`, `orth`, `dft_inv`):
  `INTT∘NTT = id`, via the orthogonality of the roots of unity — derived from a telescoping geometric
  sum + the integral-domain property (no zero divisors), over a primitive n-th root. So **NTT is a
  complete ring isomorphism** (homomorphism `+` invertible), both halves machine-checked.

**Bottom line on boundaries (precise).** The cryptographic *design* is machine-checked; **all four**
algorithm-level lattice facts — masking change-of-variables, rounding/hint decomposition, NTT convolution,
and NTT inversion — are source-proved from first principles. The **bit-level encoding** is now also begun
and machine-checked at the arithmetic level (`ml_adsa_montgomery.ec`, axiom-free): both integer reductions
the implementations use are proven to compute the abstract `Z_q` ring — the reference int64 Euclidean
reduction `modQ` (ring-respecting), and the standard Dilithium **int32 Montgomery** reduction the external
FIPS-204 verifiers use (`montred_exact`/`montred_mont`/`montred_range`/`fqmul`, with `q·qinv ≡ 1 mod 2³²`
evaluated by EC). The **structural transcription** of the NTT loop is now source-proved in **full**
(`ml_adsa_ntt_ct.ec`, axiom-free): not just one butterfly layer but the **entire multi-level Cooley–Tukey
transform = the DFT**, for any depth. `ct_step` is the radix-2 recurrence (DFT_{2m} = DFT_m(even) +
wᵏ·DFT_m(odd)); `ct_butterfly` its negacyclic ± form X[k]=E+wᵏO, X[k+m]=E−wᵏO (*exactly* the code's
`a[j]=t1+t2; a[j+len]=t1−t2`); and **`ct_correct`** proves by induction on the level count that the recursive
`ct` transform equals `dft w a (pow2 lvl) k` — the complete algorithm, every layer. The **flat-array
data-layout** is now also source-proved (`ml_adsa_ntt_crt.ec`, axiom-free): `polyL_cat` shows the literal
array low/high split `polyL (lo ++ hi) = polyL lo + Xᵐ·polyL hi`; `polyL_bfly` shows the in-place butterfly
write-back `bfly s lo hi = map (λ(x,y). x+s·y) (zip lo hi)` read as a polynomial **is** `polyL lo + s ** polyL hi`;
and the capstone **`ntt_tree_correct`** proves by structural induction that the flat factor-tree transform
(`take`/`drop` halves → `bfly` write-back on the `+s`/`−s` legs → concatenate in array order) computes the
per-root evaluation vector — every output slot holds `peval (polyL a)` at that leaf's root — for any
well-formed (`wf`) twiddle schedule. **Both items that were previously open are now source-proved too:**
**(a)** the *iterative, level-by-level* loop (the BFS order the Go code actually uses) is shown to compute
the same transform as the depth-first recursion — `forest_step` performs exactly one `length`-level (one
butterfly on every block, twiddles consumed left-to-right = the `zetas[k]` order), `forest_step_inv` proves
one level **preserves** the eventual transform, and `forest_loop_correct` concludes that once the loop has
reduced every block to a size-1 leaf the flat array **is** `ntt_tree t a` (BFS = DFS); and **(b)**
**FIPS-204's own bit-reversed `ζ=1753` schedule satisfies `wf`** — `negtree`/`negtree_wf`/`negtree_root`
build the negacyclic CRT factor tree from a primitive root `ω` (`ω²⁵⁶=−1`) and discharge `wf`, so
`negtree_computes_eval` gives the per-root evaluation vector for the real schedule (parameterized by `ω` and
its one property — no axiom; the concrete `1753²⁵⁶≡−1 mod q` is the parameter-layer fact `ntt_inv.ec` already
uses). **Termination is now proved too:** `tdepth`/`forest_step_depth`/`forest_iter_leaves` show every block
becomes a size-1 leaf after `tdepth t` levels, `tdepth_negtree` gives `tdepth (negtree l …) = size l` (= 8
for n=256), so `forest_loop_complete` and the end-to-end **`fips_ntt_loop`** are *unconditional* — running the
level-loop `size l` times on the FIPS-204 schedule yields the per-root evaluation vector. **The literal
absolute-index arithmetic is now machine-checked too:** `jloop z m a` transcribes the Go inner loop with its
*exact* indices (`output[j] = a[j] + z·a[j+m]`, `output[j+m] = a[j] − z·a[j+m]`), and `jloop_eq` proves this
in-place pass equals the block butterfly `bfly z lo hi ‖ bfly (−z) lo hi`, with `jloop_forest` tying it to one
`forest_step`. **The bit-reversed twiddle precompute is now machine-checked too:** `brv8 = bsrev 8` (the
Go `zetas[k] = ζ^brv8(k)` exponent) is proved to satisfy *exactly* `negtree`'s negacyclic twiddle recursion —
`brv8 1 = 2⁷`, `brv8 (2k) = brv8 k / 2`, `brv8 (2k+1) = brv8 k / 2 + 2⁷` (`brv8_lo`/`brv8_hi`/`brv8_1`/
`brv8_twiddle_rec`, via EasyCrypt's `BitReverse`) — so the `k`-counter walking the precomputed `zetas` array
enumerates the tree's twiddles in heap/BFS order. **The literal `while`-loop transcription is now also
machine-checked:** `ml_adsa_ntt_imp.ec` gives all three nested `while`s as EasyCrypt `proc`s over a mutable
array (an `int->coeff` map, `a.[i] <- v` = `aset a i v`) — `NTTimp.jl` (inner butterfly = `jfun`,
`jl_correct`), `NTTimp.sl` (the start-loop = one full level = `levelf`, `sl_correct`), and `NTTimp.ntt`
(the len-loop = the level-by-level composition = `applyf`, `ntt_correct`) — each proved by Hoare logic with
explicit loop invariants (the locality lemmas `levelf_local`/`applyf_local` carry the `[0,256)` array
footprint across levels). What now remains is only the **encoding bridge**: that the flat `int->coeff`
array composition (`applyf`) and the list-block model (`forest_step`/`fips_ntt_loop`, already shown to
compute the per-root evaluation vector) are two encodings of the *same* level-loop — the
absolute-index↔block correspondence (`jloop_eq`/`forest_step_jloop`) lifted across all levels. That
residual is pure model↔model encoding (the file's own `fips_ntt_loop` comment calls flat↔list "pure
syntax"), also covered operationally by the byte-exact KATs against CIRCL + go-qrllib. This whole boundary is a pure
**implementation-conformance** matter, **not a security assumption** — the algorithm-level proofs never
invoke the NTT.

---

## 2. Prover toolchain and headline result

| Prover | Where | Count | Result |
|---|---|---|---|
| EasyCrypt (classical) | opam switch `discus-verified` | 23 files | green |
| EasyCrypt (QROM / EasyPQC) | opam switch `easypqc`, via `ec-quantum.sh` | 5 files | green |
| Coq / Rocq (`nsatz` over R) | system | 5 files | green |
| **Total prover artifacts** | `formal/check-all.sh` | **32** | **ALL GREEN** |
| Gobra (ETH, Docker) | `formal/gobra/` | 6 theorems | green |
| Genuineness (weaken-axiom → proof breaks) | `formal/genuineness.sh` | **50** | 50/50 |

Lemma tally: **212 admit-free EasyCrypt lemmas + 32 Coq lemmas/theorems = 244 machine-checked**, plus 6
Gobra code-level theorems. (Artifact *file* count is 32; lemma count is 200 — both framings are used in
the literature; do not conflate them. All figures are produced by `formal/count-artifacts.sh`, the single
source of truth.)

> **Discrepancy note.** Earlier prose used a deprecated lemma tally of "77 (= 72 EC + 5 Coq)", which
> conflated *5 Coq files* with *5 Coq lemmas* (Coq has 32 lemmas/theorems) and predated the masking /
> rounding / NTT / NTT-inversion / GHHM additions; older docs also quote stale artifact counts (23, 24).
> The authoritative current numbers are those of `formal/count-artifacts.sh`: **36 artifacts**
> (26 classical + 5 quantum + 5 Coq) and **244 lemmas** (212 EC + 32 Coq), with `genuineness.sh` at 50/50.
> The cross-consistency audit `docs/35` reconciles every document to these.

---

## 3. Spec → Code → Proof → Test traceability matrix

Lemma names and locations below were verified against the repository. "Prover" abbreviations: EC = EasyCrypt
classical, ECq = EasyCrypt QROM, Coq = Coq/Rocq, Gob = Gobra.

| # | Property / algorithm (spec §) | Go symbol(s) | Machine-checked lemma (file:loc) — prover | Test / KAT |
|---|---|---|---|---|
| 1 | Content-key refresh independence (F-C2; §4) | `ContentKeyDerive`, `prf` (`refresh.go`) | `ml_adsa_F_refresh.ec` — EC; framing `integrity.go:framingRoundTrip` — Gob | KAT_Primitives (`kat_test.go`) |
| 2 | Many-time / Q-independence (F-C4; §4) | `ContentKeyDerive`, `DeriveNonce` | `ml_adsa_F_manytime.ec : F_manytime_bound` — EC | KAT_Rotation |
| 3 | Deterministic nonce + one-time (N1/N2; §4) | `DeriveNonce`, `DurableOneTimeGuard` (`onetime_durable.go`) | `integrity.go:reuseRejected` — Gob | `onetime_durable_test.go` |
| 4 | Core aggregate correctness (§5) | `AggregateRejfree`, `AggregateM1` (`mladsa.go`) | `ml_adsa_identity.v` (reconstruction identity) — Coq | `attestation_aggregation_test.go` |
| 5 | Decentralized combine = secret-key combine (§5.3) | `CombineFromPublic`, `SharedChallenge` (`decentralized.go`), `ConsensusAggregate(Labeled)` (`consensus.go`) | reconstruction identity — Coq; EUF reduction — EC | `TestDecentralized_EqualsAggregateF` |
| 6 | Verify = FIPS-204 (§5.4) | `Verify` (`mldsa87.go`) | inherited by T1/T6 (verifier is the model's `verify`) | CIRCL + go-qrllib byte-accept |
| 7 | EUF-CMA (T1; §8.2) | aggregate + verify | `ml_adsa_euf.ec : msufcma_uncond` (≈ line 200) — EC | — |
| 8 | SUF-CMA (T2) | aggregate + verify | `ml_adsa_suf.ec : sufcma_uncond` — EC | — |
| 9 | Rogue-key collapse (T3, F-C5) | `MemberKeyGen`, `VerifyPoP` (`construction_f.go`) | `ml_adsa_rogue_proof.ec : rogue_reduces_to_single` — EC | `f_construction_test.go` |
| 10 | No-new-power / extraction (T4) | combine | `ml_adsa_nnp_proof.ec : new_power_reduces_to_sis` — EC | — |
| 11 | Concurrent / ROS-resistance (T6) | commit-reveal flow | `ml_adsa_F_concurrent.ec : unbiasable_challenge`, `challenge_adversary_independent` — EC | — |
| 12 | Hiding (T7, Module-LWE) | `CommitWeight`, commitment (`decoy.go`, `commit.go`) | `ml_adsa_F_hiding.ec : commit_hiding` — EC | `decoy_test.go` |
| 13 | Decision integrity, weight-0 decoys (T8, F-C7) | `BuildRegistry`, `Weight`, `FilterRecognized`, decoys (`construction_f.go`, `decoy.go`) | Coq `ml_adsa_F_decisions.v` (section-scoped); EC; Gob `filterRecognized`/`isMember` | `decisions_modes_test.go`, `decoy_test.go` |
| 14 | Epoch key tree / non-equivocation (F-C8/C9; §6.2) | `EpochKeyTreeBuild`, `VerifyEpochRoot`, `VerifyContentInTree` (`construction_f.go`, `merkle.go`, `accessors.go`) | Coq `ml_adsa_F_provenance.v` (section-scoped); Gob `merkleBinding` | `epochtree_test.go` |
| 15 | Equivalence-class hardness, ROM (T9) | `SignaturesEquivalent` (`mladsaconsensus/equivalence.go`) | `ml_adsa_euf.ec : equiv_class_guess_bound` (≈ line 193) — EC | `equivalence_test.go` |
| 16 | QROM EUF-CMA tight / lossy (T10/T11) | aggregate + verify | `ml_adsa_qrom.ec : qrom_eufcma_uncond` (≈437), `qrom_eufcma_lossy` (≈476), `reprog_at_our_types` — ECq; O2H `ml_adsa_qrom_o2h.ec`; reprog DERIVED `ml_adsa_qrom_ghhm.ec : ghhm_hybrid` (cross-check `ml_adsa_qrom_reprog.ec`) | — |
| 17 | Equivalence-class hardness, QROM (T12) | — | `ml_adsa_qrom.ec : qrom_equiv_class_uncond` (≈531) — ECq | — |
| 18 | Order/grouping byte-identity (§7) | `CoeffSumL/K`, `AttestationCombineInputs` (`accessors.go`, `consensus.go`) | sum permutation-invariance (algebraic; Coq identity basis) | `hieragg_math_test.go`; live `cmd/mladsa-hieragg` |
| 19 | Domain-portability / cross-chain (§) | aggregate with `ctx` | Coq `ml_adsa_identity.v` domain invariant; `ml_adsa_F_bridge.ec` | KATs |
| 20 | MLWE key-indistinguishability hop | key gen | `ml_adsa_mlwe_hop.ec`; ROM `ml_adsa_F_euf.ec`; masking `ml_adsa_F_zk.ec`; regimes `ml_adsa_regimes.ec` | — |
| 21 | Perfect-HVZK rejection-sampling change-of-variables (the masking kernel, formerly axiomatized) | signer response `z=y+c·s1` | `ml_adsa_masking.ec : reject_uniform`, `perfect_hvzk_coeff`, `masking_perfect_concrete` — EC (DERIVED from first principles) | window-count genuineness check |
| 22 | Rounding/hint decomposition correctness (FIPS-204 §2.4) | `Power2Round`/`Decompose`/`UseHint` | `ml_adsa_rounding.ec : decompose_reconstruct`, `power2round_correct`, `usehint_makehint` — EC (DERIVED) | off-by-one genuineness check |
| 23 | NTT convolution theorem (evaluation ring homomorphism) | `NTT`/`INTT` fast multiply | `ml_adsa_ntt.ec : peval_mul`, `ntt_mul_nth` (and `peval_add`/`ntt_add_nth`) — EC (DERIVED from `polyME`) | `exact peval_mul` genuineness check |
| 24 | NTT inversion (CRT / DFT round-trip, `INTT∘NTT = id`) | `INTT` | `ml_adsa_ntt_inv.ec : dft_inv` (via `orth` orthogonality + `geo` geometric sum) — EC (DERIVED) | root-primitivity genuineness check |

---

## 4. Assumption base and named in-proof axioms

Every theorem reduces to one or more of: decisional **MLWE**, **SelfTargetMSIS**, **Module-SIS**, **PRF**
security, **collision-resistant hash**. The reductions isolate the cryptographic content into a small set
of named axioms; each axiom is exercised by a `genuineness.sh` check that *weakens it and confirms the
proof breaks* (so the axiom is load-bearing, not vacuous).

| Axiom (file) | Abstracts | Genuineness check |
|---|---|---|
| `mlwe_assumption` (euf/qrom) | decisional MLWE advantage `adv_mlwe` | weaken → reduction breaks |
| `extract_sound` / `extract_or_break` (euf/nnp) | a PoP-valid verifying forgery IS a SelfTargetMSIS/Module-SIS solution | weaken conclusion → breaks |
| `masking_ok` / `masking_perfect` (euf/zk) | perfect HVZK masking (rejection output depends only on pk) — **kernel now DERIVED in `ml_adsa_masking.ec`** (`reject_uniform`), not just abstracted | weaken → breaks (+ window-count check on the derivation) |
| `rogue_collapse` (rogue) | PoP knowledge-soundness + key-agg linearity | weaken → breaks |
| `A_regularity`, `commit_binding` (concurrent) | leftover/regularity of `A`; commitment binding (ROS defense) | weaken → breaks |
| `ghhm_hybrid` / `reprog_ghhm` (qrom_ghhm) | DERIVED distinct-per-query GHHM21 loss `qs·(qh+1)/|from|` from proven per-round resampling (`LambdaReprogram.main_theorem`) + distinct-query bound (`T_Distinct.bound_distinct`, Thm 6.1) | derived; Thm 6.1 + `Ynontriv` only |
| `keygen_key_ok`, `dsecret_ll` (euf) | keygen well-formedness, secret-distribution losslessness | weaken → breaks |

Because `pk* = (ρ, HighBits(Σ tᵢ))` is a sum of MLWE samples (itself an MLWE sample), the aggregate
inherits ML-DSA-87's Category-5 hardness *exactly* — there is no aggregation-specific hardness assumption.

---

## 5. The three runnable "process" verifications

"Verification of the entire process" is not only static — it is exercised live, end to end, across real OS
processes with real go-qrllib verification (no mocks, no string-print fakes):

- **`cmd/mladsa-devnet`** — N node processes (each beacon+validator) each self-combine to the
  byte-identical `σ*` via the §5 decentralized procedure, with per-commit epoch-key-tree Merkle-path
  authentication; equivocators and sybils are excluded; every node verifies with both the in-house and the
  go-qrllib verifier.
- **`cmd/mladsa-hieragg`** — proves order/grouping independence: two aggregators combine the same users via
  different partitions/orders → byte-identical `σ*`; a judge process independently re-derives `pk*`,
  byte-compares, and re-verifies natively; negative controls (drop signer, tamper `σ*`) are rejected.
- **`cmd/mladsa-epochnet`** — proves the full epoch-key-tree glue: validators publish bundles; a node
  ingests/validates them into a gossip cache, builds a **real beacon state** from the published
  registration keys, installs the resolver at the epoch boundary, combines, and verifies through the real
  consensus path + go-qrllib; a forged bundle is rejected and the signer excluded while the honest set
  still verifies.

---

## 6. Residual / open items (honest)

1. **Independent external cryptanalysis** — not yet performed; the decisive standardization gate (`docs/32`).
2. **Lattice-arithmetic functional source-proof** — NTT/rounding correctness is measured + dual-reference
   cross-checked (CIRCL, go-qrllib), not source-proved; the Gobra theorems cover the *structural* (non-
   arithmetic) logic.
3. **Tight QROM-B** — the rejection-free variant's GHHM21 distinct-per-query adaptive-reprogramming bound
   is now DERIVED in-prover (`ml_adsa_qrom_ghhm.ec`): the tight linear loss `reprog_ghhm qs qh =
   qs·(qh+1)/|from|` is built from the *proven* per-round perfect resampling
   (`LambdaReprogram.main_theorem`) + the elementary distinct-query bound (`T_Distinct.bound_distinct`,
   Thm 6.1), replacing the imported Zhandry semi-constant-distribution axiom. Nothing about the bound is
   assumed — the per-round hypothesis of `ghhm_hybrid` is discharged hypothesis-free by
   `ghhm_multiround_perfect` (each resampling round's gap is *proven* 0 via `reprog_single_perfect`), and
   the signing-round program-equivalence (real-RO signer ~ reprogramming HVZK simulator) is itself
   machine-checked (`reprog_round_equiv`/`reprog_round_pr_eq`, concrete `ReprogRound` modules). The
   remaining input is the lattice response's HVZK-simulatability — *not a gap and not aggregation-specific*:
   it is ML-DSA's own `masking_ok` (= `masking_perfect`), with consequences machine-checked classically
   (`zero_leakage_perfect_A`) AND quantumly (`sq_perfect`), and the aggregate→single-signer reduction
   machine-checked (`F_zk_per_content`, `session_simulatable`); only ML-DSA's rejection-sampling
   distribution identity is left to the lattice-arithmetic boundary (Formosa-Crypto scope, surface B/§6
   below), inherited from ML-DSA, not introduced. Standing reprogramming-path axioms: Thm 6.1 + `Ynontriv`.
   Construction A (perfect masking) needs none of it and is tight and unconditional (`qrom_eufcma_uncond`).
4. **Coq theorem scoping (reproducibility note)** — the Coq results (`option_separation`,
   `threshold_over_members`, `no_equivocation`, `key_indep_of_ctx`, `setup_public_only`, etc.) are real
   `Theorem`/`Corollary`s but live inside `Section … End` blocks over abstract typed interfaces (injective
   hash, registry predicate, abstract HighBits); a top-level `grep "^Theorem"` will not find them. This is
   the intended boundary (structure proved over abstract primitives) and is flagged for auditors.
5. **Parameter sets** — all three instantiated and CIRCL-cross-validated (ML-ADSA-44/65/87 at NIST
   Categories 2/3/5; `go-mladsa` `Params44/65/87` + parameterized keygen/sign/aggregate/verify, `docs/40`).
   Remaining is the official **ACVP-vector submission** for -44/-65 (the ACVP wire format is a submission
   deliverable; KATs and ACVP-shaped JSON exist for -87).

---

## 7. How to reproduce (commands)

```
# Algorithm proofs (36 artifacts): EasyCrypt classical+QROM + Coq
cd formal && zsh check-all.sh                 # → ALL GREEN (26 classical + 5 quantum + 5 Coq = 36)
zsh count-artifacts.sh                         # → 36 artifacts, 244 lemmas (212 EC + 32 Coq), 50/50, 6 Gobra
zsh genuineness.sh                            # → 50/50 (weaken axiom ⇒ proof breaks)
# Code-level structural proofs (Gobra, Docker)
cd formal/gobra && zsh run.sh                 # → 6 theorems, "Gobra found 0 errors"; zsh genuineness.sh → 5/5
# Implementation conformance + KATs (CIRCL + go-qrllib byte-accept)
cd go-mladsa && go test ./...
cd qrl-integration/ml-adsa/qrysm && go test ./mladsa/ ./mladsaconsensus/ ./mladsalegacy/
# Live, real-process, end-to-end process verification
zsh cmd/mladsa-devnet/run-devnet.sh           # decentralized identical σ*, equivocator/sybil excluded
zsh cmd/mladsa-hieragg/run-hieragg.sh         # order/grouping byte-identity + negatives
zsh cmd/mladsa-epochnet/run-epochnet.sh       # full epoch-key-tree glue + forged-bundle exclusion
```

**Conclusion.** The cryptographic design is machine-checked and admit-free against ML-DSA's own
assumptions in ROM and QROM; the implementation is byte-anchored to two independent FIPS-204 references and
KAT-pinned; the non-arithmetic code structure is Gobra-proved; and the full decentralized process is
demonstrated live with real verification. The remaining gaps (independent review, lattice-arith source
proof, tight QROM-B, more parameter sets) are itemized and none undermines the core claims.
