# 36 — ML-ADSA Cryptanalysis Review Packet (for independent reviewers)

> **What this is.** A self-contained packet inviting and structuring **independent cryptanalysis** of
> ML-ADSA. Machine-checked proofs establish the reductions *as modeled*; they do **not** replace human
> cryptanalysis, which we regard as the decisive gate before any deployment or standardization. This
> packet tells a reviewer exactly what is claimed, what is proven and how, what is **not** proven, where
> to attack, and what would falsify the scheme. We want to be wrong early if we are wrong.

Compiled 2026-06-11. Companion to: spec `docs/30`, verification dossier `docs/31`, research paper
`paper/ml-adsa.md`, consistency audit `docs/35`. Reproduce numbers with `formal/count-artifacts.sh`.

---

## 0. TL;DR for the reviewer

ML-ADSA aggregates `N` ML-DSA-87 (FIPS-204) signatures on a **common message** into **one byte-exact
ML-DSA-87 signature** that the **unmodified FIPS-204 verifier** accepts under a summed key, by **summing
Fiat–Shamir responses** over a **shared challenge**: `z* = Σ zᵢ`, `t* = Σ tᵢ`, `c̃* = H(μ ‖ HighBits(Σ wᵢ))`.
No trusted setup, no trapdoor, no proof system, no aggregator. Security is claimed to reduce to **exactly
ML-DSA's assumptions** (MLWE, SelfTargetMSIS, Module-SIS) at Category 5, in ROM and QROM.

**The five things we most want attacked** (details in §6):
1. **The summed-response forgery surface** — does binding `c̃*` to the *full* `W*` really stop an adversary
   from crafting a verifying `(c̃*, z*, h*)` from chosen/observed partial contributions?
2. **Concurrent / ROS** for the *interactive* commit-reveal variant (the deployed scheme is non-interactive
   and atomic — see §6.2; the interactive variant is where the genuine open question lives).
3. **Deterministic-nonce safety** under faults / one-time-discipline failure (key recovery on nonce reuse).
4. **The norm budget / cohort cap** — is the secure `N` honestly stated, and is the rejection-free
   (Construction B) leakage really negligible, not just small?
5. **The perfect-HVZK kernel** (`masking_ok`) — the one cryptographic primitive left axiomatic (shared with
   all ML-DSA proofs); is our use of it sound for the *aggregate*?

---

## 1. Construction (concise; normative spec is `docs/30`)

Parameters: ML-DSA-87, `q=8380417`, `n=256`, `(k,ℓ)=(8,7)`, `η=2`, `τ=60`, `β=120`, `γ1=2¹⁹`,
`γ2=(q−1)/32`, `d=13`, `ω=75`, `ζ=1753`; `pk=2592 B`, `sig=4627 B`; Category 5.

Each signer `i` has an ordinary ML-DSA key `(ρ shared, t_i = A·s1_i + s2_i)`, `A = ExpandA(ρ)`. To aggregate
on common message `m` (domain/context `ctx`):
1. each signer derives a **deterministic** nonce `y_i = DeriveNonce(seed_i, C)` (PRF; `C` the content label)
   and commitment `w_i = A·y_i`;
2. the public combiner forms `W* = Σ w_i`, `pk* = (ρ, HighBits(Σ t_i))`, `μ = H(H(pk*) ‖ ctx ‖ m)`,
   `c̃* = H(μ ‖ HighBits(W*))`, `c = SampleInBall(c̃*)`;
3. each signer returns `z_i = y_i + c·s1_i` (with the FIPS-204 bound/hint discipline); the combiner sets
   `z* = Σ z_i`, builds the hint `h*` so `UseHint(h*, A·z* − c·t1*·2^d) = HighBits(W*)`;
4. output `σ* = (c̃*, z*, h*)`. **`Verify(pk*, m, σ*)` is the unmodified FIPS-204 verifier.**

Layers (Construction F): **L1** per-content key/nonce *refresh* (PRF) for many-time security; **L2** epoch
**Merkle key-tree** for non-equivocation/accountability; **L3** registry + **proof-of-possession** for
rogue-key resistance; a one-time discipline (N1/N2) on `(signer, C)`; a ZKP-free decoy mechanism for
signer-set privacy. Two masking regimes: **A** (bit-zero / per-signer rejection, *perfect* HVZK, small
cohort) and **B** (wide masks, rejection-free, *computational* HVZK, the regime used for the N=1000 demos).

---

## 2. Threat model & security goals

- **Adversary:** chooses messages, sees a signing oracle (classical), controls all but one honest signer
  (with valid PoP), and — in QROM — has superposition access to the Fiat–Shamir hash. Static corruption.
- **Goals claimed:** EUF-CMA and SUF-CMA of the aggregate (forgery = a verifying `σ*` on an un-queried `m`
  with a PoP-valid cohort); **equivalence-class** hardness (producing *any* verifying `σ*` for fixed
  `(pk*, m)` is as hard as one ML-DSA forgery); **many-time** (advantage not degrading beyond the standard
  multi-instance union with the number of contents); **concurrent** security; **rogue-key** resistance;
  **non-equivocation**; **signer-set privacy** (decoys, computational/Module-LWE).
- **Out of scope of the *proofs* (must be assessed by review/engineering):** side-channels and fault
  injection (deterministic-nonce exposure, shared with EdDSA); the one-time state being correctly enforced;
  parameter/cohort operational limits.

---

## 3. Claims, reductions, and assumptions (what to check)

| # | Claim | Reduction (file:lemma) | Bottoms out in |
|---|---|---|---|
| C1 | Aggregate correctness (the summed σ* verifies) | `ml_adsa_identity.v` (algebraic identity, N=2/10/100/1000) + Go/CIRCL byte-accept | — (functional) |
| C2 | EUF-CMA, tight, no N-loss (Constr. A) | `ml_adsa_euf.ec : msufcma_uncond` ≤ `adv_mlwe + Pr[STMSIS]` | MLWE + SelfTargetMSIS, **+ `masking_ok`** |
| C3 | SUF-CMA | `ml_adsa_suf.ec : sufcma_uncond` | MLWE + StrongSIS (STMSIS ∨ M-SIS) |
| C4 | Equivalence-class hardness (ROM+QROM) | `ml_adsa_euf.ec : equiv_class_guess_bound`; `ml_adsa_qrom.ec : qrom_equiv_class_uncond` | = C2/QROM (definitional: hitting the verify-set *is* forging) |
| C5 | Many-time (refresh) | `ml_adsa_F_manytime.ec : F_manytime_bound` ≤ `adv_prf + Q·eps_content` | + PRF security |
| C6 | Rogue-key → single signer | `ml_adsa_rogue_proof.ec : rogue_reduces_to_single` | PoP knowledge-soundness (`rogue_collapse`) |
| C7 | No-new-power → Module-SIS | `ml_adsa_nnp_proof.ec : new_power_reduces_to_sis` | `extract_or_break` |
| C8 | QROM (Constr. A tight; B lossy/derived) | `ml_adsa_qrom.ec : qrom_eufcma_uncond` / `qrom_eufcma_lossy`; GHHM21 derived in `ml_adsa_qrom_ghhm.ec` | MLWE + QROM-STMSIS **+ `masking_ok`**; B: + Thm 6.1 distinct-query, `Ynontriv` |
| C9 | Concurrent (deployed atomic) | `ml_adsa_euf.ec : concurrent_atomic_uncond` (= `msufcma_uncond`; no open sessions) | = C2 |
| C10 | Concurrent (interactive variant) | `ml_adsa_F_concurrent.ec` — **ROS-defense core + HVZK hop mechanized; full reduction SUPPLIED** | A-regularity + commit-binding; **needs cryptanalysis** |
| C11 | Hiding / signer-set privacy | `ml_adsa_F_hiding.ec : commit_hiding ≤ 2·adv_mlwe` | Module-LWE |
| C12 | NTT is a ring isomorphism | `ml_adsa_ntt.ec` (convolution) + `ml_adsa_ntt_inv.ec` (CRT inversion) | — (first principles) |
| C13 | Masking / rounding / Montgomery encoding / NTT loop (CT = DFT) | `ml_adsa_masking.ec`, `ml_adsa_rounding.ec`, `ml_adsa_montgomery.ec`, `ml_adsa_ntt_ct.ec` (`ct_step`/`ct_butterfly`/`ct_correct`) | — (first principles; integer arithmetic) |

**Assumption base (the whole thing):** MLWE, Module-SIS, SelfTargetMSIS (ML-DSA's own); a PRF; a
collision-resistant/injective hash (SHAKE-256). **No** ROS, AGM, OMDL, trapdoor, SNARK/STARK, or trusted
setup. The aggregate key `pk*` is itself a bona-fide ML-DSA key (a sum of MLWE samples is an MLWE sample).

---

## 4. What is machine-checked vs. what needs human review

**Machine-checked (32 prover artifacts, 194 lemmas = 162 EasyCrypt + 32 Coq, 43/43 genuineness, 6 Gobra;
`formal/count-artifacts.sh`).** The reductions in §3, the NTT ring-isomorphism and the
masking/rounding/Montgomery integer kernels, and 6 Go-code structural theorems (Gobra). Every proof is
admit-free and accompanied by a **genuineness check** (weaken its named primitive → the proof must break).

**NOT established by the proofs — for the reviewer:**
1. **`masking_ok` (= `masking_perfect`)** — the perfect-HVZK *distribution identity* `sign1 sk m = simsig
   pk m` is an **axiom** (its consequences are machine-checked; the in-range change-of-variables is proven
   in `ml_adsa_masking.ec`, but the full bit-level rejection-sampling identity is the shared-with-all-ML-DSA
   lattice boundary). **Is its use for the *aggregate* (summed, shared-challenge) sound?**
2. **The interactive-variant concurrent reduction (C10)** — the "secret-free concurrent game ≤
   single-session bound" step is the standard FS argument given an unbiasable challenge; **not** separately
   mechanized. The deployed scheme avoids this (C9), but if an interactive variant is used, this is open.
3. **Soundness of the assumptions themselves** at Category 5 (MLWE/STMSIS/M-SIS concrete hardness) — we
   inherit ML-DSA's parameters; we do not re-derive their security.
4. **Side-channel / fault resistance** of the deterministic construction (out of proof scope).
5. **In-place NTT array loop (iterative realization)** — the arithmetic kernels (`modQ`/Montgomery,
   `ml_adsa_montgomery.ec`), the **full multi-level Cooley–Tukey transform = DFT** (`ml_adsa_ntt_ct.ec`:
   `ct_step`, `ct_butterfly`, `ct_correct`), **and the flat-array factor-tree transform** (`ml_adsa_ntt_crt.ec`:
   `polyL_cat` = array low/high split, `polyL_bfly` = array butterfly write-back, **`ct_correct`**'s sibling
   **`ntt_tree_correct`** = the flat `take`/`drop`/`bfly`/concat tree computes the per-root evaluation vector
   for any well-formed twiddle schedule) are now source-proved over Z_q — **as are both items that were
   previously open:** **(a)** the *iterative, level-by-level* loop computes the same transform as the
   recursion (`forest_step` = one `length`-level; `forest_step_inv` = one level preserves the transform;
   `forest_loop_correct` = once all blocks are size-1 leaves the flat array is `ntt_tree t a`; i.e. BFS = DFS),
   and **(b)** FIPS-204's bit-reversed `ζ=1753` schedule satisfies `wf` (`negtree_wf`; `negtree_computes_eval`
   gives the per-root evaluations for the real schedule). **Termination is proved** (`tdepth_negtree` +
   `forest_iter_leaves`), so `fips_ntt_loop` is *unconditional*: `size l` (= 8) levels on the FIPS-204 schedule
   yield the evaluation vector. **The absolute-index arithmetic is machine-checked too** (`jloop_eq`: the Go
   inner loop `output[j]=a[j]+z·a[j+m]`, `output[j+m]=a[j]−z·a[j+m]` equals the block butterfly; `jloop_forest`
   ties it to one `forest_step`). The sole residual is the **loop control-flow scaffolding** (the `while`
   bounds + `k`-counter over `zetas[k]` driving `jloop` over the right segments/levels) — the same model↔code
   conformance step all of surface B covers, established by the byte-exact KATs against CIRCL + go-qrllib; no
   algorithmic, index, or termination content is left. (NB: the NTT is implementation-conformance, **not** a
   security assumption — no reduction invokes it.)

---

## 5. Known non-issues (so you don't spend time here)

These were probed (internally and by an adversarial review pass, `docs/35` §6) and are believed resolved or
correctly scoped — but **re-checking them is welcome**:
- **"Summing responses overflows the norm bound."** True worst-case; the construction relies on
  concentration (Irwin–Hall) and a stated cohort cap; the `c·t0*` correction is **N-independent** (it
  rounds the *sum* `t*`, not the sum of roundings), so the earlier "LMFA" cross-term failure does **not**
  recur. See §6.4 to attack the *concrete* bound.
- **"HighBits(Σ w) ≠ Σ HighBits(w) breaks the hint."** The signer computes the hint from the *actual* summed
  `w*` and re-checks `UseHint == HighBits(w*)` before emitting; correctness is enforced at signing time and
  byte-validated. (Attack the *hint forgery* surface in §6.1, not the honest-correctness path.)
- **"Equivalence-class hardness is circular."** It is *definitional* by design (hitting the verify-set = the
  EUF-CMA win); we present it as a clarification, not a deep theorem.
- **"Many-time is not really Q-independent."** Correct — the bound is `adv_prf + Q·eps_content` (negligible,
  the standard multi-instance union); the *leakage*-accumulation wall is what refresh removes.
- **Counts/claims drift.** Reconciled and locked to `count-artifacts.sh` (`docs/35`).

---

## 6. Priority attack surfaces (please probe these)

### 6.1 The summed-response / shared-challenge forgery surface (HIGHEST PRIORITY)
The crux: a forger sees honest `(w_i, z_i)` contributions (or chooses adversarial cohort members) and must
produce a verifying `σ* = (c̃*, z*, h*)` for an un-queried `m`. We claim binding `c̃* = H(μ‖HighBits(W*))` to
the **entire** `W*` collapses this to a single ML-DSA forgery (`eq_exact`: a verifying forgery relative to
the RO *is* a SelfTargetMSIS witness). **Attack ideas to try:** malleability of `(z*, h*)` keeping `c̃*`
fixed; choosing adversarial `t_j`/`w_j` to shift `pk*`/`W*` favorably (note: `pk*` is bound via the epoch
key-tree + PoP, `docs/29` §4.6b); exploiting the hint `h*` degrees of freedom; sub-aggregate substitution.

### 6.2 Concurrent / ROS — the interactive variant (C10)
The deployed scheme is **non-interactive and atomic** (deterministic one-time signing; one content = one
challenge = one release), so it has **no open sessions** to interleave and concurrent security = standard
multi-query EUF-CMA (C9, `concurrent_atomic_uncond`). **But** any *interactive* commit-reveal variant lives
in the family Drijvers et al. (S&P 2019) showed is **not** secured by nonce-commitment alone. We claim
A-regularity + commit-binding give an *unbiasable* challenge; **we have not mechanized the full
concurrent→single-session reduction.** Please attack: can a rushing adversary across `k` interactive
sessions solve a ROS/Wagner system despite the unbiasability claim? Is the deployed atomic model truly free
of an interleaving surface (e.g., via the gossip "pool" of published `w_i`, `docs/35` §6 / `docs/29`)?

### 6.3 Deterministic-nonce safety under faults / state failure
Nonces are `PRF(seed, C)` (no randomness). Reuse of `(seed, C)` under two different challenges leaks
`s1 = (z−z')·(c−c')⁻¹` (the classic attack; and deterministic schemes are fault-attack-prone, cf.
Poddebniak et al., Groot-Bruinderink–Pessl). We rely on a **durable one-time guard** (write-ahead + fsync,
`onetime_durable.go`) + epoch non-equivocation. Please attack: restart/rollback/replay windows; a single
equivocating signer or content-key collision inducing cohort-wide reuse; fault models that bypass the guard.

### 6.4 Norm budget, cohort cap, and Construction-B leakage
For the rejection-free Construction B (σ = 12β = 1440) used in the scaling demos, `z*` is an Irwin–Hall sum;
we claim it stays under `γ1−β` for the stated cohort and that leakage is *negligible* (computational HVZK,
`ml_adsa_regimes.ec`: narrow regime → `adv_mask`, argued ≤ `adv_mlwe`). Please attack: is the secure `N`
honestly bounded? Is the per-content leakage of the summed `z*` (whose mean tracks `c·s1*`) really
negligible per *fresh* key (one-time refresh), or does any cross-content correlation accumulate? Is
`adv_mask ≤ adv_mlwe` justified at these parameters?

### 6.5 The perfect-HVZK kernel (`masking_ok`) for the aggregate
`masking_ok` is the one axiomatic cryptographic primitive (its consequences are machine-checked classically
and quantumly; the change-of-variables is proven). It is ML-DSA's own rejection-sampling HVZK property.
Please check: is applying it to the **summed, shared-challenge** response distribution (not a single
signer's) sound — does the rejection event correlation under a shared `c` invalidate the per-coefficient
uniformity argument?

### 6.6 Other surfaces
Rogue-key/PoP soundness (`rogue_collapse`); epoch-tree non-equivocation binding; decoy hiding reduction
(`commit_hiding`); QROM-B adaptive-reprogramming derivation (`ghhm.ec`, Thm 6.1 + `Ynontriv` as standing
inputs); the SelfTargetMSIS extraction tightness (`eq_exact`).

---

## 7. Reproduction

```sh
# proofs (29 EasyCrypt/Coq artifacts + tallies)
cd formal && zsh check-all.sh          # → ALL GREEN (22 classical + 5 quantum + 5 Coq)
zsh count-artifacts.sh                  # → 32 artifacts, 194 lemmas (162 EC + 32 Coq), 43/43, 6 Gobra
zsh genuineness.sh                      # → ALL 35 GENUINENESS CHECKS PASS (weaken a primitive ⇒ proof breaks)
cd gobra && zsh run.sh                  # → 6 Gobra theorems, "Gobra found 0 errors"
# implementation conformance (byte-exact vs two independent FIPS-204 verifiers)
cd go-mladsa && go test ./...           # CIRCL + theQRL/go-qrllib byte-accept; KATs; rotation KATs
# live decentralized demos
cmd/mladsa-devnet | mladsa-hieragg | mladsa-epochnet   # order/grouping independence, equivocator exclusion
```
Toolchains: EasyCrypt (opam switch `discus-verified`), EasyPQC (`easypqc`, via `ec-quantum.sh`), Coq/Rocq,
Gobra (Docker `ghcr.io/viperproject/gobra`). See `formal/README.md`.

---

## 8. Falsification criteria (what would break ML-ADSA)

A reviewer would falsify a core claim by exhibiting any of:
- an EUF-CMA / SUF-CMA forgery (a verifying `σ*` on an un-queried `m` with PoP-valid cohort) that does **not**
  yield an MLWE / SelfTargetMSIS / Module-SIS solution — i.e. a forgery strategy bypassing the reduction;
- a concurrent (ROS/Drijvers-style) forgery against the **interactive** variant under honestly-followed
  commit-reveal, or a demonstration that the deployed atomic model in fact exposes an interleaving surface;
- a nonce-reuse / fault path that recovers `s1` without violating the stated one-time discipline;
- a parameter regime where the summed aggregate verifies but leaks the secret beyond ML-DSA's own leakage
  (breaking the "no assumption weaker than ML-DSA" claim);
- a flaw in `masking_ok`'s application to the aggregate (the per-coefficient uniformity failing under the
  shared challenge);
- any proof artifact that does not actually compile, or a genuineness check that passes when it should break.

A finding that an *axiom/primitive* is unrealistic (e.g., `masking_ok`, `rogue_collapse`, Thm 6.1) is equally
valuable — those are exactly the trust anchors we want pressure-tested.

---

## 9. Submitting findings (responsible disclosure)

This is a **defensive publication**; cryptanalysis is explicitly invited and credited. Please report:
- to the public site's issue channel / the contact in `docs/32` (publication & NIST roadmap), with a clear
  PoC or proof sketch and the affected claim ID (C1–C13) and surface (§6.x);
- for a *break*, please allow coordinated disclosure before public release; for *modeling/assumption*
  feedback, open discussion is welcome immediately.

We commit to publishing confirmed findings and corrections in `docs/35` (consistency ledger) and the paper's
errata, with attribution. The goal is to be wrong early if we are wrong.
