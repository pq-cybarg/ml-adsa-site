# EUF-CMA for F-OFFSET at small nonce width — strategy, what's established, the one open step

**Status: research strategy (NOT a completed proof).** This is the gate (task #78) on shrinking the per-signer
nonce width σ below the current 12β, which would raise the single-aggregate norm-wall ceiling from ~32 768
(rejection-aware, F12d) toward effectively unbounded (the recovery bar permits σ≈3, F12e). It is written to the
same honesty standard as the rest of the corpus: the obligation is stated precisely and labeled open.

## 1. The goal and why it's nontrivial

The norm wall `‖Σzᵢ‖∞ < γ1−β` caps a single aggregate at n≈16k (single-draw) / ~32k (with the rejection already
in `AggregateOffsetF`) at σ=12β. The wall is linear in σ (max|Σz| ≈ σ√(n/3)·c), so smaller σ ⇒ larger n. The
question: **is F-OFFSET still EUF-CMA-secure (≥ native) at σ ≪ 12β?**

The current EUF-CMA proof (`ml_adsa_F_euf.ec`, ROM; `ml_adsa_qrom.ec`, QROM) routes through **HVZK**: the
reduction answers signing queries with a simulator that produces `z` *without* the secret. The proven perfect
HVZK (`ml_adsa_masking.ec : reject_uniform`) is native ML-DSA's **γ1-mask + rejection** — `z` uniform,
independent of the secret. **The aggregate cannot use the γ1 mask** (`Σz` overflows at n=2, #80), so it already
runs at σ=12β rejection-free under a *separate* deterministic-nonce argument ([[deterministic-nonce-security]]).
At σ ≪ 12β the rejection-free `z = y + c·s1` has a non-negligible statistical distance from the simulator's
distribution (≈ `Σδ/2σ`), so the **HVZK-route bound becomes vacuous**. A different argument is needed.

## 2. What IS established (machine-checked / measured)

- **(A) Recovery-hardness ≥ native to σ≈3** (F12e, estimator): the published response `z = c·s1 + y` is an LWE
  view of `s1` (matrix circ(c), error σ); recovering `s1` from it is ≥ native for σ ≥ 3 (480× below 12β).
- **(B) Combined three-view hardness = native** (F12f): native `t` + offset `b` + response `z` together give no
  advantage over native (worst case = native at m=5888 = 252).
- **(C) Offset published artifact is ≥ native** (F8/F9/F10): the persistent `(pk*, σ*)` and the offset transcript
  reduce to MLWE at ≥ native, independent of attack (reduction + real estimator).
- **(D) One-time / refresh firewall** (#101, #111): each `s1_C` signs exactly ONE content; fresh `s1_C` and
  fresh `r_i` per content ⇒ no cross-content accumulation; spent keys are forward-secret-erased.
- **(E) No-new-power / extraction** (`ml_adsa_nnp_proof.ec`): producing any valid `σ*` for a fresh message
  reduces to Module-SIS — forgery requires breaking the lattice, not just seeing transcripts.

## 3. The reduction strategy (the claim to prove)

> **Theorem (target, #78).** For F-OFFSET with a one-time refresh and per-signer nonce width σ ≥ σ₀ (σ₀ a small
> constant, ~native-error-scale), the aggregate is EUF-CMA-secure, reducing to MLWE + Module-SIS at the native
> level, **without** assuming perfect HVZK.

**Strategy — replace the HVZK simulation with a one-time, knowledge-of-secret reduction.** The HVZK route
simulates *unboundedly many* queries per key. But here each key is **one-time** (D), so the signing oracle answers
**at most once per key**. That changes what the reduction needs:

1. *Embed* the MLWE challenge in the cohort key `pk* = Σtᵢ` (as in the existing hop, `ml_adsa_mlwe_hop.ec`).
2. *Answer the single query per content honestly*: because the nonce `y_C` and key `s1_C` are deterministic PRF
   outputs (N2) and used once, the reduction can derive the *one* transcript it must emit from the PRF — it does
   **not** need to simulate a distribution, only to reproduce the one deterministic transcript. The leak in that
   single `z` is then irrelevant to the reduction's ability to answer (it answers by computation, not simulation).
3. *Extract from the forgery* via no-new-power (E): a forgery on a fresh message yields a Module-SIS solution.
4. *Bound the residual*: the only place the σ-dependent leak can help the adversary is **recovering a queried
   key `s1_C` from its one revealed `z`** and using it — but that is exactly the recovery instance (A), which is
   ≥ native for σ ≥ σ₀; and even combined with the other views it is ≥ native (B). A recovered *spent* one-time
   key, moreover, only re-signs the already-agreed message (containment, finding-#3) — a no-op.

So the EUF advantage is bounded by `Adv_MLWE + Adv_SIS + (per-key recovery advantage)`, and the last term is
≤ native for σ ≥ σ₀ by (A)/(B) — **no HVZK distance term**, because the deterministic one-time oracle answers by
PRF computation rather than by simulating a secret-independent distribution.

## 4. The one open step (precisely)

The strategy hinges on one lemma not yet machine-checked:

> **Open lemma (#78-core).** In the EUF game where the reduction holds the embedded MLWE instance as `pk*`, the
> deterministic one-time signing oracle can be answered *consistently with that embedding* (i.e. the PRF-derived
> `(y_C, z_C)` is jointly consistent with the embedded `t*` to the adversary's view) **without** the reduction
> knowing the embedded secret, OR the inconsistency is bounded by the recovery advantage (A).

This is the lattice analogue of the classical *one-time-signature → full-signature* and *lossy-key* arguments,
specialized to the deterministic-nonce setting already used by the scheme. It is plausibly true (the one-time
structure is exactly what such arguments exploit) but is a genuine reduction to construct — paper-level, not a
tweak. Until it is discharged:

- **Conservative deployment: keep σ = 12β** ⇒ rejection-aware ceiling ≈ 32 768 per committee (F12d), with
  unbounded total via committee sharding (#117). F-OFFSET adds **no** HVZK concern beyond the base aggregate
  (both use the σ=12β deterministic nonce).
- The recovery headroom (A) shows there is large margin *if* #78-core is proved; that is the prize.

## 5. Next concrete steps

1. Read whether the existing deterministic-nonce / equiv-class argument ([[deterministic-nonce-security]],
   `ml_adsa_euf.ec : equiv_class_guess_bound`) already discharges a form of #78-core, and at what σ.
2. If not, attempt #78-core as an EC game-hop (skeleton like `mlwe_hop`), with the one-time-oracle answer as the
   key lemma and the recovery-advantage (A) as the residual.
3. Either result (proved, or a concrete obstruction) updates the deployable σ and the per-committee ceiling.

## 6. #78 step 1 result — what the existing argument does and does NOT give (read 2026-06-18)

Reading the corpus:
- **`ml_adsa_F_nonce.ec` (`reuse_iff_collision`, `binding_failure_leaks`)** — the deterministic-nonce **reuse**
  attack (`s1=(z−z′)/(c−c′)`) leaks the key **iff** two nonces collide. One-time-per-content + a
  content-determined challenge + a high-entropy PRF nonce forbid it. **σ-independent — fully covers reuse.** ✓
- **`ml_adsa_F_zk.ec` (`F_zk_per_content`) → `ml_adsa_props.ec` (`zero_leakage_perfect_A`) →
  `masking_perfect`** (discharged by `ml_adsa_masking.ec : reject_uniform`) — per-content **perfect ZK**, but
  `reject_uniform` is the **Construction-A single-signature** masking: nonce uniform on `[−(γ1−1), γ1−1]` with
  the `‖z‖<γ1−β` **rejection**. It is the *γ1-uniform-with-rejection* regime.

**The gap (applies to BASE and OFFSET equally).** The deployed *aggregate* nonce is `y* = Σ DeriveNonce(σ=12β)`
— a **sum-of-uniforms**, rejection-free per-signer, and **narrower than γ1** for any realistic n (it reaches
γ1-spread only near n≈10⁵). So `masking_perfect`'s γ1-uniform model is **not** the aggregate's nonce
distribution; the clean perfect-ZK lemma is about the single-signature regime and does **not**, by itself,
establish perfect ZK for the aggregate's summed/narrower nonce. What *does* hold at σ=12β is **recovery-hardness
≥ native** (F12e: recovering `s1` from the summed/per-signer `z` is ≈446 bits) — so the aggregate's exposure is
≥ native by the LWE-recovery argument, **not** by the perfect-ZK lemma.

**Consequence for #78.** The existing argument does **not** already give EUF at small σ via perfect ZK; both the
base and offset aggregates already rely on **recovery-hardness (≥native) + one-time**, not perfect ZK, for the
narrower-mask exposure. So #78-core is genuinely needed, and its right form is **not** "recover perfect ZK at
small σ" (infeasible) but **"formalize the recovery-hardness + one-time argument the aggregate already implicitly
uses"** — i.e. an EUF reduction whose residual is the per-key recovery advantage (≥native, σ≳3), with the
one-time deterministic oracle answered by PRF computation. This also flags a **base-scheme tightening**: state
explicitly that the aggregate's ZK at the deployed summed-σ nonce is the recovery-hardness bound, distinct from
the single-signature `reject_uniform` perfect ZK. (Not an error in the existing lemmas — a scope/applicability
clarification of which lemma covers which object.)

## 7. The pivotal axiom: `masking_ok` (step-1 complete)

`ml_adsa_euf.ec` reduces MSUFCMA to `mlwe_assumption + extract_sound` (Module-SIS) **via the axiom `masking_ok`**
(= `masking_perfect`; used at the signing-oracle simulation, proof `smt(masking_ok)`). `equiv_class_guess_bound`
(T9) shows producing *any* class member = a forgery (same bound) and frames the deterministic/one-time setting —
but it **still rides on `masking_ok`**; it bounds signature-*multiplicity* and *Q*, not the single-signature HVZK.

So the entire small-σ question reduces to ONE thing: **`masking_ok` for the deployed nonce.** Two routes:
- **(i) Establish `masking_ok` (perfect HVZK) for the aggregate's summed σ=12β nonce.** `reject_uniform` gives it
  only for the γ1-uniform single-signature regime; the summed nonce is a different (narrower) distribution, so
  this route most likely *still needs a wide mask* — no help for shrinking σ.
- **(ii) Replace `masking_ok` with a recovery-hardness simulation bound (#78-core).** Since each key is one-time
  and the nonce/response are deterministic PRF outputs, the reduction answers the single query by *computation*
  (not by sampling a secret-independent distribution), so the HVZK-distance term is replaced by the **per-key
  recovery advantage** — which is ≥ native for σ≳3 (F12e) and combines to ≥ native (F12f). This is the route that
  lets σ shrink, and it is exactly the open lemma #78-core.

**Net (step 1 done):** the existing corpus does NOT already discharge small-σ EUF — it routes through `masking_ok`
(perfect HVZK), which is the γ1-regime. The deployed aggregate (base and offset alike) already departs from that
regime; what carries it is recovery-hardness + one-time, not perfect HVZK. Making that rigorous = replacing
`masking_ok` with the recovery-bound simulation (route ii) = #78-core. That is a paper-level reduction; step 2 is
to draft it as an EC game-hop with `masking_ok` swapped for the recovery-advantage residual.

## 8. #78-core attempt — the obstacle is the SIGNING-ORACLE SIMULATION distance (not recovery)

Pushing the reduction (2026-06-18) clarifies *why* small σ is hard, and it is NOT what F12e addressed:

**Both reduction routes must simulate honest signing.**
- *Route MLWE (key-indistinguishability):* embed the MLWE challenge in the honest cohort key `pk*`. The reduction
  does not know the embedded secret, so it must **simulate** the honest members' signing-oracle answers.
- *Route SIS (no-new-power extraction):* an aggregate forgery falsely asserts an **honest** member signed; the
  reduction again holds the challenge in the honest keys and must answer their signing queries **without** the
  secret. (If instead the reduction knew all honest secrets it could sign the "forged" content itself, so the
  forgery would be no new power — no contradiction to extract.)

So in *either* route the honest one-time signature must be produced without the secret = **simulated**.

**The one-time structure bounds COUNT, not per-query DISTANCE.** The refresh firewall gives Q≈1 query per key,
which is what `equiv_class_guess_bound` / F-C4 exploit to avoid Construction-B accumulation. But the EUF bound
still carries, per simulated query, the **statistical distance** between the simulator's transcript and the real
one. With perfect HVZK (`masking_ok`, wide γ1 mask + rejection) that distance is 0. At σ ≪ 12β the rejection-free
`z = y + c·s1` has per-coordinate distance ≈ `δ/2σ` from any secret-independent simulator (δ≤β), summing to a
**non-negligible** transcript distance. So the simulation step — not the recovery step — is what breaks.

**Why F12e (recovery ≥ native to σ≈3) does NOT rescue this.** Recovery-hardness says the adversary cannot
*invert* `z` to get `s1`. But the EUF reduction's obstacle is the opposite direction: the *reduction* cannot
*produce* a `z` matching the real distribution without `s1`. Hardness-of-inversion ≠ existence-of-a-simulator.
These are independent; F12e is necessary (else the leak is directly exploitable) but not sufficient (the proof
still needs a simulator).

**Verdict for the ATOMIC-MASKING route (this section): obstacle precisely located.** On the route that
answers the signing oracle by an HVZK-*simulated signature* (`ml_adsa_euf.ec`: `sq_perfect` → `smt(masking_ok)`),
small-σ single-aggregate EUF is blocked by the signing-oracle simulation distance, which the one-time structure
does not remove. A genuinely new technique would be needed on THAT route — e.g. a *lossy-key* simulation, or an
*online-extractable* one-time argument. I did not find one; on the masking route this is a real obstacle.

For the masking / non-key-leak model specifically, the honest standing remains (preserved record):

- **Conservatively, σ = 12β stands on this route** ⇒ rejection-aware ceiling ≈ 32 768 per committee (F12d), with
  unbounded total via committee sharding (#117). F-OFFSET adds **no** HVZK concern beyond the base aggregate
  (both use the σ=12β deterministic nonce).
- **Committee sharding (#117) is the practical answer to unbounded total** — and it has NO such gap on this route
  either (each committee is a standard σ=12β aggregate with the existing proof).
- **The small-σ ceiling-lift on the non-key-leak route remains a *possible* future result gated on the simulation
  obstacle above, NOT a claimed property** ([[dont-conclude-prematurely]]: open on this route, obstacle located).
  §10 digs into the concrete technique (Hint-MLWE) that could discharge it.

**But the deployed scheme does NOT use the masking route.** The whole of §8 analyses the atomic-σ\* oracle, which
returns a *simulated signature*. The deployed transcript-exposing scheme answers the oracle by *leaking the whole
one-time key* (`ml_adsa_F_open.ec`: `transcript_le_keyleak`) — there is nothing to HVZK-simulate. §9 shows that
removes the σ-dependence entirely. **Read §9 — it resolves the small-σ question for the deployed construction.**

## 9. RESOLUTION — the DEPLOYED bound is σ-INDEPENDENT (the §8 obstacle is a wrong-route artifact)

**Date 2026-06-19, machine-checked: `formal/ml_adsa_F_keyonly.ec` (admit-free, 0 new axioms, 3 lemmas).**

§8 is correct but it analyses the **atomic-masking route** (`ml_adsa_euf.ec`), whose signing oracle returns an
HVZK-**simulated signature** (`sign1 sk m ↦ simsig pk m`, bridged in `sq_perfect` by `smt(masking_ok)`).
`masking_ok` (= perfect HVZK = the γ1 mask + rejection) is the **only** place the nonce width σ enters the
security argument. The deployed transcript-exposing scheme **does not use that route**.

**What the deployed scheme actually does (already in the corpus).** `ml_adsa_F_open.ec : deployed_open_uncond`
proves the deployed bound through the **KEY-LEAK model**:
- `transcript_le_keyleak` — the published transcript `T_m=(w,z,h)` is a deterministic public-coin function of
  the one-time key, so it is recomputable from the key; the worst case **hands the adversary the entire one-time
  key** (s1,s2,t0 *and* the nonce y). There is **no signature to simulate**.
- `open_refresh_hop` — real per-content keys ≈ independent fresh keys within `adv_prf` (the PRF refresh; RO-free).
- residual `eps` — the **ideal** game (independent fresh keys) bound, in which the forgery **target is un-queried**.

**The new lemma (`ml_adsa_F_keyonly.ec`).** The un-queried target is a **no-message / key-only** attack: the
adversary gets only `(ρ, pk*)` for the target and has **no signing oracle** on it. `konly_uncond` proves

> `Pr[ key-only forge ] ≤ adv_mlwe + Pr[ STMSIS ]`  — **without `masking_ok`**,

by reusing exactly the two **lattice** hops of the keystone (`mlwe_assumption`, `eq_exact`=`extract_sound`)
through `WrapKO`, a wrapper that ignores the unused oracle. `konly_eq_mlweL` shows the key-only game **is**
`MLWE_L` on the wrapped adversary (the ignored oracle never fires; `! mem qs m` holds vacuously). No HVZK term
appears because there is no oracle to bridge.

**Therefore every term of the deployed bound is σ-independent:**

| term | what it bounds | depends on |
|---|---|---|
| `adv_prf` | refresh / confine leak to spent keys | the PRF; σ is post-processing of its output — **not σ** |
| `adv_mlwe` | recover `s1` from `t=A·s1+s2` | secret width **η=2** — **not σ** |
| `Pr[STMSIS]` | fresh-challenge forgery | norm bound **γ1/β** (FIPS params) — **not σ** |

So `Pr[ deployed forge ] ≤ adv_prf + Q·(adv_mlwe + STMSIS)` has **no σ-dependent term**. The §8 simulation
obstacle exists **only** on the masking route, which the deployed (and the F-OFFSET) scheme does not take.
F-OFFSET reveals **less** than the full-w deployed transcript (it hides `LowBits(w)` under the offset `r`), so
it is **a fortiori** covered by the key-leak model.

**Consequences (honest scope).**
- **The EUF-driven σ floor of 12β was a masking-route artifact.** The deployable σ is lower-bounded only by
  (a) Fiat–Shamir commitment entropy / deterministic-nonce collision-freeness — a small constant
  (`ml_adsa_F_nonce : reuse_iff_collision`); and (b) the per-content key's own MLWE hardness (η-based, σ-indep).
- **F12e (recovery ≥ native to σ≈3) is now DEFENSE-IN-DEPTH, not a requirement** — in the key-leak model spent
  keys are leaked anyway, so inverting `z` buys nothing; the target is never published.
- **The norm wall prefers smaller σ.** Empirically (`construction_offset_sigma_independence_test.go`,
  `construction_offset_ceiling_lift_test.go`): a **σ=3β** aggregate verifies **byte-exact** end-to-end, and the
  rejection-aware per-committee ceiling rises from ~**32 768** (σ=12β) to ~**262 144** (σ=3β) — an **8×** lift
  (4× analytic, rounded up by power-of-two quantization). σ=3β=360 is still ~120× above the F12e floor (σ≈3), so
  even the defense-in-depth recovery margin is preserved.

**Recommended deployable parameter: σ = 3β** (per committee), giving an ≈8× larger single-aggregate ceiling at
**no EUF cost** in the deployed model, with committee sharding (#117) still providing unbounded total beyond it.

**Status of #78: RESOLVED for the deployed construction** — the small-σ ceiling-lift is *supported* (σ-independent
deployed bound, machine-checked), not blocked. The blocker located in §8 was specific to a proof route the
deployed scheme does not use. ([[dont-conclude-prematurely]]: the failed masking-route attempt did NOT mean the
route was closed — the deployed key-leak route was open all along.)

## 10. DIGGING the still-open part: small-σ EUF in the NON-KEY-LEAK (tighter) model

§9 closed the *deployed* problem (key-leak model, σ-independent). What remains genuinely open is the **tighter
model**: prove small-σ EUF *without* the generous "leak the whole one-time key" worst-case — i.e. when the
per-content key is treated as SECRET even after signing. F-OFFSET actually *is* in this tighter regime: it hides
`LowBits(w)` under the offset `r`, so the nonce is **not** recoverable by linear algebra (recovering `s1` from
`(hi,q,z)` is the LWE instance b=M·s1+e, ≥native, F10) — unlike the full-w deployed transcript, F-OFFSET does
**not** trivially leak the key. So a tighter, smaller-`eps` bound *should* exist; §8 shows the **statistical**
HVZK route can't reach it at small σ. Two published techniques can, and the one-time structure puts us in their
mildest regime:

### 10a. Route A — Rényi-divergence HVZK (statistical, no new assumption)
Replace the requirement "simulator distance = 0" (total-variation, which needs the wide γ1 mask) by "**Rényi
divergence** `R_α(real ‖ sim)` is a small constant." For a Gaussian mask of width σ (use the #119 Gaussian
offsets) the per-signature shift is `Δ = c·s1`, and `R_α(D_σ(Δ) ‖ D_σ(0)) = exp(α·π·‖Δ‖²/σ²)` (natural
convention). A constant Rényi divergence multiplies the forger's success probability by a constant — acceptable —
provided `σ ≳ √(α/2)·‖Δ‖₂` with `α = 2λ`. Precedent: Rényi-divergence security is how BLISS and the tightened
Dilithium analyses handle narrow masks.

**Computed result (`formal/smallsigma_floor.py`, falsifiable assertions) — Route A is a DEAD END, NOT the win I
first sketched.** The Rényi gap uses the FULL `‖Δ‖₂`, not the per-coordinate `β`: with `‖c·s1‖₂ ≈ √(dim·τ·Var(s1))
≈ 464` (dim = N·L = 1792, τ=60, Var(U[-2,2])=2) and `α = 2λ = 256`, the floor is

> `σ_min(A) ≈ √128 · 464 ≈ 5246 ≈ **43.7β ≈ 3.6× the deployed 12β**` (at Q=1; ×√Q for Q queries).

So the statistical route needs a **larger** σ than the deployed 12β — it cannot shrink σ. Worse, at σ=12β the
Rényi log-divergence is already `α‖Δ‖²/(2σ²) ≈ 13.3` (gap ≈ e¹³·³ ≈ 6·10⁵ ≫ 1), i.e. **statistical HVZK is
vacuous at 12β** — exactly consistent with docs/48 §6: the aggregate at 12β relies on recovery-hardness +
one-time, NOT on statistical HVZK. (This corrects an earlier optimistic "σ=O(β)" sketch; the full-vector
divergence kills it.) Route A is kept in the EC file (`msufcma_renyi`) only as the honest baseline that shows
WHY statistical HVZK was abandoned for the aggregate. The Q-dependence (`R_α^Q`) only makes it worse.

### 10b. Route B — Hint-MLWE (computational, one published assumption)
Kim–Lee–Seo–Stehlé (CRYPTO 2023) show **Hint-MLWE** — MLWE where the adversary also sees hints
`zᵢ = cᵢ·s + yᵢ`, `yᵢ` Gaussian — reduces to plain MLWE at an adjusted width. This converts the simulation
distance from a *statistical* term into the *computational* `Adv_MLWE`. Threshold Raccoon (EUROCRYPT 2024) and
Plover build their EUF on exactly this to use **narrow** masks. Porting it here: the published `z = c·s1 + y` is a
Hint-MLWE hint on `s1`; under Hint-MLWE the simulator may output a secret-independent `y'` and the gap is
`Adv_HintMLWE ≈ Adv_MLWE` at the KLSS-adjusted parameters. The parameter condition for **one hint per key**
(our one-time case) is the mildest in the KLSS hierarchy (loss ∝ √(#hints-per-key) = 1), giving a σ-floor near the
lattice **smoothing parameter** `η_ε(Λ) ≈ √(ln(2·dim·(1+1/ε))/π)·σ_s` scaled by the single-hint challenge norm
`‖c‖₂=√τ`. Computed (`formal/smallsigma_floor.py`): `η_ε ≈ 5.55` (dim=1792, ε=2⁻¹²⁸), so

> `σ_min(B) ≈ η_ε·‖c‖₂·σ_s ≈ 5.55·7.75·1.41 ≈ 61 ≈ **0.51β ≈ 0.042× the deployed 12β**`

— i.e. **~24× below 12β**, and crucially **independent of `‖Δ‖₂` and of Q** (the whole point: the gap is now the
*computational* `Adv_HintMLWE`, which does not blow up the way Route A's statistical divergence does). Even with
several× margin on the constants it stays well under 12β. Cost: it needs the **Hint-MLWE assumption axiomatized**
(a *named, published* assumption, not one we invent) and an EC port of the KLSS reduction. This is the cleaner
route to a small-σ bound, and the **only** route that actually shrinks σ.

**EC PORT DONE (`formal/ml_adsa_F_hintmlwe.ec`, admit-free).** The first cut (`ml_adsa_F_smallsigma.ec`) stated
Route B as a hand-axiom on the signing gap (`hintmlwe_bounds_gap`). The port does it properly: it MODELS
Hint-MLWE as a decisional game (`HMreal`/`HMideal`, the signature's `z=c·s1+y` IS the hint) and **PROVES** (byequiv
`real_eq`/`ideal_eq`) that the signing-simulation gap `|Pr[MSUFCMA]−Pr[MSUFCMA_sim]|` EQUALS a Hint-MLWE
distinguishing advantage (`gap_le_hint`), so `msufcma_hintmlwe : Pr[forge] ≤ adv_hint + adv_mlwe + STMSIS`. The
gap→Hint-MLWE step is now **machine-checked**; the lone assumption is the published KLSS decisional hardness
`hintmlwe_assumption` (stated exactly like `mlwe_assumption`; weaken-to-break genuine).

**Q-count precision (no overclaim).** `MSUFCMA` allows many queries on one key, so the reduction targets
*multi-hint* Hint-MLWE in general (Q-dependent floor). The **Q-independent ≈0.5β floor needs the one-time
refresh** (F-C2): fresh key per content ⇒ each key gets exactly ONE hint ⇒ single-hint KLSS (mild, Q-independent
σ-floor), the total bound being a multi-instance union of Q mild single-hint terms — the same shape as
`deployed_open`'s `Q·eps_content`. So the σ-FLOOR is Q-independent; the TOTAL advantage is `Q·(mild single-hint)`.
For ONE aggregate (#78, single key) it is exactly single-hint.

### 10c. Honest standing after the dig
- For the **deployed** scheme under our LOCKED requirements (one-time + refresh + full transcript published), the
  **key-leak bound (F20) dominates**: it is both σ-independent **and** Q-independent, and F-OFFSET satisfies it a
  fortiori. So neither Route A nor B is *needed* for deployment — they are quantitative refinements.
- The **genuinely-open academic problem** is now sharp: a **non-key-leak, Q-independent** small-σ EUF bound. Route
  B (Hint-MLWE) is the concrete path to it; Route A gets there with a √Q floor and no new assumption. Both are
  enabled by the #119 Gaussian offsets. This is no longer "no technique found" (§8) — it is "two published
  techniques identified, one-time puts us in their best regime, EC port + (for B) one named assumption remain."
- **Net:** #78 is RESOLVED for deployment (F20); #78-core (tighter, Q-independent, no-new-assumption) remains the
  open research frontier, now with a concrete attack plan rather than a wall. ([[dont-conclude-prematurely]].)

> External numbers (Raccoon ~13 KiB / EUROCRYPT'24; Hint-MLWE = KLSS CRYPTO'23; Plover) are from memory and MUST
> be re-verified against primary sources before any publication (per the raccoon-chipmunk fact-check note).
