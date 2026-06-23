# Findings ledger — what is machine-verified vs. what is interpretation

**Why this exists.** The earlier `option_c_*.go` tests baked conclusions into `t.Log("FINDING…")` strings and
asserted nothing — they could not fail, so they verified nothing, yet their narrative was lifted into docs and
memory as if proven. This ledger rebuilds the record on a strict two-tier discipline:

- **TIER 1 — machine-verified facts.** A number or structural fact backed by a falsifiable `t.Errorf`/`t.Fatalf`
  assertion that FAILS if reality disagrees, plus sanity assertions on the measurement machinery itself. The
  PASS is the evidence. Tests log only measured numbers; no prose conclusions in code.
- **TIER 2 — interpretation.** Reasoning built on Tier-1 facts (e.g. security implications). Stated here as
  reasoning, with explicit dependency on which Tier-1 facts it uses and a confidence level. **Never** claimed as
  "tested."

A claim may only appear in `docs/43`/`44`/`45` or memory if it is either a Tier-1 fact (cite the test+assertion)
or a Tier-2 interpretation explicitly labeled as such. Anything else is struck.

Status legend: ✅ verified (assertion passes) · ❌ failed (assertion fails — claim was wrong) · ⏳ not yet
retrofitted · 🚫 removed (could not be made falsifiable).

---

## Retrofit progress (per test file)

| File | Assertions added | Re-run status | Notes |
|---|---|---|---|
| option_c_102_sourcecoding_test.go | ✅ analytic-vs-sim + 3σ band + premise | **PASS** | spine: P*=2^13 (asserted ∈[2^12,2^14]) |
| option_c_84_combine_test.go | ✅ + solver unit tests + in-range 256/256 | **PASS** | tall-A: random/α-sparse reachable 0/256 |
| option_c_76_compose_test.go | ✅ budget thresholds | **PASS** | native carry dense(1662)/max8; B=2^14 in-budget |
| option_c_80_inversion_test.go | ✅ overflow + monotone + n=1 sanity | **PASS** | norm wall bites at n=2 |
| option_c_105_rns_test.go | ✅ primality + identity + threshold | **PASS** | q prime; carry-save exact; B-threshold |
| option_c_carrybudget_test.go | ✅ ±1 over 20000 r | **PASS** | useHint deviation exactly ±1 |
| option_c_82_quant_test.go | ✅ monotone + b=6≤ω + machinery | **PASS** | b=6→19 misses (n=8) |
| option_c_93_fourier_test.go | ✅ round-identity + phase=residue | **PASS** | phase→residue, not carry |
| option_c_95_offset_test.go | ✅ R=0 machinery + viable window | **PASS** | R=2^11→22 misses, R/β=17 |
| option_c_103_dp_test.go | ✅ Δ2 + Young bound; ε made CONDITIONAL | **PASS** | Δ2=429.7; ε downgraded to Tier-2 |
| option_c_108_magnitude_test.go | ✅ E1/E2/E3 assertions | **PASS** | norm-invariance, multilateration err 0 |
| option_c_69_noise_test.go | partial (1) | not re-audited | lower priority |
| option_c_71_carrysave_test.go | partial (4) | passes | carry-save lemmas (Fatalf pattern) |
| option_c_76_hint_test.go | ✅ density + centered-low machinery | **PASS** | fixed buggy highbits(modQ(lo)) sub-claim |
| option_c_84_linearize_test.go | ✅ T1/T2/T3 assertions | **PASS** | non-additive, α∤q, dense carry |
| option_c_carry_test.go | ✅ already correct (FINDING-in-Fatalf) | passes | the right pattern all along |
| option_c_test.go | ✅ already correct (Fatalf assertions) | passes | core hiding, 0/1792 |

---

## TIER 1 — machine-verified facts (assertion passes; machinery sanity-checked)

| ID | Fact (measurable) | Backing test::assertion | Status |
|---|---|---|---|
| F1 | The largest per-coordinate uncertainty `±P` in `Σlow` that keeps carry-misses ≤ ω (n=64, KN=2048) is **P*=2¹³**; native nonce granularity α/2=2¹⁸ ⇒ ratio **5.00 bits**. Sim matches analytic `KN·2P/α` within 3σ. | `TestTask102_CarryPrecisionThreshold`: asserts P*∈[2¹²,2¹⁴], 3σ band, premise max\|carry\|≥2, monotonicity, endpoints | ✅ |
| F2 | `A` is tall (rows K·N=2048 > cols L·N=1792). Carry-correction targets (random and α-sparse) are reachable as `A·δ` at **0/256** NTT points; an in-range target `A·δ` is reachable at **256/256**. | `TestTask84_TallA_CarryNotInRange`: asserts reach≤1 for random/α-sparse, ==N for in-range, + F_q solver unit tests | ✅ |
| F3 | Naive `Σzᵢ` of native-size responses overflows the V3 cap (γ1−β=524168) **already at n=2** (max≈1.04M); n=1 is in-bounds; max grows monotonically. `c̃*` is 512 bits. | `TestTask80_NormWall`: asserts n=2 overflow, n=1 sanity, monotonicity | ✅ |
| F4 | q=8 380 417 is **prime** (full trial division). The carry-save identity `HighBits(Σ)=(Σhi+carry) mod m` holds **exactly** (0/2048 mismatch). Mixed-radix low-digit overflows: B=2¹⁴→≤ω, B=2¹⁸→1695≫ω. | `TestTask105_CarryElimination`: asserts primality, 0 mismatch, both thresholds | ✅ |
| F5 | At native low-bit size the aggregate carry is **dense** (1662/2048 nonzero) and **large** (max=8); it enters the hint-absorbable region (≤ω nonzero AND max≤1) at **B=2¹⁴**. | `TestTask76_WitnessComposition`: asserts native nonzero>ω & max≥2, B=2¹⁴ in-budget, B=2¹⁸ out | ✅ |
| F6 | `useHint(0,·)` is a no-op; `useHint(1,·)` changes the high digit by **exactly ±1** (0/20000 deviations; max deviation 1). ⇒ per-coord hint budget is ±1, ≤ω coords. | `TestCarryBudget_HintIsPlusMinusOne`: asserts no-op, deviation∈{±1}, max==1 | ✅ |
| F7 | Primal-uSVP core-SVP estimator (self-validating: **asserts** Kyber-512=118.6, Kyber-768=181.9, Kyber-1024=254.9, ML-DSA-87=252.0). Native ML-DSA-87 MLWE = **252 classical / 229 quantum**, and is **unchanged** by m=4096/8192 (extra samples don't reduce β). Offset-alone `b=M·s1+e` (s1~η2, e~±R): **248 @R=2¹**, **262 @R=2²**, 374 @R=2⁸, **464 @R=2¹¹**, 502 @R=2¹². | `estimator99.py` (validation = `assert` on published values; data rows only) | ✅ (model: core-SVP primal, no dual/hybrid) |
| F8 | The deployed offset view reduces **exactly** to `b = M·s1 − r` (M=A·c): over K·N=2048 coords, **0 boundary, 0 reconstruction errors, 0 instance-mismatches, recovered error == injected r, max\|e\|=R exactly**. ⇒ NO hidden A-conditioning / noise-amplification; the LWE noise scale is exactly R (σ_e=R/√3). The #99 instance IS the shipped instance. | `TestTask109_OffsetModelPin`: asserts reconBad≤boundary, mismatch≤boundary, errBad≤boundary, max\|e\|≤R | ✅ |
| F9 | **Aggregate `s1*` (cohort nc=64) is ≥ native** by every route: the aggregate key's own MLWE `t*=A·s1*+s2*` = **352** (harder than single native — summed errors flood noise); the aggregate offset `b*=M·s1*−r*` = **789 @R=2¹¹, 884 @R=2¹²**. All ≥ 252. | `estimator99.py` aggregate block: asserts agg-native ≥ nat and agg-offset(R=2¹¹,2¹²) ≥ nat | ✅ (same model caveats as F7) |
| F16 | **F-OFFSET KAT (deterministic fixed-point).** `AggregateOffsetF` from a single fixed-seed PRNG (rho, members, offset draws) is reproducible byte-for-byte; KAT asserts (a) determinism across builds, (b) `VerifyF`==true, (c) the output digest is locked: `shake256(pk‖σ‖partRoot‖regRoot‖content‖epoch)` = `6b465b72d2dce107…8cae4d97`. Any construction change fails it. Full Go suite green (`-skip TestNormBudget`). | `TestAggregateOffsetF_KAT` | ✅ |
| F15 | **F-OFFSET end-to-end drop-in `AggregateOffsetF`.** Same API/scaffolding as `AggregateF` (canonical order, dedup, registry/part-root binding, epoch, one-time guard, retry-on-bound) but the nonce-hiding offset combine. Returns an `AggSigF` the unmodified verifier accepts: n=6 → `VerifyF`==true, sig 4627 B / pk 2592 B. Binding negative controls (payload/epoch/reg-root) all reject; one-time guard refuses repeats; empty cohort refused. No regression to `AggregateF`/decentralized. | `TestAggregateOffsetF_EndToEnd` | ✅ |
| F14 | **Full-corpus integration green.** `check-all.sh` compiles the entire formal corpus **including** `ml_adsa_F_offset.ec` (which now `require import`s `Ml_adsa_rounding`) in build order: **31 ✅ EC, 0 ❌**, Coq green (`ml_adsa_identity.v` ✅ …). The offset file does not break the corpus. | `/tmp/checkall.log` (exit 0) | ✅ |
| F13 | **F-OFFSET formal artifact** (`formal/ml_adsa_F_offset.ec`, compiles GREEN, no admits, in `check-all.sh`; 3 lemmas). Scope (honest): the q-ring arithmetic (`Ms`,`addn`, noise shapes) is abstracted as in `mlwe_hop`; the structure is concrete. (1) `noise_flood_reduction` over an **additive-noise instance** (`b = addn (Ms s) e`; offset = same `M·s` + fresh flood) ⇒ Adv_offset ≤ Adv_native (concrete counterpart of F10/I5). (2) `choose_reproduces` — **PROVED** against the **REAL high-bits model**: the file `require import`s `Ml_adsa_rounding`, so `highbits` is its `rhigh` (the actual HighBits, with proven `highlow_id` reconstruction) and `usehint` is the real one — NOT fresh black boxes (corrected after "you sure that's doing the high bits?"). The combiner's `chooseHC` rule lands the real `usehint` exactly on the target. (3) `offset_combine_correct` **derives** verifier-match from (2) over the real `usehint`. (4)+(5) the **REAL one-step ±1 hint** is now modelled: `fips_usehint` applies the FIXED +1/−1 set by `sign(lowbits r)` (exactly `mldsa87.go useHint(h=1)`); `chooseF_reproduces` proves the combiner's actual decision (`Some h`) reproduces the target, and the **`None` case = the carry-miss-not-bridgeable ⇒ Go retry** (F12); `offset_combine_correct_fips` lifts it to byte-exact accept. (6) `offset_combine_proc` — the **FULL combine LOOP as a `module`/`proc`** (literal while-loop, Hoare-verified with a loop invariant): scanning coords + early-fail, `ok ⇒` every coord was a successful `chooseF` (the `ok=false` path = the Go attempt-retry). **6 lemmas, 0 admits, full-corpus green (F14), genuineness 53/53.** Tally 39 artifacts / 260 lemmas (228 EC + 32 Coq). **Residual abstraction:** `Ms`/`addn`/noise distributions (q-ring arithmetic, as `mlwe_hop`); mod-m wrap + q−1 boundary of `usehint` (rounding-model level, shared with the base scheme); the combine's `rr2 = A·z*−c·t1*·2^d` / norm / weight≤ω glue (standard, covered by the existing NTT/encode files). The **novel** offset logic (the targeting hint loop) is now procedure-level verified. | `easycrypt compile` exit 0; `count-artifacts.sh` | ✅ |
| F12 | **F-OFFSET scale envelope** (`TestConstructionOffset_ScaleEnvelope`, 8 trials/cell): succeeds 8/8 within retry budget for n∈{2,4,8,16,32}, R∈{2⁶,2⁸,2¹⁰}. Hint-weight ~54–60 (**flat in n** — `c·t0*` is bounded by power2round, n-independent) ≤ ω=75; carry-misses small and absorbed by ≤1 retry avg. Marginal offset cost over the base = just the misses. | asserts deployable points n∈{2,4,8} @R=2⁸ succeed, weight≤ω | ✅ |
| F12f | **Combined three-view hardness = native.** The attacker holds native `t` (m=2048,σ=√2) + offset `b` (m=2048) + response `z` (m=1792) on the same `s1`. Worst case (all at native noise) = native with m=5888 = **252** (estimator; native flat in m, F7). ⇒ combining the views gives no advantage; combined ≥ native iff each view's noise ≥ native's (R≥~2.4, σ≥~2.4). | `estimator99.py`-style native m=5888 = 252 | ✅ |
| F12e | **Response-leak recovery is ≥ native down to σ≈3** (estimator99.py, RESPONSE-LEAK block): the published response `z=c·s1+y` is itself an LWE view of `s1` (matrix circ(c), error σ, m=L·N=1792); recovering `s1` from it is **≥ native (252) for σ≥3** (σ=3→256), i.e. **480× below the 12β used for masking** — by the same noise-flooding floor (σ_e ≥ native ⇔ σ≳2.4). So the *recovery-hardness* bar permits a tiny mask (norm wall → effectively unbounded). | `estimator99.py` (asserts via row≥nat); sigma-floor printed | ✅ (recovery-hardness only) |
| F18 | **Discrete-Gaussian offsets** (#119, `construction_offset.go` `sampleDiscreteGaussian`/`OffsetPartsGaussian`, `construction_offset_gaussian_test.go`): sampler stddev 1182.7 vs target R/√3=1182.4 (<5%), mean≈0; full offset round verifies **byte-exact**. Security identical to uniform (depends only on σ_e); makes the #103 DP bound clean (Gaussian mechanism). | asserts stddev≈s, `Verify`==true | ✅ |
| F19 | **QROM/ROM EUF inherited by F-OFFSET** (#118, assessment): σ\* is a standard ML-DSA sig under pk\*; EUF is forging-under-pk\*-given-the-FS-hash, independent of the hashed commitment choice (`w1est` vs `HighBits(ΣW)`), so the base `qrom_eufcma_uncond` (GHHM) + ROM EUF cover it. The only F-OFFSET delta is the `(hi,q,z)` broadcast = hiding (≥native, F8/F10/F12e) at σ=12β. | cross-ref `ml_adsa_qrom.ec` + F8/F10 | ✅ (σ=12β) |
| F20 | **The DEPLOYED EUF bound is σ-INDEPENDENT (masking_ok-free key-leak target)** (#122, `formal/ml_adsa_F_keyonly.ec`, admit-free, 0 new axioms): the deployed scheme answers the signing oracle by *leaking the whole one-time key* (`ml_adsa_F_open.ec : transcript_le_keyleak`), not by an HVZK-simulated signature, and the forgery target is un-queried → a **key-only** attack. `konly_uncond` proves that target's bound is `adv_mlwe + STMSIS` **without `masking_ok`** (reuses `mlwe_assumption`+`eq_exact` via `WrapKO`). So `Pr[deployed forge] ≤ adv_prf + Q·(adv_mlwe+STMSIS)`; none of adv_prf (PRF), adv_mlwe (η), STMSIS (γ1/β) depends on the nonce width σ. Empirically (`construction_offset_sigma_independence_test.go`): σ=3β verifies byte-exact, ceiling 32 768→262 144 (8×). | EC compiles; byte-exact `VerifyF`==true; ceiling ratio≥3 asserted | ✅ |
| I7 | **Small-σ single-aggregate EUF is blocked by the signing-oracle SIMULATION distance, not recovery.** Both reduction routes must simulate honest one-time signing without the secret; one-time bounds query *count* (Q≈1) but not per-query *distance* (≈Σδ/2σ, large at small σ). Recovery-hardness (F12e) is necessary, not sufficient (inverting `z` ≠ simulating `z`). `masking_ok` (perfect HVZK, wide mask) is load-bearing. New technique (lossy-key sim) would be needed — not found. ⇒ keep σ=12β (ceiling 32 768); sharding (#117) is the unbounded answer. | docs/48 §8 | **SUPERSEDED in scope by F20/I8** — correct for the ATOMIC-MASKING route only; the deployed scheme does not use it |
| I8 | **#78 RESOLVED for the deployed construction: σ is not security-constrained.** I7's obstacle is specific to the atomic-σ\* oracle (simulated *signature*). The deployed transcript-exposing scheme uses the **key-leak** route (F20), which has no HVZK term, so the EUF-driven σ=12β floor was a masking-route artifact. The deployable σ floor is only (a) FS/nonce-collision entropy (small const, `ml_adsa_F_nonce`) + (b) per-content MLWE (η-based). F12e recovery margin is now defense-in-depth. **Recommend σ=3β** (8× ceiling lift, no EUF cost); sharding (#117) still gives unbounded total. F-OFFSET hides more than full-w, so a fortiori covered. | docs/48 §9, F20 | RESOLVED (deployed model) |
| F21 | **Tighter-model small-σ EUF backbone, PROVEN unconditional** (#123, `formal/ml_adsa_F_smallsigma.ec`, admit-free): `msufcma_lossy` proves `Pr[MSUFCMA] ≤ \|Pr[MSUFCMA]−Pr[MSUFCMA_sim]\| + adv_mlwe + STMSIS` with **NO masking_ok** (reuses `bridge_sim`+`mlwe_assumption`+`eq_exact`). I.e. in the non-key-leak model the ONLY extra term over the keystone is the real-vs-sim signing gap; everything else reduces to MLWE+Module-SIS. | EC compiles; weaken `eq_exact`/`mlwe_assumption`→break | ✅ |
| I9 | **Two named-assumption routes for the tighter-model gap; floors COMPUTED (`formal/smallsigma_floor.py`).** Route A (Rényi statistical HVZK, `msufcma_renyi`): floor `√(α/2)·‖Δ‖₂ ≈ 5246 ≈ 43.7β ≈ 3.6× the deployed 12β` — a **DEAD END** (statistical route needs *larger* σ; at 12β the Rényi log-divergence is 13.3, already vacuous — consistent with the aggregate relying on recovery-hardness not HVZK). Route B (Hint-MLWE, KLSS CRYPTO'23, `msufcma_hintmlwe`): replaces the statistical gap by computational `adv_hintmlwe`, floor `η_ε·‖c‖₂·σ_s ≈ 61 ≈ 0.51β ≈ 24× BELOW 12β`, **Q-independent** — the only viable small-σ route; cost = the named `hintmlwe_bounds_gap` axiom (+ EC port of KLSS). **#78-core: discharged modulo one named published assumption** (no longer open prose). Adds 2 named-assumption axioms (vs F20's 0). External cites (Raccoon/Plover/KLSS) flagged for primary-source re-verify. | EC compiles; floor assertions in smallsigma_floor.py | ✅ (Route B viable, Route A dead) |
| F22 | **KLSS Hint-MLWE reduction PORTED — the gap→Hint-MLWE step is now MACHINE-CHECKED** (#123, `formal/ml_adsa_F_hintmlwe.ec`, admit-free). Upgrades I9's Route-B hand-axiom: models Hint-MLWE as a decisional game `HMreal`/`HMideal` (the signature's `z=c·s1+y` IS the hint), **PROVES** by byequiv (`real_eq`,`ideal_eq`) that `\|Pr[MSUFCMA]−Pr[MSUFCMA_sim]\|` EQUALS a Hint-MLWE distinguishing advantage (`gap_le_hint`), giving `msufcma_hintmlwe : Pr[forge] ≤ adv_hint + adv_mlwe + STMSIS`. Only assumption = published KLSS decisional hardness `hintmlwe_assumption` (stated like `mlwe_assumption`; 1 axiom, replaces smallsigma's hand-axiom). **Q-count scope:** reduction is to multi-hint Hint-MLWE in general; the one-time refresh (F-C2, fresh key/content) makes each key single-hint ⇒ Q-independent ≈0.5β σ-floor, total = Q·(mild) (multi-instance, like `deployed_open`). | EC compiles; weaken `hintmlwe_assumption`→`gap_le_hint` breaks | ✅ |
| F23 | **σ=3β wired as deployment default + estimator cross-check + requirements assessment** (#124). `SigmaOffsetDefault=3·BETA=360` + `AggregateOffsetFDefault` (`construction_offset.go`, byte-exact `TestAggregateOffsetFDefault_Wired`). Estimator (`estimator99.py` #124 block, asserted): single-hint recovery at σ=3β = **387 classical / 351 quantum ≥ native 252**; at σ=β = 349; KLSS single-hint eff-width degradation **0.046%** (σ\*=1.4136 vs η=1.4142) ⇒ reduced MLWE = native; binding security = native **252/229 (Cat-5)**, hint does not lower it. docs/49 maps ALL locked requirements (byte-exact FIPS, non-interactive, no-setup, order-indep, hide≤native, unbounded-total, EUF/SUF ROM+QROM) → all met at Cat-5; ≈8× ceiling lift vs 12β, no property weakened. Limitations: KLSS theorem assumed (tighter model only; deployed needs no Hint-MLWE), Q-indep needs one-time refresh, estimator primal-uSVP approximate (Sage #110 cross-validates), cites to re-verify, CT nonce sampler note. | estimator asserts ≥native; byte-exact VerifyF; go test green | ✅ |
| F17 | **Committee sharding ⇒ unbounded total** (`construction_offset_shard.go`, `TestAggregateSharded_UnboundedTotal`). Canonical partition (sort-by-id, chunk ≤ceiling); one F-OFFSET aggregate per committee (index bound into content); `ShardedAggregate.Verify` = all committees VerifyF-true + same (payload,regRoot,epoch). N=2048/cap=512 → 4 committees, total **28876 B (=4×7219)** vs naive per-signer list 9.48 MB (**328× smaller**); size LINEAR in #committees, INDEPENDENT of N. Dropped-committee + wrong-payload detected. No new assumption (Ethereum-style committees). | asserts Verify, size = nc×7219 < N×4627 | ✅ |
| F12d | **Ceiling-lift levers (measured).** (a) **Rejection on z\* is already in `AggregateOffsetF`** (retry on `‖z*‖≥γ1−β`), so the true ceiling is where accept-prob `P(‖Σz‖<cap)` < 1/64 — **n≈32768 at HVZK-safe σ=12β** (2× the naive single-draw 16384), analytic CLT validated vs MC (16384: .98/.99, 32768: .08/.10). (b) **σ→ceiling:** 6β→65536, 3β→262144. (c) **HVZK cost of small σ:** the exact per-coord nonce-mask SD = β/(2σ+1) (worst δ=β): **0.042 (12β), 0.083 (6β), 0.166 (3β), 0.50 (1β)** — so small σ degrades the rejection-free mask (not free); rejection-based *perfect* HVZK at small σ is infeasible (reject-rate→1 over L·N coords). With **one-time** keys only ONE `zᵢ` exists, so moderate per-coord SD is weakly exploitable + contained, but needs its own analysis. (d) **Committee sharding** = clean unbounded total. | `TestOffset_RejectionCeiling` (asserts ceiling>16384, analytic≈MC), `TestOffset_NonceMaskLeak` (asserts SD monotone) | ✅ |
| F12c | **Scaling ceiling = the additive norm wall, ~16k signers (shared with base), tunable.** Cheap probe (`TestConstructionOffset_NormWallCeiling`, sums per-signer z coords directly): at the HVZK-safe nonce width sigma=12β the norm wall `‖Σzᵢ‖∞<γ1−β` first overflows at **n≈16384**; at sigma=3β it stays in-bounds to **n=262144**. This cap is a property of *additive* aggregation (`z*=Σzᵢ`) — **the base aggregate has it too**; it is NOT the offset mechanism (which scales further by R-tuning, F12b). Smaller sigma extends it but trades HVZK margin (sigma is the rejection-free mask width); beyond one aggregate's ceiling, **shard into committees** (each ≤ ceiling, unbounded total). | asserts n=8192 in-bounds at sigma=12β | ✅ |
| F12b | **F-OFFSET scales to THOUSANDS** (`TestConstructionOffset_LargeN`): with `R·√n` held ~const (R: 128→16 as n: 256→8192), **n=256/1024/2048/4096/8192 all succeed 3/3 on the FIRST attempt** (avgAttempt 0). Misses stay ~3–6 and **bridge first-try** — confirming the carry-miss direction correlates with the `UseHint` direction (a miss occurs at a `Σlow` boundary, where `LowBits(W*)`'s sign sets both), so retries do NOT explode. Weight ~50–57 ≤ ω. R≥16 ⇒ ≥native (R=16 ≈ 292 bits vs native 267). | asserts n=1024 succeeds every trial | ✅ |
| F11 | **F-OFFSET instantiation BUILT and end-to-end verified.** A separate construction (`construction_offset.go`, signers broadcast `(HighBits(wᵢ), LowBits(wᵢ)+rᵢ)`; challenge over the noised-carry estimate `w1*`; hint built to TARGET `w1*`) produces an aggregate `σ*` that the **UNMODIFIED FIPS-204 `Verify` accepts byte-exact** (n=4, R=2⁸, first attempt, hint-weight **56 ≤ ω=75**, sig 4627 B / pk 2592 B = exact ML-DSA-87 sizes). Wrong-message control rejects. Low bits masked by fresh ±R offset (2041/2048 coords). Keyed via the #101 forward-secret ratchet. | `TestConstructionOffset_EndToEnd` (asserts `Verify`==true, weight≤ω, binding) + `TestConstructionOffset_HidesLowBits` | ✅ |
| F10 | **REAL Albrecht et al. `lattice-estimator` (Sage 10.7), FULL attack suite** (usvp/bdd/bdd_hybrid/bdd_mitm_hybrid/dual/dual_hybrid/bkw): native ML-DSA-87 = **267** (best=dual_hybrid); offset = **455 @R=2¹¹, 489 @R=2¹²** (best=dual_hybrid); aggregate-native **367**, aggregate-offset **867/938** (best=bdd). **Offset ≫ native by +188/+222** under the *same* best attack. The pure-Python core-SVP (F7: offset@2¹¹=464) agrees with the real dual_hybrid (455). Tool sanity: Kyber-512/768 = 139.7/196.4 (tool's gate-count model). | `/tmp/run_estimate.py` via real estimator; `/tmp/estimate_out.log` | ✅ (real tool, all attacks) |

## TIER 2 — interpretations (reasoning on Tier-1; NOT machine-tested)

| ID | Interpretation | Depends on | Confidence | Notes |
|---|---|---|---|---|
| I1 | "Carry-precision tax": a party that resolves the carry **by estimating Σlow** must learn it ~5 bits finer than native reveals of a single nonce. | F1 | Medium-high | F1 uses a worst-case boundary model (conservative). The *security* conclusion ("reveals more than native") is reasoning; the lattice estimator (#99) is the real adjudicator. |
| I2 | Convergence: byte-exact + naive-sum combine ⇒ the carry must land in the ±1/≤ω hint budget (F6) ⇒ needs small low bits (F4/F5) ⇒ which pins each `wᵢ` finer than native (leak relocates aggregate→per-signer). | F4,F5,F6 | Medium | "small low bits" is *sufficient* (shown); whether it is *necessary* is NOT proven — other combine mechanisms untested. Do not read as impossibility. |
| I3 | The V3 norm-slack cannot absorb the carry, because tall `A` makes carry-correction targets unreachable as `A·δ`. | F2 | High | F2 is a clean structural fact + validated solver; interpretation is direct. |
| I4 | Any additive aggregate needs small per-signer nonces, independent of hiding. | F3 | High | Direct from the norm bound. |
| I5 | **req G HOLDS for the offset route in a wide window R ∈ [~3, 2¹²]**, and the argument is now **attack-independent** (a reduction, not just an estimate). **(i) Noise-flooding reduction:** native and offset are the same LWE params (n=1792, m=2048, q=2²³, secret η2) differing only in error (native σ=√2, offset σ=R/√3); raising error from σ to σ′≥σ is a *reduction* (add fresh noise), so the offset instance is **≥ native against ANY attack** (primal, dual, kernel, hybrid) once R/√3 ≥ √2 ⇒ **R ≥ √6 ≈ 2.45**. **(ii) Combined view** (attacker holds native `t` *and* offset `b`): raising the b-block noise to √2 is a reduction, and the all-√2 stacked instance = native with m=4096 = **252, flat** (F7 asserts native flat at m=2048/4096/8192) ⇒ combined ≥ native too. Carry caps R≤2¹² (F5/#95). **Overturns the earlier struck "tax / easier-than-native" narrative.** | F7 (asserts: native flat in m; offset monotone in R; offset(R=4)=262≥native) + noise-flooding reduction | Medium-High | The **dual/kernel caveat is CLOSED both ways**: by the attack-independent reduction AND by the **REAL lattice-estimator full attack suite (F10)** — dual_hybrid is literally the best attack and offset still beats native by +188/+222 bits. The **A-conditioning caveat is CLOSED by F8**; the **aggregate by F9+F10**; **multi-attempt by #111(b)+#101**. Residual caveats: only (a) the estimator's absolute gate-count model is a modelling choice (req G is *relative* — native and offset run through the identical model, so robust); (e) the deployment must actually wire the offset mechanism (#95) and the refresh ratchet (#101) as modelled. No cryptographic gap remains in the ≥-native argument. |

**Struck / downgraded vs. earlier docs:** the "two-family **theorem**", "**provably** capped", and any claim that
a route is impossible are NOT supported — they were narrative. What survives is: F1–F6 (facts) and I1–I4
(reasoning, with the stated confidence and the explicit "not an impossibility" caveat on I2).

---

## Reopened by the retrofit (closures that were interpretation, not proof)

Downgrading the narrative to Tier-2 reopens every option that was shut **only** by reasoning:

| Reopened | Why it is NOT actually closed | Decided by |
|---|---|---|
| **Strict-≥-native for the offset/quantized family (#82/#95)** | I1/I2 are Tier-2; "family A can't be strict-≥-native" was never proven. The verified fact is only the precision threshold (F1), not a security verdict. | lattice estimator **#99** + remapping **#100** |
| **Reaching the ±1/≤ω hint budget WITHOUT small low bits** | I2 is "small low bits *sufficient*", explicitly **not proven necessary**. | public dither **#83**, approximate readout **#96B**, per-signer-challenge **#77/#79/#81**, anti-correlated nonces |
| **#99 as the sole decisive gate for the offset family** | the #103 "DP footing" that de-prioritized it is withdrawn (only Δ2 verified, ε conditional). | run **#99** |
| **Per-signer-distinct-challenge combine** | the #84 linearity argument (Tier-2) doesn't cover it; never tested. | new experiment |

## Consolidated branch status (after the #99→#112 push)

| Branch | Verdict | Basis |
|---|---|---|
| **#95 offset (LEADING)** | **req G ≥ native, window R∈[~3,2¹²]; reduction-backed + model-pinned + aggregate-confirmed** | I5, F8, F9, #95 carry |
| #101 refresh-firewall ratchet | **ELEVATED — buildable companion securing multi-attempt** | #111(b) |
| #82 quantized | riskier — NOT reduction-covered (secret-correlated error) | I6 |
| #83 dither | dead (public=subtractable) / ≡#95 (secret-random) | I6 |
| #110 Sage dual/hybrid | deferred; subsumed by attack-independent reduction for the relative claim | env + I5 |
| #100 remapping | deprioritized — #95 hits ≥native without it (margin tool only) | I5 |
| #70 multi-key, #104 HSS, #73/#74 KEM | pruned under locked req F/E (need setup/interaction) unless a no-setup non-interactive variant appears | docs/45 |
| #88 one-way, #96B approx-readout, #97 ratchet, #77/#79/#81 per-signer-challenge | OPEN alternatives, deprioritized while #95 holds | — |

## Coverage of the reveal-with-noise family (task #112, ledger I6)

The noise-flooding reduction covers a route **only if its revealed error is fresh and independent of the secret**
(`TestTask112_NoiseFloodCoverage`, verified):

| route | revealed error | fresh+independent? | reduction covers? | status |
|---|---|---|---|---|
| **#95 offset** | injected random `r~±R` | **yes** (2 draws differ 2048/2048) | **yes** | ✅ ≥ native by reduction (I5) |
| **#82 quantized** | quant residual `e_q(w)` | **NO** — deterministic fn of `w` (recompute differs 0/2048), so correlated with `s1` via `w=A(z−c·s1)` | **no** | ⚠️ riskier; needs real estimator with *structured/secret-correlated* error model |
| **#83 dither (public)** | common public `d` | — subtractable | n/a | ❌ no hiding (attacker subtracts `d`) |
| **#83 dither (secret-random)** | fresh secret per-signer | yes | yes | = collapses to #95 |

**I6 (interpretation):** the reveal-with-noise win is specifically a **fresh-independent-randomness** win — it
elevates **#95** (and #83-as-secret-random ≡ #95) and does **not** rescue **#82** (deterministic quantization
error is secret-correlated; standard LWE hardness does not transfer; treat as open/riskier). #83-as-public-dither
is dead (subtractable). Confidence: high (the independence distinction is verified; the "secret-correlated error
may be weaker than LWE" is standard caution, not a proof that #82 is broken — it just isn't reduction-covered).

## Reusable principle (recorded) — the noise-flooding req-G test

**Surfaced by #99; attack-independent.** If a route reveals, about a secret `s`, a quantity of the form
`L·s + e` (any public linear map `L`) with **error `e` whose magnitude ≥ native ML-DSA's error** on the same
`(n, m, q, secret-distribution)`, then recovering `s` from that revelation is **≥ as hard as native** — *against
any attack* (primal, dual, kernel, hybrid). Proof: raising an LWE instance's error from `σ` to `σ′≥σ` is a
reduction (add fresh `√(σ′²−σ²)` noise to the low-noise instance), so the higher-noise instance is no easier.
Combined with the estimator-asserted fact that native MLWE hardness is **flat in the sample count**, an attacker
holding *both* the native key and a higher-noise reveal is still ≥ native (raise the reveal-block to native noise
→ stacked all-native-noise instance → flat). **Use:** to clear req G for a reveal-route, you need only show the
reveal is a noised linear image of `s` with noise ≥ native's — no lattice-estimator gamble. **Caveat:** this
needs the reveal to *actually be* of that form with that noise scale (the modeling-pin, task #109). Applies to
re-examine #82/#83/#95 uniformly (task #112).

## NOT reopened (closed by a VERIFIED fact or a locked-requirement conflict — these stay shut)

| Stays closed | Basis |
|---|---|
| Absorbing the carry via the V3 `z*` slack (`A·δ` correction) | **F2** (verified): tall `A`, carry targets reachable 0/256 |
| Bridging a ±2-or-larger carry coordinate with one hint bit | **F6** (verified): `useHint` moves exactly ±1 |
| Threshold / multi-key / HSS / FE with an authority | **requirement conflict**: they need setup/privilege ⇒ violate req F (not a narrative closure) |
| Carry elimination keeping FIPS-standard output via RNS/redundant rep | **F4** (verified): canonicalization re-introduces the carry; Z_q is a field |
