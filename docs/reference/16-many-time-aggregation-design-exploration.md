# 16 — Design-Space Exploration: Many-Time, BLS-like Aggregation of ML-DSA-87

> **Historical / iteration note (2026-06-11).** This document is part of the research/design trail and reflects an **earlier iteration**; some counts, status labels, and construction details predate the current Construction F. The authoritative current specification is **`docs/30`**, the verification status and tallies are in **`docs/31`** and reproducible via **`formal/count-artifacts.sh`** (29 artifacts, 134 lemmas, 33/33 genuineness, 6 Gobra), and the cross-document reconciliation is **`docs/35`**. Numbers below are preserved as the historical record.

**Status:** research design record (Session 3). This document captures, comprehensively and
honestly, an extended design exploration of whether/how ML-DSA-87 signatures can be aggregated
into a *single native* signature that is *many-time* and BLS-like, under strict cypherpunk
constraints. It records **every approach tried, every finding, every limitation, every refuted
idea (with the precise reason), and the differing points of view** (including where the assistant
and an external model, Grok, were each wrong and corrected).

Claim labels used throughout: **[proven]** (algebra/arithmetic that is tight), **[measured]**
(running code, validated against an independent verifier), **[computed]** (numeric evaluation in
`prototype/agg_rejection_calc.py` / `prototype/renyi_leakage_calc.py`), **[structural]** (an
argument about the construction, not a machine-checked theorem), **[cited]** (literature),
**[open]** (not done / no known construction). A central epistemic point (see §16): a *strong
structural barrier with no counterexample* is **not** the same as a *proven impossibility*; this
document keeps them distinct.

---

## 0. The question

> Can 10 ML-DSA-87 signatures be combined into **one** object that (a) is a genuine byte-exact
> ML-DSA-87 signature accepted by the *unmodified* FIPS-204 verifier, (b) has BLS-like aggregate
> properties, (c) has **no security loss** vs ML-DSA-87 (NIST Level 5), and (d) is many-time and
> composable — all with **no trapdoors, no trusted setup, no SNARK/STARK, no TEE, no trusted
> aggregator, non-interactive**?

Short answer developed below: a **single native ML-DSA-87 aggregate exists and works
([measured])**, with **BLS-like verification UX** and **security reducing to ML-DSA's own
assumptions**. But the *many-time* property is the hard part: a rejection-free native aggregate
is **few-time per cohort key** (it leaks the aggregate secret over many uses). Many-time is
recoverable **only** by one of four "levers," and the only one compatible with a byte-exact
native signature is **per-signature key refresh** (content-deterministic), which is many-time at
the cost of per-content public-key availability (a Merkle key-tree). No noise-shaping trick
escapes this.

---

## 1. ML-DSA-87 parameters and notation

```
q = 8380417,  n = 256,  R_q = Z_q[X]/(X^256+1)
(k,ℓ) = (8,7),  η = 2,  τ = 60,  β = τη = 120
γ1 = 2^19 = 524288,  γ2 = (q−1)/32 = 261888,  α = 2γ2,  d = 13,  ω = 75
pk = 2592 B,  sig = 4627 B
‖a‖∞ = max centered coeff;  ‖c·x‖∞ ≤ ‖c‖_1·‖x‖∞ = τ‖x‖∞  (negacyclic convolution)
HighBits/LowBits/Decompose, Power2Round, MakeHint/UseHint, SampleInBall, ExpandA — FIPS-204.
```

Single ML-DSA sign: `y` (‖y‖∞<γ1) → `w=Ay` → `c=SampleInBall(H(μ‖HighBits(w)))` → `z=y+c·s1`,
**reject** unless `‖z‖∞<γ1−β` and `‖LowBits(w−c·s2)‖∞<γ2−β` and `‖c·t0‖∞<γ2`. The mask `y`
is committed **before** `c` (Fiat–Shamir binding); rejection is what makes the accepted `z`
uniform-on-box and therefore secret-independent (→ many-time).

---

## 2. The two aggregation scheme types we considered

Throughout the project there are exactly **two families** (whitepaper §14, "two clusters"):

- **Technique 1 — shared-ρ lattice multisignature (Constructions A/B/C/D).** The aggregate of N
  signatures **is itself a genuine ML-DSA-87 signature** `σ* = (c̃*, z*, h*)` under aggregate key
  `pk* = (ρ, t1*)`, accepted by the **unmodified FIPS-204 verifier**. **This is "the first
  technique." It is NOT LaBRADOR.**
- **Technique 2 — transparent native-lattice proof of knowledge (Construction E).** A Module-SIS
  argument (LaBRADOR-class) that N signatures verify; public, unbounded, arbitrary keys — but a
  **custom (transparent) verifier** and **sublinear (not constant)** size. **This is the
  LaBRADOR one.**

A correction made early in the session: the assistant had been defaulting to "LaBRADOR-class" as
*the* path; that conflated Technique 2's limits with the whole project. The N=10 target is
Technique 1.

---

## 3. Technique 1 in detail — the shared-ρ multisignature (Construction A/B)

Shared seed `ρ ⇒ A = ExpandA(ρ)` for the cohort (epoch parameter). Per signer `i`: `s1ⁱ,s2ⁱ`
(η-bounded), `tⁱ = A·s1ⁱ + s2ⁱ`, plus a one-time proof-of-possession (PoP) at registration.

```
s1* = Σ s1ⁱ,  s2* = Σ s2ⁱ,  t* = Σ tⁱ = A·s1* + s2*,  (t1*,t0*) = Power2Round(t*)
y*  = Σ yⁱ,  w* = A·y* = Σ wⁱ
c*  = SampleInBall(H(μ* ‖ HighBits(w*)))          ← ONE common challenge
z*  = Σ zⁱ = y* + c*·s1*
```

**Correctness identity [proven, measured]** — substitute and the `c*·t1*·2^d` cancels exactly:

```
A·z* − c*·t1*·2^d = w* + c*(t*−s2*) − c*·t1*·2^d = w* − c*·s2* + c*·t0*
```

This is the single-signature identity with aggregate secrets, so `UseHint` recovers
`w1 = HighBits(w*)`, `c̃* = H(μ*‖w1)` holds, and the **standard verifier accepts**. **[measured]**
`pqcrypto.ml_dsa_87.verify` and Cloudflare CIRCL accept these aggregates (n = 2,4,8,16,32).

### 3.1 Correction: it is **non-interactive** (the assistant initially got this wrong)

The assistant first marked Technique 1 as "interactive" (importing the MuSig "needs rounds"
assumption). That was wrong. The signing is **non-interactive** because the **message is
determinable**: every signer independently arrives at the same public message (block/tx), signs
independently, and anyone aggregates. The commit step is not interaction — it's covered by the
determinable message and (later) by context-committed nonces (§12). The corrected residual costs
of Technique 1 are **shared ρ, n-of-n liveness, a cohort cap, and a one-time PoP** — *not* rounds.

---

## 4. Domains — portability, cross-chain, domain-scoped composition

- **The domain must match the (determinable) message.** The aggregate verifies under
  `ctx = QRL‖modification` (message-matched domain), **not** bare `QRL`. Still the unmodified
  verifier (FIPS-204 takes `ctx`), just invoked with the matching `ctx`. Binding the message into
  `ctx` changes only `μ = H(H(pk)‖ctxframe‖M)`, not the commitment `w` — so it does **not** leak
  (avoids the "pin the commitment ⇒ public nonce ⇒ leak" trap).
- **Composition is domain-scoped.** An aggregate lives in one `QRL‖mod` domain; further
  aggregation requires *all* signatures to share that domain, fixed at signing time. Unlike BLS
  (free cross-domain BGLS aggregation), Technique 1 aggregates only within a domain.
- **Accounts are domain-portable (whitepaper §12.3 invariant).** `ctx` is bound into the
  *message*, never the key: private key same, public key same across domains; only the *signature*
  differs. So the **same accounts can re-enter any agreed domain** without re-keying.
- **Cross-chain via shared domain.** A QRL/Sui bridge agrees `ctx = "QRL:SUI"`; both sides produce
  and verify in that one domain with the same `μ`-framing. The aggregate object is domain-bound;
  the *accounts* are domain-portable. Requirement: both chains run ML-DSA-87 verify with that
  `ctx`, agreed out-of-band.

The other "cool parts" (already in the docs/whitepaper) that ride on this: participation
**bitmap** accountability (§12.1), **governance/voting** via domain-separated aggregates +
bitmaps (§12.2, App C, measured vs CIRCL), additively-**homomorphic Module-SIS value tallies**
(App C.2, measured), and the **unified verification form** `A·x ≈ T(message)` (§4, docs/11).

---

## 5. BLS property scorecard for Technique 1 (corrected)

| BLS property | Technique 1 | note |
|---|---|---|
| P1 non-interactive public aggregation | ✅ | determinable message; commit = message-driven, not a round |
| **P2 constant size** | ✅ | **one 4627-B ML-DSA-87 sig, independent of N** (lattice-sized, not 48 B) |
| P3 aggregate verification | ✅ | **exact FIPS-204 verifier** in `QRL‖mod` |
| P4 key aggregation | ✅ | `pk* = (ρ, HighBits(Σtⁱ))` |
| P5 composability / layering | ⚠️ | domain-scoped; **no compressing recursion** (see §8) |
| P6 EUF-CMA, one honest signer | ✅ | reduces to MLWE+SelfTargetMSIS; PoP collapses n-of-n → 1 honest |
| P7 deterministic | ⚠️ | ML-DSA hedged mode |
| P8 no trusted setup | ✅ | Module-SIS/hashes only |

BLS is strictly better only on **constant *bytes* (48 vs 4627), free cross-domain aggregation,
and free unbounded nesting** — but BLS is **quantum-broken** (Shor solves its discrete-log/
pairing). The limits of Technique 1 are the *cost of being post-quantum at all*; BLS pays the
entire bill elsewhere (it does not survive the threat QRL exists to defend against).

---

## 6. Formal-verification status (machine-checked vs measured vs prose)

The `.md` files (incl. this one) are **prose** — no prover touches them. The checked artifacts:

- **EasyCrypt `.ec`** — game-based security at the **abstract-operator** level (`verify`,
  `aggkey`, `msg` opaque; **no `ctx`/domain modeled** — domain is folded into the opaque `msg`).
  Machine-checked, admit-free: A2 EUF-CMA + SUF-CMA, A3 (ZK-A perfect), A4 (rogue-key→single),
  A5 (no-new-power→Module-SIS), the two masking regimes, QROM-A. (`check-all.sh`, `genuineness.sh`,
  `ec-quantum.sh`.)
- **Coq `.v`** — concrete ring algebra: the aggregate-key identity, key/response linearity,
  `aggregate_verifies_2` (**N=2 only, abstract ring, no `ctx`**).
- **Empirical** — Go/CIRCL + pqcrypto acceptance of aggregates (measured, not proof).

**Honest gaps for "the scheme in this domain-keyed form":**
1. **EC↔Coq bridge missing** — the abstract `verify`/`aggkey` are not pinned to concrete
   ML-DSA-87-in-`QRL‖mod`; security and correctness are about *different objects*.
2. **Correctness is N=2, domain-less** — not N=10, not with `μ`/`ctx` binding.
3. **Domain-portability/§12.3, bitmap, governance, tallies** — structural / measured / specified,
   **not machine-checked**.

(The N=10 capstone plan — tasks #7–#12 — closes exactly these gaps: Phase 1A correctness N=10
+ domain, 1B domain invariant, 2C bridge, 3D N=10 security, 4F empirical, plus the concurrent-
security obligation.)

A positive: the EC security games quantify over *all* messages, so EUF-CMA/ZK/etc. **automatically
cover any single domain** including `QRL‖mod` — but they say nothing about the *relational*
cross-domain properties (portability, non-cross-validation), which need their own statements.

---

## 7. The core finding — the rejection-free aggregate is FEW-TIME (leakage analysis)

This is the central technical result of the session. All numbers from
`prototype/agg_rejection_calc.py` and `prototype/renyi_leakage_calc.py` **[computed]**.

### 7.1 What leaks, and why

The published response is `z* = y* + c*·s1*`. The verifier **forces** `c*·s1*` to remain in `z*`
(it is what cancels `c*·t1*·2^d`). Single ML-DSA scrubs the secret dependence via **rejection**
(accepted `z` is uniform-on-box, secret-independent). The aggregate **cannot reject jointly**
(see 7.3), so it runs **rejection-free** with reduced masks `γ1' ≈ γ1/N` to fit the native box —
and a bounded mask is **not shift-invariant**, so each `z*` carries a nonzero statistical
dependence on the fixed aggregate secret `s1*`, **accumulating over Q signatures under the same
cohort key**.

### 7.2 Rejection rates and norm headroom (N=10) [computed]

```
STANDARD single ML-DSA-87:  reps 3.85,  masking ratio γ1/β = 4369,  bit-zero (perfect)

CONSTRUCTION B (rejection-free z; r0 ~ uniform ⇒ native abort), N=10:
  γ1'      ratio   worst ‖z*‖∞   fits γ1−β?   reps(~r0)   leak shift (typ/max per coeff)
  2^15      273     328,870       YES          2.56        5.79e-4 / 2.01e-2
  2^15.67   436     ~524,000      YES (max)    ~2.6        ~4e-4  / ~1.5e-2
  2^16      546     656,550       no (P=0.978) 2.56        2.90e-4 / 1.00e-2
  2^17      1092    1,311,910     NO           —           —
max γ1' for guaranteed fit at N=10 = 52,296 (=2^15.67), ratio 436.
```

So at N=10 the **norm is not the binding constraint** (huge headroom) and reps are actually
*fewer* than native (only `r0` aborts; `z*` never does). The problem is purely **leakage over Q**.

### 7.3 Bit-zero (rejection / Model 1) is infeasible at N=10 [computed]

Per-signer rejection makes each `zⁱ` uniform ⇒ `z*` secret-independent (**bit-zero, many-time**),
but any rejection resamples `yⁱ` ⇒ changes `wⁱ` ⇒ changes `w*` ⇒ changes `c*` ⇒ **all restart**
(joint abort `~exp(−N²·ℓn·β/γ1)`):

```
 N    expected ROUNDS
 4    1.8e3      ← feasible (borderline)
 5    7.3e4      ← infeasible
 10   1.7e18     ← hopeless
⇒ bit-zero feasible only up to N ≈ 4.  (Tiling N=10 → ~3 bit-zero tiles = 3 sigs, not one.)
```

### 7.4 The leakage is query-count dependent — and Gaussian does NOT save it [computed]

`‖c*·s1*‖₂² ≈ τ·ℓn·N·Var(s1coeff) = 60·1792·10·2 = 2,150,400`. Per-signature Rényi divergence
`D₂ = ‖δ‖²/σ_agg²`; bit-loss over Q independent sigs `≈ Q·D₂/ln2`:

```
                       uniform γ1'=52400 (σ_agg 95,669)   Gaussian σ=20000 (σ_agg 63,246)
 Q=2^10 (~1,000)       0.35 bits                           0.79 bits   ← "0.4–0.8 bits" lives ONLY here
 Q=2^20 (~1e6)         356 bits                            813 bits    ← broken
 Q=2^30                3.6e5                                8.3e5
 Q=2^64               6.3e15                                1.4e16      ← catastrophic
```

- **Gaussian masks help the *shape* (no Irwin–Hall peaking) but not the *magnitude*** — the
  dominant term `σ_agg²/‖δ‖²` is the same form; Gaussian is even slightly worse at Grok's σ.
- **Flooding to <1 bit at Q=2^64** needs per-signer `σ ≈ 2.4e12` (**4.6 million × γ1**), giving
  `‖z*‖ ≈ 3.8e13` (**7.2e7 × the native bound**) — impossible inside native ML-DSA. This is why
  Raccoon (rejection-free + flood) has *larger* signatures; the native box can't hold the flood.
- **Direct attack (SNR/regression):** `s1*` is recoverable in **~2×10⁷ signatures** under a fixed
  cohort key. A blockchain produces far more.

### 7.5 Cohort size N vs query count Q — a distinction the docs had conflated

`N` (cohort size, ~thousands feasible by norm) and `Q` (sigs per cohort key) are **orthogonal**.
The docs' "k ≈ thousands" was about **N**. The Rényi bound (was listed **[open]**) is about **Q**,
and the answer is: **Construction B is few-time in Q (safe ~Q ≲ 10³, broken ~10⁷), large in N.**
Correction to the prior masking story: cohort-size ≠ query-count; the rejection-free aggregate is
**few-time**, regardless of how many signers.

---

## 8. Why it leaks / why nesting fails — the binding principle and the four levers

**Binding principle [structural, docs/04].** A constant-size object binding N distinct things is
sound only via **commitment, proof, or secret** — never from "the verification equation merely
passes." A value *derivable from public data* binds nothing (a forger derives it too).

**Nesting [proven, docs/10].** Technique 1 cannot compress recursively:
- *Challenge-collapse:* emitted aggregates have distinct `c*`; merging needs `c*·t1* = Σc*ⱼ·t1*ⱼ`,
  which holds only if all `c*ⱼ` equal. A tree of finished aggregates can't be fused into one sig.
- *Norm-additivity:* a pre-planned tree = a flat aggregate; norm grows with total leaves → same
  cap. Only the **gadget `G/G⁻¹`** refreshes norm, and verifying the refresh **is a proof** (E).

**The four (and only four) levers** to break the leak `z* = y* + c*·s1*` (observed Q×, fixed `s1*`)
— each corresponds to breaking one of {fixed s1*, observable shift, bounded mask}:

| lever | breaks | owner scheme | byte-exact native ML-DSA? |
|---|---|---|---|
| **SCRUB** (rejection) | observable shift | MuSig-L (feasible rejection) | only N≤4 |
| **DROWN** (flood σ) | bounded mask | Raccoon | ❌ breaks norm ×10⁷ |
| **REFRESH** (fresh secret/use) | fixed s1* | Chipmunk (one-time leaves) | **✅ — the only one** |
| **HIDE** (proof) | observable shift | Construction E | ❌ custom verifier |

These are exhaustive (there are only three knobs in the equation). **REFRESH is the unique
native-compatible many-time lever** [structural]; DROWN and HIDE change the verifier, SCRUB is
joint-infeasible at N=10.

---

## 9. Refuted approaches (the dead ends — with the precise reason each fails)

Every noise/algebra trick proposed (by the user, and several by Grok) was examined. All fail for
one of: **(1)** the `z*=0` litmus (binding broken → forgery), **(2)** the native norm box, or
**(3)** Q-independence against a *reused* secret without rejection.

1. **Challenge = domain** (`c̃* = H(domain)` instead of `H(μ‖w1)`). **Forgery.** With a
   commitment-independent challenge, set `z*=0`: `w' = −c*·t1*·2^d`, no binding check fails →
   verifier accepts with no secret, nothing signed. Binding = **self-reference** (`c` depends on
   `w1` depends on `c`), which a domain hash lacks. (docs/04 §3.)
2. **Offset = hash of the context hash** (`c* = H(domain‖H(H(ctx)))`). Still a function of **public
   data** → forger computes it forward, sets `z*=0` → same forgery. **One-wayness ≠ binding**; the
   FS hash is already one-way. Binding needs `w1`-dependence, which iterating a context hash never
   adds.
3. **Coordinated mask "skew" so they compose without leak.** To make `z*` secret-independent the
   mask must *absorb* `c*·s1*`, i.e. `y*` chosen *after* `c*`. But `c* = H(…‖HighBits(A·y*))`
   depends on `y*` ⇒ circular; resolving "mask after challenge" is exactly the forgery of #1.
   Redistributing `yⁱ` among signers keeps `y*` and `z*` fixed — only the *timing* matters, and
   "after" = forgery. Rejection (fresh retries, proper order) is the only legit scrub → joint
   abort.
4. **(1/n) transform + e_mid + "rejection forces the identity"** (Grok). Multiple errors:
   `n⁻¹ mod q` is a **large** element (no integer division) ⇒ `z**` becomes full-size ⇒ fails
   `‖z*‖<γ1−β`; adding `e_mid` injects `A·e_mid` ⇒ breaks the exact identity unless tiny (then
   useless); and **rejection selects among valid outputs — it cannot make a false algebraic
   identity true** (`c̃* = H(μ*‖w1')` is exact 256-bit equality; "≈/within bounds" never satisfies
   it). Grok also reverted to `(c*, z*, h*)` in its own final line, contradicting the step.
5. **Weighted aggregate** `t* = Σ cⁱ·tⁱ` with single `c*` (Grok). Two fatal flaws: a
   challenge-weighted key is **adaptive** (depends on the message via `cⁱ`) ⇒ not a fixed public
   key ⇒ docs/04 "fitted value, not a key" (forgeable); and the identity leaves an uncancelled
   `(1−c*)·t1*·2^d` (full-scale) ⇒ verifier rejects. (Grok's own earlier "EQ2" already said this
   needs all `cⁱ` equal.)
6. **Gaussian "0.4–0.8 bits, certified negligible"** (Grok). True **only at Q≈10³**; the leakage
   scales **linearly in Q** (813 bits at Q=2^20, 1.4e16 at 2^64). The Q-dependence — the whole
   story — was omitted. Grok also widened `γ1' ≈ 1.82e6` (35× over the real max 52,296 — backwards;
   you *reduce* `γ1'`). And it repeatedly invoked "Rescue Prime / STARK / critical-damping ζ" —
   irrelevant to ML-DSA (Rescue Prime is a STARK-friendly hash; there is no second-order system,
   so "damping ratio" has no referent).
7. **Decoys / rolling cohorts ⇒ many-time** (user idea; Grok agreed). **Refuted for persistent
   members.** Leakage is anchored to each **persistent individual `s1ⁱ`**, reused across every
   aggregate that signer joins. Decoys are used once (protect only themselves). They **cannot add
   meaningful hiding noise**: the total mask variance is **capped by the norm box** (`Var(y*) ≤
   ~γ1²/3`; with `γ1'≈γ1/N` it is `γ1²/(3N)` — decoys can make it *worse*); decoy secrets are
   η-bounded (`~β`) ≪ the mask (~52,000) and would need ~10⁶ of them to matter, which the norm
   forbids. So churn of decoys leaves the persistent member's leak rate **unchanged**. Grok hedged
   this once, then re-stated it as a feature — that was the error.
8. **Perlin / multiple moving-mean noise.** No asymptotic help: leakage is governed by **variance**
   (capped by the box), not by the *predictability* of the mean's trajectory — the attacker models
   the (public, deterministic) distribution regardless. A wandering mean adds no variance; any
   *consistent* drift is an estimable bias that **helps** the attacker. Constant factors at best.
9. **Per-signer N-dependent noise.** Can improve *N*-scaling of the per-aggregate quality, but does
   nothing for **Q**-accumulation against a fixed secret — same root cause.

**Common root cause [structural]:** none of these can push the mask variance past the native norm
ceiling, and all leave the **reused** secret `c*·s1*` in `z*` (the verifier forces it). Noise
*shaping* only redistributes within a capped budget.

---

## 10. The three properties that kept getting conflated

A clarifying separation (the source of much confusion in the thread):

1. **Decision integrity** — weight-0 outsiders/decoys cannot bias the outcome. **Solved** by the
   recognized-member-set rule + message binding. ✅ (genuinely good)
2. **Membership privacy** — decoys hide *which* members signed (anonymity set). ✅ (if desired)
3. **Many-time key security** — persistent members' secrets don't leak over Q. **NOT** solved by
   decoys. Requires REFRESH (§11). ✗-via-decoys

The decoy idea is sound for (1) and (2); it does **not** deliver (3). The "decoys ⇒ many-time"
conclusion incorrectly attributed (3) to decoys.

---

## 11. The synthesized construction (the path that holds all constraints)

The only native-compatible many-time lever is **REFRESH**, realized **statelessly on the signer
side** via content-deterministic key derivation — the user's correct insight: *"if it is content
deterministic but the content always changes then it is many-sign."*

```
LEAF:     native ML-DSA-87 aggregate (Construction B)        → byte-exact sig + standard verifier
REFRESH:  s1ⁱ_content = PRF(skⁱ, content),  content always fresh
          ⇒ each derived secret used once (Q=1)  ⇒ no accumulation  ⇒ MANY-TIME
WHO:      per-decision Merkle tree of (memberID, tⁱ_content); publish root (32 B)
DECOYS:   weight-0 (recognized-member-set rule)              → decision integrity + privacy
```

- Borrows **Chipmunk's key-tree** (but with a **native ML-DSA leaf**, not a one-time-hash leaf —
  so it is *not* Chipmunk), **Raccoon's Gaussian masks** (bounded to native γ1, not flooded — *not*
  Raccoon), and **MuSig-L's** efficiency ideas (output is the single native sig — *not* MuSig-L).
  **Does not** use Construction E / any proof (no SNARK).
- **Assumptions:** MLWE + MSIS + PRF/ROM — **≤ ML-DSA's own** (a PRF it already uses).
- Holds **all** constraints simultaneously: many-time ✅, byte-exact native verifier ✅,
  non-interactive ✅, no trapdoor ✅, no SNARK/STARK ✅, no TEE ✅, **no trusted aggregator** ✅
  (see 11.2).

### 11.1 The irreducible cost — fresh secret ⇒ non-derivable public key [proven]

```
You CANNOT have {publicly-derivable pk}  AND  {fresh independent secret}:
  derivable pk ⇒ s1_content = s1_master + public offset ⇒ subtract ⇒ reused s1_master ⇒ LEAKS
  fresh secret ⇒ pk_content is a fresh short-preimage key ⇒ NOT derivable (=solving SIS, no trapdoor)
                ⇒ pk_content must be PUBLISHED or COMMITTED per content
```

So the *signer* is stateless (PRF from content), but the **per-content public keys must be carried**
— a Merkle key-tree (bounded-but-large many-time, exactly the XMSS/SPHINCS⁺ shape) or per-sig
publication. **This is bandwidth/storage, not a weakened security bound.**

### 11.2 The Merkle "who" — cheap by default, trustless via audit

The per-decision tree compresses provenance, but it commits the **who-list**, not the
**binding** that `pk*_content = Σ tⁱ_content`. To keep *no trusted aggregator*:

```
publish per signature:  sig (4627 B) + pk*_content (2592 B) + Merkle root (32 B)  ≈ 7.25 KB
Optimistic (default):   trust pk* vs root; ANY auditor fetches the N leaves (via root) and
                        recomputes Σ → fraud-proof if mismatch.  Trustless under ≥1 honest auditor.
Full (per-verifier):    fetch N leaves (≈N×2560 B + proofs), recompute pk*_content, verify.  Zero trust.
"is member X in it?":   membership proof = O(log N) hashes.
```

`N×KB` is paid **only on audit**. The per-decision tree is the only state, and it's **content-
derived** (no remembered counter).

---

## 12. Context-committed nonces — non-interactivity done soundly (a sub-result)

A sound way to make the common challenge non-interactive (and the right reading of "the challenge
relates to the domain" *without* the §9.1 forgery): derive nonces **secret-keyed deterministically**
`yⁱ = PRF(s1ⁱ, ctx)`, publish `Wⁱ = A·yⁱ`. Then `c* = H(μ*‖HighBits(ΣWⁱ))` is the **standard**
challenge (still binds the commitment `ΣWⁱ` — passes `z*=0`), the verifier is exact, and there is
**no commit-reveal round** (determinism *is* the commitment; defeats rushing). Caveats: **strictly
one-time per ctx** (reuse ⇒ two sigs, same `y`, different `c` ⇒ recover secret), the `Wⁱ` must be
shared/pre-registered to form `ΣWⁱ`, and the multi-session **ROS/concurrent-security** is the
substantive proof obligation (task #12). This composes with §11 (content-refresh is the same
"fresh per ctx" discipline).

---

## 13. Is the ML-DSA-87 signature preserved?

**Yes — the signature object is preserved**, with two honest caveats (about distribution and
key-origin, not validity):

**Preserved (fully):**
- `σ* = (c̃*,z*,h*)` is a **byte-exact 4627-B ML-DSA-87 signature**, accepted by the **unmodified
  FIPS-204 verifier** against `pk*_content`. **[measured]** (pqcrypto + CIRCL).
- The Merkle root, per-content keys, decoys, bitmap are **out-of-band** — not in the signature
  bytes. A validity-only consumer runs standard `Verify(pk*_content, M, σ*)` and ignores them.

**Caveat 1 — `pk*_content` is format-valid but over-norm.** `t* = A·s1*+s2*` with `‖s1*‖ ≤ N·η`
(not `≤η`). Verifier-valid and hint conditions hold for N=10 (`‖c*·s2*‖ ≤ βN=1200 < γ2`; valid to
N≈2000), but it is **not in the image of honest keygen** (secret over-norm). Invisible and
harmless to the verifier.

**Caveat 2 — distribution differs (detectably "an aggregate").** A real ML-DSA `z` is uniform on
the full box (rejection); the aggregate `z*` is a sum of reduced masks ⇒ **concentrated** (smaller
norm, bell-shaped). Consequences: verifier accepts ✅; unforgeable / secret-safe ✅ (Q=1 with
refresh); but **statistically distinguishable as "an aggregate vs a single sig"** ❌. This is
**metadata** (cannot forge, cannot learn who) and is **intrinsic** — a sum of bounded masks can
never be uniform-on-box.

| property | preserved? |
|---|---|
| byte-exact 4627-B format | ✅ |
| unmodified FIPS-204 verifier accepts | ✅ [measured] |
| unforgeable under `pk*_content` (ML-DSA assumptions) | ✅ |
| `pk*_content` keygen-distributed | ⚠️ format-valid, secret over-norm (harmless) |
| `z*` distribution = single-signer | ❌ detectably an aggregate (metadata only) |

If "preserve" means *a third-party ML-DSA verifier accepts it* → **yes, fully**. If it means
*indistinguishable from an ordinary single signature* → **no**, and that's unavoidable for any
linear aggregate (only rejection at N≤4, or a proof, would give indistinguishability).

---

## 14. Blockchain-culture implications (POV recorded from the discussion)

- **vs BLS:** keeps the "verify like a normal signature" UX and is post-quantum from day one, but
  aggregation is **not free** (aggregator does real work + key-tree), signatures are **4627 B vs
  ~96 B**, and many-time needs **key-refresh discipline** (a tree) rather than BLS's true
  statelessness. Provenance/binding to explicit signer sets is **stronger** than BLS's implicit
  model.
- **vs Threshold Raccoon** [cited 2024/184]: a **threshold** (shared key, hidden who) scheme for
  **Raccoon**, not an aggregate for ML-DSA; many-time and clean, but **not byte-exact ML-DSA**,
  needs a dealer + DKG. Validates Construction B's masking direction.
- **vs ZKP/Construction E:** many-time + unbounded recursion + Q-independent, but a **proof layer**
  (custom verifier; and if it counts as SNARK-class, excluded by the no-SNARK constraint).
- **Composition note:** unlike BLS, permutations/membership change the outcome (the aggregate is
  *set-bound*); decoys make this more pronounced — which is a feature for accountable decisions
  (decision integrity) and a difference from BLS's commutativity.

---

## 15. Consolidated numbers (reference)

```
single ML-DSA-87:    reps 3.85,  ratio 4369,  bit-zero (many-time via rejection)
Construction B N=10: γ1' ≤ 52,296 (=2^15.67, ratio 436) for guaranteed fit; reps ~2.56
bit-zero feasibility: N ≤ 4 (N=5 → 7.3e4 rounds; N=10 → 1.7e18)
leakage (rejection-free, fixed key):  ~0.35–0.8 bits at Q=10³;  broken ~Q=10⁷ (recover s1*)
flood to many-time:  σ ≈ 2.4e12 (4.6e6×γ1) ⇒ ‖z*‖ 7.2e7× over native bound — impossible
synthesized cost:    common path ≈ 7.25 KB/sig; N×2560 B only on audit; ephemeral per-decision tree
```

Reproduce: `python3 prototype/agg_rejection_calc.py`, `python3 prototype/renyi_leakage_calc.py`.

---

## 16. Honest epistemic status (the key meta-finding)

The assistant **overstated "impossible"** at one point and corrected it. The accurate status:

**Tight [proven]:** the verifier forces `c*·s1*` into `z*`; a bounded mask is not shift-invariant;
therefore rejection-free `z*` leaks nonzero/sig against a fixed secret, accumulating in Q; joint
rejection at N=10 aborts `~10¹⁸`.

**NOT proven — only "no construction known":** that *no* alternative key/challenge/commitment
structure yielding a **byte-exact ML-DSA-87 sig under the unmodified verifier** can sidestep this;
that **REFRESH is the unique** native-compatible many-time lever (the "four levers" is a heuristic
decomposition, not a lower bound).

A real impossibility would need a reduction *"byte-exact-native + no-proof + many-time at N=10 ⇒
break MLWE/SIS."* We do **not** have it. **The falsifiable target** — what a genuine counterexample
must clear *simultaneously*:

1. **`z*=0` litmus** — a forger with no secret/sub-sigs fails (binding survives).
2. **Native norm box** — `‖z*‖∞ < γ1−β`, output byte-exact 4627 B.
3. **Q-independence** — published-object distribution (Rényi) independent of a **reused** fixed
   secret over unbounded Q, **without per-signature rejection**.

Every approach in §9 fails (1), (2), or (3). "Every attempt here" ≠ "every possible attempt."

---

## 17. Open problems / proof obligations

- **Concurrent-security (ROS / MuSig-L-class)** for the per-content/context signing round (task #12)
  — the substantive content behind non-interactivity; HIGH, research-grade.
- **Per-content Rényi margin** — now trivial at Q=1 under refresh; document the bound.
- **N=10 capstone (tasks #7–#11):** correctness N=10 + domain (Coq), domain-portability invariant
  (Coq), EC↔concrete bridge, N=10 security in-domain, empirical anchor + cross-chain.
- **QROM-B GHHM21** distinct-per-query reprogramming (task #6).
- **The synthesized construction** (§11) — write the concrete spec and add formal targets:
  content→key derivation, the per-decision Merkle key-tree, weight-0 member-set binding, the
  optimistic/full audit model, exact per-signature byte budget.
- **The §16 falsifiable bars** — if anyone proposes a many-time native aggregate, test it against
  (1)/(2)/(3) before believing it.

---

## 18. Points of view — where each party was wrong and corrected (for the record)

**Assistant (Claude) corrections:**
- Said the first technique was "interactive" → **wrong**; it is non-interactive (determinable
  message / context-committed nonces). §3.1.
- Defaulted to "LaBRADOR/E" as *the* path → conflated Technique 2's limits with the whole project;
  the N=10 target is Technique 1. §2.
- The "×2 / 1-bit reduction loss" framing (earlier in session) was **self-inflicted** by collapsing
  `adv_mask ≤ adv_mlwe` into `2·adv_mlwe`; fixed — the honest bound is distinct terms, no security-
  level loss (see `formal/ml_adsa_regimes.ec`).
- Said "impossible" for the strict combo → **overstated**; corrected to "strong structural barrier,
  no proven impossibility" with the falsifiable bars. §16.

**Grok refuted claims:**
- `challenge = domain` and `(1/n)+e_mid` "constructions" — **forgeable / break the identity** (§9.1,
  §9.4); contradicted Grok's own EQ2.
- `γ1' ≈ 1.82e6` widening — **backwards** (real max 52,296). §9.6.
- "0.4–0.8 bits certified negligible" — true only at Q≈10³; **Q-dependence omitted**, off by ~16
  orders at Q=2^64. §9.6.
- "decoys/churn ⇒ many-time" — **only protects one-time decoys**; persistent members leak
  unchanged. §9.7, §10.
- Repeated "Rescue Prime / STARK / critical-damping" — **irrelevant** to ML-DSA. §9.6.
- Grok also concluded "impossible" then "it is not possible" — same overstatement; the correct
  epistemic status is §16.

**User instincts that were correct and adopted:**
- Aggregate verifies like a normal signature; provenance is a separate, on-demand step (matches
  BLS/Ethereum practice). §5, §13.
- Separate **signature verification** from **composition proof** (the verifier checks the sig, not
  the composition; composition recurses). §8, §11.
- **Domain-portable accounts → cross-chain via shared domain.** §4.
- **Content-deterministic key with always-changing content ⇒ many-time** (the correct REFRESH
  realization). §11.
- **Merkle tree for the "who"** (cheap provenance, ephemeral per-decision state). §11.2.

---

## 19. Bottom line

A **single, byte-exact, native ML-DSA-87 aggregate** of N=10 exists, verifies under the unmodified
FIPS-204 verifier, has BLS-like verification UX, and reduces to ML-DSA's own assumptions
**[measured + structural]**. Rejection-free, it is **few-time** per cohort key (leakage proven and
quantified). **Many-time** is recoverable, under all the strict constraints (no trapdoor/SNARK/TEE/
trusted-aggregator, non-interactive), **only** via **content-deterministic key refresh** — a
Merkle key-tree (XMSS-shaped), with weight-0 decoys for decision integrity and membership privacy,
and a Merkle "who" that is cheap by default and trustless by audit. The irreducible price is
**per-content public-key availability** (bandwidth/state), **not** a weakened security bound. The
ML-DSA-87 signature itself is **preserved** in format, verification, and unforgeability; what is
*not* preserved is distributional indistinguishability from a single-signer signature (it is
detectably an aggregate) — intrinsic to any linear aggregate, and not a security defect.
