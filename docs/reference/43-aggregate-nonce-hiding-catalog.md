# Catalog: hiding the aggregate nonce/key (`s1*`) — routes and their costs

**Status: research catalog (Option C, Step 2+).** Companion to [docs/42](42-confining-nonce-exposure.md).
This enumerates every candidate route to prevent recovery of the *aggregate* one-time key `s1*` — i.e. to
hide `y*` so the combination reveals only `HighBits(W*)` — while trying to keep ML-ADSA's defining qualities:
**non-interactive, no trusted setup, no privileged party, byte-exact ML-DSA output, post-quantum.** Each
route is tracked as a task (#69–#75) for deeper exploration.

---

## 0. Two corrections to keep the framing honest

**(a) A combiner that opens `Σlow` CAN forge.** Earlier I loosely said a combiner "cannot forge." That is
wrong. Opening `Σlow` → reconstructing `W*` → `y*` → `s1* = c⁻¹(z*−y*)` gives the **full secret behind
`pk*_C`**; that party can sign anything under it (this is exactly pentest finding #3). What contains it is
**not** an inability to forge — it is: (i) **message binding** makes `pk*_C` single-purpose
(`pk*(m) ≠ pk*(m')`), and (ii) **consumers must verify `pk*` is the committed cohort key for the claimed
message** (epoch tree / `ProvenanceVerifyF`), never trusting a supplied `pk*`. Under (i)+(ii) the forgery is
confined to the one already-agreed, already-spent message. Without (ii) the combiner — like any #3 attacker —
forges freely. So a combiner that recovers `s1*` is a **#3-capable party every slot**; that is precisely why
removing it (or never letting any party see `W*`) is a real security improvement.

**(b) The published signature already hides `s1*`.** From `(pk*, σ*)` alone, `rr2 = A·z* − c·t1*·2^d =
W* + c·(t0*−s2*)` exposes only `HighBits(W*)` (the low bits are masked by the *secret* `t0*,s2*`). Nonce
recovery from the signature is at the noise floor (tested: 0/1792). The leak lives **only** in the transient
combination broadcasts. So "hiding `s1*`" means: compute the challenge without any party broadcasting (or
reconstructing) the full `W*`.

---

## 1. The impossibility that bounds every route

Computing `HighBits(W*)` without revealing `Σ LowBits(wᵢ)` is a **secure function evaluation** on
distributed private inputs. A standard lower bound applies:

> You cannot have **non-interactive + no-setup + no-privileged-party + hides-the-aggregate** simultaneously.

The base scheme spends *nothing* by **not hiding** (`s1*` leaks, contained by binding + one-time). Every route
below buys hiding by spending **at least one** property. The catalog is "which property, and the lightest form
of that spend." This is the trilemma of docs/42 sharpened to an impossibility — the goal of the exploration
(#69–#75) is to find the route whose single sacrifice is most acceptable, or to prove each corner is closed.

### 1a. A working framework: the carry-precision tax and two route families (NOT a proven theorem)

**Epistemic status (read first).** Earlier drafts called this a "two-family theorem" and said the no-setup
corner is "provably capped at ≥Cat-5-absolute." **That was an overreach — absence of a found construction is
not a proof of impossibility ([[dont-conclude-prematurely]]).** Here is the honest split of what holds:

- **MEASURED (solid): the carry-precision tax.** A party that recovers the carry *by estimating `Σlow`* must
  know `Σlow` to `±P* ≈ 2¹³` — **~5 bits finer** than native's nonce granularity `±α/2 ≈ 2¹⁸`. This is robust
  and encoding-independent **for the Σlow-estimation routes** (offset #95, quant #82, source-coding #102, RNS
  #105 — they all literally form a `Σlow` estimate). `option_c_102_sourcecoding_test.go`.
- **NOT PROVEN (folklore/conjecture): the SFE impossibility and the carry-crossing obstruction.** Stated in §1
  and §R4 as informal lower bounds. They block the *naive* public constructions tried so far; they are **not**
  machine-checked impossibility proofs and may have loopholes.

**Scope limit I previously missed:** the tax bounds only routes that **resolve the carry by estimating `Σlow`**.
A route that crosses the carry **without ever forming a `Σlow` estimate** — e.g. per-signer secretly-generated
hints (#76), self-masking à la native — is **not** bound by the tax. I had conflated "resolve the carry" with
"estimate `Σlow`"; they are not the same.

**Existence witness that the hard corner may be non-empty:** *native ML-DSA itself* publishes `HighBits(w)`
while **hiding** `LowBits(w)`, using only the signer's **own** secret (`t0,s2`) plus a public, secretly-
generated **hint** that crosses the rounding boundary — with **zero shared setup**. So "public high bits +
hidden low bits + hint-crossed carry, no shared secret" already exists for **one** party. The aggregate
question is therefore *not* "can family (B) exist with no setup" (it provably can, n=1) but the **narrower,
genuinely open** "does per-signer self-masking **compose** to the aggregate carry non-interactively?"

The two families remain a useful **map**, not a verdict:

| | **Family (A): public Σlow-resolver** | **Family (B): reveal-only-the-carry** |
|---|---|---|
| Carry obtained by | a public party estimating `Σlow` | per-signer/joint secret, no public `Σlow` estimate |
| That party sees | `Σlow` to `±P*` (**5 bits finer than native**) | only `HighBits(W*)` (conjectured) |
| Bar reached *so far* | **≥ Cat-5 absolute** (noise + #99 + #103 DP) | **strict ≥ native** *if it composes* |
| Members shown | offset #95, quant #82, SC #102, RNS #105 | native (n=1 witness); #70, #76, #88 (n>1 OPEN) |

**Caution: even this table is a lens, not a constraint.** It sorts routes by *one* axis (does a public party
form a `Σlow` estimate). Some candidate routes don't respect it — e.g. a **remappable-lattice** route (#95/#100)
is "family (A)" by the table (it does reveal `Σlow` to `±P*`) yet could still reach **strict-≥-native** if that
`±P*` precision is computationally useless for recovering `y` on the remapped basis. So the table's "Bar reached"
column is a *current observation*, not a law; do not use it to rule anything out.

**The frontier is plural, not a single question.** "Compose the carry without leaking more than native" has many
structurally-distinct candidate **objects**, and "a hidden per-signer mask that yields small low bits" is only
*one*. Keep all of these live ([[dont-conclude-prematurely]]):

1. **Sparse-carry encodings** — make the aggregate carry ≤ω-sparse so a summed hint bridges it (small low bits is
   one way; a public dither #83 or a re-encoding is another). Sub-variants differ in *who learns what*.
2. **Dense-carry transfer** — drop the assumption the carry must be sparse; a homomorphic/structured object could
   convey a *dense* carry directly (#70/#88/#104).
3. **Carry elimination** — pick a representation (RNS/CRT #105, modulus-switch #85, carry-save #71) where
   `HighBits` is additive, so there is no carry to cross.
4. **Equation decomposition / inversion** (#80/#81) — assemble the byte-exact signature from pre-inverted shares
   so `W*` and its carry are never formed at all.
5. **Approximate/robust readout** (#96B/#107-open horn) — a nonlinear, position-preserving statistic that returns
   the carry to ≤ω misses *without* precision on `Σlow`.
6. **One-way / forward-ratchet** (#88/#97) — the crossing data exists but is computationally locked except for the
   exact carry output (floor-homomorphic one-way map).
7. **Useless-precision remapping** (#95/#100) — reveal `Σlow` to `±P*` but on a lattice/basis where that precision
   does not recover `y` (the "valid LWE on a remappable space" lever).
8. **Joint-without-DKG** (#70) / **keyed-code** (#102-open) / **HSS** (#104) — secret/joint readout of *only* the
   carry, with the secret never a *shared setup*.
9. **Change what is summed** (#84) — sum a transform `T(wᵢ)` chosen so the high-bit-of-sum is additive *and* `T`
   hides; or a geometric projection/inner-product readout (#86/#98) exact on the carry, lossy on `y`.

The n=1 native witness (self-masking + hint) shows family (B) is non-empty for one party; whether it *composes*
is one probe (#76), not the whole question. Evidence *against* the broad goal would be a real
(machine-checkable) impossibility proof spanning **all** these object classes — which we **do not have**. Until
then the corner is **OPEN on many independent fronts**.

---

## 2. The routes

Legend — *Spends*: the property given up. *Combiner?*: needs a privileged party. *PQ*: post-quantum.

### R1 — Rotating combiner + `commit.go` plaintext carry  · task: (fallback, not pursued)
A rotating combiner opens the homomorphic `commit.go` sum **in plaintext**, computes the carry (ML-DSA-style,
no ZK), broadcasts it; the network forms `HighBits(W*) = Σ HighBits + carry` and the stock FIPS-204 verifier
self-validates. *Spends*: privileged role (the combiner is #3-capable per §0a). *Combiner?* yes. *PQ* yes.
**Prototyped** (`step2_carry_commit_test.go`). QRL already rotates consensus roles, but the trust delta here
is real (combiner sees a spent key), so the program seeks to avoid it.

### R2 — Retained-noise combination (smudging-style)  · **task #69**
Each signer's contribution carries a noise factor with **structurally-unpredictable volume**; the combination
completes only with the noise retained, individual secrets stay hidden by the noise, and it must work for
**partial sets**. Prior art: noise-flooding in **Threshold Raccoon** (EUROCRYPT 2024) — but Raccoon needs a
trusted dealer + interaction. *Prize*: a Raccoon-style smudge that is non-interactive, setup-free,
dropout-robust, byte-exact. *Open*: with `W*` revealed the noise must reconstruct for the verifier; does
*variable-volume* noise dodge the "reveal low bits" wall differently than a fixed mask? Pairs with #75.

### Security bar (governs all routes) + the carry-crossing obstruction
**Acceptance bar (user):** lose no more security than native ML-DSA — every party (incl. combiners) learns no
more than `HighBits(W*)` + a native-safe hint, with **zero accumulable leak over unbounded attempts**
([[option-c-security-bar]]). The persistent `(pk*,σ*)` already meets it (proven); the bar bites on combiners.
This rules out raw-bit reveal (R12) under the strict multi-attempt reading, and points at hiding/joint routes.

**Carry-crossing obstruction (task #87a):** an additively-homomorphic commitment that publicly exposes
`HighBits`-of-the-sum while hiding the low bits cannot exist by the natural construction — adding two
commitments needs the `carry = HighBits(LowBits(x)+LowBits(y))` to move from the *hidden* low register to the
*public* high register, but the carry is a function of the hidden low bits, so a *public* operation can't
cross it. ⇒ the carry-crossing requires a **joint/secret (threshold/multi-key)** step. So the bar-meeting,
no-trusted-combiner route is **R3/#70**, with the joint operation revealing **only** `HighBits(W*)`.

### R3 — PVAC-HFHE → multi-key  · **task #70 — ELEVATED (meets bar by construction)**
Modify PVAC-HFHE (additive+mult homomorphic, F_p, LPN/hypergraph, **single-key** PoC) to **multi-key** so no
single party holds the decryption key → n-of-n partial decryption of **only the carry** (functional decrypt of
a rounding), no DKG. *Spends*: a new (unaudited) assumption + likely one partial-decrypt step. *Combiner?* no
(if multi-key works). *PQ* claimed (needs scrutiny). *Open*: multi-key without DKG, functional decrypt of the
rounding, the real verify API, security of the assumption.

### R4 — Carry-save / redundant representation  · task #71 — **OPEN (negative results so far)**
Find an encoding where the high part is **additive** — signers publish a redundant form whose sum collapses to
stock `HighBits(W*)` without exposing the carries/low bits. **Status: not closed.** What's established so far
(`option_c_71_carrysave_test.go`) are *negative results for the naive approaches*, not an impossibility proof:
- The clean decomposition is real and exact (validated over 2000 random cohorts): `HighBits(W*) =
  (Σ HighBits(wᵢ) + carry) mod m` with `carry = HighBits(Σ LowBits)` and **no interaction term**, *provided the
  low register's high bits are zeroed* so the rollover recombines additively. (This is the correct structure
  for R1/R6 and is the right mental model for R2's noise — see below.)
- But the carry is **irreducible**: the per-signer high bits of the zeroed low register are all 0, so the carry
  is *not* additively derivable from public per-signer data — it requires the low-bit **sum** (Lemma 1).
- And `HighBits(W*)` is a **non-constant function of an individual signer's low bits even with that signer's
  high bits fixed** (Lemma 2) — so any per-signer encoding that lets the cohort compute it *publicly* leaks the
  low bits (hence `yᵢ`). Subsetting the public encodings makes it strictly worse.
- **Escapes** (both leave R4's "free" corner): correlated randomness so the sum doesn't compute on subsets/
  variations (= masking = **setup**, R6), or a homomorphic encoding needing **decryption** (= combiner/
  threshold, R1/R3). Carry-save only *defers* carry resolution; the final resolve still needs `Σ LowBits`.

**Takeaway (not a verdict):** the *naive* "publish a per-signer redundant encoding and compute HighBits
publicly" fails — and the decomposition is genuinely useful (it's how R1/R6 compute the carry, and it locates
where R2's noise lives). But these are negative results for specific encodings, **not** a proof the route is
closed. Untried directions to keep digging: encodings that are only well-formed for the *full* set (without a
shared secret), algebraic/structured representations, or representations that reveal a *coarsened* carry that
provably leaks o(1) about any individual. Keep R4 OPEN.

### R5 — Non-interactive coordinated rejection / perturbation (HVZK closer)  · **task #72**
The *complement*, not a standalone hider: once `y*` is hidden (R2/R3/R4), rejection sampling / a perturbation
closes the residual *distributional* `z*` leak, as in real ML-DSA. *Open*: ML-DSA rejection resamples `y`,
which in the aggregate changes `W*`→`c*` (why Construction B is rejection-free with wide masks); is a
non-interactive coordinated rejection or post-hoc perturbation possible (content-index advance, deterministic
re-derivation)? *Spends*: ideally nothing. *Combiner?* no. *PQ* yes.

### R6 — One-time pairwise KEM (ML-KEM) masking  · **tasks #74 (+#73, #75)**
Per-signer masking (hides individuals; +rounding for the aggregate) with pairwise secrets from a **one-time**
ML-KEM exchange at registration, reused across contents. *Spends*: setup (O(n²) pairwise state) + dropout
machinery. *Combiner?* no. *PQ* yes (ML-KEM). *Open*: can published registry ciphertexts make per-pair
derivation effectively non-interactive after one setup epoch; re-keying on membership change; dropout (#75).

### R7 — PQ-NIKE (would make R6 non-interactive & setup-light)  · **task #73**
EC gets pairwise secrets free via static Diffie–Hellman (a NIKE); PQ lacks a practical one — the single place
masking is genuinely worse than EC. Research CSIDH (slow, isogeny; security debate) + competitors (CSI-FiSh,
CTIDH, others) and any non-isogeny PQ-NIKE. *If* a usable PQ-NIKE exists, R6 becomes non-interactive with only
registration-level setup. *Open*: is any PQ-NIKE practical/safe enough; user has many specific questions.

### R8 — Hint-summation / bounded carry-hint aggregation  · **task #76 — PRIORITY** [Grok thread]
The most concrete new lead. In ML-DSA the *only* public info about `w`'s low bits is the **hint `h`** — sparse
(≤ ω ones; ~83 B for ML-DSA-87), revealing only **carry indicators** (boundary crossings vs a small
secret-bounded perturbation), **not** the `w0` values — and ML-DSA's proof shows this **does not leak**
`y`/`s1`/`s2`. So a per-signer hint is a *coarsened carry that provably leaks ~o(1)* — exactly the kind of
low-bit info we can afford to publish. Replace "publish full `wᵢ`" with "publish `HighBits(wᵢ)` + a bounded
hint," and **sum the bounded hints** (generalized multi-valued `UseHint` over small integers) to get the
aggregate. **Re-scaling** kills the aliasing: effective noise `∝ nβ/α_eff`, pick coarser `α_eff` (or
center/round `h_sum`) so it stays `< 1`. Precedent: threshold ML-DSA (TALUS) — and **ML-ADSA already lives in
that favorable shared-`c*`/single-signature regime**, not the hard independent-aggregation case. *Spends*:
ideally nothing (no setup, no combiner) — *if* it works. *PQ* yes. **Key open questions (do NOT pre-conclude):**
(i) the hint normally aids *verification* (needs `z*`), but our bottleneck is *challenge derivation* (needs
`HighBits(W*)` before `z*`) — can a hint-like object be published at commit time? (ii) does summing per-signer
hints give the *aggregate* carry `HighBits(Σw0)` without computing `Σw0`? (iii) re-scaling factor + abort
probability for `n` signers; (iv) does the bounded-hint reveal stay within ML-DSA's proven no-leak envelope at
the aggregate.

**DATA so far (`option_c_76_hint_test.go`, route OPEN):** the commit-time inter-signer carry is **dense**
(nonzero on 26% of coeffs at n=2 → 83% at n=64) but **small-valued** (max ±1→±7). *Dense* because it comes
from full-sized low bits `w0ᵢ∈(−α/2,α/2]` (~2¹⁷), **not** the small `β≈120` perturbations that make
threshold-signing hints sparse — so Grok's sparse-hint+re-scaling (correct for `β`-sized perturbations) does
**not** transfer as-is to the commit-time carry, and the carry can't be packed into the *binary* FIPS-204
hint. *Small-valued* means it IS a compact small-integer vector (~1 KB) — a **generalized multi-valued hint**
— so the natural fork is a slightly-extended verifier (#80: "verifies like ML-DSA," not byte-identical). The
carry is also **irreducibly joint** (every signer's `HighBits(LowBits(wᵢ))=0`), so computing it still needs
`Σw0` (joint sum / combiner / a verification-time relocation). Untried from here: #80 generalized-hint at
verification, shrinking the per-signer perturbation so the carry turns sparse, #77/#79.

### R9 — Split-nonce (revealed mask + hidden HVZK nonce)  · **task #77**
`yᵢ = y_pub,i + y_sec,i`; aggregate/reveal only the public part's commitment for combination, hidden part
carries HVZK hiding of `s1`. Hiding magnitude is cheap (modest `γ1` noise, not flooding). *Open*: interaction
with the carry / challenge derivation. *Spends*: TBD. *PQ* yes.

### R10 — BDD/LWE-hardness hiding  · **task #78**
Make `s1*` recovery decode-LWE/BDD-**hard** rather than linear (this is *how ML-DSA's own HVZK works*); the
obstacle is that exact `W*` makes it linear, so publish only a hardness-preserving function of `W*`. *Open*:
port to the revealed-aggregate setting with non-interactive challenge derivation. *Spends*: TBD. *PQ* yes.

### R11 — Full-set-only encodings (no shared secret)  · **task #79**
Per-signer encodings that combine correctly *only* for the whole set (garbage on subsets) **without** pairwise
secrets — using registry / `pk*` / epoch-tree / bound-content structure to bind to the full cohort, dodging
the #71 subset-differential leak. *Open*: does full-set binding inherently need correlated setup? *Spends*:
ideally nothing. *PQ* yes.

### R12 — Quantized low bits + sparse hint bridge  · **task #82 — PROMISING** [suppressor/ADC lens]
The strongest lead so far. Key reframe (user): the carry need **not** be exact — ML-DSA is non-exact by design,
and a sparse hint (≤ω) bridges boundary cases. So each signer publishes `HighBits(wᵢ)` + only the **top b
low-bits**; the cohort reconstructs `HighBits(W*)` *approximately*, and the boundary **misses** (where it
differs from true) are bridged by a hint. **Measured (`option_c_82_quant_test.go`):** at **b≈4–7**
low-bits/signer the misses are already **sparse (≤ω=75)** — n=8: 73 misses@b4, 17@b6, 9@b7 — with a **large
hiding margin** `e=±α/2^(b+1)`, `e/β ≈ 17–136` (the `y`-uncertainty dwarfs the `c·s1` signal). `b` grows only
~`0.5·log2(n)` (b=4 for n≤8, 5 for n=16, 6 for n=64). *Spends:* ideally nothing (no setup, no combiner; a few
low bits transmitted). *PQ* yes. **Two open questions to settle (NOT concluded):** (1) **LWE/BDD hardness** at
these params — `e/β` large is encouraging, but the noise rate `e/q≈2^-9…2^-12` is low; needs a real lattice
estimator (possibly + R-dither #83 to raise effective noise); (2) **hint-bridging construction** — can the ≤ω
misses (plus the normal `c·t0` corrections) live in a *byte-exact binary hint*, and does the
commit-over-approximate / verify-recomputes-approximate flow close?

### R13–R16 — further transformation lenses (tasks #83 dither, #84 transform-lossiness, #85 modulus-switch, #86 projection/finite-difference)
DC-offset/subtractive dither to reshape/uniformize the carry (#83, pairs with R12); DFT/NTT lossiness to
sparsify the carry or under-determine `y` (#84); modulus switching to simplify the low-bit structure (#85);
rank-deficient projection / carry-as-derivative views (#86). See the tasks for the precise statements.

**#84 — transforms TRIED and ruled out for linearizing the carry (`option_c_84_linearize_test.go`; only the
tried ones are eliminated — untried stay OPEN):** T1 plain-linear/scaling (HighBits non-additive 1007/4000 &
non-homogeneous 1994/4000 ⇒ no plain linear functional equals it); T2 NTT/DFT (carry dense 1376/2048 in coeff
domain, still dense in NTT — no sparsify, HighBits doesn't commute with NTT); T3 mod-α quotient (`q ≡ 1 mod α`
⇒ no ring-hom; residue is the *leaky* low part, not the carry); T4 carry-save (#71, defers ≠ eliminates).
**Structural pattern:** `HighBits` is a FLOOR (geometric/ordering, not an algebraic homomorphism) — so
algebra-preserving transforms don't linearize it, and pure *hiding* transforms (DLOG/phase, non-PQ) hide the
carry too. This **sharpens toward #88** (non-linear / computational / inexact transforms); it does **not**
close #84 — untried: non-linear lifts, mixed-radix/CRT views, data-dependent/learned bases, maps exploiting
`A`'s structure.

---

## Crystallization (the obstruction in one line) — from the Fourier lens (#93)
`HighBits(W*) = ΣHigh (additive, free) + carry`, and **the carry is exactly the periodic sawtooth term of the
floor's Fourier series.** That periodic term is *multiplicatively homomorphic* over signers via phases
`e^{2πi·w0_i/α}` — but the readable phase yields `Σlow mod α` (the **leaky** low part), while the integer carry
needs a low-frequency phase that reveals `Σlow`. Over reals the phase leaks; over a DLOG group it hides but is
unreadable (non-PQ). **So the entire problem is: a PQ "partially-readable phase" — a representation where the
floor's Fourier modes are mult-homomorphic AND readable to *exactly* carry-precision without revealing `Σlow`
(#93).** Equivalent restatements that would each solve it: a transform that *linearizes* the carry (#84), a
one-way structure opening only into `HighBits(W*)` (#88), or accepted registration-setup correlated randomness
(#73/#74). The carry is `o(1)`-small (±7) and `≤ω`-sparse-bridgeable at modest resolution (#82) — the only
thing missing is reading it without revealing `Σlow`.

## Leading candidate + the decisive gate
**R18 — secret tolerated-offset carry (task #95), no setup.** Each signer publishes `HighBits(wᵢ)` + a noised
low part `w0ᵢ + rᵢ` with a **secret, independent** offset `rᵢ` *tolerated as noise (never subtracted)* — so no
cancellation, no shared secret, non-interactive, multi-attempt-safe (fresh `w0ᵢ` & `rᵢ` per content). **Tested
(n=64):** `R=2¹¹` → 27/2048 carry misses (≤ω, hint-bridgeable), hides `w0ᵢ` to `±2048 = 17β`; `R=2¹²` → 60
misses, `34β`. This **dissolves the masking-needs-setup dilemma** (the offset is tolerated noise, not a mask to
remove). It's the concrete, working shadow of the #93 PQ-lattice-phase (the `rᵢ` = RLWE small-vector noise).

**The decisive gate (shared by R12/R13/R18 = #82/#83/#95):** does revealing `w` to `±R` keep `s1`/`y` recovery
**≥ native ML-DSA hardness** (the bar)? The offset raises the effective noise (favorable), but the rate
`R/q ≈ 2⁻¹²` is low → a **real lattice-estimator** question on the exact instance (recover small `s1` / `y`
from `w=A·y` known to `±R`, given `z=y+c·s1`, `q=8380417`, `(K,L,N)=(8,7,256)`, `c` weight `τ=60`). This is now
the single most decisive open computation: it adjudicates the entire no-setup "reveal-coarse-noised-low-bits"
family in one shot. The zero-leak alternative that *skips* the estimator is #93 (partially-readable PQ phase).

## Excluded (per user direction)
- **ZK proof systems** (LaBRADOR/Greyhound/lattice SNARKs) — excluded outright for now.
- **Generic MPC** (additive-secret-sharing carry, interactive multi-key) — excluded as interactive, *unless*
  modifiable to non-interactive.
- **Interactive commit–reveal / 2-round multisig (DOTT-style)** — rejected: not new, gives up
  non-interactivity.

## Weak / backlogged paths (documented, not main focus)
- **R17 — Σhi-challenge / non-byte-exact (task #90).** Meets the bar non-interactively (only high bits ever
  published) BUT is not byte-identical, and **likely fails composition**: its challenge basis (`Σhi`) differs
  from a standard ML-DSA sig's (`HighBits`), so re-aggregating it *with* plain sigs or other aggregates has no
  clean mechanism. **User gate:** acceptable only if it can aggregate *with* non-aggregate **and** aggregate
  sigs. Backlogged. Note: "composes with everything" essentially **re-imposes byte-exactness** → main focus
  stays byte-exact + meets-bar + composing.
- **Hjorth / EMD / Hilbert–Huang over signature ordering (task #91).** Doesn't fit: order-dependent (vs the
  mandatory order-independence), participation-variable / yes-no aggregates are separate, and they're
  data-adaptive non-linear *analysis* tools (not homomorphisms preserving the lattice structure). Set aside.
- **Cross-claim "disposable" low bits as a collective hint (task #92).** Borrowing known low bits from a
  *different* claim doesn't help THIS claim's carry: the per-content refresh makes cross-claim low bits
  **independent** (zero mutual info — the very property that's load-bearing for security), and *known* values
  can't hide (subtractable). Making them help requires **correlating** claims → reintroduces nonce-reuse-style
  key-recovery risk. One sliver kept: a *public* reference as a shared **dither** to reshape this claim's carry
  statistics (ties #83). Weak.

### R19 — compression into nonvector magnitudes / distance metrics  · **task #107 — characterized (one horn OPEN)**
Reveal scalar invariants (norms `‖lowᵢ‖`, distances `d(wᵢ,ref)`) instead of the low-bit vector — lossy,
dimension-collapsing, one-way-ish. `option_c_108_magnitude_test.go` establishes a **dichotomy**:
- **E1** a magnitude is an `Sₙ`-orbit invariant; the per-coefficient carry is *not* orbit-invariant — a witness
  pair `x`, `perm(x)` with identical L1/L2/L∞ norm differs in carry on 4/8 coords. ⇒ a single magnitude cannot
  yield the carry.
- **E2** *aggregate-vs-hide*: a sketch linear enough to aggregate across signers (`Σᵢ⟨g,lowᵢ⟩=⟨g,Σlow⟩`, verified)
  is a functional of the **leaky `Σlow`** (≡ #93/#94); a nonlinear magnitude hides but is non-additive
  (`Σ‖lowᵢ‖≠‖Σlow‖`) **and** positionless. No middle term among the tested forms.
- **E3** distances are **affine** in the secret (polarization `‖x−p‖²−‖x‖²=−2⟨p,x⟩+‖p‖²`) ⇒ **multilateration**:
  1 norm + `D` coordinate-distances recover the secret EXACTLY (worst-coord err 0) → the metric route
  **accumulates** across attempts → fails the multi-attempt zero-leak clause.

Note HighBits *itself* is already a distance map (nearest α-coset = CVP-lite), so "recast as distance"
re-derives the #84 floor/rounding structure. **OPEN on one horn only:** a *robust/approximate* aggregate
statistic — a **nonlinear, position-preserving, lossy** sketch (per-coordinate median/trimmed estimator, or a
metric embedding contractive only *off* the carry subspace) that returns the aggregate carry to ≤ω misses
without being linearly invertible to `Σlow`. Such an object must evade **both** E2 horns; existence ties to #88
(one-way) and #96 (approximate hypergraph reconstruction).

### R20 — distributed source coding for the carry  · **task #102 — characterized; yields the CARRY-PRECISION TAX**
Slepian–Wolf / Körner–Marton / Orlitsky–Roche compute a *function* of distributed sources at reduced **rate**.
The cohort needs only `carry = round(Σlow/α)`, not each `lowᵢ`, so source coding *should* convey it cheaply.
`option_c_102_sourcecoding_test.go` confirms a real rate saving (≈52%: ~11 vs ~23 bits/coord) **but** shows
rate↓ ≠ hiding↑, and in doing so measures the program's sharpest unifying quantity:

**The carry-precision tax (measured).** Resolving the byte-exact carry forces knowing `Σlow` to **±P\* ≈ 2¹³**
(largest precision keeping carry-misses ≤ ω over `KN=2048` coords). Native ML-DSA's own nonce granularity is
`±α/2 ≈ 2¹⁸`. So **any byte-exact-carry route must learn `Σlow` ≈ 5 bits *finer* than native reveals of a
single nonce** — an irreducible property of the rounding boundary, identical for offset (#95), quant (#82),
source-coding (#102), and RNS (#105). Linear/Körner–Marton syndromes can't dodge it: the carry is a *nonlinear*
floor (a random linear functional tracks the carry sign at chance, ~14/32), so determining it needs full ±P\*
precision anyway.

**Consequence — the viable-family dichotomy (this is the load-bearing takeaway for the whole catalog):**
- **(A) public-resolver routes** (offset/quant/source-coding): a public party resolves the carry ⇒ sees `Σlow`
  ~5-bits-finer-than-native ⇒ **cannot be strict-≥-native**; only reachable target is **≥Cat-5 absolute** via
  added noise (the #95/#99 estimator + #103 DP framing).
- **(B) reveal-only-the-carry routes**: the ~5-bit-finer precision is **consumed inside a secret/joint step** and
  never exposed to any single party ⇒ **strict-≥-native achievable**. Only threshold/multi-key (#70) or a
  one-way commit-time structure (#88) live here.

**OPEN:** Körner–Marton over a *secret/keyed* linear code (keyed syndrome) could move the decoder's view from
`Σlow` toward only-the-carry, migrating source coding from family (A) toward (B); ties #88/#100.

## How the tasks relate
- **#69 (retained-noise)** is the most novel and, if it works, potentially spends the least — pair with
  **#75 (dropout)** and close with **#72 (rejection/HVZK)**.
- **#70 (PVAC multi-key)** and **#71 (carry-save)** are the two "no-combiner, no-setup" long shots; #71 may
  resolve to a clean impossibility.
- **#73/#74/#75** form the masking branch (real but spends setup); #73's PQ-NIKE question gates whether that
  branch can be non-interactive.

The standing instruction: dig into every route until each is either a working construction or a rigorous dead
end. "There must be a way" — the catalog is the map for finding it.
