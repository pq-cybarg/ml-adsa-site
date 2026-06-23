# Necessity audit — what do we *really* need for a FIPS-verifiable ML-DSA aggregate signature?

**Purpose.** A first-principles teardown driven by the directive: *"Why do we need things? Do we really? Are
there other re-interpretations? What alternative tools exist? What do we REALLY need?"* The discipline here is
to separate **what FIPS-204 actually demands** (the only hard floor) from **what we imposed** (design choices we
have been treating as laws), and to locate exactly which self-imposed constraint creates the carry problem.
Companion to the route catalog [docs/43](43-aggregate-nonce-hiding-catalog.md). Nothing here closes a route; it
re-scopes the search ([[dont-conclude-prematurely]]).

> ## ⛔ REQUIREMENTS ARE LOCKED (user, 2026-06-16: "I refuse to drop our requirements period.")
> **All external requirements are inviolable and are NOT design variables.** Every one of these is held, always:
> **(A) byte-exact** unmodified-FIPS-204-verifiable · **(B) one compact aggregate** signature · **(E)
> non-interactive** · **(F) no trusted setup / no shared secret** · **(no privileged party / no combiner)** ·
> **(G) hide — lose no more security than native ML-DSA** · **(H) order/grouping-independent, partial sets,
> hierarchical** · **(PQ)**.
>
> This audit's ONLY legitimate role is to separate those **requirements** (locked) from our **internal
> mechanisms** (free to change *as long as every requirement above still holds*). The carry problem comes from a
> *mechanism* (naive additive combine), not from any requirement — that is the one useful, still-valid finding.
> **Any earlier table cell that suggested "relax requirement X" is REJECTED and struck below.** Do not read this
> document as offering escape hatches; there are none. We solve the hard problem with every requirement intact.

---

## 0. The ONLY hard floor: the verifier's acceptance predicate

The unmodified FIPS-204 `ML-DSA.Verify(pk*, M, σ*)` (our `mldsa87.go:456`) accepts **iff every one** of these
holds — and it checks **nothing else**:

| # | Check | Exact condition |
|---|---|---|
| V1 | encoding | `len(pk*) = 2592`, `len(σ*) = 4627` (param-set sizes) |
| V2 | hint well-formed | `h*` decodes; total ones `≤ ω = 75` |
| V3 | **norm** | `‖z*‖∞ < γ1 − β = 2¹⁹ − 120`, every coordinate |
| V4 | **hash/high-bits** | with `c* = SampleInBall(c̃*)`, `w1' = UseHint(h*, A·z* − c*·t1*·2^d)`, then `c̃* = H(μ* ‖ w1Encode(w1'))` |

where `A = ExpandA(ρ*)`, `μ* = H(H(pk*) ‖ ctx ‖ M)`. **That is the entire contract.** Everything else in our
program — sums, shared challenges, hiding, non-interactivity — is a *means we chose*, not part of this contract.

**Immediate consequence (the reframing).** The verifier does **not** require that `z*` be a sum, that `t1*` be a
sum, that a secret `s1*` exist, that `w1'` equal `HighBits(Σwᵢ)`, or that anything be "aggregated" at all. It
requires one tuple `(ρ*, t1*, c̃*, z*, h*)` satisfying V1–V4. **The carry problem is not in this contract.** It
enters only when we *additionally* decide `z*=Σzᵢ`, `t1*=Σt1ᵢ`, and `c̃*=H(μ*‖HighBits(Σwᵢ))` — three choices
that together force `HighBits` across a sum, which is where the non-additive carry lives.

---

## 1. Requirements (LOCKED) vs. mechanisms (free) — the only honest split

The earlier "do we really need it?" column asked the wrong question of the *requirements*. The answer for every
requirement is **yes, always** (locked banner above). The right question is asked only of our **mechanisms**:
*do we need this particular implementation choice, given the requirements are fixed?* Two tables.

**Table 1 — REQUIREMENTS (locked; not design variables):**

| Req | Statement | Held |
|---|---|---|
| **A** | Output verifies under *unmodified* FIPS-204 (byte-exact) | ✅ always |
| **B** | `σ*` is one compact aggregate signature | ✅ always |
| **E** | Non-interactive (no signer↔signer rounds) | ✅ always |
| **F** | No trusted setup / no shared secret / no privileged party | ✅ always |
| **G** | Hide: lose no more security than native ML-DSA (incl. combine-transient) | ✅ always |
| **H** | Order/grouping-independent; partial sets; hierarchical | ✅ always |
| **PQ** | Post-quantum (MLWE/Module-SIS/SelfTargetMSIS + PRF) | ✅ always |

**Table 2 — MECHANISMS (our choices; changeable *only if* all of Table 1 still holds):**

| Mech | Current choice | Is the *choice* forced? | Free move (requirements intact) |
|---|---|---|---|
| **C** | additive combine `z*=Σzᵢ`, `t1*=Σt1ᵢ` | **NO — the carry's root cause** | Any **order-independent** (req H) combine that still yields a byte-exact (A), hiding (G), no-setup (F), non-interactive (E) tuple. Symmetric ⊋ sum. Fronts #80/#81/#84/#86. |
| **D** | `c̃* = H(μ* ‖ HighBits(Σwᵢ))` | follows from C only | Per V4 the hash is over `HighBits(A z*−c* t1*·2^d)` — *what that value is* depends on the combine. Change C ⇒ D changes. |
| **carry-exactness** | resolve the carry exactly | **NO** | The hint absorbs ω coords free + native-safe (tool 3.1); carry need only be ≤ω-sparse, not exact. |
| **compute-`Σlow`** | combine forms `Σlow` | **NO** | Nothing requires forming `Σlow`; a combine that crosses the carry without it is allowed (docs/43 §1a). |
| **same `A`** | shared `A` across cohort | benign public param | A *public* common matrix is a published parameter, not a *secret* setup — compatible with req F. Keep. |
| **`z*` value** | `z*` set by the sum | only V3 (`‖z*‖∞<2¹⁹−120`) is required | V3 is a **bound, not an equation** — large slack to choose `z*` (tool 3.2). |

**Net:** under locked requirements, the *only* root-level mechanism freedom is **the combine operation itself**
(C), which must stay order-independent and satisfy A+E+F+G — plus exploiting the free tools (§3). The carry is a
property of the *naive-sum* combine, not of any requirement; replacing that combine (without dropping anything)
is the legitimate root attack.

---

## 2. Re-interpretations that respect every requirement

### 2.1 The carry is a *mechanism* artifact (naive sum), not intrinsic to aggregation
`HighBits` is non-additive, so `HighBits(Σwᵢ) = ΣHighBits(wᵢ) + carry`. The carry exists **because the combine
mechanism sums the `wᵢ`** — not because any requirement demands it. The verifier (A) never asked for a sum; req H
asks only for *order-independence*, which sum is one (not the only) way to achieve. An order-independent combine
that produces a V1–V4 tuple **without forming `Σwᵢ` and taking its high bits** has *no carry to hide* — while
keeping A,B,E,F,G,H,PQ all intact. ⇒ fronts that replace the linear-sum combine (#80, #84, #86) attack the root.

### 2.2 `c̃*` is pinned to high bits — but *which* value's high bits is a mechanism choice
V4 forces `c̃* = H(μ* ‖ HighBits(A z* − c* t1*·2^d))`. We cannot dodge "hash of some high bits" (req A). **But the
value `A z* − c* t1*·2^d` is whatever our combine makes it.** In native signing the *signer* resolves the
circularity (`c` depends on `w`, `z` depends on `c`) using secret knowledge + the hint. The aggregate question
is *who resolves the circularity and with what knowledge* — within non-interactivity (E) and no-setup (F).

### 2.3 ~~Byte-exactness is the prize, not a law~~ — REJECTED (req A is locked)
*Struck per the locked-requirements directive.* Byte-exact unmodified-FIPS verification is a **hard requirement**,
not a negotiable. We do **not** consider a QRL-native / `Σhi` verifier. Every route must output a tuple the stock
FIPS-204 verifier accepts. (The only residual use of the V1–V4 analysis is to know precisely *what* that stock
verifier checks, so we satisfy it exactly — never to weaken it.)

### 2.4 ~~Hiding may be unnecessary if containment is airtight~~ — REJECTED (req G is locked)
*Struck.* "Lose no more security than native ML-DSA" is a **hard requirement**, including the combine-transient.
Containment (binding + one-time + consumer-checks-`pk*`) is **necessary but not sufficient** and does **not**
substitute for hiding — both are required. We pursue Option-C hiding to full strength with no requirement waived.
(Containment hardening remains valuable in parallel, but it is *additive to*, never *instead of*, hiding.)

---

## 3. Under-exploited tools (the "what alternative tools exist" question)

1. **The hint is a free ±1 corrector on ω=75 coordinates.** V4's `UseHint` lets the verifier *adjust* high bits.
   We have mostly treated the carry as needing exact resolution; up to ω of it is **free** to absorb (#76/#82).
2. **V3 is a norm bound, not an equation.** `z*` only needs `‖·‖∞ < 2¹⁹−120`. Any construction can use this
   slack — e.g. add a structured term to `z*` that cancels a carry-creating quantity while staying in-norm.
3. **`t0*` (low bits of `t*`) is secret and already masks `w` in native.** The native scheme hides `LowBits(w)`
   precisely via the secret `t0,s2` + hint. That mechanism (the n=1 family-(B) witness, docs/43 §1a) is a tool,
   not just a fact.
4. **Deterministic nonces** remove the commit-round's randomness (already used) — collapses some interaction.
5. **`μ*` is ours to define.** What goes into the message representation (domain sep, cohort id, epoch) is a
   free design surface (used for binding; possibly more).
6. **We choose the cohort's `pk*` construction.** `t1*` need not be `HighBits(Σtᵢ)`; it is any value we publish
   and that consumers bind to (#80).

---

## 4. Re-scoped route map — which *mechanism change* opens which front (requirements all locked)

**No requirement is a variable.** The only legitimate freedom is the *combine mechanism* (C) and the free tools
(§3), used to satisfy **all** of A,B,E,F,G,H,PQ simultaneously:

| Mechanism change (requirements ALL intact) | What it attacks |
|---|---|
| Replace naive-sum combine with another **order-independent** combine | #80 equation-inversion, #84 transform-then-combine, #86 projection — produce a byte-exact tuple **without forming `Σwᵢ`**, so no carry, while keeping E/F/G |
| Use the **hint** to absorb a ≤ω-sparse carry (native-safe) | #76/#82 — exactness not required |
| Exploit **V3 slack** (`z*` is bounded, not fixed) | add an in-norm structured term that cancels carry-creating quantities |
| Exploit **`t0*`/secret-mask** (the n=1 family-(B) tool) | #88/#77 — hide low bits like native does, composed |
| Design **`μ*` / `pk*` construction** | #80 — bind/structure without leaking |

**The discipline:** the carry and most of Option-C's difficulty sit downstream of the *naive-sum combine
mechanism* — a choice, not a requirement. We attack that mechanism (and use the free tools) to meet **every**
locked requirement at once. We never "confuse hard with impossible," and we never buy easiness by waiving a
requirement — there are no escape hatches. The obsessive sweep (docs/43 fronts, one at a time) runs entirely
inside this locked box.
