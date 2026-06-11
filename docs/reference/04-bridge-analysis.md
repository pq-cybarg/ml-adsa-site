# LMSA — Bridging the coordination gap: the c*-inverse construction and why it's a cliff

Question (user): MLADSA gives an exact-verifier aggregate but needs a shared challenge
(coordination/shared-context, single-purpose). Individual ML-DSA sigs are exact and need
no coordination. Is there a formulation that bridges to a no-coordination, arbitrary-use
aggregate that the standard verifier still accepts?

Answer: a non-interactive bridge **does exist algebraically** — and it is a **forgery
factory**. That pins the gap precisely: it is a *security* cliff, not a missing identity.

## 1. Localizing the obstruction to ONE term
Independent sigs: `z_i = y_i + c_i s1_i`, with per-sig identity
`A z_i − c_i t1_i 2^d = w_i − c_i s2_i + c_i t0_i`, `HighBits = w1_i`,
`c̃_i = H(μ_i ‖ w1_i)`. Each challenge `c_i` is paired with its OWN key `t1_i`.

The standard verifier multiplies ONE challenge by ONE key: `c* · t1*`. The honest total
is `Σ_i c_i t1_i`. So the whole barrier is the single term:
```
   need:   c* · t1*  =  Σ_i c_i t1_i      (one product = sum of M distinct products)
```
Coordination's *entire* job is to force `c_1 = … = c_M = c*`, making
`Σ c_i t1_i = c*·Σ t1_i = c*·t1*` with `t1* = Σ t1_i` a fixed, well-formed key.

## 2. The bridge: make the key absorb the challenge (c*-inverse)
`R_q` fully splits (`q ≡ 1 mod 2n`), so a `SampleInBall` output `c*` is invertible whp.
Then **define the aggregate key adaptively**:
```
   t1*  :=  c*^{-1} · Σ_i c_i t1_i           ⇒   c* · t1* = Σ_i c_i t1_i  ✓
```
The barrier term collapses with NO common challenge. And the verifier never checks that
`t1*` is a well-formed key, so "garbage" `t1*` is accepted. Now the construction is
**non-interactive** and closes without circularity, because `c*` cancels:
```
   w' = A z* − c* t1* 2^d = A z* − (Σ_i c_i t1_i) 2^d        # independent of c*!
```
Aggregator (no rounds): pick `z*`; `W := A z* − (Σ c_i t1_i)2^d`; `w1* := HighBits(W)`,
hint `h*`; `μ* :=` batch statement; `c̃* := H(μ* ‖ w1*)`; `c* := SampleInBall(c̃*)`;
`t1* := c*^{-1} Σ c_i t1_i`. Output `pk*=(ρ,t1*), μ*, σ*=(c̃*,z*,h*)`.
The standard verifier recomputes `w' = A z* − c* t1* 2^d = W`, `UseHint(h*,W)=w1*`,
`c̃*=H(μ*‖w1*)` ✓, norm/hint ✓. **It accepts.** The bridge you predicted is real.

## 3. Why it's vacuous — a forgery with NO underlying signatures
Run the same algorithm with **made-up inputs**: set `z* = 0` (norm 0 ✓), pick *any*
`c_1` (sparse) and *any* `t1_1` (a key the forger does not own); then
`W = −c_1 t1_1 2^d`, derive `w1*, c̃*, c*` as above, set `t1* = c*^{-1} c_1 t1_1`,
`h*` the matching hint. The verifier accepts `σ*=(c̃*,0,h*)` under `pk*=(ρ,t1*)`.
**No real signature, no secret, nothing signed** — yet it verifies. The adaptive `t1*`
carries no commitment to any real key, so the object attests to nothing. This is a
universal forgery against "aggregation with an aggregator-chosen key."

> **This is NOT a break of ML-DSA.** ML-DSA EUF-CMA fixes an honestly-generated key and
> forbids forgery on a new message under *that* key. Here the adversary instead *chooses*
> the aggregate key (`t1*` falls out as `c*^{-1}Σc_i t1_i`; degenerately `t1*=0, z*=0`
> gives a "signature" under the all-zeros key). It cannot steer `t1*` to a real fixed key
> — that would require `c* t1 = Σ c_i t1_i` for fixed `t1`, i.e. SelfTargetMSIS = breaking
> ML-DSA. So §3 is a forgery against the *aggregation wrapper* (aggregator-chosen key),
> attesting to nothing; ML-DSA itself is untouched and is what we rely on. The moment
> `t1*` is pinned to a fixed well-formed key, the trick evaporates and forgery reduces to
> SelfTargetMSIS.

Equivalently: also note `z* = Σ z_i` (the *honest* combination) is excluded anyway —
`‖Σ z_i‖∞ ≤ M(γ1−β)` blows the `‖z*‖∞ < γ1−β` bound for `M ≥ 2`, and the only short
combination `Σ e_i z_i` with `Σ‖e_i‖_1 ≤ 1` is a single signature. So even the honest
version can't put M responses into one in-bound `z*`. Two independent walls, same cliff.

## 4. The equivalence (this is the real theorem)
For an aggregate the standard verifier accepts:
```
   secure (binds to real sigs)  ⟺  t1* is a FIXED, well-formed key (real secret)
                                ⟺  one shared challenge c* across contributors
                                ⟺  coordination / shared context (MLADSA)
```
Proof idea: security needs `t1*` pinned to real `t_i` (so the sig can't be cooked up);
the per-sig FS bindings `c̃_i = H(μ_i‖w1_i)` are nonlinear and each ties `c_i` to `t1_i`;
the verifier checks exactly ONE binding `c̃*=H(μ*‖w1*)`, which can cover M underlying
bindings only if they were all the same binding (common `c*`, fixed `t1*=Σt_i`) — that
is coordination. Drop coordination and the only freedom left (adaptive `t1*`) is exactly
the forgery of §3.

## 5. The only way to "neglect coordination": prove the bindings
To attest to M *distinct* FS bindings without collapsing them, you must **carry a proof**
that each `c̃_i = H(μ_i‖w1_i)` holds for real fixed keys. The standard verifier has no
slot for that proof, so this is necessarily an **augmented verifier** = the
PoK/folding "second type." There is no third option: one standard-verifier FS-check
attests to exactly one binding; M>1 ⇒ collapse (coordination) **or** proof (augmented).
"Enough information some other way" = a succinct proof, by construction.

## 6. Conclusion — two points, no continuous bridge
- **MLADSA**: exact standard verifier, secure, no-coordination *only* for one shared
  context/message (single-purpose). `t1*` fixed = `Σ t_i`.
- **LMSA (arbitrary, no coordination)**: forces an **augmented verifier** carrying a
  proof of the per-sig bindings (PoK). Cannot be the byte-identical ML-DSA verifier.
- The forbidden middle (standard verifier + no coordination + arbitrary distinct keys)
  is not unbuilt — it is **provably forgeable** (§3). The endpoints exist; the space
  between them is disconnected by the security cliff.

## 7. "How is the paired validating object different from a public key?"
A public key is not merely "an object under which signatures verify." It is a validating
object that is additionally **binding (extractable)**: (i) fixed/committed *before and
independently of* the signatures it validates, and (ii) such that a valid signature under
it *certifies a secret was used* (a forgery extracts a hard-problem solution).
- `t1* = Σ t_i` (MLADSA): fixed by the cohort in advance; bound to `s1* = Σ s1_i`; valid
  aggregate ⟹ cohort signed (else SelfTargetMSIS). **A public key.**
- `t1* = c*^{-1}Σ c_i t1_i` (§3): computed *from* the signatures after the fact; `z*=0`
  passes with no secret. Certifies nothing. **Not a public key — a fitted value.**
Litmus: *can a valid object be produced under it with `z*=0` and no secret?* Yes ⟹ not a
key. The deep tension: the validating object derivable **non-interactively from
independent sigs** is not binding; the one that **is** a public key (`Σ t_i`) can't
validate independent (distinct-challenge) sigs. BLS gets both only by having no challenge.
Binding comes only from **commitment** (MLADSA) or **proof** (augmented verifier) — never
from the equation merely passing.

If a different bridge mechanism is on the table (a convolution/transform identity, a
key/challenge structure), the test it must pass is §3: instantiate it with `z*=0` and
fabricated `(c_i, t1_i)` and check the verifier rejects. Any mechanism that lets the
aggregator choose the aggregate key adaptively will fail that test.
