# σ = 3β as the F-OFFSET deployment default — security vs the LOCKED requirements, and remaining limitations

**Decision (#124).** `SigmaOffsetDefault = 3·BETA = 360` is wired as the F-OFFSET deployment nonce width
(`go-mladsa/construction_offset.go`; entry point `AggregateOffsetFDefault`). This replaces the older conservative
`12β = 1440` *as the default* (callers may still pass a larger σ for extra margin; the 12β regression tests are
kept). This document states exactly which security properties hold at σ=3β, with the evidence, and what
limitations remain — to the project's honesty standard (machine-checked / estimator-measured / assumed, labelled).

## 1. Why 3β is sound (the chain, each link evidenced)

| Link | Statement | Evidence | Kind |
|---|---|---|---|
| L1 | The deployed (transcript-exposing) EUF bound is **σ-independent**: `Pr[forge] ≤ adv_prf + Q·(adv_mlwe+STMSIS)`, no term depends on the nonce width. | `formal/ml_adsa_F_keyonly.ec` (`konly_uncond`) + `ml_adsa_F_open.ec` (`deployed_open_uncond`) | machine-checked |
| L2 | The σ=12β figure was an artifact of the **atomic-masking** proof route, which the deployed scheme does not use (it uses key-leak). | docs/48 §8–§9, F20 | machine-checked + analysis |
| L3 | At σ=3β the published single hint `z=c·s1+y` keeps **direct recovery of s1 ≥ native** (Cat-5): classical **387** vs native 252 (the hint error 207.8 ≫ native 1.4 ⇒ near-useless to an attacker). σ=β still gives 349. | `go-mladsa/estimator99.py` (#124 block, asserted) | estimator-measured |
| L4 | The **KLSS single-hint effective-width** degradation of the secret is negligible: σ\* = 1.4136 vs η = 1.4142, **0.046%** ⇒ the reduced MLWE is native ⇒ Cat-5 carries. | `estimator99.py` (#124) + `formal/smallsigma_floor.py` | computed |
| L5 | The **binding** security is native MLWE (the public key `t`), which the hint does **not** lower (noise-flooding reduction + combined-view = native, F12f). | estimator99 (offset monotone, combined=native, asserted) + docs/48 §2 | reduction + measured |
| L6 | σ=3β = 360 is **~120× above** the F12e recovery floor (σ≈3) and **~6× above** the Hint-MLWE proof floor (~0.5β), so both defense-in-depth margins survive. | F12e, `smallsigma_floor.py` | measured/computed |

**Net deployed bit-security at σ=3β: native ML-DSA-87 = 252 classical / 229 quantum (NIST Category 5).** The
nonce-hiding broadcast adds no reduction in this number.

## 2. The LOCKED requirements, checked at σ=3β

| Requirement (locked) | Holds at σ=3β? | Evidence |
|---|---|---|
| **Byte-exact FIPS-204** (unmodified verifier accepts) | ✅ | `TestAggregateOffsetFDefault_Wired`, `TestOffset_SigmaIndependence_DeployablePayoff` (VerifyF==true at 3β) |
| **Non-interactive** (no 2-round handshake) | ✅ | unchanged from F-OFFSET ([[ml-adsa-noninteractive]]) |
| **No trusted setup / no privileged party** | ✅ | unchanged (refresh + canonical partition; no dealer) |
| **Order-independent** combine | ✅ | canonical sort+dedup (`sortMembersByID`/`dedupMembersByID`) |
| **Post-quantum, hide ≤ native** | ✅ | EUF σ-independent = native (L1); recovery ≥ native (L3); quantum 229 = Cat-5 |
| **Unbounded total signers** | ✅ | committee sharding (#117); σ=3β raises per-committee ceiling ~8× (≈32 768 → ≈262 144) ⇒ fewer committees |
| **EUF-CMA + SUF-CMA, ROM + QROM** | ✅ | deployed_open (RO-free refresh hop, ROM=QROM); base EUF/SUF + QROM inherited (F19) |

**All locked requirements are met at σ=3β.** The change vs 12β is strictly an improvement (≈8× larger
per-committee ceiling) with no requirement weakened.

## 3. Security properties — summary

- **EUF (deployed / key-leak model):** `adv_prf + Q·(adv_mlwe+STMSIS)`, σ-independent, machine-checked (F20).
- **EUF (tighter / non-key-leak model):** `adv_hint + adv_mlwe + STMSIS`; the gap→Hint-MLWE step is
  machine-checked (`ml_adsa_F_hintmlwe.ec`, F22), reducing to the published KLSS Hint-MLWE assumption.
- **Recovery hardness (estimator):** s1 from the σ=3β hint = 387 classical / 351 quantum ≥ native.
- **Deterministic-nonce safety:** reuse leaks iff nonce collision; one-time + content-bound challenge + PRF nonce
  forbid it (`ml_adsa_F_nonce.ec`), σ-independent — and the PRF nonce entropy at σ=3β is astronomically
  collision-free.
- **Provenance / Byzantine / non-malleability:** unchanged from F-OFFSET (already built+tested).

### 3a. OPTIONAL CONFIGURATION — computational ZK-parity with native ML-DSA (Hint-MLWE)

Beyond the (statistical, ≥native) leakage bound, the deployment can claim a **stronger, computational
zero-knowledge parity** with a bare ML-DSA signature, as a configuration option:

> **Config: Hint-MLWE ZK-parity.** Under the (named, published) Hint-MLWE assumption, the F-OFFSET aggregate
> transcript is **computationally indistinguishable** from a simulated, secret-independent transcript — i.e. it
> leaks *no more than a native ML-DSA signature*, computationally. This is exactly `gap_le_hint` in
> `formal/ml_adsa_F_hintmlwe.ec` (machine-checked reduction: the real-vs-simulated signing gap **equals** a
> Hint-MLWE distinguishing advantage), giving `leakage ≤ Adv_HintMLWE`.

When to enable: if a deployment wants the *strongest* leakage guarantee (computational native-equivalence) it
opts into the Hint-MLWE assumption (one extra named assumption). The **default** does NOT require it — the
deployed key-leak bound (σ-independent, F20) and the ≥native recovery hardness (estimator) already secure the
scheme **without** Hint-MLWE. So this is a *strengthening toggle*, not a dependency:
- **Default (no Hint-MLWE):** leakage is statistical-≥native (recovery 387 ≥ 252; docs/51) + key-leak/refresh.
- **ZK-parity config (+Hint-MLWE):** leakage ≤ `Adv_HintMLWE` ≈ native (transcript computationally indistinguishable
  from a fresh native signature). The structurally-perfect (zero-extra-leak) parity is *not* achievable with
  non-interactive additive aggregation (docs/48 §6); this computational parity is the strongest attainable.

## 4. Limitations remaining (honest)

1. **The KLSS Hint-MLWE→MLWE theorem is ASSUMED**, not re-formalized — a *named, published* assumption
   (`hintmlwe_assumption`), exactly like `mlwe_assumption`/`SelfTargetMSIS` are assumed everywhere in this corpus.
   Formalizing its Gaussian-convolution proof from scratch (a CRYPTO'23 paper) is out of scope by the same rule
   that lets us assume MLWE itself. This limitation applies only to the *tighter (non-key-leak)* model; the
   *deployed* bound (L1) needs **no** Hint-MLWE assumption at all.
2. **Tighter-model Q-independence relies on the one-time refresh** (fresh key per content ⇒ each key single-hint).
   With key reuse this would degrade; the scheme forbids reuse (one-time guard), so this is a discipline, not a gap.
3. **Estimator is primal-uSVP core-SVP** (`estimator99.py`): absolute numbers are approximate; the
   *offset-vs-native comparison* is the robust read. The real Sage lattice-estimator (dual+hybrid) separately
   cross-validated the offset family at much higher figures (#110: offset 455–489 ≫ native 267). σ=3β sits inside
   that validated regime.
4. **External citations** (KLSS CRYPTO'23, Raccoon/Plover) are flagged for primary-source re-verification before
   any publication ([[raccoon-chipmunk-facts]]).
5. **Implementation side-channel note (not a scheme limitation):** the deployed default derives the nonce by the
   constant-time PRF (`DeriveNonce`, uniform), not by a rejection-based Gaussian sampler — so narrowing σ does not
   introduce a timing channel. If the #119 discrete-Gaussian offset variant is used instead, its sampler must be
   constant-time. The default path is CT-friendly.
6. **No HVZK claim at the deployed nonce** — and none is needed: the aggregate never relied on perfect HVZK (the
   wide γ1 mask), neither at 12β nor 3β; its security is the key-leak/recovery argument. Lowering σ removes a
   margin the proof never used. (Stated so no reader infers a lost HVZK property.)

## 6. Scope clarification — KLSS is a proof-layer assumption, NOT the aggregation mechanism (anti-overclaim)

A natural misreading is "KLSS-based non-interactive aggregation = the holy grail of PQ lattice aggregation,
solved." That conflates two orthogonal layers. Stated precisely so the record cannot be misread:

**(a) KLSS / Hint-MLWE is a hardness ASSUMPTION used in the security PROOF — it is not the construction and confers
no (non)interactivity.** It appears in exactly one place: bounding the signing-simulation gap in the *tighter
(non-key-leak)* EUF proof of small-σ F-OFFSET (`ml_adsa_F_hintmlwe.ec`). The **deployed** security bound (the
σ-independent key-leak result, F20) uses **no Hint-MLWE at all**. Non-interactivity is a property of the
construction and holds regardless of which assumption the proof uses.

**(b) The non-interactivity comes from DETERMINISM + PUBLICATION, not from KLSS.** Nonces are deterministic
(`wᵢ = A·PRF(seedᵢ, C)`, pre-published per-slot in the epoch commitment tree); the Fiat–Shamir challenge
`c* = H(μ*, HighBits(ΣW))` **does** depend on `ΣW` (it must, for a byte-exact FIPS signature), but every signer
**self-computes** it from the published commitments — no aggregator ever sends a challenge. Each signer emits one
broadcast `zᵢ = yᵢ + c*·s1ᵢ`; an untrusted aggregator sums ([[ml-adsa-noninteractive]]). Honest caveat: there is a
**commit-before-respond data dependency** (`zᵢ` needs `c*` needs `ΣW`), resolved by pre-publishing the
deterministic commitments per slot (content label `C` is known before the decision payload), **not** by a live
round. So "non-interactive" = no handshake / untrusted aggregator / one per-decision message — not "zero
coordination, one-shot self-contained per-signer signatures."

**(c) The precedent schemes that use KLSS are NOT non-interactive aggregation.** Threshold Raccoon (EUROCRYPT'24)
is an *interactive, trusted-dealer threshold* signature; Plover is *single-signer*. They are precedent for the
Hint-MLWE *assumption* only — do **not** read them as "non-interactive lattice aggregation already exists."

**(d) Where F-OFFSET sits relative to the holy grail.** It is a **non-interactive, no-setup, key-aggregating
*multi-signature***: a cohort signing the *same* decision, producing *one byte-exact ML-DSA signature under the
aggregate key `pk*=Σtᵢ`*. It is **not** the fully general "BLS for lattices":
  - it aggregates a **same-message cohort** (multisig / attestation flavor), not arbitrary independent signatures
    on **different** messages (that general case remains open; known PQ routes are SNARK-of-many-signatures — a
    succinct *proof*, not a real signature — or interactive multisigs);
  - commitment material is **pre-published per slot** (determinism), so it is non-interactive but not "one-shot,
    zero-coordination";
  - a per-committee **norm-wall ceiling** means **sharding** (#117) is needed for very large totals;
  - the *small-σ tighter-model* security leans on the KLSS assumption (the deployed model does not).

**Honest verdict on the "holy grail" framing:** F-OFFSET solves the **same-message multi-signature / attestation
corner** non-interactively, no-setup, byte-exact, at Cat-5 — which is precisely the consensus use case and is
itself unusual for a PQ scheme — but the **general** non-interactive aggregation of arbitrary independent lattice
signatures is **not** claimed and remains open. Saying "the holy grail is solved" would be an overclaim; saying
"this corner is solved non-interactively" is accurate.

## 7. Verdict

At σ=3β, **F-OFFSET meets every locked requirement at NIST Category 5** (252 classical / 229 quantum), with an
≈8× larger per-committee ceiling and unbounded total via sharding, and **no security property is weakened** versus
12β. The deployed EUF bound is machine-checked σ-independent; the tighter-model bound reduces (machine-checked
reduction) to one named published lattice assumption. The remaining items in §4 are the standard assumed-primitive
boundary plus citation hygiene — not open security questions about the deployed scheme. Per §6, this is the
non-interactive same-message multi-signature corner of PQ aggregation, not the fully general holy grail.
