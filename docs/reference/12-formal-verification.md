# ML-ADSA — Formal Verification: complete property map, status, and plan

> **Historical / iteration note (2026-06-11).** This document is part of the research/design trail and reflects an **earlier iteration**; some counts, status labels, and construction details predate the current Construction F. The authoritative current specification is **`docs/30`**, the verification status and tallies are in **`docs/31`** and reproducible via **`formal/count-artifacts.sh`** (29 artifacts, 134 lemmas, 33/33 genuineness, 6 Gobra), and the cross-document reconciliation is **`docs/35`**. Numbers below are preserved as the historical record.

This maps **every** desirable property and **every** unwanted property to a precise formal
statement, the right tool, and an honest status. The cardinal rule here: a property is only
marked **MACHINE-CHECKED** if a prover actually verified it in this repo. Everything else is
**SPECIFIED** (formal statement given, proof technique fixed) or **STRUCTURAL** (an argument
about the construction). No game-based security property is claimed proven that is not.

**Crucial honesty:** "absence of an unwanted property" *is* a security property — e.g.
"no existential forgery" **is** EUF-CMA. Such properties are proved with **game-based**
reasoning, whose machine-checked home is **EasyCrypt** (or SSProve/CryptHOL in Coq).
EasyCrypt is **not installed** here (we have Coq/Rocq + Lean). Game-based FV of a full
signature scheme is a person-months effort — even **ML-DSA itself has only partial
machine-checked security** in the literature. So those proofs are **specified, not done**;
this document is their specification.

## Tooling reality
| tool | present? | scope |
|---|---|---|
| Coq/Rocq + `nsatz` | **yes** | ring/algebraic identities (correctness) — **used** |
| Lean 4 | yes (no mathlib) | unused (mathlib absent) |
| EasyCrypt | **yes** (installed; why3 1.8.2 + Z3 4.13.3/4.15.4) | game-based: EUF-CMA game/assumption/reduction **statement type-checked** (`formal/ml_adsa_euf.ec`, proof admitted); **GENUINELY PROVED reductions**: perfect zero-leakage / Construction A (`ml_adsa_zk_proof.ec`), rogue-key→single-signer (`ml_adsa_rogue_proof.ec`), no-new-power→Module-SIS (`ml_adsa_nnp_proof.ec`) — each reduced to one named primitive |
| Gobra (Go FV) | **no** | code-level FV of the Go implementation — **specified only** |
| Go tests + CIRCL cross-check | yes | empirical correctness — **used** |

## A. Desirable properties

### A1. Correctness / completeness — **MACHINE-CHECKED** (Coq) + **TESTED** (Go vs CIRCL)
Statement: for honestly produced inputs, the aggregate satisfies the ML-DSA-87 verification
relation. Algebra machine-checked in `formal/ml_adsa_identity.v` (reconstruction identity,
key/response linearity, `aggregate_verifies_2`). End-to-end empirically confirmed: CIRCL's
verifier accepts ML-ADSA aggregates (`go-mladsa/*_test.go`).

### A2. Unforgeability (EUF-CMA / MS-UF-CMA) — **STATEMENT TYPE-CHECKED** (EasyCrypt); proof admitted
Statement (game): no PPT adversary, controlling ≤ n−1 co-signers and the network with a
signing oracle, outputs `(M*, σ*)` accepted under the aggregate key with `M*` un-queried,
except with negligible probability. Reduction → SelfTargetMSIS (+ MLWE, ROM-commitment) via
the standard multisignature simulation (program RO, simulate honest `w_i` by HVZK,
commit-then-equivocate, fork on `c̃` to extract). QROM: non-tight (inherits `Ω(ε²/Q⁴)`).
**EasyCrypt status (`formal/ml_adsa_euf.ec`): the MS-UF-CMA game, the **MLWE** and
**SelfTargetMSIS** assumption games, the reductions `B(A)` (STMSIS) and `RedMLWE(A)` (MLWE),
and the theorem `msufcma_reduction` all TYPE-CHECK (machine-checked well-formed; EasyCrypt
rejects a deliberately broken variant). As of the baseline-alignment pass (see
docs/13), the bound now matches the machine-checked `Dilithium_secure` shape
(`Pr[MSUFCMA] ≤ |MLWE_L(RedMLWE A) − MLWE_R(RedMLWE A)| + Pr[STMSIS∘B] + eps`) — i.e. exactly
the FIPS-204 assumption set MLWE + SelfTargetMSIS, with `eps` the non-tight (Q)ROM loss. The
proof is `admit`-ted with five enumerated obligations: (M) MLWE key-indistinguishability
(their `hop1`), (S) oracle-simulation indistinguishability (HVZK+RO; their `ReprogHybrid`),
(E) extraction soundness (uses the Coq reconstruction identity; their `hop3`), (R) rogue-key
collapse via PoP (**the collapse step is machine-checked** in `ml_adsa_rogue_proof.ec`), (F)
forking/QROM accounting → `eps`. Discharging M/S/E/F is the continuing (person-months) effort,
to be built on the `formosa-crypto/dilithium` artifact (license/dev-branch caveats in docs/13).**

### A3. Zero-knowledge / zero-leakage — Construction A perfect-ZK **MACHINE-CHECKED** (EasyCrypt); general bound admitted
Statement (game): the published aggregate (and partial transcripts) are simulatable from
public data. Construction A (per-signer rejection): **perfect/statistical** (bit-zero),
provable by the Model-1 distribution argument (each `z_i` uniform-on-box, secret-independent).
Construction B (wide masks): **computational/negligible** via a Rényi-divergence bound.
**Tool: EasyCrypt (sim-based).** Measurement caveat: `prototype/leak_test.py` is
underpowered (see docs/08); the claim rests on the proof, not that probe.

**Discharged (`formal/ml_adsa_zk_proof.ec`, compiles EXIT=0):** the perfect zero-leakage
lemma `zero_leakage_perfect_A` — `Pr[ZK(D).real] = Pr[ZK(D).ideal]` **for every distinguisher
`D`** — is GENUINELY PROVED (not `admit`), reduced via `byequiv` to a single named
cryptographic primitive `masking_perfect` (`(pk,sk) ∈ dkeygen ρ ⇒ sign1 sk m = simS pk m`,
the standard Dilithium/Model-1 fact that rejection-sampled output depends only on the public
key). The quantification over `D` and the game equivalence are machine-checked; only the
distribution-identity primitive is taken as an axiom (separately justified). Verified genuine:
a broken variant that drops the `smt(masking_perfect)` hint fails with `cannot prove goal
(strict)`. The weaker general bound `zero_leakage` (covering Construction B's Rényi case) and
the props-file copies remain admitted (obligation Z).

### A4. Rogue-key resistance — reduction to single-signer **MACHINE-CHECKED** (EasyCrypt); residual = A2
Statement: an adversary cannot register a key `t_j` making the aggregate key one it can sign
under, without knowing `t_j`'s secret. Mechanism: one-time proof-of-possession at
registration. Reduces A2's n-of-n to one honest signer. **Tool: EasyCrypt.**

**Discharged (`formal/ml_adsa_rogue_proof.ec`, compiles EXIT=0):** the substantive game step
is GENUINELY PROVED. `rogue_reduces_to_single` shows `Pr[RogueGame(F)] ≤ Pr[SingleForge(F)]`
for every adversary `F`, via `byequiv`, reduced to a single named primitive `rogue_collapse`
(`all popok cohort ⇒ verify(aggkey ρ (pk::cohort)) m s ⇒ verify pk m (deagg s (map
pop_extract cohort))` — PoP knowledge-soundness composed with key-aggregation linearity:
a valid-PoP cohort collapses the n-of-n aggregate to a single-key forgery on the honest key).
`rogue_key_resistance_bounded` then transfers any single-signer bound `ε` (from A2) to the
rogue game: `Pr[SingleForge] ≤ ε ⇒ Pr[RogueGame] ≤ ε`. Verified genuine: dropping the
`rogue_collapse` hint, **or** the reduction lemma in the corollary, makes EasyCrypt fail with
`cannot prove goal (strict)`. The residual `admit` in `ml_adsa_props.ec`'s
`rogue_key_resistance` now stands *only* for the A2 single-signer bound (the honest hand-off),
not for the rogue-key collapse itself — that is closed.

### A5. Binding / knowledge-soundness / no-new-power — reduction to Module-SIS **MACHINE-CHECKED** (EasyCrypt)
Statement: a verifying aggregate implies an extractor recovers leaf witnesses (or breaks
Module-SIS); the aggregate can sign nothing beyond the cohort's collective ability. The
*negative* boundary — why an adaptively-chosen aggregate key is forgeable — is captured
algebraically and **machine-checked** (`adaptive_key_collapses` in `formal/`), which is the
formal reason the scheme **requires** a fixed well-formed key.

**Discharged (`formal/ml_adsa_nnp_proof.ec`, compiles EXIT=0):** the substantive game step is
GENUINELY PROVED. `new_power_reduces_to_sis` shows `Pr[NewPower(A)] ≤ Pr[SISBreak(A)]` for
every adversary `A`, via `byequiv`, reduced to a single named primitive `extract_or_break`
(`verify(aggkey ρ cohort) m s ⇒ leaves_ok cohort m (extract …) ∨ sis_ok (to_sis …)` — the
LaBRADOR-class knowledge extractor with a Module-SIS escape hatch). The "new power" event is
*the aggregate verifies but the per-member leaves don't all individually verify* — i.e. it
certifies a message no member is shown to have signed; the theorem says exhibiting that is no
easier than breaking Module-SIS. `no_new_power_bounded` transfers SIS hardness to the
new-power bound; `no_new_power_det` is the deterministic form matching `ml_adsa_props.ec`'s
`no_new_power` (binding-soundness hypothesis made explicit). Combined with the **Coq
reconstruction identity** (`ml_adsa_identity.v`), the recovered leaves recombine to exactly
the aggregate, so it is a deterministic function of the leaves — no capability beyond the
cohort. Verified genuine: dropping `extract_or_break` (in any of the three lemmas) or the
reduction lemma fails with `cannot prove goal (strict)`. Residual = Module-SIS hardness.

### A6. Aggregation soundness for Construction E (transparent proof) — **SPECIFIED**
Statement: a verifying ML-DSA-LaBRADOR proof implies knowledge of N valid signatures. From
LaBRADOR NI knowledge-soundness (CRYPTO 2024). **Tool: EasyCrypt / the LaBRADOR analysis.**

### A7. Post-quantum security (QROM) — **FORMALIZED in the quantum logic**; O2H step machine-checked at our types
All reductions stated in the (Q)ROM; ML-ADSA inherits ML-DSA-87's non-tight QROM bound; no
new assumption beyond MLWE/MSIS/SelfTargetMSIS. **Tool: EasyPQC (quantum EasyCrypt), installed
and validated** — the `deploy-quantum-upgrade` branch built in opam switch `easypqc`
(why3 1.6 + z3 4.13.3/alt-ergo); run via `formal/ec-quantum.sh`. See **docs/14** for the full
account. Concretely: `formal/ml_adsa_qrom.ec` (compiles on the quantum prover) formalizes the
**aggregate QROM-EUF game** against a quantum forger with superposition RO access, the
**QROM-SelfTargetMSIS** assumption, and the reduction theorem with the correct quantum bound
`Pr[QROM-EUF] ≤ adv_mlwe + Pr[QROM-SelfTargetMSIS] + o2h_loss` (main reduction admitted; quantum
obligations Mq/Sq/Eq enumerated). `formal/ml_adsa_qrom_o2h.ec` **PROVES** `o2h_at_our_types` by
applying the **imported semi-classical O2H lemma** (`T_OW2H.SemiClassical.ow2hsc1h`, = AHU19) at
our Fiat-Shamir hash types — so the quantum reprogramming/extraction loss is a genuine imported
bound, broken-variant-rejected. (Mq) reuses the machine-checked `mlwe_keyswap`; the
aggregation-specific risk is handled by the machine-checked `rogue_collapse` *before* the quantum
hops. Residual: the (mechanical) main-reduction wiring + the imported quantum lemmas as primitives.

### A8. Transparency / no trusted setup — **STRUCTURAL** (formalizable)
Statement: `Setup` takes only public coins and retains **no secret**; the shared `A =
ExpandA(ρ)` is a deterministic public-hash expansion of a public seed `ρ`. Formalize as:
`Setup` is a deterministic function of public input with empty secret output (a typed
interface property — checkable by inspection, and expressible as a Coq/Lean signature
constraint). No CRS, no toxic waste.

## B. Unwanted properties — to be *dis*proved (each ≡ a security game above)

| unwanted property | formal negation = | status |
|---|---|---|
| existential forgery exists | A2 (EUF-CMA: adv. advantage negligible) | SPECIFIED (EasyCrypt) |
| secret leaks from signatures | A3 (ZK: transcript simulatable) | A=perfect **MACHINE-CHECKED** (`ml_adsa_zk_proof.ec`); B=negligible SPECIFIED |
| aggregate grants new signing power | A5 (extractability / no-new-power) | reduction→Module-SIS **MACHINE-CHECKED** (`ml_adsa_nnp_proof.ec`); collapse lemma also MACHINE-CHECKED |
| rogue-key takeover of aggregate key | A4 (PoP soundness) | reduction→single-signer **MACHINE-CHECKED** (`ml_adsa_rogue_proof.ec`); residual = A2 |
| backdoor / trapdoor / toxic waste | A8 (Setup has no secret output) | STRUCTURAL (formalizable) |
| forgeable adaptive-key aggregate (§3) | `c·t1* = Σ c_i t1_i` collapse ⇒ binds nothing | **MACHINE-CHECKED** (why it's excluded) |
| double-counting in a vote | bitmap disjointness across option-aggregates | SPECIFIED (protocol/tally rule) |

"Proving it does NOT have a property we don't want" is therefore exactly proving the
corresponding security game (A2/A3/A4/A5) and the structural no-trapdoor (A8). The §3
forgery is the one unwanted behavior whose *exclusion criterion* (fixed well-formed key) we
have already machine-checked the algebra for.

## C. The honest bottom line and the plan
- **Done (machine-checked):** the aggregation **algebra/correctness** (Coq/nsatz); the
  algebraic reason the forgeable variant is excluded; **perfect zero-leakage for
  Construction A** (EasyCrypt `zero_leakage_perfect_A`, game-level real≡ideal for any
  distinguisher, reduced to the single `masking_perfect` primitive — not an admit); and the
  **rogue-key→single-signer reduction** (EasyCrypt `rogue_reduces_to_single` +
  `rogue_key_resistance_bounded`, reduced to the single `rogue_collapse` primitive — the A4
  collapse is closed; only the A2 single-signer bound remains as the hand-off); and the
  **no-new-power→Module-SIS reduction** (EasyCrypt `new_power_reduces_to_sis` +
  `no_new_power_bounded` + `no_new_power_det`, reduced to the single `extract_or_break`
  knowledge-soundness primitive — the A5 collapse is closed; only Module-SIS hardness remains).
- **Done (empirical):** end-to-end correctness against an independent verifier (Go vs CIRCL).
- **Specified, not done (needs EasyCrypt; person-months):** the remaining game-based
  properties — EUF-CMA (A2, the keystone), ZK for Construction B (A3's negligible/Rényi
  case), E's knowledge-soundness (A6), QROM (A7). Note A3 (Construction-A perfect ZK), A4
  (rogue-key), and A5 (no-new-power) are no longer in this bucket: their substantive game
  steps are now machine-checked, each reduced to one named primitive — with the residuals
  being, respectively, the masking fact, the A2 single-signer hand-off, and Module-SIS
  hardness.
- **Structural:** no-trapdoor/transparency (A8) — by construction; formalizable as a typed
  Setup-interface property.
- **Code FV:** the Go implementation would need **Gobra** for machine-checked code; today it
  is verified by property tests + CIRCL cross-checking.

### Recommended FV roadmap
1. **EasyCrypt** formalization of A2 (EUF-CMA reduction) — the keystone; build on existing
   Dilithium/ML-DSA EasyCrypt artifacts where available.
2. EasyCrypt A3 (ZK: A bit-zero via perfect sim; B via Rényi), A4 (PoP), A5 (extraction).
3. A6 for Construction E (LaBRADOR knowledge-soundness).
4. Formalize A8 (no-secret Setup) in Coq/Lean as an interface theorem.
5. (Optional) Gobra spec for the Go `Verify`/aggregate to lift code from tested to verified.
Independent cryptographic review remains required regardless of FV coverage.
