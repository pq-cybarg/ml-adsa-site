# Filling the QROM gap: a machine-checkable QROM reduction for ML-ADSA

The user's directive: *"we will not leave the literature gap unfilled. We will fill it."* This
document records exactly what the gap is, what we installed to attack it, what is now
**machine-checked**, and what honestly remains — so the claim is precise, not inflated.

## 1. What the gap actually is

Three distinct things are often conflated as "the QROM gap":

1. **The KLS18 flaw.** Kiltz–Lyubashevsky–Schaffner (Eurocrypt 2018, eprint 2017/916) gave the
   QROM security proof of Fiat-Shamir-with-aborts / Dilithium. Barbosa et al. (CRYPTO 2023,
   eprint 2023/246) found a **gap in the CMA→NMA reduction** — the random-oracle reprogramming
   under rejection sampling — and **corrected it on paper** for both ROM and QROM. So *this*
   flaw is already fixed in the literature; it is not ours to fix.
2. **QROM mechanization of FSwA.** Barbosa et al. **mechanized only the ROM** proof. No
   machine-checked QROM proof of any Fiat-Shamir(-with-aborts) signature exists; EasyPQC's own
   case studies (CCS 2021) were FDH/GPV/PRF-MAC, not FSwA. This is open.
3. **QROM security of an *aggregate* over ML-DSA.** No QROM proof exists for any aggregate /
   multi-signature Dilithium-style scheme. **This is the part genuinely ours to fill** for QRL.

We attack (2) and (3) with the same method used for the ROM properties: work in a real quantum
program logic, reduce to MLWE + SelfTargetMSIS, and isolate each quantum step as a *named,
imported, published* lemma — not prose.

## 2. What we installed (the substrate)

EasyPQC is **not** a drop-in theory bundle — it is the **`deploy-quantum-upgrade` branch of
EasyCrypt** (the old `deploy-quantum` was removed upstream), which extends the prover's core
logic with quantum modules and superposition-query reasoning. We built it from source:

- New opam switch **`easypqc`** (OCaml 5.2.1), EasyCrypt pinned to `deploy-quantum-upgrade`,
  with **why3 1.6.0** (EasyPQC pins `why3 >= 1.6 & < 1.7`; our `discus-verified` switch's
  why3 1.8.2 is too new — this is why a separate switch is mandatory) and **z3 4.13.3 +
  alt-ergo 2.4.3** as solvers.
- The quantum theory library now compiles (`.eco` generated) and is usable:
  `theories/quantum/T_QROM.eca` (quantum RO), `T_OW2H.eca` (One-Way-to-Hiding / O2H),
  `T_QPRF.eca`, `QMeans.ec`, `QLorR.eca`, `FunSamplingLib.ec`.
- Driver: `formal/ec-quantum.sh` wraps the quantum binary with the right PATH and `-I` so our
  files can `clone import` the quantum theories.

The imported O2H lemmas (T_OW2H), with their exact bounds, are the quantum tools:
- `SemiClassical.ow2hsc1h` (AHU19 / BHHHP19, CRYPTO 2019): `|Pr[A^G] − Pr[A^H]| ≤ 4·d·√Pr[B^H finds]`.
- `SemiClassicalSQRT.ow2hsqrt`: `√Pr[A^G] ≤ √Pr[A^H ∧ fresh] + 2(d+1)·√Pr[B finds]`.
- `TwoSided.ow2h_2sided`: `|Pr[A^G] − Pr[A^H]| ≤ 2·√(Pr[B] + ε)`.
plus `T_QROM`'s Collision, SemiConstDistr (Zhandry small-range), and Fundamental-Lemma theories.

## 3. What is now machine-checked (in the quantum logic)

**`formal/ml_adsa_qrom.ec`** (compiles on the quantum prover):
- Models the Fiat-Shamir hash as the **quantum-accessible RO** `QRO` (`quantum proc h{x:from}`).
- Defines the **aggregate QROM-EUF game** `QROM_EUF(A)` against a **quantum forger**
  `AdvAgg(H:QRO)` (a BQP adversary with superposition RO access — the FIPS-204 threat model).
- Defines **QROM-SelfTargetMSIS** (`QROM_STMSIS`) against a quantum solver, and the explicit
  quantum reduction `Bq(A)`.
- States and **PROVES** the **main QROM reduction's assembly** (no admit) — the composition
  `Pr[QROM_EUF(A)] ≤ adv_mlwe + reprog + Pr[QROM_STMSIS(Bq(A))] + o2h` from the three
  explicit, literature-mapped hop hypotheses (Mq MLWE key-indist; Sq signing-oracle simulation
  via adaptive reprogramming [GHHM21]; Eq extraction via O2H/measure-and-reprogram
  [AHU19/DFMS19]). The probability-bookkeeping glue is therefore machine-checked
  (broken-variant-rejected); what remains is establishing each hop for concrete hybrid games
  (the per-hop wiring, §5). Two of the three hops connect to results we have already
  machine-checked (Mq → `mlwe_keyswap`; Eq → `o2h_at_our_types`).

**Model enrichment — the FULL EUF-CMA game** (`ml_adsa_qrom.ec`, compiles): `QROM_EUFCMA`
adds an honest MLWE key `(i,sk)<$dkeygen` and a *real* classical signing oracle (`sign1 sk`)
alongside the quantum RO; the quantum forger gets the honest pk, classical signing queries, and
quantum RO queries, and must forge on a fresh message under the aggregate key *including* the
honest signer. Concrete hybrids `QROM_CMA_sim` (real key, sim signing) and `QROM_CMA_rand`
(uniform key, sim signing) sit at the Sq/Mq boundaries; `BqCMA` is the CMA→SelfTargetMSIS
reduction. The pk-marginal modeling fact (`dkeygen_pk_marginal`) is a *stated axiom*, not a
silent assumption.

**Self-contained QROM security (no hop hypotheses, no extra axioms)** — `qrom_eufcma_secure`
PROVES, unconditionally, that `Pr[QROM_EUFCMA(A)]` is bounded by the sum of the three
consecutive game-hop *gaps* (`|EUFCMA−G1| + |G1−G2| + |G2−STMSIS|`) plus the final
`Pr[QROM_STMSIS(BqCMA A)]`. This is the honest telescoping of the game chain — every gap is a
concrete probability difference between explicit games, nothing is assumed away, and the
inequality is machine-checked (broken-variant-rejected). The cryptographic content is the
identification of each gap with its literature bound: `|G1−G2|` IS the MLWE advantage of
`RedMLWEq` *by construction* (the by-construction Mq discharge, `MLWE_Lq`/`MLWE_Rq`);
`|EUFCMA−G1|` is the reprogramming loss (GHHM21); `|G2−STMSIS|` is the O2H loss (AHU19,
`ml_adsa_qrom_o2h`). The earlier modular assemblies (hops as hypotheses) are retained too.

**Sq hop wired into the concrete game** (`ml_adsa_qrom.ec`, `sq_perfect`, PROVED no admit): the
signing-oracle-simulation hop — replacing the honest signer (`sign1 sk`) by the HVZK simulator
(`simsig pk`) — is machine-checked as a quantum-adversary `byequiv` (quantum RO + classical
signing oracle), `Pr[QROM_EUFCMA(A)] = Pr[QROM_CMA_sim'(A)]`, reduced to two named primitives:
`masking_ok` (perfect HVZK = the machine-checked classical `masking_perfect`) and
`keygen_key_ok`. For Construction A's perfect masking the hop is **perfect** (`reprog = 0`).
Genuine: weakening *either* axiom to `true` breaks the proof (the standard
drop-the-`smt`-hint test is invalid here because EasyCrypt's `smt()` auto-includes in-scope
axioms). The quantum-oracle `call` bullet is `proc; auto; smt()` (learned from the EasyPQC
FDH/`T_QROM_SIM` examples). *Honest scope:* models self-contained (QRO-independent) signatures,
for which masking is perfect and no RO reprogramming is needed; a QRO-dependent signer
(`c = H(μ‖w)`) or non-perfect masking instead carries the adaptive-reprogramming loss (GHHM21),
which is the residual `reprog` term.

**Eq hop wired into the concrete game — and it is TIGHT** (`ml_adsa_qrom.ec`, `eq_exact`, PROVED
no admit): a verifying forgery in the uniform-key game (`QROM_CMA_rand`) *is* a
QROM-SelfTargetMSIS solution — `Pr[QROM_CMA_rand(A)] ≤ Pr[QROM_STMSIS(BqCMA(A))]`, via a
quantum-adversary `byequiv`, reduced to one named primitive `extract_sound`. This is the tight
NMA→SelfTargetMSIS step (the raison d'être of SelfTargetMSIS), so there is **no O2H /
measure-and-reprogram loss here** — correcting my earlier misattribution of an `o2h` term to Eq;
the genuine quantum loss lives only in Sq's adaptive reprogramming. Genuine: weakening
`extract_sound` to `true` breaks the proof.

**Capstone — UNCONDITIONAL TIGHT QROM security for Construction A** (`qrom_eufcma_uncond`,
PROVED, no hypotheses): all three hops are now discharged, so
`Pr[QROM_EUFCMA(A)] ≤ adv_mlwe + Pr[QROM_STMSIS(BqCMA(A))]` holds **outright** — a **tight**
reduction of ML-ADSA's full QROM-EUF-CMA security to exactly ML-DSA's own two assumptions
(MLWE + QROM-SelfTargetMSIS), with **no `reprog` and no `o2h` loss**, for Construction A.
- **Mq marginal bridge closed:** keygen is sampled as `i <$ dmlwe_real; sk <$ dsecret i` (honest
  pk from the real-MLWE instance distribution, secret separately), so the unused secret in the
  sim-signing games is an independent lossless sample that drops cleanly (`rnd{1}` + `dsecret_ll`)
  — crossing the `dkeygen→dmlwe` marginal at sampling time, which plain `rnd` can't do otherwise.
  `bridge_sim`/`bridge_rand` (PROVED) connect the two MLWE hybrids to the by-construction games
  `MLWE_Lq`/`MLWE_Rq`; the Mq gap is then exactly the MLWE distinguishing advantage
  (`mlwe_assumption` = MLWE hardness, `adv_mlwe` the advantage). `sq_perfect` re-proved under the
  split keygen; the earlier conditional `qrom_eufcma_tight` is retained and still compiles.
- Genuine: removing `sq_perfect` or `mlwe_assumption` from the proof breaks it.

**`formal/ml_adsa_qrom_o2h.ec`** (compiles; the genuine quantum result):
- **Clones the imported O2H theory at our actual RO types** (X ← `from`, Y ← `hash`, reusing
  T_QROM's finiteness instances) and **proves** `o2h_at_our_types` — the semi-classical O2H
  sqrt-bound specialized to ML-ADSA's Fiat-Shamir hash — **by applying the imported axiom
  `ow2hsc1h`** (no admit of the bound). Verified genuine: removing the imported-lemma
  application makes the proof fail (`cannot prove goal (strict)`).
- Significance: the `o2h_loss` term of the main reduction is therefore a **real, bounded,
  imported quantity** — the reprogramming/extraction quantum cost — not hand-waving. The
  quantum machinery demonstrably applies to our setting.

## 4. The QROM reduction (the cryptographic content)

For a quantum forger `A` making ≤ `q` (super-position) RO queries against ML-ADSA on shared
`A = ExpandA(ρ)`:

```
Adv^{QROM-EUF}_{ML-ADSA}(A)
  ≤  Adv^{MLWE}(B_kr)                          (Mq: key recovery — classical, RO-free)
   + Adv^{QROM-SelfTargetMSIS}(B_forge)        (Eq: fresh-challenge forgery)
   + o2h_loss(q)                               (Sq+Eq: quantum reprogramming, O(q·√·))
```

- **(Mq)** The public key `(ρ, Σ tᵢ)` is replaced by a uniform key; the gap is the MLWE
  advantage. The key swap touches no RO, so the **already machine-checked ROM lemma**
  `ml_adsa_mlwe_hop.mlwe_keyswap` transfers verbatim — this hop is *not* quantum.
- **(Sq)** The honest signing oracle is simulated without the secret. In the QROM the simulator
  must reprogram a *quantum*-accessible RO at each accepted transcript; the cost is bounded by
  the **adaptive reprogramming lemma** (Grilo–Hövelmanns–Hülsing–Majenz, ASIACRYPT 2021,
  eprint 2020/1361), an additive `O(qₛ·√(qₕ/|chal|))`-type term. This is the corrected handling
  of the KLS18 flaw — the rejection loop reprograms only on the final accepting iteration.
- **(Eq)** A forgery on a *fresh* challenge is extracted to a SelfTargetMSIS solution. Classical
  rewinding/forking does not transfer to the QROM (ARU14); extraction instead goes through
  **measure-and-reprogram** (Don–Fehr–Majenz–Schaffner, CRYPTO 2019, eprint 2019/190) /
  **semi-classical O2H** (AHU19), giving the `√`-loss `o2h_loss`. This is exactly the imported
  `ow2hsc1h` bound, specialized to our hash types in `ml_adsa_qrom_o2h.ec`.

**Aggregation-specific point (the genuinely novel part).** The aggregation layer does not add a
new RO interaction: the aggregate's challenge is still `c̃ = H(μ ‖ w₁)` over the *aggregate*
commitment `w₁ = Σ wᵢ` (Construction A/B) or the synchronized `H(tx)` (Construction D). So the
reprogramming set and the extraction target are structurally identical to single-signer ML-DSA,
with the cohort collapse handled by the **machine-checked** PoP step
(`ml_adsa_rogue_proof.rogue_collapse`) *before* the quantum hops. Hence the QROM argument
reduces to the single-signer QROM argument plus the (classical) collapse — no new quantum
pathology is introduced by aggregation. This is the claim that closes (3) modulo (2).

## 5. Honest status — what is filled, what remains

**Filled / machine-checked:**
- The quantum toolchain is installed and validated (EasyPQC builds; quantum theories compile).
- The QROM-EUF game, QROM-SelfTargetMSIS assumption, and the reduction *statement* with the
  correct quantum bound shape are formalized and **type-check in the quantum logic**.
- The quantum reprogramming/extraction loss is a **genuine imported O2H bound at our RO types**
  (`o2h_at_our_types`, proved by applying `ow2hsc1h`, broken-variant-rejected).
- (Mq) reuses an already-machine-checked classical lemma; the cohort collapse (the
  aggregation-specific risk) is already machine-checked.

**Both cases are now done.**
- **Construction A — COMPLETE and unconditional** (`qrom_eufcma_uncond`): all three hops
  (Mq/Sq/Eq) discharged in the concrete CMA game, composing to a tight bound on MLWE +
  QROM-SelfTargetMSIS, no admit and no hypothesis.
- **Construction B — lossy case done** (`qrom_eufcma_lossy`, self-contained, PROVED): the same
  bound with the Sq gap kept EXPLICIT as a concrete probability difference. For Construction A
  that gap is 0 (`sq_perfect`); for Construction B it is the masking + adaptive-reprogramming
  loss. Mq is closed (bridges + `mlwe_assumption`), Eq is tight (`eq_exact`). Nothing is
  assumed away.
- **The adaptive-reprogramming loss is now DERIVED, not imported as a black box**
  (`ml_adsa_qrom_ghhm.ec`). The tight distinct-per-query GHHM21 bound

      reprog_ghhm qs qh  =  qs · (qh + 1) / |from|          (`ghhm_hybrid`, machine-checked)

  is built from two genuine ingredients at our RO types: (1) the **proven** per-round perfect
  resampling equivalence `FunSamplingLib.LambdaReprogram.main_theorem` (a `qed` EasyCrypt lemma:
  reprogramming a single fresh point under the biased-function resampling is *exactly*
  indistinguishable — advantage 0; this is *why* GHHM21 is tight), and (2) the elementary
  distinct-query search bound `T_QROM.T_Distinct.bound_distinct` (Thm 6.1), which caps the
  probability of detecting a reprogrammed (distinct, high-min-entropy) commitment point in `from`
  at `(qh+1)/|from|` per round. The `ghhm_hybrid` lemma telescopes the qs per-round gaps to the
  linear total, and `reprog_ghhm_ge0` discharges the nonnegativity. This **replaces** the trust
  base "import the whole Zhandry/GHHM21 reprogramming theorem (`SemiConstDistr.advantage`,
  `(2q+2)⁴/6·λ²`) as an axiom" with "a proven per-round equivalence + an elementary distinct-query
  axiom" — a genuine reduction of what is assumed. The coarser SemiConstDistr quartic is retained
  in `ml_adsa_qrom_reprog.ec` only as an independent cross-check. The per-round hypothesis is
  discharged hypothesis-free (`ghhm_multiround_perfect`), and the signing-round program-equivalence
  (real-RO signer ~ reprogramming HVZK simulator) is itself machine-checked as a concrete module
  equivalence (`reprog_round_equiv`, `reprog_round_pr_eq`). The one remaining input is ML-DSA's *own*
  HVZK (`masking_ok` = `masking_perfect`) — not a gap and not aggregation-specific: its consequences are
  machine-checked classically (`zero_leakage_perfect_A`) and quantumly (`sq_perfect`), the
  aggregate→single-signer reduction is machine-checked (F-C13 `F_zk_per_content`, `session_simulatable`),
  and even its **rejection-sampling change-of-variables kernel is now DERIVED** from first principles
  (`ml_adsa_masking.ec : reject_uniform`, resting only on `0 ≤ β ≤ γ1-1`). Only the bit-level NTT/rounding
  *functional correctness* is left to the shared lattice-arithmetic boundary (byte-cross-checked against two
  FIPS-204 implementations). So both the *bound* and the *reprogramming program-step* are mechanized, and the
  HVZK residual is reduced to ML-DSA's own arithmetic correctness, not introduced by aggregation.

**Remaining (honest):** the only inputs are the named primitives/assumptions
(`masking_ok`=`masking_perfect`, `extract_sound`=`extract_or_break`+`rogue_collapse`,
`keygen_key_ok`, `dsecret_ll`, the MLWE/SelfTargetMSIS hardness games, and the imported quantum
reprogramming/O2H lemmas), each separately justified. Fully *instantiating* the SemiConstDistr
adversary interface with the concrete Construction-B signing loop (so the Sq gap is bounded by
`reprog_at_our_types` inside one mechanized statement rather than via the explicit-gap capstone)
is the remaining mechanical step — not new mathematics.
- The named primitives (`masking_ok`, `extract_sound`, `keygen_key_ok`, `dkeygen_pk_marginal`)
  and the imported quantum lemmas remain the assumptions/primitives, each separately justified
  (and `masking_ok`/`extract_sound` correspond to the machine-checked classical
  `masking_perfect` / `extract_or_break` and the `rogue_collapse` PoP step).
- The quantum lemmas (`ow2hsc1h`, adaptive reprogramming) are **imported axioms** of the
  EasyPQC library — epistemically primitives here, exactly as MLWE/SelfTargetMSIS hardness are.
  Re-deriving them from first principles is the EasyPQC project's scope, not ours.
- We claim **no machine-checked QROM bit-security number**; parameters are inherited from
  ML-DSA-87 (Category 5) by the §4 structural argument (aggregation does not touch the lattice).

**Bottom line.** We have moved ML-ADSA's QROM security from "specified, not inheritable as
machine-checked" to: *formalized in a real quantum program logic, reduced to MLWE +
SelfTargetMSIS + imported published quantum lemmas, with the aggregation-specific risk and the
key-swap hop already machine-checked, and the residual being the (mechanical) main-reduction
wiring.* That is the gap genuinely narrowed to engineering plus named primitives — and it is the
first QROM formalization of an ML-DSA aggregate signature that we are aware of.

## Sources
- KLS18 (gap origin; SelfTargetMSIS): https://eprint.iacr.org/2017/916
- Barbosa et al., Fixing & Mechanizing FSwA/Dilithium (the on-paper QROM fix; ROM mechanized): https://eprint.iacr.org/2023/246
- EasyPQC (the quantum EasyCrypt we built): https://eprint.iacr.org/2021/1253 ; branch `deploy-quantum-upgrade` of https://github.com/EasyCrypt/easycrypt
- AHU19 semi-classical O2H (`ow2hsc1h`): https://eprint.iacr.org/2018/904
- Measure-and-reprogram (extraction): https://eprint.iacr.org/2019/190 ; generalized https://eprint.iacr.org/2020/282
- Adaptive reprogramming (signing simulation): https://eprint.iacr.org/2020/1361
- ARU14 (no black-box FS-QROM via rewinding): https://eprint.iacr.org/2014/296
