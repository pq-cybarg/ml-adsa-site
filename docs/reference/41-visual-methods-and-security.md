# ML-DSA & ML-ADSA — Visual Walkthrough, End-to-End, with Security & Side-Channel Guarantees

This document is the **picture book** for the corpus: every step of **ML-DSA** (FIPS-204) and of
**ML-ADSA** (the aggregate construction) drawn as a diagram, end-to-end, together with **what guarantees
each step's security** and **how each step is kept free of side-channels / secret leaks**. It is a
navigation layer over the authoritative text — the formal spec (`docs/30`), the verification dossier
(`docs/31`), the optimization / constant-time posture (`docs/34`), and the research paper (`paper/`).

The diagrams are [Mermaid](https://mermaid.js.org/) — they render natively on GitHub and on the docs site,
and the source is plain text (auditable, deterministic, no binary assets).

---

## 0. How to read these diagrams

Every value is colored by its **secrecy class**, because the side-channel story is exactly "which wires
carry secrets, and is every gate that touches them data-independent?"

```mermaid
flowchart LR
  s["SECRET — must never influence timing/branch/memory-access"]:::secret
  p["PUBLIC — may be branched on freely"]:::public
  d["DERIVED / HASH — public function of inputs"]:::derived
  x["ABORT / REJECT branch (data-dependent control flow)"]:::danger
  classDef secret fill:#ffe0e0,stroke:#c0392b,color:#000;
  classDef public fill:#e6f5e6,stroke:#1e8449,color:#000;
  classDef derived fill:#e3edff,stroke:#2471a3,color:#000;
  classDef danger fill:#fff3cd,stroke:#b9770e,color:#000;
```

- **Red = secret.** The whole constant-time argument is: every operation on a red wire is straight-line
  and branchless (§5).
- **Green = public.** Anything an adversary already knows; branching on it is free.
- **Blue = derived/hash.** A deterministic public function (SHAKE, encode, NTT of a public value).
- **Amber = a data-dependent branch** — flagged explicitly so the residual control-flow surface is visible
  rather than hidden.

Each diagram is followed by **🔒 Security** (what makes the step sound) and **🛡 Side-channel** (how the step
avoids leaking), with pointers to the Go symbol and the proof artifact.

---

## 1. The shared base layer: the ring `R_q` and the NTT

Both schemes live in `R_q = Z_q[X]/(X²⁵⁶+1)`, `q = 8380417`, `n = 256`. All polynomial multiplication goes
through the **Number-Theoretic Transform** (NTT) — the single hottest operation, and therefore the focus of
both the optimization and the constant-time work.

```mermaid
flowchart LR
  a["a ∈ R_q (coeffs)"]:::secret
  b["b ∈ R_q (coeffs)"]:::secret
  na["NTT(a)"]:::derived
  nb["NTT(b)"]:::derived
  pw["⊙ pointwise multiply"]:::derived
  inv["INTT"]:::derived
  out["a·b ∈ R_q"]:::secret
  a --> na --> pw
  b --> nb --> pw
  pw --> inv --> out
  classDef secret fill:#ffe0e0,stroke:#c0392b,color:#000;
  classDef derived fill:#e3edff,stroke:#2471a3,color:#000;
```

The NTT itself is a fixed network of **Cooley–Tukey butterflies** — the control flow (which indices pair
with which, the loop bounds, the twiddle schedule `ζ = 1753`) depends only on `n = 256`, **never on the
coefficient values**:

```mermaid
flowchart TD
  subgraph L["8 levels, length = 128 → 64 → … → 1"]
    bf["butterfly:  t = ζ·a[j+len];  a[j+len] = a[j] − t;  a[j] = a[j] + t"]:::derived
  end
  in["input coeffs"]:::secret --> L --> out["NTT-domain coeffs"]:::secret
  note["loop bounds & index pairs fixed by n=256 only → DATA-INDEPENDENT"]:::public
  L -.-> note
  classDef secret fill:#ffe0e0,stroke:#c0392b,color:#000;
  classDef derived fill:#e3edff,stroke:#2471a3,color:#000;
  classDef public fill:#e6f5e6,stroke:#1e8449,color:#000;
```

**🔒 Security.** The NTT is a *ring isomorphism* — multiplication via NTT is exact (`NTT(p·q)=NTT(p)⊙NTT(q)`,
`INTT∘NTT=id`). This is machine-checked from first principles (`ct_correct`, `ntt_tree_correct`,
`forest_loop_correct`, and the literal index arithmetic `jloop_eq`/`jloop_forest`), and the Montgomery
reduction constant `q·qinv ≡ 1 (mod 2³²)` is proved (`ml_adsa_montgomery.ec`). See `docs/31` and the paper §1.4.

**🛡 Side-channel.** The butterfly network is **straight-line with data-independent control flow** — this is
the property that makes the NTT constant-time, and it is **machine-backed** (`docs/34 §2a`). The reductions
inside the butterfly are branchless (`modQ` = `r + ((r>>63)&Q)`; the AVX2 kernel uses a Montgomery reduce
with a branchless `2³²−Q` correction, byte-identical to generic — `ntt_amd64.s`, `montgomery.go`). Go
symbols: `nttGeneric`/`inttGeneric` (`mldsa87.go`), `nttAVX2`/`inttAVX2` (`ntt_amd64.go`).

---

## 2. ML-DSA-87 (FIPS-204) end-to-end

### 2.1 KeyGen (Algorithm 1)

```mermaid
flowchart TD
  xi["ξ seed (32 B)"]:::secret
  H["H = SHAKE-256"]:::derived
  rho["ρ (32 B) — matrix seed"]:::public
  rhop["ρ' (64 B) — secret seed"]:::secret
  Kk["K (32 B) — signing seed"]:::secret
  A["A = ExpandA(ρ) ∈ R_q^{k×ℓ} (NTT domain)"]:::public
  s1s2["(s1, s2) = ExpandS(ρ')  ‖coeff‖ ≤ η"]:::secret
  t["t = A·s1 + s2"]:::secret
  pr["(t1, t0) = Power2Round(t)  (split at 2¹³)"]:::derived
  pk["pk = (ρ, t1)  → 2592 B"]:::public
  sk["sk = (ρ, K, tr=H(pk), s1, s2, t0)  → 4896 B"]:::secret
  xi --> H --> rho & rhop & Kk
  rho --> A
  rhop --> s1s2
  A --> t
  s1s2 --> t --> pr
  rho --> pk
  pr --> pk
  pr --> sk
  Kk --> sk
  rhop --> sk
  classDef secret fill:#ffe0e0,stroke:#c0392b,color:#000;
  classDef public fill:#e6f5e6,stroke:#1e8449,color:#000;
  classDef derived fill:#e3edff,stroke:#2471a3,color:#000;
```

**🔒 Security.** `t = A·s1 + s2` is a **Module-LWE sample**: recovering `(s1,s2)` from `(A,t)` is the MLWE
problem at Category 5. `t1` (the published high bits) leaks nothing usable; `t0` is kept secret in `sk`.
Go: `KeyGenP` (`sign_param.go`). Assumption: decisional MLWE.

**🛡 Side-channel.** `s1,s2` are sampled by rejection from a SHAKE stream (`rejBoundedPolyP`); the *number*
of XOF reads can vary, but it is a function of the **public seed expansion**, not of any pre-existing
secret, and the sampled coefficients never steer a secret-dependent branch downstream. `A·s1+s2` is the
constant-time NTT path of §1.

### 2.2 Sign — Fiat–Shamir **with aborts** (Algorithm 7)

This is the only place with an intentional **data-dependent loop** (the rejection sampler). It is drawn
explicitly:

```mermaid
flowchart TD
  msg["μ = H(H(pk) ‖ ctx ‖ m)"]:::derived
  start(["κ = 0"]):::public
  y["y = ExpandMask(ρ'', κ)   ‖y‖∞ < γ1"]:::secret
  w["w = A·y   (NTT)"]:::secret
  w1["w1 = HighBits(w)"]:::derived
  ct["c̃ = H(μ ‖ w1Encode(w1))"]:::derived
  c["c = SampleInBall(c̃)   (τ ±1's)"]:::public
  z["z = y + c·s1"]:::secret
  chkz{"‖z‖∞ ≥ γ1−β ?"}:::danger
  r0["r0 = LowBits(w − c·s2)"]:::secret
  chkr0{"‖r0‖∞ ≥ γ2−β ?"}:::danger
  ct0["c·t0"]:::secret
  chkct0{"‖c·t0‖∞ ≥ γ2 ?"}:::danger
  h["h = MakeHint(−c·t0, w − c·s2 + c·t0)"]:::derived
  chkh{"weight(h) > ω ?"}:::danger
  out["σ = (c̃, z, h)  → 4627 B"]:::public
  bump["κ += ℓ"]:::public

  msg --> start --> y --> w --> w1 --> ct --> c --> z --> chkz
  chkz -- yes --> bump
  chkz -- no --> r0 --> chkr0
  chkr0 -- yes --> bump
  chkr0 -- no --> ct0 --> chkct0
  chkct0 -- yes --> bump
  chkct0 -- no --> h --> chkh
  chkh -- yes --> bump
  chkh -- no --> out
  bump --> y
  classDef secret fill:#ffe0e0,stroke:#c0392b,color:#000;
  classDef public fill:#e6f5e6,stroke:#1e8449,color:#000;
  classDef derived fill:#e3edff,stroke:#2471a3,color:#000;
  classDef danger fill:#fff3cd,stroke:#b9770e,color:#000;
```

**🔒 Security.** The accepted `z = y + c·s1` is **perfectly masked**: conditioned on acceptance it is uniform
on its norm window, *independent of the secret shift `c·s1`*. This perfect-HVZK property is the heart of the
EUF-CMA proof and is now **machine-checked from first principles** — the rejection-sampling
change-of-variables `reject_uniform` / `masking_perfect_concrete` (`ml_adsa_masking.ec`), resting only on
`0 ≤ β ≤ γ1−1`. Go: `SignP` (`sign_param.go`).

**🛡 Side-channel.** The four amber checks (`‖z‖`, `‖r0‖`, `‖c·t0‖`, hint weight) **abort the attempt** — the
*number of attempts* is secret-dependent (inherent to FS-with-aborts). Two mitigations:
(1) the magnitude comparisons use the **branchless centered absolute value** `cabs` (a constant-time select,
not a data branch — `mldsa87.go`); (2) ML-ADSA's deployment uses **deterministic nonces** and a combiner
that **abstains on a *public* norm sum** (§3), so the loop-count surface is removed from the aggregate path.
The automated screen for this is the dudect Welch t-test harness (`ct_test.go`, `docs/34 §2c`).

### 2.3 Verify (Algorithm 8) — no secrets at all

```mermaid
flowchart TD
  inp["pk, m, σ=(c̃,z,h), ctx"]:::public
  len{"len(pk)=2592 ∧ len(sig)=4627 ?"}:::danger
  decz["decode z, h"]:::public
  bnd{"‖z‖∞ < γ1−β ∧ weight(h) ≤ ω ?"}:::danger
  A["A = ExpandA(ρ)"]:::public
  c["c = SampleInBall(c̃)"]:::public
  wapprox["w'₁ = UseHint(h,  A·z − c·t1·2^d)   (NTT)"]:::derived
  mu["μ = H(H(pk) ‖ ctx ‖ m)"]:::derived
  ctp["c̃' = H(μ ‖ w1Encode(w'₁))"]:::derived
  eq{"c̃' == c̃ ?"}:::danger
  ok(["ACCEPT"]):::public
  no(["REJECT"]):::danger
  inp --> len
  len -- no --> no
  len -- yes --> decz --> bnd
  bnd -- no --> no
  bnd -- yes --> A --> wapprox
  c --> wapprox
  wapprox --> ctp
  mu --> ctp --> eq
  eq -- no --> no
  eq -- yes --> ok
  classDef public fill:#e6f5e6,stroke:#1e8449,color:#000;
  classDef derived fill:#e3edff,stroke:#2471a3,color:#000;
  classDef danger fill:#fff3cd,stroke:#b9770e,color:#000;
```

**🔒 Security.** Verify recomputes the challenge from `w'₁` and checks it matches `c̃`. A forgery requires a
SelfTargetMSIS solution. Go: `Verify` (`mldsa87.go`); the length/range guards (audit H1/H2/H3) make it
**panic-free on adversarial input** — important because in consensus a panic is a remote-DoS primitive.

**🛡 Side-channel.** Verify touches **no secret**, so all of its branches (amber) are on public data and are
free. The same code is the ML-ADSA verifier — the aggregate *is* a FIPS-204 signature.

---

## 3. ML-ADSA end-to-end

### 3.1 The one-line idea: the additive dual of BLS

```mermaid
flowchart LR
  subgraph BLS["BLS (pairing group)"]
    bls["σ* = Π σᵢ   (homomorphic PRODUCT)"]:::public
  end
  subgraph MLADSA["ML-ADSA (module R_q)"]
    mla["z* = Σ zᵢ,  t* = Σ tᵢ,  W* = Σ wᵢ   (homomorphic SUM)"]:::public
  end
  BLS -. "same algebra, different group" .-> MLADSA
  classDef public fill:#e6f5e6,stroke:#1e8449,color:#000;
```

Aggregation is literally **addition in `R_q`**. The summed key `t* = Σ tᵢ` is itself a bona-fide ML-DSA key
(a sum of MLWE samples is an MLWE sample), and `z* = Σ zᵢ = (Σ yᵢ) + c̃*·(Σ s1ᵢ)` is the response of a single
signer holding that key — so `σ* = (c̃*, z*, h*)` verifies under the **unmodified** FIPS-204 verifier.

### 3.2 The non-interactive combine — no coordinator, no challenge sent, one broadcast per signer

> **This is _not_ an interactive (MuSig-style) handshake.** There is no aggregator that collects nonce
> commitments, replies with a challenge, and then gathers responses across rounds. Non-interactivity comes
> from three facts, and it is important to draw it that way:
>
> 1. **Deterministic nonces.** `y_i = DeriveNonce(msk_i, C)` — so each commitment `w_i = A·y_i` is fixed by
>    `(key_i, content C)` and is **pre-published** alongside `t_i` in the epoch key-tree / commitment pool,
>    in bulk, ahead of time. It is *not* a per-signature interactive "round 1."
> 2. **Self-derived challenge.** Every signer **computes `c*` itself** from the public cohort commitments
>    `{w_j}` (`c* = H(μ ‖ HighBits(W*))`). **Nobody sends a challenge.**
> 3. **Single broadcast.** Each signer therefore emits its response `z_i` as **one** message (exactly like a
>    BLS attestation gossip), and **any untrusted party just sums** `{t_j, w_j, z_j}` into `σ*`.

```mermaid
flowchart TD
  subgraph PRE["Ahead of time, per epoch — deterministic bulk pre-publication (NOT a round)"]
    yi["y_i = DeriveNonce(msk_i, C)  [deterministic]"]:::secret
    wi["w_i = A·y_i"]:::derived
    ti["t_i  (refreshed content key)"]:::public
    pool["PUBLIC pool / epoch key-tree:  { t_j , w_j }"]:::public
    yi --> wi --> pool
    ti --> pool
  end
  subgraph LOCAL["Per content C — each signer acts ALONE, no coordinator"]
    read["read public { w_j } of the cohort"]:::public
    Wstar["W* = Σ w_j"]:::public
    cstar["c* = SampleInBall(H(μ ‖ HighBits(W*)))  [self-derived, nobody sends it]"]:::derived
    zi["z_i = y_i + c*·s1_i"]:::secret
    bcast["broadcast z_i  (ONE message)"]:::public
    read --> Wstar --> cstar --> zi --> bcast
  end
  subgraph ANY["Any party (passive, untrusted) — only sums, holds no secret"]
    sum["z* = Σ z_j ;  t* = Σ t_j ;  pk* = (ρ, Power2Round(t*).t1)"]:::public
    hint["h* = MakeHint(−c*·t0*,  A·z* − c*·t1*·2^d)  [public hint identity]"]:::derived
    sig["σ* = (c̃*, z*, h*) → unmodified FIPS-204 Verify ACCEPTS"]:::public
    sum --> hint --> sig
  end
  pool --> read
  bcast --> sum
  classDef secret fill:#ffe0e0,stroke:#c0392b,color:#000;
  classDef public fill:#e6f5e6,stroke:#1e8449,color:#000;
  classDef derived fill:#e3edff,stroke:#2471a3,color:#000;
```

**On "two rounds."** There *is* a logical data dependency — `c*` depends on `W* = Σ w_j`, so commitments
must exist before responses (this is the Fiat–Shamir binding, and exactly why finished aggregates are
*homomorphic but not freely mergeable*). But that dependency is satisfied by **deterministic
pre-publication**, not by an interactive exchange: no signer waits on a message *from* another signer or
*from* a coordinator, and no challenge is ever transmitted. The earlier framing of this as an
aggregator-driven "round 1 / round 2" would describe the interactive MuSig design that ML-ADSA explicitly is
**not** (see [[ml-adsa-noninteractive]]).

**🔒 Security.** The self-derived `c*` binds the **entire** commitment `W*`, which is exactly what defeats the
Drijvers/ROS attack — giving concurrent security with **no ROS/AGM/OMDL assumption**
(`unbiasable_challenge`, `challenge_adversary_independent`; paper §6.4). Determinism + the public,
predictable content `C = (slot, committee)` also enforces the one-time discipline (fixed cohort ⇒ fixed `c*`
⇒ no nonce reuse). Go: the reference combine is `AggregateF` (`construction_f.go`) and the parameterized
`AggregateP` (`aggregate_param.go`); the per-node **decentralized** combine over public broadcasts is
`CombineFromPublic` (qrysm `mladsa/decentralized.go`), asserted byte-identical to `AggregateF` by
`TestDecentralized_EqualsAggregateF`.

**🛡 Side-channel.** The only secret-touching step is each signer's **local** `z_i = y_i + c*·s1_i` (the §2.2
constant-time path); the published `z_i` is HVZK-simulatable, so broadcasting it leaks nothing. The summing
party runs **entirely on public data** — `t_j, w_j, z_j` are public, and `rr2 = A·z* − c*·t1*·2^d` is the
public hint identity (computed *without* `s2*`). Its only branch — **ABSTAIN** when `‖z*‖∞ ≥ γ1−β` — is a
test on a **public sum**, so it leaks nothing and needs no resampling round.

### 3.3 The layered construction (L0–L3)

```mermaid
flowchart TD
  L0["L0 — core aggregate (the §3.2 summation; n=1 ⇒ vanilla ML-DSA)"]:::public
  L1["L1 — content-key refresh (many-time)"]:::derived
  L2["L2 — epoch Merkle key-tree (non-equivocation)"]:::derived
  L3["L3 — registry + proof-of-possession (rogue-key)"]:::public
  msk["msk (32 B master secret)"]:::secret
  skc["sk_C = (s1,s2,t) = ExpandS(PRF(msk,'F.refresh',C))"]:::secret
  nonce["y = DeriveNonce(msk, C, σ)  (deterministic)"]:::secret
  root["epoch root = Merkle({t_C}); signed by reg key"]:::derived
  reg["registry: (id, regpk, PoP); weight(non-member)=0"]:::public

  msk --> skc
  msk --> nonce
  skc --> L1
  nonce --> L1
  L1 --> L0
  skc --> root --> L2 --> L0
  reg --> L3 --> L0
  classDef secret fill:#ffe0e0,stroke:#c0392b,color:#000;
  classDef public fill:#e6f5e6,stroke:#1e8449,color:#000;
  classDef derived fill:#e3edff,stroke:#2471a3,color:#000;
```

- **L1 (many-time).** Distinct contents `C` give independent keys (PRF security), so aggregating across many
  contents is safe and per-content security equals single ML-DSA (`ml_adsa_F_manytime.ec`,
  `ml_adsa_F_refresh.ec`). Nonces are **deterministic** — no per-signature RNG — subject to the **one-time
  discipline**: a `(signer, C)` signs at most once (enforced by `DurableOneTimeGuard`, fsync'd, write-ahead).
- **L2 (non-equivocation, properties F-C8/C9).** A `t_C` is accepted only if it is a proven member of a
  registration-signed epoch root. Go: `EpochKeyTreeBuild` + `(EpochKeyTree).PathFor` + `MerkleVerify`
  (`construction_f.go`, `merkle.go`), checked in aggregation by `ProvenanceVerifyF`; proofs: Coq
  `ml_adsa_F_provenance.v` and Gobra `merkleBinding`. ("VerifyEpochRoot"/"VerifyContentInTree" are the
  *prose* names for these checks in the spec, not Go symbols.)
- **L3 (rogue-key).** Recognized weight comes from the public registry + PoP; non-registered signers
  (decoys) have weight 0 and **cannot change outcomes** (`ml_adsa_rogue_proof.ec`, Coq
  `ml_adsa_F_decisions.v`, Gobra `filterRecognized`).

**🛡 Side-channel.** `msk` and the refreshed `sk_C`/nonce are the only long-lived secrets; they feed the
deterministic PRF (constant work) and then the §2.2 signer path. The one-time guard prevents the *one* fatal
leak of deterministic signing (two responses under the same nonce ⇒ key recovery) — see
[[deterministic-nonce-security]].

---

## 4. Security guarantees — the reduction chains

### 4.1 EUF-CMA (ROM keystone)

```mermaid
flowchart LR
  F["Forger A (chosen-message)"]:::danger
  H1["Hop S: simulate signing from public data<br/>(perfect HVZK — masking_ok)"]:::derived
  H2["Hop M: swap real key for random<br/>(MLWE indistinguishable — mlwe_assumption)"]:::derived
  H3["Hop E: a verifying forgery IS a<br/>SelfTargetMSIS solution (extract_sound)"]:::derived
  G["Adv ≤ adv_mlwe + Adv^{SelfTargetMSIS}"]:::public
  F --> H1 --> H2 --> H3 --> G
  classDef danger fill:#fff3cd,stroke:#b9770e,color:#000;
  classDef derived fill:#e3edff,stroke:#2471a3,color:#000;
  classDef public fill:#e6f5e6,stroke:#1e8449,color:#000;
```

Machine-checked, admit-free: `msufcma_uncond` (`ml_adsa_euf.ec`). **SUF-CMA** adds the same-`(μ,c)`-new-`(z,h)`
collision term, bundled as `StrongSIS = SelfTargetMSIS ∨ Module-SIS` (`sufcma_uncond`, `ml_adsa_suf.ec`).

### 4.2 QROM (post-quantum) and equivalence-class hardness

```mermaid
flowchart TD
  qa["Construction A (perfect masking)"]:::public
  qat["TIGHT: Adv ≤ adv_mlwe + Adv^{QROM-STMSIS}<br/>no reprogramming / no O2H loss (sq_perfect)"]:::derived
  qb["Construction B (rejection-free)"]:::public
  qbt["LOSSY: distinct-per-query GHHM21 reprogramming<br/>DERIVED in-prover (ghhm_hybrid), not imported"]:::derived
  eqc["Equivalence-class: producing ANY σ ∈ {σ : Verify(pk*,m,σ)}<br/>= the EUF-CMA win ⇒ as hard as one ML-DSA forgery"]:::derived
  qa --> qat
  qb --> qbt
  qat --> eqc
  qbt --> eqc
  classDef public fill:#e6f5e6,stroke:#1e8449,color:#000;
  classDef derived fill:#e3edff,stroke:#2471a3,color:#000;
```

`qrom_eufcma_uncond` (A, tight), `qrom_eufcma_lossy` + `ml_adsa_qrom_ghhm.ec` (B, derived bound),
`equiv_class_guess_bound` / `qrom_equiv_class_uncond` (multiplicity gives no advantage). All inherit the
**parameter set's** NIST category — 2/3/5 for ML-ADSA-44/65/87 (the proofs quantify over `(k,ℓ,η,τ,γ,ω)`).

### 4.3 Which assumption guards which step

```mermaid
flowchart LR
  mlwe["decisional Module-LWE"]:::public
  stm["SelfTargetMSIS"]:::public
  msis["Module-SIS"]:::public
  prf["secure PRF"]:::public
  crh["collision-resistant hash"]:::public
  k["key secrecy (t = A·s1+s2)"]:::derived
  uf["unforgeability (forge ⇒ STMSIS)"]:::derived
  su["strong unforgeability (collision ⇒ SIS)"]:::derived
  mt["many-time refresh (independent keys)"]:::derived
  nq["non-equivocation (epoch tree)"]:::derived
  mlwe --> k
  stm --> uf
  msis --> su
  prf --> mt
  crh --> nq
  classDef public fill:#e6f5e6,stroke:#1e8449,color:#000;
  classDef derived fill:#e3edff,stroke:#2471a3,color:#000;
```

These are **exactly ML-DSA's own assumptions** — ML-ADSA adds no new hardness assumption.

---

## 5. Side-channel & leak-freedom — how it is guaranteed

The constant-time goal: **no secret value influences a branch, a memory-access pattern, or instruction
timing.** The posture and its evidence are in `docs/34 §2`; here is the picture.

### 5.1 The secret-data-flow map

```mermaid
flowchart TD
  msk["msk / ρ' / K"]:::secret
  s["s1, s2, t0"]:::secret
  y["nonce y"]:::secret
  z["response z"]:::secret
  m1["modQ — branchless<br/>r + ((r>>63)&Q)"]:::derived
  m2["cabs — branchless centered abs<br/>(constant-time select)"]:::derived
  m3["NTT — data-independent control flow<br/>(machine-checked)"]:::derived
  m4["Montgomery reduce (AVX2)<br/>branchless 2³²−Q correction"]:::derived
  ok["constant-time secret path"]:::public
  msk --> m1
  s --> m3
  y --> m3
  z --> m2
  s --> m1
  z --> m1
  m1 --> ok
  m2 --> ok
  m3 --> ok
  m4 --> ok
  classDef secret fill:#ffe0e0,stroke:#c0392b,color:#000;
  classDef derived fill:#e3edff,stroke:#2471a3,color:#000;
  classDef public fill:#e6f5e6,stroke:#1e8449,color:#000;
```

Every red→blue edge is an operation on a secret, and every blue node is **branchless / data-independent**.

### 5.2 Branchless reductions (the pattern, before → after)

```mermaid
flowchart LR
  subgraph BAD["data-dependent (avoided)"]
    b1["if r < 0 { r += Q }"]:::danger
  end
  subgraph GOOD["constant-time (used)"]
    g1["r + ((r>>63) & Q)        // modQ"]:::derived
    g2["(x &^ mask)|(t & mask)   // cabs select"]:::derived
    g3["u − (mask & (2³²−Q))     // Montgomery canonicalize"]:::derived
  end
  BAD -. "replaced by" .-> GOOD
  classDef danger fill:#fff3cd,stroke:#b9770e,color:#000;
  classDef derived fill:#e3edff,stroke:#2471a3,color:#000;
```

> Honest note: Go's compiler often lowers a naive `if r<0 { r+=Q }` to a branchless `cmov` anyway — which is
> *why* the dudect positive control had to use a data-dependent **loop count**, not a sign test, to register
> leakage (`ct_test.go`). The code uses the explicit branchless forms regardless, so the property does not
> depend on a compiler optimization (`docs/34 §2b`).

### 5.3 The NTT data-independence — as a proof obligation

```mermaid
flowchart TD
  claim["CLAIM: NTT's control flow depends only on n=256"]:::public
  p1["loop bounds (length: 128→1) — constant"]:::derived
  p2["index pairs (j, j+len) — fixed schedule"]:::derived
  p3["twiddle order (ζ^{brv8(k)}) — fixed table"]:::derived
  p4["reductions branchless (modQ / Montgomery)"]:::derived
  proof["machine-checked: ct_correct, forest_loop_correct,<br/>jloop_eq, jloop_forest (docs/31, docs/34 §2a)"]:::derived
  claim --> p1 & p2 & p3 & p4 --> proof
  classDef public fill:#e6f5e6,stroke:#1e8449,color:#000;
  classDef derived fill:#e3edff,stroke:#2471a3,color:#000;
```

This is stronger than "we wrote it carefully": the iterative loop the code runs is *proved equal* to the
recursion, with termination, and the literal `a[j]`/`a[j+len]` index arithmetic is checked — so the
data-independence is a theorem, not a comment.

### 5.4 The validation pipeline (defense in depth)

```mermaid
flowchart LR
  src["secret-path source"]:::secret
  f["FORMAL: NTT data-independence + perfect-HVZK masking<br/>(EasyCrypt / Coq, machine-checked)"]:::derived
  d["DYNAMIC: dudect Welch t-test, fixed-vs-random inputs<br/>(ct_test.go, CT_MEASURE)"]:::derived
  x["CROSS-IMPL: byte-exact vs CIRCL + go-qrllib<br/>(differential, all 3 param sets)"]:::derived
  a["AVX2 KERNEL: byte-identical to generic<br/>(docker linux/amd64, 2000-vector gate)"]:::derived
  verdict["leak-freedom: proven (control flow) +<br/>measured (timing) + cross-checked (output)"]:::public
  src --> f --> verdict
  src --> d --> verdict
  src --> x --> verdict
  src --> a --> verdict
  classDef secret fill:#ffe0e0,stroke:#c0392b,color:#000;
  classDef derived fill:#e3edff,stroke:#2471a3,color:#000;
  classDef public fill:#e6f5e6,stroke:#1e8449,color:#000;
```

### 5.5 Constant-time checklist (decision view)

```mermaid
flowchart TD
  q0{"Does the op touch a SECRET?"}:::danger
  q1{"Branch / loop count<br/>depends on the secret?"}:::danger
  q2{"Memory access index<br/>depends on the secret?"}:::danger
  q3{"Variable-latency instr<br/>on secret (div/mod)?"}:::danger
  okp(["free — public data"]):::public
  fix1["→ branchless select / masking (modQ, cabs)"]:::derived
  fix2["→ data-independent schedule (NTT), or<br/>determinism + public-sum abstain (aggregate)"]:::derived
  fix3["→ Montgomery/branchless reduction (no %Q on secret)"]:::derived
  ct(["CONSTANT-TIME ✓"]):::public
  q0 -- no --> okp
  q0 -- yes --> q1
  q1 -- yes --> fix1 --> ct
  q1 -- no --> q2
  q2 -- yes --> fix2 --> ct
  q2 -- no --> q3
  q3 -- yes --> fix3 --> ct
  q3 -- no --> ct
  classDef danger fill:#fff3cd,stroke:#b9770e,color:#000;
  classDef public fill:#e6f5e6,stroke:#1e8449,color:#000;
  classDef derived fill:#e3edff,stroke:#2471a3,color:#000;
```

**Honest residual.** The one inherently data-dependent element is the **rejection-loop attempt count** in
single-signer signing (§2.2) — universal to Fiat–Shamir-with-aborts. ML-ADSA's deployment removes it from
the *aggregate* path (deterministic nonces + abstain on the *public* sum), and a fully hardened
single-signer build (constant-time sampler, masking) is the remaining engineering item (`docs/34 §2`,
`docs/32 #7`). Microarchitectural leakage on native silicon (`dudect`/`ctgrind` on x86) is a deployment-time
validation step, not yet run on hardware here.

---

## 6. Traceability and reproduction

Each diagram maps a step to its **Go symbol** and its **proof artifact**; the full row-by-row matrix is the
verification dossier (`docs/31`) and the implementation-conformance map (`docs/20`). Counts are the single
source of truth from `formal/count-artifacts.sh` (**36 artifacts / 244 lemmas / 50 genuineness / 6 Gobra**).

```
# regenerate the proof tallies these diagrams reference
cd formal && zsh count-artifacts.sh

# the constant-time evidence behind §5
cd go-mladsa && CT_MEASURE=1 go test -run TestConstantTime -v # dudect Welch t-test
cd go-mladsa && ./validate-avx2-docker.sh                    # AVX2 byte-identity (incl. NTT)
cd go-mladsa && go test -run 'TestCoreVsCIRCL|TestParamVerifyVsCIRCL'   # cross-impl differential
```

**Boundary (unchanged from the rest of the corpus).** The machine-checked proofs are about the
algorithm/model and the NTT's structure; the Go is byte-anchored to two independent FIPS-204 verifiers
(measurement). The diagrams visualize *both* surfaces and which is which — they do not assert a code-level
proof of the Go source beyond the Gobra structural theorems (`docs/22`).
