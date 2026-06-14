# ML-ADSA Construction F — A Plain-Language Whitepaper

*An undergraduate-level explanation of how to combine many post-quantum signatures into one, why it
is hard, and exactly what we proved. No prior cryptography assumed; a little algebra is enough.*

Companion to the technical specification (`docs/17`), the design record (`docs/16`), and the
verification summary (`docs/18`). This document trades rigor for clarity; where it simplifies, the
technical docs have the exact statements. Project: **pq-cybarg**; deployment target: **QRL 2.0**
(which uses the ML-DSA-87 signatures this scheme aggregates).

---

## 1. The problem in one paragraph

A **digital signature** lets you prove "I authorized this message" without revealing your secret
key. On a blockchain, thousands of people sign things (blocks, votes, transactions) constantly.
Storing thousands of separate signatures is expensive. **Signature aggregation** squashes many
signatures into one small object that a verifier can check in one shot. The famous tool for this is
**BLS**, used by Ethereum. The catch: **BLS is broken by quantum computers.** We need an aggregator
that survives quantum attacks. This document explains the one we built, **Construction F**, and what
we *proved* about it.

---

## 2. Signatures, in friendly terms

A signature scheme has three actions:

- **KeyGen** → a *secret key* `sk` (you keep) and a *public key* `pk` (everyone sees).
- **Sign(sk, message)** → a *signature* `σ`.
- **Verify(pk, message, σ)** → *yes* or *no*.

Security ("unforgeability"): nobody without `sk` can produce a `σ` that verifies on a new message.

**ML-DSA-87** (a.k.a. Dilithium, the NIST post-quantum standard FIPS-204, the one QRL 2.0 uses) is a
*lattice* signature. Roughly, its secret is a vector `s` of **small** numbers, and signing produces a
response `z = y + c·s`, where `y` is a fresh random **mask** and `c` is a challenge derived by hashing
the message. The verifier checks an equation **and** that `z` is **small** (its numbers stay below a
bound). That "stay small" rule is the whole source of both its quantum-resistance and the difficulty
below. (Contrast: BLS lives in a group where "size" is not a constraint — that freedom is exactly what
a quantum computer exploits to break it.)

---

## 3. What BLS does, and why we can't just copy it

BLS aggregation is almost magic: to combine signatures you literally **multiply** them together, and
the result is **one** group element (~48 bytes), *no matter how many* you combined. Verification is
one check against the (summed) public keys. It is:

- **constant size** (48 bytes for a million signers),
- **non-interactive** (signers don't talk to each other),
- **unbounded** (combine forever),
- **many-time** (one key signs forever).

Why can't lattices copy this? Two walls (both real, both proven in `docs/16`):

1. **Norm growth.** Lattice signatures must stay *small*. Add `N` of them and the sum gets ~`√N`
   bigger. Past a point it breaks the "stay small" rule. BLS has no size rule, so it never hits this.
2. **No free homomorphism.** BLS multiplication collapses `N` checks into one *exactly*, thanks to a
   "pairing." Lattices have no pairing. There is **no known post-quantum equivalent** — this is a
   recognized open problem, not a gap in our effort.

So a perfect BLS clone is impossible today **and** BLS itself is quantum-dead. The honest goal is:
get **as much of BLS's behavior as possible** while staying post-quantum and trustless.

---

## 4. Two honest techniques (and which one this is)

There are exactly two families that get close:

- **Technique 1 — Multisignature.** The aggregate *is itself a genuine ML-DSA-87 signature* under a
  combined key, checked by the **unmodified** standard verifier. Constant size (one signature). The
  price: the signers must share a setup and there's a cohort-size cap. **This is what Construction F
  builds on.**
- **Technique 2 — A proof system** (LaBRADOR-class). A succinct proof that "N signatures exist."
  Unbounded and arbitrary, but a *custom* verifier and bigger objects. (Not used by F.)

**Construction F is Technique 1, upgraded** so that it is *many-time* and supports rich on-chain
decisions — while keeping the output a real ML-DSA-87 signature.

**What about the other recent post-quantum schemes?** Two are worth naming, because they solve
*nearby but different* problems:

- **Threshold Raccoon** (EUROCRYPT 2024) is a *threshold* signature: a group jointly produces **one**
  signature under a **shared** key, but the signers must **talk to each other over three rounds**, the
  result is a **new ~13 KB signature type** (not a standard ML-DSA one), and the key is handed out by a
  **trusted dealer**. Great when you want "`t`-of-`n` people authorize one action together"; not the same
  as combining many *independent* signatures into a standard one.
- **Chipmunk** (CCS 2023) is a *synchronized* multi-signature: many signers sign the **same message in a
  given time slot** and those combine into **one aggregate (still ~100+ KB)** using an evolving key tree.
  A real improvement over its predecessor, but you must agree on time slots, each signer carries a **large
  secret key state**, and it needs a **new verifier**.

ML-ADSA's distinguishing bet: the aggregate is a **plain ML-DSA-87 signature the unmodified standard
verifier already accepts**, built **without any rounds of interaction, without time slots, and without a
trusted aggregator** — at the cost of everyone signing a common message. (A side-by-side table is in
`docs/35` §4.)

---

## 5. The core trick that makes the aggregate verify

Here is the one piece of algebra worth seeing. Suppose `N` signers share a public matrix `A` and all
sign the **same** challenge `c*`. Write the aggregate of their secrets/masks/responses as sums
(`s* = Σsᵢ`, `y* = Σyᵢ`, `z* = Σzᵢ`). Then:

```
A·z* − c*·(aggregate key) = (aggregate commitment) − c*·(small stuff)
```

This is **exactly the same equation a single ML-DSA-87 signature satisfies** — just with the *summed*
quantities. So the **standard verifier accepts the aggregate as if it were one ordinary signature.**
We proved this identity in the Rocq proof assistant for cohorts of size **10, 100, and 1000** (and
for general N), and we confirmed it empirically: the independent Cloudflare **CIRCL** verifier accepts
our N=10/100/1000 aggregates as valid ML-DSA-87 signatures. (See §9.)

---

## 6. The hard part: making it *many-time*

A subtle danger: each signature `z = y + c·s` leaks a *tiny* bit about the secret `s`, because the
mask `y` is *small* (it can't fully hide `s` once you sum many of them). A single ML-DSA signature
avoids this with **rejection sampling** (it retries until `z` looks perfectly random). But in the
aggregate, retrying is jointly infeasible past ~4 signers. So the basic aggregate is **few-time**:
safe for ~1,000 uses of the same combined key, then the tiny leaks add up and the secret can be
recovered (we computed: around 10 million signatures). That is not good enough for a long-lived
blockchain key.

**The fix (the keystone of Construction F): refresh the key every time.** Derive a *fresh* secret for
each new context (each block/decision) using a PRF (a keyed hash):

```
secret_for_context_C  =  derive( master_seed , C )
```

Because each context uses a **brand-new, independent** key that is used **exactly once**, there is
**nothing to accumulate** — the leak that broke the few-time version never gets a second sample. We
proved (in EasyCrypt) that this refresh makes the scheme **many-time**: the only cost of swapping the
real keys for fresh independent ones is the PRF's (negligible) advantage. This is the single most
important theorem in the build (`F-C4`).

The honest price of refresh: the *public* key changes per context too, so those per-context public
keys must be published or committed in a small **Merkle tree** (the same idea behind hash-based
signatures like the NIST-standardized XMSS). The signer stays "stateless" (it just hashes the
context); the system carries a compact key-tree. This is bandwidth/storage, **not** a security
weakness.

---

## 7. Making it non-interactive and attack-proof (ROS)

For signers not to chat back-and-forth, the challenge must be common and computable by all. A known
danger here is the **ROS / Drijvers attack**: a cheating co-signer who picks its random value *after*
seeing the honest signer's value can *bias* the shared challenge and forge.

Construction F closes this with two standard ingredients (no exotic assumptions):

1. **Commit-then-reveal:** everyone commits to their random value first, so the cheater is *locked
   in* before it sees the honest value.
2. **Regularity of A** (a property ML-DSA *already* relies on): the honest random value `A·y` is
   essentially uniform, so adding it scrambles the shared challenge **no matter what the cheater
   chose**.

We proved (EasyCrypt) that together these make the challenge **unbiasable** — the cheater's choice has
*zero* effect on the challenge distribution — and that the whole multi-session signing process is
**secret-independent** (a simulator with no secret produces the same thing). That removes the ROS
attack's prerequisite entirely, **without** the "ROS/AGM" assumptions that other 2-round schemes lean
on. (`F-C11`.)

---

## 8. Bonus: it's a substrate for on-chain decisions

Because the domain (context) is just part of the message, the *same* accounts can sign in *any* agreed
domain — including a cross-chain bridge domain like `"QRL:SUI"` — without new keys. On top of that, we
formalized the common decision/voting patterns (all machine-checked in Rocq):

- **Yes/No** consensus (two domain-separated aggregates + a tally),
- **1-of-M** choice, **approval** (pick several), **ranked/Borda**,
- **Choose N-of-M options** (aggregate everyone who picked the same option-subset),
- **k-of-n threshold** ("at least k members signed," with *who* auditable),
- **Weighted/continuous tallies** using an *additively-homomorphic commitment*: you can **sum hidden
  numbers** (budgets, scores) and open only the total, individual values staying private.

And **decoys have zero weight**: anyone can flood the system with fake non-member signatures and it
**cannot** change the outcome, because only recognized members count (proven).

---

## 8b. Case study: we wired it into a real post-quantum blockchain (QRL 2.0)

Theory and tests are one thing; a running system is another. So we took Construction F and built it into
**QRL 2.0's actual blockchain client** (`qrysm`, a post-quantum fork of Ethereum's Prysm) to see whether
it really removes the bloat — and to try to break it.

**The problem we were fixing.** On a chain like this, a committee of validators all "attest" to (vote on)
each block. Today the client can't combine their signatures, so it just keeps every one of them. A single
attestation from a full 128-member committee carries up to **~592 KB** of signatures — 128 separate
4,627-byte ML-DSA-87 signatures stapled together. That bloat is in every block, forever.

**What we changed — and only what we changed.** We swapped *one step*: instead of stapling signatures
together, each node runs Construction F's decentralized combine. Everything else — who runs a node, who
gets picked to aggregate, how signatures are checked — stays exactly the same. The result is **one
4,627-byte signature** plus a tiny "who-signed" bitfield. That's a flat, constant size no matter how many
validators sign:

| Validators who signed | Old way (a list) | Construction F | Shrink |
|---|---|---|---|
| 8   | 37 KB  | 4,627 bytes | **8×**   |
| 16  | 74 KB  | 4,627 bytes | **16×**  |
| 64  | 296 KB | 4,627 bytes | **64×**  |
| 128 | 592 KB | 4,627 bytes | **128×** |

**Nobody is in charge — and everyone agrees.** We ran this as a real local network of independent node
*processes* (not a simulation, not a mock). Each node combines the signatures on its own from public
information, and **every node computes the byte-for-byte identical aggregate** — no trusted "aggregator"
in the middle. And the clincher: every aggregate is accepted by **QRL's own shipping signature verifier**,
because the aggregate genuinely *is* a normal ML-DSA-87 signature. We didn't ask the chain to trust new
code; we handed it something its existing code already accepts.

**Nothing important is lost.** The "who signed" bitfield still tells you exactly which validators
participated (that's what rewards and slashing actually use), and the aggregate proves the committee
signed. The only thing dropped is the individual signatures — which is exactly what BLS aggregation drops
on Ethereum today.

**We tried hard to break it, live:**
- **Fake validators (a sybil flood):** we threw 1,000 non-members at it. The aggregate came out
  *byte-identical* — outsiders simply don't count.
- **A cheating insider (equivocation):** a node tried to slip in a key it never committed to. **Every**
  other node detected it, kicked it out, dropped to "7 of 8 signed," and still agreed on the same
  signature over the honest seven. The cheater couldn't move the result.
- **Tampered or forged signatures:** rejected by both our verifier and QRL's.
- **Combine in a different order or grouping:** two independent aggregators split the same signers into
  different sub-groups, in different orders, and produced the **exact same bytes** — verified natively.
  (This matters because the math sums everyone's contributions, and addition doesn't care about order.)

**We also checked for secret leakage with statistics, not faith.** Across millions of samples, the
fresh-per-vote keys showed essentially no correlation (the tell-tale "distinguisher's edge" was 0.26%),
and asking a validator to sign the same thing twice is simply *refused* — so there's nothing to
accumulate. This is the hands-on counterpart to the machine-checked "zero-knowledge" proof.

**Bottom line of the case study:** a real post-quantum chain can replace a ~592 KB pile of signatures with
**one 4,627-byte aggregate** that every node computes identically and the chain's own software verifies —
with cheaters provably powerless — by changing only the combine step. (The remaining work to a full
production fork is plumbing — hooking into the chain's peer-to-peer gossip and batching verification —
not new cryptography. The deep technical write-up is `docs/29`; the live demos are
`cmd/mladsa-{devnet,hieragg,epochnet}`.)

---

## 9. What "we proved it" actually means

Cryptographers distinguish three strengths of evidence. We are explicit about which is which:

- **Machine-checked** — a proof assistant (Rocq/EasyCrypt) verified the math with zero trust in us.
- **Measured** — we ran real code and an *independent* verifier accepted the output.
- **Assumed** — a standard, named hardness assumption (everyone in the field relies on these).

For Construction F: **35 machine-checked prover artifacts** (all passing — 234 lemmas across EasyCrypt,
EasyPQC, and Rocq, plus 6 Gobra code-level theorems) **+** independent-verifier (CIRCL) measurements
**+** a small, standard assumption set. Concretely, we machine-checked:

- correctness for N = 10/100/1000 (the aggregate really verifies),
- unforgeability at **NIST Level 5 with no loss** vs a single ML-DSA-87 signature,
- the **many-time** keystone,
- **post-quantum (QROM)** security,
- **ROS/concurrent** resistance,
- zero-knowledge, transparency, cross-chain portability, provenance, one-time binding, decision
  integrity, and every decision mode above.

Crucially, **we also stamped each proof for "genuineness"**: an automated check deletes the key
assumption from each proof and confirms the proof then *fails* — so no proof is secretly trivial.
There are **no `admit`s** (no "trust me" steps) anywhere.

---

## 10. What it rests on (the whole trust story)

Construction F assumes **nothing beyond what ML-DSA-87 already assumes, plus a hash-based PRF and a
collision-resistant hash** (both of which ML-DSA already uses internally):

- the hardness of certain lattice problems (MLWE, Module-SIS, SelfTargetMSIS),
- a secure PRF and a collision-resistant hash.

It uses **no** trusted setup, **no** secret/"toxic-waste," **no** trusted aggregator, **no** special
hardware, and **none** of the heavier assumptions (no pairings, no ROS/AGM, no SNARK/STARK). This is
the "cypherpunk" trust posture: anyone can check everything; nobody has to be trusted.

---

## 11. Honest limitations (the things we did *not* hide)

- **Size.** One aggregate is 4,627 bytes (a full ML-DSA-87 signature), versus BLS's ~48 bytes. It is
  *constant* in the number of signers, but it is lattice-sized. That is the post-quantum tax.
- **Statefulness.** Many-time needs the per-context key refresh (a key-tree), à la XMSS — not BLS's
  "generate once, forget forever."
- **It's detectably an aggregate.** The signature verifies as normal ML-DSA-87, but a statistician
  looking at many signatures could tell it came from an aggregate (the response is more
  concentrated). This is metadata, not a forgery risk — and it's unavoidable for any linear
  aggregate.
- **Cohort cap.** The "stay small" rule caps how many signers fit in one aggregate (comfortably into
  the thousands; we verified through 1,000).
- **One scoping note in the proofs.** Two theorems (the many-time keystone and the concurrent bound)
  plug in a standard, separately-proven bound as a supplied input; the reductions themselves are fully
  proven. The deepest byte-level internals of ML-DSA (its hashing/NTT) are treated as named building
  blocks in the proofs and validated by running real code — fully formalizing those is a multi-year
  effort underway in the wider community, separate from this work.
- **Review.** As with all new cryptography, independent expert review is required before any real-world
  deployment.

---

## 12. Bottom line

You cannot have *all* of BLS post-quantum — that's an open problem, and BLS itself doesn't survive
quantum computers. **Construction F gets you the practically important parts:** combine 10, 100, or
1,000 ML-DSA-87 signatures into **one genuine ML-DSA-87 signature** that any standard verifier accepts;
make it **many-time** (refresh), **concurrent-safe** (no ROS), **post-quantum**, **cross-chain**, and a
**substrate for accountable voting and private tallies** — all trustlessly, resting only on
ML-DSA-87's own assumptions. And, unusually for cryptography this young, **almost all of it is
machine-checked, with the honest boundaries clearly marked.**
