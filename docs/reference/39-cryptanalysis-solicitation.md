# 39 — Cryptanalysis Solicitation & Outreach Packet

Companion to the reviewer-facing **cryptanalysis review packet** (`docs/36`) and the roadmap
(`docs/32 §3.4`). Independent third-party cryptanalysis is, by the project's own assessment, **the
single decisive gate** before any standardization claim — the machine-checked proofs verify the
reductions *as modeled*; they do not rule out a modeling gap or a novel attack on the composition.
This document is the *outreach* layer: who to ask, how, what's in scope, and how findings are handled.

> **One-line ask.** "Here is a non-interactive aggregate signature whose output is a bona-fide,
> unmodified-verifier **FIPS-204 ML-DSA-87** signature, reducing to ML-DSA's own assumptions, with a
> machine-checked proof corpus. Please try to break the *composition* — especially the
> shared-challenge summed-response surface (`docs/36 §6.1`)."

---

## 1. What we are asking reviewers to do

Attack the **construction**, not re-derive ML-DSA. Concretely, in priority order (full detail and the
exact lemma each item would falsify are in `docs/36 §6`):

1. **Summed-response / shared-challenge forgery (`§6.1`, HIGHEST).** Every signer answers the *same*
   challenge `c̃*` (bound to the aggregate commitment `W*`). Is there a forgery that exploits the
   shared challenge + additive `z* = Σ zᵢ` structure that is *not* a forgery against a single ML-DSA
   instance? This is the crux — it would break `equiv_class_guess_bound` / `eq_exact`.
2. **Norm-budget / cohort-cap / Construction-B leakage (`§6.4`).** Attack the *concrete* secure-`N`:
   `‖z*‖∞` grows ~√(cohort); does the stated cap + the abstain test leave exploitable slack, or does
   Construction-B's rejection-free masking leak? (Concrete study: `docs/37`.)
3. **Deterministic-nonce safety under faults / state failure (`§6.3`).** The one-time-release guard
   closes nonce-reuse-under-different-challenge; can a fault, a restart race, or an equivocating
   aggregator defeat it in a way the protocol (not just the implementation) permits?
4. **Perfect-HVZK kernel for the aggregate (`§6.5`).** Is `masking_ok` (the ML-DSA HVZK simulator)
   actually perfect *for the aggregate distribution*, or is there a residual bias an attacker can use?
5. **Concurrent / ROS in the interactive variant (`§6.2`), QROM-B reprogramming derivation (`§6.6`).**
6. **Modeling-gap hunting.** A finding that a *named axiom/primitive* is unrealistic
   (`masking_ok`, `rogue_collapse`, the Thm-6.1 distinct-query bound) is as valuable as a direct break.

A reviewer should be able to start from `docs/36` alone; this packet adds the engagement logistics.

## 2. What is already settled (don't spend time here)

- ML-DSA-87 itself (FIPS-204) — out of scope; assume it secure.
- Honest correctness / the NTT / encode-decode — machine-checked (`formal/`, incl. the NTT→eval-vector
  bridge and bit-packing losslessness); attack the *forgery* surface, not the honest path.
- ROM & QROM unforgeability *as reduced* — machine-checked; attack the *modeling*, not the algebra.

## 3. Outreach plan (where to solicit)

| Channel | Mechanism | Target audience |
|---|---|---|
| **IACR ePrint comment + direct email** | post the paper, email lattice cryptanalysts with the §1 ask | del Pino, Lyubashevsky, Prest, Espitau, the Dilithium/Raccoon authors, NIST PQC mailing list `[VERIFY current list]` |
| **pqc-forum / NIST MPTC feedback** | post to the NIST pqc-forum and respond to MPTC calls for feedback | NIST PQC + MPTC community |
| **Conference / workshop** | submit to CRYPTO/EUROCRYPT/ASIACRYPT/PKC; present at a rump session or RWC | peer reviewers |
| **Real-World Crypto / CHES** | deployment + side-channel framing | implementers, side-channel researchers |
| **Targeted bounty** (optional, §4) | a public, time-boxed challenge with rewards | independent researchers, students |

## 4. Optional bounty structure (template)

A bounty is *not* required for credibility (peer review + ePrint scrutiny is the main signal), but a
small, well-scoped challenge can accelerate adversarial attention. If run:

| Tier | What qualifies | Suggested reward band |
|---|---|---|
| **Break** | A practical forgery against ML-ADSA-87 that the *unmodified* FIPS-204 verifier accepts, without the secret key, using ≤ the claimed Cat-5 work | top tier |
| **Reduction break** | A demonstrated gap between the modeled reduction and the real construction (an attack the proofs "miss" due to a modeling assumption), or a falsified named axiom | high |
| **Concrete-parameter weakness** | A secure-`N` / norm-budget attack beating the stated cap, or a Construction-B leakage attack | medium |
| **Implementation / fault** | A protocol-level (not impl-only) defeat of the one-time/equivocation guard | medium |
| **Documented hardening** | A precise modeling improvement or tightened bound, even without a break | acknowledgement + small |

Rules of engagement: public scope = this repo's spec + reference impl; findings disclosed to
`resistant@tuta.com` with a 90-day coordinated-disclosure window; results published with credit
(or anonymously, reviewer's choice). Fund/escrow and exact amounts: `[owner to decide]`.

## 5. How to submit a finding

1. Email **`resistant@tuta.com`** with subject `ML-ADSA cryptanalysis: <surface>`.
2. Include: the surface (`§6.x`), the claim, the exact lemma/axiom it falsifies (if any), and a
   reproducible artifact (script/PoC against `go-mladsa/`, or a precise mathematical argument).
3. We will acknowledge within `[N]` days, attempt to reproduce, and either (a) confirm + credit +
   coordinate disclosure, or (b) explain why the modeled proof already excludes it (and, if the
   explanation reveals a doc gap, fix the docs and credit the reporter).

## 6. Honesty statement (carry into every outreach)

> The machine-checked proofs are a strong *positive* signal and a precise statement of *what* is
> assumed, but they are **not** a substitute for human cryptanalysis. They verify the reductions to
> MLWE/SelfTargetMSIS as modeled; a novel attack on the composition or an unrealistic modeling
> assumption would not be caught by them. That is exactly what this solicitation is for.
