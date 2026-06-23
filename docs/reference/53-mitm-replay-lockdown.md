# MitM & Replay lockdown — every front, what locks it, and what the deployment must add

**Threat model.** An active network adversary on the path between signers, the (untrusted) aggregator, and
verifiers: it can capture, modify, drop, reorder, inject, and re-send any message. Three concrete goals, per the
deployment ask: **(1) steal credentials from captured traffic; (2) fake a different request than the user
authorized; (3) impersonate the user.** Each front below is mapped to the mechanism that locks it, the evidence,
and — honestly — whether the *scheme* closes it or the *deployment* must.

## Front 1 — Steal credentials from captured traffic

| Attack | Locked by | Evidence | Closed? |
|---|---|---|---|
| Recover a signer's long-term/root key from captured transcripts | Leakage register: every exposed channel ≥ native; root unrecoverable across unlimited cycles | docs/51; `ml_adsa_F_rootsafe.ec` (root ⇒ PRF, Q-independent); estimator (offset 455–489, hint 387 ≥ native) | **scheme** ✓ |
| Recover a *spent* per-content key | Possible by design (transcript reveals it) but it is **one-time** ⇒ re-signing the already-agreed decision is a no-op; confined by the forward-secret refresh | F20 key-leak model; `ForwardSecretRatchet` | **scheme** ✓ (no value to attacker) |
| Passive eavesdropping needs to be prevented? | **No** — the scheme is secure with fully public transcripts, so transport *confidentiality is not required* for credential safety | docs/51 §2 | **scheme** ✓ |

**Bottom line:** captured traffic yields nothing usable — not the root, not any live/future key; only spent
one-time keys whose job is done. Credential theft via MitM capture is closed by the scheme.

## Front 2 — Fake a different request than the user authorized

| Attack | Locked by | Evidence | Closed? |
|---|---|---|---|
| Alter the decision in a finished aggregate (A→B) | `VerifyF = Verify(PkStar, bind(Payload,PartRoot,RegRoot,Epoch), Sig, Ctx)` binds the payload | `TestMitM_Replay_AllBoundFieldsTamperEvident` (payload tamper rejected) | **scheme** ✓ |
| Reuse signers' A-contributions to assemble a valid B-aggregate | Each response `zᵢ` is bound to the challenge `c = H(μ*(payload), HighBits(ΣW))`; a different payload ⇒ different `c` ⇒ responses don't combine | challenge-binding (§Construction); `TestMitM…` (decision tamper) | **scheme** ✓ |
| Get two different decisions signed for the same slot | One-time guard keys on `(signer, content)`; a slot/content is consumed once | `TestMitM_OneTimeGuardBlocksContributionReplay` | **scheme** ✓ |
| Make the signer authorize B while believing it is A (UI/display attack) | **WYSIWYS** — the signing code must hash the *displayed* payload into `μ*`; the scheme binds whatever payload is hashed | — | **deployment** ⚠ (see §Residuals) |

**Bottom line:** a MitM cannot alter, re-target, or re-assemble a request into a different decision — every path
fails verification or the one-time guard. The one residual is WYSIWYS at the wallet UI (true of *every* signature
scheme): the application must hash exactly what the user sees.

## Front 3 — Impersonate the user

| Attack | Locked by | Evidence | Closed? |
|---|---|---|---|
| Forge a signature/aggregate under the user's key | EUF-CMA / SUF-CMA at ML-DSA-87 (Cat-5), ROM+QROM | `ml_adsa_euf`/`ml_adsa_suf`/`ml_adsa_qrom`; docs/50 (267c/229q) | **scheme** ✓ |
| Inject/substitute a chosen key into the cohort (rogue-key) | Proof-of-Possession; a member without a valid PoP is never recognized | `TestMitM_RogueKeySubstitutionRejected`; `BuildRegistry`/`VerifyPoP` (F-C5, `ml_adsa_rogue_proof.ec`) | **scheme** ✓ |
| Corrupt the Fiat–Shamir challenge in transit to bias a response | **N/A by design** — the challenge is SELF-COMPUTED by each signer from public data, never transmitted; there is no challenge channel to MitM | non-interactivity ([[ml-adsa-noninteractive]]) | **scheme** ✓ (no channel) |
| Aggregator equivocation (different aggregates to different verifiers) | Each aggregate binds its exact decision/participant-set/epoch; non-equivocation epoch key-tree + provenance/audit | F-C7/F-C9 (`ml_adsa_F_provenance`), `Audit` | **scheme** ✓ |

**Bottom line:** impersonation requires breaking ML-DSA-87 (Cat-5) or forging a PoP for a key not possessed —
neither feasible; and the non-interactive self-computed challenge removes the classic MitM-the-challenge vector.

## Replay, specifically

An aggregate is valid **only** for its exact `(payload, part-root, reg-root, epoch, ctx-domain)` tuple — all bound
by `VerifyF` and all tamper-rejected (test, 7/7). A **verbatim** replay still verifies (it *is* a valid signature),
so the application closes replay by **consuming each `(epoch, decision)` once** — which the binding makes
sufficient and the one-time guard enforces at aggregation. Cross-domain/cross-chain replay is blocked by the `ctx`
domain tag (e.g. `"ZOND"` / `"ZOND:<chain>"`); cross-epoch by the epoch field + forward-secret ratchet.

## Residuals the DEPLOYMENT must lock (honest)

These are outside the signature scheme (true for any scheme) and must be handled by the QRL client:
1. **WYSIWYS:** hash exactly the payload the user approved into `μ*` (wallet-UI integrity). The scheme binds it;
   it cannot police what the UI displays.
2. **Anti-DoS / liveness:** a MitM can drop/delay messages → a *liveness* problem (no decision reached), never a
   *safety* one (cannot forge or change a decision). Handled by the consensus layer's standard timeouts/retries.
3. **Unique decision identifier:** the payload/epoch must include a unique per-decision id (slot/height/chain-id)
   so the consume-once check is well-defined. QRL binds slot+epoch already.
4. **Transport integrity (optional):** not required for safety (binding catches tampering at verify time), but a
   transport MAC/TLS reduces wasted work from injected garbage. Confidentiality is *not* required.

## Net

Fronts 1–3 are **closed by the scheme** (credential theft, decision-faking, impersonation, replay), evidenced by
machine-checked proofs (EUF/SUF/QROM, rogue-key, root-safety, non-equivocation) and falsifiable tests
(`construction_offset_mitm_replay_test.go`, `byzantine_test.go`). The only items left to the deployment are the
universal application-layer ones (WYSIWYS, anti-DoS, unique decision id) — none of which any signature scheme can
close on its own.
