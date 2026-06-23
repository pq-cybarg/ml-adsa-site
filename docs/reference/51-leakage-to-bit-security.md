# Leakage risk to bit security — what the AGGREGATION PROCESS exposes, and why it doesn't drop below ML-DSA-87

**The right question (not "the output is byte-exact").** A standalone ML-DSA signing reveals only `(c̃, z, h)`.
The F-OFFSET *aggregation process* reveals MORE, every cycle: per-signer commitment-derived data, the offset
broadcast, the per-signer response, the aggregate key. This document enumerates **every** channel the process
exposes beyond a bare signature, gives the bit-security of exploiting each (and all together, across unlimited
cycles), and states what is machine-checked vs measured vs named. Baseline = ML-DSA-87 (267 gate-count / 252
core-SVP classical; ~243/229 quantum — see docs/50).

## 1. The leakage register

| # | Channel exposed by the process (not by a bare ML-DSA sig) | Hardness of exploiting it | Evidence | ≥ native? |
|---|---|---|---|---|
| L1 | **Offset broadcast** `(hiᵢ=HighBits(wᵢ), qᵢ=LowBits(wᵢ)+rᵢ)` — recover `s1ᵢ` from `b=M·s1+e` (`e~±R`) | offset LWE | F8/F10; Sage #110 = **455–489** (dual+hybrid) ≫ native | **yes (≫)** |
| L2 | **Per-signer / aggregate response** `z=c·s1+y` — single-hint recovery | hint LWE at σ=3β | F12e; estimator99 **387**; **Sage-confirmed 387.2** ≥ native 267 | **yes** |
| L3 | **Aggregate key** `pk*=Σtᵢ` — MLWE on `s1*=Σs1ᵢ` (larger secret) | aggregate MLWE | estimator **352** (nc=64) > native | **yes (>)** |
| L4 | **Combined view**: attacker holds native `tᵢ` + offset `bᵢ` + response `zᵢ` on the SAME `s1ᵢ` | combined LWE | F12f: = native worst case (noise-flooding reduction) | **= native** |
| L5 | **Worst-case (full-w / no hiding)**: full `wᵢ` ⇒ nonce `yᵢ` by linear algebra (tall A) ⇒ `s1ᵢ` with `zᵢ` | whole one-time key leaks | **modelled directly** by the deployed key-leak proof (F20) | n/a (see §2) |
| L6 | **Cross-cycle accumulation**: every cycle leaks its per-content key; does it compound to the ROOT? | PRF refresh | **#129 `ml_adsa_F_rootsafe.ec`**: root recovery ≤ `adv_prf + p_coll`, **Q-INDEPENDENT** | **yes** |
| L7 | **Deterministic-nonce reuse** `s1=(z−z′)/(c−c′)` | forbidden by construction | `ml_adsa_F_nonce` (`reuse_iff_collision`): one-time + content-bound `c` + PRF nonce ⇒ no collision | σ-indep |
| L8 | hint `h*`, part-root, Merkle/provenance data | public, no secret | standard ML-DSA + Merkle | no secret |

## 2. The unifying argument: the deployed key-leak model is a conservative UPPER BOUND on all of L1–L6

Rather than argue each channel leaks "a little," the deployed proof (`ml_adsa_F_open.ec`: `deployed_open_uncond`,
F20) assumes the **worst case — the entire per-content one-time key leaks every cycle** (L5 dominates L1–L4,
since revealing the nonce/key is strictly more than revealing the offset). It then proves:

1. **Per-content / per-cycle:** the forgery target is an **un-queried** content whose key is fresh and never
   exposed ⇒ a clean ML-DSA-87 instance ⇒ **native bit security** (`konly_uncond`, F22; machine-checked,
   masking-free, σ-independent).
2. **Confinement:** the refresh firewall (`adv_prf`) keeps every leak confined to the **spent** one-time key whose
   job is already done; it tells nothing about other/future content keys.
3. **Across unlimited cycles:** the **root/base-wallet key is unrecoverable** from the leakage of *any* number of
   cycles — `root_key_safety`: advantage ≤ `adv_prf + p_coll`, **with no #-cycles factor** (#129, this session).
   The only cross-cycle dependence anywhere is the mild, self-reducible multi-instance factor (docs/50).

So `Pr[forge or recover a live/future/root key] ≤ adv_prf + Q·(adv_mlwe + STMSIS)` — every term at **native**
ML-DSA-87 level, and **independent of the nonce width and of how many aggregation cycles ran**. F-OFFSET's actual
hiding (offset masks the nonce) means the real leakage is **strictly less** than this worst case, so it is covered
a fortiori; and L1–L4 confirm even the *spent*-key recovery is itself ≥ native (estimator).

## 3. Bottom line on bit security

- **Forging a fresh decision, or recovering any live/future/root key, stays at ML-DSA-87 (Cat-5): 267 gate / 252
  core-SVP classical, ~243/229 quantum** — *despite* the full aggregation-process exposure, and *for unlimited
  cycles*. This is not "because the output is byte-exact"; it is because (a) every extra channel is independently
  ≥ native (L1–L4, measured), and (b) the worst-case key-leak model + refresh firewall + root-safety (machine-
  checked) bound the *combined, multi-cycle* exposure to native + `adv_prf`.
- **What an attacker CAN get:** a *spent* one-time content key (already revealed by design; one-time ⇒ re-signing
  the already-agreed decision is a no-op), and only at ≥ native cost. Nothing about fresh content, future keys, or
  the base-wallet root.

## 4. Honest residuals

1. The blind-guess term in #129 (`ideal_root_blind`) is a **named entropy primitive** (= max mass of a fresh key,
   `dkey_coll`), not byphoare-discharged — like `mlwe_assumption`/`dkey_coll` elsewhere. The *reduction* (root ⇒
   PRF, Q-independent) is machine-checked.
2. Estimator absolute numbers are model-dependent (core-SVP vs gate-count, docs/50 §2); the **≥-native comparisons
   and Q-independence are the robust reads**.
3. Side-channel/implementation leakage (timing) is out of scope of this *information* leakage analysis; the default
   nonce path is constant-time (PRF `DeriveNonce`), see docs/49 §4.
