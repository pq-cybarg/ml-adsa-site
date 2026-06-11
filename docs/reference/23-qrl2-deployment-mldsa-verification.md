# 23 — QRL 2.0 Deployment: QRVM / Hyperion and ML-DSA-87 Verification Integration

Research record (compiled 2026-06-07) of how the deployment target, **QRL 2.0 ("Zond")**, is
architected and how an ML-ADSA aggregate — a byte-exact ML-DSA-87 signature — is verified on-chain.
This documents what is **confirmed by public sources**, what is **not yet pinned**, and the concrete
**integration items** to settle before deployment. Honest labels throughout: **[confirmed]** (QRL
or standards sources), **[unconfirmed]** (not found in public sources), **[implication]** (follows
from ML-ADSA's design).

> Methodology: web research over QRL's official sites (theqrl.org, qrlhub.com), the Ethereum EIP
> registry, and the `theQRL/go-zond` source. Sources listed in §6. This is a moving target (QRL 2.0
> Testnet V2 launched 2026-03-31); re-verify against `zond-docs.theqrl.org` and the current
> `go-zond` branch before relying on the unconfirmed items.

---

## 1. Correction: QRVM is an EVM fork (EVM-compatible)

**[confirmed]** QRL 2.0's VM, the **QRVM** (Quantum Resistant Virtual Machine), is *"an EVM-friendly
VM **forked from the EVM**"* (QRL's own wording). It is **not** a non-EVM bespoke design — it is a
customized, post-quantum EVM fork. Corollary corrections to earlier project notes:

- "QRL is not EVM based" — **inaccurate**. QRL 2.0 *is* EVM-compatible (an EVM fork). The accurate
  framing is "a bespoke, **Ethereum-based** (EVM-forked) post-quantum VM," which is consistent with
  the original intent, just not with the literal "not EVM" phrasing.
- **Hyperion** is QRL's **Solidity-derived** smart-contract language — *"most valid Solidity is valid
  Hyperion"* — extended with post-quantum primitives. It requires QRL's Hyperion compiler.
- Other QRVM deltas vs stock EVM: **modified opcode logic**, an **address format in flux** (a
  **64-byte address** change is **underway and incomplete** per the project, with a crypto
  **descriptor** model — earlier public mentions of a 24-byte/"Q"-prefixed form are transitional),
  PQ-aware tooling.

**Naming (user, 2026-06):** QRL renamed **"Zond" → "QRL 2.0"**; the execution client **`go-zond` is
now `go-qrl`** (GitHub redirects the old path), and other `zond`-named things are renamed or in
progress — e.g. the precompile map is still literally `PrecompiledContractsZond` in `go-qrl` code.
An isolated working area with pristine + modifiable clones of the relevant repos is set up under
`../qrl-integration/` (see its README).

(Unrelated naming collision: the **Gobra** code-level verifier (docs/22) is from **ETH Zürich**, the
university — nothing to do with Ethereum/QRVM, and it introduces no chain dependency.)

---

## 2. Where ML-DSA-87 lives in QRL 2.0

| layer | status | detail |
|---|---|---|
| Protocol / account signatures | **[confirmed]** | ML-DSA-87 (NIST Level 5) integrated across `go-qrllib`, `go-zond`, `qrysm`, deposit contracts; key-gen/sign verified against NIST ACVP vectors; FIPS-204 deterministic mode via `SignDeterministic(ctx,msg)`. Every transaction is natively ML-DSA-87-signed. |
| Smart-contract verification | **[confirmed ABSENT in public `main` — it is integration work to add]** | Verified by reading the cloned source (2026-06-07): `go-qrl/core/vm/contracts.go` has **no** ML-DSA precompile (set = `{0x01 depositroot, 0x02 sha256, 0x04 dataCopy, 0x05 bigModExp}`), and `hyperion` builtins are only `keccak256/sha256/blockhash/...` (**no ML-DSA verify builtin**). QRL's public "Hyperion natively verifies lattice signatures" statements are **ahead of the public `main` code**. So enabling contract-level (aggregate) verification = adding a go-qrl precompile + a Hyperion builtin (see `../qrl-integration/README.md`). |

---

## 3. The verification-mechanism question (precompile / opcode / builtin)

What the evidence says, precisely:

- **[confirmed]** Contract-level ML-DSA-87 verification is intended and delivered via **Hyperion
  compiler support** for lattice primitives, with **modified opcode logic** in the QRVM.
- **[confirmed by source read]** `theQRL/go-qrl` (formerly go-zond) `main` `core/vm/contracts.go`
  precompile set (`PrecompiledContractsZond`) is **only** `0x01` depositroot, `0x02` sha256, `0x04`
  dataCopy, `0x05` bigModExp — **no ML-DSA / XMSS precompile**. Account-level ML-DSA verify exists at
  `go-qrl/crypto/pqcrypto/crypto.go`: `MLDSA87VerifySignature(sig,msg,pk) → walletmldsa87.Verify(msg,
  sig,&pk,desc)` (with an address **descriptor**), backed by `go-qrllib/crypto/ml_dsa_87` (the
  canonical ML-DSA-87: K=8, L=7, ctx-param Verify) — i.e. verification is wired for **transactions**,
  not exposed to **contracts**. `hyperion` builtins (`libhyperion/ast/Types.cpp`) are keccak/sha256
  only. So contract-level verify is **not present in `main`** and is the integration work to add.
- **[confirmed]** Ethereum **EIP-8051** *does* standardize an ML-DSA verification **precompile**:
  addresses `0x12` (NIST/SHAKE256) and `0x13` (Keccak-PRNG, EVM-optimized), **4500 gas** each. But it
  covers **only ML-DSA-44 (NIST Level II)** — `k=l=4` — **not ML-DSA-65/87** — and uses a
  **pre-expanded** public key (`A_hat ‖ tr ‖ t1` ≈ 20512 B), input `message(32) ‖ sig(2420) ‖
  pk(20512)`, output 32-byte `1`/`0`. QRL may or may not adopt an EIP-8051-style precompile; if it
  does, an **ML-DSA-87 variant** would be required.
- **[unconfirmed]** Whether QRL 2.0 exposes ML-DSA-**87** contract verification as a precompile (and
  at which address), a dedicated opcode, or a Hyperion intrinsic — and the exact `pk`/`sig` byte
  encoding it expects. To be resolved from `zond-docs.theqrl.org`, the `go-zond` **testnet-v2** branch,
  or the Hyperion compiler repo.

---

## 4. Implication for ML-ADSA (why deployment is structurally clean)

**[implication]** An ML-ADSA aggregate **is** a byte-exact ML-DSA-87 signature: `pk* = (ρ, t1*)`
**2592 B**, `σ* = (c̃*, z*, h*)` **4627 B**, verified by the **unmodified FIPS-204 verifier** (docs/20,
docs/21 §4). Therefore:

- **Verification** uses **whatever ML-DSA-87 verify primitive Hyperion/QRVM exposes** — opcode,
  builtin, or precompile — **unchanged**. There is no custom verifier and no new cryptographic
  assumption on-chain; an aggregate is indistinguishable from an ordinary ML-DSA-87 signature to the
  verifier.
- **Decision / provenance / tally logic** (registry `REG`, `part_root`, `reg_root`, k-of-n thresholds,
  option-subset selection, approval sets, homomorphic tallies, optimistic provenance + fraud `Audit`)
  is **ordinary Hyperion contract logic** over plain bytes + Merkle roots — and since most Solidity is
  valid Hyperion, it ports directly.

---

## 5. Deployment integration checklist (to confirm before mainnet)

```
[ ] (P1) Contract-level verify primitive is ML-DSA-87 (Level 5), NOT ML-DSA-44 (EIP-8051 default).
[ ] (P2) Exposure mechanism identified: precompile address | new opcode | Hyperion builtin.
[ ] (P3) Expected pk/sig ENCODING:
         - standard FIPS-204 pk* = 2592 B, sig* = 4627 B  -> ML-ADSA output is directly consumable;
         - EIP-8051-style PRE-EXPANDED pk (A_hat‖tr‖t1 ≈ 20512 B) -> re-encode pk* before the call.
[ ] (P4) Gas/limits for an ML-DSA-87 verify call (EIP-8051 quotes 4500 gas for ML-DSA-44; 87 differs).
[ ] (P5) Merkle/registry data availability path (calldata vs storage) for ProvenanceVerify/Audit.
[ ] (P6) Domain/ctx framing (lenPrefixed, "QRL"‖C) matches the on-chain message the verify primitive
         hashes (FIPS-204 mu = H(H(pk)‖ctxframe‖msg)); confirm ctx handling in the QRVM verify path.
```

Open action: pull the `go-zond` **testnet-v2** branch precompile/opcode set and the **Hyperion**
ML-DSA verify builtin signature to close P1–P4 with source certainty.

---

## 6. Sources

- QRL 2.0 / Zond overview — https://qrlhub.com/en/zond  (QRVM = "EVM-friendly VM forked from the EVM")
- QRL 2.0 — https://www.theqrl.org/2/  ("ML-DSA-87 (Dilithium) for signatures, targeting NIST Level 5")
- Zond public devnet pre-release — https://www.theqrl.org/blog/zond-public-devnet-prerelease/
- QRL Testnet V2 press (Hyperion lattice primitives, EVM-friendly) — https://www.theqrl.org/press/qrl-launches-testnet-v2-for-its-postquantum-evmfriendly-blockchain/
- EIP-8051: Precompile for ML-DSA signature verification — https://eips.ethereum.org/EIPS/eip-8051  (0x12/0x13, 4500 gas, **ML-DSA-44 only**, pre-expanded pk)
- theQRL/go-zond (precompile set in `core/vm/contracts.go`) — https://github.com/theQRL/go-zond
- theQRL/go-qrllib — https://github.com/theQRL/go-qrllib
- (to consult) zond-docs — https://zond-docs.theqrl.org/

> Re-verify the **[unconfirmed]** items (§3, §5 P1–P4) against the live `zond-docs` and the current
> `go-zond` testnet-v2 branch; QRL 2.0 is under active development and the contract-level ML-DSA
> verification surface may change between testnet and mainnet.
