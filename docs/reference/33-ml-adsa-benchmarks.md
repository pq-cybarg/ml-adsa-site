# ML-ADSA-87 — Benchmarks and Sizes

Companion to the specification (`docs/30`) and verification dossier (`docs/31`). All numbers below are
**measured** by `go test -bench` on the actual reference implementation — not estimates.

**Measurement conditions (honest).**
- Platform: Apple M5 (arm64), Go reference implementation in `qrl-integration/ml-adsa/qrysm/mladsa/`
  (byte-identical to the canonical `go-mladsa/`).
- Command: `go test ./mladsa/ -run='^$' -bench=. -benchmem` (default `benchtime`); deterministic KAT
  inputs (`bench_test.go` reuses `kat_test.go` conditions).
- This is the **reference** implementation: portable, **not** optimized, **not** yet constant-time
  hardened, and `AggregateF` includes Fiat-Shamir-with-aborts **rejection sampling**, so per-op timing has
  real variance (an optimized/AVX2/assembly + batched implementation would be substantially faster;
  `docs/32` item #6). Numbers are indicative of the algorithm's shape, not of a production-tuned build.

---

## 1. Primitive operations

| Operation | ns/op | ≈ time | B/op | allocs/op |
|---|---:|---:|---:|---:|
| `ExpandA(ρ)` (matrix expansion) | 166,835 | 0.167 ms | 121,664 | 177 |
| `ContentKeyDerive` (per-content key refresh, L1) | 101,076 | 0.101 ms | 203,937 | 147 |
| `MemberKeyGen` (registration keypair + PoP) | 807,869 | 0.81 ms | 920,402 | 589 |
| `Verify` (in-house, = FIPS-204 verify) | 433,461 | 0.43 ms | 356,668 | 318 |
| `Verify` (go-qrllib native ML-DSA-87) | 137,960 | 0.138 ms | 1,158 | 4 |

`MemberKeyGen` is a one-time, per-epoch-registration cost (it generates an ML-DSA registration keypair and
a proof-of-possession). `ContentKeyDerive` is the recurring per-content refresh.

## 2. Aggregation (`AggregateF`) by committee size N

Includes rejection sampling; the output is a **single** ML-DSA-87 signature regardless of N.

| N (signers) | ns/op | ≈ time | per-signer | B/op | allocs/op |
|---:|---:|---:|---:|---:|---:|
| 1 | 399,119 | 0.40 ms | 0.40 ms | 708,286 | 521 |
| 4 | 851,372 | 0.85 ms | 0.21 ms | 1,470,873 | 1,139 |
| 16 | 4,983,889 | 4.98 ms | 0.31 ms | 9,011,744 | 7,107 |
| 64 | 18,927,026 | 18.9 ms | 0.30 ms | 16,729,178 | 13,393 |
| 128 | 23,825,097 | 23.8 ms | 0.19 ms | 33,002,311 | 26,452 |

Aggregation is ≈ linear in N (one `A·y` and one response per signer, plus the shared combine), modulated by
rejection retries — hence the per-op variance and the not-perfectly-monotone per-signer column. Crucially
this is a **one-time combine per slot/content**, and in the decentralized deployment it is split across the
committee (each signer does its own `ContentParts`/`ContentResponse`; any party runs the public combine).

## 3. Verification cost is O(1) in N — the headline result

The verifier does **one** ML-DSA-87 verify against `pk*` regardless of how many signers aggregated:

| Scheme | bytes on the wire | verify cost |
|---|---:|---:|
| Per-attester signature **list** (naive PQ port) | N × 4627 (≤ 592,256 at N=128) | N verifies (O(N)) |
| **ML-ADSA aggregate** | **4627 (constant)** | **1 verify (~0.14–0.43 ms), O(1)** |

This is the BLS-like win: constant signature size and constant verification, independent of committee size.

## 4. Sizes

| Object | Size | Note |
|---|---:|---|
| Aggregate public key `pk*` | **2592 B** | a valid ML-DSA-87 public key (constant) |
| Aggregate signature `σ*` | **4627 B** | a valid ML-DSA-87 signature (constant, any N) |
| Aggregation bits | ⌈N/8⌉ + 1 B (≤ ~17 B at N=128) | already present upstream; identifies the signer set |
| Master secret seed | 32 B | the only long-term secret per signer |

### Compression vs the per-attester list

| Committee N | list size | ML-ADSA | reduction |
|---:|---:|---:|---:|
| 16 | 74,032 B | 4,627 B | 16× |
| 64 | 296,128 B | 4,627 B | 64× |
| 128 (max) | 592,256 B | 4,627 B | **128×** |

No needed information is lost: signer set = the public aggregation bits, key = Σ epoch-tree `tᵢ`, validity
= one FIPS-204 verify.

---

## 4b. After optimization pass (pure-Go, byte-identical, same machine)

The pure-Go arithmetic was optimized (branchless constant-time `modQ`/`cabs`; a fused allocation-free
multiply-accumulate `pwacc` replacing `padd(acc, pw(...))` in the `A·y`/`A·z` matrix products). Output is
**byte-identical** (all KATs unchanged). Measured deltas (Apple M5):

| Op | before | after | Δ allocs/op | Δ B/op |
|---|---:|---:|---:|---:|
| ContentKeyDerive | 0.101 ms | **0.077 ms** | 147 → 91 | 204 KB → 89 KB |
| AggregateF N=16 | 4.98 ms | **5.3 ms¹** | 7,107 → 5,202 | 9.0 MB → 5.1 MB |
| AggregateF N=64 | 18.9 ms | **15.8 ms** | 13,393 → 9,753 | 16.7 MB → 9.3 MB |
| AggregateF N=128 | 23.8 ms | **19.4 ms** | 26,452 → 19,228 | 33.0 MB → 18.2 MB |
| Verify (in-house) | 0.43 ms | **0.37 ms** | 318 → 262 | 357 KB → 242 KB |

¹ N=16 time is within rejection-sampling noise; allocations/bytes dropped ~30–45% across the board, which
is the durable win. Roughly **45% less memory traffic** and **~18–25% faster** on the hot path, byte-for-
byte identical output. Further gains (in-place NTT, lazy reduction, AVX2 asm) are in `docs/34`.

## 5. Reproduce

```
cd qrl-integration/ml-adsa/qrysm
go test ./mladsa/ -run='^$' -bench=. -benchmem            # all benchmarks above
```

Indicative production-tuning headroom (not yet done, `docs/32`): NTT/poly arithmetic in assembly/AVX2,
batched verification, allocation reduction (the reference allocates liberally), and a constant-time
hardened build. These would primarily speed up `AggregateF` (the rejection-sampling loop) and bring
in-house `Verify` toward the go-qrllib native figure.
