# ML-ADSA — Optimization & Constant-Time Posture

Companion to the benchmarks (`docs/33`) and spec §9.4. Covers (1) the optimization pass already applied
(real, measured, byte-identical), (2) the constant-time posture and what is/isn't hardened, and (3) the
AVX2 NTT path — with an honest statement of why the assembly kernels are *designed here but not shipped
untested*.

---

## 1. Optimization pass (applied, byte-identical)

All output is **byte-identical** to before (every KAT in `kat_test.go` unchanged; both the canonical
`go-mladsa/` reference and the vendored `qrysm/mladsa/` copy were updated identically).

1. **Branchless constant-time reduction.** `modQ` replaced its `if r < 0 { r += Q }` branch with
   `r + ((r>>63)&Q)` (arithmetic-shift mask). `cabs` replaced `if x > Q/2` with a branchless select
   `(x &^ mask) | ((Q-x) & mask)`. Same canonical results; no secret-dependent branch.
2. **Fused allocation-free multiply-accumulate.** The matrix–vector products `A·y` (commitments) and
   `A·z` (combine) used `acc = padd(acc, pw(A[r][s], v[s]))`, allocating two `N`-length slices per term.
   These now call `pwacc(acc, A[r][s], v[s])` (`acc[i] = modQ(acc[i] + a[i]*b[i])`) in place. Because
   `modQ` is a ring homomorphism, `modQ(acc + a·b) == modQ(acc + (a·b mod Q))`, so the result is identical
   while two allocations per term disappear (the dominant cost — `docs/33`).

**Measured (Apple M5, reference Go):** ~30–45% fewer allocations/bytes, ~18–25% faster on the hot path;
AggregateF N=128 went 33.0→18.2 MB/op and 23.8→19.4 ms (`docs/33 §4b`).

**Further pure-Go headroom (not yet done):** in-place NTT (avoid the `make+copy` per `ntt`/`intt` call),
lazy reduction in the NTT butterfly (defer `modQ`, reduce once at the end), and a small-object pool for
the `N`-length scratch buffers. These are byte-identical-preserving and would primarily cut the residual
`ntt`/`intt`/`pw` allocations.

---

## 2. Constant-time posture

ML-ADSA inherits ML-DSA's Fiat-Shamir-with-aborts structure. The honest classification:

| Operation | secret-dependent? | constant-time status |
|---|---|---|
| `modQ`, `cabs` reductions | yes (on `s1,s2,z`) | **branchless / constant-time** (this pass) |
| `pwacc`, `pw`, `padd`, `psub`, NTT butterflies | data-flow only, no branch on value | constant-time (straight-line arithmetic) |
| `ContentKeyDerive`, `DeriveNonce` (PRF) | yes (master seed) | SHAKE is constant-time; no secret-dependent branch |
| response `z = y + c·s1` | yes | straight-line; constant-time |
| **rejection-sampling acceptance** (`‖z‖<γ1−β`, hint weight, `‖c·t0‖<γ2`) | yes | **inherently data-dependent** — the *number of attempts* leaks (this is true of ML-DSA itself and is accepted; it leaks attempt count, **not** the secret). The per-coefficient comparisons use the branchless `cabs`; the accept/reject decision is a loop count, standard for Dilithium. |
| `Verify`, `Decompose/HighBits/UseHint`, hint logic | public data at verify time | not security-relevant (public) |

So: the secret arithmetic path is straight-line and uses branchless reduction; the only data-dependent
timing is the rejection-loop attempt count, which is the standard, accepted Dilithium behavior and reveals
nothing about the key. A full automated constant-time verification (`dudect`/`ctgrind`/`valgrind`-based, or
a Jasmin/ct-checker pass) and a microarchitectural side-channel evaluation are standardization
deliverables (`docs/32` items #6/#7); this pass establishes the source-level posture and removes the
value-dependent branches in the reduction primitives.

A `mladsa_ct` build tag is **not** introduced because the branchless primitives are strictly better (same
result, no branch) and are therefore the unconditional default — there is no "fast but variable-time"
variant to gate against.

### 2a. Formal backing for the NTT's data-independence (machine-checked)

The NTT/INTT is the one piece of the secret hot path with non-trivial control flow (three nested loops),
so its constant-time property is now **machine-checked**, not merely argued. `formal/ml_adsa_ntt_imp.ec`
transcribes the Go inner loop as an EasyCrypt `proc` over a mutable array (`NTTimp.jl`), proved correct by
Hoare logic (`jl_correct`). The decisive fact is **manifest in the verified program text**:

- every **loop bound** (`len`, `start`, `j`) and the twiddle counter `k` is a function of the **loop
  counters only**;
- every **memory index** read or written (`a[j]`, `a[j+len]`, `zetas[k]`) is computed from those counters,
  **never** from a coefficient value `a[_]`;
- there is **no `if` on `a`** and **no `a`-indexed memory access** anywhere in the transform.

So for any two inputs of the same length the NTT's **control-flow trace and memory-access pattern are
identical** — constant-time *by construction*, and the EasyCrypt model exhibits exactly that structure (the
loop invariant quantifies over the data, but the program never branches on it). The twiddle schedule
`zetas[k] = ζ^brv8(k)` is a compile-time constant table (`ml_adsa_ntt_crt.ec : brv8_twiddle_rec`), so even
twiddle accesses are input-independent.

### 2b. Side-channel audit of the rest of the hot path (source-level)

No **secret**-dependent timing beyond the accepted Dilithium rejection-loop count:

- **`modQ` / `cabs`** — branchless (§1); secret-dependent *values*, data-independent *time*.
- **`DeriveNonce` (Construction B masks)** — `y[s][t] = u % (2σ+1) − σ` over a SHAKE stream, **no rejection
  loop**, modulo a public constant → constant-time (the mask, the only secret here, is produced in fixed
  time).
- **`SampleInBall`** — its rejection loop reads a SHAKE stream of the **public** challenge `c̃*`; timing
  depends only on public data.
- **`ExpandA` / `rejNTTPoly`** — rejection on the **public** seed `ρ`; public-data timing.
- **the combiner** (`Σ wᵢ`, `Σ tᵢ`, `Σ zᵢ`, hint construction, the abstain test `maxAbs(z*) ≥ γ1−β`,
  `construction_f.go:318`) — operates entirely on the **public aggregate**; its branches/`maxAbs`
  comparison are over public data.
- **deterministic nonce** — **no RNG draw at signing time**, so no RNG/entropy side channel; the residual
  concern is *fault* injection on the deterministic path (out of constant-time scope, `docs/36 §6.3`).

**Residual (honest):** (i) Construction **A**'s per-signer rejection has the standard ML-DSA
secret-dependent *attempt count* (leaks attempts, not the key); Construction **B**, used for scale, is
rejection-free; (ii) integer `%` by the constant `q` is constant-time on the target ISAs but not guaranteed
by the language — a hardened build would use Barrett/Montgomery (the Montgomery reduction is already
source-proved, `ml_adsa_montgomery.ec`); (iii) automated `dudect`/`ctgrind` measurement and a
microarchitectural evaluation remain standardization deliverables (`docs/32 §6/§7`). None is a
secret-revealing leak at the source level.

---

## 3. AVX2 NTT — design, and why it is not shipped here

The single largest remaining speedup for ML-DSA-class arithmetic is a vectorized NTT. The standard result
(CRYSTALS-Dilithium AVX2 reference, and Cloudflare CIRCL's optimized ML-DSA) is hand-tuned x86-64 AVX2
assembly: packed 32-bit lanes (`VPMULUDQ`/`VPADDD`/`VPSUBD`), Montgomery/Barrett reduction in-lane, and a
merged-layer Cooley-Tukey schedule, typically a **4–10× NTT speedup**.

**Why it is documented here but not committed as code:** this development host is **arm64 (Apple M5)**.
Hand-written AVX2 `.s` kernels cannot be assembled, run, or differentially tested on arm64 — and committing
unvalidated SIMD assembly into a cryptographic core would be exactly the kind of unverified artifact this
project refuses to ship. Correct, fuzz-checked AVX2 requires an x86-64 CI runner.

### Drop-in design (for x86-64 CI)

A clean, low-risk integration that preserves byte-identity and the existing tests:

1. **Seam:** factor the NTT/INTT and pointwise kernels behind an internal interface
   `nttKernel{ NTT(*[256]int64); INTT(*[256]int64); PWMulAcc(acc,a,b *[256]int64) }`, with the current
   pure-Go implementation as `genericKernel`.
2. **Dispatch by build tag:** `ntt_generic.go` (`//go:build !amd64 || mladsa_noasm`) → `genericKernel`;
   `ntt_amd64.go` (`//go:build amd64 && !mladsa_noasm`) → `avx2Kernel` (with a `cpuid` AVX2 check falling
   back to generic), calling `ntt_amd64.s`.
3. **Validation gate (mandatory before trusting it):** a differential test that runs both kernels on the
   same random inputs and asserts bit-equality, plus the full KAT suite under `-tags ''` (asm) and
   `-tags mladsa_noasm` (generic) — both must produce the *identical* pinned KAT digests. CI must run on an
   AVX2 x86-64 host.
4. **Alternative considered — wire CIRCL's NTT:** CIRCL's ML-DSA NTT lives in
   `github.com/cloudflare/circl/sign/mldsa/mldsa87/internal/` (an **internal** package: Montgomery int32,
   AVX2 `amd64.s` + arm64 `arm64.s`), so it is **not importable** from outside CIRCL without forking it —
   and its representation/convention differs from this reference's standard-domain int64 NTT, so it is not
   a transparent byte-identical drop-in either. (CIRCL is only a `go-mladsa` *test* dependency, for
   high-level signature cross-checks; it is not a `qrysm` dependency, and we are **not** adding one now.)
   So the CIRCL route is deferred — it would mean vendoring CIRCL internals + a domain-conversion shim,
   which is rearchitecting, not integration.

Until an x86-64 CI runner is available, the portable kernel (now allocation-optimized and branchless) is
the shipped path. The cleanest future option is hand-written AVX2 under the §3 dispatch + differential
KAT gate on x86 CI (option 1–3), not the CIRCL-internal route.

---

## 4. Reproduce

```
# byte-identity after optimization (KATs unchanged) + benchmarks
cd qrl-integration/ml-adsa/qrysm && go test ./mladsa/ -run 'KAT' -count=1
go test ./mladsa/ -run='^$' -bench=. -benchmem
cd ../../../../go-mladsa && go test ./...     # canonical reference, also optimized, also byte-identical
```
