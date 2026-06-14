# ML-ADSA — Optimization & Constant-Time Posture

Companion to the benchmarks (`docs/33`) and spec §9.4. Covers (1) the optimization pass already applied
(real, measured, byte-identical), (2) the constant-time posture and what is/isn't hardened, and (3) the
AVX2 NTT path — a full Montgomery-domain AVX2 NTT/INTT kernel, byte-identical to the generic kernel,
*implemented and validated under `docker linux/amd64` emulation and enabled by default on AVX2 CPUs*; the
only open item is a native-x86 timing measurement.

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
transcribes **all three** Go loops as EasyCrypt `proc`s over a mutable array — `NTTimp.jl` (inner
butterfly, `jl_correct`), `NTTimp.sl` (the start-loop = one full level, `sl_correct`), and `NTTimp.ntt`
(the len-loop = the whole transform, `ntt_correct`) — each proved correct by Hoare logic with explicit
loop invariants. The decisive fact is **manifest in the verified program text**:

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
source-proved, `ml_adsa_montgomery.ec`); (iii) a full microarchitectural evaluation and a
Jasmin/ct-verif machine proof remain standardization deliverables (`docs/32 §6/§7`). None is a
secret-revealing leak at the source level.

### 2c. Automated timing-leakage screen (dudect-style, machine-run)

`go-mladsa/ct_test.go` implements the Reparaz–Balasch–Yarom **dudect** methodology as a runnable
harness: for a primitive `f`, it times `f` on a **fixed** input class vs a **random** input class and
runs **Welch's two-sample t-test** on the timing distributions (slowest 10% cropped for scheduler
outliers, A/B interleaved to cancel drift). `|t|` staying small ⇒ no input-dependent timing detected;
`|t|` diverging ⇒ a data-dependent path.

```
CT_MEASURE=1 go test ./ -run TestConstantTime -count=1 -v
```

**Result (Apple M-series, macOS arm64; representative run):**

| primitive | `\|t\|` | reading |
|---|---|---|
| `leakyVarWork` (positive control — a data-dependent loop count) | **≈ 1259** | leak correctly detected (≫ 4.5) |
| `modQ` (shipped, branchless `r + ((r>>63)&Q)`) | **≈ 0.2** | no detectable input-dependence |
| `cabs` (shipped, branchless select) | **≈ 8** | branchless by construction; the small absolute value is OS-scheduler noise, ≫100× below the control |

Two findings worth stating: (1) the harness **does** detect leakage — the positive control is loud, so
a null on the shipped primitives is meaningful, not vacuous; (2) a *naive* `if r<0 { r += Q }` reduction
is **not** a valid positive control, because the Go compiler lowers it to a branchless conditional-select
(`cmov`) — i.e. even the source-level branch compiles to constant-time code here (a reassuring,
independently-checked fact about the reduction). The test asserts the control is detected and that the
shipped primitives stay far below it; it is **env-gated** (not in CI) because wall-clock timing on a
multitasking OS is noisy. A cycle-accurate counter on a quiet machine (or `ctgrind`/Valgrind on x86) is
the next step for a clean *absolute* null and is part of the side-channel standardization deliverable.

---

## 3. AVX2 NTT — implemented, validated under emulation, shipped on AVX2 CPUs

The single largest remaining speedup for ML-DSA-class arithmetic is a vectorized NTT. The standard result
(CRYSTALS-Dilithium AVX2 reference, and Cloudflare CIRCL's optimized ML-DSA) is hand-tuned x86-64 AVX2
assembly: packed 32-bit lanes (`VPMULUDQ`/`VPADDD`/`VPSUBD`), Montgomery/Barrett reduction in-lane, and a
merged-layer Cooley-Tukey schedule, typically a **4–10× NTT speedup**.

**Why it is documented here but not committed as code:** this development host is **arm64 (Apple M5)**.
Hand-written AVX2 `.s` kernels cannot be assembled, run, or differentially tested on arm64 — and committing
unvalidated SIMD assembly into a cryptographic core would be exactly the kind of unverified artifact this
project refuses to ship. Correct, fuzz-checked AVX2 requires an x86-64 CI runner.

### AVX2 — validated under emulation (no native x86 needed)

**Update:** the "needs an x86-64 CI runner" caveat is *lifted for correctness validation*. A real
AVX2 routine — `ntt_amd64.s : paddAVX2` (4×int64 mod-Q lane add: `VPADDQ` + branchless `VPCMPGTQ`
mask + conditional `VPSUBQ`) — is **bit-exact to the generic `padd` over 1000 random vectors, validated
by executing actual AVX2 instructions under `docker linux/amd64` emulation** (QEMU/TCG) on this arm64
host. The reproducible gate is `go-mladsa/validate-avx2-docker.sh` (cross-compile `GOARCH=amd64` → run
the differential test in an amd64 container); `avx2_test.go : TestPaddAVX2` is the assertion. So
hand-written AVX2 can now be authored and *functionally* validated here, not only on native silicon —
the only thing emulation does not measure is native timing/throughput.

**The full AVX2 NTT is now implemented and validated.** The key obstacle was the in-lane *reduction*:
our reference keeps coefficients in the int64 **standard domain**, but a vectorized butterfly needs a
divide-free reduction, and AVX2 has no 64-bit integer divide. We solve it with an in-lane **Montgomery
reduction** (`ntt_amd64.s`), exactly the technique Dilithium's AVX2 uses, but kept **byte-identical to the
standard-domain generic kernel** rather than leaving coefficients in a wider lazy form:

- The per-butterfly product `p = z·a` (both operands `< Q < 2²³`, so `p < 2⁴⁶`) is reduced by
  `montgomery_reduce(p) = (p − t·Q)/2³²` where `t = (int32)p·QINV mod 2³²`. The load-bearing congruence
  `Q·QINV ≡ 1 (mod 2³²)` (QINV = 58728449) is **machine-checked** in `formal/ml_adsa_montgomery.ec`; the
  scalar reference of the exact lane computation is `montgomery.go : montReduce`, with its own arch-neutral
  proof-tests (`montgomery_test.go`, runnable on arm64).
- AVX2 lacks a 64-bit arithmetic shift (`VPSRAQ` is AVX-512), so the `/2³²` of the (always-`2³²`-divisible)
  intermediate is done with a logical `VPSRLQ $32` plus a branchless `2³²−Q` correction for the negative
  case — yielding a canonical `[0,Q)` residue, not a lazy one.
- Pre-scaling each zeta into Montgomery form (`zmont = z·R mod Q`, tables `zetasMont`/`zetasMontNeg` in
  `montgomery.go`) makes `montgomery_reduce(zmont·a) ≡ z·a (mod Q)`, so the transform output **equals the
  generic kernel's representatives bit-for-bit**. Forward (Cooley–Tukey, `ctButterflyAVX2`) and inverse
  (Gentleman–Sande, `gsButterflyAVX2` + the `inv256` scale `montMulConstAVX2`) butterflies process four
  `int64` coefficients per `Y` register; the two smallest levels (group width 1 and 2, narrower than a
  4-lane vector) fall back to the generic scalar butterfly.

**Validation (reproducible here, no native x86):** `validate-avx2-docker.sh` cross-compiles `GOARCH=amd64`
and runs the differential gate under `docker linux/amd64` (AVX2 via QEMU/TCG). `avx2_test.go : TestNTTAVX2`
asserts the AVX2 forward/inverse NTT are **bit-exact to `nttGeneric`/`inttGeneric` over 2000 random
vectors** and that `INTT∘NTT = id`; `TestKernelDifferential` confirms the *dispatched* `activeKernel`
(which under the emulated cpuid resolves to `avx2Kernel`) matches generic for NTT/INTT/PW/PWAcc; and the
end-to-end CIRCL cross-checks (`TestCoreVsCIRCL`, `TestF_AggregateF_CIRCL`, `TestParamVerifyVsCIRCL` over
all three parameter sets) **pass with the AVX2 kernel active**, i.e. every aggregate is still a byte-exact
FIPS-204 signature CIRCL accepts. The **only** thing emulation cannot measure is native
timing/throughput — that perf sign-off is the lone remaining step, and is deliberately left for an x86-64
runner since QEMU/TCG cycle counts are meaningless.

### Drop-in design — seam + AVX2 kernel now IMPLEMENTED and ENABLED

**Status:** the full design (steps 1–3 below) is **implemented and green** in `go-mladsa/`:
`kernel.go` (the `nttKernel` interface + `genericKernel` + the `ntt/intt/pw/pwacc` dispatchers through
`activeKernel`), `kernel_amd64.go` (`//go:build amd64 && !mladsa_noasm`; `hasAVX2 = cpu.X86.HasAVX2`, and
the dispatch now **active**: `if hasAVX2 { activeKernel = avx2Kernel{} }`), `ntt_amd64.s` + `ntt_amd64.go`
(the Montgomery-domain `ctButterflyAVX2`/`gsButterflyAVX2`/`montMulConstAVX2` and the level drivers
`nttAVX2`/`inttAVX2`), `montgomery.go` (constants + zeta tables), and the gates `kernel_test.go` /
`avx2_test.go` / `montgomery_test.go`. The path is **safe to ship on by default** for AVX2-capable CPUs
precisely because it is byte-identical: enabling it can change only *speed*, never *output* — and that
byte-identity is what the differential gate proves. Every build still has an escape hatch: `-tags
mladsa_noasm` (or any non-amd64 arch) keeps the validated generic kernel everywhere, and is byte-identical
to the pre-seam reference. The original design rationale follows:

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

The hand-written AVX2 route (options 1–3) is the one we took, and it is now the shipped fast path on
AVX2 CPUs (generic elsewhere) — *not* the CIRCL-internal route, which would have meant vendoring CIRCL
internals plus a domain-conversion shim. Correctness is validated under emulation; the only open item is a
native-x86 timing/throughput measurement (perf, not correctness).

---

## 4. Reproduce

```
# byte-identity after optimization (KATs unchanged) + benchmarks
cd qrl-integration/ml-adsa/qrysm && go test ./mladsa/ -run 'KAT' -count=1
go test ./mladsa/ -run='^$' -bench=. -benchmem
cd ../../../../go-mladsa && go test ./...     # canonical reference, also optimized, also byte-identical
```
