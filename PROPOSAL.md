# XelisHash V4 Proposal — GPU/CPU Equalization

**Author:** ocminer (admin@suprnova.cc)
**Date:** 2026-03-22
**Status:** Proposal for review by Xelis core team

---

## Motivation

I run Suprnova mining pools and have spent the last couple of months optimizing
XelisHashV3 for GPU mining (both GDDR7 and HBM2 cards). During that work I
noticed something that I think deserves attention: HBM2 cards like the CMP 170HX
get a disproportionate advantage over GDDR cards like the RTX 5090, simply
because V3's stage 3 is almost entirely memory-latency bound. The ALU work per
iteration is so light that the GPU just hides it all behind warp scheduling.

That got me thinking about whether V3 could be hardened to level the playing
field — not just between memory types, but between CPUs and GPUs in general.
A 32-core Threadripper should be able to compete with a high-end GPU if the
algorithm is designed right.

After a fair amount of experimentation (and a few dead ends) I arrived at a
design that I'm calling "V4" here. It's a minimal, surgical change to V3's
stage 3 that keeps all the existing memory-hardness properties intact while
adding two mechanisms that cap GPU throughput without hurting CPUs much.

## What V4 Changes (and What It Doesn't)

**Unchanged:**
- Stage 1 (ChaCha8 scratchpad fill) — identical to V3
- Stage 4 (Blake3 finalization) — identical to V3
- Scratchpad size (544 KB), inner iteration count (33,984 x 2), all 16 branch
  operations, the random RMW pattern — all unchanged

**Added to stage 3, per inner iteration:**
1. A 2 KB lookup table ("S-box") that lives in shared memory on GPU, L1 cache
   on CPU. One lookup per iteration, one entry updated per iteration (so it
   evolves and can't be precomputed or shared between threads).
2. A chain of 16 dependent 64-bit multiplies that feeds into the index derivation.
   Each multiply depends on the previous one — can't be pipelined or parallelized.

That's it. No new hash functions, no new memory structures, no parameter
changes to the scratchpad. The diff against V3's stage_3 is about 30 lines.

## Why It Works

The S-box is the key. On a GPU, 2 KB per thread in shared memory means the SM
can only fit ~2 warps (64 threads) instead of the 16-40+ warps V3 allows. With
only 2 warps, the GPU can't hide memory latency by switching between them — it
just stalls. On a CPU, 2 KB fits trivially in L1 cache and costs ~4 cycles to
access. No impact.

The multiply chain adds a hard latency floor. Each 64-bit multiply is ~3 cycles
on x86 (single IMUL instruction) but 5-6 cycles on GPU (MUL.WIDE.U32 through
the integer pipe). With 16 chained multiplies, that's ~48 cycles on CPU vs ~80-96
on GPU — but the real cost on GPU is that those 80 cycles can't overlap with
anything because there are only 2 warps to schedule.

My first attempt was a Salsa20/8 barrier (400 ALU ops) without the S-box. It
was completely invisible on GPU (1.6% overhead) because the warps just absorbed
it in idle ALU slots. Lesson learned: you have to starve the SM of warps first,
then the compute starts to matter.

## Benchmark Results

All benchmarks run with random input data to prevent cache effects.

### GPU — Stage 3 Only (standalone CUDA kernel, random scratchpads)

| GPU | V3 | V4 | Slowdown | Per-SM |
|-----|----|----|----------|--------|
| RTX 5090 (GDDR7, 170 SMs) | 27.0 kH/s | 11.7 kH/s | 2.31x | 68.8 H/s |
| CMP 170HX (HBM2, 70 SMs) | 4.42 kH/s | 4.16 kH/s | 1.06x | 59.4 H/s |

**Per-SM equalization: 68.8 / 59.4 = 1.15x** — the HBM2 advantage is gone.
The remaining 15% is clock speed and arch differences, not memory bandwidth.

### CPU — Full Hash (Rust, random inputs)

| Configuration | V3 | V4 | Slowdown |
|---------------|----|----|----------|
| TR 3970X, 1 core | 575 H/s | 294 H/s | 1.95x |
| TR 3970X, 32 cores | — | 7,306 H/s | — |
| TR 3970X, 64 threads (SMT) | — | 9,697 H/s | — |

### The Bottom Line

| Hardware | V4 Hashrate | vs RTX 5090 |
|----------|-------------|-------------|
| RTX 5090 | 11,700 H/s | 1.00x |
| TR 3970X (64T) | 9,697 H/s | 0.83x |
| TR 7970X (est.) | ~13,500 H/s | **1.16x (CPU wins)** |

A current-gen 32-core Threadripper is in the same ballpark as a top-end GPU.
That's the goal.

### MUL_CHAIN_LEN Sweep (for tuning)

| Chain | GPU kH/s | CPU H/s (1 core) | GPU/CPU-32c |
|-------|----------|-------------------|-------------|
| 16 | 11.6 | 296 | 1.2x |
| 32 | 11.3 | 198 | 1.8x |
| 64 | 10.6 | 118 | 2.8x |
| 128 | 9.6 | 68 | 4.4x |

16 is the sweet spot. Higher values hurt CPU disproportionately because the
multiply chain is strictly serial and CPUs can't parallelize across hashes
the way GPUs do.

## Security Properties

- **Memory-hardness**: Unchanged. Same 544 KB scratchpad, same random access
  pattern, same iteration count.
- **Serial dependency**: Strengthened. The multiply chain output feeds into
  idx_seed, which determines the next iteration's memory addresses. You can't
  skip it.
- **S-box evolution**: The S-box changes every iteration (`sbox[idx] ^= chain`),
  preventing precomputation or sharing between GPU threads. After 33,984
  iterations each of the 256 entries has been XOR'd ~133 times on average.
- **Avalanche**: Tested — flipping 1 input bit changes ~48% of output bits.
- **No new primitives**: Uses only operations already present in V3 (multiply,
  rotate, XOR). The S-box is just a lookup table initialized from scratchpad
  data.

## Files

- `src/v4.rs` — the V4 implementation (drop-in alongside v1/v2/v3)
- `PROPOSAL.md` — this document
- `benches/v4.rs` — criterion benchmark (same structure as v3 bench)

The implementation follows the exact same patterns as v3.rs — same function
signatures, same ScratchPad type, same error handling, same tracker support.
It should slot into the existing crate with a `v4 = ["v2"]` feature flag.

## How to Test

```bash
# add v4 feature to Cargo.toml: v4 = ["v2"]
# add pub mod v4; to lib.rs (gated on feature = "v4")

cargo test --features v4
cargo bench --features v4 --bench v4
```

## What I'm Asking

I'd like the Xelis team to consider this as a candidate for a future hard fork.
The numbers speak for themselves — V3 currently gives HBM2 cards a ~2x per-SM
advantage and GPUs a ~47x advantage over single-core CPU. V4 brings those down
to 1.15x and ~1.2x respectively, with a Threadripper matching or beating an
RTX 5090.

The change is intentionally minimal. I didn't want to redesign the algorithm,
just add the smallest possible tweak that fixes the GPU/CPU imbalance. The S-box
and multiply chain are well-understood constructions — nothing exotic.

Happy to discuss parameter choices, run more benchmarks, or iterate on the
design. I'm reachable at admin@suprnova.cc or on the Xelis Discord.

Cheers,
ocminer
