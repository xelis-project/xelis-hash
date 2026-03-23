use aes::cipher::generic_array::GenericArray;
use crate::{v2, Error, Hash, scratchpad::ScratchPad as ScratchPadInternal};

#[cfg(feature = "tracker")]
use crate::tracker::*;

// Same scratchpad geometry as V3
const MEMORY_SIZE: usize = 531 * 128;
const MEMORY_SIZE_BYTES: usize = MEMORY_SIZE * 8;
const SCRATCHPAD_ITERS: usize = 2;
const BUFFER_SIZE: usize = MEMORY_SIZE / 2;

const KEY: [u8; 16] = *b"xelishash-pow-v4";

// V4 parameters -- these control the GPU occupancy cap and compute weight.
// SBOX_ENTRIES: 256 entries x 8 bytes = 2 KB per thread.
// On a GPU this lives in shared memory (fast but limited per SM), which caps
// the number of resident warps to ~2 per SM. On CPU it just sits in L1.
const SBOX_ENTRIES: usize = 256;

// 8 persistent state words that feed into the multiply chain each iteration.
// They evolve over the inner loop so the chain inputs are never static.
const STATE_WORDS: usize = 8;

// How many dependent multiply-accumulate steps per inner iteration.
// Each mul64 is ~3 cycles on x86 but ~5-6 on GPU (MUL.WIDE.U32).
// 16 is the sweet spot where a 32-core Threadripper roughly matches
// an RTX 5090, while keeping single-core overhead tolerable (~1.9x vs V3).
const MUL_CHAIN_LEN: usize = 16;

pub type ScratchPad = ScratchPadInternal<MEMORY_SIZE>;

// -- helpers (same as v3) --

#[inline]
const fn murmurhash3(mut seed: u64) -> u64 {
    seed ^= seed >> 55;
    seed = seed.wrapping_mul(0xff51afd7ed558ccd);
    seed ^= seed >> 32;
    seed = seed.wrapping_mul(0xc4ceb9fe1a85ec53);
    seed ^= seed >> 15;
    seed
}

#[inline(always)]
pub fn map_index(mut x: u64) -> usize {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    ((x as u128) * (BUFFER_SIZE as u128) >> 64) as usize
}

#[inline(always)]
pub fn pick_half(seed: u64) -> bool {
    (murmurhash3(seed) & (1u64 << 58)) != 0
}

#[inline(always)]
pub fn isqrt(n: u64) -> u64 {
    if n < 2 { return n; }
    let approx = (n as f64).sqrt() as u64;
    if approx * approx > n {
        approx - 1
    } else if (approx + 1) * (approx + 1) <= n {
        approx + 1
    } else {
        approx
    }
}

const fn modular_power(mut base: u64, mut exp: u64, mod_: u64) -> u64 {
    let mut result: u64 = 1;
    base %= mod_;
    while exp > 0 {
        if exp & 1 == 1 {
            result = ((result as u128 * base as u128) % mod_ as u128) as u64;
        }
        base = ((base as u128 * base as u128) % mod_ as u128) as u64;
        exp /= 2;
    }
    result
}

// -- V4-specific: serial multiply chain --
//
// 16 dependent 64-bit multiplies where each result feeds into the next.
// The mixing operands rotate through (si, sj, result, sbox_val, a) with
// varying bit rotations so the compiler can't fold anything at compile time.
// On GPU this creates a hard latency floor (MUL.WIDE.U32 is 5-6 cycle
// latency, and with only 2 warps per SM there's nothing to interleave).
// On CPU the pipelined IMUL makes it much cheaper per step.
#[inline(always)]
fn mul_chain(v: u64, sbox_val: u64, si: u64, sj: u64, result: u64, a: u64) -> u64 {
    let mix_ops: [u64; 5] = [si, sj, result, sbox_val, a];
    let mut chain = v ^ sbox_val;
    let mut m = 0;
    while m < MUL_CHAIN_LEN {
        let operand = mix_ops[m % 5];
        let rot = ((m * 7 + 3) & 63) as u32;
        chain = chain.wrapping_mul((operand ^ chain.rotate_left(rot)) | 1);
        m += 1;
    }
    chain
}

// -- stage 3 (V4) --
//
// Keeps the full V3 memory access pattern (random reads from both halves
// of the 544 KB scratchpad, sequential walk of c, random RMW at the end)
// and adds an S-box lookup + multiply chain between the branch computation
// and the index derivation. The chain output feeds into idx_seed, so it's
// part of the serial dependency -- can't be skipped or overlapped.

pub(crate) fn stage_3(scratch_pad: &mut [u64; MEMORY_SIZE], #[cfg(feature = "tracker")] tracker: &mut OpsTracker) -> Result<(), Error> {
    let key = GenericArray::from(KEY);
    let mut block = GenericArray::from([0u8; 16]);

    let (mem_buffer_a, mem_buffer_b) = scratch_pad.as_mut_slice().split_at_mut(BUFFER_SIZE);

    // init S-box from scratchpad -- XOR with a constant so it's not a plain copy
    let mut sbox = [0u64; SBOX_ENTRIES];
    for k in 0..SBOX_ENTRIES {
        sbox[k] = mem_buffer_a[k] ^ (0xA5A5A5A5A5A5A5A5u64.wrapping_add(k as u64));
    }

    // persistent state -- evolves every iteration, feeds the multiply chain
    let mut state = [0u64; STATE_WORDS];
    for k in 0..STATE_WORDS {
        state[k] = mem_buffer_a[SBOX_ENTRIES + k];
    }

    let mut addr_a = mem_buffer_b[BUFFER_SIZE - 1];
    let mut addr_b = mem_buffer_a[BUFFER_SIZE - 1] >> 32;

    #[cfg(feature = "tracker")]
    {
        tracker.add_mem_op(BUFFER_SIZE - 1, MemOp::Read);
        tracker.add_mem_op(MEMORY_SIZE - 1, MemOp::Read);
    }

    let mut r: usize = 0;

    for i in 0..SCRATCHPAD_ITERS {
        let index_a = map_index(addr_a);
        let mem_a = mem_buffer_a[index_a];
        let index_b = map_index(mem_a ^ addr_b);
        let mem_b = mem_buffer_b[index_b];

        #[cfg(feature = "tracker")]
        {
            tracker.add_mem_op(index_a, MemOp::Read);
            tracker.add_mem_op(BUFFER_SIZE + index_b, MemOp::Read);
        }

        block[..8].copy_from_slice(&mem_b.to_le_bytes());
        block[8..].copy_from_slice(&mem_a.to_le_bytes());
        aes::hazmat::cipher_round(&mut block, &key);

        let hash1 = u64::from_le_bytes(block[..8].try_into().map_err(|_| Error::FormatError)?);
        let hash2 = u64::from_le_bytes(block[8..].try_into().map_err(|_| Error::FormatError)?);
        let mut result = !(hash1 ^ hash2);

        for j in 0..BUFFER_SIZE {
            // -- same V3 random access pattern --
            let index_a = map_index(result);
            let a = mem_buffer_a[index_a];
            let index_b = map_index(a ^ !result.rotate_right(r as u32));
            let b = mem_buffer_b[index_b];

            #[cfg(feature = "tracker")]
            {
                tracker.add_mem_op(index_a, MemOp::Read);
                tracker.add_mem_op(BUFFER_SIZE + index_b, MemOp::Read);
                tracker.add_mem_op(r, MemOp::Read);
            }

            let c = if r < BUFFER_SIZE {
                mem_buffer_a[r]
            } else {
                mem_buffer_b[r - BUFFER_SIZE]
            };
            r = if r < MEMORY_SIZE - 1 { r + 1 } else { 0 };

            // -- same V3 branch ops --
            let branch_idx = (result.rotate_left(c as u32) & 0xf) as u8;
            #[cfg(feature = "tracker")]
            {
                tracker.add_branch(branch_idx);
            }

            let v = match branch_idx {
                0 => {
                    let t1 = v2::combine_u64(a.wrapping_add(i as u64), isqrt(b.wrapping_add(j as u64)));
                    let denom = murmurhash3(c ^ result ^ i as u64 ^ j as u64) | 1;
                    (t1 % (denom as u128)) as u64
                }
                1 => {
                    let t1 = c.wrapping_add(i as u64).wrapping_rem(isqrt(b | 2));
                    let t2 = t1.rotate_left((i.wrapping_add(j)) as u32);
                    t2.wrapping_mul(isqrt(a.wrapping_add(j as u64)))
                }
                2 => {
                    let t1 = isqrt(a.wrapping_add(i as u64));
                    let t2 = isqrt(c.wrapping_add(j as u64));
                    t1.wrapping_mul(t2) ^ b.wrapping_add(i as u64).wrapping_add(j as u64)
                }
                3 => a.wrapping_add(b).wrapping_mul(c),
                4 => b.wrapping_sub(c).wrapping_mul(a),
                5 => c.wrapping_sub(a).wrapping_add(b),
                6 => a.wrapping_sub(b).wrapping_add(c),
                7 => b.wrapping_mul(c).wrapping_add(a),
                8 => c.wrapping_mul(a).wrapping_add(b),
                9 => a.wrapping_mul(b).wrapping_mul(c),
                10 => {
                    let t1 = v2::combine_u64(a, b);
                    (t1.wrapping_rem((c | 1) as u128)) as u64
                }
                11 => {
                    let t1 = v2::combine_u64(b, c);
                    let t2 = v2::combine_u64(result.rotate_left(r as u32), a | 2);
                    if t2 > t1 { c } else { t1.wrapping_rem(t2) as u64 }
                }
                12 => {
                    let t1 = v2::combine_u64(c, a);
                    t1.wrapping_div((b | 4) as u128) as u64
                }
                13 => {
                    let t1 = v2::combine_u64(result.rotate_left(r as u32), b);
                    let t2 = v2::combine_u64(a, c | 8);
                    if t1 > t2 { t1.wrapping_div(t2) as u64 } else { a ^ b }
                }
                14 => {
                    let t1 = v2::combine_u64(b, a);
                    (t1.wrapping_mul(c as u128) >> 64) as u64
                }
                15 => {
                    let t1 = v2::combine_u64(a, c);
                    let t2 = v2::combine_u64(result.rotate_right(r as u32), b);
                    (t1.wrapping_mul(t2) >> 64) as u64
                }
                _ => unreachable!(),
            };

            // -- V4 addition: S-box lookup + multiply chain --
            let sbox_val = sbox[((v >> 56) & 0xFF) as usize];
            let si = state[((result >> 4) & (STATE_WORDS as u64 - 1)) as usize];
            let sj = state[((result >> 7) & (STATE_WORDS as u64 - 1)) as usize];

            let chain = mul_chain(v, sbox_val, si, sj, result, a);

            // update one state slot and one S-box entry per iteration
            state[((result >> 10) & (STATE_WORDS as u64 - 1)) as usize] = chain;
            sbox[((chain >> 48) & 0xFF) as usize] ^= chain;

            // chain feeds into idx_seed (replaces plain v in V3)
            let idx_seed = (v ^ chain) ^ result;
            result = idx_seed.rotate_left(r as u32);

            // -- same V3 scratchpad RMW --
            let use_buffer_b = pick_half(v);
            let index_t = map_index(idx_seed);
            let t = if use_buffer_b { mem_buffer_b[index_t] } else { mem_buffer_a[index_t] } ^ result;

            let index_a = map_index(t ^ result ^ 0x9e3779b97f4a7c15);
            let index_b = map_index(index_a as u64 ^ !result ^ 0xd2b74407b1ce6e93);

            #[cfg(feature = "tracker")]
            {
                if use_buffer_b {
                    tracker.add_mem_op(BUFFER_SIZE + index_t, MemOp::Read);
                } else {
                    tracker.add_mem_op(index_t, MemOp::Read);
                }
                tracker.add_mem_op(index_a, MemOp::Read);
                tracker.add_mem_op(index_a, MemOp::Write);
                tracker.add_mem_op(BUFFER_SIZE + index_b, MemOp::Read);
                tracker.add_mem_op(BUFFER_SIZE + index_b, MemOp::Write);
            }

            let old_a = std::mem::replace(&mut mem_buffer_a[index_a], t);
            mem_buffer_b[index_b] ^= old_a ^ t.rotate_right(i.wrapping_add(j) as u32);
        }

        addr_a = modular_power(addr_a, addr_b, result);
        addr_b = isqrt(result).wrapping_mul((r as u64).wrapping_add(1)).wrapping_mul(isqrt(addr_a));
    }

    Ok(())
}

pub fn xelis_hash(input: &[u8], scratch_pad: &mut ScratchPad, #[cfg(feature = "tracker")] distribution: &mut OpsTracker) -> Result<Hash, Error> {
    v2::stage_1::<MEMORY_SIZE, MEMORY_SIZE_BYTES>(input, scratch_pad)?;
    let scratch_pad = scratch_pad.as_mut_slice();
    stage_3(scratch_pad, #[cfg(feature = "tracker")] distribution)?;
    v2::stage_4(scratch_pad)
}

#[cfg(test)]
mod tests {
    use rand::{RngCore, rngs::OsRng};
    use super::*;

    #[test]
    fn test_reused_scratchpad() {
        let mut scratch_pad = ScratchPad::default();
        let mut input = [0u8; 112];
        OsRng.fill_bytes(&mut input);
        let expected = xelis_hash(&input, &mut scratch_pad, #[cfg(feature = "tracker")] &mut OpsTracker::new(MEMORY_SIZE)).unwrap();
        let hash = xelis_hash(&input, &mut scratch_pad, #[cfg(feature = "tracker")] &mut OpsTracker::new(MEMORY_SIZE)).unwrap();
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_deterministic() {
        let mut sp1 = ScratchPad::default();
        let mut sp2 = ScratchPad::default();
        let input = [0u8; 112];
        let h1 = xelis_hash(&input, &mut sp1, #[cfg(feature = "tracker")] &mut OpsTracker::new(MEMORY_SIZE)).unwrap();
        let h2 = xelis_hash(&input, &mut sp2, #[cfg(feature = "tracker")] &mut OpsTracker::new(MEMORY_SIZE)).unwrap();
        assert_eq!(h1, h2, "V4 must be deterministic");
    }

    #[test]
    fn test_nonzero_output() {
        let mut sp = ScratchPad::default();
        let input = [0u8; 112];
        let h = xelis_hash(&input, &mut sp, #[cfg(feature = "tracker")] &mut OpsTracker::new(MEMORY_SIZE)).unwrap();
        assert_ne!(h, [0u8; 32], "hash of zero input should not be all zeros");
    }

    #[test]
    fn test_avalanche() {
        let mut sp = ScratchPad::default();
        let input1 = [0u8; 112];
        let mut input2 = [0u8; 112];
        input2[0] = 1;
        let h1 = xelis_hash(&input1, &mut sp, #[cfg(feature = "tracker")] &mut OpsTracker::new(MEMORY_SIZE)).unwrap();
        let h2 = xelis_hash(&input2, &mut sp, #[cfg(feature = "tracker")] &mut OpsTracker::new(MEMORY_SIZE)).unwrap();
        let diff_bits: u32 = h1.iter().zip(h2.iter()).map(|(a, b)| (a ^ b).count_ones()).sum();
        assert!(diff_bits > 64 && diff_bits < 192,
            "poor avalanche: {} of 256 bits differ", diff_bits);
    }
}
