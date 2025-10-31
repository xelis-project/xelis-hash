use aes::cipher::generic_array::GenericArray;
use crate::{v2, Error, Hash, scratchpad::ScratchPad as ScratchPadInternal};

#[cfg(feature = "tracker")]
use crate::tracker::*;

// These are tweakable parameters
// Memory size is the size of the scratch pad in u64s
// In bytes, this is equal to ~ 544 kB
const MEMORY_SIZE: usize = 531 * 128;
const MEMORY_SIZE_BYTES: usize = MEMORY_SIZE * 8;
const SCRATCHPAD_ITERS: usize = 2;
const BUFFER_SIZE: usize = MEMORY_SIZE / 2;

// Stage 3 AES key
const KEY: [u8; 16] = *b"xelishash-pow-v3";

pub type ScratchPad = ScratchPadInternal<MEMORY_SIZE>;

#[inline(always)]
const fn murmurhash3(mut seed: u64) -> u64 {
    /* MurmurHash3 finalizer.
    * Avalanches the input seed to produce a uniformly distributed output.
    */
	seed ^= seed >> 33;
	seed = seed.wrapping_mul(0xff51afd7ed558ccd);
	seed ^= seed >> 33;
	seed = seed.wrapping_mul(0xc4ceb9fe1a85ec53);
	seed ^= seed >> 33;

    seed
}

#[inline(always)]
pub const fn map_index(seed: u64) -> usize {
	/* MurmurHash3 finalizer + multiply-high reduction.
	* The finalizer avalanches the input seed; the mulhi step maps
	* uniformly into [0, BUFSIZE) with minimal modulo bias.
    */
    ((murmurhash3(seed) as u128) * (BUFFER_SIZE as u128) >> 64) as usize
}

#[inline(always)]
pub const fn pick_half(seed: u64) -> bool {
    // Murmur3 finalizer to get a uniform selector bit
    (murmurhash3(seed) >> 63) == 1
}


#[inline(always)]
pub fn isqrt(n: u64) -> u64 {
    if n < 2 {
        return n;
    }

    // Compute floating-point square root as an approximation
    let approx = (n as f64).sqrt() as u64;

    // Verify and adjust if necessary
    if approx * approx > n {
        approx - 1
    } else if (approx + 1) * (approx + 1) <= n {
        approx + 1
    } else {
        approx
    }
}

fn modular_power(mut base: u64, mut exp: u64, mod_: u64) -> u64 {
    let mut result: u64 = 1;
    // Ensure base is within the range of mod
    base %= mod_;

    while exp > 0 {
        // If exp is odd, multiply base with result
        if exp & 1 == 1 {
            result = ((result as u128 * base as u128) % mod_ as u128) as u64;
        }

        // Square the base and reduce by mod
        base = ((base as u128 * base as u128) % mod_ as u128) as u64;
        exp /= 2;
    }

    result
}

pub(crate) fn stage_3(scratch_pad: &mut [u64; MEMORY_SIZE], #[cfg(feature = "tracker")] tracker: &mut OpsTracker) -> Result<(), Error> {
    let key = GenericArray::from(KEY);
    let mut block = GenericArray::from([0u8; 16]);
    let buffer_size = BUFFER_SIZE as u64;

    // Create two new slices for each half
    let (mem_buffer_a, mem_buffer_b) = scratch_pad.as_mut_slice().split_at_mut(BUFFER_SIZE);

    let mut addr_a = mem_buffer_b[BUFFER_SIZE-1];
    let mut addr_b = mem_buffer_a[BUFFER_SIZE-1] >> 32;

    #[cfg(feature = "tracker")]
    {
        tracker.add_mem_op(BUFFER_SIZE-1, MemOp::Read);
        tracker.add_mem_op(MEMORY_SIZE-1, MemOp::Read);
    }

    let mut r: usize = 0;

    for i in 0..SCRATCHPAD_ITERS {
        let index_a = (addr_a % buffer_size) as usize;
        let index_b = (addr_b % buffer_size) as usize;

        #[cfg(feature = "tracker")]
        {
            tracker.add_mem_op(index_a, MemOp::Read);
            tracker.add_mem_op(BUFFER_SIZE + index_b, MemOp::Read);
        }

        let mem_a = mem_buffer_a[index_a];
        let mem_b = mem_buffer_b[index_b];

        block[..8].copy_from_slice(&mem_b.to_le_bytes());
        block[8..].copy_from_slice(&mem_a.to_le_bytes());

        aes::hazmat::cipher_round(&mut block, &key);

        let hash1 = u64::from_le_bytes(block[..8]
            .try_into()
            .map_err(|_| Error::FormatError)?);

        let hash2 = u64::from_le_bytes(block[8..]
            .try_into()
            .map_err(|_| Error::FormatError)?);

        let mut result = !(hash1 ^ hash2);

        for j in 0..BUFFER_SIZE {
            let index_a = map_index(result);
            let index_b = map_index(!result.rotate_right(r as u32));

            #[cfg(feature = "tracker")]
            {
                tracker.add_mem_op(index_a, MemOp::Read);
                tracker.add_mem_op(BUFFER_SIZE + index_b, MemOp::Read);
            }

            let a = mem_buffer_a[index_a];
            let b = mem_buffer_b[index_b];

            #[cfg(feature = "tracker")]
            {
                // This is the same index in scratchpad
                tracker.add_mem_op(r, MemOp::Read);
            }

            let c = if r < BUFFER_SIZE {
                mem_buffer_a[r]
            } else {
                mem_buffer_b[r-BUFFER_SIZE]
            };
            r = if r < MEMORY_SIZE - 1 {
                r + 1
            } else {
                0
            };

            let branch_idx = (result.rotate_left(c as u32) & 0xf) as u8;
            #[cfg(feature = "tracker")]
            {
                tracker.add_branch(branch_idx);
            }

            let v = match branch_idx {
                // combine_u64((a + i), isqrt(b + j)) % (murmurhash3(c ^ result ^ i ^ j) | 1)
                0 => {
                    let t1 = v2::combine_u64(
                        a.wrapping_add(i as u64),
                        isqrt(b.wrapping_add(j as u64)),
                    );
                    let denom = murmurhash3(c ^ result ^ i as u64 ^ j as u64) | 1;
                    (t1 % (denom as u128)) as u64
                }
                // ROTL((c + i) % isqrt(b | 2), i + j) * isqrt(a + j)
                1 => {
                    let t1 = c.wrapping_add(i as u64).wrapping_rem(isqrt(b | 2));
                    let t2 = t1.rotate_left((i.wrapping_add(j)) as u32);
                    let t3 = isqrt(a.wrapping_add(j as u64));
                    t2.wrapping_mul(t3)
                }
                // (isqrt(a + i) * isqrt(c + j)) ^ (b + i + j)
                2 => {
                    let t1 = isqrt(a.wrapping_add(i as u64));
                    let t2 = isqrt(c.wrapping_add(j as u64));
                    let t3 = t1.wrapping_mul(t2);
                    t3 ^ b.wrapping_add(i as u64).wrapping_add(j as u64)
                }
                // (a + b) * c
                3 => a.wrapping_add(b).wrapping_mul(c),
                // (b - c) * a
                4 => b.wrapping_sub(c).wrapping_mul(a),
                // c - a + b
                5 => c.wrapping_sub(a).wrapping_add(b),
                // a - b + c
                6 => a.wrapping_sub(b).wrapping_add(c),
                // b * c + a
                7 => b.wrapping_mul(c).wrapping_add(a),
                // c * a + b
                8 => c.wrapping_mul(a).wrapping_add(b),
                // a * b * c
                9 => a.wrapping_mul(b).wrapping_mul(c),
                10 => {
                    let t1 = v2::combine_u64(a, b);
                    let t2 = (c | 1) as u128;
                    t1.wrapping_rem(t2) as u64
                },
                11 => {
                    let t1 = v2::combine_u64(b, c);
                    let t2 = v2::combine_u64(result.rotate_left(r as u32), a | 2);
                    if t2 > t1 { c } else { t1.wrapping_rem(t2) as u64 }
                },
                12 => {
                    let t1 = v2::combine_u64(c, a);
                    let t2 = (b | 4) as u128;
                    t1.wrapping_div(t2) as u64
                },
                13 => {
                    let t1 = v2::combine_u64(result.rotate_left(r as u32), b);
                    let t2 = v2::combine_u64(a, c | 8);
                    if t1 > t2 {t1.wrapping_div(t2) as u64} else {a^b}
                },
                14 => {
                    let t1 = v2::combine_u64(b, a);
                    let t2 = c as u128;
                    (t1.wrapping_mul(t2) >> 64) as u64
                },
                15 => {
                    let t1 = v2::combine_u64(a, c);
                    let t2 = v2::combine_u64(result.rotate_right(r as u32), b);
                    (t1.wrapping_mul(t2) >> 64) as u64
                },
                _ => unreachable!(),
            };

            let idx_seed = v ^ result;
            result = (result ^ v).rotate_left(r as u32);

            let index_t = map_index(idx_seed);
            let index_a = map_index(result ^ 0x9e3779b97f4a7c15);
            let index_b = map_index(!result ^ 0xd2b74407b1ce6e93);

            let use_buffer_b = pick_half(v);
            let t = if use_buffer_b { mem_buffer_b[index_t] } else { mem_buffer_a[index_t] } ^ result;
            mem_buffer_a[index_a] = t;
			mem_buffer_b[index_b] ^= t.rotate_right(i.wrapping_add(j) as u32);

            #[cfg(feature = "tracker")]
            {
                if use_buffer_b {
                    tracker.add_mem_op(BUFFER_SIZE + index_t, MemOp::Read);
                } else {
                    tracker.add_mem_op(index_t, MemOp::Read);
                }

                // mem_buffer_a[index_a] and mem_buffer_b[index_b] are written
                tracker.add_mem_op(index_a, MemOp::Write);
                tracker.add_mem_op(BUFFER_SIZE + index_b, MemOp::Write);
            }
        }

        addr_a = modular_power(addr_a, addr_b, result);
        addr_b = isqrt(result).wrapping_mul((r as u64).wrapping_add(1)).wrapping_mul(isqrt(addr_a));
    }

    Ok(())
}

pub fn xelis_hash(input: &[u8], scratch_pad: &mut ScratchPad, #[cfg(feature = "tracker")] distribution: &mut OpsTracker) -> Result<Hash, Error> {
    v2::stage_1::<MEMORY_SIZE, MEMORY_SIZE_BYTES>(input, scratch_pad)?;

    let scratch_pad = scratch_pad.as_mut_slice();

    // stage 3 is customized compared to v2
    stage_3(scratch_pad, #[cfg(feature = "tracker")] distribution)?;

    // final stage 4
    v2::stage_4(scratch_pad)
}


#[cfg(test)]
mod tests {
    use rand::{rngs::OsRng, RngCore};
    use super::*;

    #[test]
    fn test_reused_scratchpad() {
        let mut scratch_pad = ScratchPad::default();
        let mut input = [0u8; 112];
        OsRng.fill_bytes(&mut input);

        // Do a first hash
        let expected_hash = xelis_hash(&input, &mut scratch_pad, #[cfg(feature = "tracker")] &mut OpsTracker::new(MEMORY_SIZE)).unwrap();

        // Do a second hash with dirty scratch pad but same input
        let hash = xelis_hash(&input, &mut scratch_pad, #[cfg(feature = "tracker")] &mut OpsTracker::new(MEMORY_SIZE)).unwrap();
        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_zero_hash() {
        let mut scratch_pad = ScratchPad::default();
        let mut input = [0u8; 112];

        let hash = xelis_hash(&mut input, &mut scratch_pad, #[cfg(feature = "tracker")] &mut OpsTracker::new(MEMORY_SIZE)).unwrap();
        let expected_hash = [
            220, 125, 107, 5, 193, 114, 57, 220,
            15, 63, 154, 248, 218, 205, 79, 113,
            7, 42, 159, 137, 120, 181, 105, 192,
            254, 95, 254, 194, 173, 250, 129, 56,
        ];

        assert_eq!(hash, expected_hash);
    }
 
    #[test]
    fn test_verify_output() {
        let input = [
            172, 236, 108, 212, 181, 31, 109, 45, 44, 242, 54, 225, 143, 133,
            89, 44, 179, 108, 39, 191, 32, 116, 229, 33, 63, 130, 33, 120, 185, 89,
            146, 141, 10, 79, 183, 107, 238, 122, 92, 222, 25, 134, 90, 107, 116,
            110, 236, 53, 255, 5, 214, 126, 24, 216, 97, 199, 148, 239, 253, 102,
            199, 184, 232, 253, 158, 145, 86, 187, 112, 81, 78, 70, 80, 110, 33,
            37, 159, 233, 198, 1, 178, 108, 210, 100, 109, 155, 106, 124, 124, 83,
            89, 50, 197, 115, 231, 32, 74, 2, 92, 47, 25, 220, 135, 249, 122,
            172, 220, 137, 143, 234, 68, 188
        ];

        let mut scratch_pad = ScratchPad::default();
        let hash = xelis_hash(&input, &mut scratch_pad, #[cfg(feature = "tracker")] &mut OpsTracker::new(MEMORY_SIZE)).unwrap();

        let expected_hash = [
            34, 34, 205, 25, 30, 84, 34, 154,
            128, 54, 199, 81, 18, 144, 227, 43,
            189, 36, 81, 225, 210, 90, 164, 34,
            95, 242, 79, 232, 155, 218, 59, 109
        ];

        assert_eq!(hash, expected_hash);
    }

    #[test]
    #[cfg(feature = "tracker")]
    fn test_distribution() {
        const ITERATIONS: usize = 1000;

        let mut scratch_pad = ScratchPad::default();
        let mut input = [0u8; 112];
        let mut distribution = OpsTracker::new(MEMORY_SIZE);
        for _ in 0..ITERATIONS {
            OsRng.fill_bytes(&mut input);
            let _ = xelis_hash(&input, &mut scratch_pad, &mut distribution).unwrap();
        }

        distribution.generate_branch_distribution("branch_v3.png").unwrap();
        distribution.generate_memory_usage_graph("memory_v3.png").unwrap();
    }

    #[test]
    fn test_pick_half() {
        let mut ones = 0;
        let mut zeros = 0;

        for _ in 0..1_000_000 {
            let i = OsRng.next_u64();
            if pick_half(i) {
                ones += 1;
            } else {
                zeros += 1;
            }
        }

        let ratio = ones as f64 / (ones + zeros) as f64;
        assert!((ratio - 0.5).abs() < 0.01, "pick_half is not balanced: ratio={}", ratio);
    }
}