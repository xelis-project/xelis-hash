use aes::cipher::generic_array::GenericArray;
use crate::{v2, Error, Hash, scratchpad::ScratchPad as ScratchPadInternal};

// These are tweakable parameters
// Memory size is the size of the scratch pad in u64s
// In bytes, this is equal to ~ 440KB
const MEMORY_SIZE: usize = 531 * 128;
const MEMORY_SIZE_BYTES: usize = MEMORY_SIZE * 8;
const SCRATCHPAD_ITERS: usize = 2;
const BUFFER_SIZE: usize = MEMORY_SIZE / 2;

// Stage 3 AES key
const KEY: [u8; 16] = *b"xelishash-pow-v3";

pub type ScratchPad = ScratchPadInternal<MEMORY_SIZE>;

fn isqrt(n: u64) -> u64 {
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

        let hash1 = u64::from_le_bytes(block[0..8]
            .try_into()
            .map_err(|_| Error::FormatError)?);

        let hash2 = mem_a ^ mem_b;
        let mut result = !(hash1 ^ hash2);

        for j in 0..BUFFER_SIZE {
            let index_a = (result % buffer_size) as usize;
            let index_b = (!result.rotate_right(r as u32) % buffer_size) as usize;

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

            let v = result ^ match branch_idx {
                0 => ((a + i as u64) | isqrt(b.wrapping_add(j as u64))) % isqrt(c | 1),
                1 => (c.wrapping_add(i as u64) % isqrt(b | 2)).rotate_left(i.wrapping_add(j) as u32) * isqrt(a.wrapping_add(j as u64)),
                2 => (isqrt(a.wrapping_add(i as u64)) * isqrt(c.wrapping_add(j as u64))) ^ b.wrapping_add(i as u64).wrapping_add(j as u64),
                3 => a.wrapping_add(b).wrapping_mul(c),
                4 => b.wrapping_sub(c).wrapping_mul(a),
                5 => c.wrapping_sub(a).wrapping_add(b),
                6 => a.wrapping_sub(b).wrapping_add(c),
                7 => b.wrapping_mul(c).wrapping_add(a),
                8 => c.wrapping_mul(a).wrapping_add(b),
                9 => a.wrapping_mul(b).wrapping_mul(c),
                10 => {
                    let t1 = ((a as u128) << 64) | (b as u128);
                    let t2 = (c | 1) as u128;
                    t1.wrapping_rem(t2) as u64
                },
                11 => {
                    let t1 = (b as u128) << 64 | c as u128;
                    let t2 = (result.rotate_left(r as u32) as u128) << 64 | (a | 2) as u128;
                    t1.wrapping_rem(t2) as u64
                },
                12 => {
                    let t1 = ((c as u128)<<64) | (a as u128);
                    let t2 = (b | 4) as u128;
                    t1.wrapping_div(t2) as u64
                },
                13 => {
                    let t1 = (result.rotate_left(r as u32) as u128) << 64 | b as u128;
                    let t2 = (a as u128) << 64 | (c | 8) as u128;
                    if t1 > t2 {
                        t1.wrapping_div(t2) as u64
                    } else {
                        a ^ b
                    }
                },
                14 => {
                    let t1 = ((b as u128) << 64) | a as u128;
                    let t2 = c as u128;
                    (t1.wrapping_mul(t2) >> 64) as u64
                },
                15 => {
                    let t1 = (a as u128) << 64 | c as u128;
                    let t2 = (result.rotate_right(r as u32) as u128) << 64 | b as u128;
                    (t1.wrapping_mul(t2) >> 64) as u64
                },
                _ => unreachable!(),
            };

            result = v.rotate_left(r as u32);

            let index_t = (v % BUFFER_SIZE as u64) as usize;
            let index_a = ((result >> 21) % BUFFER_SIZE as u64) as usize;
            let index_b = ((result >> 42) % BUFFER_SIZE as u64) as usize;

            let t = mem_buffer_a[index_t] ^ result;

            mem_buffer_a[index_a] = t;
			mem_buffer_b[index_b] ^= t.rotate_left(i.wrapping_add(j) as u32);

            #[cfg(feature = "tracker")]
            {
                tracker.add_mem_op(index_t, MemOp::Read);
                tracker.add_mem_op(index_a, MemOp::Write);
                tracker.add_mem_op(index_b, MemOp::Write);
            }
        }

        addr_a = modular_power(addr_a, addr_b, result);
        addr_b = isqrt(result) * (r as u64).wrapping_add(1) * isqrt(addr_a);
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