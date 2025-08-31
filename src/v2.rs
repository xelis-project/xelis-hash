use aes::cipher::generic_array::GenericArray;
use blake3::hash as blake3_hash;
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha8,
};

use crate::{
    scratchpad::ScratchPad as ScratchPadInternal,
    Error,
    Hash,
    HASH_SIZE
};

#[cfg(feature = "tracker")]
use crate::tracker::{OpsTracker, MemOp};

// These are tweakable parameters
// Memory size is the size of the scratch pad in u64s
// In bytes, this is equal to ~ 440KB
const MEMORY_SIZE: usize = 429 * 128;
// Memory size in bytes
const MEMORY_SIZE_BYTES: usize = MEMORY_SIZE * 8;

// Scratchpad iterations in stage 3
const SCRATCHPAD_ITERS: usize = 3;
// Buffer size for stage 3 (inner loop iterations)
const BUFFER_SIZE: usize = MEMORY_SIZE / 2;

// Stage 1 config
const CHUNK_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const OUTPUT_SIZE: usize = MEMORY_SIZE * 8;

// Stage 3 AES key
const KEY: [u8; 16] = *b"xelishash-pow-v2";

pub type ScratchPad = ScratchPadInternal<MEMORY_SIZE>;

// Combine two u64 into a u128
#[inline(always)]
pub(crate) fn combine_u64(high: u64, low: u64) -> u128 {
    (high as u128) << 64 | low as u128
}

// Stage 1 of the hashing algorithm
// This stage is responsible for generating the scratch pad
// The scratch pad is generated using ChaCha8 with a custom nonce
// that is updated after each iteration
pub(crate) fn stage_1<const M: usize, const M_BYTES: usize>(input: &[u8], scratch_pad: &mut ScratchPadInternal<M>) -> Result<(), Error> {
    let bytes = scratch_pad.as_mut_bytes::<M_BYTES>()?;

    // Reset the scratchpad to 0
    // This is done to ensure that the scratchpad is clean
    // and prevent us to do multiple heap allocations in below loop
    bytes.fill(0);

    let mut output_offset = 0;
    let mut nonce = [0u8; NONCE_SIZE];

    // Generate the nonce from the input
    let mut input_hash: Hash = blake3_hash(input).into();
    nonce.copy_from_slice(&input_hash[..NONCE_SIZE]);

    let num_chunks = (input.len() + CHUNK_SIZE - 1) / CHUNK_SIZE;

    for (chunk_index, chunk) in input.chunks(CHUNK_SIZE).enumerate() {
        // Concatenate the input hash with the chunk
        let mut tmp = [0u8; HASH_SIZE * 2];
        tmp[0..HASH_SIZE].copy_from_slice(&input_hash);
        tmp[HASH_SIZE..HASH_SIZE + chunk.len()].copy_from_slice(chunk);

        // Hash it to not trust the input
        input_hash = blake3_hash(&tmp).into();

        let mut cipher = ChaCha8::new(&input_hash.into(), &nonce.into());

        // Calculate the remaining size and how much to generate this iteration
        let remaining_output_size = OUTPUT_SIZE - output_offset;
        // Remaining chunks
        let chunks_left = num_chunks - chunk_index;
        let chunk_output_size = remaining_output_size / chunks_left;
        let current_output_size = remaining_output_size.min(chunk_output_size);

        // Apply the keystream to the output
        let offset = chunk_index * current_output_size;
        let part = &mut bytes[offset..offset+current_output_size];
        cipher.apply_keystream(part);

        output_offset += current_output_size;

        // Update the nonce with the last NONCE_SIZE bytes of temp_output
        let nonce_start = current_output_size.saturating_sub(NONCE_SIZE);

        // Copy the new nonce
        nonce.copy_from_slice(&part[nonce_start..]);
    }

    Ok(())
}

// Stage 3 of the hashing algorithm
// This stage is responsible for hashing the scratch pad
// Its goal is to have lot of random memory accesses
// and some branching to make it hard to optimize on GPUs
// it shouldn't be possible to parallelize this stage
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

            let c = if r < BUFFER_SIZE {mem_buffer_a[r]} else {mem_buffer_b[r-BUFFER_SIZE]};
            r = if r < MEMORY_SIZE-1 {r+1} else {0};

            let branch_idx = (result.rotate_left(c as u32) & 0xf) as u8;
            #[cfg(feature = "tracker")]
            {
                tracker.add_branch(branch_idx);
            }

            let v = result ^ match branch_idx {
                0 => c.rotate_left(i.wrapping_mul(j) as u32) ^ b,
                1 => c.rotate_right(i.wrapping_mul(j) as u32) ^ a,
                2 => a ^ b ^ c,
                3 => a.wrapping_add(b).wrapping_mul(c),
                4 => b.wrapping_sub(c).wrapping_mul(a),
                5 => c.wrapping_sub(a).wrapping_add(b),
                6 => a.wrapping_sub(b).wrapping_add(c),
                7 => b.wrapping_mul(c).wrapping_add(a),
                8 => c.wrapping_mul(a).wrapping_add(b),
                9 => a.wrapping_mul(b).wrapping_mul(c),
                10 => {
                    let t1 = combine_u64(a, b);
                    let t2 = (c | 1) as u128;
                    t1.wrapping_rem(t2) as u64
                },
                11 => {
                    let t1 = combine_u64(b, c);
                    let t2 = combine_u64(result.rotate_left(r as u32), a | 2);
                    t1.wrapping_rem(t2) as u64
                },
                12 => {
                    let t1 = combine_u64(c, a);
                    let t2 = (b | 4) as u128;
                    t1.wrapping_div(t2) as u64
                },
                13 => {
                    let t1 = combine_u64(result.rotate_left(r as u32), b);
                    let t2 = combine_u64(a, c | 8);
                    if t1 > t2 {t1.wrapping_div(t2) as u64} else {a^b}
                },
                14 => {
                    let t1 = combine_u64(b, a);
                    let t2 = c as u128;
                    (t1.wrapping_mul(t2) >> 64) as u64
                },
                15 => {
                    let t1 = combine_u64(a, c);
                    let t2 = combine_u64(result.rotate_right(r as u32), b);
                    (t1.wrapping_mul(t2) >> 64) as u64
                },
                _ => unreachable!(),
            };

            result = v.rotate_left(1);

            #[cfg(feature = "tracker")]
            {
                tracker.add_mem_op(BUFFER_SIZE-j-1, MemOp::Write);
                tracker.add_mem_op(BUFFER_SIZE+j, MemOp::Write);
            }

            let t = mem_buffer_a[BUFFER_SIZE-j-1] ^ result;
            mem_buffer_a[BUFFER_SIZE-j-1] = t;
            mem_buffer_b[j] ^= t.rotate_right(result as u32);
        }
        addr_a = result;
        addr_b = isqrt(result);
    }

    Ok(())
}

// Stage 4 hash the whole scratchpad using Blake3 to prevent any shortcut in
// the scratchpad computation
#[inline]
pub(crate) fn stage_4(scratch_pad: &[u64]) -> Result<Hash, Error> {
    let bytes: &[u8] = bytemuck::try_cast_slice(scratch_pad)
        .map_err(Error::CastError)?;

    Ok(blake3_hash(bytes).into())
}

fn isqrt(n: u64) -> u64 {
    if n < 2 {
        return n;
    }

    let mut x = n;
    let mut y = (x.wrapping_add(1)) >> 1;

    while y < x {
        x = y;
        y = (x.wrapping_add(n.wrapping_div(x))) >> 1;
    }

    x
}

// This function is used to hash the input using the generated scratch pad
// NOTE: The scratchpad is completely overwritten in stage 1  and can be reused without any issues
pub fn xelis_hash(input: &[u8], scratch_pad: &mut ScratchPad, #[cfg(feature = "tracker")] distribution: &mut OpsTracker) -> Result<Hash, Error> {
    stage_1::<MEMORY_SIZE, MEMORY_SIZE_BYTES>(input, scratch_pad)?;

    let scratch_pad = scratch_pad.as_mut_slice();

    // stage 2 got removed as it got completely optimized on GPUs

    // stage 3
    stage_3(scratch_pad, #[cfg(feature = "tracker")] distribution)?;

    // final stage 4
    stage_4(scratch_pad)
}

#[cfg(test)]
mod tests {
    use rand::{rngs::OsRng, RngCore};
    use std::time::Instant;
    use super::*;

    const ITERATIONS: usize = 10000;

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
            126, 219, 112, 240, 116, 133, 115, 144, 39, 40, 164,
            105, 30, 158, 45, 126, 64, 67, 238, 52, 200, 35,
            161, 19, 144, 211, 214, 225, 95, 190, 146, 27
        ];

        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_xelis_stages() {
        let mut input = [0u8; 112];
        OsRng.fill_bytes(&mut input);

        let mut scratch_pad = ScratchPad::default();
        let instant = Instant::now();
        for i in 0..ITERATIONS {
            input[0] = i as u8;
            std::hint::black_box(stage_1::<MEMORY_SIZE, MEMORY_SIZE_BYTES>(&mut input, &mut scratch_pad).unwrap());
        }
        println!("Stage 1 took: {} microseconds", instant.elapsed().as_micros() / ITERATIONS as u128);

        let instant = Instant::now();
        for _ in 0..ITERATIONS {
            std::hint::black_box(stage_3(scratch_pad.as_mut_slice(), #[cfg(feature = "tracker")] &mut OpsTracker::new(MEMORY_SIZE)).unwrap());
        }
        println!("Stage 3 took: {} microseconds", instant.elapsed().as_micros() / ITERATIONS as u128);

        let instant = Instant::now();
        for _ in 0..ITERATIONS {
            std::hint::black_box(blake3_hash(scratch_pad.as_mut_bytes::<MEMORY_SIZE_BYTES>().unwrap()));
        }
        println!("Stage 4 took: {} microseconds", instant.elapsed().as_micros() / ITERATIONS as u128);
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
            199, 114, 154, 28, 4, 164, 196, 178, 117, 17, 148,
            203, 125, 228, 51, 145, 162, 222, 106, 202, 205,
            55, 244, 178, 94, 29, 248, 242, 98, 221, 158, 179
        ];

        assert_eq!(hash, expected_hash);
    }

    #[test]
    #[cfg(feature = "tracker")]
    fn test_distribution() {
        let mut scratch_pad = ScratchPad::default();
        let mut input = [0u8; 112];
        let mut distribution = OpsTracker::new(MEMORY_SIZE);
        for _ in 0..ITERATIONS {
            OsRng.fill_bytes(&mut input);
            let _ = xelis_hash(&input, &mut scratch_pad, &mut distribution).unwrap();
        }

        println!("{:?}", distribution.get_mem_accesses());
        println!("{:?}", distribution.get_branches());
        let mut min = usize::MAX;
        let mut max = 0;

        for accesses in distribution.get_mem_accesses() {
            if *accesses < min {
                min = *accesses;
            }

            if *accesses > max {
                max = *accesses;
            }
        }

        println!("Min: {}, Max: {}", min, max);
    }
}