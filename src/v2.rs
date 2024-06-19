use aes::cipher::generic_array::GenericArray;
use blake3::hash as blake3_hash;

use crate::{Error, Hash};

// These are tweakable parameters
// Memory size is the size of the scratch pad in u64s
// In bytes, this is equal to ~ 440KB
const MEMORY_SIZE: usize = 429 * 128;
// Scratchpad iterations in stage 3
const SCRATCHPAD_ITERS: usize = 3;
// Buffer size for stage 3 (inner loop iterations)
const BUFFER_SIZE: usize = MEMORY_SIZE / 2;

// Stage 1 config
const AES_SIZE: usize = 16;

// Stage 3 AES key
const KEY: [u8; 16] = *b"xelishash-pow-v2";

// Scratchpad used to store intermediate values
// It has a fixed size of `MEMORY_SIZE` u64s
// It can be easily reused for multiple hashing operations safely
#[derive(Debug, Clone)]
pub struct ScratchPad([u64; MEMORY_SIZE]);

impl ScratchPad {
    // Retrieve the scratchpad size
    pub fn len(&self) -> usize {
        self.0.len()
    }

    // Get the inner scratch pad as a mutable u64 slice
    pub fn as_mut_slice(&mut self) -> &mut [u64; MEMORY_SIZE] {
        &mut self.0
    }

    // Retrieve the scratch pad as a mutable bytes slice
    pub fn as_mut_bytes(&mut self) -> Result<&mut [u8; MEMORY_SIZE * 8], Error> {
        bytemuck::try_cast_slice_mut(&mut self.0)
            .map_err(|e| Error::CastError(e))?
            .try_into()
            .map_err(|_| Error::FormatError)
    }
}

impl Default for ScratchPad {
    fn default() -> Self {
        Self([0; MEMORY_SIZE])
    }
}

// Stage 1 of the hashing algorithm
// This stage is responsible for generating the scratch pad
// The scratch pad is generated using Chacha20 with a custom nonce
// that is updated after each iteration
fn stage_1(input: &[u8], scratch_pad: &mut ScratchPad) -> Result<(), Error> {
    let mut key = GenericArray::from([0u8; AES_SIZE]);

    // Generate the nonce from the input
    let input_hash: Hash = blake3_hash(input).into();
    key.copy_from_slice(&input_hash[..AES_SIZE]);

    let scratchpad_bytes = scratch_pad.as_mut_bytes().unwrap();

    // Generate the scratchpad by applying AES round to block sequentially
    let mut block = GenericArray::from([0u8; AES_SIZE]);
    for i in 0..(MEMORY_SIZE*8)/AES_SIZE {
        let index = i * AES_SIZE;

        aes::hazmat::cipher_round(&mut block, &key);

        scratchpad_bytes[index..index+AES_SIZE].copy_from_slice(&block);
    }

    Ok(())
}

// Stage 3 of the hashing algorithm
// This stage is responsible for hashing the scratch pad
// Its goal is to have lot of random memory accesses
// and some branching to make it hard to optimize on GPUs
// it shouldn't be possible to parallelize this stage
fn stage_3(scratch_pad: &mut [u64; MEMORY_SIZE]) -> Result<(), Error> {
    let key = GenericArray::from(KEY);
    let mut block = GenericArray::from([0u8; 16]);
    let buffer_size = BUFFER_SIZE as u64;

    // Create two new slices for each half
    let (mem_buffer_a, mem_buffer_b) = scratch_pad.as_mut_slice().split_at_mut(BUFFER_SIZE);

    let mut addr_a = mem_buffer_b[BUFFER_SIZE-1];
    let mut addr_b = mem_buffer_a[BUFFER_SIZE-1] >> 32;
    let mut r: usize = 0;

    for i in 0..SCRATCHPAD_ITERS {
        let mem_a = mem_buffer_a[(addr_a % buffer_size) as usize];
        let mem_b = mem_buffer_b[(addr_b % buffer_size) as usize];

        block[..8].copy_from_slice(&mem_b.to_le_bytes());
        block[8..].copy_from_slice(&mem_a.to_le_bytes());

        aes::hazmat::cipher_round(&mut block, &key);

        let hash1 = u64::from_le_bytes(block[0..8]
            .try_into()
            .map_err(|_| Error::FormatError)?);

        let hash2 = mem_a ^ mem_b;
        let mut result = !(hash1 ^ hash2);

        for j in 0..BUFFER_SIZE {
            let a = mem_buffer_a[(result % buffer_size) as usize];
            let b = mem_buffer_b[(!result.rotate_right(r as u32) % buffer_size) as usize];
            let c = if r < BUFFER_SIZE {mem_buffer_a[r]} else {mem_buffer_b[r-BUFFER_SIZE]};
            r = if r < MEMORY_SIZE-1 {r+1} else {0};

            let v = match result.rotate_left(c as u32) & 0xf {
                0 => result ^ c.rotate_left(i.wrapping_mul(j) as u32) ^ b,
                1 => result ^ c.rotate_right(i.wrapping_mul(j) as u32) ^ a,
                2 => result ^ a ^ b ^ c,
                3 => result ^ a.wrapping_add(b).wrapping_mul(c),
                4 => result ^ b.wrapping_sub(c).wrapping_mul(a),
                5 => result ^ c.wrapping_sub(a).wrapping_add(b),
                6 => result ^ a.wrapping_sub(b).wrapping_add(c),
                7 => result ^ b.wrapping_mul(c).wrapping_add(a),
                8 => result ^ c.wrapping_mul(a).wrapping_add(b),
                9 => result ^ a.wrapping_mul(b).wrapping_mul(c),
                10 => {
                    let t1 = ((a as u128) << 64) | (b as u128);
                    let t2 = (c | 1) as u128;
                    result ^ (t1.wrapping_rem(t2)) as u64
                },
                11 => {
                    let t1 = (b as u128) << 64 | c as u128;
                    let t2 = (result.rotate_left(r as u32) as u128) << 64 | (a | 2) as u128;
                    result ^ (t1.wrapping_rem(t2)) as u64
                },
                12 => {
                    let t1 = ((c as u128)<<64) | (a as u128);
                    let t2 = (b | 4) as u128;
                    result ^ (t1.wrapping_div(t2)) as u64
                },
                13 => {
                    let t1 = (result.rotate_left(r as u32) as u128) << 64 | b as u128;
                    let t2 = (a as u128) << 64 | (c | 8) as u128;
                    result ^ if t1 > t2 {t1.wrapping_div(t2) as u64} else {a^b}
                },
                14 => {
                    let t1 = ((b as u128) << 64) | a as u128;
                    let t2 = c as u128;
                    result ^ ((t1.wrapping_mul(t2)) >> 64) as u64
                },
                15 => {
                    let t1 = (a as u128) << 64 | c as u128;
                    let t2 = (result.rotate_right(r as u32) as u128) << 64 | b as u128;
                    result ^ ((t1.wrapping_mul(t2)) >> 64) as u64
                },
                _ => unreachable!(),
            };

            result = v.rotate_left(1);

            let t = mem_buffer_a[BUFFER_SIZE-j-1] ^ result;
            mem_buffer_a[BUFFER_SIZE-j-1] = t;
            mem_buffer_b[j] ^= t.rotate_right(result as u32);
        }
        addr_a = result;
        addr_b = isqrt(result);
    }

    Ok(())
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
pub fn xelis_hash(input: &[u8], scratch_pad: &mut ScratchPad) -> Result<Hash, Error> {
    // stage 1
    stage_1(input, scratch_pad)?;

    let scratch_pad = scratch_pad.as_mut_slice();
    
    // stage 2 got removed as it got completely optimized on GPUs

    // stage 3
    stage_3(scratch_pad)?;

    // stage 4
    let scratchpad_bytes: &[u8] = bytemuck::try_cast_slice(scratch_pad.as_slice())
        .map_err(|e| Error::CastError(e))?;

    let hash = blake3_hash(scratchpad_bytes).into();

    Ok(hash)
}

#[cfg(test)]
mod tests {
    use rand::{rngs::OsRng, RngCore};

    use super::*;
    use std::{time::Instant, hint};

    #[test]
    fn benchmark_cpu_hash() {
        const ITERATIONS: u32 = 1000;
        let mut input = [0u8; 112];
        let mut scratch_pad = ScratchPad::default();

        let start = Instant::now();
        for i in 0..ITERATIONS {
            input[0] = i as u8;
            input[1] = (i >> 8) as u8;
            let _ = hint::black_box(xelis_hash(&mut input, &mut scratch_pad)).unwrap();
        }

        let elapsed = start.elapsed();
        println!("Time took: {:?}", elapsed);
        println!("H/s: {:.2}", (ITERATIONS as f64 * 1000.) / (elapsed.as_millis() as f64));
        println!("ms per hash: {:.3}", (elapsed.as_millis() as f64) / ITERATIONS as f64);
    }

    #[test]
    fn test_reused_scratchpad() {
        let mut scratch_pad = ScratchPad::default();
        let mut input = [0u8; 112];
        OsRng.fill_bytes(&mut input);

        // Do a first hash
        let expected_hash = xelis_hash(&input, &mut scratch_pad).unwrap();

        // Do a second hash with dirty scratch pad but same input
        let hash = xelis_hash(&input, &mut scratch_pad).unwrap();
        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_zero_hash() {
        let mut scratch_pad = ScratchPad::default();
        let mut input = [0u8; 112];

        let hash = xelis_hash(&mut input, &mut scratch_pad).unwrap();
        let expected_hash = [
            192, 113, 203, 92, 213, 123, 33, 77, 181, 109, 22, 73, 76, 223, 58, 188,
            81, 178, 30, 147, 198, 186, 79, 113, 154, 37, 168, 146, 107, 133, 113, 238
        ];

        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_xelis_stages() {
        const ITERATIONS: usize = 1000;

        let mut input = [0u8; 112];
        OsRng.fill_bytes(&mut input);

        let mut scratch_pad = ScratchPad::default();
        let instant = Instant::now();
        for i in 0..ITERATIONS {
            input[0] = i as u8;
            std::hint::black_box(stage_1(&mut input, &mut scratch_pad).unwrap());
        }
        println!("Stage 1 took: {} microseconds", instant.elapsed().as_micros() / ITERATIONS as u128);

        let instant = Instant::now();
        for _ in 0..ITERATIONS {
            std::hint::black_box(stage_3(scratch_pad.as_mut_slice()).unwrap());
        }
        println!("Stage 3 took: {}ms", instant.elapsed().as_millis() / ITERATIONS as u128);

        let instant = Instant::now();
        for _ in 0..ITERATIONS {
            std::hint::black_box(blake3_hash(scratch_pad.as_mut_bytes().unwrap()));
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
        let hash = xelis_hash(&input, &mut scratch_pad).unwrap();

        let expected_hash = [
            98, 122, 36, 38, 105, 219, 9, 148, 157, 82, 95, 233, 85, 172, 37, 246,
            150, 156, 40, 238, 77, 32, 122, 131, 198, 100, 23, 61, 78, 77, 239, 73
        ];

        assert_eq!(hash, expected_hash);
    }
}