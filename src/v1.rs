use aes::cipher::generic_array::GenericArray;
use tiny_keccak::keccakp;

use crate::{Hash, HASH_SIZE, Error};

// These are tweakable parameters
pub const MEMORY_SIZE: usize = 32768;
pub const SCRATCHPAD_ITERS: usize = 5000;
pub const ITERS: usize = 1;
pub const BUFFER_SIZE: usize = 42;
pub const SLOT_LENGTH: usize = 256;

// Untweakable parameters
pub const KECCAK_WORDS: usize = 25;
pub const BYTES_ARRAY_INPUT: usize = KECCAK_WORDS * 8;
pub const STAGE_1_MAX: usize = MEMORY_SIZE / KECCAK_WORDS;

// Scratchpad used to store intermediate values
// It has a fixed size of `MEMORY_SIZE` u64s
// It can be easily reused for multiple hashing operations safely
#[derive(Debug, Clone)]
pub struct ScratchPad(Box<[u64; MEMORY_SIZE]>);

impl ScratchPad {
    // Retrieve the scratchpad size
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    // Get the inner scratch pad as a mutable u64 slice
    pub fn as_mut_slice(&mut self) -> &mut [u64; MEMORY_SIZE] {
        &mut self.0
    }
}

impl Default for ScratchPad {
    fn default() -> Self {
        Self(vec![0; MEMORY_SIZE].into_boxed_slice().try_into().unwrap())
    }
}

// Align the input to 8 bytes
const ALIGNMENT: usize = 8;

#[derive(Debug, bytemuck::Pod, bytemuck::Zeroable, Copy, Clone)]
#[repr(C, align(8))]
pub struct Bytes8Alignment([u8; ALIGNMENT]);

// This is a workaround to force the correct alignment on Windows and MacOS
// We need an input of `BYTES_ARRAY_INPUT` bytes, but we need to ensure that it's aligned to 8 bytes
// to be able to cast it to a `[u64; KECCAK_WORDS]` later on.
#[derive(Debug, Clone)]
pub struct AlignedInput {
    data: Vec<Bytes8Alignment>,
}

impl Default for AlignedInput {
    fn default() -> Self {
        let mut n = BYTES_ARRAY_INPUT / ALIGNMENT;
        if BYTES_ARRAY_INPUT % ALIGNMENT != 0 {
            n += 1;
        }
    
        Self {
            data: vec![Bytes8Alignment([0; ALIGNMENT]); n]
        }
    }
} 

impl AlignedInput {
    // The number of elements in the input
    pub fn len(&self) -> usize {
        self.data.len()
    }

    // The size of the input in bytes
    pub fn size(&self) -> usize {
        self.data.len() * ALIGNMENT
    }

    // Get a mutable pointer to the input
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr() as *mut u8
    }

    // Retrieve the input as a mutable slice
    pub fn as_mut_slice(&mut self) -> Result<&mut [u8; BYTES_ARRAY_INPUT], Error> {
        bytemuck::cast_slice_mut(&mut self.data).try_into().map_err(|_| Error::FormatError)
    }

    // Retrieve the input as a slice
    pub fn as_slice(&self) -> Result<&[u8; BYTES_ARRAY_INPUT], Error> {
        bytemuck::cast_slice(&self.data).try_into().map_err(|_| Error::FormatError)
    }
}

#[inline(always)]
fn stage_1(input: &mut [u64; KECCAK_WORDS], scratch_pad: &mut [u64; MEMORY_SIZE], a: (usize, usize), b: (usize, usize)) {
    for i in a.0..=a.1 {
        keccakp(input);

        let mut rand_int: u64 = 0;
        for j in b.0..=b.1 {
            let pair_idx = (j + 1) % KECCAK_WORDS;
            let pair_idx2 = (j + 2) % KECCAK_WORDS;

            let target_idx = i * KECCAK_WORDS + j;
            let a = input[j] ^ rand_int;
            // Branching
            let left = input[pair_idx];
            let right = input[pair_idx2];
            let xor = left ^ right;
            let v = match xor & 0x3 {
                0 => left & right,
                1 => !(left & right),
                2 => !xor,
                3 => xor,
                _ => unreachable!(),
            };
            let b = a ^ v;
            rand_int = b;
            scratch_pad[target_idx] = b;
        }
    }
}

// This function is used to hash the input using the generated scratch pad
// NOTE: The scratchpad is completely overwritten in stage 1  and can be reused without any issues
pub fn xelis_hash(input: &mut [u8; BYTES_ARRAY_INPUT], scratch_pad: &mut ScratchPad) -> Result<Hash, Error> {
    let int_input: &mut [u64; KECCAK_WORDS] = bytemuck::try_from_bytes_mut(input)
        .map_err(|e| Error::CastError(e))?;

    // stage 1
    let scratch_pad = scratch_pad.as_mut_slice();
    stage_1(int_input, scratch_pad, (0, STAGE_1_MAX - 1), (0, KECCAK_WORDS - 1));
    stage_1(int_input, scratch_pad, (STAGE_1_MAX, STAGE_1_MAX), (0, 17));

    // stage 2
    let mut slots: [u32; SLOT_LENGTH] = [0; SLOT_LENGTH];
    // this is equal to MEMORY_SIZE, just in u32 format
    let small_pad: &mut [u32; MEMORY_SIZE * 2] = bytemuck::try_cast_slice_mut(scratch_pad)
        .map_err(|e| Error::CastError(e))?
        .try_into()
        .map_err(|_| Error::FormatError)?;

    slots.copy_from_slice(&small_pad[small_pad.len() - SLOT_LENGTH..]);

    let mut indices: [u16; SLOT_LENGTH] = [0; SLOT_LENGTH];
    for _ in 0..ITERS {
        for j in 0..small_pad.len() / SLOT_LENGTH {
            // Initialize indices and precompute the total sum of small pad
            let mut total_sum: u32 = 0;
            for k in 0..SLOT_LENGTH {
                indices[k] = k as u16;
                if slots[k] >> 31 == 0 {
                    total_sum = total_sum.wrapping_add(small_pad[j * SLOT_LENGTH + k]);
                } else {
                    total_sum = total_sum.wrapping_sub(small_pad[j * SLOT_LENGTH + k]);
                }
            }

            for slot_idx in (0..SLOT_LENGTH).rev() {
                let index_in_indices = (small_pad[j * SLOT_LENGTH + slot_idx] % (slot_idx as u32 + 1)) as usize;
                let index = indices[index_in_indices] as usize;
                indices[index_in_indices] = indices[slot_idx];

                let mut local_sum = total_sum;
                let s1 = (slots[index] >> 31) as i32;
                let pad_value = small_pad[j * SLOT_LENGTH + index];
                if s1 == 0 {
                    local_sum = local_sum.wrapping_sub(pad_value);
                } else {
                    local_sum = local_sum.wrapping_add(pad_value);
                }

                // Apply the sum to the slot
                slots[index] = slots[index].wrapping_add(local_sum);

                // Update the total sum
                let s2 = (slots[index] >> 31) as i32;
                total_sum = total_sum.wrapping_sub(2u32.wrapping_mul(small_pad[(j * SLOT_LENGTH).wrapping_add(index)].wrapping_mul((-s1).wrapping_add(s2) as u32)));
            }
        }
    }

    small_pad[(MEMORY_SIZE * 2) - SLOT_LENGTH..].copy_from_slice(&slots);

    // stage 3
    let key = GenericArray::from([0u8; 16]);
    let mut block = GenericArray::from([0u8; 16]);

    let mut addr_a = (scratch_pad[MEMORY_SIZE - 1] >> 15) & 0x7FFF;
    let mut addr_b = scratch_pad[MEMORY_SIZE - 1] & 0x7FFF;

    let mut mem_buffer_a: [u64; BUFFER_SIZE] = [0; BUFFER_SIZE];
    let mut mem_buffer_b: [u64; BUFFER_SIZE] = [0; BUFFER_SIZE];

    for i in 0..BUFFER_SIZE as u64 {
        mem_buffer_a[i as usize] = scratch_pad[((addr_a + i) % MEMORY_SIZE as u64) as usize];
        mem_buffer_b[i as usize] = scratch_pad[((addr_b + i) % MEMORY_SIZE as u64) as usize];
    }

    let mut final_result = [0; HASH_SIZE];

    for i in 0..SCRATCHPAD_ITERS {
        let mem_a = mem_buffer_a[i % BUFFER_SIZE];
        let mem_b = mem_buffer_b[i % BUFFER_SIZE];

        block[..8].copy_from_slice(&mem_b.to_le_bytes());
        block[8..].copy_from_slice(&mem_a.to_le_bytes());

        aes::hazmat::cipher_round(&mut block, &key);

        let hash1 = u64::from_le_bytes(block[0..8].try_into().map_err(|_| Error::FormatError)?);
        let hash2 = mem_a ^ mem_b;

        let mut result = !(hash1 ^ hash2);

        for j in 0..HASH_SIZE {
            let a = mem_buffer_a[(j + i) % BUFFER_SIZE];
            let b = mem_buffer_b[(j + i) % BUFFER_SIZE];

            // more branching
            let v = match (result >> (j * 2)) & 0xf {
                0 => result.rotate_left(j as u32) ^ b,
                1 => !(result.rotate_left(j as u32) ^ a),
                2 => !(result ^ a),
                3 => result ^ b,
                4 => result ^ (a.wrapping_add(b)),
                5 => result ^ (a.wrapping_sub(b)),
                6 => result ^ (b.wrapping_sub(a)),
                7 => result ^ (a.wrapping_mul(b)),
                8 => result ^ (a & b),
                9 => result ^ (a | b),
                10 => result ^ (a ^ b),
                11 => result ^ (a.wrapping_sub(result)),
                12 => result ^ (b.wrapping_sub(result)),
                13 => result ^ (a.wrapping_add(result)),
                14 => result ^ (result.wrapping_sub(a)),
                15 => result ^ (result.wrapping_sub(b)),
                _ => unreachable!(),
            };

            result = v;
        }

        addr_b = result & 0x7FFF;
        mem_buffer_a[i % BUFFER_SIZE] = result;
        mem_buffer_b[i % BUFFER_SIZE] = scratch_pad[addr_b as usize];

        addr_a = (result >> 15) & 0x7FFF;
        scratch_pad[addr_a as usize] = result;

        let index = SCRATCHPAD_ITERS - i - 1;
        if index < 4 {
            final_result[index * 8..(SCRATCHPAD_ITERS - i) * 8].copy_from_slice(&result.to_be_bytes());
        }
    }

    Ok(final_result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_input(input: &mut [u8; BYTES_ARRAY_INPUT], expected_hash: Hash) {
        let mut scratch_pad = ScratchPad::default();
        let hash = xelis_hash(input, &mut scratch_pad).unwrap();
        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_zero_input() {
        let mut input = [0u8; 200];
        let expected_hash = [
            0x0e, 0xbb, 0xbd, 0x8a, 0x31, 0xed, 0xad, 0xfe, 0x09, 0x8f, 0x2d, 0x77, 0x0d, 0x84,
            0xb7, 0x19, 0x58, 0x86, 0x75, 0xab, 0x88, 0xa0, 0xa1, 0x70, 0x67, 0xd0, 0x0a, 0x8f,
            0x36, 0x18, 0x22, 0x65,
        ];

        test_input(&mut input, expected_hash);
    }

    #[test]
    fn test_xelis_input() {
        let mut input = [0u8; BYTES_ARRAY_INPUT];

        let custom = b"xelis-hashing-algorithm";
        input[0..custom.len()].copy_from_slice(custom);

        let expected_hash = [
            106, 106, 173, 8, 207, 59, 118, 108, 176, 196, 9, 124, 250, 195, 3,
            61, 30, 146, 238, 182, 88, 83, 115, 81, 139, 56, 3, 28, 176, 86, 68, 21
        ];
        test_input(&mut input, expected_hash);
    }

    #[test]
    fn test_scratch_pad() {
        let mut scratch_pad = ScratchPad::default();
        let mut input = AlignedInput::default();

        let hash = xelis_hash(input.as_mut_slice().unwrap(), &mut scratch_pad).unwrap();
        let expected_hash = [
            0x0e, 0xbb, 0xbd, 0x8a, 0x31, 0xed, 0xad, 0xfe, 0x09, 0x8f, 0x2d, 0x77, 0x0d, 0x84,
            0xb7, 0x19, 0x58, 0x86, 0x75, 0xab, 0x88, 0xa0, 0xa1, 0x70, 0x67, 0xd0, 0x0a, 0x8f,
            0x36, 0x18, 0x22, 0x65,
        ];
        assert_eq!(hash, expected_hash);
    }
}