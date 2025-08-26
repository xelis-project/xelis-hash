use crate::Error;


// Scratchpad used to store intermediate values
// It has a fixed size of `MEMORY_SIZE` u64s
// It can be easily reused for multiple hashing operations safely
#[derive(Debug, Clone)]
pub struct ScratchPad<const M: usize>(Box<[u64; M]>);

impl<const M: usize> ScratchPad<M> {
    // Retrieve the scratchpad size
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    // Get the inner scratch pad as a mutable u64 slice
    #[inline(always)]
    pub fn as_mut_slice(&mut self) -> &mut [u64; M] {
        &mut self.0
    }

    // Retrieve the scratch pad as a mutable bytes slice
    #[inline(always)]
    pub fn as_mut_bytes<const M_BYTES: usize>(&mut self) -> Result<&mut [u8; M_BYTES], Error> {
        bytemuck::try_cast_slice_mut(self.as_mut_slice())
            .map_err(|e| Error::CastError(e))?
            .try_into()
            .map_err(|_| Error::FormatError)
    }
}

impl<const M: usize> Default for ScratchPad<M> {
    fn default() -> Self {
        Self(
            vec![0; M]
                .into_boxed_slice()
                .try_into()
                .expect("Failed generating scratchpad")
        )
    }
}
