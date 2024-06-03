use thiserror::Error as ThisError;

#[cfg(feature = "v1")]
pub mod v1;
#[cfg(feature = "v2")]
pub mod v2;

// Number of bytes in a hash
const HASH_SIZE: usize = 32;

// Hash type alias
pub type Hash = [u8; HASH_SIZE];

// Error that can occur while hashing
#[derive(Debug, ThisError)]
#[error("Error while hashing")]
pub enum Error {
    #[error("Error while hashing")]
    Error,
    #[error("Error while casting: {0}")]
    CastError(bytemuck::PodCastError),
    #[error("Error on format")]
    FormatError,
}

