//! This module contains utilities for constructing LN-compatible preimages
//! and SHA256 hashes.

use sha2::Digest as _;

/// The size for ticket preimages.
pub const PREIMAGE_SIZE: usize = 32;

/// Compute the SHA256 hash of some input data.
pub fn sha256(input: &[u8]) -> [u8; 32] {
    sha2::Sha256::new().chain_update(input).finalize().into()
}

/// A handy type-alias for ticket and payout preimages.
///
/// We use random 32 byte preimages for compatibility with
/// lightning network clients.
pub type Preimage = [u8; PREIMAGE_SIZE];

/// Generate a random [`Preimage`] from a secure RNG.
pub fn preimage_random<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> Preimage {
    let mut preimage = [0u8; PREIMAGE_SIZE];
    rng.fill_bytes(&mut preimage);
    preimage
}

/// Parse a preimage from a hex string.
pub fn preimage_from_hex(s: &str) -> Result<Preimage, hex::FromHexError> {
    let mut preimage = [0u8; PREIMAGE_SIZE];
    hex::decode_to_slice(s, &mut preimage)?;
    Ok(preimage)
}
