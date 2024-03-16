use secp::{MaybePoint, MaybeScalar, Point, Scalar};

use crate::OutcomeIndex;

/// An oracle's announcement of a future event.
#[derive(Debug, Clone)]
pub struct EventAnnouncement {
    /// The signing oracle's pubkey
    pub oracle_pubkey: Point,

    /// The `R` point with which the oracle promises to attest to this event.
    pub nonce_point: Point,

    /// Naive but easy.
    pub outcome_messages: Vec<Vec<u8>>,

    /// The unix timestamp beyond which the oracle is considered to have gone AWOL.
    pub expiry: u32,
}

impl EventAnnouncement {
    /// Computes the oracle's locking point for the given outcome index.
    pub fn attestation_lock_point(&self, index: OutcomeIndex) -> Option<MaybePoint> {
        let msg = &self.outcome_messages.get(index)?;

        let e: MaybeScalar = musig2::compute_challenge_hash_tweak(
            &self.nonce_point.serialize_xonly(),
            &self.oracle_pubkey,
            msg,
        );

        // S = R + eD
        Some(self.nonce_point.to_even_y() + e * self.oracle_pubkey.to_even_y())
    }

    /// Computes the oracle's attestation secret scalar - the discrete log of the
    /// locking point - for the given outcome index.
    pub fn attestation_secret(
        &self,
        index: usize,
        oracle_seckey: impl Into<Scalar>,
        nonce: impl Into<Scalar>,
    ) -> Option<MaybeScalar> {
        let oracle_seckey = oracle_seckey.into();
        let nonce = nonce.into();

        if oracle_seckey.base_point_mul() != self.oracle_pubkey
            || nonce.base_point_mul() != self.nonce_point
        {
            return None;
        }

        let d = oracle_seckey.negate_if(self.oracle_pubkey.parity());
        let k = nonce.negate_if(self.nonce_point.parity());

        let msg = &self.outcome_messages.get(index)?;
        let e: MaybeScalar = musig2::compute_challenge_hash_tweak(
            &self.nonce_point.serialize_xonly(),
            &self.oracle_pubkey,
            msg,
        );
        Some(k + e * d)
    }
}
