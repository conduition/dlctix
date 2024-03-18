use secp::{MaybePoint, MaybeScalar, Point, Scalar};
use serde::{Deserialize, Serialize};

use crate::{serialization, Outcome, OutcomeIndex};

/// An oracle's announcement of a future event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventAnnouncement {
    /// The signing oracle's pubkey
    pub oracle_pubkey: Point,

    /// The `R` point with which the oracle promises to attest to this event.
    pub nonce_point: Point,

    /// Naive but easy.
    #[serde(with = "serialization::vec_of_byte_vecs")]
    pub outcome_messages: Vec<Vec<u8>>,

    /// The unix timestamp beyond which the oracle is considered to have gone AWOL.
    /// If set to `None`, the event has no expected expiry.
    pub expiry: Option<u32>,
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

    /// Returns true if the given outcome is a valid outcome to wager on
    /// for this event.
    pub fn is_valid_outcome(&self, outcome: &Outcome) -> bool {
        match outcome {
            &Outcome::Attestation(i) => i < self.outcome_messages.len(),
            Outcome::Expiry => self.expiry.is_some(),
        }
    }

    /// Returns an iterator over all possible outcomes in the event.
    pub fn all_outcomes(&self) -> impl IntoIterator<Item = Outcome> {
        (0..self.outcome_messages.len())
            .map(|i| Outcome::Attestation(i))
            .chain(self.expiry.map(|_| Outcome::Expiry))
    }
}
