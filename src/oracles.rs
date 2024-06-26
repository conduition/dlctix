use secp::{MaybePoint, MaybeScalar, Point, Scalar};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Outcome;

/// The locking points derived from the oracle's announcement of a future event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventLockingConditions {
    /// An array of locking points which represent distinct outcomes. Each locking point
    /// should have its discrete log revealed by the oracle when and if that outcome occurs.
    pub locking_points: Vec<MaybePoint>,

    /// The unix timestamp beyond which the oracle is considered to have gone AWOL.
    /// If set to `None`, the event has no expected expiry.
    pub expiry: Option<u32>,
}

impl EventLockingConditions {
    /// Returns true if the given outcome is a valid outcome to wager on
    /// for this event.
    pub fn is_valid_outcome(&self, outcome: &Outcome) -> bool {
        match outcome {
            &Outcome::Attestation(i) => i < self.locking_points.len(),
            Outcome::Expiry => self.expiry.is_some(),
        }
    }

    /// Returns an iterator over all possible outcomes in the event.
    pub fn all_outcomes(&self) -> impl IntoIterator<Item = Outcome> {
        (0..self.locking_points.len())
            .map(|i| Outcome::Attestation(i))
            .chain(self.expiry.map(|_| Outcome::Expiry))
    }
}

fn tagged_hash(tag: &str) -> Sha256 {
    let tag_hash = Sha256::new().chain_update(tag).finalize();
    Sha256::new()
        .chain_update(&tag_hash)
        .chain_update(&tag_hash)
}

pub(crate) fn outcome_message_hash(msg: impl AsRef<[u8]>) -> [u8; 32] {
    tagged_hash("DLC/oracle/attestation/v0")
        .chain_update(msg)
        .finalize()
        .into()
}

/// Computes the attestation locking point given an oracle pubkey, nonce, and message.
#[allow(non_snake_case)]
pub fn attestation_locking_point(
    oracle_pubkey: impl Into<Point>,
    nonce: impl Into<Point>,
    message: impl AsRef<[u8]>,
) -> MaybePoint {
    let oracle_pubkey = oracle_pubkey.into();
    let nonce = nonce.into();

    let R = nonce.to_even_y();
    let D = oracle_pubkey.to_even_y();

    let e: MaybeScalar = musig2::compute_challenge_hash_tweak(
        &nonce.serialize_xonly(),
        &oracle_pubkey,
        outcome_message_hash(message),
    );

    // S = R + eD
    R + e * D
}

/// Computes the oracle's attestation secret scalar - the discrete log of the
/// locking point - for the given outcome message.
pub fn attestation_secret(
    oracle_seckey: impl Into<Scalar>,
    nonce: impl Into<Scalar>,
    message: impl AsRef<[u8]>,
) -> MaybeScalar {
    let oracle_seckey = oracle_seckey.into();
    let nonce = nonce.into();

    let oracle_pubkey = oracle_seckey.base_point_mul();
    let nonce_point = nonce.base_point_mul();

    let d = oracle_seckey.negate_if(oracle_pubkey.parity());
    let k = nonce.negate_if(nonce_point.parity());

    let e: MaybeScalar = musig2::compute_challenge_hash_tweak(
        &nonce_point.serialize_xonly(),
        &oracle_pubkey,
        outcome_message_hash(message),
    );
    k + e * d
}
