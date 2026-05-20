//! Types for external signing of DLC transactions.
//!
//! This module provides types for signing DLC transactions using an external
//! signing system such as HSMs, secure enclaves, or custom MuSig2
//! implementations.
//!
//! For most use cases, [`SigningSession`][crate::SigningSession] is the preferred
//! approach as it handles nonce generation, aggregation, and signature verification
//! automatically.

use crate::contract::{Outcome, OutcomeIndex, WinCondition};
use secp::{MaybePoint, Point};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// All data needed to sign a DLC using an external signing system.
///
/// Contains sighashes and metadata needed to produce MuSig2 signatures for a
/// ticketed DLC without using [`SigningSession`][crate::SigningSession].
///
/// Attestation outcomes require adaptor signatures using the corresponding
/// [`adaptor_points`][Self::adaptor_points] entry. Expiry and split transactions
/// use regular MuSig2 signatures.
///
/// Outcome transactions are signed with [`funding_agg_pubkey`][Self::funding_agg_pubkey]
/// (tweaked aggregate key). Split transactions are signed with the untweaked
/// key from [`split_agg_pubkeys`][Self::split_agg_pubkeys].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningData {
    /// Sighash for each outcome transaction. Attestation outcomes use adaptor
    /// signatures; expiry uses a regular signature.
    pub outcome_sighashes: BTreeMap<Outcome, [u8; 32]>,

    /// Adaptor points for attestation outcomes, derived from the oracle's
    /// locking point. Expiry outcomes do not have an entry here.
    pub adaptor_points: BTreeMap<OutcomeIndex, MaybePoint>,

    /// Sighash for each split transaction. Keyed by [`WinCondition`] which
    /// specifies the outcome and winning player. Always uses regular signatures.
    pub split_sighashes: BTreeMap<WinCondition, [u8; 32]>,

    /// Tweaked aggregate public key for the funding output. Used for signing
    /// outcome transactions.
    pub funding_agg_pubkey: Point,

    /// Untweaked aggregate public keys for split transaction signing. Split
    /// transactions spend via a tapscript path, so they use the untweaked key.
    pub split_agg_pubkeys: BTreeMap<Outcome, Point>,
}

impl SigningData {
    /// Returns the total number of signatures needed (outcome + split transactions).
    pub fn total_signature_count(&self) -> usize {
        self.outcome_sighashes.len() + self.split_sighashes.len()
    }

    /// Returns true if the given outcome requires an adaptor signature.
    pub fn requires_adaptor(&self, outcome: &Outcome) -> bool {
        match outcome {
            Outcome::Attestation(idx) => self.adaptor_points.contains_key(idx),
            Outcome::Expiry => false,
        }
    }

    /// Returns the adaptor point for an attestation outcome, or `None` for
    /// expiry outcomes or unknown indexes.
    pub fn get_adaptor_point(&self, outcome_index: OutcomeIndex) -> Option<&MaybePoint> {
        self.adaptor_points.get(&outcome_index)
    }
}
