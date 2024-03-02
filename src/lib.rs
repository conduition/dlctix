//! THIS IS A PLACEHOLDER PACKAGE. DO NOT INSTALL THIS.

pub(crate) mod consts;
pub(crate) mod errors;
pub(crate) mod oracles;
pub(crate) mod parties;
pub(crate) mod spend_info;

pub mod contract;
pub mod hashlock;

pub use secp;

pub use parties::{MarketMaker, Player};

use contract::outcome::{
    build_outcome_txs, partial_sign_outcome_txs, OutcomeTransactionBuildOutput,
};
use contract::split::{build_split_txs, partial_sign_split_txs, SplitTransactionBuildOutput};
use contract::{ContractParameters, SigMap};
use errors::Error;

use bitcoin::{OutPoint, TxOut};
use musig2::{AggNonce, PartialSignature, PubNonce, SecNonce};
use secp::{Point, Scalar};

use std::collections::BTreeMap;

/// Represents the combined output of building all transactions and precomputing
/// all necessary data for a ticketed DLC.
pub struct TicketedDLC {
    params: ContractParameters,
    outcome_tx_build: OutcomeTransactionBuildOutput,
    split_tx_build: SplitTransactionBuildOutput,
}

impl TicketedDLC {
    /// Construct all ticketed DLC transactions and cache precomputed data for later signing.
    pub fn new(
        params: ContractParameters,
        funding_outpoint: OutPoint,
    ) -> Result<TicketedDLC, Error> {
        let outcome_tx_build = build_outcome_txs(&params, funding_outpoint)?;
        let split_tx_build = build_split_txs(&params, &outcome_tx_build)?;

        let txs = TicketedDLC {
            params,
            outcome_tx_build,
            split_tx_build,
        };
        Ok(txs)
    }

    /// Return the expected transaction output which the market maker should include
    /// in the funding transaction in order to fund the contract.
    ///
    /// This uses cached data which was computed during the initial contract construction,
    /// and so is more efficient than [`ContractParameters::funding_output`].
    pub fn funding_output(&self) -> TxOut {
        TxOut {
            script_pubkey: self.outcome_tx_build.funding_spend_info().script_pubkey(),
            value: self.params.funding_value,
        }
    }
}

/// A marker trait used to constrain the API of [`SigningSession`].
pub trait SigningSessionState {}

/// A [`SigningSessionState`] state for the initial nonce-sharing
/// round of communication.
pub struct NonceSharingRound {
    signing_key: Scalar,
    our_secret_nonces: SigMap<SecNonce>,
    our_public_nonces: SigMap<PubNonce>,
}

/// A [`SigningSessionState`] state for the second signature-sharing
/// round of communication. This assumes a mesh topology between
/// signers, where every signer sends their partial signatures to
/// everyone else.
pub struct PartialSignatureSharingRound {
    received_nonces: BTreeMap<Point, SigMap<PubNonce>>,
    aggregated_nonces: SigMap<AggNonce>,
    our_partial_signatures: SigMap<PartialSignature>,
}

impl SigningSessionState for NonceSharingRound {}
impl SigningSessionState for PartialSignatureSharingRound {}

/// This is a state machine to manage signing the various transactions in a [`TicketedDLC`].
pub struct SigningSession<S: SigningSessionState> {
    dlc: TicketedDLC,
    state: S,
}

impl<S: SigningSessionState> SigningSession<S> {
    /// Return a reference to the [`TicketedDLC`] inside this signing session.
    pub fn dlc(&self) -> &TicketedDLC {
        &self.dlc
    }
}

impl SigningSession<NonceSharingRound> {
    pub fn new<R: rand::RngCore + rand::CryptoRng>(
        dlc: TicketedDLC,
        mut rng: &mut R,
        signing_key: impl Into<Scalar>,
    ) -> Result<SigningSession<NonceSharingRound>, Error> {
        let signing_key = signing_key.into();

        let base_sigmap = dlc
            .params
            .sigmap_for_pubkey(signing_key.base_point_mul())
            .ok_or(Error)?;

        let our_secret_nonces = base_sigmap.map_values(|_| {
            SecNonce::build(&mut rng)
                .with_seckey(signing_key)
                // .with_extra_info(&self.dlc.params.serialize()) // TODO
                .build()
        });

        let our_public_nonces = our_secret_nonces
            .by_ref()
            .map_values(|secnonce| secnonce.public_nonce());

        let session = SigningSession {
            dlc,
            state: NonceSharingRound {
                signing_key: signing_key.into(),
                our_secret_nonces,
                our_public_nonces,
            },
        };
        Ok(session)
    }

    /// The public nonces we should send to other signers.
    pub fn our_public_nonces(&self) -> &SigMap<PubNonce> {
        &self.state.our_public_nonces
    }

    /// Receive the nonces from all other signers.
    pub fn compute_all_signatures(
        self,
        mut received_nonces: BTreeMap<Point, SigMap<PubNonce>>,
    ) -> Result<SigningSession<PartialSignatureSharingRound>, Error> {
        // Insert our own public nonces so that callers don't need
        // to inject them manually.
        received_nonces.insert(
            self.state.signing_key.base_point_mul(),
            self.state.our_public_nonces,
        );

        // Must receive nonces from all players and the market maker.
        if !received_nonces.contains_key(&self.dlc.params.market_maker.pubkey) {
            return Err(Error);
        }
        for player in self.dlc.params.players.iter() {
            if !received_nonces.contains_key(&player.pubkey) {
                return Err(Error);
            }
        }

        // The expected sigmaps each signer must provide nonces for.
        let base_sigmaps: BTreeMap<Point, SigMap<()>> = received_nonces
            .keys()
            .map(|&key| Ok((key, self.dlc.params.sigmap_for_pubkey(key).ok_or(Error)?)))
            .collect::<Result<_, Error>>()?;

        for (&signer_pubkey, nonces) in received_nonces.iter() {
            // All signers' sigmaps must match exactly.
            if !nonces.is_mirror(&base_sigmaps[&signer_pubkey]) {
                return Err(Error);
            }
        }

        let aggregated_nonces: SigMap<AggNonce> = self.dlc.params.full_sigmap().map(
            |outcome, _| {
                received_nonces
                    .values()
                    .filter_map(|nonce_sigmap| nonce_sigmap.by_outcome.get(&outcome))
                    .sum::<AggNonce>()
            },
            |win_cond, _| {
                received_nonces
                    .values()
                    .filter_map(|nonce_sigmap| nonce_sigmap.by_win_condition.get(&win_cond))
                    .sum::<AggNonce>()
            },
        );

        let our_partial_signatures = SigMap {
            by_outcome: partial_sign_outcome_txs(
                &self.dlc.params,
                &self.dlc.outcome_tx_build,
                self.state.signing_key,
                self.state.our_secret_nonces.by_outcome,
                &aggregated_nonces.by_outcome,
            )?,
            by_win_condition: partial_sign_split_txs(
                &self.dlc.params,
                &self.dlc.outcome_tx_build,
                &self.dlc.split_tx_build,
                self.state.signing_key,
                self.state.our_secret_nonces.by_win_condition,
                &aggregated_nonces.by_win_condition,
            )?,
        };

        let session = SigningSession {
            dlc: self.dlc,
            state: PartialSignatureSharingRound {
                received_nonces,
                aggregated_nonces,
                our_partial_signatures,
            },
        };
        Ok(session)
    }
}
