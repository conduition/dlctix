//! THIS IS A PLACEHOLDER PACKAGE. DO NOT INSTALL THIS.

pub(crate) mod consts;
pub(crate) mod contract;
pub(crate) mod errors;
pub(crate) mod oracles;
pub(crate) mod parties;
pub(crate) mod spend_info;

pub mod hashlock;

pub use secp;

use contract::{
    outcome::{OutcomeSignatures, OutcomeTransactionBuildOutput},
    split::SplitTransactionBuildOutput,
};
use errors::Error;

use bitcoin::{OutPoint, TxOut};
use musig2::{AdaptorSignature, AggNonce, CompactSignature, PartialSignature, PubNonce, SecNonce};
use secp::{Point, Scalar};

use std::collections::BTreeMap;

pub use contract::{ContractParameters, Outcome, SigMap, WinCondition};
pub use oracles::EventAnnouncement;
pub use parties::{MarketMaker, Player};

/// Represents the combined output of building all transactions and precomputing
/// all necessary data for a ticketed DLC.
pub struct TicketedDLC {
    params: ContractParameters,
    outcome_tx_build: OutcomeTransactionBuildOutput,
    split_tx_build: SplitTransactionBuildOutput,
}

impl TicketedDLC {
    /// Construct all ticketed DLC transactions and cache precomputed data for later signing.
    /// Returns an error if the contract parameters are invalid.
    pub fn new(
        params: ContractParameters,
        funding_outpoint: OutPoint,
    ) -> Result<TicketedDLC, Error> {
        params.validate()?;

        let outcome_tx_build = contract::outcome::build_outcome_txs(&params, funding_outpoint)?;
        let split_tx_build = contract::split::build_split_txs(&params, &outcome_tx_build)?;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractSignatures {
    /// A complete signature on the expiry transaction. Set to `None` if the
    /// [`ContractParameters::outcome_payouts`] field did not contain an
    /// [`Outcome::Expiry`] payout condition.
    pub expiry_tx_signature: Option<CompactSignature>,
    /// An ordered vector of adaptor signatures, corresponding to each of the outcomes
    /// in [`EventAnnouncement::outcome_messages`]. Each adaptor signature can be decrypted
    /// by the [`EventAnnouncement`]'s oracle producing an attestation signature using
    /// [`EventAnnouncement::attestation_secret`].
    pub outcome_tx_signatures: Vec<AdaptorSignature>,
    /// A set of signatures needed for broadcasting split transactions. Each signature
    /// is specific to a certain combination of player and outcome.
    pub split_tx_signatures: BTreeMap<WinCondition, CompactSignature>,
}

/// A [`SigningSessionState`] used for a complete signing session once
/// all signatures on the [`TicketedDLC`] have been aggregated and verified
/// successfully.
pub struct CompleteState {
    signatures: ContractSignatures,
}

impl SigningSessionState for NonceSharingRound {}
impl SigningSessionState for PartialSignatureSharingRound {}
impl SigningSessionState for CompleteState {}

/// This is a state machine to manage signing the various transactions in a [`TicketedDLC`].
pub struct SigningSession<S: SigningSessionState> {
    dlc: TicketedDLC,
    our_public_key: Point,
    state: S,
}

impl<S: SigningSessionState> SigningSession<S> {
    /// Return a reference to the [`TicketedDLC`] inside this signing session.
    pub fn dlc(&self) -> &TicketedDLC {
        &self.dlc
    }

    /// Return the public key of our signer.
    pub fn our_public_key(&self) -> Point {
        self.our_public_key
    }
}

impl SigningSession<NonceSharingRound> {
    /// Start a new signing session on the given TicketedDLC.
    pub fn new<R: rand::RngCore + rand::CryptoRng>(
        dlc: TicketedDLC,
        mut rng: &mut R,
        signing_key: impl Into<Scalar>,
    ) -> Result<SigningSession<NonceSharingRound>, Error> {
        let signing_key = signing_key.into();
        let our_public_key = signing_key.base_point_mul();

        let base_sigmap = dlc.params.sigmap_for_pubkey(our_public_key).ok_or(Error)?;

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
            our_public_key,
            state: NonceSharingRound {
                signing_key: signing_key.into(),
                our_secret_nonces,
                our_public_nonces,
            },
        };
        Ok(session)
    }

    /// The public nonces we should broadcast to other signers.
    pub fn our_public_nonces(&self) -> &SigMap<PubNonce> {
        &self.state.our_public_nonces
    }

    /// Receive the nonces from all other signers and construct our set of partial
    /// signatures. This begins the `PartialSignatureSharingRound` of the `SigningSession`.
    pub fn compute_partial_signatures(
        self,
        mut received_nonces: BTreeMap<Point, SigMap<PubNonce>>,
    ) -> Result<SigningSession<PartialSignatureSharingRound>, Error> {
        // Insert our own public nonces so that callers don't need
        // to inject them manually.
        received_nonces.insert(self.our_public_key, self.state.our_public_nonces);

        validate_sigmaps_completeness(&self.dlc.params, &received_nonces)?;

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
            by_outcome: contract::outcome::partial_sign_outcome_txs(
                &self.dlc.params,
                &self.dlc.outcome_tx_build,
                self.state.signing_key,
                self.state.our_secret_nonces.by_outcome,
                &aggregated_nonces.by_outcome,
            )?,
            by_win_condition: contract::split::partial_sign_split_txs(
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
            our_public_key: self.our_public_key,
            state: PartialSignatureSharingRound {
                received_nonces,
                aggregated_nonces,
                our_partial_signatures,
            },
        };
        Ok(session)
    }
}

impl SigningSession<PartialSignatureSharingRound> {
    /// Returns the set of partial signatures which should be shared
    /// with our signing peers.
    pub fn our_partial_signatures(&self) -> &SigMap<PartialSignature> {
        &self.state.our_partial_signatures
    }

    /// Returns the set of aggregated nonces which should be sent to
    /// our signing peers if they don't already have them.
    pub fn aggregated_nonces(&self) -> &SigMap<AggNonce> {
        &self.state.aggregated_nonces
    }

    /// Verify the signatures received from a particular signer. Returns an
    /// error if any signatures are missing, or if any signatures are not
    /// correct.
    pub fn verify_partial_signatures(
        &self,
        signer_pubkey: Point,
        partial_signatures: &SigMap<PartialSignature>,
    ) -> Result<(), Error> {
        let signer_nonces = self
            .state
            .received_nonces
            .get(&signer_pubkey)
            .ok_or(Error)?;

        contract::outcome::verify_outcome_tx_partial_signatures(
            &self.dlc.params,
            &self.dlc.outcome_tx_build,
            signer_pubkey,
            &signer_nonces.by_outcome,
            &self.state.aggregated_nonces.by_outcome,
            &partial_signatures.by_outcome,
        )?;

        contract::split::verify_split_tx_partial_signatures(
            &self.dlc.params,
            &self.dlc.outcome_tx_build,
            &self.dlc.split_tx_build,
            signer_pubkey,
            &signer_nonces.by_win_condition,
            &self.state.aggregated_nonces.by_win_condition,
            &partial_signatures.by_win_condition,
        )?;

        Ok(())
    }

    /// Combine all the partial signatures received from peers. Assumes all signature sets have
    /// been verified individually using [`verify_partial_signatures`][Self::verify_partial_signatures].
    /// The aggregated signatures will still be verified before this method returns, but not in
    /// a way that blame can be properly placed on erroneous peer signatures.
    ///
    /// This completes the signing session.
    pub fn aggregate_all_signatures(
        self,
        mut received_signatures: BTreeMap<Point, SigMap<PartialSignature>>,
    ) -> Result<SigningSession<CompleteState>, Error> {
        // Insert our own signatures so that callers don't need to inject them manually.
        received_signatures.insert(self.our_public_key, self.state.our_partial_signatures);

        validate_sigmaps_completeness(&self.dlc.params, &received_signatures)?;

        let full_sigmap = self.dlc.params.full_sigmap();

        // We were given a map of the partial signatures made by each signer. We
        // restructure them to map outcomes and win conditions into the full set of
        // partial signatures which should be aggregated per sighash.
        //
        // For each sighash we need to sign...
        let partial_signature_sets: SigMap<Vec<PartialSignature>> = full_sigmap.map(
            // Collect all the partial signatures needed for each outcome
            |outcome, _| {
                received_signatures
                    .values()
                    .filter_map(|sig_sigmap| sig_sigmap.by_outcome.get(&outcome).copied())
                    .collect::<Vec<PartialSignature>>()
            },
            // Collect all the partial signatures needed for each win condition
            |win_cond, _| {
                received_signatures
                    .values()
                    .filter_map(|sig_sigmap| sig_sigmap.by_win_condition.get(&win_cond).copied())
                    .collect::<Vec<PartialSignature>>()
            },
        );

        // Aggregate all the outcome TX signatures.
        let OutcomeSignatures {
            outcome_tx_signatures,
            expiry_tx_signature,
        } = contract::outcome::aggregate_outcome_tx_adaptor_signatures(
            &self.dlc.params,
            &self.dlc.outcome_tx_build,
            &self.state.aggregated_nonces.by_outcome,
            partial_signature_sets.by_outcome,
        )?;

        // Aggregate all the split TX signatures.
        let split_tx_signatures = contract::split::aggregate_split_tx_signatures(
            &self.dlc.outcome_tx_build,
            &self.dlc.split_tx_build,
            &self.state.aggregated_nonces.by_win_condition,
            partial_signature_sets.by_win_condition,
        )?;

        // Signing complete! Just have to send `signatures` to our peers.
        let complete_session = SigningSession {
            dlc: self.dlc,
            our_public_key: self.our_public_key,
            state: CompleteState {
                signatures: ContractSignatures {
                    expiry_tx_signature,
                    outcome_tx_signatures,
                    split_tx_signatures,
                },
            },
        };

        Ok(complete_session)
    }

    /// Verifies the complete set of contract signatures were aggregated correctly by a peer.
    ///
    /// This completes the signing session.
    pub fn verify_aggregated_signatures(
        &self,
        signatures: &ContractSignatures,
    ) -> Result<(), Error> {
        contract::outcome::verify_outcome_tx_aggregated_signatures(
            &self.dlc.params,
            &self.dlc.outcome_tx_build,
            &signatures.outcome_tx_signatures,
            signatures.expiry_tx_signature,
        )?;

        contract::split::verify_split_tx_aggregated_signatures(
            &self.dlc.params,
            &self.dlc.outcome_tx_build,
            &self.dlc.split_tx_build,
            &signatures.split_tx_signatures,
        )?;

        Ok(())
    }
}

/// This validates a set of sigmaps received from untrusted peers. Ensures
/// each sigmap contains a full set, matching the expected sigmap for the sender.
fn validate_sigmaps_completeness<T>(
    params: &ContractParameters,
    received_maps: &BTreeMap<Point, SigMap<T>>,
) -> Result<(), Error> {
    // Must receive signatures/nonces from all players and the market maker.
    if !received_maps.contains_key(&params.market_maker.pubkey) {
        return Err(Error);
    }
    for player in params.players.iter() {
        if !received_maps.contains_key(&player.pubkey) {
            return Err(Error);
        }
    }

    for (&signer_pubkey, sigmap) in received_maps.iter() {
        // The expected sigmap each signer must provide nonces/signatures for.
        let base_sigmap = params.sigmap_for_pubkey(signer_pubkey).ok_or(Error)?;

        // All signers' sigmaps must match exactly.
        if !sigmap.is_mirror(&base_sigmap) {
            return Err(Error);
        }
    }

    Ok(())
}

impl SigningSession<CompleteState> {
    pub fn signatures(&self) -> &ContractSignatures {
        &self.state.signatures
    }
}
