//! Crate documentation is TODO.
//!
//! See [the Github README](https://github.com/conduition/dlctix).

pub(crate) mod consts;
pub(crate) mod contract;
pub(crate) mod errors;
pub(crate) mod oracles;
pub(crate) mod parties;
pub(crate) mod serialization;
pub(crate) mod spend_info;

pub mod hashlock;

pub use secp;

use contract::{
    outcome::{OutcomeSignatures, OutcomeTransactionBuildOutput},
    split::SplitTransactionBuildOutput,
};
use errors::Error;
use hashlock::{sha256, Preimage};

use bitcoin::{
    sighash::Prevouts, transaction::InputWeightPrediction, OutPoint, Transaction, TxIn, TxOut,
};
use musig2::{AdaptorSignature, AggNonce, CompactSignature, PartialSignature, PubNonce, SecNonce};
use secp::{MaybeScalar, Point, Scalar};
use serde::{Deserialize, Serialize};

use std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet},
};

pub use contract::{
    ContractParameters, Outcome, OutcomeIndex, PayoutWeights, PlayerIndex, SigMap, WinCondition,
};
pub use oracles::EventAnnouncement;
pub use parties::{MarketMaker, Player};

/// Represents the combined output of building all transactions and precomputing
/// all necessary data for a ticketed DLC.
///
/// This type does not have any serialization methods or trait implementations, because
/// each party in the DLC is expected to use the [`ContractParameters`] to independently
/// construct the [`TicketedDLC`] transactions which they will sign. This reduces the
/// amount of data each party must validate. Instead of minutely inspecting thousands of
/// transactions, they should validate the properties of the [`ContractParameters`], and
/// thus be assured that if others are using the same [`ContractParameters`], then they
/// will be constructing and signing the same set of transactions.
///
/// [`TicketedDLC`] implements [`Clone`], but cloning should be done very sparingly, because
/// in real-world environments a [`TicketedDLC`] could easily encapsulate many thousands of
/// transactions involved, consuming megabytes of memory. Cloning it would be extremely
/// inefficient and potentially dangerous.
#[derive(Clone, Eq, PartialEq)]
pub struct TicketedDLC {
    params: ContractParameters,
    funding_outpoint: OutPoint,
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

        let dlc = TicketedDLC {
            params,
            funding_outpoint,
            outcome_tx_build,
            split_tx_build,
        };
        Ok(dlc)
    }

    /// Returns the contract parameters used to construct the DLC.
    pub fn params(&self) -> &ContractParameters {
        &self.params
    }

    /// Returns the funding outpoint used to construct the DLC.
    pub fn funding_outpoint(&self) -> OutPoint {
        self.funding_outpoint
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

impl std::fmt::Debug for TicketedDLC {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TicketedDLC")
            .field("params", self.params())
            .field("funding_outpoint", &self.funding_outpoint)
            .finish()
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
/// round of communication.
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
    ) -> Result<SignedContract, Error> {
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
        let signed_contract = SignedContract {
            dlc: self.dlc,
            signatures: ContractSignatures {
                expiry_tx_signature,
                outcome_tx_signatures,
                split_tx_signatures,
            },
        };

        Ok(signed_contract)
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
            self.our_public_key,
            &self.dlc.outcome_tx_build,
            &signatures.outcome_tx_signatures,
            signatures.expiry_tx_signature,
        )?;

        contract::split::verify_split_tx_aggregated_signatures(
            &self.dlc.params,
            self.our_public_key,
            &self.dlc.outcome_tx_build,
            &self.dlc.split_tx_build,
            &signatures.split_tx_signatures,
        )?;

        Ok(())
    }

    /// Consume the `SigningSession` and convert it into a [`SignedContract`]
    /// using the given set of signatures. The signatures should be verified
    /// with [`SigningSession::verify_aggregated_signatures`] first.
    pub fn into_signed_contract(self, signatures: ContractSignatures) -> SignedContract {
        SignedContract {
            signatures,
            dlc: self.dlc,
        }
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

/// A set of signatures produced by running a cooperative [`SigningSession`] on a
/// [`TicketedDLC`]. These are only the signatures needed for enforcing outcomes
/// which multiple members of the group must agree on.
///
/// Players do not need a fully copy of every outcome and split TX signature.
/// Only some players care about certain outcomes, and a player only enforce one
/// specific split TX unlock condition - the one corresponding to their ticket
/// hash. We can save bandwidth and
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContractSignatures {
    /// A complete signature on the expiry transaction. Set to `None` if the
    /// [`ContractParameters::outcome_payouts`] field did not contain an
    /// [`Outcome::Expiry`] payout condition.
    pub expiry_tx_signature: Option<CompactSignature>,
    /// A mapping of outcome attestation indexes to adaptor signatures on outcome transactions.
    /// The index of each entry corresponds to the outcomes in
    /// [`EventAnnouncement::outcome_messages`]. Each adaptor signature can be decrypted
    /// by the [`EventAnnouncement`]'s oracle producing an attestation signature using
    /// [`EventAnnouncement::attestation_secret`].
    pub outcome_tx_signatures: BTreeMap<OutcomeIndex, AdaptorSignature>,
    /// A set of signatures needed for broadcasting split transactions. Each signature
    /// is specific to a certain combination of player and outcome.
    pub split_tx_signatures: BTreeMap<WinCondition, CompactSignature>,
}

/// Represents a fully signed and enforceable [`TicketedDLC`], created
/// by running a [`SigningSession`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedContract {
    signatures: ContractSignatures,
    dlc: TicketedDLC,
}

impl SignedContract {
    /// Returns the complete set of signatures for all outcomes and win conditions.
    pub fn all_signatures(&self) -> &ContractSignatures {
        &self.signatures
    }

    /// Produce a pruned set of signatures, relevant to the specific signer's pubkey.
    /// If the pubkey belongs to the market maker, this simply returns a clone of the
    /// full set of signatures, since the market maker is involved in every multisignature
    /// spending condition.
    ///
    /// This method is used to reduce bandwidth requirements when transmitting aggregated
    /// signatures to players.
    pub fn pruned_signatures(&self, player_pubkey: Point) -> Option<ContractSignatures> {
        if player_pubkey == self.dlc.params.market_maker.pubkey {
            return Some(self.signatures.clone());
        }

        let relevant_win_conditions = self
            .dlc
            .params
            .win_conditions_claimable_by_pubkey(player_pubkey)?;

        let relevant_outcomes: BTreeSet<Outcome> = relevant_win_conditions
            .iter()
            .map(|win_cond| win_cond.outcome)
            .collect();

        let pruned_sigs = ContractSignatures {
            expiry_tx_signature: self
                .signatures
                .expiry_tx_signature
                .filter(|_| relevant_outcomes.contains(&Outcome::Expiry)),

            outcome_tx_signatures: self
                .signatures
                .outcome_tx_signatures
                .iter()
                .filter(|(&outcome_index, _)| {
                    relevant_outcomes.contains(&Outcome::Attestation(outcome_index))
                })
                .map(|(&outcome_index, &sig)| (outcome_index, sig))
                .collect(),

            split_tx_signatures: self
                .signatures
                .split_tx_signatures
                .iter()
                .filter(|(win_cond, _)| relevant_win_conditions.contains(win_cond))
                .map(|(&win_cond, &sig)| (win_cond, sig))
                .collect(),
        };

        Some(pruned_sigs)
    }

    /// Returns the [`TicketedDLC`] which has been signed.
    pub fn dlc(&self) -> &TicketedDLC {
        &self.dlc
    }

    /// Returns the contract parameters used to construct the DLC.
    pub fn params(&self) -> &ContractParameters {
        &self.dlc.params
    }

    /// Return an unsigned outcome transaction.
    pub fn unsigned_outcome_tx<'a>(
        &'a self,
        outcome_index: OutcomeIndex,
    ) -> Option<&'a Transaction> {
        self.dlc
            .outcome_tx_build
            .outcome_txs()
            .get(&Outcome::Attestation(outcome_index))
    }

    /// Return a signed outcome transaction given the oracle's attestation
    /// to a specific outcome.
    pub fn signed_outcome_tx(
        &self,
        outcome_index: OutcomeIndex,
        attestation: impl Into<MaybeScalar>,
    ) -> Result<Transaction, Error> {
        let attestation = attestation.into();
        let locking_point = self
            .dlc
            .params
            .event
            .attestation_lock_point(outcome_index)
            .ok_or(Error)?;

        // Invalid attestation.
        if attestation.base_point_mul() != locking_point {
            return Err(Error)?;
        }

        let mut outcome_tx = self
            .unsigned_outcome_tx(outcome_index)
            .ok_or(Error)?
            .clone();

        let adaptor_signature = self
            .signatures
            .outcome_tx_signatures
            .get(&outcome_index)
            .ok_or(Error)?;

        let compact_sig: CompactSignature = adaptor_signature.adapt(attestation).ok_or(Error)?;

        outcome_tx.input[0].witness.push(compact_sig.serialize());
        Ok(outcome_tx)
    }

    /// Return the signed expiry transaction, if one exists for this contract.
    pub fn expiry_tx(&self) -> Option<Transaction> {
        let mut expiry_tx = self
            .dlc
            .outcome_tx_build
            .outcome_txs()
            .get(&Outcome::Expiry)?
            .clone();

        let signature: CompactSignature = self.signatures.expiry_tx_signature?;
        expiry_tx.input[0].witness.push(signature.serialize());
        Some(expiry_tx)
    }

    /// Return the unsigned split transaction for the given outcome.
    pub fn unsigned_split_tx<'a>(&'a self, outcome: &Outcome) -> Option<&'a Transaction> {
        self.dlc.split_tx_build.split_txs().get(outcome)
    }

    /// Return a signed split transaction, given the ticket preimage for a specific player.
    pub fn signed_split_tx(
        &self,
        win_cond: &WinCondition,
        ticket_preimage: Preimage,
    ) -> Result<Transaction, Error> {
        let winner = self
            .dlc
            .params
            .sorted_players()
            .get(win_cond.player_index)
            .cloned()
            .ok_or(Error)?;

        // Verify the preimage will unlock this specific player's split TX
        // condition.
        if sha256(&ticket_preimage) != winner.ticket_hash {
            return Err(Error);
        }

        let signature = self
            .signatures
            .split_tx_signatures
            .get(win_cond)
            .ok_or(Error)?;

        let outcome_spend_info = self
            .dlc
            .outcome_tx_build
            .outcome_spend_infos()
            .get(&win_cond.outcome)
            .ok_or(Error)?;

        let witness = outcome_spend_info.witness_tx_split(
            signature,
            ticket_preimage,
            &win_cond.player_index,
        )?;

        let mut split_tx = self
            .unsigned_split_tx(&win_cond.outcome)
            .ok_or(Error)?
            .clone();

        split_tx.input[0].witness = witness;

        Ok(split_tx)
    }

    pub fn outcome_reclaim_tx_input_and_prevout<'a>(
        &'a self,
        outcome: &Outcome,
    ) -> Result<(TxIn, &'a TxOut), Error> {
        contract::outcome::outcome_tx_prevout(
            &self.dlc.outcome_tx_build,
            outcome,
            2 * self.dlc.params.relative_locktime_block_delta,
        )
    }

    pub fn outcome_close_tx_input_and_prevout<'a>(
        &'a self,
        outcome: &Outcome,
    ) -> Result<(TxIn, &'a TxOut), Error> {
        contract::outcome::outcome_tx_prevout(&self.dlc.outcome_tx_build, outcome, 0)
    }

    pub fn split_win_tx_input_and_prevout<'a>(
        &'a self,
        win_cond: &WinCondition,
    ) -> Result<(TxIn, &'a TxOut), Error> {
        contract::split::split_tx_prevout(
            &self.dlc.params,
            &self.dlc.split_tx_build,
            win_cond,
            self.dlc.params.relative_locktime_block_delta,
        )
    }

    pub fn split_reclaim_tx_input_and_prevout<'a>(
        &'a self,
        win_cond: &WinCondition,
    ) -> Result<(TxIn, &'a TxOut), Error> {
        contract::split::split_tx_prevout(
            &self.dlc.params,
            &self.dlc.split_tx_build,
            win_cond,
            2 * self.dlc.params.relative_locktime_block_delta,
        )
    }

    pub fn split_sellback_tx_input_and_prevout<'a>(
        &'a self,
        win_cond: &WinCondition,
    ) -> Result<(TxIn, &'a TxOut), Error> {
        contract::split::split_tx_prevout(&self.dlc.params, &self.dlc.split_tx_build, win_cond, 0)
    }

    pub fn outcome_reclaim_tx_input_weight(
        &self,
        outcome: &Outcome,
    ) -> Option<InputWeightPrediction> {
        self.dlc
            .outcome_tx_build
            .outcome_spend_infos()
            .get(outcome)
            .map(|outcome_spend_info| outcome_spend_info.input_weight_for_reclaim_tx())
    }

    pub fn split_win_tx_input_weight(&self) -> InputWeightPrediction {
        // All win TXs have the same input weight.
        self.dlc
            .split_tx_build
            .split_spend_infos()
            .values()
            .next()
            .unwrap()
            .input_weight_for_win_tx()
    }

    pub fn split_reclaim_tx_input_weight(&self) -> InputWeightPrediction {
        // All reclaim TXs have the same input weight.
        self.dlc
            .split_tx_build
            .split_spend_infos()
            .values()
            .next()
            .unwrap()
            .input_weight_for_reclaim_tx()
    }

    pub fn split_sellback_tx_input_weight(&self) -> InputWeightPrediction {
        // All sellback TXs have the same input weight.
        self.dlc
            .split_tx_build
            .split_spend_infos()
            .values()
            .next()
            .unwrap()
            .input_weight_for_sellback_tx()
    }

    pub fn sign_outcome_reclaim_tx_input<T: Borrow<TxOut>>(
        &self,
        outcome: &Outcome,
        reclaim_tx: &mut Transaction,
        input_index: usize,
        prevouts: &Prevouts<T>,
        market_maker_secret_key: impl Into<Scalar>,
    ) -> Result<(), Error> {
        let market_maker_secret_key = market_maker_secret_key.into();
        if market_maker_secret_key.base_point_mul() != self.dlc.params.market_maker.pubkey {
            return Err(Error);
        }

        // Confirm we're signing the correct input
        let (expected_input, expected_prevout) =
            self.outcome_reclaim_tx_input_and_prevout(outcome)?;
        check_input_matches_expected(
            reclaim_tx,
            prevouts,
            input_index,
            &expected_input,
            expected_prevout,
        )?;

        let outcome_spend_info = self
            .dlc
            .outcome_tx_build
            .outcome_spend_infos()
            .get(outcome)
            .ok_or(Error)?;

        let witness = outcome_spend_info.witness_tx_reclaim(
            reclaim_tx,
            input_index,
            prevouts,
            market_maker_secret_key,
        )?;

        reclaim_tx.input[input_index].witness = witness;
        Ok(())
    }

    /// Sign a cooperative closing transaction which spends the outcome transaction output.
    /// The market maker can use this method once they have issued off-chain payouts to
    /// all winning players for an outcome. Once the players have their payouts, they can
    /// send their secret keys to the market maker to let him reclaim all the on-chain
    /// capital.
    pub fn sign_outcome_close_tx_input<T: Borrow<TxOut>>(
        &self,
        outcome: &Outcome,
        close_tx: &mut Transaction,
        input_index: usize,
        prevouts: &Prevouts<T>,
        market_maker_secret_key: impl Into<Scalar>,
        player_secret_keys: &BTreeMap<Point, Scalar>,
    ) -> Result<(), Error> {
        let market_maker_secret_key = market_maker_secret_key.into();
        if market_maker_secret_key.base_point_mul() != self.dlc.params.market_maker.pubkey {
            return Err(Error);
        }

        // Confirm we're signing the correct input
        let (mut expected_input, expected_prevout) =
            self.outcome_close_tx_input_and_prevout(outcome)?;

        // The caller can use whatever sequence they want.
        expected_input.sequence = close_tx.input.get(input_index).ok_or(Error)?.sequence;

        check_input_matches_expected(
            close_tx,
            prevouts,
            input_index,
            &expected_input,
            expected_prevout,
        )?;

        let outcome_spend_info = self
            .dlc
            .outcome_tx_build
            .outcome_spend_infos()
            .get(outcome)
            .ok_or(Error)?;

        let witness = outcome_spend_info.witness_tx_close(
            close_tx,
            input_index,
            prevouts,
            market_maker_secret_key,
            player_secret_keys,
        )?;

        close_tx.input[input_index].witness = witness;
        Ok(())
    }

    pub fn sign_split_win_tx_input<T: Borrow<TxOut>>(
        &self,
        win_cond: &WinCondition,
        win_tx: &mut Transaction,
        input_index: usize,
        prevouts: &Prevouts<T>,
        ticket_preimage: Preimage,
        player_secret_key: impl Into<Scalar>,
    ) -> Result<(), Error> {
        let winner = self
            .dlc
            .params
            .sorted_players()
            .get(win_cond.player_index)
            .cloned()
            .ok_or(Error)?;

        let player_secret_key = player_secret_key.into();
        if player_secret_key.base_point_mul() != winner.pubkey {
            return Err(Error);
        } else if sha256(&ticket_preimage) != winner.ticket_hash {
            return Err(Error);
        }

        // Confirm we're signing the correct input
        let (expected_input, expected_prevout) = self.split_win_tx_input_and_prevout(win_cond)?;
        check_input_matches_expected(
            win_tx,
            prevouts,
            input_index,
            &expected_input,
            expected_prevout,
        )?;

        let split_spend_info = self
            .dlc
            .split_tx_build
            .split_spend_infos()
            .get(win_cond)
            .ok_or(Error)?;

        let witness = split_spend_info.witness_tx_win(
            win_tx,
            input_index,
            prevouts,
            ticket_preimage,
            player_secret_key,
        )?;

        win_tx.input[input_index].witness = witness;
        Ok(())
    }

    pub fn sign_split_reclaim_tx_input<T: Borrow<TxOut>>(
        &self,
        win_cond: &WinCondition,
        reclaim_tx: &mut Transaction,
        input_index: usize,
        prevouts: &Prevouts<T>,
        market_maker_secret_key: impl Into<Scalar>,
    ) -> Result<(), Error> {
        let market_maker_secret_key = market_maker_secret_key.into();
        if market_maker_secret_key.base_point_mul() != self.dlc.params.market_maker.pubkey {
            return Err(Error);
        }

        // Confirm we're signing the correct input
        let (expected_input, expected_prevout) =
            self.split_reclaim_tx_input_and_prevout(win_cond)?;
        check_input_matches_expected(
            reclaim_tx,
            prevouts,
            input_index,
            &expected_input,
            expected_prevout,
        )?;

        let split_spend_info = self
            .dlc
            .split_tx_build
            .split_spend_infos()
            .get(win_cond)
            .ok_or(Error)?;

        let witness = split_spend_info.witness_tx_reclaim(
            reclaim_tx,
            input_index,
            prevouts,
            market_maker_secret_key,
        )?;

        reclaim_tx.input[input_index].witness = witness;
        Ok(())
    }

    pub fn sign_split_sellback_tx_input<T: Borrow<TxOut>>(
        &self,
        win_cond: &WinCondition,
        sellback_tx: &mut Transaction,
        input_index: usize,
        prevouts: &Prevouts<T>,
        payout_preimage: Preimage,
        market_maker_secret_key: impl Into<Scalar>,
    ) -> Result<(), Error> {
        let market_maker_secret_key = market_maker_secret_key.into();
        if market_maker_secret_key.base_point_mul() != self.dlc.params.market_maker.pubkey {
            return Err(Error);
        }

        // Confirm we're signing the correct input
        let (mut expected_input, expected_prevout) =
            self.split_sellback_tx_input_and_prevout(win_cond)?;

        // The caller can use whatever sequence they want.
        expected_input.sequence = sellback_tx.input.get(input_index).ok_or(Error)?.sequence;

        check_input_matches_expected(
            sellback_tx,
            prevouts,
            input_index,
            &expected_input,
            expected_prevout,
        )?;

        let split_spend_info = self
            .dlc
            .split_tx_build
            .split_spend_infos()
            .get(win_cond)
            .ok_or(Error)?;

        let witness = split_spend_info.witness_tx_sellback(
            sellback_tx,
            input_index,
            prevouts,
            payout_preimage,
            market_maker_secret_key,
        )?;

        sellback_tx.input[input_index].witness = witness;
        Ok(())
    }

    /// Sign a cooperative closing transaction which spends a player's split transaction output.
    /// The market maker can use this method once they have issued off-chain payouts to this
    /// winning player. Once the player has her off-chain payout, they can send their secret
    /// key to the market maker to let him reclaim all the on-chain capital efficiently.
    pub fn sign_split_close_tx_input<T: Borrow<TxOut>>(
        &self,
        win_cond: &WinCondition,
        close_tx: &mut Transaction,
        input_index: usize,
        prevouts: &Prevouts<T>,
        market_maker_secret_key: impl Into<Scalar>,
        player_secret_key: impl Into<Scalar>,
    ) -> Result<(), Error> {
        let market_maker_secret_key = market_maker_secret_key.into();
        if market_maker_secret_key.base_point_mul() != self.dlc.params.market_maker.pubkey {
            return Err(Error);
        }

        // Confirm we're signing the correct input
        let (mut expected_input, expected_prevout) =
            self.split_sellback_tx_input_and_prevout(win_cond)?;

        // The caller can use whatever sequence they want.
        expected_input.sequence = close_tx.input.get(input_index).ok_or(Error)?.sequence;

        check_input_matches_expected(
            close_tx,
            prevouts,
            input_index,
            &expected_input,
            expected_prevout,
        )?;

        let split_spend_info = self
            .dlc
            .split_tx_build
            .split_spend_infos()
            .get(win_cond)
            .ok_or(Error)?;

        let witness = split_spend_info.witness_tx_close(
            close_tx,
            input_index,
            prevouts,
            market_maker_secret_key,
            player_secret_key.into(),
        )?;

        close_tx.input[input_index].witness = witness;
        Ok(())
    }
}

/// Validate that a given `Transaction` and `Prevouts` set match the expected
/// input/prevout pair for a given index on that `Transaction`'s inputs.
fn check_input_matches_expected<T: Borrow<TxOut>>(
    tx: &Transaction,
    prevouts: &Prevouts<T>,
    input_index: usize,
    expected_input: &TxIn,
    expected_prevout: &TxOut,
) -> Result<(), Error> {
    let input = tx.input.get(input_index).ok_or(Error)?;
    if input != expected_input {
        return Err(Error);
    }

    let prevout = match prevouts {
        Prevouts::All(all_prevouts) => all_prevouts.get(input_index).ok_or(Error)?.borrow(),
        Prevouts::One(i, prevout) => {
            if i != &input_index {
                return Err(Error)?;
            }
            prevout.borrow()
        }
    };

    if prevout != expected_prevout {
        return Err(Error);
    }

    Ok(())
}
