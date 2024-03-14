use bitcoin::{absolute::LockTime, OutPoint, Sequence, Transaction, TxIn, TxOut};
use musig2::{
    AdaptorSignature, AggNonce, BatchVerificationRow, CompactSignature, PartialSignature, PubNonce,
    SecNonce,
};
use secp::{Point, Scalar};

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    contract::{ContractParameters, Outcome, OutcomeIndex},
    errors::Error,
    spend_info::{FundingSpendInfo, OutcomeSpendInfo},
};

/// Represents the output of building the set of outcome transactions.
/// This contains cached data used for constructing further transactions,
/// or signing the outcome transactions themselves.
#[derive(Clone)]
pub(crate) struct OutcomeTransactionBuildOutput {
    outcome_txs: BTreeMap<Outcome, Transaction>,
    outcome_spend_infos: BTreeMap<Outcome, OutcomeSpendInfo>,
    funding_spend_info: FundingSpendInfo,
}

impl OutcomeTransactionBuildOutput {
    /// Return the set of mutually exclusive outcome transactions. One of these
    /// transactions will be executed depending on the oracle's attestation.
    pub(crate) fn outcome_txs(&self) -> &BTreeMap<Outcome, Transaction> {
        &self.outcome_txs
    }

    /// Return the set of mutually exclusive outcome spend info objects.
    pub(crate) fn outcome_spend_infos(&self) -> &BTreeMap<Outcome, OutcomeSpendInfo> {
        &self.outcome_spend_infos
    }

    /// Return the funding transaction's spending info object.
    pub(crate) fn funding_spend_info(&self) -> &FundingSpendInfo {
        &self.funding_spend_info
    }
}

/// Construct a set of unsigned outcome transactions which spend from the funding TX.
pub(crate) fn build_outcome_txs(
    params: &ContractParameters,
    funding_outpoint: OutPoint,
) -> Result<OutcomeTransactionBuildOutput, Error> {
    let all_players = params.sorted_players();

    let funding_input = TxIn {
        previous_output: funding_outpoint,
        sequence: Sequence::MAX,
        ..TxIn::default()
    };
    let outcome_value = params.outcome_output_value()?;

    let outcome_spend_infos: BTreeMap<Outcome, OutcomeSpendInfo> = params
        .outcome_payouts
        .iter()
        .map(|(&outcome, payout_map)| {
            let winners = payout_map.keys().copied();
            let spend_info = OutcomeSpendInfo::new(
                &all_players,
                winners,
                &params.market_maker,
                outcome_value,
                params.relative_locktime_block_delta,
            )?;
            Ok((outcome, spend_info))
        })
        .collect::<Result<_, Error>>()?;

    let outcome_txs: BTreeMap<Outcome, Transaction> = outcome_spend_infos
        .iter()
        .map(|(&outcome, outcome_spend_info)| {
            let outcome_output = TxOut {
                value: outcome_value,
                script_pubkey: outcome_spend_info.script_pubkey(),
            };

            let lock_time = match outcome {
                Outcome::Expiry => LockTime::from_consensus(params.event.expiry),
                Outcome::Attestation(_) => LockTime::ZERO, // Normal outcome transaction
            };

            let outcome_tx = Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time,
                input: vec![funding_input.clone()],
                output: vec![outcome_output],
            };

            (outcome, outcome_tx)
        })
        .collect();

    let funding_spend_info =
        FundingSpendInfo::new(&params.market_maker, &params.players, params.funding_value)?;

    let output = OutcomeTransactionBuildOutput {
        outcome_txs,
        outcome_spend_infos,
        funding_spend_info,
    };

    Ok(output)
}

/// Construct a set of partial signatures for the outcome transactions.
pub(crate) fn partial_sign_outcome_txs(
    params: &ContractParameters,
    outcome_build_out: &OutcomeTransactionBuildOutput,
    seckey: Scalar,
    mut secnonces: BTreeMap<Outcome, SecNonce>,
    aggnonces: &BTreeMap<Outcome, AggNonce>,
) -> Result<BTreeMap<Outcome, PartialSignature>, Error> {
    let outcome_txs = &outcome_build_out.outcome_txs;
    let funding_spend_info = &outcome_build_out.funding_spend_info;

    // Confirm the key is a part of the group.
    funding_spend_info
        .key_agg_ctx()
        .pubkey_index(seckey.base_point_mul())
        .ok_or(Error)?;

    let mut outcome_partial_sigs = BTreeMap::<Outcome, PartialSignature>::new();

    for (&outcome, outcome_tx) in outcome_txs {
        let aggnonce = aggnonces.get(&outcome).ok_or(Error)?; // must provide all aggnonces
        let secnonce = secnonces.remove(&outcome).ok_or(Error)?; // must provide all secnonces

        // Hash the outcome TX.
        let sighash = funding_spend_info.sighash_tx_outcome(outcome_tx)?;

        let partial_sig = match outcome {
            Outcome::Attestation(outcome_index) => {
                // All outcome TX signatures should be locked by the oracle's outcome point.
                let attestation_lock_point = params
                    .event
                    .attestation_lock_point(outcome_index)
                    .ok_or(Error)?;

                // sign under an attestation lock point
                musig2::adaptor::sign_partial(
                    funding_spend_info.key_agg_ctx(),
                    seckey,
                    secnonce,
                    aggnonce,
                    attestation_lock_point,
                    sighash,
                )?
            }

            Outcome::Expiry => musig2::sign_partial(
                funding_spend_info.key_agg_ctx(),
                seckey,
                secnonce,
                aggnonce,
                sighash,
            )?,
        };

        outcome_partial_sigs.insert(outcome, partial_sig);
    }
    Ok(outcome_partial_sigs)
}

/// Verify a player's partial adaptor signatures on the outcome transactions.
pub(crate) fn verify_outcome_tx_partial_signatures(
    params: &ContractParameters,
    outcome_build_out: &OutcomeTransactionBuildOutput,
    signer_pubkey: Point,
    pubnonces: &BTreeMap<Outcome, PubNonce>,
    aggnonces: &BTreeMap<Outcome, AggNonce>,
    partial_signatures: &BTreeMap<Outcome, PartialSignature>,
) -> Result<(), Error> {
    let outcome_txs = &outcome_build_out.outcome_txs;
    let funding_spend_info = &outcome_build_out.funding_spend_info;

    for (&outcome, outcome_tx) in outcome_txs {
        let aggnonce = aggnonces.get(&outcome).ok_or(Error)?; // must provide all aggnonces
        let pubnonce = pubnonces.get(&outcome).ok_or(Error)?; // must provide all pubnonces
        let &partial_sig = partial_signatures.get(&outcome).ok_or(Error)?; // must provide all sigs

        // Hash the outcome TX.
        let sighash = funding_spend_info.sighash_tx_outcome(outcome_tx)?;

        match outcome {
            Outcome::Attestation(outcome_index) => {
                // All outcome TX signatures should be locked by the oracle's outcome point.
                let attestation_lock_point = params
                    .event
                    .attestation_lock_point(outcome_index)
                    .ok_or(Error)?;

                musig2::adaptor::verify_partial(
                    funding_spend_info.key_agg_ctx(),
                    partial_sig,
                    aggnonce,
                    attestation_lock_point,
                    signer_pubkey,
                    pubnonce,
                    sighash,
                )?;
            }

            Outcome::Expiry => {
                musig2::verify_partial(
                    funding_spend_info.key_agg_ctx(),
                    partial_sig,
                    aggnonce,
                    signer_pubkey,
                    pubnonce,
                    sighash,
                )?;
            }
        };
    }

    Ok(())
}

/// The result of aggregating signatures from all signers on all outcome transactions,
/// optionally including an expiry transaction.
#[derive(Clone, Debug)]
pub(crate) struct OutcomeSignatures {
    /// A set of adaptor signatures which can be unlocked by the oracle's attestation
    /// for each outcome.
    pub(crate) outcome_tx_signatures: BTreeMap<OutcomeIndex, AdaptorSignature>,

    /// The complete signature on the expiry transaction. This is `None` if the
    /// [`ContractParameters::outcome_payouts`] field does not contain an
    /// [`Outcome::Expiry`] key.
    pub(crate) expiry_tx_signature: Option<CompactSignature>,
}

/// Aggregate groups of partial signatures for all outcome transactions.
///
/// Before running this method, the partial signatures should all have been
/// individually verified so that any blame can be assigned to signers
/// who submitted invalid signatures.
///
/// If all partial signatures are valid, then aggregation succeeds and this
/// function outputs a set of adaptor signatures which are valid once adapted
/// with the oracle's attestation.
pub(crate) fn aggregate_outcome_tx_adaptor_signatures<S>(
    params: &ContractParameters,
    outcome_build_out: &OutcomeTransactionBuildOutput,
    aggnonces: &BTreeMap<Outcome, AggNonce>,
    mut partial_signature_groups: BTreeMap<Outcome, S>,
) -> Result<OutcomeSignatures, Error>
where
    S: IntoIterator<Item = PartialSignature>,
{
    let outcome_txs = &outcome_build_out.outcome_txs;
    let funding_spend_info = &outcome_build_out.funding_spend_info;

    let mut signatures = OutcomeSignatures {
        outcome_tx_signatures: BTreeMap::new(),
        expiry_tx_signature: None,
    };

    for (&outcome, outcome_tx) in outcome_txs {
        // must provide a set of sigs for each TX
        let partial_sigs = partial_signature_groups.remove(&outcome).ok_or(Error)?;

        // must provide all aggnonces
        let aggnonce = aggnonces.get(&outcome).ok_or(Error)?;

        // Hash the outcome TX.
        let sighash = funding_spend_info.sighash_tx_outcome(outcome_tx)?;

        match outcome {
            Outcome::Attestation(outcome_index) => {
                let attestation_lock_point = params
                    .event
                    .attestation_lock_point(outcome_index)
                    .ok_or(Error)?;

                let adaptor_sig = musig2::adaptor::aggregate_partial_signatures(
                    funding_spend_info.key_agg_ctx(),
                    aggnonce,
                    attestation_lock_point,
                    partial_sigs,
                    sighash,
                )?;

                signatures
                    .outcome_tx_signatures
                    .insert(outcome_index, adaptor_sig);
            }

            Outcome::Expiry => {
                let signature: CompactSignature = musig2::aggregate_partial_signatures(
                    funding_spend_info.key_agg_ctx(),
                    aggnonce,
                    partial_sigs,
                    sighash,
                )?;

                signatures.expiry_tx_signature = Some(signature);
            }
        };
    }

    Ok(signatures)
}

/// Verify the set of complete aggregated signatures on the
/// outcome and expiry transactions.
pub(crate) fn verify_outcome_tx_aggregated_signatures(
    params: &ContractParameters,
    our_pubkey: Point,
    outcome_build_out: &OutcomeTransactionBuildOutput,
    outcome_tx_signatures: &BTreeMap<OutcomeIndex, AdaptorSignature>,
    expiry_tx_signature: Option<CompactSignature>,
) -> Result<(), Error> {
    let funding_spend_info = &outcome_build_out.funding_spend_info;

    let joint_pubkey: Point = funding_spend_info.key_agg_ctx().aggregated_pubkey();

    // We only need to verify signatures on outcomes where our pubkey might
    // win something.
    let relevant_outcomes: BTreeSet<Outcome> = params
        .win_conditions_controlled_by_pubkey(our_pubkey)
        .ok_or(Error)?
        .into_iter()
        .map(|win_cond| win_cond.outcome)
        .collect();

    // Construct a batch for efficient mass signature verification.
    let batch: Vec<BatchVerificationRow> = relevant_outcomes
        .into_iter()
        .map(|outcome| {
            let outcome_tx = outcome_build_out.outcome_txs.get(&outcome).ok_or(Error)?;

            let sighash = outcome_build_out
                .funding_spend_info
                .sighash_tx_outcome(outcome_tx)?;

            let batch_row = match outcome {
                // One adaptor signature for each possible attestation outcome.
                Outcome::Attestation(outcome_index) => {
                    let adaptor_point = params
                        .event
                        .attestation_lock_point(outcome_index)
                        .ok_or(Error)?;

                    let &signature = outcome_tx_signatures.get(&outcome_index).ok_or(Error)?;
                    BatchVerificationRow::from_adaptor_signature(
                        joint_pubkey,
                        sighash,
                        signature,
                        adaptor_point,
                    )
                }

                // One signature for the optional expiry transaction.
                Outcome::Expiry => {
                    let signature = expiry_tx_signature.ok_or(Error)?.lift_nonce()?;
                    BatchVerificationRow::from_signature(joint_pubkey, sighash, signature)
                }
            };

            Ok(batch_row)
        })
        .collect::<Result<_, Error>>()?;

    // Verify all outcome signatures at once.
    musig2::verify_batch(&batch)?;

    Ok(())
}

/// Construct an input to spend an outcome transaction for a specific outcome.
/// Also returns a reference to the outcome TX's output so it can be used
/// to construct a set of [`bitcoin::sighash::Prevouts`].
pub(crate) fn outcome_tx_prevout<'x>(
    outcome_build_out: &'x OutcomeTransactionBuildOutput,
    outcome: &Outcome,
    block_delay: u16,
) -> Result<(TxIn, &'x TxOut), Error> {
    let outcome_tx = outcome_build_out.outcome_txs().get(outcome).ok_or(Error)?;

    let outcome_input = TxIn {
        previous_output: OutPoint {
            txid: outcome_tx.txid(),
            vout: 0,
        },
        sequence: Sequence::from_height(block_delay),
        ..TxIn::default()
    };

    let prevout = outcome_tx.output.get(0).ok_or(Error)?;

    Ok((outcome_input, prevout))
}
