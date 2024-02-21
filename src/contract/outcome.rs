use bitcoin::{absolute::LockTime, OutPoint, Sequence, Transaction, TxIn, TxOut};
use musig2::{AdaptorSignature, AggNonce, CompactSignature, PartialSignature, PubNonce, SecNonce};
use secp::Scalar;

use std::collections::BTreeMap;

use crate::{
    contract::{ContractParameters, Outcome},
    errors::Error,
    parties::Player,
    spend_info::{FundingSpendInfo, OutcomeSpendInfo},
};

/// Represents the output of building the set of outcome transactions.
/// This contains cached data used for constructing further transactions,
/// or signing the outcome transactions themselves.
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

    /// Returns the number of [`musig2`] partial signatures required by each player
    /// in the DLC (and the market maker).
    ///
    /// If the contract has an expiry payout condition, this is simply the number
    /// of outcomes plus one. Otherwise it is the number of outcomes exactly.
    pub(crate) fn signatures_required(&self) -> usize {
        self.outcome_txs.len()
    }
}

/// Construct a set of unsigned outcome transactions which spend from the funding TX.
pub(crate) fn build_outcome_txs(
    params: &ContractParameters,
    funding_outpoint: OutPoint,
) -> Result<OutcomeTransactionBuildOutput, Error> {
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
///
/// The number of signatures and nonces required can be computed by using
/// checking the length of [`OutcomeTransactionBuildOutput::signatures_required`].
pub(crate) fn partial_sign_outcome_txs<'a>(
    params: &ContractParameters,
    outcome_build_out: &OutcomeTransactionBuildOutput,
    seckey: Scalar,
    secnonces: impl IntoIterator<Item = SecNonce>,
    aggnonces: impl IntoIterator<Item = &'a AggNonce>,
) -> Result<BTreeMap<Outcome, PartialSignature>, Error> {
    let outcome_txs = &outcome_build_out.outcome_txs;
    let funding_spend_info = &outcome_build_out.funding_spend_info;

    // Confirm the key is a part of the group.
    funding_spend_info
        .key_agg_ctx()
        .pubkey_index(seckey.base_point_mul())
        .ok_or(Error)?;

    let mut outcome_partial_sigs = BTreeMap::<Outcome, PartialSignature>::new();

    let mut aggnonce_iter = aggnonces.into_iter();
    let mut secnonce_iter = secnonces.into_iter();

    for (&outcome, outcome_tx) in outcome_txs {
        let aggnonce = aggnonce_iter.next().ok_or(Error)?; // must provide enough aggnonces
        let secnonce = secnonce_iter.next().ok_or(Error)?; // must provide enough secnonces

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
///
/// The number of signatures and nonces required can be computed by using
/// checking the length of [`OutcomeTransactionBuildOutput::signatures_required`].
pub(crate) fn verify_outcome_tx_partial_signatures<'p, 'a>(
    params: &ContractParameters,
    outcome_build_out: &OutcomeTransactionBuildOutput,
    player: &Player,
    pubnonces: impl IntoIterator<Item = &'p PubNonce>,
    aggnonces: impl IntoIterator<Item = &'a AggNonce>,
    partial_signatures: impl IntoIterator<Item = PartialSignature>,
) -> Result<(), Error> {
    let outcome_txs = &outcome_build_out.outcome_txs;
    let funding_spend_info = &outcome_build_out.funding_spend_info;

    let mut aggnonce_iter = aggnonces.into_iter();
    let mut pubnonce_iter = pubnonces.into_iter();
    let mut partial_sig_iter = partial_signatures.into_iter();

    for (&outcome, outcome_tx) in outcome_txs {
        let aggnonce = aggnonce_iter.next().ok_or(Error)?; // must provide enough aggnonces
        let pubnonce = pubnonce_iter.next().ok_or(Error)?; // must provide enough pubnonces
        let partial_sig = partial_sig_iter.next().ok_or(Error)?; // must provide enough sigs

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
                    player.pubkey,
                    pubnonce,
                    sighash,
                )?;
            }

            Outcome::Expiry => {
                musig2::verify_partial(
                    funding_spend_info.key_agg_ctx(),
                    partial_sig,
                    aggnonce,
                    player.pubkey,
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
    pub(crate) adaptor_signatures: Vec<AdaptorSignature>,

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
pub(crate) fn aggregate_outcome_tx_adaptor_signatures<'a, S>(
    params: &ContractParameters,
    outcome_build_out: &OutcomeTransactionBuildOutput,
    aggnonces: impl IntoIterator<Item = &'a AggNonce>,
    partial_signature_groups: impl IntoIterator<Item = S>,
) -> Result<OutcomeSignatures, Error>
where
    S: IntoIterator<Item = PartialSignature>,
{
    let outcome_txs = &outcome_build_out.outcome_txs;
    let funding_spend_info = &outcome_build_out.funding_spend_info;

    let mut aggnonce_iter = aggnonces.into_iter();
    let mut partial_sig_group_iter = partial_signature_groups.into_iter();

    let mut signatures = OutcomeSignatures {
        adaptor_signatures: Vec::with_capacity(params.event.outcome_messages.len()),
        expiry_tx_signature: None,
    };

    for (&outcome, outcome_tx) in outcome_txs {
        // must provide a set of sigs for each TX
        let partial_sigs = partial_sig_group_iter.next().ok_or(Error)?;

        let aggnonce = aggnonce_iter.next().ok_or(Error)?; // must provide enough aggnonces

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

                signatures.adaptor_signatures.push(adaptor_sig);
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
