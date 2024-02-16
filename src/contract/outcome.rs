use bitcoin::{absolute::LockTime, OutPoint, Sequence, Transaction, TxIn, TxOut};
use musig2::{AdaptorSignature, AggNonce, PartialSignature, PubNonce, SecNonce};
use secp::Scalar;

use crate::{
    contract::ContractParameters,
    errors::Error,
    parties::Player,
    spend_info::{FundingSpendInfo, OutcomeSpendInfo},
};

pub(crate) struct OutcomeTransactionBuildOutput {
    pub(crate) outcome_txs: Vec<Transaction>,
    pub(crate) outcome_spend_infos: Vec<OutcomeSpendInfo>,
    funding_spend_info: FundingSpendInfo,
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

    let n_outcomes = params.event.outcome_messages.len();
    let outcome_spend_infos: Vec<OutcomeSpendInfo> = (0..n_outcomes)
        .map(|outcome_index| {
            let payout_map = params.outcome_payouts.get(outcome_index).ok_or(Error)?;
            let winners = payout_map.keys().copied();

            OutcomeSpendInfo::new(
                winners,
                &params.market_maker,
                outcome_value,
                params.relative_locktime_block_delta,
            )
        })
        .collect::<Result<_, Error>>()?;

    let outcome_txs: Vec<Transaction> = outcome_spend_infos
        .iter()
        .map(|outcome_spend_info| {
            let outcome_output = TxOut {
                value: outcome_value,
                script_pubkey: outcome_spend_info.script_pubkey(),
            };
            Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![funding_input.clone()],
                output: vec![outcome_output],
            }
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

pub(crate) fn partial_sign_outcome_txs<'a>(
    params: &ContractParameters,
    outcome_build_out: &OutcomeTransactionBuildOutput,
    seckey: impl Into<Scalar>,
    secnonces: impl IntoIterator<Item = SecNonce>,
    aggnonces: impl IntoIterator<Item = &'a AggNonce>,
) -> Result<Vec<PartialSignature>, Error> {
    let outcome_txs = &outcome_build_out.outcome_txs;
    let funding_spend_info = &outcome_build_out.funding_spend_info;

    // Confirm the key is a part of the group.
    let seckey = seckey.into();
    funding_spend_info
        .key_agg_ctx()
        .pubkey_index(seckey.base_point_mul())
        .ok_or(Error)?;

    let n_outcomes = params.event.outcome_messages.len();
    let mut outcome_partial_sigs = Vec::with_capacity(n_outcomes);

    let mut aggnonce_iter = aggnonces.into_iter();
    let mut secnonce_iter = secnonces.into_iter();

    for (outcome_index, outcome_tx) in outcome_txs.into_iter().enumerate() {
        let aggnonce = aggnonce_iter.next().ok_or(Error)?; // must provide enough aggnonces
        let secnonce = secnonce_iter.next().ok_or(Error)?; // must provide enough secnonces

        // All outcome TX signatures should be locked by the oracle's outcome point.
        let outcome_lock_point = params
            .event
            .outcome_lock_point(outcome_index)
            .ok_or(Error)?;

        // Hash the outcome TX.
        let sighash = funding_spend_info.sighash_tx_outcome(outcome_tx)?;

        // partially sign the sighash.
        let partial_sig = musig2::adaptor::sign_partial(
            funding_spend_info.key_agg_ctx(),
            seckey,
            secnonce,
            aggnonce,
            outcome_lock_point,
            sighash,
        )?;

        outcome_partial_sigs.push(partial_sig);
    }
    Ok(outcome_partial_sigs)
}

/// Verify a player's partial adaptor signatures on the outcome transactions.
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

    for (outcome_index, outcome_tx) in outcome_txs.into_iter().enumerate() {
        let aggnonce = aggnonce_iter.next().ok_or(Error)?; // must provide enough aggnonces
        let pubnonce = pubnonce_iter.next().ok_or(Error)?; // must provide enough aggnonces
        let partial_sig = partial_sig_iter.next().ok_or(Error)?; // must provide enough sigs

        // Hash the outcome TX.
        let sighash = funding_spend_info.sighash_tx_outcome(outcome_tx)?;

        // All outcome TX signatures should be locked by the oracle's outcome point.
        let outcome_lock_point = params
            .event
            .outcome_lock_point(outcome_index)
            .ok_or(Error)?;

        musig2::adaptor::verify_partial(
            funding_spend_info.key_agg_ctx(),
            partial_sig,
            aggnonce,
            outcome_lock_point,
            player.pubkey,
            pubnonce,
            sighash,
        )?;
    }

    Ok(())
}

pub(crate) fn aggregate_outcome_tx_adaptor_signatures<'a, S>(
    params: &ContractParameters,
    outcome_build_out: &OutcomeTransactionBuildOutput,
    aggnonces: impl IntoIterator<Item = &'a AggNonce>,
    partial_signature_groups: impl IntoIterator<Item = S>,
) -> Result<Vec<AdaptorSignature>, Error>
where
    S: IntoIterator<Item = PartialSignature>,
{
    let outcome_txs = &outcome_build_out.outcome_txs;
    let funding_spend_info = &outcome_build_out.funding_spend_info;

    let mut aggnonce_iter = aggnonces.into_iter();
    let mut partial_sig_group_iter = partial_signature_groups.into_iter();

    outcome_txs
        .into_iter()
        .enumerate()
        .map(|(outcome_index, outcome_tx)| {
            // must provide a set of sigs for each TX
            let partial_sigs = partial_sig_group_iter.next().ok_or(Error)?;

            let aggnonce = aggnonce_iter.next().ok_or(Error)?; // must provide enough aggnonces

            let outcome_lock_point = params
                .event
                .outcome_lock_point(outcome_index)
                .ok_or(Error)?;

            // Hash the outcome TX.
            let sighash = funding_spend_info.sighash_tx_outcome(outcome_tx)?;

            let adaptor_sig = musig2::adaptor::aggregate_partial_signatures(
                funding_spend_info.key_agg_ctx(),
                aggnonce,
                outcome_lock_point,
                partial_sigs,
                sighash,
            )?;

            Ok(adaptor_sig)
        })
        .collect()
}
