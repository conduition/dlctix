use bitcoin::{absolute::LockTime, Amount, OutPoint, Sequence, Transaction, TxIn, TxOut};
use musig2::{AggNonce, CompactSignature, PartialSignature, PubNonce, SecNonce};
use secp::Scalar;

use crate::{
    consts::{P2TR_DUST_VALUE, P2TR_SCRIPT_PUBKEY_SIZE},
    contract::{self, fees, outcome::OutcomeTransactionBuildOutput},
    contract::{ContractParameters, WinCondition},
    errors::Error,
    parties::Player,
    spend_info::SplitSpendInfo,
};

use std::{borrow::Borrow, collections::BTreeMap};

/// Represents the output of building the set of split transactions.
/// This contains cached data used for constructing further transactions,
/// or signing the split transactions themselves.
pub(crate) struct SplitTransactionBuildOutput {
    split_txs: Vec<Transaction>,
    split_spend_infos: BTreeMap<WinCondition, SplitSpendInfo>,
}

impl SplitTransactionBuildOutput {
    /// Return the set of mutually exclusive split transactions. Each of these
    /// transactions spend from a corresponding previous outcome transaction.
    pub fn split_txs(&self) -> &[Transaction] {
        &self.split_txs
    }
}

/// Build the set of split transactions which splits an outcome TX into per-player
/// payout contracts between the player and the market maker.
pub(crate) fn build_split_txs(
    params: &ContractParameters,
    outcome_build_output: &OutcomeTransactionBuildOutput,
) -> Result<SplitTransactionBuildOutput, Error> {
    let n_outcomes = params.outcome_payouts.len();
    let mut split_spend_infos = BTreeMap::<WinCondition, SplitSpendInfo>::new();
    let mut split_txs = Vec::<Transaction>::with_capacity(n_outcomes);

    for outcome_index in 0..params.outcome_payouts.len() {
        let payout_map = params.outcome_payouts.get(outcome_index).ok_or(Error)?;

        let outcome_spend_info = &outcome_build_output
            .outcome_spend_infos
            .get(outcome_index)
            .ok_or(Error)?;

        // Fee estimation
        let input_weight = outcome_spend_info.input_weight_for_split_tx();
        let spk_lengths = std::iter::repeat(P2TR_SCRIPT_PUBKEY_SIZE).take(payout_map.len());
        let fee_total = fees::fee_calc_safe(params.fee_rate, [input_weight], spk_lengths)?;

        // Mining fees are distributed equally among all winners, regardless of payout weight.
        let fee_shared = fee_total / payout_map.len() as u64;
        let total_payout_weight: u64 = payout_map.values().copied().sum();

        let outcome_input = contract::outcome::outcome_tx_prevout(
            outcome_build_output,
            outcome_index,
            params.relative_locktime_block_delta, // Split TXs have 1*delta block delay
        )?;

        // payout_map is a btree, so outputs are automatically sorted by player.
        let mut split_tx_outputs = Vec::with_capacity(payout_map.len());
        for (&player, &payout_weight) in payout_map.iter() {
            // Payout amounts are computed by using relative weights.
            let payout = outcome_spend_info.outcome_value() * payout_weight / total_payout_weight;
            let payout_value = fees::fee_subtract_safe(payout, fee_shared, P2TR_DUST_VALUE)?;

            let split_spend_info = SplitSpendInfo::new(
                player,
                &params.market_maker,
                payout_value,
                params.relative_locktime_block_delta,
            )?;

            split_tx_outputs.push(TxOut {
                value: payout_value,
                script_pubkey: split_spend_info.script_pubkey(),
            });

            let win_cond = WinCondition {
                winner: player,
                outcome_index,
            };
            split_spend_infos.insert(win_cond, split_spend_info);
        }

        split_txs.push(Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![outcome_input],
            output: split_tx_outputs,
        });
    }

    let output = SplitTransactionBuildOutput {
        split_txs,
        split_spend_infos,
    };

    Ok(output)
}

/// Sign all split script spend paths for every split transaction needed.
///
/// Players only need to sign split transactions for outcomes in which
/// they are paid out by the DLC. Outcomes in which a player knows they
/// will not win any money are irrelevant to that player.
///
/// The market maker must sign every split script spending path of every
/// split transaction.
pub(crate) fn partial_sign_split_txs<'a>(
    params: &ContractParameters,
    outcome_build_out: &OutcomeTransactionBuildOutput,
    split_build_out: &SplitTransactionBuildOutput,
    seckey: impl Into<Scalar>,
    secnonces: impl IntoIterator<Item = SecNonce>,
    aggnonces: impl IntoIterator<Item = &'a AggNonce>,
) -> Result<BTreeMap<WinCondition, PartialSignature>, Error> {
    let seckey = seckey.into();
    let pubkey = seckey.base_point_mul();

    let mut partial_signatures = BTreeMap::<WinCondition, PartialSignature>::new();

    let win_conditions_to_sign = params
        .win_conditions_controlled_by_pubkey(pubkey)
        .ok_or(Error)?;
    if win_conditions_to_sign.is_empty() {
        return Ok(partial_signatures);
    }

    let split_txs = &split_build_out.split_txs;

    let mut aggnonce_iter = aggnonces.into_iter();
    let mut secnonce_iter = secnonces.into_iter();

    for win_cond in win_conditions_to_sign {
        let split_tx = split_txs.get(win_cond.outcome_index).ok_or(Error)?;

        let aggnonce = aggnonce_iter.next().ok_or(Error)?; // must provide enough aggnonces
        let secnonce = secnonce_iter.next().ok_or(Error)?; // must provide enough secnonces

        // Hash the split TX.
        let outcome_spend_info = outcome_build_out
            .outcome_spend_infos
            .get(win_cond.outcome_index)
            .ok_or(Error)?;

        let sighash = outcome_spend_info.sighash_tx_split(split_tx, &win_cond.winner)?;

        // Partially sign the sighash.
        // We must use the untweaked musig key to sign the split script spend,
        // because that's the key we pushed to the script.
        let partial_sig = musig2::sign_partial(
            outcome_spend_info.key_agg_ctx_untweaked(),
            seckey,
            secnonce,
            aggnonce,
            sighash,
        )?;

        partial_signatures.insert(win_cond, partial_sig);
    }

    Ok(partial_signatures)
}

/// Verify the partial signatures provided by a signer across every split transaction.
///
/// Since each split transaction may require multiple signatures (one for each [`WinCondition`]),
/// the nonces and signatures must be provided in the form of a [`BTreeMap`], which maps
/// a [`WinCondition`] to the appropriate signature for that script spending path.
/// If any signatures or nonces are missing, this method returns an error.
pub(crate) fn verify_split_tx_partial_signatures(
    params: &ContractParameters,
    outcome_build_out: &OutcomeTransactionBuildOutput,
    split_build_out: &SplitTransactionBuildOutput,
    player: &Player,
    pubnonces: &BTreeMap<WinCondition, PubNonce>,
    aggnonces: &BTreeMap<WinCondition, AggNonce>,
    partial_signatures: &BTreeMap<WinCondition, PartialSignature>,
) -> Result<(), Error> {
    let win_conditions_to_sign = params
        .win_conditions_controlled_by_pubkey(player.pubkey)
        .ok_or(Error)?;

    let split_txs = &split_build_out.split_txs;

    for win_cond in win_conditions_to_sign {
        let split_tx = split_txs.get(win_cond.outcome_index).ok_or(Error)?;

        let aggnonce = aggnonces.get(&win_cond).ok_or(Error)?; // must provide all aggnonces
        let pubnonce = pubnonces.get(&win_cond).ok_or(Error)?; // must provide all pubnonces
        let partial_sig = partial_signatures.get(&win_cond).copied().ok_or(Error)?; // must provide all sigs

        let outcome_spend_info = outcome_build_out
            .outcome_spend_infos
            .get(win_cond.outcome_index)
            .ok_or(Error)?;

        // Hash the split TX.
        let sighash = outcome_spend_info.sighash_tx_split(split_tx, &win_cond.winner)?;

        // Verifies the player's partial signature on the split TX for one specific script path spend.
        musig2::verify_partial(
            outcome_spend_info.key_agg_ctx_untweaked(),
            partial_sig,
            aggnonce,
            player.pubkey,
            pubnonce,
            sighash,
        )?;
    }

    Ok(())
}

/// Aggregate all partial signatures on every spending path of all split transactions.
///
/// Since each split transaction may require multiple signatures (one for each [`WinCondition`]),
/// the nonces and signatures must be provided in the form of a [`BTreeMap`], which maps
/// a [`WinCondition`] to the appropriate signature for that script spending path.
/// If any signatures or nonces are missing, this method returns an error.
pub(crate) fn aggregate_split_tx_signatures<'s, S, P>(
    outcome_build_out: &OutcomeTransactionBuildOutput,
    split_build_out: &SplitTransactionBuildOutput,
    aggnonces: &BTreeMap<WinCondition, AggNonce>,
    partial_signatures_by_win_cond: &'s BTreeMap<WinCondition, S>,
) -> Result<BTreeMap<WinCondition, CompactSignature>, Error>
where
    &'s S: IntoIterator<Item = P>,
    P: Borrow<PartialSignature>,
{
    let split_txs = &split_build_out.split_txs;

    split_build_out
        .split_spend_infos
        .keys()
        .map(|&win_cond| {
            let split_tx = split_txs.get(win_cond.outcome_index).ok_or(Error)?;

            let relevant_partial_sigs = partial_signatures_by_win_cond
                .get(&win_cond)
                .ok_or(Error)?
                .into_iter()
                .map(|sig| sig.borrow().clone());

            let aggnonce = aggnonces.get(&win_cond).ok_or(Error)?;

            let outcome_spend_info = outcome_build_out
                .outcome_spend_infos
                .get(win_cond.outcome_index)
                .ok_or(Error)?;

            // Hash the split TX.
            let sighash = outcome_spend_info.sighash_tx_split(split_tx, &win_cond.winner)?;

            let compact_sig = musig2::aggregate_partial_signatures(
                outcome_spend_info.key_agg_ctx_untweaked(),
                aggnonce,
                relevant_partial_sigs,
                sighash,
            )?;

            Ok((win_cond, compact_sig))
        })
        .collect()
}

/// Construct an input to spend a given player's output of the split transaction
/// for a specific outcome. Also returns the value of that prevout.
pub(crate) fn split_tx_prevout(
    params: &ContractParameters,
    split_build_out: &SplitTransactionBuildOutput,
    outcome_index: usize,
    winner: &Player,
    block_delay: u16,
) -> Result<(TxIn, Amount), Error> {
    let split_tx = split_build_out
        .split_txs()
        .get(outcome_index)
        .ok_or(Error)?;

    let payout_map = params.outcome_payouts.get(outcome_index).ok_or(Error)?;
    let split_tx_output_index = payout_map.keys().position(|p| p == winner).ok_or(Error)?;

    let input = TxIn {
        previous_output: OutPoint {
            txid: split_tx.txid(),
            vout: split_tx_output_index as u32,
        },
        sequence: Sequence::from_height(block_delay),
        ..TxIn::default()
    };

    let output_value = split_tx
        .output
        .get(split_tx_output_index)
        .ok_or(Error)?
        .value;

    Ok((input, output_value))
}