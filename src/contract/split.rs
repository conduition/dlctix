use bitcoin::{absolute::LockTime, Amount, OutPoint, Sequence, Transaction, TxIn, TxOut};
use musig2::{
    AggNonce, BatchVerificationRow, CompactSignature, PartialSignature, PubNonce, SecNonce,
};
use secp::{Point, Scalar};

use crate::{
    consts::{P2TR_DUST_VALUE, P2TR_SCRIPT_PUBKEY_SIZE},
    contract::{self, fees, outcome::OutcomeTransactionBuildOutput},
    contract::{ContractParameters, Outcome, WinCondition},
    errors::Error,
    parties::Player,
    spend_info::SplitSpendInfo,
};

use std::collections::{BTreeMap, BTreeSet};

/// Represents the output of building the set of split transactions.
/// This contains cached data used for constructing further transactions,
/// or signing the split transactions themselves.
pub(crate) struct SplitTransactionBuildOutput {
    split_txs: BTreeMap<Outcome, Transaction>,
    split_spend_infos: BTreeMap<WinCondition, SplitSpendInfo>,
}

impl SplitTransactionBuildOutput {
    /// Return the set of mutually exclusive split transactions. Each of these
    /// transactions spend from a corresponding previous outcome transaction.
    pub(crate) fn split_txs(&self) -> &BTreeMap<Outcome, Transaction> {
        &self.split_txs
    }

    /// Return the set of split spend info objects mapped by win condition.
    pub(crate) fn split_spend_infos(&self) -> &BTreeMap<WinCondition, SplitSpendInfo> {
        &self.split_spend_infos
    }
}

/// Build the set of split transactions which splits an outcome TX into per-player
/// payout contracts between the player and the market maker.
pub(crate) fn build_split_txs(
    params: &ContractParameters,
    outcome_build_output: &OutcomeTransactionBuildOutput,
) -> Result<SplitTransactionBuildOutput, Error> {
    let mut split_spend_infos = BTreeMap::<WinCondition, SplitSpendInfo>::new();
    let mut split_txs = BTreeMap::<Outcome, Transaction>::new();

    for (&outcome, payout_map) in params.outcome_payouts.iter() {
        let outcome_spend_info = &outcome_build_output
            .outcome_spend_infos()
            .get(&outcome)
            .ok_or(Error)?;

        // Fee estimation
        let input_weight = outcome_spend_info.input_weight_for_split_tx();
        let spk_lengths = std::iter::repeat(P2TR_SCRIPT_PUBKEY_SIZE).take(payout_map.len());
        let payout_values: BTreeMap<&Player, Amount> = fees::fee_calc_shared(
            outcome_spend_info.outcome_value(),
            params.fee_rate,
            [input_weight],
            spk_lengths,
            P2TR_DUST_VALUE,
            &payout_map,
        )?;

        let (outcome_input, _) = contract::outcome::outcome_tx_prevout(
            outcome_build_output,
            &outcome,
            params.relative_locktime_block_delta, // Split TXs have 1*delta block delay
        )?;

        // payout_values is a btree, so outputs are automatically sorted by player.
        let mut split_tx_outputs = Vec::with_capacity(payout_map.len());
        for (&&player, &payout_value) in payout_values.iter() {
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
                outcome,
            };
            split_spend_infos.insert(win_cond, split_spend_info);
        }

        let split_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![outcome_input],
            output: split_tx_outputs,
        };

        split_txs.insert(outcome, split_tx);
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
pub(crate) fn partial_sign_split_txs(
    params: &ContractParameters,
    outcome_build_out: &OutcomeTransactionBuildOutput,
    split_build_out: &SplitTransactionBuildOutput,
    seckey: Scalar,
    mut secnonces: BTreeMap<WinCondition, SecNonce>,
    aggnonces: &BTreeMap<WinCondition, AggNonce>,
) -> Result<BTreeMap<WinCondition, PartialSignature>, Error> {
    let pubkey = seckey.base_point_mul();

    let mut partial_signatures = BTreeMap::<WinCondition, PartialSignature>::new();

    let win_conditions_to_sign = params
        .win_conditions_controlled_by_pubkey(pubkey)
        .ok_or(Error)?;
    if win_conditions_to_sign.is_empty() {
        return Ok(partial_signatures);
    }

    for win_cond in win_conditions_to_sign {
        let split_tx = split_build_out
            .split_txs()
            .get(&win_cond.outcome)
            .ok_or(Error)?;

        let aggnonce = aggnonces.get(&win_cond).ok_or(Error)?; // must provide all aggnonces
        let secnonce = secnonces.remove(&win_cond).ok_or(Error)?; // must provide all secnonces

        let outcome_spend_info = outcome_build_out
            .outcome_spend_infos()
            .get(&win_cond.outcome)
            .ok_or(Error)?;

        // Hash the split TX.
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

/// Verify the partial signatures provided by a signer across every relevant split transaction.
///
/// Since each split transaction may require multiple signatures (one for each [`WinCondition`]),
/// the nonces and signatures must be provided in the form of a [`BTreeMap`], which maps
/// a [`WinCondition`] to the appropriate signature for that script spending path.
/// If any signatures or nonces are missing, this method returns an error.
pub(crate) fn verify_split_tx_partial_signatures(
    params: &ContractParameters,
    outcome_build_out: &OutcomeTransactionBuildOutput,
    split_build_out: &SplitTransactionBuildOutput,
    signer_pubkey: Point,
    pubnonces: &BTreeMap<WinCondition, PubNonce>,
    aggnonces: &BTreeMap<WinCondition, AggNonce>,
    partial_signatures: &BTreeMap<WinCondition, PartialSignature>,
) -> Result<(), Error> {
    let win_conditions_to_sign = params
        .win_conditions_controlled_by_pubkey(signer_pubkey)
        .ok_or(Error)?;

    for win_cond in win_conditions_to_sign {
        let split_tx = split_build_out
            .split_txs()
            .get(&win_cond.outcome)
            .ok_or(Error)?;

        let aggnonce = aggnonces.get(&win_cond).ok_or(Error)?; // must provide all aggnonces
        let pubnonce = pubnonces.get(&win_cond).ok_or(Error)?; // must provide all pubnonces
        let partial_sig = partial_signatures.get(&win_cond).copied().ok_or(Error)?; // must provide all sigs

        let outcome_spend_info = outcome_build_out
            .outcome_spend_infos()
            .get(&win_cond.outcome)
            .ok_or(Error)?;

        // Hash the split TX.
        let sighash = outcome_spend_info.sighash_tx_split(split_tx, &win_cond.winner)?;

        // Verifies the player's partial signature on the split TX for one specific script path spend.
        musig2::verify_partial(
            outcome_spend_info.key_agg_ctx_untweaked(),
            partial_sig,
            aggnonce,
            signer_pubkey,
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
pub(crate) fn aggregate_split_tx_signatures<S>(
    outcome_build_out: &OutcomeTransactionBuildOutput,
    split_build_out: &SplitTransactionBuildOutput,
    aggnonces: &BTreeMap<WinCondition, AggNonce>,
    mut partial_signatures_by_win_cond: BTreeMap<WinCondition, S>,
) -> Result<BTreeMap<WinCondition, CompactSignature>, Error>
where
    S: IntoIterator<Item = PartialSignature>,
{
    split_build_out
        .split_spend_infos
        .keys()
        .map(|&win_cond| {
            let split_tx = split_build_out
                .split_txs()
                .get(&win_cond.outcome)
                .ok_or(Error)?;

            let relevant_partial_sigs = partial_signatures_by_win_cond
                .remove(&win_cond)
                .ok_or(Error)?;

            let aggnonce = aggnonces.get(&win_cond).ok_or(Error)?;

            let outcome_spend_info = outcome_build_out
                .outcome_spend_infos()
                .get(&win_cond.outcome)
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

/// Verify the set of complete aggregated signatures on the split transactions.
pub(crate) fn verify_split_tx_aggregated_signatures(
    params: &ContractParameters,
    our_pubkey: Point,
    outcome_build_out: &OutcomeTransactionBuildOutput,
    split_build_out: &SplitTransactionBuildOutput,
    split_tx_signatures: &BTreeMap<WinCondition, CompactSignature>,
) -> Result<(), Error> {
    // We only need to verify signatures on win conditions where our pubkey might
    // win something.
    let relevant_win_conditions: BTreeSet<WinCondition> = params
        .win_conditions_controlled_by_pubkey(our_pubkey)
        .ok_or(Error)?;

    let batch: Vec<BatchVerificationRow> = relevant_win_conditions
        .into_iter()
        .map(|win_cond| {
            let split_tx = split_build_out
                .split_txs()
                .get(&win_cond.outcome)
                .ok_or(Error)?;

            let signature = split_tx_signatures.get(&win_cond).ok_or(Error)?;

            let outcome_spend_info = outcome_build_out
                .outcome_spend_infos()
                .get(&win_cond.outcome)
                .ok_or(Error)?;

            // Expect an untweaked signature by the group, so that the signature
            // can be used to trigger one of the players' split tapscripts.
            let winners_joint_pubkey: Point = outcome_spend_info
                .key_agg_ctx_untweaked()
                .aggregated_pubkey();

            let sighash = outcome_spend_info.sighash_tx_split(split_tx, &win_cond.winner)?;

            let batch_row = BatchVerificationRow::from_signature(
                winners_joint_pubkey,
                sighash,
                signature.lift_nonce()?,
            );

            Ok(batch_row)
        })
        .collect::<Result<_, Error>>()?;

    musig2::verify_batch(&batch)?;

    Ok(())
}

/// Construct an input to spend a given player's output of the split transaction
/// for a specific outcome. Also returns a reference to the split TX's output so
/// it can be used to construct a set of [`bitcoin::sighash::Prevouts`].
pub(crate) fn split_tx_prevout<'x>(
    params: &ContractParameters,
    split_build_out: &'x SplitTransactionBuildOutput,
    win_cond: &WinCondition,
    block_delay: u16,
) -> Result<(TxIn, &'x TxOut), Error> {
    let split_tx = split_build_out
        .split_txs()
        .get(&win_cond.outcome)
        .ok_or(Error)?;

    let payout_map = params.outcome_payouts.get(&win_cond.outcome).ok_or(Error)?;
    let split_tx_output_index = payout_map
        .keys()
        .position(|p| p == &win_cond.winner)
        .ok_or(Error)?;

    let input = TxIn {
        previous_output: OutPoint {
            txid: split_tx.txid(),
            vout: split_tx_output_index as u32,
        },
        sequence: Sequence::from_height(block_delay),
        ..TxIn::default()
    };

    let prevout = split_tx.output.get(split_tx_output_index).ok_or(Error)?;

    Ok((input, prevout))
}
