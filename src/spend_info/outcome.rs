use bitcoin::{
    key::constants::SCHNORR_SIGNATURE_SIZE,
    opcodes::all::*,
    sighash::{Prevouts, SighashCache},
    taproot::{
        LeafVersion, TaprootSpendInfo, TAPROOT_CONTROL_BASE_SIZE, TAPROOT_CONTROL_NODE_SIZE,
    },
    transaction::InputWeightPrediction,
    Amount, ScriptBuf, TapLeafHash, TapSighash, TapSighashType, Transaction, TxOut, Witness,
};
use musig2::{CompactSignature, KeyAggContext};
use secp::{Point, Scalar};

use crate::{
    contract::PlayerIndex,
    errors::Error,
    hashlock::{Preimage, PREIMAGE_SIZE},
    parties::{MarketMaker, Player},
};

use std::{borrow::Borrow, collections::BTreeMap};

/// Represents a taproot contract which encodes spending conditions for
/// the given outcome index's outcome TX. This tree is meant to encumber joint
/// signatures on the split transaction. Any winning player should be able to
/// broadcast the split transaction, but only if they know their ticket preimage.
/// The market maker should be able to freely spend the money if no ticketholder
/// can publish the split TX before a timeout.
///
/// Since we're using hashlocks and not PTLCs here, we unfortunately need a
/// tapscript leaf for every winner, and since tapscript signatures must commit
/// to the leaf, the winners must construct distinct musig2 signatures for each
/// leaf. This must be repeated for every outcome. With `n` outcomes and `w`
/// winners per outcome, we must create a total of `n * w` signatures.
///
/// Once PTLCs are available, we can instead sign the split transaction once
/// and distribute adaptor-signatures to each player, encrypted under the
/// player's ticket point.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct OutcomeSpendInfo {
    untweaked_ctx: KeyAggContext,
    tweaked_ctx: KeyAggContext,
    outcome_value: Amount,
    spend_info: TaprootSpendInfo,
    winner_split_scripts: BTreeMap<PlayerIndex, ScriptBuf>,
    reclaim_script: ScriptBuf,
}

impl OutcomeSpendInfo {
    pub(crate) fn new(
        all_players: &[impl Borrow<Player>],
        winner_indexes: impl IntoIterator<Item = PlayerIndex>,
        market_maker: &MarketMaker,
        outcome_value: Amount,
        block_delta: u16,
    ) -> Result<Self, Error> {
        let winners: BTreeMap<PlayerIndex, &Player> = winner_indexes
            .into_iter()
            .map(|i| {
                let player = all_players.get(i).ok_or(Error)?;
                Ok((i, player.borrow()))
            })
            .collect::<Result<_, Error>>()?;

        let mut pubkeys: Vec<Point> = [market_maker.pubkey]
            .into_iter()
            .chain(winners.values().map(|w| w.pubkey))
            .collect();
        pubkeys.sort();
        let untweaked_ctx = KeyAggContext::new(pubkeys)?;
        let joint_outcome_pubkey: Point = untweaked_ctx.aggregated_pubkey();

        let winner_split_scripts: BTreeMap<PlayerIndex, ScriptBuf> = winners
            .into_iter()
            .map(|(player_index, winner)| {
                // The winner split script, used by winning players to spend
                // the outcome transaction using the split transaction.
                //
                // Input: <joint_sig> <preimage>
                let script = bitcoin::script::Builder::new()
                    // Check ticket preimage: OP_SHA256 <ticket_hash> OP_EQUALVERIFY
                    .push_opcode(OP_SHA256)
                    .push_slice(winner.ticket_hash)
                    .push_opcode(OP_EQUALVERIFY)
                    // Check joint signature: <joint_pk> OP_CHECKSIG
                    .push_slice(joint_outcome_pubkey.serialize_xonly())
                    .push_opcode(OP_CHECKSIG)
                    // Don't need OP_CSV.
                    // Sequence number is enforced by multisig key: split TX is pre-signed.
                    .into_script();

                (player_index, script)
            })
            .collect();

        // The reclaim script, used by the market maker to recover their capital
        // if none of the winning players bought their ticket preimages.
        let reclaim_script = bitcoin::script::Builder::new()
            // Check relative locktime: <2*delta> OP_CSV OP_DROP
            .push_int(2 * block_delta as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            // Check signature from market maker: <mm_pubkey> OP_CHECKSIG
            .push_slice(market_maker.pubkey.serialize_xonly())
            .push_opcode(OP_CHECKSIG)
            .into_script();

        let weighted_script_leaves = winner_split_scripts
            .values()
            .cloned()
            .map(|script| (1, script))
            .chain([(u32::MAX, reclaim_script.clone())]); // reclaim script gets highest priority

        let tr_spend_info = TaprootSpendInfo::with_huffman_tree(
            secp256k1::SECP256K1,
            joint_outcome_pubkey.into(),
            weighted_script_leaves,
        )?;

        let tweaked_ctx = untweaked_ctx.clone().with_taproot_tweak(
            tr_spend_info
                .merkle_root()
                .expect("should always have merkle root")
                .as_ref(),
        )?;

        let outcome_spend_info = OutcomeSpendInfo {
            untweaked_ctx,
            tweaked_ctx,
            outcome_value,
            spend_info: tr_spend_info,
            winner_split_scripts,
            reclaim_script,
        };
        Ok(outcome_spend_info)
    }

    pub(crate) fn key_agg_ctx_untweaked(&self) -> &KeyAggContext {
        &self.untweaked_ctx
    }

    /// Returns the TX locking script for this this outcome contract.
    pub(crate) fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::new_p2tr_tweaked(self.spend_info.output_key())
    }

    pub(crate) fn outcome_value(&self) -> Amount {
        self.outcome_value
    }

    /// Computes the input weight when spending the output of the outcome TX
    /// as an input of the split TX. This assumes one of the winning ticketholders'
    /// tapscript leaves is being used to build a witness. This prediction aims
    /// for fee estimation in the worst-case-scenario: For the winner whose tapscript
    /// leaf is deepest in the taptree (and hence requires the largest merkle proof).
    pub(crate) fn input_weight_for_split_tx(&self) -> InputWeightPrediction {
        let outcome_script_len = self
            .winner_split_scripts
            .values()
            .nth(0)
            .expect("always at least one winner")
            .len();

        let max_taptree_depth = self
            .spend_info
            .script_map()
            .values()
            .flatten()
            .map(|proof| proof.len())
            .max()
            .expect("always has at least one node");

        // The witness stack for the split TX (spends the outcome TX) is:
        // <joint_sig> <preimage> <script> <ctrl_block>
        InputWeightPrediction::new(
            0,
            [
                SCHNORR_SIGNATURE_SIZE, // BIP340 schnorr signature
                PREIMAGE_SIZE,          // Ticket preimage
                outcome_script_len,     // Script
                TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * max_taptree_depth, // Control block
            ],
        )
    }

    /// Computes the input weight when spending the output of the outcome TX
    /// as an input of the reclaim TX. This assumes the market maker's reclaim
    /// tapscript leaf is being used to build a witness.
    pub(crate) fn input_weight_for_reclaim_tx(&self) -> InputWeightPrediction {
        let reclaim_control_block = self
            .spend_info
            .control_block(&(self.reclaim_script.clone(), LeafVersion::TapScript))
            .expect("reclaim script cannot be missing");

        // The witness stack for the reclaim TX which spends the outcome TX is:
        // <market_maker_sig> <script> <ctrl_block>
        InputWeightPrediction::new(
            0,
            [
                SCHNORR_SIGNATURE_SIZE,       // BIP340 schnorr signature
                self.reclaim_script.len(),    // Script
                reclaim_control_block.size(), // Control block
            ],
        )
    }

    /// Compute the signature hash for a given split transaction.
    pub(crate) fn sighash_tx_split(
        &self,
        split_tx: &Transaction,
        player_index: &PlayerIndex,
    ) -> Result<TapSighash, Error> {
        let outcome_prevouts = [TxOut {
            script_pubkey: self.script_pubkey(),
            value: self.outcome_value,
        }];
        let split_script = self.winner_split_scripts.get(player_index).ok_or(Error)?;
        let leaf_hash = TapLeafHash::from_script(split_script, LeafVersion::TapScript);

        let sighash = SighashCache::new(split_tx).taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&outcome_prevouts),
            leaf_hash,
            TapSighashType::Default,
        )?;
        Ok(sighash)
    }

    /// Compute a witness for a split transaction which spends from the outcome transaction.
    pub(crate) fn witness_tx_split(
        &self,
        signature: &CompactSignature,
        ticket_preimage: Preimage,
        player_index: &PlayerIndex,
    ) -> Result<Witness, Error> {
        let split_script = self
            .winner_split_scripts
            .get(player_index)
            .ok_or(Error)?
            .clone();
        let control_block = self
            .spend_info
            .control_block(&(split_script.clone(), LeafVersion::TapScript))
            .ok_or(Error)?;

        let mut witness = Witness::new();
        witness.push(signature.serialize());
        witness.push(ticket_preimage);
        witness.push(split_script);
        witness.push(control_block.serialize());

        Ok(witness)
    }

    /// Compute a witness for a reclaim transaction which spends from the outcome transaction.
    ///
    /// This would only be used if none of the attested DLC outcome winners actually paid for
    /// their ticket preimage. It allows the market maker to sweep their on-chain money back
    /// without splitting it into multiple payout contracts and recombining the outputs unnecessarily.
    pub(crate) fn witness_tx_reclaim<T: Borrow<TxOut>>(
        &self,
        reclaim_tx: &Transaction,
        input_index: usize,
        prevouts: &Prevouts<T>,
        market_maker_secret_key: Scalar,
    ) -> Result<Witness, Error> {
        let leaf_hash = TapLeafHash::from_script(&self.reclaim_script, LeafVersion::TapScript);

        let sighash = SighashCache::new(reclaim_tx).taproot_script_spend_signature_hash(
            input_index,
            prevouts,
            leaf_hash,
            TapSighashType::Default,
        )?;

        let signature: CompactSignature =
            musig2::deterministic::sign_solo(market_maker_secret_key, sighash);

        let reclaim_control_block = self
            .spend_info
            .control_block(&(self.reclaim_script.clone(), LeafVersion::TapScript))
            .expect("reclaim script cannot be missing");

        // The witness stack for a reclaim TX which spends an outcome TX is:
        // <mm_sig> <script> <ctrl_block>
        let mut witness = Witness::new();
        witness.push(signature.serialize());
        witness.push(&self.reclaim_script);
        witness.push(reclaim_control_block.serialize());

        Ok(witness)
    }

    /// Derive the witness for a cooperative closing transaction which spends from
    /// the outcome transaction. The market maker must provide the secret keys
    /// for each of the winning players involved in the outcome.
    pub(crate) fn witness_tx_close<T: Borrow<TxOut>>(
        &self,
        close_tx: &Transaction,
        input_index: usize,
        prevouts: &Prevouts<T>,
        market_maker_secret_key: Scalar,
        player_secret_keys: &BTreeMap<Point, Scalar>,
    ) -> Result<Witness, Error> {
        let mm_pubkey = market_maker_secret_key.base_point_mul();
        let sighash = SighashCache::new(close_tx).taproot_key_spend_signature_hash(
            input_index,
            prevouts,
            TapSighashType::Default,
        )?;

        let ordered_seckeys: Vec<Scalar> = self
            .tweaked_ctx
            .pubkeys()
            .into_iter()
            .map(|&pubkey| {
                if pubkey == mm_pubkey {
                    Ok(market_maker_secret_key)
                } else {
                    player_secret_keys.get(&pubkey).ok_or(Error).copied()
                }
            })
            .collect::<Result<_, Error>>()?;

        let group_seckey: Scalar = self.tweaked_ctx.aggregated_seckey(ordered_seckeys)?;

        let signature: CompactSignature = musig2::deterministic::sign_solo(group_seckey, sighash);

        let witness = Witness::from_slice(&[signature.serialize()]);
        Ok(witness)
    }
}
