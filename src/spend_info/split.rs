use bitcoin::{
    key::constants::SCHNORR_SIGNATURE_SIZE,
    opcodes::all::*,
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, TapLeafHash, TaprootSpendInfo},
    transaction::InputWeightPrediction,
    Amount, ScriptBuf, TapSighashType, Transaction, TxOut, Witness,
};
use musig2::{CompactSignature, KeyAggContext};
use secp::{Point, Scalar};

use std::borrow::Borrow;

use crate::{
    errors::Error,
    hashlock::{Preimage, PREIMAGE_SIZE},
    parties::{MarketMaker, Player},
};

/// Represents a taproot contract for a specific player's split TX payout output.
/// This tree has three nodes:
///
/// 1. A relative-timelocked hash-lock which pays to the player if they know their ticket
///    preimage after one round of block delay.
///
/// 2. A relative-timelock which pays to the market maker after two rounds of block delay.
///
/// 3. A hash-lock which pays to the market maker immediately if they learn the
//     payout preimage from the player.
#[derive(Clone)]
pub(crate) struct SplitSpendInfo {
    tweaked_ctx: KeyAggContext,
    payout_value: Amount,
    spend_info: TaprootSpendInfo,
    win_script: ScriptBuf,
    reclaim_script: ScriptBuf,
    sellback_script: ScriptBuf,
}

impl SplitSpendInfo {
    pub(crate) fn new(
        winner: &Player,
        market_maker: &MarketMaker,
        payout_value: Amount,
        block_delta: u16,
    ) -> Result<SplitSpendInfo, Error> {
        let mut pubkeys = vec![market_maker.pubkey, winner.pubkey];
        pubkeys.sort();
        let untweaked_ctx = KeyAggContext::new(pubkeys)?;
        let joint_payout_pubkey: Point = untweaked_ctx.aggregated_pubkey();

        // The win script, used by a ticketholding winner to claim their
        // payout on-chain if the market maker doesn't cooperate.
        //
        // Inputs: <player_sig> <ticket_preimage>
        let win_script = bitcoin::script::Builder::new()
            // Check relative locktime: <delta> OP_CSV OP_DROP
            .push_int(block_delta as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            // Check ticket preimage: OP_SHA256 <ticket_hash> OP_EQUALVERIFY
            .push_opcode(OP_SHA256)
            .push_slice(winner.ticket_hash)
            .push_opcode(OP_EQUALVERIFY)
            // Check signature: <winner_pk> OP_CHECKSIG
            .push_slice(winner.pubkey.serialize_xonly())
            .push_opcode(OP_CHECKSIG)
            .into_script();

        // The reclaim script, used by the market maker to reclaim their capital
        // if the player never paid for their ticket preimage.
        //
        // Inputs: <mm_sig>
        let reclaim_script = bitcoin::script::Builder::new()
            // Check relative locktime: <2*delta> OP_CSV OP_DROP
            .push_int(2 * block_delta as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            // Check signature: <mm_pubkey> OP_CHECKSIG
            .push_slice(market_maker.pubkey.serialize_xonly())
            .push_opcode(OP_CHECKSIG)
            .into_script();

        // The sellback script, used by the market maker to reclaim their capital
        // if the player agrees to sell their payout output from the split TX back
        // to the market maker.
        //
        // Inputs: <mm_sig> <payout_preimage>
        let sellback_script = bitcoin::script::Builder::new()
            // Check payout preimage: OP_SHA256 <payout_hash> OP_EQUALVERIFY
            .push_opcode(OP_SHA256)
            .push_slice(winner.payout_hash)
            .push_opcode(OP_EQUALVERIFY)
            // Check signature: <mm_pubkey> OP_CHECKSIG
            .push_slice(market_maker.pubkey.serialize_xonly())
            .push_opcode(OP_CHECKSIG)
            .into_script();

        let weighted_script_leaves = [
            (2, sellback_script.clone()),
            (1, win_script.clone()),
            (1, reclaim_script.clone()),
        ];
        let tr_spend_info = TaprootSpendInfo::with_huffman_tree(
            secp256k1::SECP256K1,
            joint_payout_pubkey.into(),
            weighted_script_leaves,
        )?;

        let tweaked_ctx = untweaked_ctx.with_taproot_tweak(
            tr_spend_info
                .merkle_root()
                .expect("should always have merkle root")
                .as_ref(),
        )?;

        let split_spend_info = SplitSpendInfo {
            tweaked_ctx,
            payout_value,
            spend_info: tr_spend_info,
            win_script,
            reclaim_script,
            sellback_script,
        };
        Ok(split_spend_info)
    }

    /// Returns the TX locking script for this player's split TX output contract.
    pub(crate) fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::new_p2tr_tweaked(self.spend_info.output_key())
    }

    pub(crate) fn payout_value(&self) -> Amount {
        self.payout_value
    }

    /// Computes the input weight when spending an output of the split TX
    /// as an input of the player's win TX. This assumes the player's win script
    /// leaf is being used to unlock the taproot tree.
    pub(crate) fn input_weight_for_win_tx(&self) -> InputWeightPrediction {
        let win_control_block = self
            .spend_info
            .control_block(&(self.win_script.clone(), LeafVersion::TapScript))
            .expect("win script cannot be missing");

        // The witness stack for the win TX which spends a split TX output is:
        // <player_sig> <ticket_preimage> <script> <ctrl_block>
        InputWeightPrediction::new(
            0,
            [
                SCHNORR_SIGNATURE_SIZE,   // BIP340 schnorr signature
                PREIMAGE_SIZE,            // Ticket preimage
                self.win_script.len(),    // Script
                win_control_block.size(), // Control block
            ],
        )
    }

    /// Computes the input weight when spending an output of the split TX
    /// as an input of the market maker's reclaim TX. This assumes the market
    /// maker's reclaim script leaf is being used to unlock the taproot tree.
    pub(crate) fn input_weight_for_reclaim_tx(&self) -> InputWeightPrediction {
        let reclaim_control_block = self
            .spend_info
            .control_block(&(self.reclaim_script.clone(), LeafVersion::TapScript))
            .expect("reclaim script cannot be missing");

        // The witness stack for the reclaim TX which spends a split TX output is:
        // <mm_sig> <script> <ctrl_block>
        InputWeightPrediction::new(
            0,
            [
                SCHNORR_SIGNATURE_SIZE,       // BIP340 schnorr signature
                self.reclaim_script.len(),    // Script
                reclaim_control_block.size(), // Control block
            ],
        )
    }

    /// Computes the input weight when spending an output of the split TX
    /// as an input of the sellback TX. This assumes the market maker's sellback
    /// script leaf is being used to unlock the taproot tree.
    pub(crate) fn input_weight_for_sellback_tx(&self) -> InputWeightPrediction {
        let sellback_control_block = self
            .spend_info
            .control_block(&(self.sellback_script.clone(), LeafVersion::TapScript))
            .expect("sellback script cannot be missing");

        // The witness stack for the sellback TX which spends a split TX output is:
        // <mm_sig> <payout_preimage> <script> <ctrl_block>
        InputWeightPrediction::new(
            0,
            [
                SCHNORR_SIGNATURE_SIZE,        // BIP340 schnorr signature
                PREIMAGE_SIZE,                 // Payout preimage
                self.sellback_script.len(),    // Script
                sellback_control_block.size(), // Control block
            ],
        )
    }

    /// Derive the witness for a win transaction input which spends from
    /// a split transaction.
    pub(crate) fn witness_tx_win<T: Borrow<TxOut>>(
        &self,
        win_tx: &Transaction,
        input_index: usize,
        prevouts: &Prevouts<T>,
        ticket_preimage: Preimage,
        player_secret_key: Scalar,
    ) -> Result<Witness, Error> {
        let leaf_hash = TapLeafHash::from_script(&self.win_script, LeafVersion::TapScript);

        let sighash = SighashCache::new(win_tx).taproot_script_spend_signature_hash(
            input_index,
            prevouts,
            leaf_hash,
            TapSighashType::Default,
        )?;

        let signature: CompactSignature =
            musig2::deterministic::sign_solo(player_secret_key, sighash);

        let win_control_block = self
            .spend_info
            .control_block(&(self.win_script.clone(), LeafVersion::TapScript))
            .expect("win script cannot be missing");

        // The witness stack for a win TX which spends a split TX output is:
        // <player_sig> <ticket_preimage> <script> <ctrl_block>
        let mut witness = Witness::new();
        witness.push(signature.serialize());
        witness.push(ticket_preimage);
        witness.push(&self.win_script);
        witness.push(win_control_block.serialize());

        Ok(witness)
    }

    /// Derive the witness for a reclaim transaction, which spends from
    /// a split transaction.
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

        // The witness stack for a reclaim TX which spends a split TX output is:
        // <mm_sig> <script> <ctrl_block>
        let mut witness = Witness::new();
        witness.push(signature.serialize());
        witness.push(&self.reclaim_script);
        witness.push(reclaim_control_block.serialize());

        Ok(witness)
    }

    /// Derive the witness for a sellback transaction, which spends from
    /// a split transaction.
    pub(crate) fn witness_tx_sellback<T: Borrow<TxOut>>(
        &self,
        sellback_tx: &Transaction,
        input_index: usize,
        prevouts: &Prevouts<T>,
        payout_preimage: Preimage,
        market_maker_secret_key: Scalar,
    ) -> Result<Witness, Error> {
        let leaf_hash = TapLeafHash::from_script(&self.sellback_script, LeafVersion::TapScript);

        let sighash = SighashCache::new(sellback_tx).taproot_script_spend_signature_hash(
            input_index,
            prevouts,
            leaf_hash,
            TapSighashType::Default,
        )?;

        let signature: CompactSignature =
            musig2::deterministic::sign_solo(market_maker_secret_key, sighash);

        let sellback_control_block = self
            .spend_info
            .control_block(&(self.sellback_script.clone(), LeafVersion::TapScript))
            .expect("sellback script cannot be missing");

        // The witness stack for the sellback TX which spends a split TX output is:
        // <mm_sig> <payout_preimage> <script> <ctrl_block>
        let mut witness = Witness::new();
        witness.push(signature.serialize());
        witness.push(payout_preimage);
        witness.push(&self.sellback_script);
        witness.push(sellback_control_block.serialize());

        Ok(witness)
    }

    /// Derive the witness for a cooperative closing transaction which spends from
    /// a single player's split TX output. The market maker must provide the secret
    /// key given by the player after a complete off-chain payout.
    pub(crate) fn witness_tx_close<T: Borrow<TxOut>>(
        &self,
        close_tx: &Transaction,
        input_index: usize,
        prevouts: &Prevouts<T>,
        market_maker_secret_key: Scalar,
        player_secret_key: Scalar,
    ) -> Result<Witness, Error> {
        let mm_pubkey = market_maker_secret_key.base_point_mul();
        let sighash = SighashCache::new(close_tx).taproot_key_spend_signature_hash(
            input_index,
            prevouts,
            TapSighashType::Default,
        )?;

        let ordered_seckeys = self.tweaked_ctx.pubkeys().into_iter().map(|pubkey| {
            if pubkey == &mm_pubkey {
                market_maker_secret_key
            } else {
                player_secret_key
            }
        });

        let group_seckey: Scalar = self.tweaked_ctx.aggregated_seckey(ordered_seckeys)?;

        let signature: CompactSignature = musig2::deterministic::sign_solo(group_seckey, sighash);
        let witness = Witness::from_slice(&[signature.serialize()]);
        Ok(witness)
    }
}
