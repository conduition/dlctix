mod errors;

use bitcoin::{
    absolute::LockTime,
    key::constants::SCHNORR_SIGNATURE_SIZE,
    opcodes::all::*,
    script::ScriptBuf,
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{
        LeafVersion, TaprootSpendInfo, TAPROOT_CONTROL_BASE_SIZE, TAPROOT_CONTROL_NODE_SIZE,
    },
    transaction::InputWeightPrediction,
    Amount, FeeRate, OutPoint, Sequence, TapSighash, Transaction, TxIn, TxOut, Witness,
};
use errors::Error;
use musig2::KeyAggContext;
use secp::{MaybePoint, MaybeScalar, Point, Scalar};
use secp256k1::XOnlyPublicKey;
use sha2::Digest as _;
use std::collections::BTreeMap;

const P2TR_SCRIPT_PUBKEY_LEN: usize = 34;

/// The agent who provides the on-chain capital to facilitate the ticketed DLC.
/// Could be one of the players in the DLC, or could be a neutral 3rd party
/// who wishes to profit by leveraging their capital.
#[derive(Debug, Clone)]
pub struct MarketMaker {
    pub pubkey: Point,
}

/// Compute the SHA256 hash of some input data.
pub fn sha256(input: &[u8]) -> [u8; 32] {
    sha2::Sha256::new().chain_update(input).finalize().into()
}

/// The size for ticket preimages.
///
/// Using lower values is more efficient on-chain, but less secure against
/// brute force attacks.
pub const TICKET_PREIMAGE_SIZE: usize = 32;

/// A handy type-alias for ticket preimages. We use random 32 byte preimages
/// for best compatibility with lightning network clients.
pub type TicketPreimage = [u8; TICKET_PREIMAGE_SIZE];

pub fn preimage_random<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> TicketPreimage {
    let mut preimage = [0u8; TICKET_PREIMAGE_SIZE];
    rng.fill_bytes(&mut preimage);
    preimage
}

/// Parse a preimage from a hex string.
pub fn preimage_from_hex(s: &str) -> Result<TicketPreimage, hex::FromHexError> {
    let mut preimage = [0u8; TICKET_PREIMAGE_SIZE];
    hex::decode_to_slice(s, &mut preimage)?;
    Ok(preimage)
}

/// A player in a ticketed DLC. Each player is identified by a public key,
/// but also by their ticket hash. If a player can learn the preimage of
/// their ticket hash (usually by purchasing it via Lightning), they can
/// claim winnings from DLC outcomes.
///
/// The same pubkey can participate in the same ticketed DLC under different
/// ticket hashes, so players might share common pubkeys. However, for the
/// economics of the contract to work, every player should be allocated
/// their own completely unique ticket hash.
#[derive(Debug, Clone, Copy, Ord, PartialOrd, Hash, Eq, PartialEq)]
pub struct Player {
    /// A public key controlled by the player.
    pub pubkey: Point,

    /// The ticket hashes used for HTLCs. To buy into the DLC, players must
    /// purchase the preimages of these hashes.
    pub ticket_hash: [u8; 32],
}

/// An oracle's announcement of a future event.
#[derive(Debug, Clone)]
pub struct EventAnnouncment {
    /// The signing oracle's pubkey
    pub oracle_pubkey: Point,

    /// The `R` point with which the oracle promises to attest to this event.
    pub nonce_point: Point,

    /// Naive but easy.
    pub outcome_messages: Vec<Vec<u8>>,

    /// The unix timestamp beyond which the oracle is considered to have gone AWOL.
    pub expiry: u32,
}

impl EventAnnouncment {
    /// Computes the oracle's locking point for the given outcome index.
    pub fn outcome_lock_point(&self, index: usize) -> Option<MaybePoint> {
        let msg = &self.outcome_messages.get(index)?;

        let e: MaybeScalar = musig2::compute_challenge_hash_tweak(
            &self.nonce_point.serialize_xonly(),
            &self.oracle_pubkey,
            msg,
        );

        // S = R + eD
        Some(self.nonce_point + e * self.oracle_pubkey)
    }

    /// Computes the oracle's unllocking scalar - the discrete log of the
    /// locking point - for the given outcome index.
    pub fn outcome_secret(
        &self,
        index: usize,
        oracle_seckey: Scalar,
        secnonce: Scalar,
    ) -> Option<MaybeScalar> {
        if oracle_seckey.base_point_mul() != self.oracle_pubkey
            || secnonce.base_point_mul() != self.nonce_point
        {
            return None;
        }

        let msg = &self.outcome_messages.get(index)?;
        let e: MaybeScalar = musig2::compute_challenge_hash_tweak(
            &self.nonce_point.serialize_xonly(),
            &self.oracle_pubkey,
            msg,
        );
        Some(secnonce + e * oracle_seckey)
    }
}

/// Represents a mapping of player to payout weight for a given outcome.
///
/// A player's payout is proportional to the size of their payout weight
/// in comparison to the payout weights of all other winners.
pub type PayoutWeights = BTreeMap<Player, u64>;

#[derive(Debug, Clone)]
pub struct FundingSpendInfo<'e> {
    key_agg_ctx: KeyAggContext,
    event: &'e EventAnnouncment,
}

impl<'e> FundingSpendInfo<'e> {
    fn new(key_agg_ctx: KeyAggContext, event: &'e EventAnnouncment) -> FundingSpendInfo<'e> {
        FundingSpendInfo { key_agg_ctx, event }
    }

    /// Return a reference to the [`KeyAggContext`] used to spend the multisig funding output.
    pub fn key_agg_ctx(&self) -> &KeyAggContext {
        &self.key_agg_ctx
    }

    /// Returns the TX locking script for funding the ticketed DLC multisig.
    pub fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::new_p2tr(
            secp256k1::SECP256K1,
            self.key_agg_ctx.aggregated_pubkey(),
            None,
        )
    }

    /// Compute the signature hash for a given outcome transaction.
    pub fn sighash_tx_outcome(
        &self,
        outcome_tx: &Transaction,
        funding_value: Amount,
    ) -> Result<TapSighash, bitcoin::sighash::Error> {
        let funding_prevouts = [TxOut {
            script_pubkey: self.script_pubkey(),
            value: funding_value,
        }];

        SighashCache::new(outcome_tx).taproot_key_spend_signature_hash(
            0,
            &Prevouts::All(&funding_prevouts),
            TapSighashType::Default,
        )
    }
}

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
#[derive(Debug, Clone)]
pub struct OutcomeSpendInfo {
    key_agg_ctx: KeyAggContext,
    spend_info: TaprootSpendInfo,
    winner_split_scripts: BTreeMap<Player, ScriptBuf>,
    reclaim_script: ScriptBuf,
}

impl OutcomeSpendInfo {
    fn new<W: IntoIterator<Item = Player>>(
        winners: W,
        market_maker: &MarketMaker,
        block_delta: u16,
    ) -> Result<Self, Error> {
        let winners: Vec<Player> = winners.into_iter().collect();
        let mut pubkeys: Vec<Point> = [market_maker.pubkey]
            .into_iter()
            .chain(winners.iter().map(|w| w.pubkey))
            .collect();
        pubkeys.sort();
        let untweaked_ctx = KeyAggContext::new(pubkeys)?;
        let joint_outcome_pubkey: Point = untweaked_ctx.aggregated_pubkey();

        let winner_split_scripts: BTreeMap<Player, ScriptBuf> = winners
            .iter()
            .map(|&winner| {
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

                (winner, script)
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
            .chain([(999999999, reclaim_script.clone())]); // reclaim script gets highest priority

        let tr_spend_info = TaprootSpendInfo::with_huffman_tree(
            secp256k1::SECP256K1,
            joint_outcome_pubkey.into(),
            weighted_script_leaves,
        )?;

        let tweaked_ctx = untweaked_ctx.with_taproot_tweak(
            tr_spend_info
                .merkle_root()
                .expect("should always have merkle root")
                .as_ref(),
        )?;

        let outcome_spend_info = OutcomeSpendInfo {
            key_agg_ctx: tweaked_ctx,
            spend_info: tr_spend_info,
            winner_split_scripts,
            reclaim_script,
        };
        Ok(outcome_spend_info)
    }

    /// Returns the TX locking script for this this outcome contract.
    pub fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::new_p2tr_tweaked(self.spend_info.output_key())
    }

    /// Computes the input weight when spending the output of the outcome TX
    /// as an input of the split TX. This assumes one of the winning ticketholders'
    /// tapscript leaves is being used to build a witness. This prediction aims
    /// for fee estimation in the worst-case-scenario: For the winner whose tapscript
    /// leaf is deepest in the taptree (and hence requires the largest merkle proof).
    pub fn input_weight_for_split_tx(&self) -> InputWeightPrediction {
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
                TICKET_PREIMAGE_SIZE,   // Ticket preimage
                outcome_script_len,     // Script
                TAPROOT_CONTROL_BASE_SIZE + TAPROOT_CONTROL_NODE_SIZE * max_taptree_depth, // Control block
            ],
        )
    }

    /// Computes the input weight when spending the output of the outcome TX
    /// as an input of the reclaim TX. This assumes the market maker's reclaim
    /// tapscript leaf is being used to build a witness.
    pub fn input_weight_for_reclaim_tx(&self) -> InputWeightPrediction {
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
}

/// Represents a taproot contract for a specific player's split TX payout output.
/// This tree only has two nodes:
///
/// 1. A relative-timelocked hash-lock which pays to the player if they know their ticket
///    preimage after one round of block delay.
///
/// 2. A relative-timelock which pays to the market maker after two rounds of block delay.
#[derive(Debug, Clone)]
pub struct SplitSpendInfo {
    key_agg_ctx: KeyAggContext,
    spend_info: TaprootSpendInfo,
    winner: Player,
    win_script: ScriptBuf,
    reclaim_script: ScriptBuf,
}

impl SplitSpendInfo {
    fn new(
        winner: Player,
        market_maker: &MarketMaker,
        block_delta: u16,
    ) -> Result<SplitSpendInfo, Error> {
        let mut pubkeys = vec![market_maker.pubkey, winner.pubkey];
        pubkeys.sort();
        let untweaked_ctx = KeyAggContext::new(pubkeys)?;
        let joint_payout_pubkey: Point = untweaked_ctx.aggregated_pubkey();

        // The win script, used by a ticketholding winner to claim their
        // payout on-chain if the market maker doesn't cooperate.
        //
        // Inputs: <player_sig> <preimage>
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

        let weighted_script_leaves = [(1, win_script.clone()), (1, reclaim_script.clone())];
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
            key_agg_ctx: tweaked_ctx,
            spend_info: tr_spend_info,
            winner,
            win_script,
            reclaim_script,
        };
        Ok(split_spend_info)
    }

    /// Returns the TX locking script for this player's split TX output contract.
    pub fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::new_p2tr_tweaked(self.spend_info.output_key())
    }

    /// Computes the input weight when spending an output of the split TX
    /// as an input of the player's win TX. This assumes the player's win script
    /// leaf is being used to unlock the taproot tree.
    pub fn input_weight_for_win_tx(&self) -> InputWeightPrediction {
        let win_control_block = self
            .spend_info
            .control_block(&(self.win_script.clone(), LeafVersion::TapScript))
            .expect("win script cannot be missing");

        // The witness stack for the win TX which spends a split TX output is:
        // <player_sig> <preimage> <script> <ctrl_block>
        InputWeightPrediction::new(
            0,
            [
                SCHNORR_SIGNATURE_SIZE,   // BIP340 schnorr signature
                TICKET_PREIMAGE_SIZE,     // Ticket preimage
                self.win_script.len(),    // Script
                win_control_block.size(), // Control block
            ],
        )
    }

    /// Computes the input weight when spending an output of the split TX
    /// as an input of the market maker's relcaim TX. This assumes the market
    /// maker's reclaim script leaf is being used to unlock the taproot tree.
    pub fn input_weight_for_reclaim_tx(&self) -> InputWeightPrediction {
        let reclaim_control_block = self
            .spend_info
            .control_block(&(self.reclaim_script.clone(), LeafVersion::TapScript))
            .expect("reclaim script cannot be missing");

        // The witness stack for the reclaim TX which spends a split TX output is:
        // <player_sig> <script> <ctrl_block>
        InputWeightPrediction::new(
            0,
            [
                SCHNORR_SIGNATURE_SIZE,       // BIP340 schnorr signature
                self.reclaim_script.len(),    // Script
                reclaim_control_block.size(), // Control block
            ],
        )
    }
}

#[derive(Debug, Clone)]
pub struct ContractParameters {
    /// The market maker who provides capital for the DLC ticketing process.
    pub market_maker: MarketMaker,

    /// Players in the DLC.
    pub players: Vec<Player>,

    /// The event whose outcome determines the payouts.
    pub event: EventAnnouncment,

    /// An ordered list of payout under different outcomes. Should align with
    /// `self.event.outcome_messages`.
    pub outcome_payouts: Vec<PayoutWeights>,

    /// Who is paid out in the event of an expiry.
    pub expiry_payout: Option<PayoutWeights>,

    /// A default mining fee rate to be used for pre-signed transactions.
    pub fee_rate: FeeRate,

    /// A reasonable number of blocks within which a transaction can confirm.
    /// Used for enforcing relative locktime timeout spending conditions.
    pub relative_locktime_block_delta: u16,
}

impl ContractParameters {
    /// Construct a key aggregation context, jointly controlled by all players
    /// and the market maker. This [`KeyAggContext`] is used for adaptor-signing
    /// the outcome transactions, spending from the funding output.
    pub fn key_agg_ctx_all(&self) -> Result<KeyAggContext, Error> {
        let mut all_pubkeys: Vec<Point> = [self.market_maker.pubkey]
            .into_iter()
            .chain(self.players.iter().map(|player| player.pubkey))
            .collect();
        all_pubkeys.sort();
        Ok(KeyAggContext::new(all_pubkeys)?)
    }

    /// Construct a multisig funding script pubkey, jointly controlled
    /// by all players and the market maker.
    pub fn multisig_spk_funding(&self) -> Result<ScriptBuf, Error> {
        let pubkey: Point = self.key_agg_ctx_all()?.aggregated_pubkey();
        let untweaked_pk = XOnlyPublicKey::from(pubkey);
        let script = ScriptBuf::new_p2tr(secp256k1::SECP256K1, untweaked_pk, None);
        Ok(script)
    }

    pub fn spend_info_funding<'s>(&'s self) -> Result<FundingSpendInfo<'s>, Error> {
        Ok(FundingSpendInfo::new(self.key_agg_ctx_all()?, &self.event))
    }

    pub fn spend_info_outcome(&self, outcome_index: usize) -> Result<OutcomeSpendInfo, Error> {
        let payout_map = self.outcome_payouts.get(outcome_index).ok_or(Error)?;
        let winners = payout_map.keys().copied();
        OutcomeSpendInfo::new(
            winners,
            &self.market_maker,
            self.relative_locktime_block_delta,
        )
    }

    pub fn spend_info_split(&self, player: Player) -> Result<SplitSpendInfo, Error> {
        SplitSpendInfo::new(
            player,
            &self.market_maker,
            self.relative_locktime_block_delta,
        )
    }

    /// Construct an outcome transaction for the given outcome index. This TX spends the
    /// funding transaction, and pays to the shared control of the market maker, plus
    /// the winners for this outcome.
    pub fn tx_outcome(
        &self,
        outcome_index: usize,
        funding_outpoint: OutPoint,
        funding_value: Amount,
    ) -> Result<Transaction, Error> {
        let funding_input = TxIn {
            previous_output: funding_outpoint,
            sequence: Sequence::MAX,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        };

        // TODO cache OutcomeSpendInfo
        let outcome_spk = self.spend_info_outcome(outcome_index)?.script_pubkey();

        let tx_weight = bitcoin::transaction::predict_weight(
            [bitcoin::transaction::InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH],
            [outcome_spk.len()],
        );
        let fee = self.fee_rate.fee_wu(tx_weight).ok_or(Error)?;
        if funding_value <= fee || funding_value - fee <= outcome_spk.dust_value() {
            return Err(Error);
        }

        let outcome_output = TxOut {
            value: funding_value - fee,
            script_pubkey: outcome_spk,
        };

        let outcome_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![funding_input],
            output: vec![outcome_output],
        };
        Ok(outcome_tx)
    }

    // /// Partially sign the given outcome transaction.
    // pub fn tx_outcome_sign_adaptor(
    //     &self,
    //     outcome_tx: &Transaction,
    //     outcome_index: usize,
    //     funding_value: Amount,
    //     seckey: Scalar,
    // ) -> Result<AdaptorSignature, Error> {
    //     let funding_spend_info = self.spend_info_funding()?;

    //     // Hash the outcome TX.
    //     let sighash = funding_spend_info.sighash_tx_outcome(outcome_tx, funding_value)?;

    //     // Adaptor-signing the outcome TX sighash, locked by the oracle's outcome point.
    //     let outcome_lock_point = contract.event.outcome_lock_point(outcome_index).unwrap();
    // }

    /// Construct a split transaction for the given outcome index. This transaction spends
    /// an outcome TX and splits the contract into individual payout contracts between
    /// the market maker and each individual winner.
    pub fn tx_outcome_split(
        &self,
        outcome_index: usize,
        outcome_tx: &Transaction,
    ) -> Result<Transaction, Error> {
        let outcome_input = TxIn {
            previous_output: OutPoint {
                txid: outcome_tx.txid(),
                vout: 0,
            },
            sequence: Sequence::from_height(self.relative_locktime_block_delta),
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        };

        // TODO cache OutcomeSpendInfo
        let outcome_spend_info = self.spend_info_outcome(outcome_index)?;
        let outcome_tx_value = outcome_tx.output.get(0).ok_or(Error)?.value;

        let payout_map = self.outcome_payouts.get(outcome_index).ok_or(Error)?;

        // Fee estimation
        let input_weight = outcome_spend_info.input_weight_for_split_tx();
        let spk_lengths = std::iter::repeat(P2TR_SCRIPT_PUBKEY_LEN).take(payout_map.len());
        let fee_total = fee_calc_safe(self.fee_rate, [input_weight], spk_lengths)?;

        // Mining fees are distributed equally among all winners, regardless of payout weight.
        let fee_shared = fee_total / payout_map.len() as u64;
        let total_payout_weight: u64 = payout_map.values().copied().sum();

        // payout_map is a btree, so outputs are automatically sorted by player.
        let mut split_tx_outputs = Vec::with_capacity(payout_map.len());
        for (&player, &payout_weight) in payout_map.iter() {
            let script_pubkey = self.spend_info_split(player)?.script_pubkey();

            // Payout amounts are computed by using relative weights.
            let payout = outcome_tx_value * payout_weight / total_payout_weight;
            let output_amount = fee_subtract_safe(payout, fee_shared, script_pubkey.dust_value())?;

            split_tx_outputs.push(TxOut {
                value: output_amount,
                script_pubkey,
            });
        }

        let split_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![outcome_input],
            output: split_tx_outputs,
        };
        Ok(split_tx)
    }

    /// Constructs a _reclaim transaction_ which returns the funds to the market maker
    /// after a given outcome TX's output timelock has expired without any ticketholders
    /// using the split TX.
    ///
    /// Technically the market maker does not need to use this particular method to reclaim
    /// their money. Once the timelock has elapsed, they have control of the outcome TX
    /// output, and can spend it however they like.
    pub fn tx_outcome_reclaim(
        &self,
        outcome_index: usize,
        outcome_tx: &Transaction,
        dest_script_pubkey: ScriptBuf,
        fee_rate: FeeRate,
    ) -> Result<Transaction, Error> {
        let outcome_input = TxIn {
            previous_output: OutPoint {
                txid: outcome_tx.txid(),
                vout: 0,
            },
            sequence: Sequence::from_height(2 * self.relative_locktime_block_delta),
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        };

        // TODO cache OutcomeSpendInfo
        let outcome_spend_info = self.spend_info_outcome(outcome_index)?;
        let outcome_tx_value = outcome_tx.output.get(0).ok_or(Error)?.value;

        let input_weight = outcome_spend_info.input_weight_for_reclaim_tx();
        let fee = fee_calc_safe(fee_rate, [input_weight], [dest_script_pubkey.len()])?;
        let output_value =
            fee_subtract_safe(outcome_tx_value, fee, dest_script_pubkey.dust_value())?;

        let reclaim_output = TxOut {
            value: output_value,
            script_pubkey: dest_script_pubkey,
        };

        let reclaim_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![outcome_input],
            output: vec![reclaim_output],
        };
        Ok(reclaim_tx)
    }

    /// Construct an input to spend a given player's output of the split transaction
    /// for a specific outcome. Also returns the value of that prevout.
    fn split_tx_prevout(
        &self,
        outcome_index: usize,
        winner: &Player,
        split_tx: &Transaction,
        block_delay: u16,
    ) -> Result<(TxIn, Amount), Error> {
        let payout_map = self.outcome_payouts.get(outcome_index).ok_or(Error)?;
        let split_tx_output_index = payout_map.keys().position(|p| p == winner).ok_or(Error)?;

        let input = TxIn {
            previous_output: OutPoint {
                txid: split_tx.txid(),
                vout: split_tx_output_index as u32,
            },
            sequence: Sequence::from_height(block_delay),
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        };

        let output_value = split_tx
            .output
            .get(split_tx_output_index)
            .ok_or(Error)?
            .value;

        Ok((input, output_value))
    }

    /// Constructs a _win transaction_ which spends a particular player's payout from the split
    /// transaction to a chosen `dest_script_pubkey`, effectively sweeping the winnings.
    ///
    /// If the player is a winning ticketholder, they MUST create, sign, and broadcast this
    /// win transaction _before_ the market maker can use the reclaim TX to claw back the winnings.
    /// They must wait for one round of block delay after the split transaction confirms.
    pub fn tx_outcome_split_win(
        &self,
        outcome_index: usize,
        winner: &Player,
        split_tx: &Transaction,
        dest_script_pubkey: ScriptBuf,
        fee_rate: FeeRate,
    ) -> Result<Transaction, Error> {
        let (split_input, split_output_value) = self.split_tx_prevout(
            outcome_index,
            winner,
            split_tx,
            self.relative_locktime_block_delta,
        )?;

        let split_spend_info = self.spend_info_split(*winner)?;

        let input_weight = split_spend_info.input_weight_for_win_tx();
        let fee = fee_calc_safe(fee_rate, [input_weight], [dest_script_pubkey.len()])?;
        let output_value =
            fee_subtract_safe(split_output_value, fee, dest_script_pubkey.dust_value())?;

        let win_output = TxOut {
            value: output_value,
            script_pubkey: dest_script_pubkey,
        };

        let win_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![split_input],
            output: vec![win_output],
        };
        Ok(win_tx)
    }

    /// Constructs a _reclaim transaction_ which allows the market maker to reclaim capital
    /// if the winner did not buy their ticket preimage.
    ///
    /// This TX can be signed and broadcast unilaterally by the market maker after two rounds
    /// of relative block delay on the split transaction.
    pub fn tx_outcome_split_reclaim(
        &self,
        outcome_index: usize,
        winner: &Player,
        split_tx: &Transaction,
        dest_script_pubkey: ScriptBuf,
        fee_rate: FeeRate,
    ) -> Result<Transaction, Error> {
        let (split_input, split_output_value) = self.split_tx_prevout(
            outcome_index,
            winner,
            split_tx,
            2 * self.relative_locktime_block_delta,
        )?;

        let split_spend_info = self.spend_info_split(*winner)?;

        let input_weight = split_spend_info.input_weight_for_reclaim_tx();
        let fee = fee_calc_safe(fee_rate, [input_weight], [dest_script_pubkey.len()])?;
        let output_value =
            fee_subtract_safe(split_output_value, fee, dest_script_pubkey.dust_value())?;

        let reclaim_output = TxOut {
            value: output_value,
            script_pubkey: dest_script_pubkey,
        };

        let reclaim_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![split_input],
            output: vec![reclaim_output],
        };
        Ok(reclaim_tx)
    }

    /// TODO
    pub fn tx_expire(&self) -> Result<Transaction, Error> {
        todo!();
    }
}

fn fee_calc_safe<I, O>(
    fee_rate: FeeRate,
    input_weights: I,
    output_spk_lens: O,
) -> Result<Amount, Error>
where
    I: IntoIterator<Item = InputWeightPrediction>,
    O: IntoIterator<Item = usize>,
{
    let tx_weight = bitcoin::transaction::predict_weight(input_weights, output_spk_lens);
    let fee = fee_rate.fee_wu(tx_weight).ok_or(Error)?;
    Ok(fee)
}

fn fee_subtract_safe(
    available_coins: Amount,
    fee: Amount,
    dust_threshold: Amount,
) -> Result<Amount, Error> {
    if fee >= available_coins {
        return Err(Error);
    }
    let after_fee = available_coins.checked_sub(fee).ok_or(Error)?;
    if after_fee <= dust_threshold {
        return Err(Error);
    }
    Ok(after_fee)
}

#[cfg(test)]
mod tests {
    use super::*;
    use musig2::{AdaptorSignature, AggNonce, CompactSignature, PartialSignature, SecNonce};

    /// Test-helper to cooperatively sign a message with musig2.
    fn musig2_group_sign_adaptor(
        key_agg_ctx: &KeyAggContext,
        message: impl AsRef<[u8]>,
        seckeys: impl IntoIterator<Item = Scalar>,
        adaptor_point: MaybePoint,
    ) -> AdaptorSignature {
        let seckeys: Vec<Scalar> = seckeys.into_iter().collect();
        let agg_pubkey: Point = key_agg_ctx.aggregated_pubkey();

        let secnonces: Vec<SecNonce> = seckeys
            .iter()
            .map(|&key| SecNonce::generate([0; 32], key, agg_pubkey, &message, b""))
            .collect();

        let aggnonce: AggNonce = secnonces
            .iter()
            .map(|secnonce| secnonce.public_nonce())
            .sum();
        let partial_signatures: Vec<PartialSignature> = seckeys
            .into_iter()
            .zip(secnonces)
            .map(|(seckey, secnonce)| {
                musig2::adaptor::sign_partial(
                    &key_agg_ctx,
                    seckey,
                    secnonce,
                    &aggnonce,
                    adaptor_point,
                    &message,
                )
                .expect("error constructing partial adaptor signature")
            })
            .collect();

        let adaptor_signature: AdaptorSignature = musig2::adaptor::aggregate_partial_signatures(
            &key_agg_ctx,
            &aggnonce,
            adaptor_point,
            partial_signatures,
            &message,
        )
        .expect("failed to aggregate partial adaptor signatures");

        adaptor_signature
    }

    struct TestOutcome {
        message: Vec<u8>,
        payouts: Vec<u64>,
    }

    struct TestContract {
        market_maker_key: Scalar,
        oracle_key: Scalar,
        oracle_nonce: Scalar,
        preimages: Vec<TicketPreimage>,
        player_keys: Vec<Scalar>,
        outcomes: Vec<TestOutcome>,
    }

    impl TestContract {
        fn new_simple_duel() -> Self {
            TestContract {
                market_maker_key: Scalar::try_from(45).unwrap(),
                oracle_key: Scalar::try_from(938).unwrap(),
                oracle_nonce: Scalar::try_from(284).unwrap(),
                preimages: vec![
                    preimage_from_hex(
                        "bdb43c9d6a2eb2c850ff2961ec742a97880da219f145a87eafe5e77d98345157",
                    )
                    .unwrap(),
                    preimage_from_hex(
                        "550fef06e230286db2b930aa4494faf1b83bf9f5534f60c3948975a121ee221c",
                    )
                    .unwrap(),
                ],
                player_keys: vec![
                    Scalar::try_from(1111).unwrap(),
                    Scalar::try_from(2222).unwrap(),
                ],
                outcomes: vec![
                    TestOutcome {
                        message: Vec::from("player 1 wins"),
                        payouts: vec![1, 0],
                    },
                    TestOutcome {
                        message: Vec::from("player 2 wins"),
                        payouts: vec![0, 1],
                    },
                    TestOutcome {
                        message: Vec::from("tie"),
                        payouts: vec![1, 1],
                    },
                ],
            }
        }

        fn contract_params(&self) -> ContractParameters {
            let players: Vec<Player> = self
                .player_keys
                .iter()
                .zip(&self.preimages)
                .map(|(&seckey, &preimage)| Player {
                    pubkey: seckey.base_point_mul(),
                    ticket_hash: sha256(&preimage),
                })
                .collect();

            let outcome_payouts: Vec<PayoutWeights> = self
                .outcomes
                .iter()
                .map(|outcome| {
                    outcome
                        .payouts
                        .iter()
                        .enumerate()
                        .filter(|(_, &weight)| weight > 0)
                        .map(|(i, &weight)| (players[i], weight))
                        .collect()
                })
                .collect();

            let event = EventAnnouncment {
                oracle_pubkey: self.oracle_key.base_point_mul(),
                nonce_point: self.oracle_nonce.base_point_mul(),
                outcome_messages: self
                    .outcomes
                    .iter()
                    .map(|outcome| outcome.message.clone())
                    .collect(),
                expiry: u32::MAX,
            };

            ContractParameters {
                market_maker: MarketMaker {
                    pubkey: self.market_maker_key.base_point_mul(),
                },
                players,
                event,
                outcome_payouts,

                expiry_payout: None,
                fee_rate: FeeRate::from_sat_per_vb_unchecked(100),
                relative_locktime_block_delta: 12 * 6, // approx 12 hours
            }
        }
    }

    #[test]
    fn test_funding_script_pubkey() {
        let test_contract = TestContract::new_simple_duel();
        let mut contract = test_contract.contract_params();

        let funding_spk = contract
            .multisig_spk_funding()
            .expect("error computing funding SPK");

        // <1> <35e9f3104b67a8b473e8dc5582b94367ae9b557c72c831746db5929ae2938392>
        let expected_spk = ScriptBuf::from_hex(
            "512035e9f3104b67a8b473e8dc5582b94367ae9b557c72c831746db5929ae2938392",
        )
        .unwrap();

        assert_eq!(funding_spk, expected_spk);

        {
            // Player order should not matter.
            (contract.players[0], contract.players[1]) = (contract.players[1], contract.players[0]);
            let funding_spk = contract
                .multisig_spk_funding()
                .expect("error computing funding SPK");
            assert_eq!(funding_spk, expected_spk);
        }
    }

    #[test]
    fn test_tx_outcome() {
        let test_contract = TestContract::new_simple_duel();
        let mut contract = test_contract.contract_params();

        let funding_outpoint = OutPoint {
            txid: "0000000000000000000000000000000000000000000000000000000000000000"
                .parse()
                .unwrap(),
            vout: 4,
        };
        let funding_value = Amount::from_sat(5_000_000);

        // Player 1 wins
        let outcome_index = 0;

        let mut outcome_tx = contract
            .tx_outcome(outcome_index, funding_outpoint, funding_value)
            .expect("failed to build outcome TX");

        let expected_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: funding_outpoint,
                sequence: Sequence::MAX,
                ..TxIn::default()
            }],
            output: vec![TxOut {
                value: funding_value - Amount::from_sat(11_100),
                script_pubkey: ScriptBuf::from_hex(
                    "51208871c31610f567c0a9e59198fbfa3ccb6f42113023050653e8d203e2dd86e437",
                )
                .unwrap(),
            }],
        };

        assert_eq!(outcome_tx, expected_tx);

        {
            // Player order should not matter.
            (contract.players[0], contract.players[1]) = (contract.players[1], contract.players[0]);
            let outcome_tx = contract
                .tx_outcome(outcome_index, funding_outpoint, funding_value)
                .expect("failed to build outcome TX");
            assert_eq!(outcome_tx, expected_tx);
        }

        let funding_spend_info = contract.spend_info_funding().unwrap();

        // Hashing the outcome TX.
        let sighash = funding_spend_info
            .sighash_tx_outcome(&outcome_tx, funding_value)
            .expect("error producing sighash on outcome TX");

        // Adaptor-signing the outcome TX sighash, locked by the oracle's outcome point.
        let outcome_lock_point = contract.event.outcome_lock_point(outcome_index).unwrap();
        let seckeys = [&test_contract.market_maker_key]
            .into_iter()
            .chain(&test_contract.player_keys)
            .copied();
        let adaptor_signature = musig2_group_sign_adaptor(
            funding_spend_info.key_agg_ctx(),
            sighash,
            seckeys,
            outcome_lock_point,
        );

        let outcome_secret = contract
            .event
            .outcome_secret(
                outcome_index,
                test_contract.oracle_key,
                test_contract.oracle_nonce,
            )
            .unwrap();
        let signature: CompactSignature = adaptor_signature.adapt(outcome_secret).unwrap();
        outcome_tx.input[0].witness.push(signature.serialize());

        assert_eq!(
            format!("{:x}", signature),
            "66f61240bc6392ca4d20a091a8d470c62f2721dbd475f1dac985d3d652480839\
             dd5f611c64219cf558145b84a7843ebd93289a0729b9e517ba4fd4f62a880fc5",
        );
    }
}
