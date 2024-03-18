pub(crate) mod fees;
pub(crate) mod outcome;
pub(crate) mod split;

use bitcoin::{transaction::InputWeightPrediction, Amount, FeeRate, TxOut};
use secp::Point;
use serde::{Deserialize, Serialize};

use crate::{
    consts::{P2TR_DUST_VALUE, P2TR_SCRIPT_PUBKEY_SIZE},
    errors::Error,
    oracles::EventAnnouncement,
    parties::{MarketMaker, Player},
    spend_info::FundingSpendInfo,
};

use std::collections::{BTreeMap, BTreeSet};

/// A type alias for clarity. Players in the DLC are often referred to by their
/// index in the sorted set of players.
pub type PlayerIndex = usize;

/// A type alias for clarity. DLC outcomes are sometimes referred to by their
/// index in the set of possible outcome messages.
pub type OutcomeIndex = usize;

/// Represents a mapping of player to payout weight for a given outcome.
///
/// A player's payout under an outcome is proportional to the size of their payout weight
/// relative to the sum of payout weights of all other winners for that outcome.
///
/// ```not_rust
/// total_payout = contract_value * weights[player] / sum(weights)
/// ```
///
/// Players who should not receive a payout from an outcome MUST NOT be given an entry
/// in a `PayoutWeights` map.
pub type PayoutWeights = BTreeMap<PlayerIndex, u64>;

/// Represents the parameters which all players and the market maker must agree on
/// to construct a ticketed DLC.
///
/// If all players use the same [`ContractParameters`], they should be able to
/// construct identical sets of outcome and split transactions, and exchange musig2
/// signatures thereupon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractParameters {
    /// The market maker who provides capital for the DLC ticketing process.
    pub market_maker: MarketMaker,

    /// The set of players in the DLC. Two players in the same DLC _may_ share
    /// the same public key, but MUST NOT share the same payout hash or ticket hash.
    pub players: BTreeSet<Player>,

    /// The event whose outcome determines the payouts.
    pub event: EventAnnouncement,

    /// A mapping of payout weights under different outcomes. Attestation indexes should
    /// align with [`self.event.outcome_messages`][EventAnnouncement::outcome_messages].
    ///
    /// If this map does not contain a key of [`Outcome::Expiry`], then there is no expiry
    /// condition, and the money simply remains locked in the funding outpoint until the
    /// Oracle's attestation is found.
    pub outcome_payouts: BTreeMap<Outcome, PayoutWeights>,

    /// A default mining fee rate to be used for pre-signed transactions.
    pub fee_rate: FeeRate,

    /// The amount of on-chain capital which the market maker will provide when funding
    /// the initial multisig deposit contract (after on-chain mining fees).
    pub funding_value: Amount,

    /// A reasonable number of blocks within which a transaction can confirm.
    /// Used for enforcing relative locktime timeout spending conditions.
    ///
    /// Reasonable values are:
    ///
    /// - `72`:  ~12 hours
    /// - `144`: ~24 hours
    /// - `432`: ~72 hours
    /// - `1008`: ~1 week
    pub relative_locktime_block_delta: u16,
}

/// Represents one possible outcome branch of the DLC. This includes both
/// outcomes attested-to by the Oracle, and expiry.
#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum Outcome {
    /// Indicates the oracle attested to a particular outcome of the given index.
    Attestation(OutcomeIndex),

    /// Indicates the oracle failed to attest to any outcome, and the event expiry
    /// timelock was reached.
    Expiry,
}

/// Points to a situation where a player wins a payout from the DLC.
#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct WinCondition {
    pub outcome: Outcome,
    pub player_index: PlayerIndex,
}

impl ContractParameters {
    /// Verifies the parameters are in standardized format, checking for
    /// errors such as duplicate players or zero-value payouts.
    pub fn validate(&self) -> Result<(), Error> {
        let uniq_ticket_hashes: BTreeSet<&[u8; 32]> = self
            .players
            .iter()
            .map(|player| &player.ticket_hash)
            .collect();

        // This would imply the players array contains duplicate ticket hashes.
        if uniq_ticket_hashes.len() != self.players.len() {
            return Err(Error);
        }

        for (outcome, payout_map) in self.outcome_payouts.iter() {
            // Check for unknown outcomes.
            if !self.event.is_valid_outcome(outcome) {
                return Err(Error);
            }

            // Check for empty payout map.
            if payout_map.len() == 0 {
                return Err(Error);
            }

            for (&player_index, &weight) in payout_map.iter() {
                // Check for zero payout weights.
                if weight == 0 {
                    return Err(Error);
                }

                // Check for out-of-bounds player indexes.
                if player_index >= self.players.len() {
                    return Err(Error);
                }
            }
        }

        // Must use a non-zero fee rate.
        if self.fee_rate == FeeRate::ZERO {
            return Err(Error);
        }

        // Must use a non-zero locktime delta
        if self.relative_locktime_block_delta == 0 {
            return Err(Error);
        }

        // Must be funded by some fixed non-zero amount.
        if self.funding_value < Amount::ZERO {
            return Err(Error);
        }

        Ok(())
    }

    /// Return a sorted vector of players. Each player's index in this vector
    /// should be used as an identifier for the DLC.
    pub fn sorted_players<'a>(&'a self) -> Vec<&'a Player> {
        self.players.iter().collect()
    }

    /// Returns the transaction output which the funding transaction should pay to.
    ///
    /// Avoid overusing this method, as it recomputes the aggregated key every time
    /// it is invoked. Instead, prefer
    /// [`TicketedDLC::funding_output`][crate::TicketedDLC::funding_output].
    pub fn funding_output(&self) -> Result<TxOut, Error> {
        let spend_info =
            FundingSpendInfo::new(&self.market_maker, &self.players, self.funding_value)?;
        Ok(spend_info.funding_output())
    }

    pub(crate) fn outcome_output_value(&self) -> Result<Amount, Error> {
        let input_weights = [InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH];
        let fee = fees::fee_calc_safe(self.fee_rate, input_weights, [P2TR_SCRIPT_PUBKEY_SIZE])?;
        let outcome_value = fees::fee_subtract_safe(self.funding_value, fee, P2TR_DUST_VALUE)?;
        Ok(outcome_value)
    }

    /// Returns the set of player indexes which this pubkey can sign for.
    ///
    /// This might contain multiple players if the same key joined the DLC
    /// with different ticket/payout hashes.
    pub fn players_controlled_by_pubkey(&self, pubkey: Point) -> BTreeSet<PlayerIndex> {
        self.players
            .iter()
            .enumerate()
            .filter_map(|(i, player)| {
                if player.pubkey == pubkey {
                    Some(i)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return the set of all win conditions for which the given pubkey can claim
    /// a split transaction output. In other words, this returns the possible
    /// paths for a given signer to claim winnings.
    ///
    /// If `pubkey` belongs to one or more players, this returns all [`WinCondition`]s
    /// in which the player or players are winners.
    ///
    /// If `pubkey` belongs to the market maker, this returns every [`WinCondition`]
    /// across the entire contract.
    ///
    /// Returns `None` if the pubkey does not belong to any player in the DLC.
    ///
    /// Returns an empty `BTreeSet` if the player is part of the DLC, but isn't due to
    /// receive any payouts on any DLC outcome.
    pub fn win_conditions_claimable_by_pubkey(
        &self,
        pubkey: Point,
    ) -> Option<BTreeSet<WinCondition>> {
        // To sign as the market maker, the caller need only provide the correct secret key.
        let is_market_maker = pubkey == self.market_maker.pubkey;

        let controlling_players = self.players_controlled_by_pubkey(pubkey);

        // Short circuit if this pubkey is not known.
        if controlling_players.is_empty() && !is_market_maker {
            return None;
        }

        let mut relevant_win_conditions = BTreeSet::<WinCondition>::new();
        for (&outcome, payout_map) in self.outcome_payouts.iter() {
            // We can broadcast the split TX for any win-conditions whose player is
            // controlled by `pubkey`. If we're the market maker, we have a claim
            // path on every win condition.
            relevant_win_conditions.extend(payout_map.keys().filter_map(|player_index| {
                if is_market_maker || controlling_players.contains(player_index) {
                    Some(WinCondition {
                        player_index: *player_index,
                        outcome,
                    })
                } else {
                    None
                }
            }));
        }

        Some(relevant_win_conditions)
    }

    /// Return the set of all win conditions which the given pubkey will need to sign
    /// split transactions for.
    ///
    /// If `pubkey` belongs to one or more players, this returns all [`WinCondition`]s
    /// for outcomes in which the player or players are winners.
    ///
    /// If `pubkey` belongs to the market maker, this returns every [`WinCondition`]
    /// across the entire contract.
    ///
    /// Returns `None` if the pubkey does not belong to any player in the DLC.
    ///
    /// Returns an empty `BTreeSet` if the player is part of the DLC, but isn't due to
    /// receive any payouts on any DLC outcome.
    pub fn win_conditions_controlled_by_pubkey(
        &self,
        pubkey: Point,
    ) -> Option<BTreeSet<WinCondition>> {
        // To sign as the market maker, the caller need only provide the correct secret key.
        let is_market_maker = pubkey == self.market_maker.pubkey;

        let controlling_players = self.players_controlled_by_pubkey(pubkey);

        // Short circuit if this pubkey is not known.
        if controlling_players.is_empty() && !is_market_maker {
            return None;
        }

        let mut win_conditions_to_sign = BTreeSet::<WinCondition>::new();
        for (&outcome, payout_map) in self.outcome_payouts.iter() {
            // We want to sign the split TX for any win-conditions under outcomes where the
            // given `pubkey` is one of the winners. If we're the market maker, we sign every
            // win condition.
            if is_market_maker
                || controlling_players
                    .iter()
                    .any(|player_index| payout_map.contains_key(player_index))
            {
                win_conditions_to_sign.extend(payout_map.keys().map(|&player_index| {
                    WinCondition {
                        player_index,
                        outcome,
                    }
                }));
            }
        }

        Some(win_conditions_to_sign)
    }

    pub fn sigmap_for_pubkey(&self, pubkey: Point) -> Option<SigMap<()>> {
        let win_conditions = self.win_conditions_controlled_by_pubkey(pubkey)?;
        let sigmap = SigMap {
            by_outcome: self
                .outcome_payouts
                .iter()
                .map(|(&outcome, _)| (outcome, ()))
                .collect(),
            by_win_condition: win_conditions.into_iter().map(|w| (w, ())).collect(),
        };
        Some(sigmap)
    }

    /// Return a full set of all possible win conditions for this DLC.
    pub fn all_win_conditions(&self) -> BTreeSet<WinCondition> {
        let mut all_win_conditions = BTreeSet::new();
        for (&outcome, payout_map) in self.outcome_payouts.iter() {
            all_win_conditions.extend(payout_map.keys().map(|&player_index| WinCondition {
                player_index,
                outcome,
            }));
        }
        all_win_conditions
    }

    /// Returns an empty sigmap covering every outcome and every win condition.
    /// This encompasses every possible message whose signatures are needed
    /// to set up the contract.
    pub fn full_sigmap(&self) -> SigMap<()> {
        SigMap {
            by_outcome: self
                .outcome_payouts
                .iter()
                .map(|(&outcome, _)| (outcome, ()))
                .collect(),
            by_win_condition: self
                .all_win_conditions()
                .into_iter()
                .map(|win_cond| (win_cond, ()))
                .collect(),
        }
    }
}

/// Represents a mapping of different signature requirements to some arbitrary type T.
/// This can be used to efficiently look up signatures, nonces, etc, for each
/// outcome transaction, and for different [`WinCondition`]s within each split transaction.
#[derive(Debug, Clone, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct SigMap<T> {
    pub by_outcome: BTreeMap<Outcome, T>,
    pub by_win_condition: BTreeMap<WinCondition, T>,
}

impl<T> SigMap<T> {
    pub fn map<V, F1, F2>(self, map_outcomes: F1, map_win_conditions: F2) -> SigMap<V>
    where
        F1: Fn(Outcome, T) -> V,
        F2: Fn(WinCondition, T) -> V,
    {
        SigMap {
            by_outcome: self
                .by_outcome
                .into_iter()
                .map(|(o, t)| (o, map_outcomes(o, t)))
                .collect(),
            by_win_condition: self
                .by_win_condition
                .into_iter()
                .map(|(w, t)| (w, map_win_conditions(w, t)))
                .collect(),
        }
    }

    pub fn map_values<V, F>(self, mut map_fn: F) -> SigMap<V>
    where
        F: FnMut(T) -> V,
    {
        SigMap {
            by_outcome: self
                .by_outcome
                .into_iter()
                .map(|(o, t)| (o, map_fn(t)))
                .collect(),
            by_win_condition: self
                .by_win_condition
                .into_iter()
                .map(|(w, t)| (w, map_fn(t)))
                .collect(),
        }
    }

    pub fn by_ref(&self) -> SigMap<&T> {
        SigMap {
            by_outcome: self.by_outcome.iter().map(|(&k, v)| (k, v)).collect(),
            by_win_condition: self.by_win_condition.iter().map(|(&k, v)| (k, v)).collect(),
        }
    }

    /// Returns true if the given sigmap mirrors the keys of this sigmap exactly.
    /// This means both sigmaps have entries for all the same outcomes and win
    /// conditions, without any extra leftover entries.
    pub fn is_mirror<V>(&self, other: &SigMap<V>) -> bool {
        for outcome in self.by_outcome.keys() {
            if !other.by_outcome.contains_key(outcome) {
                return false;
            }
        }
        for win_cond in self.by_win_condition.keys() {
            if !other.by_win_condition.contains_key(win_cond) {
                return false;
            }
        }

        if self.by_outcome.len() != other.by_outcome.len()
            || self.by_win_condition.len() != other.by_win_condition.len()
        {
            return false;
        }

        true
    }
}
