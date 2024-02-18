pub(crate) mod fees;
pub(crate) mod outcome;
pub(crate) mod split;

use bitcoin::{transaction::InputWeightPrediction, Amount, FeeRate};
use secp::Point;

use crate::{
    consts::{P2TR_DUST_VALUE, P2TR_SCRIPT_PUBKEY_SIZE},
    errors::Error,
    oracles::EventAnnouncment,
    parties::{MarketMaker, Player},
};

use std::collections::{BTreeMap, BTreeSet};

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
pub type PayoutWeights = BTreeMap<Player, u64>;

/// Represents the parameters which all players and the market maker must agree on
/// to construct a ticketed DLC.
///
/// If all players use the same [`ContractParameters`], they should be able to
/// construct identical sets of outcome and split transactions, and exchange musig2
/// signatures thereupon.
#[derive(Debug, Clone)]
pub struct ContractParameters {
    /// The market maker who provides capital for the DLC ticketing process.
    pub market_maker: MarketMaker,

    /// The set of players in the DLC. Two players in the same DLC _may_ share
    /// the same public key, but MUST NOT share the same payout hash or ticket hash.
    pub players: BTreeSet<Player>,

    /// The event whose outcome determines the payouts.
    pub event: EventAnnouncment,

    /// An ordered list of payout under different outcomes. Should align with
    /// `self.event.outcome_messages`.
    pub outcome_payouts: Vec<PayoutWeights>,

    /// Who is paid out in the event of an expiry (when the oracle attestation is not
    /// received by [`event.expiry`][EventAnnouncment::expiry]). If this field is `None`,
    /// then there is no expiry condition, and the money simply remains locked in the
    /// funding outpoint until the Oracle's attestation is found.
    pub expiry_payout: Option<PayoutWeights>,

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

/// Points to a situation where a player wins a payout from the DLC.
#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct WinCondition {
    pub outcome_index: usize,
    pub winner: Player,
}

impl ContractParameters {
    pub(crate) fn outcome_output_value(&self) -> Result<Amount, Error> {
        let input_weights = [InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH];
        let fee = fees::fee_calc_safe(self.fee_rate, input_weights, [P2TR_SCRIPT_PUBKEY_SIZE])?;
        let outcome_value = fees::fee_subtract_safe(self.funding_value, fee, P2TR_DUST_VALUE)?;
        Ok(outcome_value)
    }

    /// Return the set of all win conditions which the given pubkey will need to sign
    /// split transactions for.
    ///
    /// Returns `None` if the pubkey does not belong to any player in the DLC.
    ///
    /// Returns an empty `BTreeSet if the player is part of the DLC, but isn't due to
    /// receive any payouts on any DLC outcome.
    pub fn win_conditions_controlled_by_pubkey(
        &self,
        pubkey: Point,
    ) -> Option<BTreeSet<WinCondition>> {
        // To sign as the market maker, the caller need only provide the correct secret key.
        let is_market_maker = pubkey == self.market_maker.pubkey;

        // This might contain multiple players if the same key joined the DLC
        // with different ticket/payout hashes.
        let controlling_players: BTreeSet<&Player> = self
            .players
            .iter()
            .filter(|player| player.pubkey == pubkey)
            .collect();

        // Short circuit if this pubkey is not known.
        if controlling_players.is_empty() && !is_market_maker {
            return None;
        }

        let mut win_conditions_to_sign = BTreeSet::<WinCondition>::new();
        for (outcome_index, payout_map) in self.outcome_payouts.iter().enumerate() {
            // We want to sign the split TX for any win-conditions whose player is controlled
            // by `pubkey`. If we're the market maker, we sign every win condition.
            win_conditions_to_sign.extend(
                payout_map
                    .keys()
                    .filter(|winner| is_market_maker || controlling_players.contains(winner))
                    .map(|&winner| WinCondition {
                        winner,
                        outcome_index,
                    }),
            );
        }

        Some(win_conditions_to_sign)
    }
}
