use bitcoin::{Amount, FeeRate};
use secp::Point;

use crate::{
    consts::{P2TR_DUST_VALUE, P2TR_SCRIPT_PUBKEY_SIZE},
    contract::fees,
    errors::Error,
    oracles::EventAnnouncment,
    parties::{MarketMaker, Player},
};

use std::collections::{BTreeMap, BTreeSet};

/// Represents a mapping of player to payout weight for a given outcome.
///
/// A player's payout is proportional to the size of their payout weight
/// in comparison to the payout weights of all other winners.
pub type PayoutWeights = BTreeMap<Player, u64>;

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

    /// The amount of on-chain capital which the market maker will provide when funding
    /// the initial multisig deposit contract.
    pub funding_value: Amount,

    /// A reasonable number of blocks within which a transaction can confirm.
    /// Used for enforcing relative locktime timeout spending conditions.
    pub relative_locktime_block_delta: u16,
}

/// Points to a situation where a player wins a payout from the DLC.
#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub(crate) struct WinCondition {
    pub(crate) outcome_index: usize,
    pub(crate) winner: Player,
}

impl ContractParameters {
    pub(crate) fn outcome_output_value(&self) -> Result<Amount, Error> {
        let input_weights = [bitcoin::transaction::InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH];
        let fee = fees::fee_calc_safe(self.fee_rate, input_weights, [P2TR_SCRIPT_PUBKEY_SIZE])?;
        let outcome_value = fees::fee_subtract_safe(self.funding_value, fee, P2TR_DUST_VALUE)?;
        Ok(outcome_value)
    }

    /// Return the set of all win conditions which this pubkey will need to sign for.
    ///
    /// This might be empty if the player isn't due to receive any payouts on any DLC outcome.
    pub(crate) fn win_conditions_controlled_by_pubkey(
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
            // by `seckey`. If we're the market maker, we sign every win condition.
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
