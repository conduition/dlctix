use bitcoin::{Amount, FeeRate};

use crate::payouts::compute_deposit_and_payout_weights;
use common::{Intent, OutcomeOdds, PlayerID, ServerOffer};
use dlctix::secp::{Point, Scalar};
use dlctix::{hashlock, ContractParameters, EventAnnouncement, MarketMaker, Player, PlayerIndex};

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net,
};

const RELATIVE_LOCKTIME_BLOCK_DELTA: u16 = 60;

/// TODO: this should be dynamic
const FEE_RATE: FeeRate = FeeRate::from_sat_per_vb_unchecked(80);

#[derive(serde::Serialize)]
pub(crate) struct PlayerRegistration {
    #[serde(serialize_with = "serdect::array::serialize_hex_lower_or_bin")]
    pub(crate) ticket_preimage: hashlock::Preimage,
    pub(crate) player: Player,
    pub(crate) intent: Intent,
    #[serde(skip)]
    pub(crate) connection: net::TcpStream,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Stage {
    IntentRegistry,
    OfferAndAck,
}

pub(crate) struct GlobalState {
    pub(crate) event: EventAnnouncement,
    pub(crate) odds: OutcomeOdds,
    pub(crate) bitcoind: bitcoincore_rpc::Client,
    pub(crate) market_maker_seckey: Scalar,
    pub(crate) market_maker_pubkey: Point,
    pub(crate) registrations: HashMap<PlayerID, PlayerRegistration>,
    pub(crate) stage: Stage,
}

impl GlobalState {
    pub(crate) fn construct_offers(&self) -> BTreeMap<PlayerID, ServerOffer> {
        // Sort players and map them to their IDs.
        let player_ids: BTreeMap<&Player, PlayerID> = self
            .registrations
            .iter()
            .map(|(&id, reg)| (&reg.player, id))
            .collect();

        // Map player identifiers to player indexes.
        let player_indexes: HashMap<PlayerID, PlayerIndex> = player_ids
            .values()
            .enumerate()
            .map(|(index, &id)| (id, index))
            .collect();

        let player_intents: BTreeMap<PlayerIndex, &Intent> = self
            .registrations
            .iter()
            .map(|(id, reg)| (player_indexes[id], &reg.intent))
            .collect();

        // Compute the total amount of bitcoin which all players wish to wager.
        let (deposit_amounts, outcome_payouts) = compute_deposit_and_payout_weights(
            &player_intents,
            &self.odds,
            self.event.all_outcomes(),
        );
        let funding_value: Amount = deposit_amounts.values().copied().sum();

        let players: BTreeSet<Player> = self
            .registrations
            .values()
            .map(|reg| reg.player.clone())
            .collect();

        let contract_parameters = ContractParameters {
            market_maker: MarketMaker {
                pubkey: self.market_maker_pubkey,
            },
            players,
            event: self.event.clone(),
            funding_value,
            outcome_payouts,
            fee_rate: FEE_RATE,
            relative_locktime_block_delta: RELATIVE_LOCKTIME_BLOCK_DELTA,
        };

        player_indexes
            .into_iter()
            .map(|(player_id, player_index)| {
                let offer = ServerOffer {
                    contract_parameters: contract_parameters.clone(),
                    deposit_amount: deposit_amounts[&player_index],
                };
                (player_id, offer)
            })
            .collect()
    }
}
