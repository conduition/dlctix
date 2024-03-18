use bitcoin::Amount;
use dlctix::{ContractParameters, EventAnnouncement, Outcome};
use secp::Point;
use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;

pub type PlayerID = u128;

/// Each value in the map is a weighted likelihood. Higher -> more likely to occur.
pub type OutcomeOdds = BTreeMap<Outcome, u64>;

#[derive(Serialize, Deserialize)]
pub struct ClientHello {
    pub player_pubkey: Point,
    pub payout_hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub struct ServerHello {
    pub player_id: PlayerID,
    pub ticket_hash: [u8; 32],
    pub market_maker_pubkey: Point,
    pub event: EventAnnouncement,
    pub odds: OutcomeOdds,
}

// TODO rename: ClientIntent
#[derive(Serialize, Deserialize)]
pub struct Intent {
    pub outcome: Outcome,
    pub budget: bitcoin::Amount,
}

#[derive(Serialize, Deserialize)]
pub struct ServerOffer {
    pub contract_parameters: ContractParameters,
    pub deposit_amount: Amount,
}

#[derive(Serialize, Deserialize)]
pub enum ClientOfferAck {
    Accept,
    Reject,
}

#[derive(Serialize, Deserialize)]
pub enum ServerOfferAck {
    Ok,
    Retry,
}
