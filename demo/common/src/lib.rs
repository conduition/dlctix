use bitcoin::Amount;
use dlctix::musig2::AggNonce;
use dlctix::secp::Point;
use dlctix::{ContractParameters, ContractSignatures, EventAnnouncement, Outcome, SigMap};
use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;

pub type PlayerID = u128;

/// Each value in the map is a weighted likelihood. Higher -> more likely to occur.
pub type OutcomeOdds = BTreeMap<Outcome, u64>;

#[derive(Serialize, Deserialize)]
pub struct ClientHello {
    pub player_pubkey: Point,
    #[serde(serialize_with = "serdect::array::serialize_hex_lower_or_bin")]
    pub payout_hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub struct ServerHello {
    pub player_id: PlayerID,
    #[serde(serialize_with = "serdect::array::serialize_hex_lower_or_bin")]
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

#[derive(Serialize, Deserialize)]
pub enum ServerNonceAck {
    Ok(SigMap<AggNonce>),
}

#[derive(Serialize, Deserialize)]
pub enum ServerSignatureAck {
    Ok(ContractSignatures),
}
