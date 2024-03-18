mod errors;
mod global_state;
mod payouts;
mod server;

use bitcoincore_rpc::RpcApi;

use crate::global_state::{GlobalState, Stage};
use common::OutcomeOdds;
use dlctix::secp::Scalar;
use dlctix::EventAnnouncement;

use std::{
    collections::HashMap,
    env,
    error::Error,
    sync::{Arc, RwLock},
};

fn run_server() -> Result<(), Box<dyn Error>> {
    let bind_addr = env::var("MM_SERVER_ADDRESS").unwrap_or_else(|_| "0.0.0.0:1420".to_string());

    let market_maker_seckey: Scalar = env::var("MM_SECRET_KEY")?.parse()?;
    let market_maker_pubkey = market_maker_seckey.base_point_mul();

    let event: EventAnnouncement =
        serde_cbor::from_slice(&hex::decode(env::var("DLC_EVENT_ANNOUNCEMENT_CBOR")?)?)?;

    let odds: OutcomeOdds =
        serde_cbor::from_slice(&hex::decode(env::var("DLC_EVENT_ODDS_CBOR")?)?)?;

    let bitcoind = {
        let bitcoind_rpc_url = std::env::var("BITCOIND_RPC_URL")?;
        let bitcoind_auth_username = std::env::var("BITCOIND_RPC_AUTH_USERNAME")?;
        let bitcoind_auth_password = std::env::var("BITCOIND_RPC_AUTH_PASSWORD")?;
        let auth = bitcoincore_rpc::Auth::UserPass(bitcoind_auth_username, bitcoind_auth_password);
        bitcoincore_rpc::Client::new(&bitcoind_rpc_url, auth)?
    };

    // Check that a wallet is loaded
    let _ = bitcoind.get_wallet_info()?;

    let global_state = Arc::new(RwLock::new(GlobalState {
        event,
        odds,
        market_maker_seckey,
        market_maker_pubkey,
        bitcoind,
        registrations: HashMap::new(),
        stage: Stage::IntentRegistry,
    }));

    server::serve(bind_addr, global_state)
}

fn main() {
    if let Err(e) = run_server() {
        eprintln!("fatal error: {}", e);
        std::process::exit(1);
    }
    println!("exiting OK");
}
