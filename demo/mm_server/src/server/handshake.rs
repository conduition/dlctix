use bitcoin::Amount;

use super::SOCKET_DEFAULT_READ_TIMEOUT;
use crate::errors::InvalidInputError;
use crate::global_state::{GlobalState, PlayerRegistration};
use common::{ClientHello, Intent, ServerHello};
use dlctix::{hashlock, Player};

use std::{error::Error, net, sync::RwLock, time::Duration};

const MIN_BUDGET: Amount = Amount::from_sat(70_000);

pub(crate) fn handshake_player_register(
    state: &RwLock<GlobalState>,
    conn: net::TcpStream,
) -> Result<(), Box<dyn Error>> {
    let client_hello: ClientHello = serde_cbor::from_reader(&conn)?;

    // Sample a random ticket preimage for this player.
    let mut rng = rand::thread_rng();
    let ticket_preimage = hashlock::preimage_random(&mut rng);
    let ticket_hash = hashlock::sha256(&ticket_preimage);

    // The player ID is simply the first 16 bytes of the ticket hash.
    let player_id = u128::from_be_bytes({
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&ticket_hash[..16]);
        buf
    });

    let player = Player {
        pubkey: client_hello.player_pubkey,
        ticket_hash,
        payout_hash: client_hello.payout_hash,
    };

    let server_hello = {
        let state_rlock = state.read().unwrap();
        ServerHello {
            player_id,
            ticket_hash,
            market_maker_pubkey: state_rlock.market_maker_pubkey,
            event: state_rlock.event.clone(),
            odds: state_rlock.odds.clone(),
        }
    };
    serde_cbor::to_writer(&conn, &server_hello)?;

    // Give the client 2 minutes to compose an Intent.
    conn.set_read_timeout(Some(Duration::from_secs(120)))?;
    let intent: Intent = serde_cbor::from_reader(&conn)?;
    conn.set_read_timeout(Some(SOCKET_DEFAULT_READ_TIMEOUT))?;

    {
        // validate intent outcome is acceptable
        let state_rlock = state.read().unwrap();
        if !state_rlock.event.is_valid_outcome(&intent.outcome) {
            return Err(InvalidInputError(
                "player's intended outcome is not valid for this event",
            ))?;
        }

        if !state_rlock.odds.contains_key(&intent.outcome) {
            return Err(InvalidInputError(format!(
                "we have no odds for the player's requested outcome '{}'",
                intent.outcome
            )))?;
        }

        if intent.budget < MIN_BUDGET {
            return Err(InvalidInputError(format!(
                "budget must be at least {}",
                MIN_BUDGET
            )))?;
        }
    }

    let registration = PlayerRegistration {
        ticket_preimage,
        player,
        intent,
        connection: conn,
    };

    println!(
        "registering new player: {}",
        serde_json::to_string_pretty(&registration).unwrap()
    );
    state
        .write()
        .unwrap()
        .registrations
        .insert(player_id, registration);

    Ok(())
}
