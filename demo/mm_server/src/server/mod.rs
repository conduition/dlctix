mod handshake;
mod offer_and_ack;

use crate::errors::WrongStageError;
use crate::global_state::{GlobalState, Stage};

use std::{
    error::Error,
    net,
    sync::{Arc, RwLock},
    thread,
    time::Duration,
};

pub(crate) const SOCKET_DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const SOCKET_WRITE_TIMEOUT: Duration = Duration::from_secs(8);

pub(crate) const MIN_PLAYERS: usize = 5;
pub(crate) const PLAYERS_THRESHOLD: usize = 10;

fn handle_tcp_conn(
    state: Arc<RwLock<GlobalState>>,
    conn: net::TcpStream,
) -> Result<(), Box<dyn Error>> {
    conn.set_read_timeout(Some(SOCKET_DEFAULT_READ_TIMEOUT))?;
    conn.set_write_timeout(Some(SOCKET_WRITE_TIMEOUT))?;

    {
        let state_rlock = state.read().unwrap();
        if state_rlock.stage != Stage::IntentRegistry {
            return Err(WrongStageError(state_rlock.stage))?;
        }
    }

    handshake::handshake_player_register(&state, conn)?;

    // Once we hit the minimum threshold, dispatch offers and then prompt for signatures.
    if state.read().unwrap().registrations.len() >= PLAYERS_THRESHOLD {
        {
            let mut state_wlock = state.write().unwrap();
            state_wlock.stage = Stage::OfferAndAck;
        }

        if let Some(accepted_players) = offer_and_ack::offer_and_ack_cycle(&state)? {
            // TODO prompt all players for signatures
        }
    }

    Ok(())
}

pub(crate) fn serve(
    bind_addr: String,
    global_state: Arc<RwLock<GlobalState>>,
) -> Result<(), Box<dyn Error>> {
    println!("starting listener on {}", bind_addr);
    let listener = net::TcpListener::bind(bind_addr)?;

    // TODO use thread pool
    println!("awaiting connections...");
    for stream in listener.incoming() {
        let conn = match stream {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("error accepting TCP connection: {}", e);
                continue;
            }
        };

        match conn.peer_addr() {
            Ok(peer_addr) => {
                println!("received new TCP connection from {}", peer_addr);
            }
            Err(e) => {
                eprintln!("new TCP connection; unable to get peer IP address: {}", e);
            }
        }

        let state = Arc::clone(&global_state);
        thread::spawn(move || {
            if let Err(e) = handle_tcp_conn(state, conn) {
                eprintln!("TCP connection handling failure: {}", e);
            }
        });
    }
    Ok(())
}
