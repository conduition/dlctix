use super::{MIN_PLAYERS, SOCKET_DEFAULT_READ_TIMEOUT};
use crate::global_state::GlobalState;
use common::{ClientOfferAck, PlayerID, ServerOffer, ServerOfferAck};

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    net,
    sync::{mpsc, Arc, RwLock},
    thread,
    time::Duration,
};

fn send_offer_and_receive_ack(conn: &net::TcpStream, offer: &ServerOffer) -> ClientOfferAck {
    let client_offer_ack: ClientOfferAck = serde_cbor::to_writer(conn, offer)
        .and_then(|_| {
            // Give the user 2 minutes to ACK the offer. Fall back to rejection.
            conn.set_read_timeout(Some(Duration::from_secs(120)))
                .unwrap();
            serde_cbor::from_reader(conn)
        })
        .unwrap_or(ClientOfferAck::Reject);

    // Reset the read timeout.
    conn.set_read_timeout(Some(SOCKET_DEFAULT_READ_TIMEOUT))
        .unwrap();

    client_offer_ack
}

pub(crate) fn offer_and_ack_cycle(
    state: &Arc<RwLock<GlobalState>>,
) -> Result<Option<BTreeMap<PlayerID, ServerOffer>>, Box<dyn Error>> {
    let offers = state.read().unwrap().construct_offers();

    let (ack_sender, ack_receiver) = mpsc::channel();

    for (player_id, offer) in offers {
        let state = Arc::clone(state);
        let ack_sender = ack_sender.clone();

        thread::spawn(move || {
            let state_rlock = state.read().unwrap();
            let conn = &state_rlock.registrations[&player_id].connection;
            let client_offer_ack = send_offer_and_receive_ack(conn, &offer);
            ack_sender
                .send((player_id, offer, client_offer_ack))
                .unwrap();
        });
    }
    drop(ack_sender); // Otherwise the ack_receiver channel will stay open.

    let mut accepted_offers = BTreeMap::new();
    let mut rejected_players = BTreeSet::new();

    while let Ok((player_id, offer, client_offer_ack)) = ack_receiver.recv() {
        match client_offer_ack {
            ClientOfferAck::Accept => {
                accepted_offers.insert(player_id, offer);
            }
            ClientOfferAck::Reject => {
                rejected_players.insert(player_id);
            }
        };
    }

    if rejected_players.len() > 0 {
        let thread_handles: Vec<thread::JoinHandle<()>> = accepted_offers
            .into_keys()
            .map(|player_id| {
                let state = Arc::clone(state);
                thread::spawn(move || {
                    let state_rlock = state.read().unwrap();
                    let conn = &state_rlock.registrations[&player_id].connection;
                    if serde_cbor::to_writer(conn, &ServerOfferAck::Retry).is_err() {
                        drop(state_rlock);
                        state.write().unwrap().registrations.remove(&player_id);
                    }
                })
            })
            .collect();

        // Disconnect rejecting players.
        {
            let mut state_wlock = state.write().unwrap();
            for player_id in rejected_players {
                state_wlock.registrations.remove(&player_id);
            }
        }

        // Wait for all ACKs to be sent
        for handle in thread_handles {
            handle.join().unwrap();
        }

        // We don't have enough accepting players to try again.
        if state.read().unwrap().registrations.len() < MIN_PLAYERS {
            return Ok(None);
        }

        // Retry with accepting players.
        return offer_and_ack_cycle(state);
    }

    Ok(Some(accepted_offers))
}
