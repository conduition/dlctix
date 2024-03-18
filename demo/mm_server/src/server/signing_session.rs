use bitcoin::{absolute::LockTime, OutPoint, Transaction};
use bitcoincore_rpc::RpcApi;

use crate::global_state::GlobalState;
use common::{PlayerID, ServerNonceAck, ServerOffer, ServerOfferAck, ServerSignatureAck};
use dlctix::musig2::{PartialSignature, PubNonce};
use dlctix::secp::Point;
use dlctix::{SigMap, SignedContract, SigningSession, TicketedDLC};

use std::{
    collections::BTreeMap,
    error::Error,
    sync::{Arc, RwLock},
    thread,
};

pub(crate) fn run_signing_sessions(
    state: &Arc<RwLock<GlobalState>>,
    accepted_offers: BTreeMap<PlayerID, ServerOffer>,
) -> Result<(Transaction, SignedContract), Box<dyn Error>> {
    let contract_parameters = accepted_offers
        .values()
        .next()
        .unwrap()
        .contract_parameters
        .clone();

    // Create, fund, and sign the funding transaction using
    // bitcoind's current loaded wallet.
    let funding_tx = {
        let skeleton_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![contract_parameters.funding_output()?],
        };

        let state_rlock = state.read().unwrap();
        let funded_tx = state_rlock
            .bitcoind
            .fund_raw_transaction(&skeleton_tx, None, Some(true))?
            .hex;

        state_rlock
            .bitcoind
            .sign_raw_transaction_with_wallet(&funded_tx, None, None)?
            .transaction()?
    };

    let funding_outpoint = OutPoint {
        txid: funding_tx.txid(),
        vout: 0,
    };

    let ticketed_dlc = TicketedDLC::new(contract_parameters, funding_outpoint)?;
    let signing_session = SigningSession::new(
        ticketed_dlc,
        &mut rand::thread_rng(),
        state.read().unwrap().market_maker_seckey,
    )?;

    // Round 1: receive nonces.
    let thread_handles: Vec<thread::JoinHandle<_>> = accepted_offers
        .keys()
        .map(|&player_id| {
            let state = Arc::clone(state);
            thread::spawn(move || -> serde_cbor::Result<(Point, SigMap<PubNonce>)> {
                let state_rlock = state.read().unwrap();
                let conn = &state_rlock.registrations[&player_id].connection;
                let pubkey = state_rlock.registrations[&player_id].player.pubkey;
                serde_cbor::to_writer(conn, &ServerOfferAck::Ok)?;
                let nonces: SigMap<PubNonce> = serde_cbor::from_reader(conn)?;
                Ok((pubkey, nonces))
            })
        })
        .collect();

    // TODO tell clients if someone failed to share nonces and we have to retry.
    let received_nonces: BTreeMap<Point, SigMap<PubNonce>> = thread_handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Result<_, serde_cbor::Error>>()?;

    // TODO handle invalid (incomplete) sets of nonces
    let signing_session = signing_session.compute_partial_signatures(received_nonces)?;

    // Round 2: distribute agg nonces and receive partial signatures
    let thread_handles: Vec<thread::JoinHandle<_>> = accepted_offers
        .keys()
        .map(|&player_id| {
            let state = Arc::clone(state);
            let agg_nonces = signing_session.aggregated_nonces().clone();

            thread::spawn(
                move || -> serde_cbor::Result<(Point, SigMap<PartialSignature>)> {
                    let state_rlock = state.read().unwrap();
                    let conn = &state_rlock.registrations[&player_id].connection;
                    let pubkey = state_rlock.registrations[&player_id].player.pubkey;

                    serde_cbor::to_writer(conn, &ServerNonceAck::Ok(agg_nonces))?;
                    let partial_sigs: SigMap<PartialSignature> = serde_cbor::from_reader(conn)?;
                    Ok((pubkey, partial_sigs))
                },
            )
        })
        .collect();

    let received_signatures: BTreeMap<Point, SigMap<PartialSignature>> = thread_handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Result<_, serde_cbor::Error>>()?;

    // TODO assign blame
    for (&signer, partial_sigs) in &received_signatures {
        signing_session.verify_partial_signatures(signer, partial_sigs)?;
    }

    let signed_contract = signing_session.aggregate_all_signatures(received_signatures)?;

    // Final round: distribute aggregated signatures.
    let thread_handles: Vec<thread::JoinHandle<_>> = accepted_offers
        .keys()
        .map(|&player_id| {
            let state = Arc::clone(state);
            // TODO send only pruned signatures to peers
            let signatures = signed_contract.all_signatures().clone();

            thread::spawn(move || -> serde_cbor::Result<()> {
                let state_rlock = state.read().unwrap();
                let conn = &state_rlock.registrations[&player_id].connection;
                serde_cbor::to_writer(conn, &ServerSignatureAck::Ok(signatures))
            })
        })
        .collect();

    // ensure all players receive their signatures
    for handle in thread_handles {
        handle.join().unwrap()?;
    }

    Ok((funding_tx, signed_contract))
}
