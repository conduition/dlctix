use bitcoincore_rpc::{jsonrpc::serde_json, Auth, Client as BitcoinClient, RpcApi};
use dlctix::*;
use serial_test::serial;

use bitcoin::{
    blockdata::transaction::{predict_weight, InputWeightPrediction},
    key::TweakedPublicKey,
    locktime::absolute::LockTime,
    sighash::{Prevouts, SighashCache, TapSighashType},
    Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut,
};
use musig2::{CompactSignature, LiftedSignature, PartialSignature, PubNonce};
use rand::{CryptoRng, RngCore};
use secp::{Point, Scalar};

use std::collections::{BTreeMap, BTreeSet};

const P2TR_SCRIPT_PUBKEY_SIZE: usize = 34;

/// Generate a P2TR address which pays to the given pubkey (no tweak added).
fn p2tr_address(pubkey: Point) -> Address {
    let (xonly, _) = pubkey.into();
    let tweaked = TweakedPublicKey::dangerous_assume_tweaked(xonly);
    Address::p2tr_tweaked(tweaked, Network::Regtest)
}

/// Generate a P2TR script pubkey which pays to the given pubkey (no tweak added).
fn p2tr_script_pubkey(pubkey: Point) -> ScriptBuf {
    let (xonly, _) = pubkey.into();
    let tweaked = TweakedPublicKey::dangerous_assume_tweaked(xonly);
    ScriptBuf::new_p2tr_tweaked(tweaked)
}

/// Build a bitcoind RPC client for regtest. Expects the following environment variables
/// to be defined:
///
/// - `BITCOIND_RPC_URL`
/// - `BITCOIND_RPC_AUTH_USERNAME`
/// - `BITCOIND_RPC_AUTH_PASSWORD`
fn new_rpc_client() -> BitcoinClient {
    dotenv::dotenv().unwrap();

    let bitcoind_rpc_url =
        std::env::var("BITCOIND_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:18443".to_string());

    let bitcoind_auth_username =
        std::env::var("BITCOIND_RPC_AUTH_USERNAME").expect("missing BITCOIND_RPC_AUTH_USERNAME");

    let bitcoind_auth_password =
        std::env::var("BITCOIND_RPC_AUTH_PASSWORD").expect("missing BITCOIND_RPC_AUTH_PASSWORD");

    let auth = Auth::UserPass(bitcoind_auth_username, bitcoind_auth_password);
    BitcoinClient::new(&bitcoind_rpc_url, auth).expect("failed to create bitcoind RPC client")
}

const FUNDING_VALUE: Amount = Amount::from_sat(200_000);

/// Make sure we're on the regtest network and we have enough bitcoins
/// in the regtest node wallet, otherwise the actual test will not work.
fn check_regtest_wallet(rpc_client: &BitcoinClient, min_balance: Amount) {
    let info = rpc_client
        .get_mining_info()
        .expect("failed to get network info from remote node");

    assert_eq!(
        info.chain,
        bitcoin::Network::Regtest,
        "node should be running in regtest mode, found {} instead",
        info.chain
    );

    let mut wallet_info = rpc_client.get_wallet_info().unwrap_or_else(|_| {
        if let Some(wallet_name) = rpc_client.list_wallet_dir().unwrap().into_iter().next() {
            rpc_client.load_wallet(&wallet_name).unwrap();
        } else {
            rpc_client
                .create_wallet("dlctix_market_maker", None, None, None, None)
                .unwrap();
        }
        rpc_client.get_wallet_info().unwrap()
    });

    while wallet_info.balance < min_balance {
        mine_blocks(&rpc_client, 101).expect("error mining blocks");
        wallet_info = rpc_client.get_wallet_info().unwrap();
    }
}

/// Take some money from the regtest node and deposit it into the given address.
/// Return the outpoint and prevout.
fn take_usable_utxo(rpc: &BitcoinClient, address: &Address, amount: Amount) -> (OutPoint, TxOut) {
    check_regtest_wallet(rpc, amount + Amount::from_sat(50_000));

    let txid: bitcoin::Txid = rpc
        .call(
            "sendtoaddress",
            &[
                serde_json::Value::String(address.to_string()),
                serde_json::Value::Number(serde_json::Number::from_f64(amount.to_btc()).unwrap()),
                serde_json::Value::Null,
                serde_json::Value::Null,
                serde_json::Value::Null,
                serde_json::Value::Null,
                serde_json::Value::Null,
                serde_json::Value::Null,
                serde_json::Value::Null,
                // must specify fee rate or the regtest node will fail to estimate it
                serde_json::Value::Number(1.into()),
            ],
        )
        .unwrap();
    let sent_tx = rpc.get_raw_transaction(&txid, None).unwrap();

    let (vout, prevout) = sent_tx
        .output
        .into_iter()
        .enumerate()
        .find(|(_, output)| output.script_pubkey == address.script_pubkey())
        .unwrap();

    let outpoint = OutPoint {
        txid,
        vout: vout as u32,
    };

    (outpoint, prevout)
}

fn mine_blocks(rpc: &BitcoinClient, n_blocks: u16) -> Result<(), bitcoincore_rpc::Error> {
    let address = rpc
        .get_new_address(None, Some(bitcoincore_rpc::json::AddressType::Bech32m))?
        .require_network(bitcoin::Network::Regtest)
        .unwrap();
    rpc.generate_to_address(n_blocks as u64, &address)?;
    Ok(())
}

/// Construct and sign the funding transaction.
fn signed_funding_tx(
    market_maker_seckey: Scalar,
    funding_output: TxOut,
    mm_utxo_outpoint: OutPoint,
    mm_utxo_prevout: &TxOut,
) -> Transaction {
    let mut funding_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: mm_utxo_outpoint,
            ..TxIn::default()
        }],
        output: vec![funding_output],
    };

    let funding_tx_sighash = SighashCache::new(&funding_tx)
        .taproot_key_spend_signature_hash(
            0,
            &Prevouts::All(&[mm_utxo_prevout]),
            TapSighashType::Default,
        )
        .unwrap();

    let signature: CompactSignature =
        musig2::deterministic::sign_solo(market_maker_seckey, &funding_tx_sighash);

    funding_tx.input[0].witness.push(signature.serialize());
    funding_tx
}

/// Represents a simulated DLC player, including the ticket preimage which a player
/// herself may not actually know in a real DLC until having purchased it.
struct SimulatedPlayer {
    seckey: Scalar,
    ticket_preimage: hashlock::Preimage,
    payout_preimage: hashlock::Preimage,
    player: Player,
}

impl SimulatedPlayer {
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> SimulatedPlayer {
        let seckey = Scalar::random(rng);
        let payout_preimage = hashlock::preimage_random(rng);
        let ticket_preimage = hashlock::preimage_random(rng);
        SimulatedPlayer {
            seckey,
            payout_preimage,
            ticket_preimage,
            player: Player {
                pubkey: seckey.base_point_mul(),
                ticket_hash: hashlock::sha256(&ticket_preimage),
                payout_hash: hashlock::sha256(&payout_preimage),
            },
        }
    }
}

/// Cooperatively sign a `TicketedDLC` using the secret keys of every player
/// and the market maker. The order of secret keys in the `all_seckeys` iterator
/// does not matter.
fn musig_sign_ticketed_dlc<R: RngCore + CryptoRng>(
    ticketed_dlc: &TicketedDLC,
    all_seckeys: impl IntoIterator<Item = Scalar>,
    rng: &mut R,
) -> SignedContract {
    let signing_sessions: BTreeMap<Point, SigningSession<NonceSharingRound>> = all_seckeys
        .into_iter()
        .map(|seckey| {
            let session = SigningSession::new(ticketed_dlc.clone(), rng, seckey)
                .expect("error creating SigningSession");
            (seckey.base_point_mul(), session)
        })
        .collect();

    let pubnonces_by_sender: BTreeMap<Point, SigMap<PubNonce>> = signing_sessions
        .iter()
        .map(|(&sender_pubkey, session)| {
            // Simulate serialization, as pubnonces are usually sent over a transport channel.
            let serialized_nonces = serde_json::to_string(session.our_public_nonces())
                .expect("error serializing pubnonces");
            let received_pubnonces =
                serde_json::from_str(&serialized_nonces).expect("error deserializing pubnonces");
            (sender_pubkey, received_pubnonces)
        })
        .collect();

    let signing_sessions: BTreeMap<Point, SigningSession<PartialSignatureSharingRound>> =
        signing_sessions
            .into_iter()
            .map(|(pubkey, session)| {
                let new_session = session
                    .compute_partial_signatures(pubnonces_by_sender.clone())
                    .expect("failed to compute partial signatures");
                (pubkey, new_session)
            })
            .collect();

    let partial_sigs_by_sender: BTreeMap<Point, SigMap<PartialSignature>> = signing_sessions
        .iter()
        .map(|(&sender_pubkey, session)| {
            let serialized_sigs = serde_json::to_string(session.our_partial_signatures())
                .expect("error serializing partial signatures");
            let received_sigs = serde_json::from_str(&serialized_sigs)
                .expect("error deserializing partial signatures");
            (sender_pubkey, received_sigs)
        })
        .collect();

    // Everyone's signatures can be verified by everyone else.
    for session in signing_sessions.values() {
        for (&sender_pubkey, partial_sigs) in &partial_sigs_by_sender {
            session
                .verify_partial_signatures(sender_pubkey, partial_sigs)
                .expect("valid partial signatures should be verified as OK");
        }
    }

    let mut signed_contracts: BTreeMap<Point, SignedContract> = signing_sessions
        .into_iter()
        .map(|(pubkey, session)| {
            let signed_contract = session
                .aggregate_all_signatures(partial_sigs_by_sender.clone())
                .expect("error during signature aggregation");
            (pubkey, signed_contract)
        })
        .collect();

    // Everyone should have computed the same set of signatures.
    for contract1 in signed_contracts.values() {
        for contract2 in signed_contracts.values() {
            assert_eq!(contract1.all_signatures(), contract2.all_signatures());
        }
    }

    let (_, contract) = signed_contracts.pop_first().unwrap();

    // SignedContract should be able to be stored and retrieved via serde serialization.
    let decoded_contract = serde_json::from_str(
        &serde_json::to_string(&contract).expect("error serializing SignedContract"),
    )
    .expect("error deserializing SignedContract");
    assert_eq!(
        contract, decoded_contract,
        "deserialized SignedContract does not match original"
    );

    contract
}

#[test]
#[serial]
fn ticketed_dlc_with_on_chain_resolutions() {
    let mut rng = rand::thread_rng();

    // Oracle
    let oracle_seckey = Scalar::random(&mut rng);
    let oracle_secnonce = Scalar::random(&mut rng);

    // Market maker
    let market_maker_seckey = Scalar::random(&mut rng);
    let market_maker = MarketMaker {
        pubkey: market_maker_seckey.base_point_mul(),
    };
    let market_maker_address = p2tr_address(market_maker.pubkey);

    // players
    let alice = SimulatedPlayer::random(&mut rng);
    let bob = SimulatedPlayer::random(&mut rng);
    let carol = SimulatedPlayer::random(&mut rng);
    let dave = SimulatedPlayer::random(&mut rng);

    let players = BTreeSet::from([
        alice.player.clone(),
        bob.player.clone(),
        carol.player.clone(),
        dave.player.clone(),
    ]);
    let player_indexes: BTreeMap<Player, PlayerIndex> = players
        .iter()
        .enumerate()
        .map(|(i, player)| (player.clone(), i))
        .collect();

    let rpc = new_rpc_client();
    let block_height = rpc.get_block_count().unwrap();

    let outcome_payouts = BTreeMap::<Outcome, PayoutWeights>::from([
        (
            Outcome::Attestation(0),
            PayoutWeights::from([
                (player_indexes[&alice.player], 1),
                (player_indexes[&bob.player], 2),
                (player_indexes[&carol.player], 1),
            ]),
        ),
        (
            Outcome::Attestation(1),
            PayoutWeights::from([
                (player_indexes[&carol.player], 1),
                (player_indexes[&dave.player], 3),
            ]),
        ),
        (
            Outcome::Expiry,
            PayoutWeights::from([(player_indexes[&alice.player], 1)]),
        ),
    ]);

    let contract_params = ContractParameters {
        market_maker,
        players,
        event: EventAnnouncement {
            oracle_pubkey: oracle_seckey.base_point_mul(),
            nonce_point: oracle_secnonce.base_point_mul(),
            outcome_messages: vec![
                Vec::from(b"alice and bob win"),
                Vec::from(b"carol and dave win"),
            ],
            expiry: u32::try_from(block_height + 2000).ok(),
        },
        outcome_payouts,
        fee_rate: FeeRate::from_sat_per_vb_unchecked(100),
        funding_value: FUNDING_VALUE,
        relative_locktime_block_delta: 25,
    };

    // Fund the market maker
    let (mm_utxo_outpoint, mm_utxo_prevout) = take_usable_utxo(
        &rpc,
        &market_maker_address,
        FUNDING_VALUE + Amount::from_sat(50_000),
    );

    // Prepare a funding transaction
    let funding_tx = signed_funding_tx(
        market_maker_seckey,
        contract_params.funding_output().unwrap(),
        mm_utxo_outpoint,
        &mm_utxo_prevout,
    );
    let funding_outpoint = OutPoint {
        txid: funding_tx.txid(),
        vout: 0,
    };

    // Construct all the DLC transactions.
    let ticketed_dlc = TicketedDLC::new(contract_params, funding_outpoint)
        .expect("failed to constructed ticketed DLC transactions");

    // Sign all the transactions.
    let seckeys = [
        market_maker_seckey,
        alice.seckey,
        bob.seckey,
        carol.seckey,
        dave.seckey,
    ];

    let signed_contract = musig_sign_ticketed_dlc(&ticketed_dlc, seckeys, &mut rng);

    // At this point, the market maker is confident they'll be able to reclaim their
    // capital if needed, and the players know they'll be able to enforce the DLC outcome
    // if they purchase their ticket preimage.
    //
    // The market maker can now broadcast the funding TX.
    rpc.send_raw_transaction(&funding_tx)
        .expect("failed to broadcast funding TX");
    mine_blocks(&rpc, 1).unwrap();

    let event: &EventAnnouncement = &signed_contract.params().event;

    let outcome_index: usize = 0;

    // The oracle attests to outcome zero, where Alice, Bob, and Carol are winners.
    let oracle_attestation = event
        .attestation_secret(outcome_index, oracle_seckey, oracle_secnonce)
        .unwrap();

    // The attestation should be a valid BIP340 signature by the oracle's pubkey.
    {
        let oracle_signature = LiftedSignature::new(event.nonce_point, oracle_attestation);
        musig2::verify_single(
            event.oracle_pubkey,
            oracle_signature,
            &event.outcome_messages[outcome_index],
        )
        .expect("invalid oracle signature");
    }

    // Anyone can unlock and broadcast an outcome TX if they know the attestation.
    let outcome_tx = signed_contract
        .signed_outcome_tx(outcome_index, oracle_attestation)
        .expect("failed to sign outcome TX");
    rpc.send_raw_transaction(&outcome_tx)
        .expect("failed to broadcast outcome TX");

    // Assume Alice bought her ticket preimage. She can now
    // use it to unlock the split transaction.
    let alice_win_cond = WinCondition {
        outcome: Outcome::Attestation(outcome_index),
        player_index: player_indexes[&alice.player],
    };
    let split_tx = signed_contract
        .signed_split_tx(&alice_win_cond, alice.ticket_preimage)
        .expect("failed to sign split TX");

    // Alice should not be able to broadcast the split TX right away,
    // due to the relative locktime on the split TX.
    let err = rpc
        .send_raw_transaction(&split_tx)
        .expect_err("early broadcast of split TX should fail");
    assert_eq!(
        err.to_string(),
        "JSON-RPC error: RPC error response: RpcError { code: -26, \
            message: \"non-BIP68-final\", data: None }",
    );

    // Only after a block delay of `delta` should Alice be able to
    // broadcast the split TX.
    mine_blocks(&rpc, signed_contract.params().relative_locktime_block_delta).unwrap();
    rpc.send_raw_transaction(&split_tx)
        .expect("failed to broadcast split TX");

    // Alice, Bob, and Carol now have separate payout contracts with the market maker.

    // Alice paid for her ticket preimage, but wishes to receive a payout off-chain,
    // by selling her payout preimage to the market maker. The market maker uses the
    // payout preimage to sign a sellback TX which reclaims Alice's winnings before
    // she will have a chance to sweep them.
    let (alice_split_input, alice_split_prevout) = signed_contract
        .split_sellback_tx_input_and_prevout(&alice_win_cond)
        .unwrap();

    let mut sellback_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![alice_split_input],
        output: vec![TxOut {
            script_pubkey: p2tr_script_pubkey(alice.player.pubkey),
            value: {
                let sellback_tx_weight = predict_weight(
                    [signed_contract.split_sellback_tx_input_weight()],
                    [P2TR_SCRIPT_PUBKEY_SIZE],
                );
                let fee = sellback_tx_weight * FeeRate::from_sat_per_vb_unchecked(20);
                alice_split_prevout.value - fee
            },
        }],
    };

    signed_contract
        .sign_split_sellback_tx_input(
            &alice_win_cond,
            &mut sellback_tx,
            0, // input index
            &Prevouts::All(&[alice_split_prevout]),
            alice.payout_preimage,
            market_maker_seckey,
        )
        .unwrap();

    // The sellback TX has no relative locktime; it can be broadcast immediately.
    rpc.send_raw_transaction(&sellback_tx)
        .expect("failed to broadcast the sellback TX");

    // Bob will try to claim his winnings using the ticket preimage he bought.
    let bob_win_cond = WinCondition {
        outcome: Outcome::Attestation(outcome_index),
        player_index: player_indexes[&bob.player],
    };

    let (bob_split_input, bob_split_prevout) = signed_contract
        .split_win_tx_input_and_prevout(&bob_win_cond)
        .unwrap();

    // TODO test OP_CSV by spending without correct min sequence number

    let mut bob_win_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![bob_split_input],
        output: vec![TxOut {
            script_pubkey: p2tr_script_pubkey(bob.player.pubkey),
            value: {
                let win_tx_weight = predict_weight(
                    [signed_contract.split_win_tx_input_weight()],
                    [P2TR_SCRIPT_PUBKEY_SIZE],
                );
                let fee = win_tx_weight * FeeRate::from_sat_per_vb_unchecked(20);
                bob_split_prevout.value - fee
            },
        }],
    };

    signed_contract
        .sign_split_win_tx_input(
            &bob_win_cond,
            &mut bob_win_tx,
            0, // input index
            &Prevouts::All(&[bob_split_prevout]),
            bob.ticket_preimage,
            bob.seckey,
        )
        .expect("failed to sign win TX");

    // Only after a block delay of `delta` should Bob be able to
    // broadcast the win TX.
    mine_blocks(&rpc, signed_contract.params().relative_locktime_block_delta).unwrap();
    rpc.send_raw_transaction(&bob_win_tx)
        .expect("failed to broadcast Bob's win TX");

    // Carol never bought her preimage, and so her winnings will return to the market maker
    // `2*delta` blocks after the split TX is mined.
    let carol_win_cond = WinCondition {
        outcome: Outcome::Attestation(outcome_index),
        player_index: player_indexes[&carol.player],
    };

    let (carol_split_input, carol_split_prevout) = signed_contract
        .split_reclaim_tx_input_and_prevout(&carol_win_cond)
        .unwrap();

    // TODO test OP_CSV encumberance on reclaim script

    let mut reclaim_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![carol_split_input],
        output: vec![TxOut {
            script_pubkey: p2tr_script_pubkey(signed_contract.params().market_maker.pubkey),
            value: {
                let reclaim_tx_weight = predict_weight(
                    [signed_contract.split_reclaim_tx_input_weight()],
                    [P2TR_SCRIPT_PUBKEY_SIZE],
                );
                let fee = reclaim_tx_weight * FeeRate::from_sat_per_vb_unchecked(20);
                carol_split_prevout.value - fee
            },
        }],
    };

    signed_contract
        .sign_split_reclaim_tx_input(
            &carol_win_cond,
            &mut reclaim_tx,
            0, // input index
            &Prevouts::All(&[carol_split_prevout]),
            market_maker_seckey,
        )
        .expect("failed to sign reclaim TX");

    // Only after a block delay of `2*delta` can the market maker
    // broadcast the split TX.
    mine_blocks(&rpc, signed_contract.params().relative_locktime_block_delta).unwrap();
    rpc.send_raw_transaction(&reclaim_tx)
        .expect("failed to broadcast reclaim TX");
}

#[test]
#[serial]
fn ticketed_dlc_individual_sellback() {
    let mut rng = rand::thread_rng();

    // Oracle
    let oracle_seckey = Scalar::random(&mut rng);
    let oracle_secnonce = Scalar::random(&mut rng);

    // Market maker
    let market_maker_seckey = Scalar::random(&mut rng);
    let market_maker = MarketMaker {
        pubkey: market_maker_seckey.base_point_mul(),
    };
    let market_maker_address = p2tr_address(market_maker.pubkey);

    // players
    let alice = SimulatedPlayer::random(&mut rng);
    let bob = SimulatedPlayer::random(&mut rng);
    let carol = SimulatedPlayer::random(&mut rng);

    let players = BTreeSet::from([
        alice.player.clone(),
        bob.player.clone(),
        carol.player.clone(),
    ]);
    let player_indexes: BTreeMap<Player, PlayerIndex> = players
        .iter()
        .enumerate()
        .map(|(i, player)| (player.clone(), i))
        .collect();

    let rpc = new_rpc_client();

    let outcome_payouts = BTreeMap::<Outcome, PayoutWeights>::from([
        (
            Outcome::Attestation(0),
            PayoutWeights::from([(player_indexes[&alice.player], 1)]),
        ),
        (
            Outcome::Attestation(1),
            PayoutWeights::from([
                (player_indexes[&bob.player], 1),
                (player_indexes[&carol.player], 1),
            ]),
        ),
    ]);

    let contract_params = ContractParameters {
        market_maker,
        players,
        event: EventAnnouncement {
            oracle_pubkey: oracle_seckey.base_point_mul(),
            nonce_point: oracle_secnonce.base_point_mul(),
            outcome_messages: vec![Vec::from(b"alice wins"), Vec::from(b"bob and carol win")],
            expiry: None,
        },
        outcome_payouts,
        fee_rate: FeeRate::from_sat_per_vb_unchecked(100),
        funding_value: FUNDING_VALUE,
        relative_locktime_block_delta: 25,
    };

    // Fund the market maker
    let (mm_utxo_outpoint, mm_utxo_prevout) = take_usable_utxo(
        &rpc,
        &market_maker_address,
        FUNDING_VALUE + Amount::from_sat(50_000),
    );

    // Prepare a funding transaction
    let funding_tx = signed_funding_tx(
        market_maker_seckey,
        contract_params.funding_output().unwrap(),
        mm_utxo_outpoint,
        &mm_utxo_prevout,
    );
    let funding_outpoint = OutPoint {
        txid: funding_tx.txid(),
        vout: 0,
    };

    // Construct all the DLC transactions.
    let ticketed_dlc = TicketedDLC::new(contract_params, funding_outpoint)
        .expect("failed to constructed ticketed DLC transactions");

    // Sign all the transactions.
    let seckeys = [market_maker_seckey, alice.seckey, bob.seckey, carol.seckey];
    let signed_contract = musig_sign_ticketed_dlc(&ticketed_dlc, seckeys, &mut rng);

    // At this point, the market maker is confident they'll be able to reclaim their
    // capital if needed, and the players know they'll be able to enforce the DLC outcome
    // if they purchase their ticket preimage.
    //
    // The market maker can now broadcast the funding TX.
    rpc.send_raw_transaction(&funding_tx)
        .expect("failed to broadcast funding TX");
    mine_blocks(&rpc, 1).unwrap();

    let event: &EventAnnouncement = &signed_contract.params().event;

    let outcome_index: usize = 1;

    // The oracle attests to outcome 1, where Bob and Carol are winners.
    let oracle_attestation = event
        .attestation_secret(outcome_index, oracle_seckey, oracle_secnonce)
        .unwrap();

    // Anyone can unlock and broadcast an outcome TX if they know the attestation.
    let outcome_tx = signed_contract
        .signed_outcome_tx(outcome_index, oracle_attestation)
        .expect("failed to sign outcome TX");
    rpc.send_raw_transaction(&outcome_tx)
        .expect("failed to broadcast outcome TX");

    // Assume Bob bought his ticket preimage. He can now
    // use it to unlock the split transaction.
    let bob_win_cond = WinCondition {
        outcome: Outcome::Attestation(outcome_index),
        player_index: player_indexes[&bob.player],
    };
    let split_tx = signed_contract
        .signed_split_tx(&bob_win_cond, bob.ticket_preimage)
        .expect("failed to sign split TX");

    // Only after a block delay of `delta` should Bob be able to
    // broadcast the split TX.
    mine_blocks(&rpc, signed_contract.params().relative_locktime_block_delta).unwrap();
    rpc.send_raw_transaction(&split_tx)
        .expect("failed to broadcast split TX");

    // Carol is not cooperative, but Bob wants to receive his payout off-chain, so
    // he cooperates with the market maker by selling the market maker his payout
    // preimage, and then giving the market maker his secret key. This allows the
    // market maker to recover Bob's split TX output unilaterally.
    let (close_tx_input, close_tx_prevout) = signed_contract
        .split_close_tx_input_and_prevout(&bob_win_cond)
        .expect("error computing split close TX prevouts");
    let mut close_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![close_tx_input],
        output: vec![TxOut {
            script_pubkey: market_maker_address.script_pubkey(),
            value: {
                let close_tx_weight = predict_weight(
                    [InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH],
                    [P2TR_SCRIPT_PUBKEY_SIZE],
                );
                let fee = close_tx_weight * FeeRate::from_sat_per_vb_unchecked(20);
                close_tx_prevout.value - fee
            },
        }],
    };

    signed_contract
        .sign_split_close_tx_input(
            &bob_win_cond,
            &mut close_tx,
            0, // input index
            &Prevouts::All(&[close_tx_prevout]),
            market_maker_seckey,
            bob.seckey,
        )
        .expect("failed to sign split close TX");

    // The close TX can be broadcast immediately.
    rpc.send_raw_transaction(&close_tx)
        .expect("failed to broadcast split close TX");
}

#[test]
#[serial]
fn ticketed_dlc_all_winners_cooperate() {
    let mut rng = rand::thread_rng();

    // Oracle
    let oracle_seckey = Scalar::random(&mut rng);
    let oracle_secnonce = Scalar::random(&mut rng);

    // Market maker
    let market_maker_seckey = Scalar::random(&mut rng);
    let market_maker = MarketMaker {
        pubkey: market_maker_seckey.base_point_mul(),
    };
    let market_maker_address = p2tr_address(market_maker.pubkey);

    // players
    let alice = SimulatedPlayer::random(&mut rng);
    let bob = SimulatedPlayer::random(&mut rng);
    let carol = SimulatedPlayer::random(&mut rng);

    let players = BTreeSet::from([
        alice.player.clone(),
        bob.player.clone(),
        carol.player.clone(),
    ]);
    let player_indexes: BTreeMap<Player, PlayerIndex> = players
        .iter()
        .enumerate()
        .map(|(i, player)| (player.clone(), i))
        .collect();

    let rpc = new_rpc_client();

    let outcome_payouts = BTreeMap::<Outcome, PayoutWeights>::from([
        (
            Outcome::Attestation(0),
            PayoutWeights::from([(player_indexes[&alice.player], 1)]),
        ),
        (
            Outcome::Attestation(1),
            PayoutWeights::from([
                (player_indexes[&bob.player], 1),
                (player_indexes[&carol.player], 1),
            ]),
        ),
    ]);

    let contract_params = ContractParameters {
        market_maker,
        players,
        event: EventAnnouncement {
            oracle_pubkey: oracle_seckey.base_point_mul(),
            nonce_point: oracle_secnonce.base_point_mul(),
            outcome_messages: vec![Vec::from(b"alice wins"), Vec::from(b"bob and carol win")],
            expiry: None,
        },
        outcome_payouts,
        fee_rate: FeeRate::from_sat_per_vb_unchecked(100),
        funding_value: FUNDING_VALUE,
        relative_locktime_block_delta: 25,
    };

    // Fund the market maker
    let (mm_utxo_outpoint, mm_utxo_prevout) = take_usable_utxo(
        &rpc,
        &market_maker_address,
        FUNDING_VALUE + Amount::from_sat(50_000),
    );

    // Prepare a funding transaction
    let funding_tx = signed_funding_tx(
        market_maker_seckey,
        contract_params.funding_output().unwrap(),
        mm_utxo_outpoint,
        &mm_utxo_prevout,
    );
    let funding_outpoint = OutPoint {
        txid: funding_tx.txid(),
        vout: 0,
    };

    // Construct all the DLC transactions.
    let ticketed_dlc = TicketedDLC::new(contract_params, funding_outpoint)
        .expect("failed to constructed ticketed DLC transactions");

    // Sign all the transactions.
    let seckeys = [market_maker_seckey, alice.seckey, bob.seckey, carol.seckey];
    let signed_contract = musig_sign_ticketed_dlc(&ticketed_dlc, seckeys, &mut rng);

    // At this point, the market maker is confident they'll be able to reclaim their
    // capital if needed, and the players know they'll be able to enforce the DLC outcome
    // if they purchase their ticket preimage.
    //
    // The market maker can now broadcast the funding TX.
    rpc.send_raw_transaction(&funding_tx)
        .expect("failed to broadcast funding TX");
    mine_blocks(&rpc, 1).unwrap();

    let event: &EventAnnouncement = &signed_contract.params().event;

    let outcome_index: usize = 1;
    let outcome = Outcome::Attestation(outcome_index);

    // The oracle attests to outcome 1, where Bob and Carol are winners.
    let oracle_attestation = event
        .attestation_secret(outcome_index, oracle_seckey, oracle_secnonce)
        .unwrap();

    // Anyone can unlock and broadcast an outcome TX if they know the attestation.
    let outcome_tx = signed_contract
        .signed_outcome_tx(outcome_index, oracle_attestation)
        .expect("failed to sign outcome TX");
    rpc.send_raw_transaction(&outcome_tx)
        .expect("failed to broadcast outcome TX");

    // Bob and Carol both bought their ticket preimages. They want to
    // receive payouts off-chain, so they cooperate with the market maker
    // by selling the market maker their payout preimages, and then giving
    // the market maker their secret keys. This allows the market maker
    // to recover the outcome TX output unilaterally.
    let (close_tx_input, close_tx_prevout) = signed_contract
        .outcome_close_tx_input_and_prevout(&outcome)
        .expect("error constructing outcome close TX prevouts");
    let mut close_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![close_tx_input],
        output: vec![TxOut {
            script_pubkey: market_maker_address.script_pubkey(),
            value: {
                let close_tx_weight = predict_weight(
                    [InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH],
                    [P2TR_SCRIPT_PUBKEY_SIZE],
                );
                let fee = close_tx_weight * FeeRate::from_sat_per_vb_unchecked(20);
                close_tx_prevout.value - fee
            },
        }],
    };

    signed_contract
        .sign_outcome_close_tx_input(
            &outcome,
            &mut close_tx,
            0, // input index
            &Prevouts::All(&[close_tx_prevout]),
            market_maker_seckey,
            &BTreeMap::from([
                (bob.player.pubkey, bob.seckey),
                (carol.player.pubkey, carol.seckey),
            ]),
        )
        .expect("failed to sign outcome close TX");

    // The close TX can be broadcast immediately.
    rpc.send_raw_transaction(&close_tx)
        .expect("failed to broadcast outcome close TX");
}

#[test]
#[serial]
fn ticketed_dlc_market_maker_reclaims_outcome_tx() {
    let mut rng = rand::thread_rng();

    // Oracle
    let oracle_seckey = Scalar::random(&mut rng);
    let oracle_secnonce = Scalar::random(&mut rng);

    // Market maker
    let market_maker_seckey = Scalar::random(&mut rng);
    let market_maker = MarketMaker {
        pubkey: market_maker_seckey.base_point_mul(),
    };
    let market_maker_address = p2tr_address(market_maker.pubkey);

    // players
    let alice = SimulatedPlayer::random(&mut rng);
    let bob = SimulatedPlayer::random(&mut rng);

    let players = BTreeSet::from([alice.player.clone(), bob.player.clone()]);
    let player_indexes: BTreeMap<Player, PlayerIndex> = players
        .iter()
        .enumerate()
        .map(|(i, player)| (player.clone(), i))
        .collect();

    let rpc = new_rpc_client();

    let outcome_payouts = BTreeMap::<Outcome, PayoutWeights>::from([
        (
            Outcome::Attestation(0),
            PayoutWeights::from([(player_indexes[&alice.player], 1)]),
        ),
        (
            Outcome::Attestation(1),
            PayoutWeights::from([(player_indexes[&bob.player], 1)]),
        ),
    ]);

    let contract_params = ContractParameters {
        market_maker,
        players,
        event: EventAnnouncement {
            oracle_pubkey: oracle_seckey.base_point_mul(),
            nonce_point: oracle_secnonce.base_point_mul(),
            outcome_messages: vec![Vec::from(b"alice wins"), Vec::from(b"bob wins")],
            expiry: None,
        },
        outcome_payouts,
        fee_rate: FeeRate::from_sat_per_vb_unchecked(100),
        funding_value: FUNDING_VALUE,
        relative_locktime_block_delta: 25,
    };

    // Fund the market maker
    let (mm_utxo_outpoint, mm_utxo_prevout) = take_usable_utxo(
        &rpc,
        &market_maker_address,
        FUNDING_VALUE + Amount::from_sat(50_000),
    );

    // Prepare a funding transaction
    let funding_tx = signed_funding_tx(
        market_maker_seckey,
        contract_params.funding_output().unwrap(),
        mm_utxo_outpoint,
        &mm_utxo_prevout,
    );
    let funding_outpoint = OutPoint {
        txid: funding_tx.txid(),
        vout: 0,
    };

    // Construct all the DLC transactions.
    let ticketed_dlc = TicketedDLC::new(contract_params, funding_outpoint)
        .expect("failed to constructed ticketed DLC transactions");

    // Sign all the transactions.
    let seckeys = [market_maker_seckey, alice.seckey, bob.seckey];
    let signed_contract = musig_sign_ticketed_dlc(&ticketed_dlc, seckeys, &mut rng);

    // At this point, the market maker is confident they'll be able to reclaim their
    // capital if needed, and the players know they'll be able to enforce the DLC outcome
    // if they purchase their ticket preimage.
    //
    // The market maker can now broadcast the funding TX.
    rpc.send_raw_transaction(&funding_tx)
        .expect("failed to broadcast funding TX");
    mine_blocks(&rpc, 1).unwrap();

    let event: &EventAnnouncement = &signed_contract.params().event;

    // The oracle attests to outcome 0, where Alice wins.
    let outcome_index: usize = 0;
    let outcome = Outcome::Attestation(outcome_index);
    let oracle_attestation = event
        .attestation_secret(outcome_index, oracle_seckey, oracle_secnonce)
        .unwrap();

    // Anyone can unlock and broadcast an outcome TX if they know the attestation.
    let outcome_tx = signed_contract
        .signed_outcome_tx(outcome_index, oracle_attestation)
        .expect("failed to sign outcome TX");
    rpc.send_raw_transaction(&outcome_tx)
        .expect("failed to broadcast outcome TX");

    // Alice didn't buy her ticket preimage, so the market maker reclaims the outcome TX output.
    let (reclaim_tx_input, reclaim_tx_prevout) = signed_contract
        .outcome_reclaim_tx_input_and_prevout(&outcome)
        .expect("error constructing outcome reclaim TX prevouts");
    let mut reclaim_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![reclaim_tx_input],
        output: vec![TxOut {
            script_pubkey: market_maker_address.script_pubkey(),
            value: {
                let reclaim_tx_weight = predict_weight(
                    [signed_contract
                        .outcome_reclaim_tx_input_weight(&outcome)
                        .unwrap()],
                    [P2TR_SCRIPT_PUBKEY_SIZE],
                );
                let fee = reclaim_tx_weight * FeeRate::from_sat_per_vb_unchecked(20);
                reclaim_tx_prevout.value - fee
            },
        }],
    };

    signed_contract
        .sign_outcome_reclaim_tx_input(
            &outcome,
            &mut reclaim_tx,
            0, // input index
            &Prevouts::All(&[reclaim_tx_prevout]),
            market_maker_seckey,
        )
        .expect("failed to sign outcome reclaim TX");

    // Loop twice to ensure we used the correct locktime multiple of delta.
    for _ in 0..2 {
        // The market maker should not be able to broadcast the reclaim TX right away,
        // due to the relative locktime requirement.
        let err = rpc
            .send_raw_transaction(&reclaim_tx)
            .expect_err("early broadcast of reclaim TX should fail");
        assert_eq!(
            err.to_string(),
            "JSON-RPC error: RPC error response: RpcError { code: -26, \
                message: \"non-BIP68-final\", data: None }",
        );

        mine_blocks(&rpc, signed_contract.params().relative_locktime_block_delta).unwrap();
    }

    // The reclaim TX can be broadcast once a block delay of 2*delta
    // blocks has elapsed.
    rpc.send_raw_transaction(&reclaim_tx)
        .expect("failed to broadcast outcome reclaim TX");
}
