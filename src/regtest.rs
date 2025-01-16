//! This module contains integration tests which leverage a remote Bitcoin regtest node.

use crate::*;

use bitcoin::{
    blockdata::transaction::{predict_weight, InputWeightPrediction},
    hashes::Hash,
    key::TweakedPublicKey,
    locktime::absolute::LockTime,
    sighash::{Prevouts, SighashCache, TapSighashType},
    Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
};
use musig2::{CompactSignature, LiftedSignature, PartialSignature, PubNonce};
use rand::{CryptoRng, Rng, RngCore, SeedableRng};
use secp::{MaybePoint, MaybeScalar, Point, Scalar};

use bitcoincore_rpc::{jsonrpc::serde_json, Auth, Client as BitcoinClient, RpcApi};
use once_cell::sync::Lazy;
use tempdir::TempDir;

use std::{
    collections::BTreeMap,
    process,
    sync::{Mutex, MutexGuard},
    thread, time,
};

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

fn simple_sweep_tx(
    destination_pubkey: Point,
    input: TxIn,
    input_weight: InputWeightPrediction,
    prevout_value: Amount,
) -> Transaction {
    let script_pubkey = p2tr_script_pubkey(destination_pubkey);
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![input],
        output: vec![TxOut {
            value: {
                let tx_weight = predict_weight([input_weight], [script_pubkey.len()]);
                let fee = tx_weight * FeeRate::from_sat_per_vb_unchecked(20);
                prevout_value - fee
            },
            script_pubkey,
        }],
    }
}

const DEFAULT_REGTEST_RPC_USERNAME: &str = "regtest";
const DEFAULT_REGTEST_RPC_PASSWORD: &str = "regtest";
const DEFAULT_REGTEST_RPC_URL: &str = "http://127.0.0.1:18443";

/// This represents a handle to temporary resources which should be
/// cleaned up when the test ends.
#[derive(Debug)]
struct BitcoindSubprocessHandle {
    #[allow(dead_code)]
    tempdir: TempDir,
    #[allow(dead_code)]
    child: process::Child,
}

fn run_bitcoind() -> Option<(BitcoindSubprocessHandle, BitcoinClient)> {
    let dir = TempDir::new("dlctix").expect("error making tempdir");

    let rpc_port: u16 = rand::thread_rng().gen_range(20000..u16::MAX);
    let p2p_port: u16 = rpc_port + 1;

    let child: process::Child = process::Command::new("bitcoind")
        .arg("-regtest")
        .arg("-server")
        .arg(format!("-rpcport={}", rpc_port))
        .arg(format!("-port={}", p2p_port))
        .arg(format!("-rpcuser={}", DEFAULT_REGTEST_RPC_USERNAME))
        .arg(format!("-rpcpassword={}", DEFAULT_REGTEST_RPC_PASSWORD))
        .arg(format!("-datadir={}", dir.path().display()))
        .stdout(process::Stdio::null())
        .spawn()
        .ok()?;

    let subproc_handle = BitcoindSubprocessHandle {
        tempdir: dir,
        child,
    };

    let auth = Auth::UserPass(
        DEFAULT_REGTEST_RPC_USERNAME.to_string(),
        DEFAULT_REGTEST_RPC_PASSWORD.to_string(),
    );
    let bitcoind_rpc_url = format!("http://127.0.0.1:{}", rpc_port);
    let rpc_client =
        BitcoinClient::new(&bitcoind_rpc_url, auth).expect("failed to create bitcoind RPC client");

    Some((subproc_handle, rpc_client))
}

static REMOTE_NODE_SINGLETON: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

/// Build a bitcoind RPC client for regtest. If `bitcoind` is installed and
/// available in the `PATH`, then this executes bitcoind and runs it in regtest
/// mode, pointing to a temporary data directory. In this case we return a handle
/// pointing to the temporary directory being used, as well as the child process
/// handle.
///
/// Otherwise, the following environment variables should be defined:
///
/// - `BITCOIND_RPC_URL` (if missing, falls back to DEFAULT_REGTEST_RPC_URL)
/// - `BITCOIND_RPC_AUTH_USERNAME`
/// - `BITCOIND_RPC_AUTH_PASSWORD`
fn new_rpc_client() -> (Option<BitcoindSubprocessHandle>, BitcoinClient) {
    dotenv::dotenv().unwrap();

    match run_bitcoind() {
        Some((subproc_handle, rpc_client)) => {
            // Wait for bitcoind to start.
            let start = time::Instant::now();
            while start.elapsed() < time::Duration::from_secs(3) {
                if rpc_client.get_network_info().is_ok() {
                    return (Some(subproc_handle), rpc_client);
                }
                thread::sleep(std::time::Duration::from_millis(50));
            }
            panic!("cannot reach local bitcoind instance");
        }

        None => {
            let bitcoind_auth_username = std::env::var("BITCOIND_RPC_AUTH_USERNAME")
                .expect("bitcoind not installed; missing BITCOIND_RPC_AUTH_USERNAME");

            let bitcoind_auth_password = std::env::var("BITCOIND_RPC_AUTH_PASSWORD")
                .expect("bitcoind not installed; missing BITCOIND_RPC_AUTH_PASSWORD");

            let auth = Auth::UserPass(bitcoind_auth_username, bitcoind_auth_password);

            let bitcoind_rpc_url = std::env::var("BITCOIND_RPC_URL")
                .unwrap_or_else(|_| DEFAULT_REGTEST_RPC_URL.to_string());

            let rpc_client = BitcoinClient::new(&bitcoind_rpc_url, auth)
                .expect("failed to create bitcoind RPC client");

            (None, rpc_client)
        }
    }
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

    // Break into chunks of 30 blocks each to avoid hitting the 15 second default
    // timeout which bitcoincore_rpc won't let us configure.
    let mut remaining = n_blocks;
    while remaining != 0 {
        let chunk = remaining.min(30);
        rpc.generate_to_address(chunk as u64, &address)?;
        remaining -= chunk;
    }

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
    index: PlayerIndex,
}

impl SimulatedPlayer {
    fn random<R: RngCore + CryptoRng>(rng: &mut R, index: PlayerIndex) -> SimulatedPlayer {
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
            index,
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
    verify_all_partial_signatures: bool,
) -> SignedContract {
    let mut signing_sessions: BTreeMap<Point, SigningSession<NonceSharingRound>> = all_seckeys
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

    let coordinator_session = signing_sessions
        .remove(&ticketed_dlc.params().market_maker.pubkey)
        .unwrap()
        .aggregate_nonces_and_compute_partial_signatures(pubnonces_by_sender)
        .expect("error aggregating pubnonces");

    let signing_sessions: BTreeMap<Point, SigningSession<ContributorPartialSignatureSharingRound>> =
        signing_sessions
            .into_iter()
            .map(|(pubkey, session)| {
                let new_session = session
                    .compute_partial_signatures(coordinator_session.aggregated_nonces().clone())
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

    // Every player's signatures can be verified individually by the coordinator.
    if verify_all_partial_signatures {
        for (&sender_pubkey, partial_sigs) in &partial_sigs_by_sender {
            coordinator_session
                .verify_partial_signatures(sender_pubkey, partial_sigs)
                .expect("valid partial signatures should be verified as OK");
        }
    }

    let signed_contract = coordinator_session
        .aggregate_all_signatures(partial_sigs_by_sender)
        .expect("error aggregating partial signatures");

    for session in signing_sessions.into_values() {
        session
            .verify_aggregated_signatures(signed_contract.all_signatures())
            .expect("player failed to verify signatures aggregated by the market maker");

        // let player_signed_contract =
        //     session.into_signed_contract(signed_contract.all_signatures().clone());
    }

    // SignedContract should be able to be stored and retrieved via serde serialization.
    let decoded_contract = serde_json::from_str(
        &serde_json::to_string(&signed_contract).expect("error serializing SignedContract"),
    )
    .expect("error deserializing SignedContract");
    assert_eq!(
        signed_contract, decoded_contract,
        "deserialized SignedContract does not match original"
    );

    signed_contract
}

struct SimulationManager {
    alice: SimulatedPlayer,
    bob: SimulatedPlayer,
    carol: SimulatedPlayer,
    dave: SimulatedPlayer,

    market_maker_seckey: Scalar,
    oracle_seckey: Scalar,
    oracle_secnonce: Scalar,
    outcome_messages: Vec<Vec<u8>>,

    contract: SignedContract,
    rpc: BitcoinClient,
    bitcoind_handle: Option<BitcoindSubprocessHandle>,

    // Used for synchronization only
    #[allow(dead_code)]
    bitcoind_lock: Option<MutexGuard<'static, ()>>,
}

impl SimulationManager {
    fn new() -> Self {
        let mut rng = rand::thread_rng();

        // Oracle
        let oracle_seckey = Scalar::random(&mut rng);
        let oracle_secnonce = Scalar::random(&mut rng);
        let oracle_pubkey = oracle_seckey.base_point_mul();
        let nonce_point = oracle_secnonce.base_point_mul();
        let outcome_messages = vec![
            Vec::from(b"alice, bob, and carol win"),
            Vec::from(b"bob and carol win"),
            Vec::from(b"alice wins"),
        ];
        let locking_points: Vec<MaybePoint> = outcome_messages
            .iter()
            .map(|msg| attestation_locking_point(oracle_pubkey, nonce_point, msg))
            .collect();

        // Market maker
        let market_maker_seckey = Scalar::random(&mut rng);
        let market_maker = MarketMaker {
            pubkey: market_maker_seckey.base_point_mul(),
        };
        let market_maker_address = p2tr_address(market_maker.pubkey);

        // players
        let alice = SimulatedPlayer::random(&mut rng, 0);
        let bob = SimulatedPlayer::random(&mut rng, 1);
        let carol = SimulatedPlayer::random(&mut rng, 2);
        let dave = SimulatedPlayer::random(&mut rng, 3);

        let players = vec![
            alice.player.clone(),
            bob.player.clone(),
            carol.player.clone(),
            dave.player.clone(),
        ];

        let (bitcoind_handle, rpc) = new_rpc_client();

        // If we're using a remote bitcoind instance, we don't want tests
        // to interfere with each other, so grab a lock on a global mutex
        // which will be released when the SimulationManager is dropped.
        let bitcoind_lock = if bitcoind_handle.is_none() {
            // Tests panic sometimes, we should ignore poisoned mutex state.
            let lock = REMOTE_NODE_SINGLETON
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            Some(lock)
        } else {
            None
        };

        // Fund the market maker. This may mine some blocks.
        let (mm_utxo_outpoint, mm_utxo_prevout) = take_usable_utxo(
            &rpc,
            &market_maker_address,
            FUNDING_VALUE + Amount::from_sat(50_000),
        );

        let initial_block_height = rpc.get_block_count().unwrap();

        let outcome_payouts = BTreeMap::<Outcome, PayoutWeights>::from([
            (
                Outcome::Attestation(0),
                PayoutWeights::from([(alice.index, 1), (bob.index, 2), (carol.index, 1)]),
            ),
            (
                Outcome::Attestation(1),
                PayoutWeights::from([(bob.index, 3), (carol.index, 1)]),
            ),
            (
                Outcome::Attestation(2),
                PayoutWeights::from([(alice.index, 1)]),
            ),
            (Outcome::Expiry, PayoutWeights::from([(dave.index, 1)])),
        ]);

        let contract_params = ContractParameters {
            market_maker,
            players,
            event: EventLockingConditions {
                locking_points,
                expiry: u32::try_from(initial_block_height + 100).ok(),
            },
            outcome_payouts,
            fee_rate: FeeRate::from_sat_per_vb_unchecked(50),
            funding_value: FUNDING_VALUE,
            relative_locktime_block_delta: 25,
        };

        // Prepare a funding transaction
        let funding_tx = signed_funding_tx(
            market_maker_seckey,
            contract_params.funding_output().unwrap(),
            mm_utxo_outpoint,
            &mm_utxo_prevout,
        );
        let funding_outpoint = OutPoint {
            txid: funding_tx.compute_txid(),
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

        let signed_contract = musig_sign_ticketed_dlc(&ticketed_dlc, seckeys, &mut rng, true);

        // At this point, the market maker is confident they'll be able to reclaim their
        // capital if needed, and the players know they'll be able to enforce the DLC outcome
        // if they purchase their ticket preimage.
        //
        // The market maker can now broadcast the funding TX.
        rpc.send_raw_transaction(&funding_tx)
            .expect("failed to broadcast funding TX");
        mine_blocks(&rpc, 1).unwrap();

        SimulationManager {
            alice,
            bob,
            carol,
            dave,

            market_maker_seckey,
            oracle_seckey,
            oracle_secnonce,
            outcome_messages,

            contract: signed_contract,
            rpc,
            bitcoind_handle,
            bitcoind_lock,
        }
    }

    fn event(&self) -> &EventLockingConditions {
        &self.contract.params().event
    }

    fn oracle_attestation(&self, outcome_index: OutcomeIndex) -> Option<MaybeScalar> {
        Some(attestation_secret(
            self.oracle_seckey,
            self.oracle_secnonce,
            self.outcome_messages.get(outcome_index)?,
        ))
    }

    fn mine_delta_blocks(&self) -> Result<(), bitcoincore_rpc::Error> {
        mine_blocks(
            &self.rpc,
            self.contract.params().relative_locktime_block_delta,
        )
    }

    fn mine_until_expiry(&self) -> Result<(), bitcoincore_rpc::Error> {
        let block_height = self.rpc.get_block_count()?;
        let expiry_height = self.event().expiry.unwrap() as u64;
        if block_height >= expiry_height {
            return Ok(());
        }

        mine_blocks(&self.rpc, (expiry_height - block_height) as u16)
    }
}

/// When the test ends, stop bitcoind and remove its temporary datadir.
impl std::ops::Drop for SimulationManager {
    fn drop(&mut self) {
        if let Some(mut handle) = self.bitcoind_handle.take() {
            self.rpc.stop().expect("failed to stop bitcoind subprocess");
            handle.child.wait().unwrap();
            handle
                .tempdir
                .close()
                .expect("failed to clean up temporary directory");
        }
    }
}

#[test]
fn with_on_chain_resolutions() {
    let manager = SimulationManager::new();

    // The oracle attests to outcome zero, where Alice, Bob, and Carol are winners.
    let outcome_index: usize = 0;
    let oracle_attestation = manager.oracle_attestation(outcome_index).unwrap();

    // The attestation should be a valid BIP340 signature by the oracle's pubkey.
    {
        let oracle_signature =
            LiftedSignature::new(manager.oracle_secnonce.base_point_mul(), oracle_attestation);
        musig2::verify_single(
            manager.oracle_seckey.base_point_mul(),
            oracle_signature,
            crate::oracles::outcome_message_hash(&manager.outcome_messages[outcome_index]),
        )
        .expect("invalid oracle signature");
    }

    // Anyone can unlock and broadcast an outcome TX if they know the attestation.
    let outcome_tx = manager
        .contract
        .signed_outcome_tx(outcome_index, oracle_attestation)
        .expect("failed to sign outcome TX");
    manager
        .rpc
        .send_raw_transaction(&outcome_tx)
        .expect("failed to broadcast outcome TX");

    // Assume Alice bought her ticket preimage. She can now
    // use it to unlock the split transaction.
    let alice_win_cond = WinCondition {
        outcome: Outcome::Attestation(outcome_index),
        player_index: manager.alice.index,
    };
    let split_tx = manager
        .contract
        .signed_split_tx(&alice_win_cond, manager.alice.ticket_preimage)
        .expect("failed to sign split TX");

    // Alice should not be able to broadcast the split TX right away,
    // due to the relative locktime on the split TX.
    let err = manager
        .rpc
        .send_raw_transaction(&split_tx)
        .expect_err("early broadcast of split TX should fail");
    assert_eq!(
        err.to_string(),
        "JSON-RPC error: RPC error response: RpcError { code: -26, \
            message: \"non-BIP68-final\", data: None }",
    );

    // Only after a block delay of `delta` should Alice be able to
    // broadcast the split TX.
    manager.mine_delta_blocks().unwrap();
    manager
        .rpc
        .send_raw_transaction(&split_tx)
        .expect("failed to broadcast split TX");

    // Alice, Bob, and Carol now have separate payout contracts with the market maker.

    // Alice paid for her ticket preimage, but wishes to receive a payout off-chain,
    // by selling her payout preimage to the market maker. The market maker uses the
    // payout preimage to sign a sellback TX which reclaims Alice's winnings before
    // she will have a chance to sweep them.
    let (alice_split_input, alice_split_prevout) = manager
        .contract
        .split_sellback_tx_input_and_prevout(&alice_win_cond)
        .unwrap();

    let mut sellback_tx = simple_sweep_tx(
        manager.contract.params().market_maker.pubkey,
        alice_split_input,
        manager.contract.split_sellback_tx_input_weight(),
        alice_split_prevout.value,
    );

    manager
        .contract
        .sign_split_sellback_tx_input(
            &alice_win_cond,
            &mut sellback_tx,
            0, // input index
            &Prevouts::All(&[alice_split_prevout]),
            manager.alice.payout_preimage,
            manager.market_maker_seckey,
        )
        .unwrap();

    // The sellback TX has no relative locktime; it can be broadcast immediately.
    manager
        .rpc
        .send_raw_transaction(&sellback_tx)
        .expect("failed to broadcast the sellback TX");

    // Bob will try to claim his winnings using the ticket preimage he bought.
    let bob_win_cond = WinCondition {
        outcome: Outcome::Attestation(outcome_index),
        player_index: manager.bob.index,
    };

    let (bob_split_input, bob_split_prevout) = manager
        .contract
        .split_win_tx_input_and_prevout(&bob_win_cond)
        .unwrap();

    let mut bob_win_tx = simple_sweep_tx(
        manager.bob.player.pubkey,
        bob_split_input,
        manager.contract.split_win_tx_input_weight(),
        bob_split_prevout.value,
    );

    // Ensure Bob cannot broadcast a win TX early. OP_CSV should
    // enforce the relative locktime.
    {
        let mut invalid_bob_win_tx = bob_win_tx.clone();
        invalid_bob_win_tx.input[0].sequence = Sequence::MAX;

        manager
            .contract
            .unchecked_sign_split_win_tx_input(
                &bob_win_cond,
                &mut invalid_bob_win_tx,
                0, // input index
                &Prevouts::All(&[bob_split_prevout]),
                manager.bob.ticket_preimage,
                manager.bob.seckey,
            )
            .expect("failed to sign win TX");

        let err = manager
            .rpc
            .send_raw_transaction(&invalid_bob_win_tx)
            .expect_err("early broadcast of win TX should fail");
        assert_eq!(
            err.to_string(),
            "JSON-RPC error: RPC error response: RpcError { code: -26, \
             message: \"non-mandatory-script-verify-flag (Locktime requirement not satisfied)\", \
             data: None }",
        );
    }

    manager
        .contract
        .sign_split_win_tx_input(
            &bob_win_cond,
            &mut bob_win_tx,
            0, // input index
            &Prevouts::All(&[bob_split_prevout]),
            manager.bob.ticket_preimage,
            manager.bob.seckey,
        )
        .expect("failed to sign win TX");

    // Only after a block delay of `delta` should Bob be able to
    // broadcast the win TX.
    manager.mine_delta_blocks().unwrap();
    manager
        .rpc
        .send_raw_transaction(&bob_win_tx)
        .expect("failed to broadcast Bob's win TX");

    // Carol never bought her preimage, and so her winnings will return to the market maker
    // `2*delta` blocks after the split TX is mined.
    let carol_win_cond = WinCondition {
        outcome: Outcome::Attestation(outcome_index),
        player_index: manager.carol.index,
    };

    let (carol_split_input, carol_split_prevout) = manager
        .contract
        .split_reclaim_tx_input_and_prevout(&carol_win_cond)
        .unwrap();

    let mut reclaim_tx = simple_sweep_tx(
        manager.contract.params().market_maker.pubkey,
        carol_split_input,
        manager.contract.split_reclaim_tx_input_weight(),
        carol_split_prevout.value,
    );

    // Ensure the Market Maker cannot broadcast a split reclaim TX early. OP_CSV
    // should enforce the relative locktime.
    {
        let mut invalid_reclaim_tx = reclaim_tx.clone();
        invalid_reclaim_tx.input[0].sequence = Sequence::MAX;

        manager
            .contract
            .unchecked_sign_split_reclaim_tx_input(
                &carol_win_cond,
                &mut invalid_reclaim_tx,
                0, // input index
                &Prevouts::All(&[carol_split_prevout]),
                manager.market_maker_seckey,
            )
            .expect("failed to sign win TX");

        let err = manager
            .rpc
            .send_raw_transaction(&invalid_reclaim_tx)
            .expect_err("early broadcast of split reclaim TX should fail");
        assert_eq!(
            err.to_string(),
            "JSON-RPC error: RPC error response: RpcError { code: -26, \
             message: \"non-mandatory-script-verify-flag (Locktime requirement not satisfied)\", \
             data: None }",
        );
    }

    manager
        .contract
        .sign_split_reclaim_tx_input(
            &carol_win_cond,
            &mut reclaim_tx,
            0, // input index
            &Prevouts::All(&[carol_split_prevout]),
            manager.market_maker_seckey,
        )
        .expect("failed to sign reclaim TX");

    // Only after a block delay of `2*delta` can the market maker
    // broadcast the split TX.
    manager.mine_delta_blocks().unwrap();
    manager
        .rpc
        .send_raw_transaction(&reclaim_tx)
        .expect("failed to broadcast reclaim TX");
}

#[test]
fn individual_sellback() {
    let manager = SimulationManager::new();

    // The oracle attests to outcome 1, where Bob and Carol are winners.
    let outcome_index: usize = 1;
    let oracle_attestation = manager.oracle_attestation(outcome_index).unwrap();

    // Anyone can unlock and broadcast an outcome TX if they know the attestation.
    let outcome_tx = manager
        .contract
        .signed_outcome_tx(outcome_index, oracle_attestation)
        .expect("failed to sign outcome TX");
    manager
        .rpc
        .send_raw_transaction(&outcome_tx)
        .expect("failed to broadcast outcome TX");

    // Assume Bob bought his ticket preimage. He can now
    // use it to unlock the split transaction.
    let bob_win_cond = WinCondition {
        outcome: Outcome::Attestation(outcome_index),
        player_index: manager.bob.index,
    };
    let split_tx = manager
        .contract
        .signed_split_tx(&bob_win_cond, manager.bob.ticket_preimage)
        .expect("failed to sign split TX");

    // Only after a block delay of `delta` should Bob be able to
    // broadcast the split TX.
    manager.mine_delta_blocks().unwrap();
    manager
        .rpc
        .send_raw_transaction(&split_tx)
        .expect("failed to broadcast split TX");

    // Carol is not cooperative, but Bob wants to receive his payout off-chain, so
    // he cooperates with the market maker by selling the market maker his payout
    // preimage, and then giving the market maker his secret key. This allows the
    // market maker to recover Bob's split TX output unilaterally.
    let (close_tx_input, close_tx_prevout) = manager
        .contract
        .split_close_tx_input_and_prevout(&bob_win_cond)
        .expect("error computing split close TX prevouts");
    let mut close_tx = simple_sweep_tx(
        manager.contract.params().market_maker.pubkey,
        close_tx_input,
        manager.contract.close_tx_input_weight(),
        close_tx_prevout.value,
    );

    manager
        .contract
        .sign_split_close_tx_input(
            &bob_win_cond,
            &mut close_tx,
            0, // input index
            &Prevouts::All(&[close_tx_prevout]),
            manager.market_maker_seckey,
            manager.bob.seckey,
        )
        .expect("failed to sign split close TX");

    // The close TX can be broadcast immediately.
    manager
        .rpc
        .send_raw_transaction(&close_tx)
        .expect("failed to broadcast split close TX");
}

#[test]
fn all_winners_cooperate() {
    let manager = SimulationManager::new();

    // The oracle attests to outcome 1, where Bob and Carol are winners.
    let outcome_index: usize = 1;
    let outcome = Outcome::Attestation(outcome_index);
    let oracle_attestation = manager.oracle_attestation(outcome_index).unwrap();

    // Anyone can unlock and broadcast an outcome TX if they know the attestation.
    let outcome_tx = manager
        .contract
        .signed_outcome_tx(outcome_index, oracle_attestation)
        .expect("failed to sign outcome TX");
    manager
        .rpc
        .send_raw_transaction(&outcome_tx)
        .expect("failed to broadcast outcome TX");

    // Bob and Carol both bought their ticket preimages. They want to
    // receive payouts off-chain, so they cooperate with the market maker
    // by selling the market maker their payout preimages, and then giving
    // the market maker their secret keys. This allows the market maker
    // to recover the outcome TX output unilaterally.
    let (close_tx_input, close_tx_prevout) = manager
        .contract
        .outcome_close_tx_input_and_prevout(&outcome)
        .expect("error constructing outcome close TX prevouts");
    let mut close_tx = simple_sweep_tx(
        manager.contract.params().market_maker.pubkey,
        close_tx_input,
        manager.contract.close_tx_input_weight(),
        close_tx_prevout.value,
    );

    manager
        .contract
        .sign_outcome_close_tx_input(
            &outcome,
            &mut close_tx,
            0, // input index
            &Prevouts::All(&[close_tx_prevout]),
            manager.market_maker_seckey,
            &BTreeMap::from([
                (manager.bob.player.pubkey, manager.bob.seckey),
                (manager.carol.player.pubkey, manager.carol.seckey),
            ]),
        )
        .expect("failed to sign outcome close TX");

    // The close TX can be broadcast immediately.
    manager
        .rpc
        .send_raw_transaction(&close_tx)
        .expect("failed to broadcast outcome close TX");
}

#[test]
fn market_maker_reclaims_outcome_tx() {
    let manager = SimulationManager::new();

    // The oracle attests to outcome 0, where Alice wins.
    let outcome_index: usize = 2;
    let outcome = Outcome::Attestation(outcome_index);
    let oracle_attestation = manager.oracle_attestation(outcome_index).unwrap();

    // Anyone can unlock and broadcast an outcome TX if they know the attestation.
    let outcome_tx = manager
        .contract
        .signed_outcome_tx(outcome_index, oracle_attestation)
        .expect("failed to sign outcome TX");
    manager
        .rpc
        .send_raw_transaction(&outcome_tx)
        .expect("failed to broadcast outcome TX");

    // Alice didn't buy her ticket preimage, so the market maker reclaims the outcome TX output.
    let (reclaim_tx_input, reclaim_tx_prevout) = manager
        .contract
        .outcome_reclaim_tx_input_and_prevout(&outcome)
        .expect("error constructing outcome reclaim TX prevouts");
    let mut reclaim_tx = simple_sweep_tx(
        manager.contract.params().market_maker.pubkey,
        reclaim_tx_input,
        manager
            .contract
            .outcome_reclaim_tx_input_weight(&outcome)
            .unwrap(),
        reclaim_tx_prevout.value,
    );

    // Ensure the Market Maker cannot broadcast an outcome reclaim TX early. OP_CSV
    // should enforce the relative locktime.
    {
        let mut invalid_reclaim_tx = reclaim_tx.clone();
        invalid_reclaim_tx.input[0].sequence = Sequence::MAX;

        manager
            .contract
            .unchecked_sign_outcome_reclaim_tx_input(
                &outcome,
                &mut invalid_reclaim_tx,
                0, // input index
                &Prevouts::All(&[reclaim_tx_prevout]),
                manager.market_maker_seckey,
            )
            .expect("failed to sign outcome reclaim TX");

        let err = manager
            .rpc
            .send_raw_transaction(&invalid_reclaim_tx)
            .expect_err("early broadcast of outcome reclaim TX should fail");
        assert_eq!(
            err.to_string(),
            "JSON-RPC error: RPC error response: RpcError { code: -26, \
             message: \"non-mandatory-script-verify-flag (Locktime requirement not satisfied)\", \
             data: None }",
        );
    }

    manager
        .contract
        .sign_outcome_reclaim_tx_input(
            &outcome,
            &mut reclaim_tx,
            0, // input index
            &Prevouts::All(&[reclaim_tx_prevout]),
            manager.market_maker_seckey,
        )
        .expect("failed to sign outcome reclaim TX");

    // The market maker should not be able to broadcast the reclaim TX right away,
    // due to the relative locktime requirement.
    // Loop twice to ensure we used the correct locktime multiple of delta.
    for _ in 0..2 {
        let err = manager
            .rpc
            .send_raw_transaction(&reclaim_tx)
            .expect_err("early broadcast of reclaim TX should fail");
        assert_eq!(
            err.to_string(),
            "JSON-RPC error: RPC error response: RpcError { code: -26, \
                message: \"non-BIP68-final\", data: None }",
        );

        manager.mine_delta_blocks().unwrap();
    }

    // The reclaim TX can be broadcast once a block delay of 2*delta
    // blocks has elapsed.
    manager
        .rpc
        .send_raw_transaction(&reclaim_tx)
        .expect("failed to broadcast outcome reclaim TX");
}

#[test]
fn contract_expiry_on_chain_resolution() {
    let manager = SimulationManager::new();

    // The contract expires, paying out to dave.
    let expiry_tx = manager
        .contract
        .expiry_tx()
        .expect("failed to fetch signed outcome TX");

    // The expiry TX is locked so that it can only be spent once the
    // event expiry height is reached.
    let err = manager
        .rpc
        .send_raw_transaction(&expiry_tx)
        .expect_err("early broadcast of expiry TX should fail");
    assert_eq!(
        err.to_string(),
        "JSON-RPC error: RPC error response: RpcError { code: -26, \
             message: \"non-final\", data: None }",
    );

    manager.mine_until_expiry().unwrap();
    manager
        .rpc
        .send_raw_transaction(&expiry_tx)
        .expect("failed to broadcast expiry TX");

    // Assume Dave bought his ticket preimage. He can now
    // use it to unlock the split transaction.
    let dave_win_cond = WinCondition {
        outcome: Outcome::Expiry,
        player_index: manager.dave.index,
    };

    let split_tx = manager
        .contract
        .signed_split_tx(&dave_win_cond, manager.dave.ticket_preimage)
        .expect("failed to sign split TX");

    // Dave should not be able to broadcast the split TX right away,
    // due to the relative locktime on the split TX.
    let err = manager
        .rpc
        .send_raw_transaction(&split_tx)
        .expect_err("early broadcast of split TX should fail");
    assert_eq!(
        err.to_string(),
        "JSON-RPC error: RPC error response: RpcError { code: -26, \
            message: \"non-BIP68-final\", data: None }",
    );

    // Only after a block delay of `delta` should Dave be able to
    // broadcast the split TX.
    manager.mine_delta_blocks().unwrap();
    manager
        .rpc
        .send_raw_transaction(&split_tx)
        .expect("failed to broadcast split TX");

    let (dave_split_input, dave_split_prevout) = manager
        .contract
        .split_win_tx_input_and_prevout(&dave_win_cond)
        .unwrap();

    let mut dave_win_tx = simple_sweep_tx(
        manager.dave.player.pubkey,
        dave_split_input,
        manager.contract.split_win_tx_input_weight(),
        dave_split_prevout.value,
    );

    // Ensure Dave cannot broadcast the win TX early. OP_CSV should
    // enforce the relative locktime.
    {
        let mut invalid_dave_win_tx = dave_win_tx.clone();
        invalid_dave_win_tx.input[0].sequence = Sequence::MAX;

        manager
            .contract
            .unchecked_sign_split_win_tx_input(
                &dave_win_cond,
                &mut invalid_dave_win_tx,
                0, // input index
                &Prevouts::All(&[dave_split_prevout]),
                manager.dave.ticket_preimage,
                manager.dave.seckey,
            )
            .expect("failed to sign win TX");

        let err = manager
            .rpc
            .send_raw_transaction(&invalid_dave_win_tx)
            .expect_err("early broadcast of win TX should fail");
        assert_eq!(
            err.to_string(),
            "JSON-RPC error: RPC error response: RpcError { code: -26, \
             message: \"non-mandatory-script-verify-flag (Locktime requirement not satisfied)\", \
             data: None }",
        );
    }

    manager
        .contract
        .sign_split_win_tx_input(
            &dave_win_cond,
            &mut dave_win_tx,
            0, // input index
            &Prevouts::All(&[dave_split_prevout]),
            manager.dave.ticket_preimage,
            manager.dave.seckey,
        )
        .expect("failed to sign win TX");

    // Only after a block delay of `delta` should Dave be able to
    // broadcast the win TX.
    manager.mine_delta_blocks().unwrap();
    manager
        .rpc
        .send_raw_transaction(&dave_win_tx)
        .expect("failed to broadcast Dave's win TX");
}

#[test]
fn contract_expiry_all_winners_cooperate() {
    let manager = SimulationManager::new();

    // The contract expires, paying out to dave.
    let outcome = Outcome::Expiry;
    let expiry_tx = manager
        .contract
        .expiry_tx()
        .expect("failed to fetch signed outcome TX");

    // The expiry TX is locked so that it can only be spent once the
    // event expiry height is reached.
    let err = manager
        .rpc
        .send_raw_transaction(&expiry_tx)
        .expect_err("early broadcast of expiry TX should fail");
    assert_eq!(
        err.to_string(),
        "JSON-RPC error: RPC error response: RpcError { code: -26, \
             message: \"non-final\", data: None }",
    );

    manager.mine_until_expiry().unwrap();
    manager
        .rpc
        .send_raw_transaction(&expiry_tx)
        .expect("failed to broadcast expiry TX");

    // Dave cooperates, selling his payout preimage to the market maker, so they
    // can recover the outcome TX output unilaterally. Dave can now give his
    // secret key to the market maker to improve on-chain efficiency.
    let (close_tx_input, close_tx_prevout) = manager
        .contract
        .outcome_close_tx_input_and_prevout(&outcome)
        .expect("error constructing outcome close TX prevouts");
    let mut close_tx = simple_sweep_tx(
        manager.contract.params().market_maker.pubkey,
        close_tx_input,
        manager.contract.close_tx_input_weight(),
        close_tx_prevout.value,
    );

    manager
        .contract
        .sign_outcome_close_tx_input(
            &outcome,
            &mut close_tx,
            0, // input index
            &Prevouts::All(&[close_tx_prevout]),
            manager.market_maker_seckey,
            &BTreeMap::from([(manager.dave.player.pubkey, manager.dave.seckey)]),
        )
        .expect("failed to sign outcome close TX");

    // The close TX can be broadcast immediately.
    manager
        .rpc
        .send_raw_transaction(&close_tx)
        .expect("failed to broadcast outcome close TX");
}

#[test]
fn all_players_cooperate() {
    let manager = SimulationManager::new();

    // The oracle attests to outcome 0, paying out to Alice Bob and Carol.
    // Alice, Bob, Carol, and Dave all cooperate.
    //
    // Alice, Bob and Carol sell their payout preimages to the market maker,
    // and surrender their secret signing keys once they receive the payout.
    // Dave stands to earn nothing, so he surrenders his private key immediately.
    // The market maker can now sweep the funding output back to his control.
    // This is the most efficient on-chain recovery path possible.
    //
    // It is possible for one of the players to publish the split TX, which
    // double spends the funding TX, but even if the split TX is confirmed,
    // the market maker can then immediately sweep the output of the split TX anyway.
    let (close_tx_input, close_tx_prevout) = manager.contract.funding_close_tx_input_and_prevout();
    let mut close_tx = simple_sweep_tx(
        manager.contract.params().market_maker.pubkey,
        close_tx_input,
        manager.contract.close_tx_input_weight(),
        close_tx_prevout.value,
    );

    manager
        .contract
        .sign_funding_close_tx_input(
            &mut close_tx,
            0, // input index
            &Prevouts::All(&[close_tx_prevout]),
            manager.market_maker_seckey,
            &BTreeMap::from([
                (manager.alice.player.pubkey, manager.alice.seckey),
                (manager.bob.player.pubkey, manager.bob.seckey),
                (manager.carol.player.pubkey, manager.carol.seckey),
                (manager.dave.player.pubkey, manager.dave.seckey),
            ]),
        )
        .expect("failed to sign funding close TX");

    // The close TX can be broadcast immediately.
    manager
        .rpc
        .send_raw_transaction(&close_tx)
        .expect("failed to broadcast funding close TX");
}

// This stress-test confirms that signing large ticketed DLCs is plausible,
// if computationally expensive.
#[test]
fn stress_test() {
    let mut rng = rand::rngs::StdRng::from_seed([0; 32]);

    // Stress-testing parameters.
    let n_players = 20;
    let n_outcomes = 6;
    let winners_per_outcome = 2;

    let simulated_players: Vec<SimulatedPlayer> = (0..n_players)
        .map(|i| SimulatedPlayer::random(&mut rng, i))
        .collect();

    // Oracle
    let oracle_seckey = Scalar::random(&mut rng);
    let oracle_secnonce = Scalar::random(&mut rng);
    let oracle_pubkey = oracle_seckey.base_point_mul();
    let nonce_point = oracle_secnonce.base_point_mul();

    // Market maker
    let market_maker_seckey = Scalar::random(&mut rng);
    let market_maker = MarketMaker {
        pubkey: market_maker_seckey.base_point_mul(),
    };

    let players: Vec<Player> = simulated_players.iter().map(|p| p.player.clone()).collect();

    let outcome_messages: Vec<Vec<u8>> = (0..n_outcomes)
        .map(|i| Vec::from((i as u32).to_be_bytes()))
        .collect();

    let locking_points: Vec<MaybePoint> = outcome_messages
        .iter()
        .map(|msg| attestation_locking_point(oracle_pubkey, nonce_point, msg))
        .collect();

    // Generate random payouts with 4 winners per outcome
    let outcome_payouts: BTreeMap<Outcome, PayoutWeights> = (0..n_outcomes)
        .map(|i| {
            let outcome = Outcome::Attestation(i);
            let payout_map = (0..winners_per_outcome)
                .map(|_| {
                    let player_index: PlayerIndex = rng.gen_range(0..n_players);
                    (player_index, 1)
                })
                .collect();

            (outcome, payout_map)
        })
        .collect();

    let contract_params = ContractParameters {
        market_maker,
        players,
        event: EventLockingConditions {
            locking_points,
            expiry: None,
        },
        outcome_payouts,
        fee_rate: FeeRate::from_sat_per_vb_unchecked(50),
        funding_value: FUNDING_VALUE,
        relative_locktime_block_delta: 25,
    };

    let funding_outpoint = OutPoint {
        txid: bitcoin::Txid::from_byte_array([0; 32]),
        vout: 0,
    };

    // Construct all the DLC transactions.
    let ticketed_dlc = TicketedDLC::new(contract_params, funding_outpoint)
        .expect("failed to constructed ticketed DLC transactions");

    // Sign all the transactions.
    let seckeys = simulated_players
        .iter()
        .map(|p| p.seckey)
        .chain([market_maker_seckey]);
    let _ = musig_sign_ticketed_dlc(&ticketed_dlc, seckeys, &mut rng, false);
}
