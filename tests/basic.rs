use dlctix::bitcoin;
use dlctix::musig2;
use dlctix::secp::{Point, Scalar};
use dlctix::{
    hashlock, ContractParameters, ContributorPartialSignatureSharingRound, EventAnnouncement,
    MarketMaker, NonceSharingRound, Outcome, PayoutWeights, Player, SigMap, SignedContract,
    SigningSession, TicketedDLC, WinCondition,
};

use std::collections::BTreeMap;

/*
    This demo illustrates the use of dlctix to create a basic two-party ticketed DLC,
    and then enforce different outcomes.
*/

#[test]
fn two_player_example() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();

    // Define the players' secret data. Each player would normally generate
    // and store their own secret key and payout preimage on their own machine.
    let alice_seckey = Scalar::random(&mut rng);
    let alice_payout_preimage = hashlock::preimage_random(&mut rng);
    let bob_seckey = Scalar::random(&mut rng);
    let bob_payout_preimage = hashlock::preimage_random(&mut rng);

    // The market maker generates a ticket preimage (secret) for each player.
    // If a player learns their preimage, they can enforce winning outcomes favorable
    // to them. So the market maker should keep these secret, and only give a player
    // their ticket preimage if they pay for it appropriately first.
    let alice_ticket_preimage = hashlock::preimage_random(&mut rng);
    let bob_ticket_preimage = hashlock::preimage_random(&mut rng);

    // The market maker has his own key pair as well.
    let market_maker_seckey = Scalar::random(&mut rng);
    let market_maker_pubkey = market_maker_seckey.base_point_mul();

    // This is public data which the market maker shares with all players.
    let alice = Player {
        pubkey: alice_seckey.base_point_mul(),
        ticket_hash: hashlock::sha256(&alice_ticket_preimage),
        payout_hash: hashlock::sha256(&alice_payout_preimage),
    };
    let bob = Player {
        pubkey: bob_seckey.base_point_mul(),
        ticket_hash: hashlock::sha256(&bob_ticket_preimage),
        payout_hash: hashlock::sha256(&bob_payout_preimage),
    };

    let players = vec![
        alice.clone(), // Alice has player index 0
        bob.clone(),   // Bob has player index 1
    ];

    // To execute any DLC, there must be a semi-trusted oracle who
    // attests to the outcome. The oracle has the power to dictate the
    // outcome of the contract, but doesn't need to be directly involved.
    // Oracles usually publish their announcements and attestations over
    // public mediums like a website, or Twitter, or Nostr.
    let oracle_seckey = Scalar::random(&mut rng);

    // Each event has an associated nonce which the oracle commits to
    // ahead of time.
    let oracle_secnonce = Scalar::random(&mut rng);

    // An announcement describes the different messages an oracle might sign.
    let event = EventAnnouncement {
        oracle_pubkey: oracle_seckey.base_point_mul(),
        nonce_point: oracle_secnonce.base_point_mul(),

        // We enumerate the different outcome messages the oracle could sign.
        outcome_messages: vec![
            Vec::from(b"alice wins"),
            Vec::from(b"bob wins"),
            Vec::from(b"tie"),
        ],

        // The expiry time is the time after which the Expiry outcome transaction should be
        // triggered. This can either be a unix seconds timestamp, or a bitcoin block height,
        // or `None` to indicate the contract should not expire.
        expiry: Some(1710963648),
    };

    // A set of PayoutWeights describes who is paid out and how much is allocated to each
    // winner. The keys are player indexes (e.g. 0 for Alice, 1 for Bob), and the values
    // are relative weights.
    //
    // For example, `PayoutWeights::from([(0, 1), (1, 2)])` allocates two thirds of the pot
    // to player 1, and one third to player 0.
    //
    // If there is only one winner in the PayoutWeights map, then they are always allocated
    // the full pot. Payout weight values cannot be zero, or DLC TX construction will fail.
    let alice_wins_payout = PayoutWeights::from([(0, 1)]); // all to Alice
    let bob_wins_payout = PayoutWeights::from([(1, 1)]); // all to Bob
    let tie_payout = PayoutWeights::from([(0, 1), (1, 1)]); // split the pot evenly

    // An Outcome is a compact representation of which of the messages in the
    // `EventAnnouncement::outcome_messages` field (if any) an oracle might attest
    // to.
    let alice_wins_outcome = Outcome::Attestation(0);
    let bob_wins_outcome = Outcome::Attestation(1);
    let tie_outcome = Outcome::Attestation(2);

    // The outcome payouts map describes how payouts are allocated based on the Outcome
    // which should be attested to by the oracle. If the oracle doesn't attest to any
    // outcome by the expiry time, then the `Outcome::Expiry` payout map will take effect.
    // If this map does not contain an `Outcome::Expiry` entry, then there is no expiry
    // condition, and the money simply remains locked in the funding output until the
    // Oracle's attestation is found.
    let outcome_payouts = BTreeMap::from([
        (alice_wins_outcome, alice_wins_payout.clone()),
        (bob_wins_outcome, bob_wins_payout),
        (tie_outcome, tie_payout.clone()),
        (Outcome::Expiry, tie_payout.clone()),
    ]);

    // We are finally ready to construct the full set of contract parameters.
    let params = ContractParameters {
        market_maker: MarketMaker {
            pubkey: market_maker_pubkey,
        },
        players,
        event: event.clone(),
        outcome_payouts,

        // This determines a flat fee rate used for each cooperatively-signed transaction.
        // Ideally it should be high enough to cover unexpected surges in the fee market,
        // Callers may also wish to consider signing multiple sets of Ticketed DLC transactions
        // under different fee rates.
        fee_rate: bitcoin::FeeRate::from_sat_per_vb_unchecked(100),

        // This determines the amount of bitcoin which the market maker is expected to use
        // to fund the contract on-chain. Normally, this would be the expected sum of the
        // players' off-chain payments to the market maker, minus a fee. Winners will split
        // the funding value among themselves according to the agreed PayoutWeights for
        // each outcome.
        funding_value: bitcoin::Amount::from_sat(1_000_000),

        // A reasonable number of blocks within which a transaction can confirm.
        // Used for enforcing relative locktime timeout spending conditions.
        //
        // Reasonable values are:
        //
        // - `72`:  ~12 hours
        // - `144`: ~24 hours
        // - `432`: ~72 hours
        // - `1008`: ~1 week
        relative_locktime_block_delta: 72,
    };

    // Usually the market maker would construct the ContractParameters, and would send it
    // to all players. The players can validate it to ensure it meets their expectations, and
    // that they are paid out in the correct situations. Here are a few examples of things
    // Alice might validate.
    {
        // Ensure Alice is a player in the DLC. This ensures her signatures are needed
        // to unlock the funding output.
        assert_eq!(params.players[0], alice);

        // Ensure the market maker is funding the right amount.
        assert_eq!(params.funding_value, bitcoin::Amount::from_sat(1_000_000));

        // Alice should be paid out in full if she wins.
        assert_eq!(
            params.outcome_payouts[&alice_wins_outcome],
            alice_wins_payout
        );

        // Alice should be paid out half if there is a tie or expiry.
        assert_eq!(params.outcome_payouts[&tie_outcome], tie_payout);
        assert_eq!(params.outcome_payouts[&Outcome::Expiry], tie_payout);

        // Also do basic safety checks to ensure the market maker isn't fiddling
        // with the relative locktime
        assert_eq!(params.fee_rate.to_sat_per_vb_floor(), 100);
        // ...or using a crazy fee rate.
        assert_eq!(params.relative_locktime_block_delta, 72);
        // ...or modifying the expected oracle event.
        assert_eq!(params.event, event);
    }

    // Alice is now confident that her contract parameters match her expectations,
    // and if the market maker funds the contract, she can participate without
    // trusting anyone but the oracle.
    let funding_output = params.funding_output()?;
    let mut funding_tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![], // the market maker would handle funding
        output: vec![funding_output],
    };

    // The market maker shouldn't broadcast the funding_tx yet, because he
    // first needs players' signatures to ensure he can recover his money
    // if they disappear.
    let funding_outpoint = bitcoin::OutPoint {
        txid: funding_tx.txid(),
        vout: 0,
    };

    // Every player and the market maker uses the same set of ContractParameters and
    // the market maker's funding outpoint to construct a `TicketedDLC`, which
    // encapsulates all the unsigned transactions.
    let ticketed_dlc = TicketedDLC::new(params, funding_outpoint)?;

    // All participants now run a cooperative MuSig signing session to sign all the
    // various transactions. This usually consists of two rounds of network communication.
    //
    // - the players submit nonces to the market maker
    // - the market maker aggregates the nonces and replies with a set of aggregated nonces
    // - the players use the aggregated nonces to compute and submit sets of partial signatures
    // - the market maker validates and aggregates the partial signatures into a fully SignedContract
    //
    // For more details, see the `musig_sign_ticketed_dlc` function below, where we simulate
    // the process locally.
    let signed_contract: SignedContract = musig_sign_ticketed_dlc(
        &ticketed_dlc,
        [alice_seckey, bob_seckey, market_maker_seckey],
        &mut rng,
    );

    // The `signed_contract` can now be used to enforce DLC outcomes, but the contract hasn't been
    // funded yet. An optimistic market maker might immediately fund the contract, but they could
    // also require players to forward a small anti-spam deposit to the market maker, to offset
    // the risk that a player might renege and opt out of buying their ticket preimage.
    //
    // Once the market maker is ready, they can broadcast the funding TX to lock in the Ticketed DLC.
    sign_transaction(&mut funding_tx);
    broadcast_transaction(&funding_tx);
    wait_for_confs(&funding_tx.txid(), 1);

    // Once the funding TX is confirmed, players can begin buying their ticket preimages
    // from the market maker. This would probably take place via the lightning network,
    // outside the scope of this crate.
    //
    // Once Alice has her ticket preimage, she can now confidently enforce any outcome in
    // which her player index is part of the PayoutWeights map.
    //
    // However, before _any_ outcome can be enforced, the oracle must publish their attestation.
    let outcome_index = 0;
    let oracle_attestation = signed_contract
        .params()
        .event
        .attestation_secret(outcome_index, oracle_seckey, oracle_secnonce)
        .unwrap();

    // A win condition describes an outcome and a particular player
    // who is paid out under that outcome.
    let alice_win_cond = WinCondition {
        outcome: Outcome::Attestation(outcome_index),
        player_index: 0,
    };

    // At this stage, Alice knows her ticket preimage, and so she is 100% confident she'll
    // be able to claim her winnings. Here's how.
    let claim_winnings_forcefully = || -> Result<(), Box<dyn std::error::Error>> {
        // An outcome transaction spends the funding outpoint, and locks it into
        // a 2nd stage multisig contract between the outcome winners and the market maker.
        // If Alice (or any other player) knows the attestation to outcome 0, she can
        // unlock that outcome TX and publish it.
        let outcome_tx = signed_contract.signed_outcome_tx(outcome_index, oracle_attestation)?;

        broadcast_transaction(&outcome_tx);

        // Alice must wait for the relative locktime to expire before she can use the split transaction.
        wait_for_confs(
            &outcome_tx.txid(),
            signed_contract.params().relative_locktime_block_delta,
        );

        let split_tx = signed_contract.signed_split_tx(&alice_win_cond, alice_ticket_preimage)?;

        broadcast_transaction(&split_tx);

        // Alice must wait for the relative locktime to expire before she can extract her money
        // from the split transaction output.
        wait_for_confs(
            &split_tx.txid(),
            signed_contract.params().relative_locktime_block_delta,
        );

        // This prevout data is needed to construct the signature and
        // also is helpful in constructing transactions which aggregate
        // multiple inputs. Perhaps Alice might want to join the
        // winnings together with other coins.
        let (alice_split_input, alice_split_prevout) = signed_contract
            .split_win_tx_input_and_prevout(&alice_win_cond)
            .unwrap();

        let mut alice_win_tx = simple_sweep_tx(
            alice.pubkey,
            alice_split_input,
            signed_contract.split_win_tx_input_weight(),
            alice_split_prevout.value,
        );

        signed_contract.sign_split_win_tx_input(
            &alice_win_cond,
            &mut alice_win_tx,
            0, // input index
            &bitcoin::sighash::Prevouts::All(&[alice_split_prevout]),
            alice_ticket_preimage,
            alice_seckey,
        )?;

        broadcast_transaction(&alice_win_tx);
        wait_for_confs(&alice_win_tx.txid(), 1);

        // Alice now has 100% control over her winnings.
        Ok(())
    };
    claim_winnings_forcefully()?;

    // However, forceful resolution is far less efficient than cooperating. To
    // streamline the resolution process, Alice gives the market maker a lightning
    // invoice, which pays Alice out if she reveals `alice_payout_preimage`. Alice's
    // payout preimage gives the market maker the ability to reclaim the winnings Alice
    // could've claimed. Here's how.
    let reclaim_winnings_via_split_sellback = || -> Result<(), Box<dyn std::error::Error>> {
        let outcome_tx = signed_contract.signed_outcome_tx(outcome_index, oracle_attestation)?;

        broadcast_transaction(&outcome_tx);

        let (alice_split_input, alice_split_prevout) =
            signed_contract.split_sellback_tx_input_and_prevout(&alice_win_cond)?;

        let mut sellback_tx = simple_sweep_tx(
            market_maker_pubkey,
            alice_split_input,
            signed_contract.split_sellback_tx_input_weight(),
            alice_split_prevout.value,
        );

        signed_contract.sign_split_sellback_tx_input(
            &alice_win_cond,
            &mut sellback_tx,
            0, // input index
            &bitcoin::sighash::Prevouts::All(&[alice_split_prevout]),
            alice_payout_preimage,
            market_maker_seckey,
        )?;

        Ok(())
    };
    reclaim_winnings_via_split_sellback()?;

    // But this can be improved even more. Once Alice has been paid off-chain, and
    // the market maker has her payout preimage, her secret key no longer has any
    // value. She can freely surrender it to the market maker without any negative
    // effects. This allows the market maker to sweep the output of the outcome
    // TX without using inefficient HTLC script logic. Here's how.
    let reclaim_winnings_via_outcome_close = || -> Result<(), Box<dyn std::error::Error>> {
        // TODO
        Ok(())
    };
    reclaim_winnings_via_outcome_close()?;

    // Bob lost, so he has no incentive to participate in the protocol at all once the
    // attestation is revealed
    //
    // But on the off chance Bob is cooperative as well, and if the maker knows Alice's
    // payout preimage, then Alice and Bob can both surrender their secret keys. The market
    // maker can use them to sweep the funding output right back to themselves, resulting
    // in the most efficient and private on-chain footprint possible for the contract.
    let reclaim_winnings_via_funding_close = || -> Result<(), Box<dyn std::error::Error>> {
        let (close_tx_input, close_tx_prevout) =
            signed_contract.funding_close_tx_input_and_prevout();

        let mut close_tx = simple_sweep_tx(
            market_maker_pubkey,
            close_tx_input,
            signed_contract.close_tx_input_weight(),
            close_tx_prevout.value,
        );

        signed_contract.sign_funding_close_tx_input(
            &mut close_tx,
            0, // input index
            &bitcoin::sighash::Prevouts::All(&[close_tx_prevout]),
            market_maker_seckey,
            &BTreeMap::from([(alice.pubkey, alice_seckey), (bob.pubkey, bob_seckey)]),
        )?;

        Ok(())
    };
    reclaim_winnings_via_funding_close()?;

    // If Alice didn't buy her ticket preimage, Alice can still unlock the outcome transaction,
    // but she can't unlock the split transaction. Eventually, after a locktime delay, the
    // outcome TX output can be reclaimed by the market maker.
    let reclaim_winnings_via_timeout = || -> Result<(), Box<dyn std::error::Error>> {
        let outcome = Outcome::Attestation(outcome_index);
        let outcome_tx = signed_contract.signed_outcome_tx(outcome_index, oracle_attestation)?;

        broadcast_transaction(&outcome_tx);

        // The reclaim TX spending path is only unlocked after double the locktime
        // needed for the split TX.
        wait_for_confs(
            &outcome_tx.txid(),
            2 * signed_contract.params().relative_locktime_block_delta,
        );

        let (reclaim_tx_input, reclaim_tx_prevout) =
            signed_contract.outcome_reclaim_tx_input_and_prevout(&outcome)?;
        let mut reclaim_tx = simple_sweep_tx(
            market_maker_pubkey,
            reclaim_tx_input,
            signed_contract
                .outcome_reclaim_tx_input_weight(&outcome)
                .unwrap(),
            reclaim_tx_prevout.value,
        );

        signed_contract.sign_outcome_reclaim_tx_input(
            &outcome,
            &mut reclaim_tx,
            0, // input index
            &bitcoin::sighash::Prevouts::All(&[reclaim_tx_prevout]),
            market_maker_seckey,
        )?;

        Ok(())
    };
    reclaim_winnings_via_timeout()?;

    Ok(())
}

/// Cooperatively sign a `TicketedDLC` using the secret keys of every player
/// and the market maker. The order of secret keys in the `all_seckeys` iterator
/// does not matter.
fn musig_sign_ticketed_dlc<R: rand::RngCore + rand::CryptoRng>(
    ticketed_dlc: &TicketedDLC,
    all_seckeys: impl IntoIterator<Item = Scalar>,
    rng: &mut R,
) -> SignedContract {
    let mut signing_sessions: BTreeMap<Point, SigningSession<NonceSharingRound>> = all_seckeys
        .into_iter()
        .map(|seckey| {
            let session = SigningSession::new(ticketed_dlc.clone(), rng, seckey)
                .expect("error creating SigningSession");
            (seckey.base_point_mul(), session)
        })
        .collect();

    let pubnonces_by_sender: BTreeMap<Point, SigMap<musig2::PubNonce>> = signing_sessions
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

    let partial_sigs_by_sender: BTreeMap<Point, SigMap<musig2::PartialSignature>> =
        signing_sessions
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
    for (&sender_pubkey, partial_sigs) in &partial_sigs_by_sender {
        coordinator_session
            .verify_partial_signatures(sender_pubkey, partial_sigs)
            .expect("valid partial signatures should be verified as OK");
    }

    let signed_contract = coordinator_session
        .aggregate_all_signatures(partial_sigs_by_sender)
        .expect("error aggregating partial signatures");

    for session in signing_sessions.into_values() {
        session
            .verify_aggregated_signatures(signed_contract.all_signatures())
            .expect("player failed to verify signatures aggregated by the market maker");

        // This is how a player receiving signatures from the market maker might convert
        // their signing session into a complete SignedContract.
        let _: SignedContract =
            session.into_signed_contract(signed_contract.all_signatures().clone());
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

/// Used for demonstration
fn sign_transaction(_: &mut bitcoin::Transaction) {}
fn broadcast_transaction(_: &bitcoin::Transaction) {}
fn wait_for_confs(_: &bitcoin::Txid, _: u16) {}

/// Generate a P2TR script pubkey which pays to the given pubkey (no tweak added).
fn p2tr_script_pubkey(pubkey: Point) -> bitcoin::ScriptBuf {
    let (xonly, _) = pubkey.into();
    let tweaked = bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(xonly);
    bitcoin::ScriptBuf::new_p2tr_tweaked(tweaked)
}

/// Create a simple TX which sweeps to the given destination pubkey as a P2TR output.
fn simple_sweep_tx(
    destination_pubkey: Point,
    input: bitcoin::TxIn,
    input_weight: bitcoin::transaction::InputWeightPrediction,
    prevout_value: bitcoin::Amount,
) -> bitcoin::Transaction {
    let script_pubkey = p2tr_script_pubkey(destination_pubkey);
    bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![input],
        output: vec![bitcoin::TxOut {
            value: {
                let tx_weight =
                    bitcoin::transaction::predict_weight([input_weight], [script_pubkey.len()]);
                let fee = tx_weight * bitcoin::FeeRate::from_sat_per_vb_unchecked(20);
                prevout_value - fee
            },
            script_pubkey,
        }],
    }
}
