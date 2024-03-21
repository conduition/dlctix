# dlctix

Ticketed [Discreet Log Contracts (DLCs)](https://bitcoinops.org/en/topics/discreet-log-contracts/) to enable instant buy-in for conditional payment contracts on [Bitcoin](https://bitcoin.org).

This project is part of the [Backdrop Build V3 cohort](https://backdropbuild.com) <img style="width: 12px;" src="img/backdrop-logo.png">

<img width="40%" src="img/backdrop-build-v3.png">

### Summary

To read more about this concept in detail, [see my full blog post](https://conduition.io/scriptless/ticketed-dlc/).

A group of people don't trust each other, but DO trust some 3rd-party mediator called an _Oracle._ They want to wager money on some future event and redistribute the money depending on which outcome occurs (if any), according to the Oracle. Real-world examples include:

- Futures contracts (e.g. Contracts for Derivatives)
- Insurance contracts
- Security deposits (e.g. for car rentals)
- Gambling
- Competition prizes

[Discreet Log Contracts (DLCs)](https://bitcoinops.org/en/topics/discreet-log-contracts/) enable this kind of conditional payment to be executed natively on Bitcoin, with great efficiency. They have been known about for many years, but traditional DLCs are not scaleable to large contracts with many people buying in with very small amounts, such as lotteries or crowdfunding, because a traditional DLC requires on-chain Bitcoin contributions _from every participant_ in the DLC who is buying in - otherwise the contract would not be secure. The fees on such a jointly-funded contract quickly become impractical. There are also privacy issues: Every participant would be permanently associating their on-chain bitcoins with the DLC in question.

With my Ticketed DLCs approach, a single untrusted party called the Market Maker can lease their on-chain capital to use for the on-chain DLC, while buy-ins from the DLC contestants are instead paid to the Market Maker using off-chain payment protocols such as [Fedimint eCash](https://fedimint.org/) or [Lightning](https://lightning.network). The Market Maker can profit from this arrangement by charging the contestants an up-front fee which covers the opportunity cost of locking their on-chain capital for the duration of the DLC.

DLC contestants buy specific SHA256 preimages called _ticket secrets_ from the Market Maker off-chain. In so doing, a DLC contestant is buying the ability to redeem potential payouts from the DLC. Without the correct ticket secret, any winnings instead return to the Market Maker.

Once the Oracle publishes an attestation confirming the true outcome of the DLC, the Market Maker can issue off-chain payouts to the DLC winners. In exchange, the Market Maker receives a _payout preimage_ from each contestant which allows the Market Maker to reclaim his on-chain capital.

In the optimal case if everyone cooperates and payouts are conducted off-chain, there are only two on-chain transactions: The funding of the DLC by the Market Maker, and the withdrawal back to the Market Maker. **The result is zero on-chain visibility into who participated or won the DLC, and the absolute best on-chain efficiency possible** while still retaining the guarantee of on-chain contract enforcement. Assuming the Oracle is trustworthy, then the correct winners will always be paid out eventually, regardless of whether the Market Maker or the contestants cooperate, collude, or go offline.

## Code

This repository is a reusable Rust implementation of the Ticketed DLC contract using hash-locks.

It implements the transaction-building, multisignature-signing, and validation steps needed for all parties (both contestants and the Market Maker) to successfully execute a Ticketed DLC on and off-chain. It _does not_ include any networking code, nor does it package a Bitcoin or Lightning Network wallet. Rather, this crate is a generic building block for higher-level applications which can implement Ticketed DLCs in more specific contexts.

To demonstrate the practicality of this approach, I have written [a series of integration tests](./src/regtest.rs) which leverage a remote [Bitcoin Regtest Node](https://bisq.network/blog/how-to-set-up-bitcoin-regtest/) to simulate and test the various stages and paths of the Ticketed DLC's on-chain execution. The best way to visualize these stages is with a transaction diagram.

<img width="70%" src="img/ticketed-dlc-diagram.png">

## Walkthrough

To see an example, see [the basic integration test](./tests/basic.rs) which includes very detailed comments and descriptions of everything happening during the DLC construction, signing, and execution phases.

## Running the Tests

To run the integration tests, you'll need a [Bitcoin Regtest Node](https://bisq.network/blog/how-to-set-up-bitcoin-regtest/), either running locally on your machine or accessible by remote HTTP.

### 1. Clone this repo.

```console
git clone https://github.com/conduition/dlctix.git
```

### 2. [Install Rust](https://rustup.rs/)

### 3. Install `bitcoind`.

You can download a pre-compiled `bitcoind` binary from [the official bitcoin core releases page](https://bitcoincore.org/en/download/), or build it [from source yourself](https://github.com/bitcoin/bitcoin).

For tests to pass, the `bitcoind` binary should be in your executable `PATH`.

> [!TIP]
> As an alternative to installing `bitcoind` locally, you can designate a remotely-accessible regtest node and run tests against that. Fill in a `.env` file in the root of the `dlctix` repo folder:
>
> ```env
> BITCOIND_RPC_ADDRESS=http://some-remote.url:18443
> BITCOIND_RPC_AUTH_USERNAME=<your_nodes_rpc_username>
> BITCOIND_RPC_AUTH_PASSWORD=<your_nodes_rpc_password>
> ```
>
> Because the remote node's blockchain state is a singleton, tests will run in series, so that their executions do not interfere with each other's blockchain state.


### 4. Run the `dlctix` tests.

```
cargo test
```

This will compile and execute the unit and integration tests, which validate the numerous contract execution paths and validation conditions which must be enforceable by different parties.

```
$ cargo test
   Compiling proc-macro2 v1.0.78
   Compiling unicode-ident v1.0.12
   Compiling libc v0.2.153
   ...
   Compiling serde_cbor v0.11.2
   Compiling dotenv v0.15.0
   Compiling dlctix v0.0.6 (/home/user/src/dlctix)
    Finished test [unoptimized + debuginfo] target(s) in 56.70s
     Running unittests src/lib.rs (target/debug/deps/dlctix-1f9c250df9b6ac38)

running 11 tests
test consts::tests::test_p2tr_dust ... ok
test regtest::all_players_cooperate ... ok
test regtest::all_winners_cooperate ... ok
test regtest::contract_expiry_all_winners_cooperate ... ok
test regtest::contract_expiry_on_chain_resolution ... ok
test regtest::individual_sellback ... ok
test regtest::market_maker_reclaims_outcome_tx ... ok
test regtest::with_on_chain_resolutions ... ok
test serialization::tests::contract_parameters_serialization ... ok
test serialization::tests::player_serialization ... ok
test regtest::stress_test ... ok

test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 46.14s

     Running tests/basic.rs (target/debug/deps/basic-0f34ed113194694a)

running 1 test
test two_player_example ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.45s

   Doc-tests dlctix

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

```

To run more test threads in parallel, do:

```
cargo test -- --test-threads 8
```

If you have `bitcoind` installed locally, each `regtest` case will spawn its own regtest `bitcoind` instance in a subprocess and run against that.

If you _do not_ have `bitcoind` in your `$PATH`, then regtest test-cases will run sequentially regardless of how many threads you ask for.
