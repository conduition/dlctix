# dlctix

Ticketed [Discreet Log Contracts (DLCs)](https://bitcoinops.org/en/topics/discreet-log-contracts/) to enable instant buy-in for wager-like contracts on [Bitcoin](https://bitcoin.org).

This project is part of the [Backdrop Build V3 cohort](https://backdropbuild.com) <img style="width: 12px;" src="img/backdrop-logo.png">

<img width="50%" src="img/backdrop-build-v3.png">

**This repository does not work yet.**

### Summary

To read more about this concept in detail, [see my full blog post](https://conduition.io/scriptless/ticketed-dlc/).

A group of people don't trust each other, but DO trust some 3rd-party mediator called an _Oracle._ They want to wager money on some future event and redistribute the money depending on which outcome occurs (if any), according to the Oracle. Real-world examples include:

- Futures contracts (e.g. Contracts for Derivatives)
- Insurance contracts
- Security deposits (e.g. for car rentals)
- Gambling
- Competition prizes

[Discreet Log Contracts](https://bitcoinops.org/en/topics/discreet-log-contracts/) enable this, and have been known about for many years.

My Ticketed DLC approach is novel because a traditional DLC requires on-chain Bitcoin contributions _from every participant_ in the DLC who is buying in - otherwise the contract would not be secure. This is not scaleable to large contracts with many people buying in with very small amounts, such as lotteries or crowdfunding.

With Ticketed DLCs, a single untrusted party called the Market Maker can lease their on-chain capital to use for an on-chain DLC, while buy-ins from the DLC contestants are instead paid to the Market Maker using off-chain payment protocols such as [Fedimint eCash](https://fedimint.org/) or [Lightning](https://lightning.network). The Market Maker can profit from this arrangement by charging the contestants an up-front fee which covers the opportunity cost of locking their on-chain capital for the duration of the DLC.

DLC contestants buy specific SHA256 preimages called _ticket secrets_ from the Market Maker off-chain. In so doing, a DLC contestant is buying the ability to redeem potential payouts from the DLC. Without the correct ticket secret, any winnings instead return to the Market Maker.

Once the Oracle publishes an attestation confirming the true outcome of the DLC, the Market Maker can issue off-chain payouts to the DLC winners. In exchange, the Market Maker receives a _payout preimage_ from each contestant which allows the Market Maker to reclaim his on-chain capital.

In the optimal case if everyone cooperates and payouts are conducted off-chain, there are only two on-chain transactions: The funding of the DLC by the Market Maker, and the withdrawal back to the Market Maker. **The result is zero on-chain visibility into who participated or won the DLC, and the absolute best on-chain efficiency possible** while still retaining the guarantee of on-chain contract enforcement. Assuming the Oracle is trustworthy, then the correct winners will always be paid out eventually, regardless of whether the Market Maker or the contestants cooperate, collude, or go offline.

## Code

This repository is a Rust implementation of the Ticketed DLC contract using hash-locks.

The point-lock approach [described in my original blog post](https://conduition.io/scriptless/ticketed-dlc/) would be better for privacy and efficiency, but the primary utility of this concept is that it allows DLC contestants to buy into their positions using the [Lightning Network](https://lightning.network), which unfortunately does not yet support payments via [Point-time lock contracts](https://bitcoinops.org/en/topics/ptlc/). Instead, it uses [Hash-time lock contracts](https://bitcoinops.org/en/topics/htlc/), which - although less efficient - are highly cross-compatible between many payment networks, including Lightning.
