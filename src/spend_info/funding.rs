use bitcoin::{
    sighash::{Prevouts, SighashCache},
    Amount, ScriptBuf, TapSighash, TapSighashType, Transaction, TxOut,
};
use musig2::KeyAggContext;
use secp::Point;

use crate::{
    errors::Error,
    parties::{MarketMaker, Player},
};

#[derive(Debug, Clone)]
pub(crate) struct FundingSpendInfo {
    key_agg_ctx: KeyAggContext,
    funding_value: Amount,
}

impl FundingSpendInfo {
    pub(crate) fn new<'p>(
        market_maker: &MarketMaker,
        players: impl IntoIterator<Item = &'p Player>,
        funding_value: Amount,
    ) -> Result<FundingSpendInfo, Error> {
        let mut pubkeys: Vec<Point> = players
            .into_iter()
            .map(|player| player.pubkey)
            .chain([market_maker.pubkey])
            .collect();
        pubkeys.sort();

        let key_agg_ctx = KeyAggContext::new(pubkeys)?;

        Ok(FundingSpendInfo {
            key_agg_ctx,
            funding_value,
        })
    }

    /// Return a reference to the [`KeyAggContext`] used to spend the multisig funding output.
    pub(crate) fn key_agg_ctx(&self) -> &KeyAggContext {
        &self.key_agg_ctx
    }

    /// Returns the TX locking script for funding the ticketed DLC multisig.
    pub(crate) fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::new_p2tr(
            secp256k1::SECP256K1,
            self.key_agg_ctx.aggregated_pubkey(),
            None,
        )
    }

    /// Compute the signature hash for a given outcome transaction.
    pub(crate) fn sighash_tx_outcome(
        &self,
        outcome_tx: &Transaction,
    ) -> Result<TapSighash, bitcoin::sighash::Error> {
        let funding_prevouts = [TxOut {
            script_pubkey: self.script_pubkey(),
            value: self.funding_value,
        }];

        SighashCache::new(outcome_tx).taproot_key_spend_signature_hash(
            0,
            &Prevouts::All(&funding_prevouts),
            TapSighashType::Default,
        )
    }
}