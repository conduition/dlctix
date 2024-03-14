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

#[derive(Clone)]
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

    /// Returns the transaction output which the funding transaction should pay to.
    pub(crate) fn funding_output(&self) -> TxOut {
        TxOut {
            script_pubkey: self.script_pubkey(),
            value: self.funding_value,
        }
    }

    /// Returns the TX locking script for funding the ticketed DLC multisig.
    pub(crate) fn script_pubkey(&self) -> ScriptBuf {
        // This is safe because the musig key aggregation formula prevents
        // participants from hiding tapscript commitments in the aggregated key.
        let (xonly, _) = self.key_agg_ctx.aggregated_pubkey();
        let tweaked = bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(xonly);
        ScriptBuf::new_p2tr_tweaked(tweaked)
    }

    /// Compute the signature hash for a given outcome transaction.
    pub(crate) fn sighash_tx_outcome(
        &self,
        outcome_tx: &Transaction,
    ) -> Result<TapSighash, bitcoin::sighash::Error> {
        let funding_prevouts = [self.funding_output()];

        SighashCache::new(outcome_tx).taproot_key_spend_signature_hash(
            0,
            &Prevouts::All(&funding_prevouts),
            TapSighashType::Default,
        )
    }
}
