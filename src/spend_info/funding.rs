use bitcoin::{
    sighash::{Prevouts, SighashCache},
    Amount, ScriptBuf, TapSighash, TapSighashType, Transaction, TxOut, Witness,
};
use musig2::{CompactSignature, KeyAggContext};
use secp::{Point, Scalar};

use crate::{
    convert_xonly_key,
    errors::Error,
    parties::{MarketMaker, Player},
};

use std::{borrow::Borrow, collections::BTreeMap};

#[derive(Clone, Eq, PartialEq)]
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
        let tweaked =
            bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(convert_xonly_key(xonly));
        ScriptBuf::new_p2tr_tweaked(tweaked)
    }

    /// Compute the signature hash for a given outcome transaction.
    pub(crate) fn sighash_tx_outcome(
        &self,
        outcome_tx: &Transaction,
    ) -> Result<TapSighash, bitcoin::sighash::TaprootError> {
        let funding_prevouts = [self.funding_output()];

        SighashCache::new(outcome_tx).taproot_key_spend_signature_hash(
            0,
            &Prevouts::All(&funding_prevouts),
            TapSighashType::Default,
        )
    }

    /// Derive the witness for a cooperative closing transaction which spends from
    /// the funding transaction. The market maker must provide the secret keys
    /// for all of the winning players involved in the whole DLC.
    pub(crate) fn witness_tx_close<T: Borrow<TxOut>>(
        &self,
        close_tx: &Transaction,
        input_index: usize,
        prevouts: &Prevouts<T>,
        market_maker_secret_key: Scalar,
        player_secret_keys: &BTreeMap<Point, Scalar>,
    ) -> Result<Witness, Error> {
        let mm_pubkey = market_maker_secret_key.base_point_mul();
        let sighash = SighashCache::new(close_tx).taproot_key_spend_signature_hash(
            input_index,
            prevouts,
            TapSighashType::Default,
        )?;

        let ordered_seckeys: Vec<Scalar> = self
            .key_agg_ctx
            .pubkeys()
            .into_iter()
            .map(|&pubkey| {
                if pubkey == mm_pubkey {
                    Ok(market_maker_secret_key)
                } else {
                    player_secret_keys.get(&pubkey).ok_or(Error).copied()
                }
            })
            .collect::<Result<_, Error>>()?;

        let group_seckey: Scalar = self.key_agg_ctx.aggregated_seckey(ordered_seckeys)?;

        let signature: CompactSignature = musig2::deterministic::sign_solo(group_seckey, sighash);

        let witness = Witness::from_slice(&[signature.serialize()]);
        Ok(witness)
    }
}
