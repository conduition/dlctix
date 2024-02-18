use bitcoin::{transaction::InputWeightPrediction, Amount, FeeRate};

use crate::errors::Error;

/// Compute the fee for a transaction given a fixed [`FeeRate`], input weights,
/// and output script lengths.
pub(crate) fn fee_calc_safe<I, O>(
    fee_rate: FeeRate,
    input_weights: I,
    output_spk_lens: O,
) -> Result<Amount, Error>
where
    I: IntoIterator<Item = InputWeightPrediction>,
    O: IntoIterator<Item = usize>,
{
    let tx_weight = bitcoin::transaction::predict_weight(input_weights, output_spk_lens);
    let fee = fee_rate.fee_wu(tx_weight).ok_or(Error)?;
    Ok(fee)
}

/// Safely compute the given output amount by subtracting the fee
/// amount from the amount of available coins. Returns an error if
/// the result is negative, or is less than the given dust threshold.
pub(crate) fn fee_subtract_safe(
    available_coins: Amount,
    fee: Amount,
    dust_threshold: Amount,
) -> Result<Amount, Error> {
    if fee >= available_coins {
        return Err(Error);
    }
    let after_fee = available_coins.checked_sub(fee).ok_or(Error)?;
    if after_fee <= dust_threshold {
        return Err(Error);
    }
    Ok(after_fee)
}
