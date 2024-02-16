/// The serialized length of a P2TR script pubkey.
pub const P2TR_SCRIPT_PUBKEY_SIZE: usize = 34;

/// This was computed using [`bitcoin`] v0.31.1.
/// Test coverage ensures this stays is up-to-date.
pub const P2TR_DUST_VALUE: bitcoin::Amount = bitcoin::Amount::from_sat(330);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p2tr_dust() {
        let xonly = bitcoin::XOnlyPublicKey::from_slice(&[1; 32]).unwrap();
        let tweaked = bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(xonly);
        let script = bitcoin::ScriptBuf::new_p2tr_tweaked(tweaked);
        assert_eq!(script.dust_value(), P2TR_DUST_VALUE);
    }
}
