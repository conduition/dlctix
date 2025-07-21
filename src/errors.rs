use std::fmt;

#[derive(Debug)]
pub enum Error {
    // Fee calculation errors
    InsufficientFunds,
    InvalidFeeAmount,
    DustAmount,
    WeightOverflow,

    // Contract validation errors
    DuplicateTicketHash,
    InvalidPayoutWeight,
    OutOfBoundsPlayerIndex,
    InvalidFeeRate,
    InvalidLocktime,
    InvalidFundingValue,
    UnknownOutcome,
    EmptyPayoutMap,

    // Transaction signing errors
    InvalidSignature,
    MissingSignature(String),
    MissingNonce(String),
    InvalidKey,

    // Dependencies errors
    KeyAgg(musig2::errors::KeyAggError),
    Tweak(musig2::errors::TweakError),
    Verify(musig2::errors::VerifyError),
    Signing(musig2::errors::SigningError),
    InvalidPoint(secp::errors::InvalidPointBytes),
    InvalidSecretKeys(musig2::errors::InvalidSecretKeysError),
    TaprootBuilder(bitcoin::taproot::TaprootBuilderError),
    IncompleteBuilder(bitcoin::taproot::IncompleteBuilderError),
    TaprootSighash(bitcoin::sighash::TaprootError),
    ParseOutcomeIndex(std::num::ParseIntError),

    // General errors
    InvalidInput(&'static str),
    Conversion(&'static str),
}

impl std::error::Error for Error {
    // Implement source() to expose inner errors
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;
        match self {
            KeyAgg(e) => Some(e),
            Tweak(e) => Some(e),
            Verify(e) => Some(e),
            Signing(e) => Some(e),
            InvalidPoint(e) => Some(e),
            InvalidSecretKeys(e) => Some(e),
            TaprootBuilder(e) => Some(e),
            IncompleteBuilder(e) => Some(e),
            TaprootSighash(e) => Some(e),
            ParseOutcomeIndex(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match self {
            InsufficientFunds => write!(f, "insufficient funds available"),
            InvalidFeeAmount => write!(f, "invalid fee amount"),
            DustAmount => write!(f, "output amount would be below dust threshold"),
            WeightOverflow => write!(f, "transaction weight calculation overflow"),

            DuplicateTicketHash => write!(f, "duplicate ticket hash found"),
            InvalidPayoutWeight => write!(f, "invalid payout weight"),
            OutOfBoundsPlayerIndex => write!(f, "player index out of bounds"),
            InvalidFeeRate => write!(f, "invalid fee rate"),
            InvalidLocktime => write!(f, "invalid relative locktime"),
            InvalidFundingValue => write!(f, "invalid funding value"),
            UnknownOutcome => write!(f, "unknown outcome"),
            EmptyPayoutMap => write!(f, "empty payout map"),

            InvalidSignature => write!(f, "invalid signature"),
            MissingSignature(msg) => write!(f, "missing required signature: {}", msg),
            MissingNonce(msg) => write!(f, "missing required nonce: {}", msg),
            InvalidKey => write!(f, "invalid key"),

            InvalidInput(msg) => write!(f, "invalid input: {}", msg),
            Conversion(msg) => write!(f, "conversion error: {}", msg),

            KeyAgg(e) => write!(f, "key aggregation error: {}", e),
            Tweak(e) => write!(f, "key tweaking error: {}", e),
            Verify(e) => write!(f, "signature verification error: {}", e),
            Signing(e) => write!(f, "signing error: {}", e),
            InvalidPoint(e) => write!(f, "invalid point error: {}", e),
            InvalidSecretKeys(e) => write!(f, "invalid secret keys: {}", e),
            TaprootBuilder(e) => write!(f, "taproot builder error: {}", e),
            IncompleteBuilder(e) => write!(f, "incomplete taproot builder: {}", e),
            TaprootSighash(e) => write!(f, "taproot sighash error: {}", e),
            ParseOutcomeIndex(e) => write!(f, "invalid outcome index: {}", e),
        }
    }
}

// Implement From for common error types
impl From<musig2::errors::KeyAggError> for Error {
    fn from(e: musig2::errors::KeyAggError) -> Self {
        Error::KeyAgg(e)
    }
}

impl From<musig2::errors::TweakError> for Error {
    fn from(e: musig2::errors::TweakError) -> Self {
        Error::Tweak(e)
    }
}

impl From<musig2::errors::VerifyError> for Error {
    fn from(e: musig2::errors::VerifyError) -> Self {
        Error::Verify(e)
    }
}

impl From<musig2::errors::SigningError> for Error {
    fn from(e: musig2::errors::SigningError) -> Self {
        Error::Signing(e)
    }
}

impl From<secp::errors::InvalidPointBytes> for Error {
    fn from(e: secp::errors::InvalidPointBytes) -> Self {
        Error::InvalidPoint(e)
    }
}

impl From<musig2::errors::InvalidSecretKeysError> for Error {
    fn from(e: musig2::errors::InvalidSecretKeysError) -> Self {
        Error::InvalidSecretKeys(e)
    }
}

impl From<bitcoin::taproot::TaprootBuilderError> for Error {
    fn from(e: bitcoin::taproot::TaprootBuilderError) -> Self {
        Error::TaprootBuilder(e)
    }
}

impl From<bitcoin::taproot::IncompleteBuilderError> for Error {
    fn from(e: bitcoin::taproot::IncompleteBuilderError) -> Self {
        Error::IncompleteBuilder(e)
    }
}

impl From<bitcoin::sighash::TaprootError> for Error {
    fn from(e: bitcoin::sighash::TaprootError) -> Self {
        Error::TaprootSighash(e)
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(e: std::num::ParseIntError) -> Self {
        Error::ParseOutcomeIndex(e)
    }
}
