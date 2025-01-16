/// TODO actual error types.
#[derive(Debug, Clone)]
pub struct Error;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("generic error")
    }
}

impl std::error::Error for Error {}

impl From<musig2::errors::KeyAggError> for Error {
    fn from(_: musig2::errors::KeyAggError) -> Self {
        Error
    }
}

impl From<musig2::errors::TweakError> for Error {
    fn from(_: musig2::errors::TweakError) -> Self {
        Error
    }
}

impl From<musig2::errors::VerifyError> for Error {
    fn from(_: musig2::errors::VerifyError) -> Self {
        Error
    }
}

impl From<musig2::errors::SigningError> for Error {
    fn from(_: musig2::errors::SigningError) -> Self {
        Error
    }
}

impl From<secp::errors::InvalidPointBytes> for Error {
    fn from(_: secp::errors::InvalidPointBytes) -> Self {
        Error
    }
}

impl From<musig2::errors::InvalidSecretKeysError> for Error {
    fn from(_: musig2::errors::InvalidSecretKeysError) -> Self {
        Error
    }
}

impl From<bitcoin::taproot::TaprootBuilderError> for Error {
    fn from(_: bitcoin::taproot::TaprootBuilderError) -> Self {
        Error
    }
}

impl From<bitcoin::taproot::IncompleteBuilderError> for Error {
    fn from(_: bitcoin::taproot::IncompleteBuilderError) -> Self {
        Error
    }
}

impl From<bitcoin::sighash::TaprootError> for Error {
    fn from(_: bitcoin::sighash::TaprootError) -> Self {
        Error
    }
}
