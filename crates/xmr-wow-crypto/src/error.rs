use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum CryptoError {
    #[error("Invalid scalar bytes: not a canonical representation")]
    InvalidScalar,

    #[error("Invalid point bytes: not a valid compressed Edwards point")]
    InvalidPoint,

    #[error("Point is not on the prime-order subgroup (torsion component detected)")]
    NonPrimeOrderPoint,

    #[error("DLEQ proof verification failed")]
    DleqVerificationFailed,

    #[error("Adaptor signature verification failed")]
    AdaptorVerificationFailed,

    #[error("Adaptor secret extraction failed: signature inconsistency")]
    SecretExtractionFailed,

    #[error("Key derivation failed: {0}")]
    DerivationError(&'static str),

    #[error("Address error: {0}")]
    AddressError(String),

    #[error("Mnemonic error: {0}")]
    MnemonicError(String),
}
