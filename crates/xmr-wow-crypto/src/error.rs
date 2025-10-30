use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("DLEQ proof verification failed")]
    DleqVerification,
    #[error("scalar is zero")]
    ZeroScalar,
    #[error("invalid point encoding")]
    InvalidPoint,
    #[error("adaptor signature verification failed")]
    AdaptorVerification,
    #[error("address encode/decode error: {0}")]
    Address(String),
}
