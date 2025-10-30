use thiserror::Error;
#[derive(Debug, Error)]
pub enum VmError {
    #[error("VM error (stub)")]
    Stub,
}
