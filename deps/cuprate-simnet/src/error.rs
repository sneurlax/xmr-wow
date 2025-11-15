#[derive(Debug, thiserror::Error)]
pub enum SimnetError {
    #[error("database: {0}")]
    Database(tower::BoxError),
    #[error("consensus: {0}")]
    Consensus(Box<dyn std::error::Error + Send + Sync>),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("node not running")]
    NotRunning,
    #[error("invalid node index: {0}")]
    InvalidNodeIndex(usize),
    #[error("double-spend detected: key image {0}")]
    DoubleSpend(String),
}

impl From<tower::BoxError> for SimnetError {
    fn from(e: tower::BoxError) -> Self {
        Self::Database(e)
    }
}

impl From<cuprate_blockchain::cuprate_database::RuntimeError> for SimnetError {
    fn from(e: cuprate_blockchain::cuprate_database::RuntimeError) -> Self {
        Self::Database(e.into())
    }
}
