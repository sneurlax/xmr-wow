use serde::{Deserialize, Serialize};
use xmr_wow_wallet::RefundChain;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefundCheckpointName {
    BeforeWowLock,
    BeforeXmrLock,
}

impl RefundCheckpointName {
    pub fn label(self) -> &'static str {
        match self {
            RefundCheckpointName::BeforeWowLock => "before_wow_lock",
            RefundCheckpointName::BeforeXmrLock => "before_xmr_lock",
        }
    }

    pub fn display(self) -> &'static str {
        match self {
            RefundCheckpointName::BeforeWowLock => "before WOW lock",
            RefundCheckpointName::BeforeXmrLock => "before XMR lock",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefundCheckpointStatus {
    Ready,
    Blocked,
    UnsupportedForGuarantee,
}

impl RefundCheckpointStatus {
    pub fn label(self) -> &'static str {
        match self {
            RefundCheckpointStatus::Ready => "ready",
            RefundCheckpointStatus::Blocked => "blocked",
            RefundCheckpointStatus::UnsupportedForGuarantee => "unsupported-for-guarantee",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefundCheckpoint {
    pub name: RefundCheckpointName,
    pub chain: RefundChain,
    pub status: RefundCheckpointStatus,
    pub reason: String,
    pub artifact_present: bool,
    pub artifact_validated: bool,
    pub refund_address: Option<String>,
    pub refund_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefundEvidence {
    pub chain: RefundChain,
    pub refund_tx_hash: [u8; 32],
    pub confirmed_height: Option<u64>,
}
