use crate::swap_state::{SwapError, SwapParams, SwapRole, SwapState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuaranteeStatus {
    Supported,
    Blocked,
    UnsupportedForGuarantee,
}

impl GuaranteeStatus {
    pub fn label(self) -> &'static str {
        match self {
            GuaranteeStatus::Supported => "supported",
            GuaranteeStatus::Blocked => "blocked",
            GuaranteeStatus::UnsupportedForGuarantee => "unsupported-for-guarantee",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuaranteeMode {
    ObservedInitTiming,
    LegacyRefundNoEvidence,
    CooperativeRefundCommands,
    LiveXmrUnlockTimeRefund,
    LiveWowCooperativeRefund,
    ProofHarnessValidation,
    CurrentSingleSignerPreLockArtifact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuaranteeDecision {
    pub status: GuaranteeStatus,
    pub reason: &'static str,
}

pub fn guarantee_decision(mode: GuaranteeMode) -> GuaranteeDecision {
    match mode {
        GuaranteeMode::ObservedInitTiming => GuaranteeDecision {
            status: GuaranteeStatus::Supported,
            reason: "Observed daemon heights provide the Phase 13 timing basis required by SAFE-09.",
        },
        GuaranteeMode::LegacyRefundNoEvidence => GuaranteeDecision {
            status: GuaranteeStatus::Blocked,
            reason: "Legacy refund cannot mark success without a broadcast and confirmed refund transaction.",
        },
        GuaranteeMode::CooperativeRefundCommands => GuaranteeDecision {
            status: GuaranteeStatus::UnsupportedForGuarantee,
            reason: "Post-lock raw-secret cooperation is historical/manual only, not the v1.2 guarantee.",
        },
        GuaranteeMode::LiveXmrUnlockTimeRefund => GuaranteeDecision {
            status: GuaranteeStatus::Blocked,
            reason: "Current Monero relay policy rejects relayed nonzero unlock_time for non-coinbase transactions.",
        },
        GuaranteeMode::LiveWowCooperativeRefund => GuaranteeDecision {
            status: GuaranteeStatus::UnsupportedForGuarantee,
            reason: "WOW refund remains a cooperative post-lock flow with raw-secret disclosure, not a guaranteed refund.",
        },
        GuaranteeMode::ProofHarnessValidation => GuaranteeDecision {
            status: GuaranteeStatus::Supported,
            reason: "Simnet and proof-harness validation remain supported ways to verify refund behavior safely.",
        },
        GuaranteeMode::CurrentSingleSignerPreLockArtifact => GuaranteeDecision {
            status: GuaranteeStatus::UnsupportedForGuarantee,
            reason: "Current keysplit wallet flow has no proven pre-lock refund artifact without post-lock output discovery and secret reconstruction.",
        },
    }
}

pub fn validate_pre_risk_entry(
    params: &SwapParams,
    mode: GuaranteeMode,
) -> Result<GuaranteeDecision, SwapError> {
    params.validate_observed_refund_timing()?;
    Ok(guarantee_decision(mode))
}

pub fn guidance_decision(state: &SwapState) -> Option<GuaranteeDecision> {
    let mode = match state {
        SwapState::JointAddress { .. } => Some(GuaranteeMode::CurrentSingleSignerPreLockArtifact),
        SwapState::WowLocked {
            role: SwapRole::Alice,
            ..
        } => Some(GuaranteeMode::CurrentSingleSignerPreLockArtifact),
        SwapState::WowLocked {
            role: SwapRole::Bob,
            ..
        } => Some(GuaranteeMode::LiveWowCooperativeRefund),
        SwapState::XmrLocked {
            role: SwapRole::Alice,
            ..
        } => Some(GuaranteeMode::LiveXmrUnlockTimeRefund),
        SwapState::XmrLocked {
            role: SwapRole::Bob,
            ..
        } => Some(GuaranteeMode::LiveWowCooperativeRefund),
        _ => None,
    }?;
    Some(guarantee_decision(mode))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase13_guarantee_matrix_matches_research() {
        let cases = [
            (
                GuaranteeMode::LiveXmrUnlockTimeRefund,
                GuaranteeStatus::Blocked,
            ),
            (
                GuaranteeMode::CooperativeRefundCommands,
                GuaranteeStatus::UnsupportedForGuarantee,
            ),
            (
                GuaranteeMode::ProofHarnessValidation,
                GuaranteeStatus::Supported,
            ),
            (
                GuaranteeMode::CurrentSingleSignerPreLockArtifact,
                GuaranteeStatus::UnsupportedForGuarantee,
            ),
        ];

        for (mode, expected_status) in cases {
            let decision = guarantee_decision(mode);
            assert_eq!(decision.status, expected_status);
            assert!(!decision.reason.is_empty());
        }
    }
}
